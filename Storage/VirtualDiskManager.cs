using DiskMountUtility.Core.Entities;
using DiskMountUtility.Core.Enums;
using DiskMountUtility.Core.Interfaces;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace DiskMountUtility.Infrastructure.Storage
{
    public class VirtualDiskManager : IVirtualDiskService
    {
        private readonly ICryptographyService _cryptographyService;
        private readonly IDiskRepository _diskRepository;
        private readonly string _diskStoragePath;
        private VirtualDisk? _mountedDisk;
        private Dictionary<string, DiskFile> _mountedDiskFiles = new();
        public string? MountedVaultPath { get; private set; }

        // ✅ ONLY CHANGE: Cache password during mount
        private string? _mountedDiskPassword;

        public VirtualDiskManager(ICryptographyService cryptographyService, IDiskRepository diskRepository)
        {
            _cryptographyService = cryptographyService;
            _diskRepository = diskRepository;
            _diskStoragePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DiskMountUtility", "Disks");
            Directory.CreateDirectory(_diskStoragePath);
        }

        public async Task InitializeAsync()
        {
            var mountedDisks = await _diskRepository.GetByStatusAsync(DiskStatus.Mounted);

            foreach (var disk in mountedDisks)
            {
                disk.Status = DiskStatus.Created;
                await _diskRepository.UpdateAsync(disk);
            }
        }

        public async Task<VirtualDisk> CreateDiskAsync(string name, long sizeInBytes, string password)
        {
            var diskId = Guid.NewGuid();
            var filePath = Path.Combine(_diskStoragePath, $"{diskId}.vdisk");

            // Step 0: Generate a single salt for both password hash and key derivation
            var salt = RandomNumberGenerator.GetBytes(32);
            var passwordHash = _cryptographyService.HashPassword(password, salt);

            // Step 1: Create disk entity
            var disk = new VirtualDisk
            {
                Id = diskId,
                Name = name,
                SizeInBytes = sizeInBytes,
                UsedSpaceInBytes = 0,
                Status = DiskStatus.Created,
                EncryptionAlgorithm = EncryptionAlgorithm.KyberAesGcm256,
                FilePath = filePath,
                CreatedAt = DateTime.UtcNow,
                PasswordHash = passwordHash
            };

            // Step 2: Prepare initial empty disk content
            var initialData = new { files = new List<DiskFile>() };
            var jsonData = JsonSerializer.SerializeToUtf8Bytes(initialData);

            // Step 3: Encrypt disk content and generate all cryptographic material using the SAME salt
            var encryptedData = _cryptographyService.EncryptData(
                jsonData,
                password,
                out var kyberCiphertext,
                out var kyberPublicKey,
                out var kyberSecretKeyEncrypted,
                out var diskNonce,
                salt, // ✅ pass the SAME salt, do NOT let EncryptData generate a new one
                out var kyberSecretKeyNonce
            );

            // Step 4: Build encryption metadata
            var metadata = new EncryptionMetadata
            {
                KyberCiphertext = kyberCiphertext,
                KyberPublicKey = kyberPublicKey,
                KyberSecretKeyEncrypted = kyberSecretKeyEncrypted,
                Nonce = diskNonce,
                Salt = salt, // ✅ same salt used for password hash
                KyberSecretKeyNonce = kyberSecretKeyNonce,
                VirtualDiskId = disk.Id
            };

            disk.Metadata = metadata;

            // Step 5: Write disk data to file
            var diskData = new
            {
                metadata = new
                {
                    kyberCiphertext = Convert.ToBase64String(kyberCiphertext),
                    kyberPublicKey = Convert.ToBase64String(kyberPublicKey),
                    kyberSecretKey = Convert.ToBase64String(kyberSecretKeyEncrypted),
                    kyberSecretKeyNonce = Convert.ToBase64String(kyberSecretKeyNonce),
                    nonce = Convert.ToBase64String(diskNonce),
                    salt = Convert.ToBase64String(salt)
                },
                encryptedContent = Convert.ToBase64String(encryptedData)
            };

            await File.WriteAllTextAsync(filePath, JsonSerializer.Serialize(diskData));

            // Step 6: Save to DB
            return await _diskRepository.CreateAsync(disk);
        }

        public async Task<bool> MountDiskAsync(Guid diskId, string password)
        {
            try
            {
                if (_mountedDisk != null)
                {
                    Console.WriteLine($"Switching mounted disk from '{_mountedDisk.Name}' to new disk...");

                    _mountedDisk.Status = DiskStatus.Unmounted;
                    await _diskRepository.UpdateAsync(_mountedDisk);

                    await UnmountDiskAsync(diskId);
                    _mountedDisk = null;
                }

                // 1️ Get disk info
                var disk = await _diskRepository.GetByIdAsync(diskId);
                if (disk == null || !File.Exists(disk.FilePath))
                {
                    Console.WriteLine("Disk not found or missing file path.");
                    return false;
                }

                // 2️ Fetch associated encryption metadata from DB
                var metadata = await _diskRepository.GetMetadataByDiskIdAsync(diskId);
                if (metadata == null)
                {
                    Console.WriteLine("No metadata found for disk.");
                    return false;
                }

                // 3️ Verify password using stored salt
                if (!_cryptographyService.VerifyPassword(password, disk.PasswordHash, metadata.Salt))
                {
                    Console.WriteLine("Password verification failed.");
                    return false;
                }

                // 4️ Read the encrypted content from disk file
                var jsonContent = await File.ReadAllTextAsync(disk.FilePath);
                var diskData = JsonSerializer.Deserialize<JsonDocument>(jsonContent);
                var encryptedContent = Convert.FromBase64String(
                    diskData!.RootElement.GetProperty("encryptedContent").GetString()!
                );

                // 5️ Decrypt using metadata (not the file)
                var decryptedData = _cryptographyService.DecryptData(
                    encryptedContent,
                    password,
                    metadata.KyberCiphertext,
                    metadata.KyberPublicKey,
                    metadata.KyberSecretKeyEncrypted,
                    metadata.KyberSecretKeyNonce,
                    metadata.Nonce,
                    metadata.Salt
                );

                // 6️ Deserialize back to in-memory files
                var diskContent = JsonSerializer.Deserialize<JsonDocument>(decryptedData);
                var files = diskContent!.RootElement.GetProperty("files");

                _mountedDiskFiles.Clear();
                foreach (var file in files.EnumerateArray())
                {
                    var diskFile = JsonSerializer.Deserialize<DiskFile>(file.GetRawText())!;
                    _mountedDiskFiles[diskFile.Path] = diskFile;
                }

                disk.Status = DiskStatus.Mounted;
                disk.LastMountedAt = DateTime.UtcNow;
                _mountedDisk = disk;
                _mountedDiskPassword = password; // Store password for save operations

                // Logical (in-memory) mount does not expose a filesystem path; clear any previous mounted vault path
                //MountedVaultPath = null;

                await _diskRepository.UpdateAsync(disk);

                Console.WriteLine($"Disk '{disk.Name}' mounted successfully.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Mount failed: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> UnmountDiskAsync(Guid diskId)
        {
            if (_mountedDisk == null || _mountedDisk.Id != diskId)
            {
                return false;
            }

            _mountedDisk.Status = DiskStatus.Unmounted;
            await _diskRepository.UpdateAsync(_mountedDisk);

            _mountedDisk = null;
            _mountedDiskFiles.Clear();

            //  ONLY CHANGE: Clear cached password
            _mountedDiskPassword = null;

            // Clear mounted vault path as well (if any)
            MountedVaultPath = null;

            return true;
        }

        public Task<VirtualDisk?> GetMountedDiskAsync()
        {
            return Task.FromResult(_mountedDisk);
        }

        public async Task<bool> ResizeDiskAsync(Guid diskId, long newSizeInBytes)
        {
            var disk = await _diskRepository.GetByIdAsync(diskId);
            if (disk == null || newSizeInBytes < disk.UsedSpaceInBytes)
            {
                return false;
            }

            disk.SizeInBytes = newSizeInBytes;
            disk.LastModifiedAt = DateTime.UtcNow;
            await _diskRepository.UpdateAsync(disk);

            return true;
        }

        public async Task<bool> ResizeDiskAsync(Guid diskId, long newSizeInBytes, string password)
        {
            var disk = await _diskRepository.GetByIdAsync(diskId);
            if (disk == null || newSizeInBytes < disk.UsedSpaceInBytes)
            {
                return false;
            }

            if (_mountedDisk != null && _mountedDisk.Id == diskId)
            {
                disk.SizeInBytes = newSizeInBytes;
                disk.LastModifiedAt = DateTime.UtcNow;
                _mountedDisk.SizeInBytes = newSizeInBytes;
                await _diskRepository.UpdateAsync(disk);
                return true;
            }

            if (disk.Status == DiskStatus.Mounted)
            {
                return false;
            }

            try
            {
                var metadata = await _diskRepository.GetMetadataByDiskIdAsync(diskId);
                if (metadata == null)
                {
                    Console.WriteLine("No metadata found for disk.");
                    return false;
                }

                if (!_cryptographyService.VerifyPassword(password, disk.PasswordHash, metadata.Salt))
                {
                    Console.WriteLine("Password verification failed.");
                    return false;
                }

                if (!File.Exists(disk.FilePath))
                {
                    return false;
                }

                var jsonContent = await File.ReadAllTextAsync(disk.FilePath);
                var diskData = JsonSerializer.Deserialize<JsonDocument>(jsonContent);
                var encryptedContent = Convert.FromBase64String(
                    diskData!.RootElement.GetProperty("encryptedContent").GetString()!
                );

                var decryptedData = _cryptographyService.DecryptData(
                    encryptedContent,
                    password,
                    metadata.KyberCiphertext,
                    metadata.KyberPublicKey,
                    metadata.KyberSecretKeyEncrypted,
                    metadata.KyberSecretKeyNonce,
                    metadata.Nonce,
                    metadata.Salt
                );

                disk.SizeInBytes = newSizeInBytes;
                disk.LastModifiedAt = DateTime.UtcNow;

                var reEncryptedData = _cryptographyService.EncryptData(
                    decryptedData,
                    password,
                    out var kyberCiphertext,
                    out var kyberPublicKey,
                    out var kyberSecretKey,
                    out var nonce,
                    metadata.Salt,
                    out var kyberSecretKeyNonce
                );

                metadata.KyberCiphertext = kyberCiphertext;
                metadata.KyberPublicKey = kyberPublicKey;
                metadata.KyberSecretKeyEncrypted = kyberSecretKey;
                metadata.Nonce = nonce;
                metadata.KyberSecretKeyNonce = kyberSecretKeyNonce;

                var updatedDiskData = new
                {
                    metadata = new
                    {
                        kyberCiphertext = Convert.ToBase64String(kyberCiphertext),
                        kyberPublicKey = Convert.ToBase64String(kyberPublicKey),
                        kyberSecretKey = Convert.ToBase64String(kyberSecretKey),
                        kyberSecretKeyNonce = Convert.ToBase64String(kyberSecretKeyNonce),
                        nonce = Convert.ToBase64String(nonce),
                        salt = Convert.ToBase64String(metadata.Salt)
                    },
                    encryptedContent = Convert.ToBase64String(reEncryptedData)
                };

                await File.WriteAllTextAsync(disk.FilePath, JsonSerializer.Serialize(updatedDiskData));
                await _diskRepository.UpdateAsync(disk);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Resize unmounted disk failed: {ex.Message}");
                return false;
            }
        }

        public Task<List<DiskFile>> GetFilesAsync(Guid diskId, string path = "/")
        {
            if (_mountedDisk == null || _mountedDisk.Id != diskId)
            {
                return Task.FromResult(new List<DiskFile>());
            }

            var files = _mountedDiskFiles.Values
                .Where(f => f.Path.StartsWith(path) && f.Path != path)
                .ToList();

            return Task.FromResult(files);
        }

        public async Task<bool> WriteFileAsync(Guid diskId, string path, string fileName, byte[] content)
        {
            if (_mountedDisk == null || _mountedDisk.Id != diskId)
            {
                return false;
            }

            var fullPath = Path.Combine(path, fileName).Replace("\\", "/");
            var fileSize = content.Length;

            if (_mountedDisk.UsedSpaceInBytes + fileSize > _mountedDisk.SizeInBytes)
            {
                return false;
            }

            var diskFile = new DiskFile
            {
                Id = Guid.NewGuid(),
                DiskId = diskId,
                Name = fileName,
                Path = fullPath,
                SizeInBytes = fileSize,
                IsDirectory = false,
                CreatedAt = DateTime.UtcNow,
                ModifiedAt = DateTime.UtcNow,
                EncryptedContent = content
            };

            if (_mountedDiskFiles.ContainsKey(fullPath))
            {
                _mountedDisk.UsedSpaceInBytes -= _mountedDiskFiles[fullPath].SizeInBytes;
            }

            _mountedDiskFiles[fullPath] = diskFile;
            _mountedDisk.UsedSpaceInBytes += fileSize;
            _mountedDisk.LastModifiedAt = DateTime.UtcNow;

            await SaveMountedDiskAsync();
            return true;
        }

        public Task<byte[]?> ReadFileAsync(Guid diskId, string path)
        {
            if (_mountedDisk == null || _mountedDisk.Id != diskId)
            {
                return Task.FromResult<byte[]?>(null);
            }

            if (_mountedDiskFiles.TryGetValue(path, out var file))
            {
                return Task.FromResult<byte[]?>(file.EncryptedContent);
            }

            return Task.FromResult<byte[]?>(null);
        }

        public async Task<bool> DeleteFileAsync(Guid diskId, string path)
        {
            if (_mountedDisk == null || _mountedDisk.Id != diskId)
            {
                return false;
            }

            if (_mountedDiskFiles.TryGetValue(path, out var file))
            {
                _mountedDisk.UsedSpaceInBytes -= file.SizeInBytes;
                _mountedDiskFiles.Remove(path);
                _mountedDisk.LastModifiedAt = DateTime.UtcNow;

                await SaveMountedDiskAsync();
                return true;
            }

            return false;
        }

        public async Task<bool> CreateDirectoryAsync(Guid diskId, string path)
        {
            if (_mountedDisk == null || _mountedDisk.Id != diskId)
            {
                return false;
            }

            var diskFile = new DiskFile
            {
                Id = Guid.NewGuid(),
                DiskId = diskId,
                Name = Path.GetFileName(path),
                Path = path,
                SizeInBytes = 0,
                IsDirectory = true,
                CreatedAt = DateTime.UtcNow,
                ModifiedAt = DateTime.UtcNow,
                EncryptedContent = Array.Empty<byte>()
            };

            _mountedDiskFiles[path] = diskFile;
            await SaveMountedDiskAsync();
            return true;
        }

        private async Task SaveMountedDiskAsync()
        {
            if (_mountedDisk == null)
            {
                return;
            }

            // ✅ Get metadata from database
            var metadata = await _diskRepository.GetMetadataByDiskIdAsync(_mountedDisk.Id);
            if (metadata == null)
            {
                Console.WriteLine("Cannot save: No metadata found");
                return;
            }

            var dataToEncrypt = new { files = _mountedDiskFiles.Values.ToList() };
            var jsonData = JsonSerializer.SerializeToUtf8Bytes(dataToEncrypt);

            // ✅ ONLY CHANGE: Use cached password instead of empty string
            var password = _mountedDiskPassword ?? string.Empty;

            var encryptedData = _cryptographyService.EncryptData(
                jsonData,
                password,
                out var kyberCiphertext,
                out var kyberPublicKey,
                out var kyberSecretKey,
                out var nonce,
                metadata.Salt,  // ✅ Use existing salt from metadata
                out var kyberSecretKeyNonce
            );

            // ✅ Update metadata in database
            metadata.KyberCiphertext = kyberCiphertext;
            metadata.KyberPublicKey = kyberPublicKey;
            metadata.KyberSecretKeyEncrypted = kyberSecretKey;
            metadata.Nonce = nonce;
            metadata.KyberSecretKeyNonce = kyberSecretKeyNonce;
            // Note: Salt remains unchanged

            var updatedDiskData = new
            {
                metadata = new
                {
                    kyberCiphertext = Convert.ToBase64String(kyberCiphertext),
                    kyberPublicKey = Convert.ToBase64String(kyberPublicKey),
                    kyberSecretKey = Convert.ToBase64String(kyberSecretKey),
                    kyberSecretKeyNonce = Convert.ToBase64String(kyberSecretKeyNonce),
                    nonce = Convert.ToBase64String(nonce),
                    salt = Convert.ToBase64String(metadata.Salt)
                },
                encryptedContent = Convert.ToBase64String(encryptedData)
            };

            await File.WriteAllTextAsync(_mountedDisk.FilePath, JsonSerializer.Serialize(updatedDiskData));
            await _diskRepository.UpdateAsync(_mountedDisk);
        }

        public async Task<bool> MountAsPhysicalDriveAsync(Guid diskId)
        {
            var disk = await _diskRepository.GetByIdAsync(diskId);
            if (disk == null || !File.Exists(disk.FilePath))
            {
                Console.WriteLine("❌ Disk not found or file missing.");
                return false;
            }

            if (disk.Status != DiskStatus.Mounted)
            {
                Console.WriteLine("⚠️ Disk must be logically mounted before attaching to system.");
                return false;
            }

            if (string.IsNullOrEmpty(_mountedDiskPassword))
            {
                Console.WriteLine("❌ No cached plaintext password available. Unlock vault first.");
                return false;
            }

            // 🔹 Find an available drive letter dynamically
            char driveLetter = GetAvailableDriveLetter();
            if (driveLetter == '\0')
            {
                Console.WriteLine("❌ No free drive letters available.");
                return false;
            }

            // 🔹 Use a persistent location for VHDs instead of Temp (avoid SYSTEM access issues)
            var vaultBaseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "DiskMountUtility", "MountedVHDs");
            Directory.CreateDirectory(vaultBaseDir);

            var tempVhdxPath = Path.Combine(vaultBaseDir, $"{disk.Id}.vhdx");
            var tempExtractFolder = Path.Combine(vaultBaseDir, $"{disk.Id}_extracted");
            var tempScriptPath = Path.Combine(vaultBaseDir, $"{disk.Id}_diskpart.txt");
            var batchFile = Path.Combine(vaultBaseDir, $"{disk.Id}_run_diskpart.bat");
            var logPath = Path.Combine(vaultBaseDir, $"{disk.Id}_diskpart.log");

            if (Directory.Exists(tempExtractFolder))
                Directory.Delete(tempExtractFolder, recursive: true);
            Directory.CreateDirectory(tempExtractFolder);

            try
            {
                // 1️⃣ Extract in-memory decrypted files into tempExtractFolder
                foreach (var kv in _mountedDiskFiles)
                {
                    var file = kv.Value;
                    if (file.IsDirectory)
                    {
                        var dirPath = Path.Combine(tempExtractFolder, file.Path.TrimStart('/').Replace("/", Path.DirectorySeparatorChar.ToString()));
                        Directory.CreateDirectory(dirPath);
                    }
                    else
                    {
                        var outPath = Path.Combine(tempExtractFolder, file.Path.TrimStart('/').Replace("/", Path.DirectorySeparatorChar.ToString()));
                        var parent = Path.GetDirectoryName(outPath);
                        if (!string.IsNullOrEmpty(parent) && !Directory.Exists(parent))
                            Directory.CreateDirectory(parent);
                        await File.WriteAllBytesAsync(outPath, file.EncryptedContent ?? Array.Empty<byte>());
                    }
                }

                if (File.Exists(tempVhdxPath))
                {
                    try
                    {
                        Console.WriteLine($"🧹 Deleting existing VHDX: {tempVhdxPath}");
                        File.Delete(tempVhdxPath);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"⚠️ Could not delete existing VHDX ({tempVhdxPath}): {ex.Message}");
                        return false;
                    }
                }

                // 2️⃣ Create DiskPart script (more reliable with re-select)
                var sizeMb = (disk.SizeInBytes + (1024 * 1024 - 1)) / (1024 * 1024);
                var diskpartScript = $@"
                    create vdisk file=""{tempVhdxPath}"" maximum={sizeMb} type=expandable
                    select vdisk file=""{tempVhdxPath}"" 
                    attach vdisk
                    select vdisk file=""{tempVhdxPath}"" 
                    create partition primary
                    format fs=ntfs quick label={disk.Name}
                    assign letter={driveLetter}
                    exit
                    ".Trim();

                await File.WriteAllTextAsync(tempScriptPath, diskpartScript);

                // 3️⃣ Create batch file that logs DiskPart output
                var batchContent = $@"
                    @echo off
                    echo Running DiskPart as admin...
                    diskpart /s ""{tempScriptPath}"" > ""{logPath}"" 2>&1
                    exit /b %errorlevel%
                    ";
                await File.WriteAllTextAsync(batchFile, batchContent);

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = batchFile,
                    UseShellExecute = true,
                    Verb = "runas", // triggers UAC prompt
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                try
                {
                    var proc = System.Diagnostics.Process.Start(psi);
                    proc?.WaitForExit();
                }
                catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
                {
                    Console.WriteLine("⚠️ User denied elevation. Mount aborted.");
                    return false;
                }

                // 4️⃣ Check if drive appeared
                var driveRoot = $"{driveLetter}:\\";
                var timeout = DateTime.UtcNow.AddSeconds(10);
                while (!Directory.Exists(driveRoot) && DateTime.UtcNow < timeout)
                    await Task.Delay(500);

                if (!Directory.Exists(driveRoot))
                {
                    Console.WriteLine($"❌ Drive {driveRoot} not available after attach.");
                    if (File.Exists(logPath))
                    {
                        Console.WriteLine("📜 DiskPart log output:");
                        Console.WriteLine(await File.ReadAllTextAsync(logPath));
                    }
                    return false;
                }

                Console.WriteLine($"✅ Drive {driveRoot} ready — copying decrypted contents...");

                // 5️⃣ Copy extracted files into the new drive
                CopyDirectory(tempExtractFolder, driveRoot);

                // 6️⃣ Test write access
                try
                {
                    var testFile = Path.Combine(driveRoot, "test.txt");
                    await File.WriteAllTextAsync(testFile, "Vault mount test OK");
                    Console.WriteLine($"✅ Test file created at {testFile}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Could not write test file: {ex.Message}");
                }

                // 7️⃣ Update DB
                disk.TempMountPath = tempVhdxPath;
                disk.Status = DiskStatus.Mounted;
                disk.LastMountedAt = DateTime.UtcNow;
                await _diskRepository.UpdateAsync(disk);

                // Set mounted vault path so FileWatcher or other components can find the drive root
                MountedVaultPath = driveRoot;

                Console.WriteLine($"✅ Vault mounted as physical drive {driveLetter}:\\");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ MountAsPhysicalDriveAsync failed: {ex}");
                if (File.Exists(logPath))
                {
                    Console.WriteLine("📜 DiskPart log output:");
                    Console.WriteLine(await File.ReadAllTextAsync(logPath));
                }
                return false;
            }
            finally
            {
                try
                {
                    if (Directory.Exists(tempExtractFolder))
                        Directory.Delete(tempExtractFolder, recursive: true);
                    // Don’t delete the log or VHD yet — useful for inspection
                }
                catch { /* ignore cleanup errors */ }
            }
        }

        // helper to copy directories (preserve structure)
        private static void CopyDirectory(string sourceDir, string destinationDir)
        {
            foreach (var dirPath in Directory.GetDirectories(sourceDir, "*", SearchOption.AllDirectories))
            {
                Directory.CreateDirectory(dirPath.Replace(sourceDir, destinationDir));
            }

            foreach (var filePath in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
            {
                var targetPath = filePath.Replace(sourceDir, destinationDir);
                File.Copy(filePath, targetPath, overwrite: true);
            }
        }

        public async Task<bool> UnmountPhysicalDriveAsync(Guid diskId)
        {
            try
            {
                var disk = await _diskRepository.GetByIdAsync(diskId);
                if (disk == null || string.IsNullOrEmpty(disk.TempMountPath))
                {
                    Console.WriteLine("❌ No mounted physical disk found for this vault.");
                    return false;
                }

                var vhdxPath = disk.TempMountPath;
                if (!File.Exists(vhdxPath))
                {
                    Console.WriteLine($"⚠️ VHDX file not found: {vhdxPath}");
                    return false;
                }

                Console.WriteLine($"🔧 Detaching virtual disk: {vhdxPath}");

                // Create a temporary diskpart script file
                var tempDir = Path.Combine(Path.GetTempPath(), "DiskMountUtility", "VhdxMounts");
                Directory.CreateDirectory(tempDir);
                var tempScriptPath = Path.Combine(tempDir, $"{disk.Id}_detach.txt");

                var detachScript = $@"
                    select vdisk file=""{vhdxPath}""
                    detach vdisk
                    exit
                    ".Trim();

                await File.WriteAllTextAsync(tempScriptPath, detachScript);

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "diskpart.exe",
                    Arguments = $"/s \"{tempScriptPath}\"",
                    UseShellExecute = true,
                    Verb = "runas", // triggers elevation (needed)
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                var proc = System.Diagnostics.Process.Start(psi);
                proc?.WaitForExit();

                // Give the OS a moment to clean up
                await Task.Delay(300);

                // Update DB and clean up
                disk.Status = DiskStatus.Unmounted;
                disk.TempMountPath = null;
                disk.LastMountedAt = DateTime.UtcNow;
                await _diskRepository.UpdateAsync(disk);

                // Clear the mounted vault path so FileWatcher / other components don't refer to stale path
                MountedVaultPath = null;

                Console.WriteLine($"✅ Successfully detached VHDX {vhdxPath}");
                return true;
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                Console.WriteLine("⚠️ User denied elevation. Unmount aborted.");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Unmount failed: {ex}");
                return false;
            }
        }

        public Task<string?> GetMountedPathAsync(Guid diskId)
        {
            // Prefer explicit physically-mounted path (MountedVaultPath).
            // Fall back to the disk.TempMountPath if present.
            if (_mountedDisk != null && _mountedDisk.Id == diskId)
            {
                if (!string.IsNullOrEmpty(MountedVaultPath))
                    return Task.FromResult<string?>(MountedVaultPath);

                return Task.FromResult<string?>(_mountedDisk.TempMountPath);
            }

            return Task.FromResult<string?>(null);
        }

        private static char GetAvailableDriveLetter()
        {
            // Collect currently used drive letters from mounted drives
            var used = DriveInfo.GetDrives()
                .Select(d => char.ToUpperInvariant(d.Name[0]))
                .ToHashSet();

            // 🔹 Also include reserved drive letters from the registry (MountedDevices)
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\MountedDevices");
                if (key != null)
                {
                    foreach (var name in key.GetValueNames())
                    {
                        if (name.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase) &&
                            name.Length == 13)
                        {
                            char letter = char.ToUpperInvariant(name[11]);
                            used.Add(letter);
                        }
                    }
                }
            }
            catch
            {
                // ignore registry read errors
            }

            // 🔹 Scan from Z → D (avoid C and system reserved)
            for (char letter = 'Z'; letter >= 'D'; letter--)
            {
                if (!used.Contains(letter))
                {
                    Console.WriteLine($"✅ Selected available drive letter: {letter}");
                    return letter;
                }
            }

            Console.WriteLine("❌ No available drive letter found.");
            return '\0';
        }

        // -------------------------------------------------------------------------
        // P/Invoke and struct definitions
        // -------------------------------------------------------------------------
        [Flags]
        private enum VIRTUAL_DISK_ACCESS_MASK : uint
        {
            NONE = 0,
            ATTACH_RO = 0x00010000,
            ATTACH_RW = 0x00020000,
            DETACH = 0x00040000,
            GET_INFO = 0x00080000,
            CREATE = 0x00100000,
            METAOPS = 0x00200000,
            READ = 0x000D0000,
            WRITE = 0x00020000,
            ALL = 0x003F0000
        }

        [Flags]
        private enum ATTACH_VIRTUAL_DISK_FLAG : uint
        {
            NONE = 0x00000000,
            READ_ONLY = 0x00000001,
            NO_DRIVE_LETTER = 0x00000002,
            PERMANENT_LIFETIME = 0x00000004,
            NO_LOCAL_HOST = 0x00000008
        }

        private enum ATTACH_VIRTUAL_DISK_VERSION
        {
            UNSPECIFIED = 0,
            WIN7 = 1,
            WIN8 = 2,
            WIN10 = 3
        }

        private enum OPEN_VIRTUAL_DISK_FLAG : uint
        {
            NONE = 0x00000000
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ATTACH_VIRTUAL_DISK_PARAMETERS
        {
            public ATTACH_VIRTUAL_DISK_VERSION Version;
            public uint Reserved;
        }

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
        private static extern int OpenVirtualDisk(
            IntPtr VirtualStorageType,
            string Path,
            VIRTUAL_DISK_ACCESS_MASK VirtualDiskAccessMask,
            OPEN_VIRTUAL_DISK_FLAG Flags,
            IntPtr Parameters,
            out SafeFileHandle Handle);

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
        private static extern int AttachVirtualDisk(
            SafeFileHandle VirtualDiskHandle,
            IntPtr SecurityDescriptor,
            ATTACH_VIRTUAL_DISK_FLAG Flags,
            uint ProviderSpecificFlags,
            ref ATTACH_VIRTUAL_DISK_PARAMETERS Parameters,
            IntPtr Overlapped);
    }
}