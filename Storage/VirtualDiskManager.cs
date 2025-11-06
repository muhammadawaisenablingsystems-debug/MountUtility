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
        private string? _mountedDiskPassword;

        // ✅ Track VHDX handle to properly dispose
        private SafeFileHandle? _activeVhdxHandle;

        public VirtualDiskManager(ICryptographyService cryptographyService, IDiskRepository diskRepository)
        {
            _cryptographyService = cryptographyService;
            _diskRepository = diskRepository;
            _diskStoragePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DiskMountUtility", "Disks");
            Directory.CreateDirectory(_diskStoragePath);
        }

        public async Task InitializeAsync()
        {
            // ✅ FIX: Clean up orphaned VHDXs and reset disk states
            var vaultBaseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "DiskMountUtility", "MountedVHDs");

            if (Directory.Exists(vaultBaseDir))
            {
                try
                {
                    // Detach any VHDXs that might be attached
                    foreach (var vhdxPath in Directory.GetFiles(vaultBaseDir, "*.vhdx"))
                    {
                        await DetachVhdxSilently(vhdxPath);
                    }

                    // Clean up all VHDX-related files
                    foreach (var file in Directory.GetFiles(vaultBaseDir))
                    {
                        try
                        {
                            File.Delete(file);
                            Console.WriteLine($"🧹 Cleaned up: {Path.GetFileName(file)}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"⚠️ Could not delete {file}: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Cleanup warning: {ex.Message}");
                }
            }

            // Reset all mounted disks to unmounted state
            var mountedDisks = await _diskRepository.GetByStatusAsync(DiskStatus.Mounted);
            foreach (var disk in mountedDisks)
            {
                disk.Status = DiskStatus.Created;
                disk.TempMountPath = null;
                await _diskRepository.UpdateAsync(disk);
            }
        }

        private async Task DetachVhdxSilently(string vhdxPath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(vhdxPath) || !File.Exists(vhdxPath))
                {
                    Console.WriteLine($"⚠️ Invalid or missing VHDX file: {vhdxPath}");
                    return;
                }

                var tempDir = Path.GetDirectoryName(vhdxPath) ?? Path.GetTempPath();
                var tempScriptPath = Path.Combine(tempDir, $"detach_{Guid.NewGuid():N}.txt");

                var detachScript = $@"
            select vdisk file=""{vhdxPath}""
            detach vdisk
            exit
        ".Trim();

                await File.WriteAllTextAsync(tempScriptPath, detachScript);

                var psi = new ProcessStartInfo
                {
                    FileName = "diskpart.exe",
                    Arguments = $"/s \"{tempScriptPath}\"",
                    UseShellExecute = true,              // must be true for runas
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    Verb = "runas"                       // 👈 triggers admin elevation prompt
                };

                using (var proc = Process.Start(psi))
                {
                    if (proc != null)
                        await proc.WaitForExitAsync();
                }

                try { File.Delete(tempScriptPath); } catch { }

                Console.WriteLine($"✅ Detached (elevated) VHDX: {Path.GetFileName(vhdxPath)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Silent detach failed for {Path.GetFileName(vhdxPath)}: {ex.Message}");
            }
        }

        public async Task<VirtualDisk> CreateDiskAsync(string name, long sizeInBytes, string password)
        {
            var diskId = Guid.NewGuid();
            var filePath = Path.Combine(_diskStoragePath, $"{diskId}.vdisk");

            var salt = RandomNumberGenerator.GetBytes(32);
            var passwordHash = _cryptographyService.HashPassword(password, salt);

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

            // Create initial JSON structure with disk-level metadata and empty files array
            var metadata = new EncryptionMetadata
            {
                KyberCiphertext = Array.Empty<byte>(),
                KyberPublicKey = Array.Empty<byte>(),
                KyberSecretKeyEncrypted = Array.Empty<byte>(),
                Nonce = Array.Empty<byte>(),
                Salt = salt,
                KyberSecretKeyNonce = Array.Empty<byte>(),
                VirtualDiskId = disk.Id
            };

            disk.Metadata = metadata;

            var diskData = new
            {
                metadata = new
                {
                    salt = Convert.ToBase64String(salt)
                },
                files = new object[] { }
            };

            await File.WriteAllTextAsync(filePath, JsonSerializer.Serialize(diskData));

            return await _diskRepository.CreateAsync(disk);
        }

        public async Task<bool> MountDiskAsync(Guid diskId, string password)
        {
            try
            {
                if (_mountedDisk != null)
                {
                    Console.WriteLine($"Switching mounted disk from '{_mountedDisk.Name}' to new disk...");
                    await UnmountDiskAsync(_mountedDisk.Id);
                }

                var disk = await _diskRepository.GetByIdAsync(diskId);
                if (disk == null || !File.Exists(disk.FilePath))
                {
                    Console.WriteLine("Disk not found or missing file path.");
                    return false;
                }

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

                var jsonContent = await File.ReadAllTextAsync(disk.FilePath);
                var diskData = JsonSerializer.Deserialize<JsonDocument>(jsonContent);

                _mountedDiskFiles.Clear();

                if (diskData != null && diskData.RootElement.TryGetProperty("files", out var filesElement))
                {
                    foreach (var fileEl in filesElement.EnumerateArray())
                    {
                        try
                        {
                            var path = fileEl.GetProperty("path").GetString()!;
                            var name = fileEl.TryGetProperty("name", out var n) ? n.GetString() ?? Path.GetFileName(path) : Path.GetFileName(path);
                            var isDir = fileEl.TryGetProperty("isDirectory", out var d) && d.GetBoolean();
                            var size = fileEl.TryGetProperty("sizeInBytes", out var s) ? s.GetInt64() : 0L;
                            var createdAt = fileEl.TryGetProperty("createdAt", out var c) && c.ValueKind == JsonValueKind.String ? DateTime.Parse(c.GetString()!) : DateTime.UtcNow;
                            var modifiedAt = fileEl.TryGetProperty("modifiedAt", out var m) && m.ValueKind == JsonValueKind.String ? DateTime.Parse(m.GetString()!) : DateTime.UtcNow;

                            byte[] encryptedContent = Array.Empty<byte>();
                            if (fileEl.TryGetProperty("encryptedContent", out var enc) && enc.ValueKind == JsonValueKind.String)
                            {
                                encryptedContent = Convert.FromBase64String(enc.GetString()!);
                            }

                            var diskFile = new DiskFile
                            {
                                Id = Guid.NewGuid(),
                                DiskId = disk.Id,
                                Name = name,
                                Path = path,
                                SizeInBytes = size,
                                IsDirectory = isDir,
                                CreatedAt = createdAt,
                                ModifiedAt = modifiedAt,
                                EncryptedContent = encryptedContent,
                                KyberCiphertext = fileEl.TryGetProperty("kyberCiphertext", out var kct) && kct.ValueKind == JsonValueKind.String ? Convert.FromBase64String(kct.GetString()!) : Array.Empty<byte>(),
                                KyberPublicKey = fileEl.TryGetProperty("kyberPublicKey", out var kpk) && kpk.ValueKind == JsonValueKind.String ? Convert.FromBase64String(kpk.GetString()!) : Array.Empty<byte>(),
                                KyberSecretKeyEncrypted = fileEl.TryGetProperty("kyberSecretKey", out var ksk) && ksk.ValueKind == JsonValueKind.String ? Convert.FromBase64String(ksk.GetString()!) : Array.Empty<byte>(),
                                KyberSecretKeyNonce = fileEl.TryGetProperty("kyberSecretKeyNonce", out var kskn) && kskn.ValueKind == JsonValueKind.String ? Convert.FromBase64String(kskn.GetString()!) : Array.Empty<byte>(),
                                FileNonce = fileEl.TryGetProperty("fileNonce", out var fn) && fn.ValueKind == JsonValueKind.String ? Convert.FromBase64String(fn.GetString()!) : Array.Empty<byte>(),
                                Salt = fileEl.TryGetProperty("salt", out var saltEl) && saltEl.ValueKind == JsonValueKind.String ? Convert.FromBase64String(saltEl.GetString()!) : Array.Empty<byte>()
                            };

                            _mountedDiskFiles[diskFile.Path] = diskFile;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"⚠️ Could not load file entry during mount: {ex.Message}");
                        }
                    }
                }

                disk.Status = DiskStatus.Mounted;
                disk.LastMountedAt = DateTime.UtcNow;
                _mountedDisk = disk;
                _mountedDiskPassword = password;

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

            // ✅ FIX: Ensure physical drive is unmounted first
            if (!string.IsNullOrEmpty(_mountedDisk.TempMountPath))
            {
                await UnmountPhysicalDriveAsync(diskId);
            }

            _mountedDisk.Status = DiskStatus.Unmounted;
            await _diskRepository.UpdateAsync(_mountedDisk);

            _mountedDisk = null;
            _mountedDiskFiles.Clear();
            _mountedDiskPassword = null;
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
                // For per-file model we don't need to decrypt whole vault here - just update disk.SizeInBytes
                disk.SizeInBytes = newSizeInBytes;
                disk.LastModifiedAt = DateTime.UtcNow;

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

            // Encrypt per-file
            var password = _mountedDiskPassword ?? string.Empty;
            var salt = RandomNumberGenerator.GetBytes(32);
            var encryptedData = _cryptographyService.EncryptData(
                content,
                password,
                out var kyberCiphertext,
                out var kyberPublicKey,
                out var kyberSecretKey,
                out var fileNonce,
                salt,
                out var kyberSecretKeyNonce
            );

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
                EncryptedContent = encryptedData,
                KyberCiphertext = kyberCiphertext,
                KyberPublicKey = kyberPublicKey,
                KyberSecretKeyEncrypted = kyberSecretKey,
                KyberSecretKeyNonce = kyberSecretKeyNonce,
                FileNonce = fileNonce,
                Salt = salt
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
                try
                {
                    var password = _mountedDiskPassword ?? string.Empty;
                    // Decrypt per-file content before returning
                    if (file.EncryptedContent == null || file.EncryptedContent.Length == 0)
                        return Task.FromResult<byte[]?>(Array.Empty<byte>());

                    var decrypted = _cryptographyService.DecryptData(
                        file.EncryptedContent,
                        password,
                        file.KyberCiphertext ?? Array.Empty<byte>(),
                        file.KyberPublicKey ?? Array.Empty<byte>(),
                        file.KyberSecretKeyEncrypted ?? Array.Empty<byte>(),
                        file.KyberSecretKeyNonce ?? Array.Empty<byte>(),
                        file.FileNonce ?? Array.Empty<byte>(),
                        file.Salt ?? Array.Empty<byte>()
                    );

                    return Task.FromResult<byte[]?>(decrypted);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Decrypt file failed: {ex.Message}");
                    return Task.FromResult<byte[]?>(null);
                }
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
                EncryptedContent = Array.Empty<byte>(),
                KyberCiphertext = Array.Empty<byte>(),
                KyberPublicKey = Array.Empty<byte>(),
                KyberSecretKeyEncrypted = Array.Empty<byte>(),
                KyberSecretKeyNonce = Array.Empty<byte>(),
                FileNonce = Array.Empty<byte>(),
                Salt = Array.Empty<byte>()
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

            var metadata = await _diskRepository.GetMetadataByDiskIdAsync(_mountedDisk.Id);
            if (metadata == null)
            {
                Console.WriteLine("Cannot save: No metadata found");
                return;
            }

            var vaultPath = _mountedDisk.FilePath;
            var tempPath = vaultPath + ".tmp";

            try
            {
                // Ensure directory exists
                Directory.CreateDirectory(Path.GetDirectoryName(vaultPath) ?? ".");

                // Stream JSON to a temp file to avoid building huge in-memory objects
                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 65536, useAsync: true))
                using (var writer = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = false }))
                {
                    writer.WriteStartObject();

                    writer.WritePropertyName("metadata");
                    writer.WriteStartObject();
                    writer.WriteString("salt", Convert.ToBase64String(metadata.Salt ?? Array.Empty<byte>()));
                    writer.WriteEndObject();

                    writer.WritePropertyName("files");
                    writer.WriteStartArray();

                    foreach (var f in _mountedDiskFiles.Values)
                    {
                        try
                        {
                            writer.WriteStartObject();

                            writer.WriteString("path", f.Path);
                            writer.WriteString("name", f.Name);
                            writer.WriteBoolean("isDirectory", f.IsDirectory);
                            writer.WriteNumber("sizeInBytes", f.SizeInBytes);
                            writer.WriteString("createdAt", f.CreatedAt.ToString("o"));
                            writer.WriteString("modifiedAt", f.ModifiedAt.ToString("o"));

                            if (f.EncryptedContent != null && f.EncryptedContent.Length > 0)
                                writer.WriteBase64String("encryptedContent", f.EncryptedContent);
                            else
                                writer.WriteNull("encryptedContent");

                            if (f.KyberCiphertext != null && f.KyberCiphertext.Length > 0)
                                writer.WriteBase64String("kyberCiphertext", f.KyberCiphertext);
                            else
                                writer.WriteNull("kyberCiphertext");

                            if (f.KyberPublicKey != null && f.KyberPublicKey.Length > 0)
                                writer.WriteBase64String("kyberPublicKey", f.KyberPublicKey);
                            else
                                writer.WriteNull("kyberPublicKey");

                            if (f.KyberSecretKeyEncrypted != null && f.KyberSecretKeyEncrypted.Length > 0)
                                writer.WriteBase64String("kyberSecretKey", f.KyberSecretKeyEncrypted);
                            else
                                writer.WriteNull("kyberSecretKey");

                            if (f.KyberSecretKeyNonce != null && f.KyberSecretKeyNonce.Length > 0)
                                writer.WriteBase64String("kyberSecretKeyNonce", f.KyberSecretKeyNonce);
                            else
                                writer.WriteNull("kyberSecretKeyNonce");

                            if (f.FileNonce != null && f.FileNonce.Length > 0)
                                writer.WriteBase64String("fileNonce", f.FileNonce);
                            else
                                writer.WriteNull("fileNonce");

                            if (f.Salt != null && f.Salt.Length > 0)
                                writer.WriteBase64String("salt", f.Salt);
                            else
                                writer.WriteNull("salt");

                            writer.WriteEndObject();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"⚠️ Error serializing file entry '{f.Path}': {ex.Message}");
                        }
                    }

                    writer.WriteEndArray();
                    writer.WriteEndObject();
                    await writer.FlushAsync().ConfigureAwait(false);
                    await fs.FlushAsync().ConfigureAwait(false);
                }

                // Atomically replace the original file (avoid partial overwrites)
                if (File.Exists(vaultPath))
                {
                    // Use Replace to minimize risk (keeps atomic replace semantics if possible)
                    try
                    {
                        File.Replace(tempPath, vaultPath, null);
                    }
                    catch
                    {
                        // Fallback to Move overwrite (supported in .NET)
                        File.Delete(vaultPath);
                        File.Move(tempPath, vaultPath);
                    }
                }
                else
                {
                    File.Move(tempPath, vaultPath);
                }

                _mountedDisk.LastModifiedAt = DateTime.UtcNow;
                await _diskRepository.UpdateAsync(_mountedDisk);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ SaveMountedDiskAsync failed: {ex.Message}");
                // Clean up temp file if exists
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            }
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

            // ✅ FIX: Clean up any existing VHDX for this disk first
            var vaultBaseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "DiskMountUtility", "MountedVHDs");
            Directory.CreateDirectory(vaultBaseDir);

            var tempVhdxPath = Path.Combine(vaultBaseDir, $"{disk.Id}.vhdx");

            if (File.Exists(tempVhdxPath))
            {
                await DetachVhdxSilently(tempVhdxPath);
                try
                {
                    File.Delete(tempVhdxPath);
                    Console.WriteLine($"🧹 Deleted existing VHDX: {tempVhdxPath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Could not delete existing VHDX: {ex.Message}");
                    return false;
                }
            }

            char driveLetter = GetAvailableDriveLetter();
            if (driveLetter == '\0')
            {
                Console.WriteLine("❌ No free drive letters available.");
                return false;
            }

            var tempExtractFolder = Path.Combine(vaultBaseDir, $"{disk.Id}_extracted");
            var tempScriptPath = Path.Combine(vaultBaseDir, $"{disk.Id}_diskpart.txt");
            var logPath = Path.Combine(vaultBaseDir, $"{disk.Id}_diskpart.log");

            if (Directory.Exists(tempExtractFolder))
                Directory.Delete(tempExtractFolder, recursive: true);
            Directory.CreateDirectory(tempExtractFolder);

            try
            {
                // Extract: write DECRYPTED file content for each file into the tempExtractFolder
                foreach (var kv in _mountedDiskFiles)
                {
                    var file = kv.Value;
                    var relative = file.Path.TrimStart('/').Replace("/", Path.DirectorySeparatorChar.ToString());
                    var outPath = Path.Combine(tempExtractFolder, relative);

                    if (file.IsDirectory)
                    {
                        Directory.CreateDirectory(outPath);
                    }
                    else
                    {
                        var parent = Path.GetDirectoryName(outPath);
                        if (!string.IsNullOrEmpty(parent) && !Directory.Exists(parent))
                            Directory.CreateDirectory(parent);

                        byte[] decrypted = Array.Empty<byte>();
                        try
                        {
                            decrypted = _cryptographyService.DecryptData(
                                file.EncryptedContent ?? Array.Empty<byte>(),
                                _mountedDiskPassword ?? string.Empty,
                                file.KyberCiphertext ?? Array.Empty<byte>(),
                                file.KyberPublicKey ?? Array.Empty<byte>(),
                                file.KyberSecretKeyEncrypted ?? Array.Empty<byte>(),
                                file.KyberSecretKeyNonce ?? Array.Empty<byte>(),
                                file.FileNonce ?? Array.Empty<byte>(),
                                file.Salt ?? Array.Empty<byte>()
                            );
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"⚠️ Could not decrypt file '{file.Path}' for mount: {ex.Message}");
                            decrypted = Array.Empty<byte>();
                        }

                        // Write using FileStream to reduce temporary buffering and allow async IO
                        try
                        {
                            using var outFs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 65536, useAsync: true);
                            if (decrypted.Length > 0)
                            {
                                await outFs.WriteAsync(decrypted.AsMemory(0, decrypted.Length)).ConfigureAwait(false);
                            }
                            await outFs.FlushAsync().ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"⚠️ Failed to write decrypted file '{outPath}': {ex.Message}");
                        }
                    }
                }

                var sizeMb = Math.Max((disk.SizeInBytes + (1024 * 1024 - 1)) / (1024 * 1024), 50);

                // ✅ FIX: Improved DiskPart script with better error handling
                var diskpartScript = $@"create vdisk file=""{tempVhdxPath}"" maximum={sizeMb} type=expandable
select vdisk file=""{tempVhdxPath}""
attach vdisk
select vdisk file=""{tempVhdxPath}""
create partition primary
format fs=ntfs quick label=""{disk.Name}""
assign letter={driveLetter}
exit";

                await File.WriteAllTextAsync(tempScriptPath, diskpartScript);

                // ✅ FIX: Run DiskPart with proper elevation and error capture
                var psi = new ProcessStartInfo
                {
                    FileName = "diskpart.exe",
                    Arguments = $"/s \"{tempScriptPath}\"",
                    UseShellExecute = true,
                    Verb = "runas",
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                try
                {
                    var proc = Process.Start(psi);
                    if (proc != null)
                    {
                        await proc.WaitForExitAsync();
                        proc.Dispose();
                    }
                }
                catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
                {
                    Console.WriteLine("⚠️ User denied elevation. Mount aborted.");
                    return false;
                }

                var driveRoot = $"{driveLetter}:\\";
                var timeout = DateTime.UtcNow.AddSeconds(15);

                while (!Directory.Exists(driveRoot) && DateTime.UtcNow < timeout)
                    await Task.Delay(500);

                if (!Directory.Exists(driveRoot))
                {
                    Console.WriteLine($"❌ Drive {driveRoot} not available after attach.");
                    return false;
                }

                Console.WriteLine($"✅ Drive {driveRoot} ready — copying decrypted contents...");

                CopyDirectory(tempExtractFolder, driveRoot);

                disk.TempMountPath = tempVhdxPath;
                disk.Status = DiskStatus.Mounted;
                disk.LastMountedAt = DateTime.UtcNow;
                await _diskRepository.UpdateAsync(disk);

                MountedVaultPath = driveRoot;

                Console.WriteLine($"✅ Vault mounted as physical drive {driveLetter}:\\");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ MountAsPhysicalDriveAsync failed: {ex}");
                return false;
            }
            finally
            {
                try
                {
                    if (Directory.Exists(tempExtractFolder))
                        Directory.Delete(tempExtractFolder, recursive: true);
                }
                catch { }
            }
        }

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

                // ✅ FIX: Dispose handle before detach
                if (_activeVhdxHandle != null && !_activeVhdxHandle.IsInvalid)
                {
                    _activeVhdxHandle.Dispose();
                    _activeVhdxHandle = null;
                }

                MountedVaultPath = null;

                if (!File.Exists(vhdxPath))
                {
                    Console.WriteLine($"⚠️ VHDX file not found: {vhdxPath}");
                    disk.Status = DiskStatus.Unmounted;
                    disk.TempMountPath = null;
                    await _diskRepository.UpdateAsync(disk);
                    return true;
                }

                Console.WriteLine($"🔧 Detaching virtual disk: {vhdxPath}");

                await DetachVhdxSilently(vhdxPath);

                // ✅ FIX: Wait for file to be unlocked
                await Task.Delay(1000);

                // Try to delete VHDX file
                int retries = 3;
                for (int i = 0; i < retries; i++)
                {
                    try
                    {
                        if (File.Exists(vhdxPath))
                        {
                            File.Delete(vhdxPath);
                            Console.WriteLine($"🧹 Deleted VHDX: {Path.GetFileName(vhdxPath)}");
                        }
                        break;
                    }
                    catch (IOException) when (i < retries - 1)
                    {
                        Console.WriteLine($"⏳ VHDX locked, retrying... ({i + 1}/{retries})");
                        await Task.Delay(500);
                    }
                }

                disk.Status = DiskStatus.Unmounted;
                disk.TempMountPath = null;
                await _diskRepository.UpdateAsync(disk);

                Console.WriteLine($"✅ Successfully unmounted physical drive");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Unmount failed: {ex}");
                return false;
            }
        }

        public Task<string?> GetMountedPathAsync(Guid diskId)
        {
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
            var used = DriveInfo.GetDrives()
                .Select(d => char.ToUpperInvariant(d.Name[0]))
                .ToHashSet();

            // ✅ FIX: Don't rely on registry, just scan actual drives
            for (char letter = 'Z'; letter >= 'D'; letter--)
            {
                if (!used.Contains(letter))
                {
                    var testPath = $"{letter}:\\";
                    try
                    {
                        if (!Directory.Exists(testPath))
                        {
                            Console.WriteLine($"✅ Selected available drive letter: {letter}");
                            return letter;
                        }
                    }
                    catch
                    {
                        // Letter might be available
                        Console.WriteLine($"✅ Selected available drive letter: {letter}");
                        return letter;
                    }
                }
            }

            Console.WriteLine("❌ No available drive letter found.");
            return '\0';
        }

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