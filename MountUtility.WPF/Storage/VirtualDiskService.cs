using Microsoft.Win32.SafeHandles;
using MountUtility.WPF.Cryptography;
using MountUtility.WPF.Entities;
using MountUtility.WPF.Enums;
using MountUtility.WPF.Interfaces;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace DiskMountUtility.Infrastructure.Storage
{
    public class VirtualDiskService : IVirtualDiskService
    {
        private readonly ICryptographyService _cryptographyService;
        private readonly IDiskRepository _diskRepository;
        private readonly string _diskStoragePath;
        private static VirtualDisk? _mountedDisk;
        private static Dictionary<string, DiskFile> _mountedDiskFiles = new();
        public string? MountedVaultPath { get; private set; }
        private static string? _mountedDiskPassword;
        private const int NonceSize = 12;

        // ✅ Track VHDX handle to properly dispose
        private SafeFileHandle? _activeVhdxHandle;

        public VirtualDiskService(ICryptographyService cryptographyService, IDiskRepository diskRepository)
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

            // Pick algorithm from user's preference
            var algo = VaultKeyManager.SelectedKeyExchange == KeyExchangeAlgorithm.EcdhP256
                ? EncryptionAlgorithm.EcdhP256AesGcm256
                : EncryptionAlgorithm.KyberAesGcm256;

            var disk = new VirtualDisk
            {
                Id = diskId,
                Name = name,
                SizeInBytes = sizeInBytes,
                UsedSpaceInBytes = 0,
                Status = DiskStatus.Created,
                EncryptionAlgorithm = algo,
                FilePath = filePath,
                CreatedAt = DateTime.UtcNow,
                PasswordHash = passwordHash
            };

            var metadata = new EncryptionMetadata
            {
                Salt = salt,
                VirtualDiskId = disk.Id
            };

            // If ECDH selected generate recipient keypair and persist public + encrypted private
            if (algo == EncryptionAlgorithm.EcdhP256AesGcm256)
            {
                var (ecdhPub, ecdhPriv) = _cryptographyService.GenerateEcdhKeyPair();
                metadata.EcdhPublicKey = ecdhPub;
                metadata.EcdhPrivateKeyNonce = RandomNumberGenerator.GetBytes(NonceSize);
                var passwordKey = _cryptographyService.DerivePasswordKey(password, salt);
                metadata.EcdhPrivateKeyEncrypted = _cryptographyService.EncryptKyberSecretKey(ecdhPriv, passwordKey, metadata.EcdhPrivateKeyNonce);
            }
            else
            {
                // Kyber defaults left empty; per-file Kyber keys are created when writing a file.
                metadata.KyberCiphertext = Array.Empty<byte>();
                metadata.KyberPublicKey = Array.Empty<byte>();
                metadata.KyberSecretKeyEncrypted = Array.Empty<byte>();
                metadata.KyberSecretKeyNonce = Array.Empty<byte>();
            }

            disk.Metadata = metadata;

            var diskData = new
            {
                metadata = new
                {
                    salt = Convert.ToBase64String(salt),
                    algorithm = algo.ToString(),
                    ecdhPublicKey = metadata.EcdhPublicKey.Length > 0 ? Convert.ToBase64String(metadata.EcdhPublicKey) : null
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
                    // Inside MountDiskAsync, in the file loading loop:
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
                                EcdhEphemeralPublic = fileEl.TryGetProperty("ecdhEphemeralPublic", out var eep) && eep.ValueKind == JsonValueKind.String ? Convert.FromBase64String(eep.GetString()!) : Array.Empty<byte>(),
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
                return Task.FromResult(new List<DiskFile>());

            string normalized = path.TrimEnd('/');

            var result = _mountedDiskFiles.Values
                .Where(f =>
                {
                    var parent = Path.GetDirectoryName(f.Path.Replace("\\", "/"))?.Replace("\\", "/") ?? "/";
                    parent = parent.TrimEnd('/');
                    return parent == normalized;
                })
                .ToList();

            return Task.FromResult(result);
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
            byte[] encryptedData;
            byte[] fileNonce = Array.Empty<byte>();
            byte[] kyberCiphertext = Array.Empty<byte>();
            byte[] kyberPublicKey = Array.Empty<byte>();
            byte[] kyberSecretKeyEncrypted = Array.Empty<byte>();
            byte[] kyberSecretKeyNonce = Array.Empty<byte>();
            byte[] ecdhEphemeralPublic = Array.Empty<byte>();

            var metadata = await _diskRepository.GetMetadataByDiskIdAsync(diskId);
            if (metadata == null)
            {
                Console.WriteLine("No metadata found for disk.");
                return false;
            }

            if (_mountedDisk.EncryptionAlgorithm == EncryptionAlgorithm.EcdhP256AesGcm256)
            {
                // Use disk-level ECDH recipient public key
                encryptedData = _cryptographyService.EncryptDataEcdh(content, password, metadata.EcdhPublicKey, out ecdhEphemeralPublic, out fileNonce, salt);
            }
            else
            {
                encryptedData = _cryptographyService.EncryptData(
                    content,
                    password,
                    out kyberCiphertext,
                    out kyberPublicKey,
                    out kyberSecretKeyEncrypted,
                    out fileNonce,
                    salt,
                    out kyberSecretKeyNonce);
            }

            // create DiskFile and set fields
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
                KyberSecretKeyEncrypted = kyberSecretKeyEncrypted,
                KyberSecretKeyNonce = kyberSecretKeyNonce,
                EcdhEphemeralPublic = ecdhEphemeralPublic,
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

        public async Task<byte[]?> ReadFileAsync(Guid diskId, string path)
        {
            if (_mountedDisk == null || _mountedDisk.Id != diskId)
            {
                return await Task.FromResult<byte[]?>(null);
            }

            if (_mountedDiskFiles.TryGetValue(path, out var file))
            {
                try
                {
                    var password = _mountedDiskPassword ?? string.Empty;

                    if (file.EncryptedContent == null || file.EncryptedContent.Length == 0)
                        return await Task.FromResult<byte[]?>(Array.Empty<byte>());

                    var metadata = await _diskRepository.GetMetadataByDiskIdAsync(diskId);
                    if (metadata == null)
                        throw new InvalidOperationException("Missing metadata");

                    byte[] decrypted;

                    if (_mountedDisk.EncryptionAlgorithm == EncryptionAlgorithm.EcdhP256AesGcm256)
                    {
                        // ECDH decryption path
                        try
                        {
                            // IMPORTANT: use disk-level salt (metadata.Salt) to derive password key for decrypting recipient private key.
                            // Passing per-file salt here caused wrong key derivation and AES-GCM tag mismatch.
                            decrypted = _cryptographyService.DecryptDataEcdh(
                                file.EncryptedContent,
                                password,
                                file.EcdhEphemeralPublic ?? Array.Empty<byte>(),
                                metadata.EcdhPrivateKeyEncrypted ?? Array.Empty<byte>(),
                                metadata.EcdhPrivateKeyNonce ?? Array.Empty<byte>(),
                                file.FileNonce ?? Array.Empty<byte>(),          // diskNonce
                                metadata.Salt ?? Array.Empty<byte>(),           // diskSalt (used to derive password key to decrypt recipient private key)
                                file.Salt ?? Array.Empty<byte>()                // fileSalt (used to derive AES key for file content)
                            );
                        }
                        catch (CryptographicException cex)
                        {
                            Console.WriteLine($"❌ ECDH decrypt failed (cryptographic/tag error): {cex.Message}. lengths: enc={file.EncryptedContent?.Length}, eph={file.EcdhEphemeralPublic?.Length}, privEnc={metadata.EcdhPrivateKeyEncrypted?.Length}, privNonce={metadata.EcdhPrivateKeyNonce?.Length}, fileNonce={file.FileNonce?.Length}, diskSalt={metadata.Salt?.Length}");
                            throw;
                        }
                    }
                    else
                    {
                        // Kyber decryption path
                        decrypted = _cryptographyService.DecryptData(
                            file.EncryptedContent,
                            password,
                            file.KyberCiphertext ?? Array.Empty<byte>(),
                            file.KyberPublicKey ?? Array.Empty<byte>(),
                            file.KyberSecretKeyEncrypted ?? Array.Empty<byte>(),
                            file.KyberSecretKeyNonce ?? Array.Empty<byte>(),
                            file.FileNonce ?? Array.Empty<byte>(),
                            file.Salt ?? Array.Empty<byte>()
                        );
                    }

                    return await Task.FromResult<byte[]?>(decrypted);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Decrypt file failed: {ex.Message}");
                    return await Task.FromResult<byte[]?>(null);
                }
            }

            return await Task.FromResult<byte[]?>(null);
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

                // If directory, also remove all children
                if (file.IsDirectory)
                {
                    var childrenToRemove = _mountedDiskFiles.Keys
                        .Where(p => p.StartsWith(path.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    foreach (var childPath in childrenToRemove)
                    {
                        if (_mountedDiskFiles.TryGetValue(childPath, out var childFile))
                        {
                            _mountedDisk.UsedSpaceInBytes -= childFile.SizeInBytes;
                            _mountedDiskFiles.Remove(childPath);
                        }
                    }
                }

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

            // Normalize path
            path = path.Replace("\\", "/").TrimEnd('/');
            if (!path.StartsWith("/")) path = "/" + path;

            // Skip if already exists
            if (_mountedDiskFiles.ContainsKey(path))
            {
                Console.WriteLine($"Directory already exists: {path}");
                return true;
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

            // Also create the directory in the mounted physical drive (if mounted)
            if (!string.IsNullOrEmpty(MountedVaultPath))
            {
                try
                {
                    var physicalPath = MountedVaultPath.TrimEnd('\\') + path.Replace("/", "\\");
                    if (!Directory.Exists(physicalPath))
                    {
                        Directory.CreateDirectory(physicalPath);
                        Console.WriteLine($"✅ Created directory in vault and physical drive: {path}");
                    }
                    else
                    {
                        Console.WriteLine($"✅ Created directory in vault (already exists physically): {path}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Failed to create physical directory: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine($"✅ Created directory in vault: {path}");
            }

            return true;
        }

        public async Task<bool> RenameFileAsync(Guid diskId, string oldPath, string newPath)
        {
            if (_mountedDisk == null || _mountedDisk.Id != diskId)
            {
                return false;
            }

            oldPath = oldPath.Replace("\\", "/");
            newPath = newPath.Replace("\\", "/");

            if (!_mountedDiskFiles.TryGetValue(oldPath, out var file))
            {
                Console.WriteLine($"⚠️ File not found for rename: {oldPath}");
                return false;
            }

            _mountedDiskFiles.Remove(oldPath);

            file.Path = newPath;
            file.Name = Path.GetFileName(newPath);
            file.ModifiedAt = DateTime.UtcNow;

            _mountedDiskFiles[newPath] = file;

            // If directory, update all children paths
            if (file.IsDirectory)
            {
                var oldPrefix = oldPath.TrimEnd('/') + "/";
                var newPrefix = newPath.TrimEnd('/') + "/";

                var childrenToUpdate = _mountedDiskFiles
                    .Where(kv => kv.Key.StartsWith(oldPrefix, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                foreach (var child in childrenToUpdate)
                {
                    var childFile = child.Value;
                    var updatedPath = newPrefix + child.Key.Substring(oldPrefix.Length);

                    _mountedDiskFiles.Remove(child.Key);
                    childFile.Path = updatedPath;
                    childFile.ModifiedAt = DateTime.UtcNow;
                    _mountedDiskFiles[updatedPath] = childFile;
                }
            }

            _mountedDisk.LastModifiedAt = DateTime.UtcNow;
            await SaveMountedDiskAsync();
            Console.WriteLine($"✅ Renamed in vault: {oldPath} → {newPath}");
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
                Directory.CreateDirectory(Path.GetDirectoryName(vaultPath) ?? ".");

                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 65536, useAsync: true))
                using (var writer = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = false }))
                {
                    writer.WriteStartObject();

                    // metadata (salt + ecdhPublicKey when present)
                    writer.WritePropertyName("metadata");
                    writer.WriteStartObject();
                    writer.WriteString("salt", Convert.ToBase64String(metadata.Salt ?? Array.Empty<byte>()));

                    if (metadata.EcdhPublicKey != null && metadata.EcdhPublicKey.Length > 0)
                        writer.WriteBase64String("ecdhPublicKey", metadata.EcdhPublicKey);
                    else
                        writer.WriteNull("ecdhPublicKey");

                    writer.WriteEndObject();

                    // files
                    writer.WritePropertyName("files");
                    writer.WriteStartArray();

                    // In SaveMountedDiskAsync, inside the foreach loop writing file entries:
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

                            // Write Kyber fields only if used
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

                            // Write ECDH per-file ephemeral public key
                            if (f.EcdhEphemeralPublic != null && f.EcdhEphemeralPublic.Length > 0)
                                writer.WriteBase64String("ecdhEphemeralPublic", f.EcdhEphemeralPublic);
                            else
                                writer.WriteNull("ecdhEphemeralPublic");

                            // Common per-file fields
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

                // atomic replace
                if (File.Exists(vaultPath))
                {
                    try { File.Replace(tempPath, vaultPath, null); }
                    catch { File.Delete(vaultPath); File.Move(tempPath, vaultPath); }
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
                            var metadata = await _diskRepository.GetMetadataByDiskIdAsync(diskId);
                            if (metadata == null)
                                throw new InvalidOperationException("Missing metadata");

                            if (disk.EncryptionAlgorithm == EncryptionAlgorithm.EcdhP256AesGcm256)
                            {
                                // ECDH decryption
                                try
                                {
                                    // IMPORTANT: pass disk-level salt (metadata.Salt) when decrypting ECDH so the private key can be decrypted correctly.
                                    decrypted = _cryptographyService.DecryptDataEcdh(
                                        file.EncryptedContent ?? Array.Empty<byte>(),
                                        _mountedDiskPassword ?? string.Empty,
                                        file.EcdhEphemeralPublic ?? Array.Empty<byte>(),
                                        metadata.EcdhPrivateKeyEncrypted ?? Array.Empty<byte>(),
                                        metadata.EcdhPrivateKeyNonce ?? Array.Empty<byte>(),
                                        file.FileNonce ?? Array.Empty<byte>(),          // diskNonce
                                        metadata.Salt ?? Array.Empty<byte>(),           // diskSalt
                                        file.Salt ?? Array.Empty<byte>()                // fileSalt
                                    );
                                }
                                catch (CryptographicException cex)
                                {
                                    Console.WriteLine($"⚠️ ECDH decrypt failed for '{file.Path}': {cex.Message}. lengths -> enc={file.EncryptedContent?.Length}, eph={file.EcdhEphemeralPublic?.Length}, privEnc={metadata.EcdhPrivateKeyEncrypted?.Length}, diskSalt={metadata.Salt?.Length}");
                                    decrypted = Array.Empty<byte>();
                                }
                            }
                            else
                            {
                                // Kyber decryption
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
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"⚠️ Could not decrypt file '{file.Path}' for mount: {ex.Message}");
                            decrypted = Array.Empty<byte>();
                        }

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

                NotifyExplorerMountComplete(driveRoot, driveLetter);

                disk.TempMountPath = tempVhdxPath;
                disk.Status = DiskStatus.Mounted;
                disk.LastMountedAt = DateTime.UtcNow;
                await _diskRepository.UpdateAsync(disk);

                MountedVaultPath = driveRoot;

                Console.WriteLine($"✅ Vault mounted as physical drive {driveLetter}:\\")
; return true;
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

        private void NotifyExplorerMountComplete(string drivePath, char driveLetter)
        {
            try
            {
                Console.WriteLine($"🔔 Notifying Explorer of mount completion: {drivePath}");

                // Multiple notification events for best coverage
                IntPtr pathPtr = Marshal.StringToHGlobalUni(drivePath);
                try
                {
                    // 1. Update directory (most important for showing files)
                    SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATH | SHCNF_FLUSH, pathPtr, IntPtr.Zero);

                    // 2. Media inserted event
                    SHChangeNotify(SHCNE_MEDIAINSERTED, SHCNF_PATH | SHCNF_FLUSH, pathPtr, IntPtr.Zero);

                    // 3. Association changed (global refresh)
                    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
                }
                finally
                {
                    Marshal.FreeHGlobal(pathPtr);
                }

                // 4. Additional drive-specific refresh
                RefreshDriveInExplorer(driveLetter);

                Console.WriteLine($"✅ Explorer notified successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Explorer notification failed: {ex.Message}");
            }
        }

        private void RefreshDriveInExplorer(char driveLetter)
        {
            try
            {
                // Force refresh of the specific drive
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c echo ^< ^> | out-null & dir {driveLetter}:\\ >nul",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };

                using (var process = Process.Start(psi))
                {
                    process?.WaitForExit(1000);
                }
            }
            catch { }
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

        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        private static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);

        private const int SHCNE_ASSOCCHANGED = 0x08000000;
        private const int SHCNE_UPDATEDIR = 0x00001000;
        private const int SHCNE_MEDIAINSERTED = 0x00000020;
        private const uint SHCNF_IDLIST = 0x0000;
        private const uint SHCNF_PATH = 0x0001;
        private const uint SHCNF_FLUSH = 0x1000;
    }
}