using DiskMountUtility.Core.Entities;
using DiskMountUtility.Core.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DiskMountUtility.Application.Services
{
    public class RealtimeVaultSyncService
    {
        private readonly ICryptographyService _cryptographyService;
        private readonly IDiskRepository _diskRepository;
        private readonly SemaphoreSlim _syncLock = new(1, 1);

        private Guid? _activeDiskId;
        private string? _activePassword;
        private string? _activeMountPath;
        private bool _isSyncing;

        public RealtimeVaultSyncService(
            ICryptographyService cryptographyService,
            IDiskRepository diskRepository)
        {
            _cryptographyService = cryptographyService;
            _diskRepository = diskRepository;
        }

        public void Initialize(Guid diskId, string password, string mountPath)
        {
            _activeDiskId = diskId;
            _activePassword = password;
            _activeMountPath = mountPath;

            Console.WriteLine($"✅ Realtime Sync initialized for disk {diskId}");
        }

        public void Shutdown()
        {
            _activeDiskId = null;
            _activePassword = null;
            _activeMountPath = null;

            Console.WriteLine("⛔ Realtime Sync shutdown");
        }

        public async Task SyncFileChangeAsync(string fullPath, FileChangeType changeType, string? oldPath = null)
        {
            if (!_activeDiskId.HasValue || string.IsNullOrEmpty(_activePassword) || string.IsNullOrEmpty(_activeMountPath))
            {
                Console.WriteLine("⚠️ Sync skipped: Not initialized");
                return;
            }

            // Prevent recursive syncing and debounce rapid changes
            if (_isSyncing)
            {
                Console.WriteLine($"⏳ Sync already in progress, queuing: {Path.GetFileName(fullPath)}");
                return;
            }

            await _syncLock.WaitAsync();

            try
            {
                _isSyncing = true;

                Console.WriteLine($"🔄 Syncing {changeType}: {Path.GetFileName(fullPath)}");

                var disk = await _diskRepository.GetByIdAsync(_activeDiskId.Value);
                if (disk == null)
                {
                    Console.WriteLine("❌ Disk not found");
                    return;
                }

                var metadata = await _diskRepository.GetMetadataByDiskIdAsync(_activeDiskId.Value);
                if (metadata == null)
                {
                    Console.WriteLine("❌ Metadata not found");
                    return;
                }

                // Scan entire drive to get current state
                var allFiles = ScanPhysicalDrive(_activeMountPath);

                // Serialize and encrypt
                var dataToEncrypt = new { files = allFiles };
                var jsonData = JsonSerializer.SerializeToUtf8Bytes(dataToEncrypt);

                var encryptedData = _cryptographyService.EncryptData(
                    jsonData,
                    _activePassword,
                    out var kyberCiphertext,
                    out var kyberPublicKey,
                    out var kyberSecretKey,
                    out var nonce,
                    metadata.Salt,
                    out var kyberSecretKeyNonce
                );

                // Update metadata
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
                    encryptedContent = Convert.ToBase64String(encryptedData)
                };

                // Write to vault file atomically
                var tempVaultPath = disk.FilePath + ".tmp";
                await File.WriteAllTextAsync(tempVaultPath, JsonSerializer.Serialize(updatedDiskData));

                // Atomic replace
                File.Move(tempVaultPath, disk.FilePath, overwrite: true);

                // Update disk space usage
                long totalSize = allFiles.Where(f => !f.IsDirectory).Sum(f => f.SizeInBytes);
                disk.UsedSpaceInBytes = totalSize;
                disk.LastModifiedAt = DateTime.UtcNow;
                await _diskRepository.UpdateAsync(disk);

                Console.WriteLine($"✅ Synced to vault: {allFiles.Count} items, {FormatBytes(totalSize)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Sync failed: {ex.Message}");
            }
            finally
            {
                _isSyncing = false;
                _syncLock.Release();
            }
        }

        private List<DiskFile> ScanPhysicalDrive(string mountedPath)
        {
            var files = new List<DiskFile>();

            if (!Directory.Exists(mountedPath))
            {
                Console.WriteLine($"⚠️ Mount path does not exist: {mountedPath}");
                return files;
            }

            var basePathLength = mountedPath.TrimEnd('\\', '/').Length;
            ScanDirectory(mountedPath, basePathLength, files);

            return files;
        }

        private void ScanDirectory(string currentPath, int basePathLength, List<DiskFile> files)
        {
            try
            {
                // Scan directories
                foreach (var dirPath in Directory.GetDirectories(currentPath))
                {
                    var dirInfo = new DirectoryInfo(dirPath);

                    if (ShouldSkipSystemFile(dirInfo.Name))
                        continue;

                    var relativePath = GetRelativePath(dirPath, basePathLength);

                    files.Add(new DiskFile
                    {
                        Id = Guid.NewGuid(),
                        DiskId = _activeDiskId!.Value,
                        Name = dirInfo.Name,
                        Path = relativePath,
                        SizeInBytes = 0,
                        IsDirectory = true,
                        CreatedAt = dirInfo.CreationTimeUtc,
                        ModifiedAt = dirInfo.LastWriteTimeUtc,
                        EncryptedContent = Array.Empty<byte>()
                    });

                    ScanDirectory(dirPath, basePathLength, files);
                }

                // Scan files
                foreach (var filePath in Directory.GetFiles(currentPath))
                {
                    var fileInfo = new FileInfo(filePath);

                    if (ShouldSkipSystemFile(fileInfo.Name))
                        continue;

                    var relativePath = GetRelativePath(filePath, basePathLength);
                    byte[] content = Array.Empty<byte>();

                    try
                    {
                        // Read file content with retry for locked files
                        content = ReadFileWithRetry(filePath);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"⚠️ Could not read {fileInfo.Name}: {ex.Message}");
                        continue;
                    }

                    files.Add(new DiskFile
                    {
                        Id = Guid.NewGuid(),
                        DiskId = _activeDiskId!.Value,
                        Name = fileInfo.Name,
                        Path = relativePath,
                        SizeInBytes = fileInfo.Length,
                        IsDirectory = false,
                        CreatedAt = fileInfo.CreationTimeUtc,
                        ModifiedAt = fileInfo.LastWriteTimeUtc,
                        EncryptedContent = content
                    });
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Skip directories we can't access
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Error scanning {currentPath}: {ex.Message}");
            }
        }

        private byte[] ReadFileWithRetry(string filePath, int maxRetries = 3)
        {
            for (int i = 0; i < maxRetries; i++)
            {
                try
                {
                    using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var ms = new MemoryStream();
                    stream.CopyTo(ms);
                    return ms.ToArray();
                }
                catch (IOException) when (i < maxRetries - 1)
                {
                    Thread.Sleep(100); // Wait before retry
                }
            }

            throw new IOException($"Could not read file after {maxRetries} attempts");
        }

        private string GetRelativePath(string fullPath, int basePathLength)
        {
            var relativePath = fullPath.Substring(basePathLength)
                .TrimStart('\\', '/')
                .Replace("\\", "/");

            return "/" + relativePath;
        }

        private bool ShouldSkipSystemFile(string name)
        {
            return name.StartsWith("$") ||
                   name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase) ||
                   name.StartsWith("~$", StringComparison.OrdinalIgnoreCase) ||
                   name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
                   name.EndsWith("~", StringComparison.OrdinalIgnoreCase);
        }

        private string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        public bool IsActive()
        {
            return _activeDiskId.HasValue;
        }
    }

    public enum FileChangeType
    {
        Created,
        Modified,
        Deleted,
        Renamed
    }
}
