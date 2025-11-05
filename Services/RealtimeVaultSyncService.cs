using DiskMountUtility.Core.Entities;
using DiskMountUtility.Core.Interfaces;
using System.Collections.Concurrent;

namespace MountUtility.Services
{
    public class RealtimeVaultSyncService
    {
        private readonly ICryptographyService _cryptographyService;
        private readonly IDiskRepository _diskRepository;
        private readonly IVirtualDiskService _virtualDiskService;
        private readonly SemaphoreSlim _syncLock = new(1, 1);

        private Guid? _activeDiskId;
        private string? _activePassword;
        private string? _activeMountPath;
        private bool _isSyncing;

        // short-lived cache to avoid reacting to our own writes
        private readonly ConcurrentDictionary<string, DateTime> _recentWrites = new();
        private const int RecentWriteWindowMs = 2000;

        public RealtimeVaultSyncService(
            ICryptographyService cryptographyService,
            IDiskRepository diskRepository,
            IVirtualDiskService virtualDiskService)
        {
            _cryptographyService = cryptographyService;
            _diskRepository = diskRepository;
            _virtualDiskService = virtualDiskService;
        }

        public void Initialize(Guid diskId, string password, string mountPath)
        {
            _activeDiskId = diskId;
            _activePassword = password;
            _activeMountPath = mountPath?.TrimEnd('\\', '/');

            Console.WriteLine($"✅ Realtime Sync initialized for disk {diskId} (mount: {_activeMountPath})");
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

            // Avoid processing changes we recently wrote ourselves
            if (IsRecentlyWritten(fullPath) || oldPath != null && IsRecentlyWritten(oldPath))
            {
                if (DateTime.UtcNow - GetRecentWriteTime(fullPath) < TimeSpan.FromMilliseconds(RecentWriteWindowMs) ||
                    oldPath != null && DateTime.UtcNow - GetRecentWriteTime(oldPath) < TimeSpan.FromMilliseconds(RecentWriteWindowMs))
                {
                    if (_isSyncing == false)
                        Console.WriteLine($"🔕 Skipping recent self-write: {fullPath}");
                    return;
                }
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

                switch (changeType)
                {
                    case FileChangeType.Created:
                    case FileChangeType.Modified:
                        {
                            if (!File.Exists(fullPath))
                            {
                                Console.WriteLine($"⚠️ File not found for {changeType}: {fullPath}");
                                return;
                            }

                            byte[] content;
                            try
                            {
                                content = ReadFileWithRetry(fullPath);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"⚠️ Could not read file {fullPath}: {ex.Message}");
                                return;
                            }

                            var (dirPath, fileName) = SplitRelativeDirAndName(fullPath);
                            var wrote = await _virtualDiskService.WriteFileAsync(_activeDiskId.Value, dirPath, fileName, content);
                            if (!wrote)
                            {
                                Console.WriteLine($"❌ Failed to persist {fileName} into vault.");
                                return;
                            }

                            Console.WriteLine($"✅ Persisted {fileName} to vault (per-file).");
                            break;
                        }

                    case FileChangeType.Deleted:
                        {
                            var rel = GetRelativePath(fullPath, _activeMountPath!);
                            var deleted = await _virtualDiskService.DeleteFileAsync(_activeDiskId.Value, rel);
                            if (deleted)
                                Console.WriteLine($"✅ Deleted {rel} from vault.");
                            else
                                Console.WriteLine($"⚠️ Delete not found in vault: {rel}");
                            break;
                        }

                    case FileChangeType.Renamed:
                        {
                            if (string.IsNullOrEmpty(oldPath))
                            {
                                Console.WriteLine("⚠️ Rename event missing old path.");
                                return;
                            }

                            var oldRel = GetRelativePath(oldPath, _activeMountPath!);
                            var deleteOk = await _virtualDiskService.DeleteFileAsync(_activeDiskId.Value, oldRel);
                            if (deleteOk)
                                Console.WriteLine($"✅ Removed old path from vault: {oldRel}");

                            if (File.Exists(fullPath))
                            {
                                byte[] content;
                                try
                                {
                                    content = ReadFileWithRetry(fullPath);
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"⚠️ Could not read renamed file {fullPath}: {ex.Message}");
                                    return;
                                }

                                var (dirPath, fileName) = SplitRelativeDirAndName(fullPath);
                                var wrote = await _virtualDiskService.WriteFileAsync(_activeDiskId.Value, dirPath, fileName, content);
                                if (wrote)
                                    Console.WriteLine($"✅ Persisted renamed file to vault: {fileName}");
                                else
                                    Console.WriteLine($"❌ Failed to persist renamed file: {fileName}");
                            }

                            break;
                        }
                }
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

        // Call this from the UI server side when the web UI updates a file inside the vault.
        // It will write the file into the encrypted vault and then push plaintext to the mounted drive if present.
        public async Task<bool> PushFileFromUiAsync(Guid diskId, string path, string fileName, byte[] content)
        {
            // write to vault (encrypt per-file)
            var ok = await _virtualDiskService.WriteFileAsync(diskId, path, fileName, content);
            if (!ok)
            {
                Console.WriteLine($"❌ Failed to write {fileName} to vault.");
                return false;
            }

            // If mounted, write plaintext into mounted path so physical view is updated immediately.
            if (_activeDiskId.HasValue && _activeDiskId.Value == diskId && !string.IsNullOrEmpty(_activeMountPath))
            {
                var rel = NormalizePath(Path.Combine(path, fileName).Replace("\\", "/"));
                var physicalFullPath = Path.Combine(_activeMountPath!, rel.TrimStart('/').Replace("/", Path.DirectorySeparatorChar.ToString()));

                try
                {
                    // mark as recent write to avoid reacting to our own FileSystemWatcher events
                    MarkRecentWrite(physicalFullPath);

                    var dir = Path.GetDirectoryName(physicalFullPath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        Directory.CreateDirectory(dir);

                    // Write plaintext to mounted drive
                    await File.WriteAllBytesAsync(physicalFullPath, content);
                    File.SetLastWriteTimeUtc(physicalFullPath, DateTime.UtcNow);

                    Console.WriteLine($"✅ Pushed plaintext {fileName} to mounted drive at {physicalFullPath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Failed writing plaintext to mounted drive: {ex.Message}");
                    // still return true because vault write succeeded
                }
            }

            return true;
        }

        private (string dirPath, string fileName) SplitRelativeDirAndName(string fullPath)
        {
            var rel = GetRelativePath(fullPath, _activeMountPath!);
            var normalized = NormalizePath(rel);
            var dir = Path.GetDirectoryName(normalized.Replace("/", Path.DirectorySeparatorChar.ToString())) ?? string.Empty;
            dir = dir.Replace(Path.DirectorySeparatorChar, '/').TrimStart('/');
            var dirPath = string.IsNullOrEmpty(dir) ? "/" : "/" + dir;
            var fileName = Path.GetFileName(normalized);
            return (dirPath, fileName);
        }

        private static string NormalizePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return "/";
            return path.Replace("\\", "/").Replace("//", "/");
        }

        private List<DiskFile> ScanPhysicalDrive(string mountedPath)
        {
            // kept for compatibility but not used by per-file sync
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
                foreach (var dirPath in Directory.GetDirectories(currentPath))
                {
                    var dirInfo = new DirectoryInfo(dirPath);
                    if (ShouldSkipSystemFile(dirInfo.Name))
                        continue;

                    // FIX: Use overload that accepts int for basePathLength
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

                foreach (var filePath in Directory.GetFiles(currentPath))
                {
                    var fileInfo = new FileInfo(filePath);
                    if (ShouldSkipSystemFile(fileInfo.Name))
                        continue;

                    // FIX: Use overload that accepts int for basePathLength
                    var relativePath = GetRelativePath(filePath, basePathLength);
                    byte[] content = Array.Empty<byte>();

                    try
                    {
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
                // Skip
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
                    Thread.Sleep(100);
                }
            }

            throw new IOException($"Could not read file after {maxRetries} attempts: {filePath}");
        }

        private string GetRelativePath(string fullPath, string baseMountPath)
        {
            var basePathLength = baseMountPath.TrimEnd('\\', '/').Length;
            var p = fullPath.Substring(Math.Min(basePathLength, fullPath.Length));
            var relativePath = p.TrimStart('\\', '/').Replace("\\", "/");
            return "/" + relativePath;
        }

        private string GetRelativePath(string fullPath, int basePathLength)
        {
            var p = fullPath.Substring(Math.Min(basePathLength, fullPath.Length));
            var relativePath = p.TrimStart('\\', '/').Replace("\\", "/");
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

        private void MarkRecentWrite(string fullPath)
        {
            try
            {
                _recentWrites[fullPath] = DateTime.UtcNow;
                // cleanup old entries opportunistically
                var cutoff = DateTime.UtcNow - TimeSpan.FromMilliseconds(RecentWriteWindowMs * 2);
                foreach (var kv in _recentWrites.ToArray())
                {
                    if (kv.Value < cutoff)
                        _recentWrites.TryRemove(kv.Key, out _);
                }
            }
            catch { }
        }

        private bool IsRecentlyWritten(string fullPath)
        {
            return _recentWrites.ContainsKey(fullPath);
        }

        private DateTime GetRecentWriteTime(string fullPath)
        {
            if (_recentWrites.TryGetValue(fullPath, out var dt)) return dt;
            return DateTime.MinValue;
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