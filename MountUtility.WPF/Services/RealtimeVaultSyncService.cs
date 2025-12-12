using MountUtility.WPF.Entities;
using MountUtility.WPF.FileWatcher;
using MountUtility.WPF.Interfaces;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;

namespace MountUtility.Services
{
    public class RealtimeVaultSyncService
    {
        private readonly ICryptographyService _cryptographyService;
        private readonly IDiskRepository _diskRepository;
        private readonly IVirtualDiskService _virtualDiskService;
        private readonly VaultFileWatcherService? _fileWatcher;
        private readonly SemaphoreSlim _syncLock = new(1, 1);

        private Guid? _activeDiskId;
        private string? _activePassword;
        private string? _activeMountPath;
        private bool _isSyncing;

        private readonly ConcurrentDictionary<string, DateTime> _recentWrites = new();
        private const int RecentWriteWindowMs = 2000;

        [DllImport("shell32.dll")]
        private static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);

        private const int SHCNE_UPDATEITEM = 0x0002;
        private const int SHCNE_CREATE = 0x0002;
        private const int SHCNE_MKDIR = 0x0008;
        private const int SHCNE_UPDATEDIR = 0x1000;
        private const uint SHCNF_PATH = 0x0005;
        private const uint SHCNF_FLUSH = 0x1000;

        public RealtimeVaultSyncService(
            ICryptographyService cryptographyService,
            IDiskRepository diskRepository,
            IVirtualDiskService virtualDiskService,
            VaultFileWatcherService? fileWatcher = null)
        {
            _cryptographyService = cryptographyService;
            _diskRepository = diskRepository;
            _virtualDiskService = virtualDiskService;
            _fileWatcher = fileWatcher;
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

        private void NotifyExplorerChange(string fullPath, bool isDirectory = false, bool isCreated = false)
        {
            try
            {
                IntPtr pathPtr = Marshal.StringToHGlobalUni(fullPath);
                try
                {
                    int eventId;

                    if (isDirectory)
                    {
                        eventId = isCreated ? SHCNE_MKDIR : SHCNE_UPDATEDIR;
                    }
                    else
                    {
                        eventId = SHCNE_UPDATEITEM;
                    }

                    SHChangeNotify(eventId, SHCNF_PATH | SHCNF_FLUSH, pathPtr, IntPtr.Zero);
                    Console.WriteLine($"🔔 Notified Explorer: {Path.GetFileName(fullPath)} ({eventId})");
                }
                finally
                {
                    Marshal.FreeHGlobal(pathPtr);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Failed to notify Explorer: {ex.Message}");
            }
        }

        public async Task SyncFileChangeAsync(string fullPath, FileChangeType changeType, string? oldPath = null)
        {
            if (!_activeDiskId.HasValue || string.IsNullOrEmpty(_activePassword) || string.IsNullOrEmpty(_activeMountPath))
            {
                Console.WriteLine("⚠️ Sync skipped: Not initialized");
                return;
            }

            fullPath = Path.GetFullPath(fullPath);

            if (IsRecentlyWritten(fullPath) || (oldPath != null && IsRecentlyWritten(oldPath)))
            {
                if (_isSyncing == false)
                    Console.WriteLine($"🔕 Skipping recent self-write: {fullPath}");
                return;
            }

            await _syncLock.WaitAsync();
            try
            {
                _isSyncing = true;
                Console.WriteLine($"🔄 Syncing {changeType}: {Path.GetFileName(fullPath)}");

                var disk = await _disk_repository_GetByIdSafeAsync(_activeDiskId.Value);
                if (disk == null)
                {
                    Console.WriteLine("❌ Disk not found");
                    return;
                }

                switch (changeType)
                {
                    case FileChangeType.Created:
                        {
                            if (Directory.Exists(fullPath))
                            {
                                var dirRel = GetRelativePath(fullPath, _activeMountPath!);
                                await _virtualDiskService.CreateDirectoryAsync(_activeDiskId.Value, dirRel);
                                Directory.CreateDirectory(fullPath);
                                NotifyExplorerChange(fullPath, isDirectory: true, isCreated: true);
                                return;
                            }

                            if (File.Exists(fullPath))
                            {
                                var content = ReadFileWithRetry(fullPath);
                                var (dirPath, fileName) = SplitRelativeDirAndName(fullPath);
                                await _virtualDiskService.WriteFileAsync(_activeDiskId.Value, dirPath, fileName, content);
                                return;
                            }

                            byte[] createdContent;
                            try
                            {
                                createdContent = ReadFileWithRetry(fullPath);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"⚠️ Could not read file {fullPath}: {ex.Message}");
                                return;
                            }

                            var (createdDirPath, createdFileName) = SplitRelativeDirAndName(fullPath);
                            var wroteCreated = await _virtualDiskService.WriteFileAsync(_activeDiskId.Value, createdDirPath, createdFileName, createdContent);
                            if (!wroteCreated)
                            {
                                Console.WriteLine($"❌ Failed to persist {createdFileName} into vault.");
                                return;
                            }

                            Console.WriteLine($"✅ Persisted {createdFileName} to vault (per-file).");
                            break;
                        }

                    case FileChangeType.Modified:
                        {
                            if (Directory.Exists(fullPath))
                            {
                                return;
                            }

                            if (!File.Exists(fullPath))
                            {
                                Console.WriteLine($"⚠️ File not found for Modified: {fullPath}");
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
                            var deleted = await _virtualDiskService.DeleteFileAsync(_active_disk_Id_or_throw(_activeDiskId.Value), rel);
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
                            var newRel = GetRelativePath(fullPath, _activeMountPath!);

                            var renamed = await _virtualDiskService.RenameFileAsync(_activeDiskId.Value, oldRel, newRel);
                            if (renamed)
                            {
                                Console.WriteLine($"✅ Renamed in vault: {oldRel} → {newRel}");

                                if (Directory.Exists(fullPath))
                                {
                                    Console.WriteLine($"✅ Directory renamed with all children preserved: {newRel}");
                                }
                                else if (File.Exists(fullPath))
                                {
                                    Console.WriteLine($"✅ File renamed: {newRel}");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"⚠️ Rename failed in vault, treating as delete+create");
                                await _virtualDiskService.DeleteFileAsync(_activeDiskId.Value, oldRel);

                                if (Directory.Exists(fullPath))
                                {
                                    await _virtualDiskService.CreateDirectoryAsync(_activeDiskId.Value, newRel);
                                    await SyncDirectoryContentsAsync(fullPath, newRel);
                                }
                                else if (File.Exists(fullPath))
                                {
                                    try
                                    {
                                        var content = ReadFileWithRetry(fullPath);
                                        var (dirPath, fileName) = SplitRelativeDirAndName(fullPath);
                                        await _virtualDisk_service_WriteFileAsyncWithChecks(_activeDiskId.Value, dirPath, fileName, content, fullPath);
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"⚠️ Could not create renamed file {fullPath}: {ex.Message}");
                                    }
                                }
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

        private async Task<bool> _virtualDisk_service_WriteFileAsyncWithChecks(Guid diskId, string dirPath, string fileName, byte[] content, string physicalFullPath)
        {
            var ok = await _virtualDiskService.WriteFileAsync(diskId, dirPath, fileName, content);
            if (!ok) return false;

            try
            {
                if (File.Exists(physicalFullPath))
                {
                    MarkRecentWrite(physicalFullPath);
                }
            }
            catch { }

            return true;
        }

        public async Task<bool> PushFileFromUiAsync(Guid diskId, string path, string fileName, byte[] content)
        {
            var ok = await _virtualDiskService.WriteFileAsync(diskId, path, fileName, content);
            if (!ok)
            {
                Console.WriteLine($"❌ Failed to write {fileName} to vault.");
                return false;
            }

            if (_activeDiskId.HasValue && _activeDiskId.Value == diskId && !string.IsNullOrEmpty(_activeMountPath))
            {
                string rel;
                if (string.IsNullOrEmpty(path) || path == "/")
                    rel = fileName;
                else
                    rel = $"{path.TrimStart('/').TrimEnd('/')}/{fileName}";

                var physicalFullPath = Path.Combine(_activeMountPath!, rel.Replace("/", Path.DirectorySeparatorChar.ToString()));

                try
                {
                    MarkRecentWrite(physicalFullPath);

                    var dir = Path.GetDirectoryName(physicalFullPath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        Directory.CreateDirectory(dir);

                    if (_fileWatcher != null)
                    {
                        await _fileWatcher.RunWithoutRaisingEventsAsync(async () =>
                        {
                            await File.WriteAllBytesAsync(physicalFullPath, content).ConfigureAwait(false);
                            File.SetLastWriteTimeUtc(physicalFullPath, DateTime.UtcNow);
                        }).ConfigureAwait(false);
                    }
                    else
                    {
                        await File.WriteAllBytesAsync(physicalFullPath, content).ConfigureAwait(false);
                        File.SetLastWriteTimeUtc(physicalFullPath, DateTime.UtcNow);
                    }

                    NotifyExplorerChange(physicalFullPath, false);

                    Console.WriteLine($"✅ Pushed plaintext {fileName} to mounted drive at {physicalFullPath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Failed writing plaintext to mounted drive: {ex.Message}");
                }
            }

            return true;
        }

        public async Task<bool> DeleteFileFromUiAsync(Guid diskId, string path)
        {
            var removedFromVault = await _virtualDiskService.DeleteFileAsync(diskId, path);
            if (!removedFromVault)
            {
                Console.WriteLine($"⚠️ Delete from vault failed or not found: {path}");
            }

            if (_activeDiskId.HasValue && _activeDiskId.Value == diskId && !string.IsNullOrEmpty(_activeMountPath))
            {
                var rel = path.TrimStart('/');
                var physicalFullPath = Path.Combine(_activeMountPath!, rel.Replace("/", Path.DirectorySeparatorChar.ToString()));

                try
                {
                    MarkRecentWrite(physicalFullPath);

                    bool isDirectory = Directory.Exists(physicalFullPath);

                    if (_fileWatcher != null)
                    {
                        await _fileWatcher.RunWithoutRaisingEventsAsync(async () =>
                        {
                            if (File.Exists(physicalFullPath))
                            {
                                File.Delete(physicalFullPath);
                            }
                            else if (Directory.Exists(physicalFullPath))
                            {
                                Directory.Delete(physicalFullPath, recursive: true);
                            }
                            await Task.CompletedTask;
                        }).ConfigureAwait(false);
                    }
                    else
                    {
                        if (File.Exists(physicalFullPath))
                        {
                            File.Delete(physicalFullPath);
                        }
                        else if (Directory.Exists(physicalFullPath))
                        {
                            Directory.Delete(physicalFullPath, recursive: true);
                        }
                    }

                    NotifyExplorerChange(physicalFullPath, isDirectory);

                    Console.WriteLine($"✅ Removed physical path: {physicalFullPath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Failed to remove physical path {physicalFullPath}: {ex.Message}");
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

        private async Task SyncDirectoryContentsAsync(string physicalDirPath, string vaultDirPath)
        {
            if (!Directory.Exists(physicalDirPath)) return;

            try
            {
                foreach (var subDir in Directory.GetDirectories(physicalDirPath))
                {
                    var dirInfo = new DirectoryInfo(subDir);
                    if (ShouldSkipSystemFile(dirInfo.Name)) continue;

                    var relPath = GetRelativePath(subDir, _activeMountPath!);
                    await _virtualDiskService.CreateDirectoryAsync(_activeDiskId!.Value, relPath);

                    await SyncDirectoryContentsAsync(subDir, relPath);
                }

                foreach (var file in Directory.GetFiles(physicalDirPath))
                {
                    var fileInfo = new FileInfo(file);
                    if (ShouldSkipSystemFile(fileInfo.Name)) continue;

                    try
                    {
                        var content = ReadFileWithRetry(file);
                        var (dirPath, fileName) = SplitRelativeDirAndName(file);
                        await _virtualDiskService.WriteFileAsync(_activeDiskId!.Value, dirPath, fileName, content);
                        MarkRecentWrite(file);
                        Console.WriteLine($"✅ Synced moved file: {fileName}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"⚠️ Failed to sync moved file {fileInfo.Name}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Error syncing directory contents: {ex.Message}");
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

                foreach (var filePath in Directory.GetFiles(currentPath))
                {
                    var fileInfo = new FileInfo(filePath);
                    if (ShouldSkipSystemFile(fileInfo.Name))
                        continue;

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
            if (string.IsNullOrEmpty(fullPath) || string.IsNullOrEmpty(baseMountPath))
                return "/";

            var basePath = baseMountPath.TrimEnd('\\', '/');
            if (!fullPath.StartsWith(basePath, StringComparison.OrdinalIgnoreCase))
            {
                var normalized = fullPath.Replace("\\", "/").TrimStart('/');
                return "/" + normalized;
            }

            if (fullPath.Length <= basePath.Length)
                return "/";

            var p = fullPath.Substring(basePath.Length);
            var relativePath = p.TrimStart('\\', '/').Replace("\\", "/");
            return "/" + relativePath;
        }

        private string GetRelativePath(string fullPath, int basePathLength)
        {
            if (string.IsNullOrEmpty(fullPath) || basePathLength < 0)
                return "/";

            if (fullPath.Length <= basePathLength)
                return "/";

            var p = fullPath.Substring(basePathLength);
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
            if (string.IsNullOrEmpty(fullPath)) return false;
            if (_recentWrites.TryGetValue(fullPath, out var dt))
            {
                return DateTime.UtcNow - dt < TimeSpan.FromMilliseconds(RecentWriteWindowMs);
            }
            return false;
        }

        private DateTime GetRecentWriteTime(string fullPath)
        {
            if (_recentWrites.TryGetValue(fullPath, out var dt)) return dt;
            return DateTime.MinValue;
        }

        private async Task<VirtualDisk?> _disk_repository_GetByIdSafeAsync(Guid id)
        {
            try { return await _diskRepository.GetByIdAsync(id); }
            catch { return null; }
        }

        private Guid _active_disk_Id_or_throw(Guid id)
        {
            return id;
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