using MountUtility.Services;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace MountUtility.WPF.FileWatcher
{
    public class VaultFileWatcherService : IDisposable
    {
        private FileSystemWatcher? _watcher;
        private string? _vaultPath;
        private Timer? _debounceTimer;
        private Timer? _pollingTimer;

        private readonly ConcurrentDictionary<string, PendingChange> _pendingChanges = new();
        private readonly ConcurrentDictionary<string, FileSystemSnapshot> _lastSnapshot = new();
        private readonly SemaphoreSlim _processingLock = new(1, 1);
        private readonly SemaphoreSlim _pollingLock = new(1, 1);
        private bool _disposed = false;

        private const int DebounceDelayMs = 800;
        private const int PollingIntervalMs = 2000;

        public event Action<string>? FileAdded;
        public event Action<string>? FileUpdated;
        public event Action<string>? FileDeleted;
        public event Action<string, string>? FileRenamed;

        public Func<string, FileChangeType, string?, Task>? OnChangeDetected { get; set; }

        public bool EnableDebugLogging { get; set; } = false;

        private int _suppressEventsFlag = 0;

        private sealed class PendingChange
        {
            public FileChangeType ChangeType { get; set; }
            public string? OldPath { get; set; }
            public DateTime LastSeenUtc { get; set; }
        }

        private sealed class FileSystemSnapshot
        {
            public string Path { get; set; } = string.Empty;
            public bool IsDirectory { get; set; }
            public long Size { get; set; }
            public DateTime LastWriteTimeUtc { get; set; }
        }

        public void Initialize(string vaultPath)
        {
            _vaultPath = vaultPath ?? throw new ArgumentNullException(nameof(vaultPath));
            _pendingChanges.Clear();

            try
            {
                _debounceTimer?.Dispose();
                _pollingTimer?.Dispose();
            }
            catch { }

            _debounceTimer = new Timer(_ => _ = ScheduleProcessPendingChangesAsync(), null, Timeout.Infinite, Timeout.Infinite);
            _pollingTimer = new Timer(_ => _ = PollFileSystemAsync(), null, Timeout.Infinite, Timeout.Infinite);
        }

        public void StartWatcher()
        {
            if (string.IsNullOrEmpty(_vaultPath))
            {
                Log("⚠ Watcher Start skipped: Vault path not initialized.");
                return;
            }

            if (!Directory.Exists(_vaultPath))
            {
                Log($"⚠️ Vault path does not exist: {_vaultPath}");
                return;
            }

            _watcher?.Dispose();

            _watcher = new FileSystemWatcher(_vaultPath)
            {
                EnableRaisingEvents = true,
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName
                             | NotifyFilters.Size
                             | NotifyFilters.LastWrite
                             | NotifyFilters.DirectoryName
                             | NotifyFilters.Attributes
            };

            _watcher.Created += OnFileCreated;
            _watcher.Changed += OnFileChanged;
            _watcher.Deleted += OnFileDeleted;
            _watcher.Renamed += OnFileRenamed;
            _watcher.Error += OnWatcherError;

            TakeSnapshot();

            try
            {
                _pollingTimer?.Change(PollingIntervalMs, PollingIntervalMs);
            }
            catch (ObjectDisposedException) { }

            Log($"✅ File Watcher Started (with polling backup) for: {_vaultPath}");
        }

        public void StopWatcher()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }

            try
            {
                _debounceTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                _pollingTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            }
            catch { }

            try
            {
                _debounceTimer?.Dispose();
                _pollingTimer?.Dispose();
            }
            catch { }

            _debounceTimer = null;
            _pollingTimer = null;
            _pendingChanges.Clear();
            _lastSnapshot.Clear();

            Log("⛔ File Watcher Stopped.");
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Log($"⚠️ FileSystemWatcher error: {e.GetException()?.Message}");
        }

        private bool AreEventsSuppressed() => Interlocked.CompareExchange(ref _suppressEventsFlag, 0, 0) == 1;

        public async Task<T> RunWithoutRaisingEventsAsync<T>(Func<Task<T>> action)
        {
            Interlocked.Exchange(ref _suppressEventsFlag, 1);
            try
            {
                return await action().ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Exchange(ref _suppressEventsFlag, 0);
            }
        }

        public async Task RunWithoutRaisingEventsAsync(Func<Task> action)
        {
            Interlocked.Exchange(ref _suppressEventsFlag, 1);
            try
            {
                await action().ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Exchange(ref _suppressEventsFlag, 0);
            }
        }

        private void TakeSnapshot()
        {
            if (string.IsNullOrEmpty(_vaultPath) || !Directory.Exists(_vaultPath))
                return;

            _lastSnapshot.Clear();

            try
            {
                ScanDirectoryForSnapshot(_vaultPath);
                Log($"📸 Snapshot taken: {_lastSnapshot.Count} items");
            }
            catch (Exception ex)
            {
                Log($"⚠️ Snapshot failed: {ex.Message}");
            }
        }

        private void ScanDirectoryForSnapshot(string path)
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(path))
                {
                    if (ShouldSkipFile(dir)) continue;

                    var dirInfo = new DirectoryInfo(dir);
                    _lastSnapshot[dir] = new FileSystemSnapshot
                    {
                        Path = dir,
                        IsDirectory = true,
                        Size = 0,
                        LastWriteTimeUtc = dirInfo.LastWriteTimeUtc
                    };

                    ScanDirectoryForSnapshot(dir);
                }

                foreach (var file in Directory.GetFiles(path))
                {
                    if (ShouldSkipFile(file)) continue;

                    var fileInfo = new FileInfo(file);
                    _lastSnapshot[file] = new FileSystemSnapshot
                    {
                        Path = file,
                        IsDirectory = false,
                        Size = fileInfo.Length,
                        LastWriteTimeUtc = fileInfo.LastWriteTimeUtc
                    };
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception ex)
            {
                Log($"⚠️ Error scanning {path}: {ex.Message}");
            }
        }

        private async Task PollFileSystemAsync()
        {
            if (AreEventsSuppressed() || string.IsNullOrEmpty(_vaultPath))
                return;

            if (!await _pollingLock.WaitAsync(0).ConfigureAwait(false))
                return;

            try
            {
                var currentSnapshot = new Dictionary<string, FileSystemSnapshot>();
                ScanDirectoryForSnapshotInto(_vaultPath, currentSnapshot);

                var oldPaths = _lastSnapshot.Keys.ToHashSet();
                var newPaths = currentSnapshot.Keys.ToHashSet();

                var added = newPaths.Except(oldPaths).ToList();
                var removed = oldPaths.Except(newPaths).ToList();
                var common = newPaths.Intersect(oldPaths).ToList();

                foreach (var path in removed)
                {
                    if (AreEventsSuppressed()) break;
                    Log($"🔍 Polling detected deletion: {Path.GetFileName(path)}");
                    EnqueueOrMerge(path, FileChangeType.Deleted);
                }

                foreach (var path in added)
                {
                    if (AreEventsSuppressed()) break;
                    Log($"🔍 Polling detected creation: {Path.GetFileName(path)}");
                    EnqueueOrMerge(path, FileChangeType.Created);
                }

                foreach (var path in common)
                {
                    if (AreEventsSuppressed()) break;

                    var oldSnap = _lastSnapshot[path];
                    var newSnap = currentSnapshot[path];

                    if (!oldSnap.IsDirectory && (oldSnap.Size != newSnap.Size || oldSnap.LastWriteTimeUtc != newSnap.LastWriteTimeUtc))
                    {
                        Log($"🔍 Polling detected modification: {Path.GetFileName(path)}");
                        EnqueueOrMerge(path, FileChangeType.Modified);
                    }
                }

                var renames = DetectRenames(removed, added, _lastSnapshot, currentSnapshot);
                foreach (var (oldPath, newPath) in renames)
                {
                    if (AreEventsSuppressed()) break;
                    Log($"🔍 Polling detected rename: {Path.GetFileName(oldPath)} → {Path.GetFileName(newPath)}");

                    var oldPathCopy = oldPath;
                    var newPathCopy = newPath;

                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            if (OnChangeDetected != null)
                            {
                                await OnChangeDetected(newPathCopy, FileChangeType.Renamed, oldPathCopy);
                                FileRenamed?.Invoke(oldPathCopy, newPathCopy);
                            }
                        }
                        catch (Exception ex)
                        {
                            Log($"❌ Polling rename sync error: {ex.Message}");
                        }
                    });
                }

                _lastSnapshot.Clear();
                foreach (var kv in currentSnapshot)
                    _lastSnapshot[kv.Key] = kv.Value;
            }
            catch (Exception ex)
            {
                Log($"⚠️ Polling error: {ex.Message}");
            }
            finally
            {
                _pollingLock.Release();
            }
        }

        private void ScanDirectoryForSnapshotInto(string path, Dictionary<string, FileSystemSnapshot> snapshot)
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(path))
                {
                    if (ShouldSkipFile(dir)) continue;

                    var dirInfo = new DirectoryInfo(dir);
                    snapshot[dir] = new FileSystemSnapshot
                    {
                        Path = dir,
                        IsDirectory = true,
                        Size = 0,
                        LastWriteTimeUtc = dirInfo.LastWriteTimeUtc
                    };

                    ScanDirectoryForSnapshotInto(dir, snapshot);
                }

                foreach (var file in Directory.GetFiles(path))
                {
                    if (ShouldSkipFile(file)) continue;

                    var fileInfo = new FileInfo(file);
                    snapshot[file] = new FileSystemSnapshot
                    {
                        Path = file,
                        IsDirectory = false,
                        Size = fileInfo.Length,
                        LastWriteTimeUtc = fileInfo.LastWriteTimeUtc
                    };
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception ex)
            {
                Log($"⚠️ Error scanning {path}: {ex.Message}");
            }
        }

        private void RaiseEventForChangeType(string path, FileChangeType changeType, string? oldPath)
        {
            try
            {
                switch (changeType)
                {
                    case FileChangeType.Created:
                        FileAdded?.Invoke(path);
                        Log($"📢 Event raised: FileAdded for {Path.GetFileName(path)}");
                        break;

                    case FileChangeType.Modified:
                        FileUpdated?.Invoke(path);
                        Log($"📢 Event raised: FileUpdated for {Path.GetFileName(path)}");
                        break;

                    case FileChangeType.Deleted:
                        FileDeleted?.Invoke(path);
                        Log($"📢 Event raised: FileDeleted for {Path.GetFileName(path)}");
                        break;

                    case FileChangeType.Renamed:
                        if (!string.IsNullOrEmpty(oldPath))
                        {
                            FileRenamed?.Invoke(oldPath, path);
                            Log($"📢 Event raised: FileRenamed from {Path.GetFileName(oldPath)} to {Path.GetFileName(path)}");
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                Log($"⚠️ Error raising event for {changeType}: {ex.Message}");
            }
        }

        private List<(string oldPath, string newPath)> DetectRenames(
            List<string> removed,
            List<string> added,
            ConcurrentDictionary<string, FileSystemSnapshot> oldSnapshot,
            Dictionary<string, FileSystemSnapshot> newSnapshot)
        {
            var renames = new List<(string, string)>();

            var removedDirs = removed.Where(p => oldSnapshot.TryGetValue(p, out var s) && s.IsDirectory).ToList();
            var addedDirs = added.Where(p => newSnapshot.TryGetValue(p, out var s) && s.IsDirectory).ToList();

            foreach (var removedDir in removedDirs)
            {
                foreach (var addedDir in addedDirs)
                {
                    if (IsSameDirectory(removedDir, addedDir, oldSnapshot, newSnapshot))
                    {
                        renames.Add((removedDir, addedDir));
                        removed.Remove(removedDir);
                        added.Remove(addedDir);
                        Log($"🔍 Matched folder rename: {removedDir} → {addedDir}");
                        break;
                    }
                }
            }

            var removedFiles = removed.Where(p => oldSnapshot.TryGetValue(p, out var s) && !s.IsDirectory).ToList();
            var addedFiles = added.Where(p => newSnapshot.TryGetValue(p, out var s) && !s.IsDirectory).ToList();

            foreach (var removedFile in removedFiles)
            {
                var oldSnap = oldSnapshot[removedFile];

                foreach (var addedFile in addedFiles)
                {
                    var newSnap = newSnapshot[addedFile];

                    if (newSnap.Size == oldSnap.Size &&
                        Path.GetFileName(removedFile) == Path.GetFileName(addedFile))
                    {
                        renames.Add((removedFile, addedFile));
                        removed.Remove(removedFile);
                        added.Remove(addedFile);
                        break;
                    }
                }
            }

            return renames;
        }

        private bool IsSameDirectory(
            string oldDir,
            string newDir,
            ConcurrentDictionary<string, FileSystemSnapshot> oldSnapshot,
            Dictionary<string, FileSystemSnapshot> newSnapshot)
        {
            var oldChildren = oldSnapshot.Keys.Where(p => p.StartsWith(oldDir + Path.DirectorySeparatorChar)).Take(5).ToList();
            var newChildren = newSnapshot.Keys.Where(p => p.StartsWith(newDir + Path.DirectorySeparatorChar)).Take(5).ToList();

            if (oldChildren.Count != newChildren.Count)
                return false;

            if (oldChildren.Count == 0)
                return Path.GetFileName(oldDir) == Path.GetFileName(newDir);

            int matches = 0;
            foreach (var oldChild in oldChildren)
            {
                var oldName = Path.GetFileName(oldChild);
                if (newChildren.Any(nc => Path.GetFileName(nc) == oldName))
                    matches++;
            }

            return matches >= Math.Min(3, oldChildren.Count);
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (ShouldSkipFile(e.FullPath) || AreEventsSuppressed()) return;

            EnqueueOrMerge(e.FullPath, FileChangeType.Created);
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            if (ShouldSkipFile(e.FullPath) || AreEventsSuppressed()) return;

            EnqueueOrMerge(e.FullPath, FileChangeType.Modified);
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (ShouldSkipFile(e.FullPath) || AreEventsSuppressed()) return;

            EnqueueOrMerge(e.FullPath, FileChangeType.Deleted);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if ((ShouldSkipFile(e.FullPath) && ShouldSkipFile(e.OldFullPath)) || AreEventsSuppressed()) return;

            _ = Task.Run(async () =>
            {
                try
                {
                    if (OnChangeDetected != null)
                    {
                        await OnChangeDetected(e.FullPath, FileChangeType.Renamed, e.OldFullPath);
                    }
                }
                catch (Exception ex)
                {
                    Log($"❌ Rename sync error: {ex.Message}");
                }
            });
        }

        private void EnqueueOrMerge(string fullPath, FileChangeType changeType, string? oldPath = null)
        {
            var now = DateTime.UtcNow;

            _pendingChanges.AddOrUpdate(fullPath,
                addValueFactory: (_) => new PendingChange
                {
                    ChangeType = changeType,
                    OldPath = oldPath,
                    LastSeenUtc = now
                },
                updateValueFactory: (_, existing) =>
                {
                    if (changeType == FileChangeType.Renamed)
                    {
                        existing.ChangeType = FileChangeType.Renamed;
                        existing.OldPath = oldPath;
                    }
                    else if (existing.ChangeType == FileChangeType.Created &&
                             changeType == FileChangeType.Modified)
                    {
                    }
                    else if (changeType == FileChangeType.Deleted)
                    {
                        existing.ChangeType = FileChangeType.Deleted;
                        existing.OldPath = null;
                    }
                    else
                    {
                        existing.ChangeType = changeType;
                    }

                    existing.LastSeenUtc = now;
                    return existing;
                });

            try
            {
                _debounceTimer?.Change(DebounceDelayMs, Timeout.Infinite);
            }
            catch (ObjectDisposedException) { }

            if (EnableDebugLogging)
                Log($"Queued: [{changeType}] {fullPath} (old: {oldPath})");
        }

        private async Task ScheduleProcessPendingChangesAsync()
        {
            if (!await _processingLock.WaitAsync(0).ConfigureAwait(false))
            {
                Log("⏳ Processing already in progress, will process in next cycle");
                return;
            }

            try
            {
                await ProcessPendingChangesAsync().ConfigureAwait(false);
            }
            finally
            {
                _processingLock.Release();
            }
        }

        private async Task ProcessPendingChangesAsync()
        {
            try
            {
                if (_pendingChanges.IsEmpty || OnChangeDetected == null)
                    return;

                var now = DateTime.UtcNow;

                var ready = new List<KeyValuePair<string, PendingChange>>();
                foreach (var kv in _pendingChanges)
                {
                    if ((now - kv.Value.LastSeenUtc).TotalMilliseconds >= DebounceDelayMs)
                        ready.Add(kv);
                }

                if (ready.Count == 0) return;

                foreach (var kv in ready)
                    _pendingChanges.TryRemove(kv.Key, out _);

                Interlocked.Exchange(ref _suppressEventsFlag, 1);
                try
                {
                    foreach (var kv in ready)
                    {
                        var path = kv.Key;
                        var pending = kv.Value;
                        try
                        {
                            if (OnChangeDetected != null)
                            {
                                await SafeInvokeOnChangeDetectedAsync(path, pending.ChangeType, pending.OldPath).ConfigureAwait(false);
                                RaiseEventForChangeType(path, pending.ChangeType, pending.OldPath);
                            }
                        }
                        catch (Exception ex)
                        {
                            Log($"❌ Sync error for {Path.GetFileName(path)}: {ex.Message}");
                        }
                    }
                }
                finally
                {
                    await Task.Delay(1000);
                    Interlocked.Exchange(ref _suppressEventsFlag, 0);
                }
            }
            catch (Exception ex)
            {
                Log($"⚠️ Error in ProcessPendingChangesAsync: {ex.Message}");
            }
        }

        private async Task SafeInvokeOnChangeDetectedAsync(string fullPath, FileChangeType changeType, string? oldPath)
        {
            try
            {
                await OnChangeDetected!(fullPath, changeType, oldPath).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log($"❌ OnChangeDetected failed for {fullPath}: {ex.Message}");
            }
        }

        private bool ShouldSkipFile(string? path)
        {
            if (string.IsNullOrEmpty(path)) return true;

            var fileName = Path.GetFileName(path);
            if (string.IsNullOrEmpty(fileName)) return true;

            if (fileName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith("~$", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith("~", StringComparison.OrdinalIgnoreCase) ||
                fileName.Contains("Temp", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals("Thumbs.db", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (path.IndexOf("System Volume Information", StringComparison.OrdinalIgnoreCase) >= 0 ||
                path.IndexOf("$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            try
            {
                if (File.Exists(path))
                {
                    var attrs = File.GetAttributes(path);
                    if (attrs.HasFlag(FileAttributes.Temporary) ||
                        attrs.HasFlag(FileAttributes.Hidden) ||
                        attrs.HasFlag(FileAttributes.System))
                    {
                        return true;
                    }
                }
                else if (Directory.Exists(path))
                {
                    var attrs = File.GetAttributes(path);
                    if (attrs.HasFlag(FileAttributes.Hidden) ||
                        attrs.HasFlag(FileAttributes.System))
                    {
                        return true;
                    }
                }
            }
            catch
            {
            }

            return false;
        }

        private void Log(string message)
        {
            if (EnableDebugLogging)
                Console.WriteLine($"[VaultFileWatcher] {message}");
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            StopWatcher();

            _processingLock?.Dispose();
            _pollingLock?.Dispose();
            try { _debounceTimer?.Dispose(); } catch { }
            try { _pollingTimer?.Dispose(); } catch { }
        }
    }
}