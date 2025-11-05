using MountUtility.Services;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DiskMountUtility.Application.FileWatcher
{
    public class VaultFileWatcherService : IDisposable
    {
        private FileSystemWatcher? _watcher;
        private string? _vaultPath;
        private Timer? _debounceTimer;

        private readonly ConcurrentDictionary<string, PendingChange> _pendingChanges = new();
        private readonly SemaphoreSlim _processingLock = new(1, 1);
        private bool _disposed = false;

        // ✅ FIX: Increased debounce to handle Windows write delays
        private const int DebounceDelayMs = 3000;

        public event Action<string>? FileAdded;
        public event Action<string>? FileUpdated;
        public event Action<string>? FileDeleted;
        public event Action<string, string>? FileRenamed;

        public Func<string, FileChangeType, string?, Task>? OnChangeDetected { get; set; }

        public bool EnableDebugLogging { get; set; } = false;

        // ✅ FIX: Use int for atomic operations (0=false, 1=true)
        private int _suppressEventsFlag = 0;

        private sealed class PendingChange
        {
            public FileChangeType ChangeType { get; set; }
            public string? OldPath { get; set; }
            public DateTime LastSeenUtc { get; set; }
        }

        public void Initialize(string vaultPath)
        {
            _vaultPath = vaultPath ?? throw new ArgumentNullException(nameof(vaultPath));
            _pendingChanges.Clear();

            try
            {
                _debounceTimer?.Dispose();
            }
            catch { }

            _debounceTimer = new Timer(_ => _ = ScheduleProcessPendingChangesAsync(), null, Timeout.Infinite, Timeout.Infinite);
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
            };

            _watcher.Created += OnFileCreated;
            _watcher.Changed += OnFileChanged;
            _watcher.Deleted += OnFileDeleted;
            _watcher.Renamed += OnFileRenamed;
            _watcher.Error += OnWatcherError;

            Log($"✅ File Watcher Started for: {_vaultPath}");
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
            }
            catch { }

            try
            {
                _debounceTimer?.Dispose();
            }
            catch { }

            _debounceTimer = null;
            _pendingChanges.Clear();

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

            EnqueueOrMerge(e.FullPath, FileChangeType.Renamed, e.OldFullPath);
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
                        // keep Created
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
            // ✅ FIX: Don't skip if already processing, queue will handle it
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

                // ✅ FIX: Process with suppression to avoid feedback loops
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
                    // ✅ FIX: Wait before re-enabling events to let writes settle
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
            }
            catch
            {
                // ignore
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
            try { _debounceTimer?.Dispose(); } catch { }
        }
    }
}