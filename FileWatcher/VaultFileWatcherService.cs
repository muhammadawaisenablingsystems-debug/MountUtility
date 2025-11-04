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

        // Coalesce changes keyed by the file path (path is safe as key).
        // Value contains last seen time, change type and optional old path for renames.
        private readonly ConcurrentDictionary<string, PendingChange> _pendingChanges = new();

        private readonly SemaphoreSlim _processingLock = new(1, 1);
        private bool _disposed = false;

        // 2 seconds debounce (user requested)
        private const int DebounceDelayMs = 2000;

        // Events (kept for backward compatibility)
        public event Action<string>? FileAdded;
        public event Action<string>? FileUpdated;
        public event Action<string>? FileDeleted;
        public event Action<string, string>? FileRenamed;

        // Unified async callback used by realtime sync (kept existing API)
        public Func<string, Application.Services.FileChangeType, string?, Task>? OnChangeDetected { get; set; }

        // Optional debug logging flag (false by default)
        public bool EnableDebugLogging { get; set; } = false;

        // Suppression flag (0=false, 1=true) to avoid feedback loops during internal writes
        private volatile int _suppressEventsFlag = 0;

        // Internal record for pending change
        private sealed class PendingChange
        {
            public Application.Services.FileChangeType ChangeType { get; set; }
            public string? OldPath { get; set; }
            public DateTime LastSeenUtc { get; set; }
        }

        /// <summary>
        /// Initialize watcher with vault path. Safe to call multiple times.
        /// </summary>
        public void Initialize(string vaultPath)
        {
            _vaultPath = vaultPath ?? throw new ArgumentNullException(nameof(vaultPath));
            _pendingChanges.Clear();

            // Create or reset debounce timer; callback schedules async processing safely
            try
            {
                _debounceTimer?.Dispose();
            }
            catch { /* ignore */ }

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

            // Dispose previous watcher if exists
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
            _watcher?.EnableRaisingEvents = false;
            _watcher?.Dispose();
            _watcher = null;

            try
            {
                _debounceTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            }
            catch { /* ignore */ }

            try
            {
                _debounceTimer?.Dispose();
            }
            catch { /* ignore */ }

            _debounceTimer = null;
            _pendingChanges.Clear();

            Log("⛔ File Watcher Stopped.");
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Log($"⚠️ FileSystemWatcher error: {e.GetException()?.Message}");
        }

        private bool AreEventsSuppressed() => _suppressEventsFlag == 1;

        /// <summary>
        /// Temporarily suppresses watcher events while running async backend operations to avoid feedback loops.
        /// Usage: await watcher.RunWithoutRaisingEventsAsync(async () => { /* write files */ });
        /// </summary>
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

        /// <summary>
        /// Synchronous overload for convenience.
        /// </summary>
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

            EnqueueOrMerge(e.FullPath, Application.Services.FileChangeType.Created);
            FileAdded?.Invoke(e.FullPath);
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            if (ShouldSkipFile(e.FullPath) || AreEventsSuppressed()) return;

            EnqueueOrMerge(e.FullPath, Application.Services.FileChangeType.Modified);
            FileUpdated?.Invoke(e.FullPath);
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (ShouldSkipFile(e.FullPath) || AreEventsSuppressed()) return;

            EnqueueOrMerge(e.FullPath, Application.Services.FileChangeType.Deleted);
            FileDeleted?.Invoke(e.FullPath);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            // e.OldFullPath may be null in rare cases; handle gracefully
            if ((ShouldSkipFile(e.FullPath) && ShouldSkipFile(e.OldFullPath)) || AreEventsSuppressed()) return;

            // Enqueue both paths: new path as Renamed, keep old path info for consumers
            EnqueueOrMerge(e.FullPath, Application.Services.FileChangeType.Renamed, e.OldFullPath);
            FileRenamed?.Invoke(e.OldFullPath, e.FullPath);
        }

        /// <summary>
        /// Enqueues or merges a pending change for a given path.
        /// Coalescing strategy:
        /// - If a rename arrives, it takes precedence for that path (and stores OldPath).
        /// - If an existing Created exists and a Modified arrives, keep Created.
        /// - If a Deleted arrives after Created, Deleted wins (file removed).
        /// - Otherwise last-seen type is used.
        /// </summary>
        private void EnqueueOrMerge(string fullPath, Application.Services.FileChangeType changeType, string? oldPath = null)
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
                    // Simple priority handling
                    if (changeType == Application.Services.FileChangeType.Renamed)
                    {
                        existing.ChangeType = Application.Services.FileChangeType.Renamed;
                        existing.OldPath = oldPath;
                    }
                    else if (existing.ChangeType == Application.Services.FileChangeType.Created &&
                             changeType == Application.Services.FileChangeType.Modified)
                    {
                        // keep Created (no-op)
                    }
                    else if (changeType == Application.Services.FileChangeType.Deleted)
                    {
                        existing.ChangeType = Application.Services.FileChangeType.Deleted;
                        existing.OldPath = null; // deleted - old path not relevant
                    }
                    else
                    {
                        // otherwise update to last type (modified etc.)
                        existing.ChangeType = changeType;
                    }

                    existing.LastSeenUtc = now;
                    return existing;
                });

            // Reset debounce timer — schedule processing after DebounceDelayMs from last event
            try
            {
                _debounceTimer?.Change(DebounceDelayMs, Timeout.Infinite);
            }
            catch (ObjectDisposedException) { /* may happen during shutdown */ }

            if (EnableDebugLogging)
                Log($"Queued: [{changeType}] {fullPath} (old: {oldPath})");
        }

        /// <summary>
        /// Schedules async processing of pending items. Ensures only one processing task runs at a time.
        /// </summary>
        private async Task ScheduleProcessPendingChangesAsync()
        {
            // Try to enter processing lock - if already processing, skip scheduling (it will be re-scheduled by timer)
            if (!await _processingLock.WaitAsync(0).ConfigureAwait(false))
                return;

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

                // Collect entries ready for processing
                var ready = new List<KeyValuePair<string, PendingChange>>();
                foreach (var kv in _pendingChanges)
                {
                    if ((now - kv.Value.LastSeenUtc).TotalMilliseconds >= DebounceDelayMs)
                        ready.Add(kv);
                }

                if (ready.Count == 0) return;

                // Remove them from the dictionary (best-effort)
                foreach (var kv in ready)
                    _pendingChanges.TryRemove(kv.Key, out _);

                // Process sequentially to preserve ordering per path
                foreach (var kv in ready)
                {
                    var path = kv.Key;
                    var pending = kv.Value;
                    try
                    {
                        // Fire typed events for any local listeners (keep compatibility)
                        switch (pending.ChangeType)
                        {
                            case Application.Services.FileChangeType.Created:
                                FileAdded?.Invoke(path);
                                break;
                            case Application.Services.FileChangeType.Modified:
                                FileUpdated?.Invoke(path);
                                break;
                            case Application.Services.FileChangeType.Deleted:
                                FileDeleted?.Invoke(path);
                                break;
                            case Application.Services.FileChangeType.Renamed:
                                if (!string.IsNullOrEmpty(pending.OldPath))
                                    FileRenamed?.Invoke(pending.OldPath!, path);
                                break;
                        }

                        // Call unified async handler (await it)
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
            catch (Exception ex)
            {
                // Global catch to avoid unobserved exceptions bringing down app
                Log($"⚠️ Error in ProcessPendingChangesAsync: {ex.Message}");
            }
        }

        private async Task SafeInvokeOnChangeDetectedAsync(string fullPath, Application.Services.FileChangeType changeType, string? oldPath)
        {
            try
            {
                await OnChangeDetected!(fullPath, changeType, oldPath).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Bubble up to caller via log, but don't rethrow
                Log($"❌ OnChangeDetected failed for {fullPath}: {ex.Message}");
            }
        }

        private bool ShouldSkipFile(string? path)
        {
            if (string.IsNullOrEmpty(path)) return true;

            // quick filename checks
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

            // ignore common system folders in path
            if (path.IndexOf("System Volume Information", StringComparison.OrdinalIgnoreCase) >= 0 ||
                path.IndexOf("$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            try
            {
                // ignore hidden or system files (best-effort; file may not exist at time of event)
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
                // ignore IO errors while checking attributes
            }

            return false;
        }

        private void Log(string message)
        {
            if (EnableDebugLogging)
                Console.WriteLine($"[VaultFileWatcher] {message}");
        }

        #region IDisposable
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            StopWatcher();

            _processingLock?.Dispose();
            try { _debounceTimer?.Dispose(); } catch { }
        }
        #endregion
    }
}