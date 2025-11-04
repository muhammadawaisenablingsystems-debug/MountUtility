using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace DiskMountUtility.Application.Services
{
    public class RealtimeFileExplorerService : IDisposable
    {
        private readonly ConcurrentDictionary<string, Action> _subscribers = new();
        private Timer? _notificationTimer;
        private bool _hasChanges;
        private readonly SemaphoreSlim _notifyLock = new(1, 1);
        private bool _disposed;

        // debounce delay (ms)
        private const int DebounceMs = 500;

        public string Subscribe(Action callback)
        {
            var subscriptionId = Guid.NewGuid().ToString();
            _subscribers[subscriptionId] = callback;
            Console.WriteLine($"📡 Client subscribed for file updates: {subscriptionId}");
            return subscriptionId;
        }

        public void Unsubscribe(string subscriptionId)
        {
            _subscribers.TryRemove(subscriptionId, out _);
            Console.WriteLine($"📴 Client unsubscribed: {subscriptionId}");
        }

        public void NotifyFileChange()
        {
            if (_disposed) return;

            _hasChanges = true;

            // Ensure timer exists
            if (_notificationTimer == null)
            {
                // create single timer instance; it will call NotifyAllSubscribersTimerCallback
                _notificationTimer = new Timer(async _ => await NotifyAllSubscribersTimerCallback(), null, DebounceMs, Timeout.Infinite);
            }
            else
            {
                // reset debounce
                try
                {
                    _notificationTimer.Change(DebounceMs, Timeout.Infinite);
                }
                catch (ObjectDisposedException)
                {
                    // ignore if disposed during shutdown
                }
            }
        }

        private async Task NotifyAllSubscribersTimerCallback()
        {
            if (_disposed) return;

            // Quick check
            if (!_hasChanges) return;

            await NotifyAllSubscribersAsync().ConfigureAwait(false);
        }

        private async Task NotifyAllSubscribersAsync()
        {
            if (_disposed) return;

            await _notifyLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (!_hasChanges) return;

                _hasChanges = false;

                Console.WriteLine($"📢 Notifying {_subscribers.Count} subscribers of file changes");

                var subscribersSnapshot = _subscribers.Values.ToArray();

                foreach (var callback in subscribersSnapshot)
                {
                    try
                    {
                        // run callbacks on threadpool so a slow client doesn't block others
                        await Task.Run(() => callback.Invoke()).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"⚠️ Error notifying subscriber: {ex.Message}");
                    }
                }
            }
            finally
            {
                _notifyLock.Release();
            }
        }

        public void Shutdown()
        {
            Dispose();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            try
            {
                _notificationTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                _notificationTimer?.Dispose();
                _notificationTimer = null;
            }
            catch { /* ignore */ }

            _subscribers.Clear();
            _notifyLock?.Dispose();

            Console.WriteLine("📴 RealtimeFileExplorerService shutdown");
        }
    }
}