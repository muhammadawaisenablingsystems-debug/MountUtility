using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace MountUtility.Services
{
    public class RealtimeFileExplorerService : IDisposable
    {
        private readonly ConcurrentDictionary<string, Func<Task>> _subscribers = new();
        private Timer? _notificationTimer;
        private volatile bool _hasChanges;
        private readonly SemaphoreSlim _notifyLock = new(1, 1);
        private bool _disposed;

        private const int DebounceMs = 500;

        public string Subscribe(Func<Task> callback)
        {
            var subscriptionId = Guid.NewGuid().ToString();
            _subscribers[subscriptionId] = callback ?? throw new ArgumentNullException(nameof(callback));
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

            if (_notificationTimer == null)
            {
                _notificationTimer = new Timer(
                    async _ => await NotifyAllSubscribersAsync(),
                    null,
                    DebounceMs,
                    Timeout.Infinite
                );
            }
            else
            {
                try
                {
                    _notificationTimer.Change(DebounceMs, Timeout.Infinite);
                }
                catch (ObjectDisposedException)
                {
                }
            }
        }

        private async Task NotifyAllSubscribersAsync()
        {
            if (_disposed || !_hasChanges)
                return;

            await _notifyLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (!_hasChanges)
                    return;

                _hasChanges = false;

                if (_subscribers.IsEmpty)
                    return;

                Console.WriteLine($"📢 Notifying {_subscribers.Count} subscribers of file changes");

                var subscribersSnapshot = _subscribers.Values.ToArray();

                foreach (var callback in subscribersSnapshot)
                {
                    try
                    {
                        await callback.Invoke().ConfigureAwait(false);
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
            if (_disposed)
                return;

            _disposed = true;

            try
            {
                _notificationTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                _notificationTimer?.Dispose();
                _notificationTimer = null;
            }
            catch
            {
            }

            _subscribers.Clear();
            _notifyLock?.Dispose();

            Console.WriteLine("📴 RealtimeFileExplorerService shutdown");
        }
    }
}