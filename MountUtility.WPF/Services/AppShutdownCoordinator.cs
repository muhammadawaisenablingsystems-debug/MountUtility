using Microsoft.Extensions.DependencyInjection;
using MountUtility.Services;
using System;
using System.Collections.Generic;
using System.Text;

namespace MountUtility.WPF.Services
{
    public sealed class AppShutdownCoordinator
    {
        private static int _called;

        public static async Task SafeShutdownAsync(IServiceProvider services)
        {
            // Ensure idempotent (runs once)
            if (Interlocked.Exchange(ref _called, 1) == 1)
                return;

            try
            {
                var diskManager = services.GetRequiredService<DiskManagementService>();

                var mounted = await diskManager.GetMountedDiskInfoAsync();
                if (mounted != null)
                {
                    // FAST, NO UI, NO DB
                    await diskManager.UnmountDiskAsync(mounted.Id);
                    await diskManager.UnmountPhysicalAsync(mounted.Id);
                }
            }
            catch
            {
                // swallow – OS is shutting down
            }
        }
    }
}
