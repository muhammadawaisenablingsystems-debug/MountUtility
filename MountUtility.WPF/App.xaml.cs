using DiskMountUtility.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Win32;
using MountUtility.Services;
using MountUtility.WPF.Cryptography;
using MountUtility.WPF.FileWatcher;
using MountUtility.WPF.Interfaces;
using MountUtility.WPF.Persistence;
using MountUtility.WPF.Service;
using MountUtility.WPF.Services;
using MountUtility.WPF.Views;
using System.Windows;

namespace MountUtility.WPF
{
    public partial class App : Application
    {
        private IHost? _host;
        private TrayIconService? _trayIconService;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            SystemEvents.SessionEnding += OnSessionEnding;

            _host = Host.CreateDefaultBuilder()
                .ConfigureServices((context, services) =>
                {
                    services.AddDbContextFactory<AppDbContext>();

                    services.AddSingleton<ICryptographyService, HybridEncryptionService>();
                    services.AddSingleton<ILocalDbUnlocker, LocalDbUnlocker>();
                    services.AddSingleton<IDiskRepository, DiskRepository>();
                    services.AddSingleton<IVirtualDiskService, VirtualDiskManager>();
                    services.AddSingleton<VaultFileWatcherService>();
                    services.AddSingleton<RealtimeVaultSyncService>();
                    services.AddSingleton<RealtimeFileExplorerService>();
                    services.AddSingleton<DiskManagementService>();

                    services.AddSingleton<MainWindow>();
                    services.AddSingleton<TrayIconService>();
                    services.AddSingleton<FirstRunWindow>();
                    services.AddSingleton<FileExplorerWindow>();
                })
                .Build();

            _trayIconService = _host.Services.GetRequiredService<TrayIconService>();
            _trayIconService.Initialize();

            var diskManagement = _host.Services.GetRequiredService<DiskManagementService>();

            if (!VaultKeyManager.HasSavedSelection())
            {
                var firstRun = _host.Services.GetRequiredService<FirstRunWindow>();
                firstRun.Show();
            }
            else
            {
                var main = _host.Services.GetRequiredService<MainWindow>();
                main.Show();
            }
        }
        private async void OnSessionEnding(object? sender, SessionEndingEventArgs e)
        {
            await AppShutdownCoordinator.SafeShutdownAsync(_host!.Services);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            _trayIconService?.Dispose();
            _host?.Dispose();
            base.OnExit(e);
        }
    }
}