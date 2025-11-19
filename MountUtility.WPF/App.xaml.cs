using MountUtility.FileWatcher;
using MountUtility.Services;
using MountUtility.Interfaces;
using DiskMountUtility.Infrastructure.Cryptography;
using DiskMountUtility.Infrastructure.Persistence;
using DiskMountUtility.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MountUtility.Cryptography;
using MountUtility.WPF.Service;
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

            _host = Host.CreateDefaultBuilder()
                .ConfigureServices((context, services) =>
                {
                    services.AddDbContextFactory<AppDbContext>(options =>
                    {
                        var dbPath = System.IO.Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                            "DiskMountUtility", "vault.db");

                        System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(dbPath)!);

                        options.UseSqlite($"Data Source={dbPath}");
                    });

                    services.AddSingleton<ICryptographyService, HybridEncryptionService>();
                    services.AddSingleton<ILocalDbUnlocker, LocalDbUnlocker>();
                    services.AddSingleton<IDiskRepository, DiskRepository>();
                    services.AddSingleton<IVirtualDiskService, VirtualDiskManager>();
                    services.AddSingleton<VaultFileWatcherService>();
                    services.AddSingleton<RealtimeVaultSyncService>();
                    services.AddSingleton<RealtimeFileExplorerService>();
                    services.AddSingleton<DiskManagementService>();
                    services.AddSingleton<TrayIconService>();

                    services.AddSingleton<MainWindow>();
                    services.AddSingleton<FirstRunWindow>();
                    services.AddSingleton<FileExplorerWindow>();
                })
                .Build();

            _trayIconService = _host.Services.GetRequiredService<TrayIconService>();
            _trayIconService.Initialize();

            var diskManagement = _host.Services.GetRequiredService<DiskManagementService>();
            Task.Run(async () =>
            {
                await diskManagement.EnsureDatabaseReadyAsync();
            }).Wait();

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

        protected override void OnExit(ExitEventArgs e)
        {
            _trayIconService?.Dispose();
            _host?.Dispose();
            base.OnExit(e);
        }
    }
}