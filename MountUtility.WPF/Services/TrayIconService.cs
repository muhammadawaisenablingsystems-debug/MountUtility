using Hardcodet.Wpf.TaskbarNotification;
using MountUtility.WPF.Services;
using MountUtility.WPF.Views;
using System;
using System.Drawing;
using System.Windows;
using System.Windows.Controls;

namespace MountUtility.WPF.Service
{
    public class TrayIconService : IDisposable
    {
        private readonly MainWindow _mainWindow;
        private readonly IServiceProvider _services;
        private TaskbarIcon? _trayIcon;
        private bool _disposed;

        public TrayIconService(MainWindow mainWindow, IServiceProvider services)
        {
            _mainWindow = mainWindow;
            _services = services;
        }

        public void Initialize()
        {
            _trayIcon = new TaskbarIcon
            {
                ToolTipText = "Disk Mount Utility"
            };

            string iconPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "app.ico");
            if (!System.IO.File.Exists(iconPath))
                throw new InvalidOperationException($"Tray icon not found at {iconPath}");

            _trayIcon.Icon = new Icon(iconPath);

            var menu = new ContextMenu();

            var openItem = new MenuItem { Header = "Open" };
            openItem.Click += (s, e) => ShowMainWindow();

            var exitItem = new MenuItem { Header = "Exit" };
            exitItem.Click += async (s, e) =>
            {
                _trayIcon!.IsEnabled = false;

                await AppShutdownCoordinator.SafeShutdownAsync(_services);

                Dispose();
                Application.Current.Shutdown();
            };

            menu.Items.Add(openItem);
            menu.Items.Add(new Separator());
            menu.Items.Add(exitItem);

            _trayIcon.ContextMenu = menu;

            _trayIcon.TrayMouseDoubleClick += (s, e) => ShowMainWindow();
        }

        private void ShowMainWindow()
        {
            if (!_mainWindow.IsVisible)
                _mainWindow.Show();

            if (_mainWindow.WindowState == WindowState.Minimized)
                _mainWindow.WindowState = WindowState.Normal;

            _mainWindow.Activate();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _trayIcon?.Dispose();
            _disposed = true;
        }
    }
}