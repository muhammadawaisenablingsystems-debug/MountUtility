using System;
using System.Drawing;
using System.Windows;
using System.Windows.Controls;
using Hardcodet.Wpf.TaskbarNotification;

namespace MountUtility.WPF.Service
{
    public class TrayIconService : IDisposable
    {
        private TaskbarIcon? _trayIcon;
        private bool _disposed;

        public void Initialize()
        {
            _trayIcon = new TaskbarIcon
            {
                ToolTipText = "Disk Mount Utility"
            };

            // Load icon from WPF resource
            string iconPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "app.ico");
            if (!System.IO.File.Exists(iconPath))
                throw new InvalidOperationException($"Tray icon not found at {iconPath}");

            _trayIcon.Icon = new Icon(iconPath);

            // Create context menu
            var menu = new ContextMenu();

            // Open menu item
            var openItem = new MenuItem { Header = "Open" };
            openItem.Click += (s, e) =>
            {
                var main = Application.Current.MainWindow;
                if (main != null)
                {
                    if (!main.IsVisible) main.Show();
                    if (main.WindowState == WindowState.Minimized)
                        main.WindowState = WindowState.Normal;
                    main.Activate();
                }
            };

            // Exit menu item
            var exitItem = new MenuItem { Header = "Exit" };
            exitItem.Click += (s, e) =>
            {
                Dispose();
                Application.Current.Shutdown();
            };

            // Add items to context menu
            menu.Items.Add(openItem);
            menu.Items.Add(new Separator());
            menu.Items.Add(exitItem);

            _trayIcon.ContextMenu = menu;

            // Double-click on tray icon opens main window
            _trayIcon.TrayMouseDoubleClick += (s, e) =>
            {
                openItem.RaiseEvent(new RoutedEventArgs(MenuItem.ClickEvent));
            };
        }

        public void Dispose()
        {
            if (_disposed) return;
            _trayIcon?.Dispose();
            _disposed = true;
        }
    }
}