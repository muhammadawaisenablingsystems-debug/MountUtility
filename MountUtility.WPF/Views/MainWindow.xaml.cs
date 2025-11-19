using DiskMountUtility.Application.DTOs;
using MountUtility.Services;
using DiskMountUtility.Infrastructure.Cryptography;
using MountUtility.Cryptography;
using MountUtility.WPF.Views.Dialogs;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;

namespace MountUtility.WPF.Views
{
    public partial class MainWindow : Window
    {
        private readonly DiskManagementService _diskService;
        private readonly FileExplorerWindow _fileExplorer;
        private bool _isVaultUnlocked;
        private DiskInfoResponse? _mountedDisk;
        private ObservableCollection<DiskViewModel> _disks = new();

        public MainWindow(DiskManagementService diskService, FileExplorerWindow fileExplorer)
        {
            InitializeComponent();
            _diskService = diskService;
            _fileExplorer = fileExplorer;
            DisksListControl.ItemsSource = _disks;

            Loaded += MainWindow_Loaded;
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            LoadingPanel.Visibility = Visibility.Visible;

            await Task.Delay(500);

            VaultKeyManager.LoadSettingsIfExists();

            if (!VaultKeyManager.HasSavedSelection())
            {
                MessageBox.Show("Please complete first-run setup.", "Setup Required",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                Application.Current.Shutdown();
                return;
            }

            LoadingPanel.Visibility = Visibility.Collapsed;
            VaultUnlockPanel.Visibility = Visibility.Visible;
        }

        private async void UnlockVault_Click(object sender, RoutedEventArgs e)
        {
            var password = VaultPasswordBox.Password;

            if (string.IsNullOrWhiteSpace(password))
            {
                VaultErrorMessage.Text = "Please enter your vault password.";
                VaultErrorMessage.Visibility = Visibility.Visible;
                return;
            }

            try
            {
                VaultKeyManager.Initialize(password);
                await _diskService.EnsureDatabaseReadyAsync();
                await _diskService.InitializeDisksAfterUnlockAsync();

                _isVaultUnlocked = true;

                await LoadDisks();

                VaultUnlockPanel.Visibility = Visibility.Collapsed;
                MainContentPanel.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                VaultErrorMessage.Text = $"Failed to unlock vault: {ex.Message}";
                VaultErrorMessage.Visibility = Visibility.Visible;
            }
        }

        private async Task LoadDisks()
        {
            try
            {
                var disksList = await _diskService.GetAllDisksAsync();
                _mountedDisk = await _diskService.GetMountedDiskInfoAsync();

                _disks.Clear();
                foreach (var disk in disksList)
                {
                    _disks.Add(new DiskViewModel(disk));
                }

                if (_mountedDisk != null)
                {
                    UpdateMountedDiskUI();
                }
                else
                {
                    MountedDiskSection.Visibility = Visibility.Collapsed;
                }

                NoDisksMessage.Visibility = _disks.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to load disks: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateMountedDiskUI()
        {
            if (_mountedDisk == null) return;

            MountedDiskSection.Visibility = Visibility.Visible;
            MountedDiskTitle.Text = $"Mounted Disk: {_mountedDisk.Name}";
            MountedDiskName.Text = _mountedDisk.Name;
            MountedDiskSize.Text = FormatBytes(_mountedDisk.SizeInBytes);
            MountedDiskUsed.Text = FormatBytes(_mountedDisk.UsedSpaceInBytes);
            MountedDiskFree.Text = FormatBytes(_mountedDisk.FreeSpaceInBytes);
            MountedDiskProgress.Value = _mountedDisk.UsagePercentage;
            MountedDiskPercentage.Text = $"{_mountedDisk.UsagePercentage:F2}% used";
        }

        private async void ShowCreateDialog_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new CreateDiskDialog();
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    await _diskService.CreateDiskAsync(dialog.Result!);
                    await LoadDisks();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to create disk: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void MountDisk_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var disk = button?.Tag as DiskViewModel;
            if (disk == null) return;

            var dialog = new MountDiskDialog();
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var request = new MountDiskRequest
                    {
                        DiskId = disk.Id,
                        Password = dialog.Password!
                    };

                    var success = await _diskService.MountDiskAsync(request);
                    if (success)
                    {
                        await LoadDisks();
                    }
                    else
                    {
                        MessageBox.Show("Failed to mount disk. Check your password.", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void UnmountDisk_Click(object sender, RoutedEventArgs e)
        {
            if (_mountedDisk == null) return;

            try
            {
                await _diskService.UnmountPhysicalAsync(_mountedDisk.Id);
                await _diskService.UnmountDiskAsync(_mountedDisk.Id);
                await LoadDisks();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to unmount disk: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ResizeDisk_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var disk = button?.Tag as DiskViewModel;
            if (disk == null) return;

            var dialog = new ResizeDiskDialog(disk.Name, disk.SizeInBytes);
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var request = new ResizeDiskRequest
                    {
                        DiskId = disk.Id,
                        NewSizeInMB = dialog.NewSizeInMB
                    };

                    bool success;
                    if (disk.Status != "Mounted" && !string.IsNullOrEmpty(dialog.Password))
                    {
                        success = await _diskService.ResizeDiskAsync(request, dialog.Password);
                    }
                    else
                    {
                        success = await _diskService.ResizeDiskAsync(request);
                    }

                    if (success)
                    {
                        await LoadDisks();
                    }
                    else
                    {
                        MessageBox.Show("Failed to resize disk.", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ResizeMountedDisk_Click(object sender, RoutedEventArgs e)
        {
            if (_mountedDisk == null) return;

            var diskVm = new DiskViewModel(_mountedDisk);
            ResizeDisk_Click(sender, e);
        }

        private async void DeleteDisk_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var disk = button?.Tag as DiskViewModel;
            if (disk == null) return;

            var result = MessageBox.Show(
                "Are you sure you want to delete this disk? This action cannot be undone.",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    await _diskService.DeleteDiskAsync(disk.Id);
                    await LoadDisks();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to delete disk: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BrowseFiles_Click(object sender, RoutedEventArgs e)
        {
            _fileExplorer.Show();
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            e.Cancel = true;
            this.WindowState = WindowState.Minimized;
            this.Hide();
        }

        private void Window_StateChanged(object sender, EventArgs e)
        {
            if (WindowState == WindowState.Minimized)
            {
                this.Hide();
            }
        }

        private string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }
    }

    public class DiskViewModel : INotifyPropertyChanged
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public long SizeInBytes { get; set; }
        public string Status { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }

        public string FormattedSize => FormatBytes(SizeInBytes);
        public string FormattedCreatedAt => CreatedAt.ToLocalTime().ToString("g");
        public bool IsNotMounted => Status != "Mounted";

        public event PropertyChangedEventHandler? PropertyChanged;

        public DiskViewModel(DiskInfoResponse disk)
        {
            Id = disk.Id;
            Name = disk.Name;
            SizeInBytes = disk.SizeInBytes;
            Status = disk.Status;
            CreatedAt = disk.CreatedAt;
        }

        private string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }
    }
}