using DiskMountUtility.Application.DTOs;
using MountUtility.Services;
using Microsoft.Win32;
using MountUtility.WPF.Views.Dialogs;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace MountUtility.WPF.Views
{
    public partial class FileExplorerWindow : Window
    {
        private readonly DiskManagementService _diskService;
        private DiskInfoResponse? _mountedDisk;
        private string _currentPath = "/";
        private ObservableCollection<FileViewModel> _files = new();
        private ObservableCollection<BreadcrumbItem> _breadcrumbs = new();
        private string? _subscriptionId;

        public FileExplorerWindow(DiskManagementService diskService)
        {
            InitializeComponent();
            _diskService = diskService;
            FilesDataGrid.ItemsSource = _files;
            BreadcrumbControl.ItemsSource = _breadcrumbs;

            Loaded += FileExplorerWindow_Loaded;
            Closing += FileExplorerWindow_Closing;
        }

        private async void FileExplorerWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _mountedDisk = await _diskService.GetMountedDiskInfoAsync();

            if (_mountedDisk == null)
            {
                MessageBox.Show("No disk mounted. Please mount a disk first.", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                this.Close();
                return;
            }

            TitleText.Text = $"File Explorer - {_mountedDisk.Name}";

            _subscriptionId = _diskService.SubscribeToFileChanges(async () =>
            {
                await Dispatcher.InvokeAsync(async () => await LoadFiles());
            });

            await LoadFiles();
        }

        private void FileExplorerWindow_Closing(object sender, CancelEventArgs e)
        {
            if (!string.IsNullOrEmpty(_subscriptionId))
            {
                _diskService.UnsubscribeFromFileChanges(_subscriptionId);
            }

            e.Cancel = true;
            this.Hide();
        }

        private async Task LoadFiles()
        {
            if (_mountedDisk == null) return;

            try
            {
                var filesList = await _diskService.GetFilesAsync(_mountedDisk.Id, _currentPath);

                _files.Clear();
                foreach (var file in filesList)
                {
                    _files.Add(new FileViewModel(file));
                }

                UpdateBreadcrumbs();

                NoFilesMessage.Visibility = _files.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to load files: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateBreadcrumbs()
        {
            _breadcrumbs.Clear();

            if (_currentPath == "/") return;

            var parts = _currentPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var accumulated = "";

            foreach (var part in parts)
            {
                accumulated += "/" + part;
                _breadcrumbs.Add(new BreadcrumbItem { Name = part, Path = accumulated });
            }
        }

        private async void BreadcrumbButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var path = button?.Tag as string;
            if (path != null)
            {
                _currentPath = path;
                await LoadFiles();
            }
        }

        private async void FilesDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var selected = FilesDataGrid.SelectedItem as FileViewModel;
            if (selected != null && selected.IsDirectory)
            {
                _currentPath = selected.Path;
                await LoadFiles();
            }
        }

        private async void ShowUploadDialog_Click(object sender, RoutedEventArgs e)
        {
            if (_mountedDisk == null) return;

            var openFileDialog = new OpenFileDialog
            {
                Title = "Select File to Upload",
                Multiselect = false
            };

            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    var fileBytes = await File.ReadAllBytesAsync(openFileDialog.FileName);
                    var fileName = Path.GetFileName(openFileDialog.FileName);

                    var request = new WriteFileRequest
                    {
                        Path = _currentPath,
                        FileName = fileName,
                        Content = fileBytes
                    };

                    var success = await _diskService.WriteFileAsync(_mountedDisk.Id, request);
                    if (success)
                    {
                        await LoadFiles();
                    }
                    else
                    {
                        MessageBox.Show("Failed to upload file. Check disk space.", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Upload failed: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void ShowCreateFolderDialog_Click(object sender, RoutedEventArgs e)
        {
            if (_mountedDisk == null) return;

            var dialog = new CreateFolderDialog();
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var folderPath = _currentPath == "/"
                        ? $"/{dialog.FolderName}"
                        : $"{_currentPath}/{dialog.FolderName}";

                    var success = await _diskService.CreateDirectoryAsync(_mountedDisk.Id, folderPath);
                    if (success)
                    {
                        await LoadFiles();
                    }
                    else
                    {
                        MessageBox.Show("Failed to create folder", "Error",
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

        private async void RefreshFiles_Click(object sender, RoutedEventArgs e)
        {
            await LoadFiles();
        }

        private async void PreviewFile_Click(object sender, RoutedEventArgs e)
        {
            if (_mountedDisk == null) return;

            var button = sender as Button;
            var file = button?.Tag as FileViewModel;
            if (file == null) return;

            try
            {
                var content = await _diskService.ReadFileAsync(_mountedDisk.Id, file.Path);
                if (content != null)
                {
                    var dialog = new FilePreviewDialog(file.Name, content);
                    dialog.ShowDialog();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Preview failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void DownloadFile_Click(object sender, RoutedEventArgs e)
        {
            if (_mountedDisk == null) return;

            var button = sender as Button;
            var file = button?.Tag as FileViewModel;
            if (file == null) return;

            try
            {
                var saveFileDialog = new SaveFileDialog
                {
                    FileName = file.Name,
                    Title = "Save File"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    var content = await _diskService.ReadFileAsync(_mountedDisk.Id, file.Path);
                    if (content != null)
                    {
                        await File.WriteAllBytesAsync(saveFileDialog.FileName, content);
                        MessageBox.Show("File downloaded successfully!", "Success",
                            MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Download failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void DeleteFile_Click(object sender, RoutedEventArgs e)
        {
            if (_mountedDisk == null) return;

            var button = sender as Button;
            var file = button?.Tag as FileViewModel;
            if (file == null) return;

            var result = MessageBox.Show(
                $"Are you sure you want to delete '{file.Name}'?",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    var success = await _diskService.DeleteFileAsync(_mountedDisk.Id, file.Path);
                    if (success)
                    {
                        await LoadFiles();
                    }
                    else
                    {
                        MessageBox.Show("Failed to delete file", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to delete file: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BackToDashboard_Click(object sender, RoutedEventArgs e)
        {
            this.Hide();
        }
    }

    public class FileViewModel : INotifyPropertyChanged
    {
        public string Name { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public long SizeInBytes { get; set; }
        public bool IsDirectory { get; set; }
        public DateTime ModifiedAt { get; set; }

        public string DisplayName => (IsDirectory ? "📁 " : "📄 ") + Name;
        public string FormattedSize => IsDirectory ? "" : FormatBytes(SizeInBytes);
        public string FormattedModified => ModifiedAt.ToLocalTime().ToString("g");
        public bool IsFile => !IsDirectory;

        public event PropertyChangedEventHandler? PropertyChanged;

        public FileViewModel(FileInfoResponse file)
        {
            Name = file.Name;
            Path = file.Path;
            SizeInBytes = file.SizeInBytes;
            IsDirectory = file.IsDirectory;
            ModifiedAt = file.ModifiedAt;
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

    public class BreadcrumbItem
    {
        public string Name { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
    }
}