using MountUtility.Services;
using Microsoft.Win32;
using MountUtility.WPF.Views.Dialogs;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using MountUtility.WPF.DTOs;
using MountUtility.WPF.Helpers;
using System.Collections.Generic;
using System.Linq;

namespace MountUtility.WPF.Views
{
    public partial class FileExplorerWindow : Window, INotifyPropertyChanged
    {
        private readonly DiskManagementService _diskService;
        private DiskInfoResponse? _mountedDisk;
        private string _currentPath = "/";
        private ObservableCollection<FileViewModel> _files = new();
        private ObservableCollection<BreadcrumbItem> _breadcrumbs = new();
        private string? _subscriptionId;
        private bool _isLoading = false;

        private List<string> _navigationHistory = new();
        private int _navigationIndex = -1;
        private bool _isNavigating = false;

        private List<FileViewModel> _clipboardItems = new();
        private ClipboardOperation _clipboardOperation = ClipboardOperation.None;

        private Point _dragStartPoint;
        private bool _isDragging = false;

        private ViewMode _currentViewMode = ViewMode.Details;

        public event PropertyChangedEventHandler? PropertyChanged;

        public bool CanGoBack => _navigationIndex > 0;
        public bool CanGoForward => _navigationIndex < _navigationHistory.Count - 1;

        public FileExplorerWindow(DiskManagementService diskService)
        {
            InitializeComponent();
            _diskService = diskService;
            FilesListView.ItemsSource = _files;
            BreadcrumbControl.ItemsSource = _breadcrumbs;

            SetDetailsView();

            Loaded += FileExplorerWindow_Loaded;
            Closing += FileExplorerWindow_Closing;

            DataContext = this;
        }

        public static string NormalizePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return "/";

            path = path.Replace("\\", "/").Trim();

            if (path == "/") return "/";

            if (!path.StartsWith("/")) path = "/" + path;
            if (path.Length > 1 && path.EndsWith("/")) path = path.TrimEnd('/');

            return path;
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

            if (_isLoading) return;
            _isLoading = true;

            try
            {
                _currentPath = NormalizePath(_currentPath);

                if (!_isNavigating)
                {
                    if (_navigationIndex < _navigationHistory.Count - 1)
                    {
                        _navigationHistory.RemoveRange(_navigationIndex + 1, _navigationHistory.Count - _navigationIndex - 1);
                    }

                    if (_navigationHistory.Count == 0 || _navigationHistory[_navigationHistory.Count - 1] != _currentPath)
                    {
                        _navigationHistory.Add(_currentPath);
                        _navigationIndex = _navigationHistory.Count - 1;
                    }
                }

                _isNavigating = false;

                var filesList = await _diskService.GetFilesAsync(_mountedDisk.Id, _currentPath);

                if (filesList == null) filesList = new List<FileInfoResponse>();

                _files.Clear();
                foreach (var file in filesList.OrderByDescending(f => f.IsDirectory).ThenBy(f => f.Name))
                {
                    _files.Add(new FileViewModel(file));
                }

                UpdateBreadcrumbs();
                UpdateNavigationButtons();
                UpdateStatusBar();

                NoFilesMessage.Visibility = _files.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to load files: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _isLoading = false;
            }
        }

        private void UpdateBreadcrumbs()
        {
            _breadcrumbs.Clear();
            _breadcrumbs.Add(new BreadcrumbItem { Name = _mountedDisk?.Name ?? "Root", Path = "/" });

            var path = _currentPath.TrimEnd('/');
            if (path == "/") return;

            var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var accumulated = "";
            foreach (var part in parts)
            {
                accumulated += "/" + part;
                _breadcrumbs.Add(new BreadcrumbItem { Name = part, Path = accumulated });
            }
        }

        private void UpdateNavigationButtons()
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanGoBack)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanGoForward)));
        }

        private void UpdateStatusBar()
        {
            var itemCount = _files.Count;
            var folderCount = _files.Count(f => f.IsDirectory);
            var fileCount = itemCount - folderCount;

            ItemCountText.Text = $"{itemCount} item{(itemCount != 1 ? "s" : "")} ({folderCount} folder{(folderCount != 1 ? "s" : "")}, {fileCount} file{(fileCount != 1 ? "s" : "")})";

            var selectedCount = FilesListView.SelectedItems.Count;
            if (selectedCount > 0)
            {
                StatusText.Text = $"{selectedCount} item{(selectedCount != 1 ? "s" : "")} selected";
            }
            else
            {
                StatusText.Text = "Ready";
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

        private async void FilesListView_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (FilesListView.SelectedItem is FileViewModel selected && selected.IsDirectory)
            {
                var newPath = NormalizePath(selected.Path);
                if (newPath != _currentPath)
                {
                    _currentPath = newPath;
                    await LoadFiles();
                }
            }
        }

        private void FilesListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var hasSelection = FilesListView.SelectedItems.Count > 0;
            var hasFileSelected = FilesListView.SelectedItems.Cast<FileViewModel>().Any(f => f.IsFile);
            var hasSingleSelection = FilesListView.SelectedItems.Count == 1;

            CutButton.IsEnabled = hasSelection;
            CopyButton.IsEnabled = hasSelection;
            RenameButton.IsEnabled = hasSingleSelection;
            DeleteButton.IsEnabled = hasSelection;
            DownloadButton.IsEnabled = hasFileSelected;
            PreviewButton.IsEnabled = hasFileSelected && hasSingleSelection;

            if (FilesListView.ContextMenu != null)
            {
                ContextDownloadMenuItem.IsEnabled = hasFileSelected;
                ContextPreviewMenuItem.IsEnabled = hasFileSelected && hasSingleSelection;
            }

            UpdateStatusBar();
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
                        Path = NormalizePath(_currentPath),
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
                    var folderPath = NormalizePath($"{_currentPath.TrimEnd('/')}/{dialog.FolderName}");

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

        public void ResetExplorer()
        {
            _currentPath = "/";
            _breadcrumbs.Clear();
            _navigationHistory.Clear();
            _navigationIndex = -1;
        }

        private async void RefreshFiles_Click(object sender, RoutedEventArgs e)
        {
            await LoadFiles();
        }

        private async void PreviewFile_Click(object sender, RoutedEventArgs e)
        {
            if (_mountedDisk == null) return;

            var file = FilesListView.SelectedItem as FileViewModel;
            if (file == null || !file.IsFile) return;

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

            var selectedFiles = FilesListView.SelectedItems.Cast<FileViewModel>().Where(f => f.IsFile).ToList();
            if (selectedFiles.Count == 0) return;

            try
            {
                if (selectedFiles.Count == 1)
                {
                    var file = selectedFiles[0];
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
                else
                {
                    var dialog = new OpenFileDialog
                    {
                        Title = "Select folder to save files",
                        CheckFileExists = false,
                        CheckPathExists = true,
                        FileName = "Select Folder"
                    };

                    if (dialog.ShowDialog() == true)
                    {
                        var folderPath = Path.GetDirectoryName(dialog.FileName)!;

                        foreach (var file in selectedFiles)
                        {
                            var content = await _diskService.ReadFileAsync(_mountedDisk.Id, file.Path);
                            if (content != null)
                            {
                                var savePath = Path.Combine(folderPath, file.Name);
                                await File.WriteAllBytesAsync(savePath, content);
                            }
                        }

                        MessageBox.Show(
                            $"{selectedFiles.Count} files downloaded successfully!",
                            "Success",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
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

            var selectedItems = FilesListView.SelectedItems.Cast<FileViewModel>().ToList();
            if (selectedItems.Count == 0) return;

            var itemText = selectedItems.Count == 1 ? $"'{selectedItems[0].Name}'" : $"{selectedItems.Count} items";
            var result = MessageBox.Show(
                $"Are you sure you want to delete {itemText}?",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    var failedItems = new List<string>();

                    foreach (var item in selectedItems)
                    {
                        var success = await _diskService.DeleteFileAsync(_mountedDisk.Id, item.Path);
                        if (!success)
                        {
                            failedItems.Add(item.Name);
                        }
                    }

                    if (failedItems.Count > 0)
                    {
                        MessageBox.Show($"Failed to delete: {string.Join(", ", failedItems)}", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                    }

                    await LoadFiles();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to delete: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BackToDashboard_Click(object sender, RoutedEventArgs e)
        {
            ResetExplorer();
            this.Hide();
        }

        private async void GoUp_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_currentPath) || _currentPath == "/") return;

            var normalized = NormalizePath(_currentPath);

            var lastSlash = normalized.LastIndexOf('/');
            if (lastSlash <= 0)
            {
                _currentPath = "/";
            }
            else
            {
                var parent = normalized.Substring(0, lastSlash);
                _currentPath = string.IsNullOrEmpty(parent) ? "/" : NormalizePath(parent);
            }

            await LoadFiles();
        }

        private async void GoBack_Click(object sender, RoutedEventArgs e)
        {
            if (CanGoBack)
            {
                _navigationIndex--;
                _currentPath = _navigationHistory[_navigationIndex];
                _isNavigating = true;
                await LoadFiles();
            }
        }

        private async void GoForward_Click(object sender, RoutedEventArgs e)
        {
            if (CanGoForward)
            {
                _navigationIndex++;
                _currentPath = _navigationHistory[_navigationIndex];
                _isNavigating = true;
                await LoadFiles();
            }
        }

        private void Cut_Click(object sender, RoutedEventArgs e)
        {
            _clipboardItems = FilesListView.SelectedItems.Cast<FileViewModel>().ToList();
            _clipboardOperation = ClipboardOperation.Cut;
            PasteButton.IsEnabled = true;
            ContextPasteMenuItem.IsEnabled = true;

            StatusText.Text = $"{_clipboardItems.Count} item{(_clipboardItems.Count != 1 ? "s" : "")} cut";
        }

        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            _clipboardItems = FilesListView.SelectedItems.Cast<FileViewModel>().ToList();
            _clipboardOperation = ClipboardOperation.Copy;
            PasteButton.IsEnabled = true;
            ContextPasteMenuItem.IsEnabled = true;

            StatusText.Text = $"{_clipboardItems.Count} item{(_clipboardItems.Count != 1 ? "s" : "")} copied";
        }

        private async void Paste_Click(object sender, RoutedEventArgs e)
        {
            if (_mountedDisk == null || _clipboardItems.Count == 0) return;

            try
            {
                foreach (var item in _clipboardItems)
                {
                    var targetPath = NormalizePath($"{_currentPath.TrimEnd('/')}/{item.Name}");

                    if (item.IsFile)
                    {
                        var content = await _diskService.ReadFileAsync(_mountedDisk.Id, item.Path);
                        if (content != null)
                        {
                            var request = new WriteFileRequest
                            {
                                Path = NormalizePath(_currentPath),
                                FileName = item.Name,
                                Content = content
                            };

                            await _diskService.WriteFileAsync(_mountedDisk.Id, request);
                        }
                    }
                    else
                    {
                        await _diskService.CreateDirectoryAsync(_mountedDisk.Id, targetPath);
                    }

                    if (_clipboardOperation == ClipboardOperation.Cut)
                    {
                        await _diskService.DeleteFileAsync(_mountedDisk.Id, item.Path);
                    }
                }

                if (_clipboardOperation == ClipboardOperation.Cut)
                {
                    _clipboardItems.Clear();
                    _clipboardOperation = ClipboardOperation.None;
                    PasteButton.IsEnabled = false;
                    ContextPasteMenuItem.IsEnabled = false;
                }

                await LoadFiles();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Paste failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void Rename_Click(object sender, RoutedEventArgs e)
        {
            if (_mountedDisk == null) return;

            var item = FilesListView.SelectedItem as FileViewModel;
            if (item == null) return;

            var dialog = new RenameDialog(item.Name);
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var parentPath = item.Path.Substring(0, item.Path.LastIndexOf('/'));
                    if (string.IsNullOrEmpty(parentPath)) parentPath = "/";

                    var newPath = NormalizePath($"{parentPath.TrimEnd('/')}/{dialog.NewName}");

                    if (item.IsFile)
                    {
                        var content = await _diskService.ReadFileAsync(_mountedDisk.Id, item.Path);
                        if (content != null)
                        {
                            var request = new WriteFileRequest
                            {
                                Path = NormalizePath(parentPath),
                                FileName = dialog.NewName,
                                Content = content
                            };

                            var success = await _diskService.WriteFileAsync(_mountedDisk.Id, request);
                            if (success)
                            {
                                await _diskService.DeleteFileAsync(_mountedDisk.Id, item.Path);
                                await LoadFiles();
                            }
                        }
                    }
                    else
                    {
                        MessageBox.Show("Folder renaming not yet implemented", "Information",
                            MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Rename failed: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void FilesListView_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            _dragStartPoint = e.GetPosition(null);
        }

        private void FilesListView_MouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed && !_isDragging)
            {
                Point position = e.GetPosition(null);
                if (Math.Abs(position.X - _dragStartPoint.X) > SystemParameters.MinimumHorizontalDragDistance ||
                    Math.Abs(position.Y - _dragStartPoint.Y) > SystemParameters.MinimumVerticalDragDistance)
                {
                    StartDrag();
                }
            }
        }

        private void StartDrag()
        {
            if (FilesListView.SelectedItems.Count == 0) return;

            _isDragging = true;
            var selectedItems = FilesListView.SelectedItems.Cast<FileViewModel>().ToList();

            var dataObject = new DataObject("FileExplorerItems", selectedItems);
            DragDrop.DoDragDrop(FilesListView, dataObject, DragDropEffects.Copy | DragDropEffects.Move);

            _isDragging = false;
        }

        private void FilesListView_DragOver(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent("FileExplorerItems"))
            {
                e.Effects = (e.KeyStates & DragDropKeyStates.ControlKey) == DragDropKeyStates.ControlKey
                    ? DragDropEffects.Copy
                    : DragDropEffects.Move;
            }
            else if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }

            e.Handled = true;
        }

        private async void FilesListView_Drop(object sender, DragEventArgs e)
        {
            if (_mountedDisk == null) return;

            try
            {
                if (e.Data.GetDataPresent("FileExplorerItems"))
                {
                    var items = e.Data.GetData("FileExplorerItems") as List<FileViewModel>;
                    if (items != null)
                    {
                        var isCopy = (e.KeyStates & DragDropKeyStates.ControlKey) == DragDropKeyStates.ControlKey;

                        FileViewModel? targetFolder = null;
                        var dropPosition = e.GetPosition(FilesListView);
                        var element = FilesListView.InputHitTest(dropPosition) as FrameworkElement;

                        while (element != null && element != FilesListView)
                        {
                            if (element is ListViewItem listViewItem)
                            {
                                targetFolder = listViewItem.DataContext as FileViewModel;
                                break;
                            }
                            element = element.Parent as FrameworkElement;
                        }

                        var targetPath = targetFolder != null && targetFolder.IsDirectory
                            ? targetFolder.Path
                            : _currentPath;

                        foreach (var item in items)
                        {
                            if (item.Path.StartsWith(targetPath + "/"))
                            {
                                continue;
                            }

                            var newPath = NormalizePath($"{targetPath.TrimEnd('/')}/{item.Name}");

                            if (item.IsFile)
                            {
                                var content = await _diskService.ReadFileAsync(_mountedDisk.Id, item.Path);
                                if (content != null)
                                {
                                    var request = new WriteFileRequest
                                    {
                                        Path = NormalizePath(targetPath),
                                        FileName = item.Name,
                                        Content = content
                                    };

                                    await _diskService.WriteFileAsync(_mountedDisk.Id, request);

                                    if (!isCopy)
                                    {
                                        await _diskService.DeleteFileAsync(_mountedDisk.Id, item.Path);
                                    }
                                }
                            }
                        }

                        await LoadFiles();
                    }
                }
                else if (e.Data.GetDataPresent(DataFormats.FileDrop))
                {
                    var files = e.Data.GetData(DataFormats.FileDrop) as string[];
                    if (files != null)
                    {
                        foreach (var filePath in files)
                        {
                            if (File.Exists(filePath))
                            {
                                var fileBytes = await File.ReadAllBytesAsync(filePath);
                                var fileName = Path.GetFileName(filePath);

                                var request = new WriteFileRequest
                                {
                                    Path = NormalizePath(_currentPath),
                                    FileName = fileName,
                                    Content = fileBytes
                                };

                                await _diskService.WriteFileAsync(_mountedDisk.Id, request);
                            }
                        }

                        await LoadFiles();
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Drop operation failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ContextMenu_Open_Click(object sender, RoutedEventArgs e)
        {
            if (FilesListView.SelectedItem is FileViewModel selected && selected.IsDirectory)
            {
                _currentPath = NormalizePath(selected.Path);
                Task.Run(async () => await Dispatcher.InvokeAsync(async () => await LoadFiles()));
            }
        }

        private void SetDetailsView_Click(object sender, RoutedEventArgs e)
        {
            SetDetailsView();
        }

        private void SetTilesView_Click(object sender, RoutedEventArgs e)
        {
            SetTilesView();
        }

        private void SetListView_Click(object sender, RoutedEventArgs e)
        {
            SetListViewMode();
        }

        private void SetDetailsView()
        {
            _currentViewMode = ViewMode.Details;

            var gridView = new GridView();
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "Name",
                Width = 300,
                CellTemplate = (DataTemplate)FindResource("DetailsViewTemplate")
            });

            FilesListView.View = gridView;
            UpdateViewButtons();
        }

        private void SetTilesView()
        {
            _currentViewMode = ViewMode.Tiles;

            FilesListView.View = null;
            FilesListView.ItemTemplate = (DataTemplate)FindResource("TilesViewTemplate");

            FilesListView.ItemsPanel = new ItemsPanelTemplate(new FrameworkElementFactory(typeof(WrapPanel)));

            UpdateViewButtons();
        }

        private void SetListViewMode()
        {
            _currentViewMode = ViewMode.List;

            FilesListView.View = null;
            FilesListView.ItemTemplate = (DataTemplate)FindResource("ListViewTemplate");

            FilesListView.ItemsPanel = new ItemsPanelTemplate(new FrameworkElementFactory(typeof(StackPanel)));

            UpdateViewButtons();
        }

        private void UpdateViewButtons()
        {
            DetailsViewButton.Background = _currentViewMode == ViewMode.Details ? System.Windows.Media.Brushes.LightGray : System.Windows.Media.Brushes.Transparent;
            TilesViewButton.Background = _currentViewMode == ViewMode.Tiles ? System.Windows.Media.Brushes.LightGray : System.Windows.Media.Brushes.Transparent;
            ListViewButton.Background = _currentViewMode == ViewMode.List ? System.Windows.Media.Brushes.LightGray : System.Windows.Media.Brushes.Transparent;
        }
    }

    public class FileViewModel : INotifyPropertyChanged
    {
        public string Name { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public long SizeInBytes { get; set; }
        public bool IsDirectory { get; set; }
        public DateTime ModifiedAt { get; set; }

        public string IconGlyph => FileIconHelper.GetFileIcon(Name, IsDirectory);
        public string TypeDescription => FileIconHelper.GetFileTypeDescription(Name, IsDirectory);
        public string FormattedSize => IsDirectory ? "" : FormatBytes(SizeInBytes);
        public string FormattedModified => ModifiedAt.ToLocalTime().ToString("g");
        public bool IsFile => !IsDirectory;

        public event PropertyChangedEventHandler? PropertyChanged;

        public FileViewModel(FileInfoResponse file)
        {
            Name = file.Name;
            Path = FileExplorerWindow.NormalizePath(file.Path);
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

    public enum ClipboardOperation
    {
        None,
        Cut,
        Copy
    }

    public enum ViewMode
    {
        Details,
        Tiles,
        List
    }
}