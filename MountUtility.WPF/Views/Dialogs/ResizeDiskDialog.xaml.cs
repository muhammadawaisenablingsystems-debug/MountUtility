using System.Windows;

namespace MountUtility.WPF.Views.Dialogs
{
    public partial class ResizeDiskDialog : Window
    {
        public long NewSizeInMB { get; private set; }
        public string? Password { get; private set; }
        private readonly long _currentSizeInBytes;

        public ResizeDiskDialog(string diskName, long currentSizeInBytes, bool requirePassword = false)
        {
            InitializeComponent();

            _currentSizeInBytes = currentSizeInBytes;
            var currentSizeMB = currentSizeInBytes / (1024 * 1024);

            DiskInfoText.Text = diskName;
            CurrentSizeText.Text = $"Current size: {FormatBytes(currentSizeInBytes)}";
            NewSizeTextBox.Text = currentSizeMB.ToString();

            if (requirePassword)
            {
                PasswordPanel.Visibility = Visibility.Visible;
            }
        }

        private void Resize_Click(object sender, RoutedEventArgs e)
        {
            if (!long.TryParse(NewSizeTextBox.Text, out var newSize) || newSize <= 0)
            {
                ErrorMessage.Text = "Please enter a valid size in MB";
                ErrorMessage.Visibility = Visibility.Visible;
                return;
            }

            var currentSizeMB = _currentSizeInBytes / (1024 * 1024);
            if (newSize < currentSizeMB)
            {
                ErrorMessage.Text = "New size must be larger than current size";
                ErrorMessage.Visibility = Visibility.Visible;
                return;
            }

            if (PasswordPanel.Visibility == Visibility.Visible &&
                string.IsNullOrWhiteSpace(PasswordBox.Password))
            {
                ErrorMessage.Text = "Password is required to resize unmounted disk";
                ErrorMessage.Visibility = Visibility.Visible;
                return;
            }

            NewSizeInMB = newSize;
            Password = PasswordPanel.Visibility == Visibility.Visible ? PasswordBox.Password : null;
            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
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