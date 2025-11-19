using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Media.Imaging;

namespace MountUtility.WPF.Views.Dialogs
{
    public partial class FilePreviewDialog : Window
    {
        public FilePreviewDialog(string fileName, byte[] content)
        {
            InitializeComponent();

            TitleText.Text = fileName;

            var extension = Path.GetExtension(fileName).ToLower();

            switch (extension)
            {
                case ".jpg":
                case ".jpeg":
                case ".png":
                case ".gif":
                case ".bmp":
                    ShowImagePreview(content);
                    break;

                case ".txt":
                case ".log":
                case ".json":
                case ".xml":
                case ".csv":
                case ".cs":
                case ".js":
                case ".html":
                case ".css":
                case ".md":
                    ShowTextPreview(content);
                    break;

                default:
                    ShowUnsupportedMessage();
                    break;
            }
        }

        private void ShowTextPreview(byte[] content)
        {
            try
            {
                var text = Encoding.UTF8.GetString(content);
                TextPreview.Text = text;
                TextPreview.Visibility = Visibility.Visible;
            }
            catch
            {
                ShowUnsupportedMessage();
            }
        }

        private void ShowImagePreview(byte[] content)
        {
            try
            {
                using var ms = new MemoryStream(content);
                var bitmap = new BitmapImage();
                bitmap.BeginInit();
                bitmap.CacheOption = BitmapCacheOption.OnLoad;
                bitmap.StreamSource = ms;
                bitmap.EndInit();
                bitmap.Freeze();

                ImagePreview.Source = bitmap;
                ImagePreview.Visibility = Visibility.Visible;
            }
            catch
            {
                ShowUnsupportedMessage();
            }
        }

        private void ShowUnsupportedMessage()
        {
            UnsupportedMessage.Visibility = Visibility.Visible;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}