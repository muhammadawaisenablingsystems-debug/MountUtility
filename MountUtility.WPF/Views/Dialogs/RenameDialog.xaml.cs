using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace MountUtility.WPF.Views.Dialogs
{
    public partial class RenameDialog : Window
    {
        private readonly string _extension;
        private bool _internalUpdate;

        public string NewName { get; private set; } = string.Empty;

        public RenameDialog(string currentName)
        {
            InitializeComponent();

            _extension = Path.GetExtension(currentName);
            string nameOnly = Path.GetFileNameWithoutExtension(currentName);

            NewNameTextBox.Text = nameOnly + _extension;

            Loaded += (_, _) =>
            {
                // Select only filename (not extension)
                NewNameTextBox.SelectionStart = 0;
                NewNameTextBox.SelectionLength = nameOnly.Length;
                NewNameTextBox.Focus();
            };

            NewNameTextBox.TextChanged += NewNameTextBox_TextChanged;
        }

        private void NewNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_internalUpdate)
                return;

            _internalUpdate = true;

            // Always restore extension
            string nameOnly = Path.GetFileNameWithoutExtension(NewNameTextBox.Text);
            NewNameTextBox.Text = nameOnly + _extension;

            // Keep caret before extension
            NewNameTextBox.SelectionStart = nameOnly.Length;
            NewNameTextBox.SelectionLength = 0;

            _internalUpdate = false;
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            string nameOnly = Path.GetFileNameWithoutExtension(NewNameTextBox.Text);

            if (string.IsNullOrWhiteSpace(nameOnly))
            {
                MessageBox.Show("Name cannot be empty", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (nameOnly.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                MessageBox.Show("Name contains invalid characters", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            NewName = nameOnly + _extension;
            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}