using System.Windows;

namespace MountUtility.WPF.Views.Dialogs
{
    public partial class RenameDialog : Window
    {
        public string NewName { get; private set; } = string.Empty;

        public RenameDialog(string currentName)
        {
            InitializeComponent();

            NewNameTextBox.Text = currentName;
            NewNameTextBox.SelectAll();
            NewNameTextBox.Focus();
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(NewNameTextBox.Text))
            {
                MessageBox.Show("Name cannot be empty", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (NewNameTextBox.Text.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0)
            {
                MessageBox.Show("Name contains invalid characters", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            NewName = NewNameTextBox.Text;
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