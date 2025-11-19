using System.Windows;

namespace MountUtility.WPF.Views.Dialogs
{
    public partial class CreateFolderDialog : Window
    {
        public string? FolderName { get; private set; }

        public CreateFolderDialog()
        {
            InitializeComponent();
        }

        private void Create_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(FolderNameTextBox.Text))
            {
                ErrorMessage.Text = "Please enter a folder name";
                ErrorMessage.Visibility = Visibility.Visible;
                return;
            }

            FolderName = FolderNameTextBox.Text;
            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}