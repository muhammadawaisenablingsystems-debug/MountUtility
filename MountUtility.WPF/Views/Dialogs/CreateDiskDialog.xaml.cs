using System.Windows;
using DiskMountUtility.Application.DTOs;

namespace MountUtility.WPF.Views.Dialogs
{
    public partial class CreateDiskDialog : Window
    {
        public CreateDiskRequest? Result { get; private set; }

        public CreateDiskDialog()
        {
            InitializeComponent();
        }

        private void Create_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(DiskNameTextBox.Text) ||
                string.IsNullOrWhiteSpace(PasswordBox.Password))
            {
                ErrorMessage.Text = "Please fill in all fields correctly";
                ErrorMessage.Visibility = Visibility.Visible;
                return;
            }

            if (!long.TryParse(DiskSizeTextBox.Text, out var size) || size <= 0)
            {
                ErrorMessage.Text = "Please enter a valid size in MB";
                ErrorMessage.Visibility = Visibility.Visible;
                return;
            }

            Result = new CreateDiskRequest
            {
                Name = DiskNameTextBox.Text,
                SizeInMB = size,
                Password = PasswordBox.Password
            };

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