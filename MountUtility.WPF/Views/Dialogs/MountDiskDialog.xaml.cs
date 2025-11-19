using System.Windows;

namespace MountUtility.WPF.Views.Dialogs
{
    public partial class MountDiskDialog : Window
    {
        public string? Password { get; private set; }

        public MountDiskDialog()
        {
            InitializeComponent();
        }

        private void Mount_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(PasswordBox.Password))
            {
                ErrorMessage.Text = "Please enter the password";
                ErrorMessage.Visibility = Visibility.Visible;
                return;
            }

            Password = PasswordBox.Password;
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