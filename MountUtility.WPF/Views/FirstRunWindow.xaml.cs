using DiskMountUtility.Infrastructure.Cryptography;
using MountUtility.Cryptography;
using MountUtility.Enums;
using System.Windows;

namespace MountUtility.WPF.Views
{
    public partial class FirstRunWindow : Window
    {
        private readonly MainWindow _mainWindow;

        public FirstRunWindow(MainWindow mainWindow)
        {
            InitializeComponent();
            _mainWindow = mainWindow;
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedAlgo = KyberRadio.IsChecked == true
                    ? KeyExchangeAlgorithm.Kyber
                    : KeyExchangeAlgorithm.EcdhP256;

                VaultKeyManager.SelectedKeyExchange = selectedAlgo;

                _mainWindow.Show();
                this.Close();
            }
            catch (Exception ex)
            {
                ErrorMessage.Text = $"Error saving selection: {ex.Message}";
                ErrorMessage.Visibility = Visibility.Visible;
            }
        }
    }
}