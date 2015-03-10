using System.Security.Cryptography;
using System.Windows;

namespace EncryptDecrypt
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void GenerateButton_Click(object sender, RoutedEventArgs e)
        {
            var rsaKey = new RSACryptoServiceProvider() {PersistKeyInCsp = false};
            KeySizeTextBlock.Text = rsaKey.KeySize.ToString();
            PublicKeyGenTextBox.Text = rsaKey.ToXmlString(false);
            PrivateKeyGenTextBox.Text = rsaKey.ToXmlString(true);
        }

        private void CopyPublicKeyButton_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(PublicKeyGenTextBox.Text);
        }

        private void CopyPrivateKeyButton_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(PrivateKeyGenTextBox.Text);
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog();
            var result = dlg.ShowDialog();
            if (result == true)
            {
                var filename = dlg.FileName;
                FileToEncryptTextBox.Text = filename;
            }
        }
    }
}
