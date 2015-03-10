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
            //var keyPublicXml =  new XDocument(rsaKey.ToXmlString(false));
            KeySizeTextBlock.Text = rsaKey.KeySize.ToString();
            PublicKeyGenTextBox.Text = rsaKey.ToXmlString(false);
            PrivateKeyGenTextBox.Text = rsaKey.ToXmlString(true);
        }
    }
}
