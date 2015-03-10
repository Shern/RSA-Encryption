using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Windows;

namespace EncryptDecrypt
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private const string encryptFolder = @"C:\RSA\Encrypt\";
        private const string decryptFolder = @"C:\RSA\Decrypt\";

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

        private void OpenFileEncryptButton_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog();
            var result = dlg.ShowDialog();
            if (result == true)
            {
                var filename = dlg.FileName;
                FileToEncryptTextBox.Text = filename;
            }
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            var filePath = FileToEncryptTextBox.Text;
            if (filePath.Equals(""))
            {
                MessageBox.Show("Pas de fichier sélectionné", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            var privateKey = new RSACryptoServiceProvider();
            try
            {
                privateKey.FromXmlString(PrivateKeyEncryptTextBox.Text);
            }
            catch (System.Security.XmlSyntaxException)
            {
                MessageBox.Show("Clé privée invalide.", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            var publicKey = new RSACryptoServiceProvider();
            try
            {
                publicKey.FromXmlString(PublicKeyGenTextBox.Text);
            }
            catch (System.Security.XmlSyntaxException)
            {
                MessageBox.Show("Clé publique invalide.", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            var file = File.ReadAllBytes(FileToEncryptTextBox.Text);
            HashFile(privateKey, file);
            EncryptFile(privateKey, FileToEncryptTextBox.Text);
        }

        private static void HashFile(RSACryptoServiceProvider privateKey, byte[] fileBytes)
        {
            SHA256 sha256 = new SHA256Managed();
            var hashedFile = sha256.ComputeHash(fileBytes);
            var rsaFormatter = new RSAPKCS1SignatureFormatter(privateKey);
            rsaFormatter.SetHashAlgorithm("SHA256");
            var signedHashedValue = rsaFormatter.CreateSignature(hashedFile);
            Directory.CreateDirectory(@"C:\RSA\Encrypt\");
            File.WriteAllBytes(encryptFolder + "Signature.txt", signedHashedValue);
        }

        private static void EncryptFile(RSACryptoServiceProvider privateKey, string file)
        {
            // Create a symetric key with AES (Rijndael)
            var rjndl = new RijndaelManaged {KeySize = 256, BlockSize = 256, Mode = CipherMode.CBC};
            var transform = rjndl.CreateEncryptor();
            // Encrypt the key with the private key
            var symKeyEncrypted = privateKey.Encrypt(rjndl.Key, false);

            // Set variables to store the length values of the key and the Initialization Vector
            var lenKey = new byte[4];
            var lenIV = new byte[4];
            var lKey = symKeyEncrypted.Length;
            lenKey = BitConverter.GetBytes(lKey);
            var lIV = rjndl.IV.Length;
            lenIV = BitConverter.GetBytes(lIV);

            var startFileName = file.LastIndexOf("\\") + 1;
            var outFileName = encryptFolder + file.Substring(startFileName, file.LastIndexOf(".") - startFileName) + ".enc";

            using (var outFileStream = new FileStream(outFileName, FileMode.Create))
            {
                // Write the encrypted symetric key and the IV at the beginning of the new encrypted file
                // TO-DO: Write the encrypted symetric key in another separate file
                outFileStream.Write(lenKey, 0, 4);
                outFileStream.Write(lenIV, 0, 4);
                outFileStream.Write(symKeyEncrypted, 0, lKey);
                outFileStream.Write(rjndl.IV, 0, lIV);

                using (var outStreamEncrypted = new CryptoStream(outFileStream, transform, CryptoStreamMode.Write))
                {
                    var blockSizeInBytes = rjndl.BlockSize/8;
                    var data = new byte[blockSizeInBytes];

                    using (var inFileStream = new FileStream(file, FileMode.Open))
                    {
                        int count;
                        do
                        {
                            count = inFileStream.Read(data, 0, blockSizeInBytes);
                            outStreamEncrypted.Write(data, 0, count);
                        } while (count > 0);
                        inFileStream.Close();
                        outStreamEncrypted.FlushFinalBlock();
                        outStreamEncrypted.Close();
                    }
                    outFileStream.Close();
                }
            }
        }
    }
}
