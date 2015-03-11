using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
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
        private const string EncryptFolder = @"C:\RSA\Encrypt\";
        private const string DecryptFolder = @"C:\RSA\Decrypt\";

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
            FileToEncryptTextBox.Text = GetFileName();
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            ResultEncryptTextBox.Text = "";
            var filePath = FileToEncryptTextBox.Text;
            if (filePath.Equals(""))
            {
                MessageBox.Show("Pas de fichier sélectionné", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                ResultEncryptTextBox.Text = "Échec";
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
                ResultEncryptTextBox.Text = "Échec";
                return;
            }
            var publicKey = new RSACryptoServiceProvider();
            try
            {
                publicKey.FromXmlString(PublicKeyEncryptTextBox.Text);
            }
            catch (System.Security.XmlSyntaxException)
            {
                MessageBox.Show("Clé publique invalide.", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                ResultEncryptTextBox.Text = "Échec";
                return;
            }
            
            var startFileName = filePath.LastIndexOf("\\") + 1;
            var folderName = EncryptFolder +
                             filePath.Substring(startFileName, filePath.LastIndexOf(".") - startFileName) + @"\";
            Directory.CreateDirectory(folderName);
            HashFile(privateKey, filePath, folderName);
            EncryptFile(publicKey, FileToEncryptTextBox.Text, folderName);
        }

        private static void HashFile(RSACryptoServiceProvider privateKey, string file, string folderName)
        {
            var fileBytes = File.ReadAllBytes(file);
            SHA256 sha256 = new SHA256Managed();
            var hashedFile = sha256.ComputeHash(fileBytes);
            var rsaFormatter = new RSAPKCS1SignatureFormatter(privateKey);
            rsaFormatter.SetHashAlgorithm("SHA256");
            var signedHashedValue = rsaFormatter.CreateSignature(hashedFile);
            File.WriteAllBytes(folderName + "Signature.txt", signedHashedValue);
        }

        private void EncryptFile(RSACryptoServiceProvider publicKey, string file, string folderName)
        {
            // Create a symetric key with AES (Rijndael)
            var rjndl = new RijndaelManaged {KeySize = 256, BlockSize = 256, Mode = CipherMode.CBC};
            var transform = rjndl.CreateEncryptor();
            // Encrypt the key with the private key
            var symKeyEncrypted = publicKey.Encrypt(rjndl.Key, false);

            // Set variables to store the length values of the key and the Initialization Vector
            var lenKey = new byte[4];
            var lenIV = new byte[4];
            var lKey = symKeyEncrypted.Length;
            lenKey = BitConverter.GetBytes(lKey);
            var lIV = rjndl.IV.Length;
            lenIV = BitConverter.GetBytes(lIV);

            var startFileName = file.LastIndexOf("\\") + 1;
            var outFileName = folderName + file.Substring(startFileName, file.LastIndexOf(".") - startFileName) + ".enc";

            // Write the encrypted symetric key and the IV in a separate file
            using (var keyFileStream = new FileStream(folderName + "Key.txt", FileMode.Create))
            {
                keyFileStream.Write(lenKey, 0, 4);
                keyFileStream.Write(lenIV, 0, 4);
                keyFileStream.Write(symKeyEncrypted, 0, lKey);
                keyFileStream.Write(rjndl.IV, 0, lIV);
                keyFileStream.Close();
            }

            // Encrypt the file in a new file by using the symetric key
            using (var outFileStream = new FileStream(outFileName, FileMode.Create))
            {
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
            ResultEncryptTextBox.Text = "Succès";
            Process.Start(folderName);
        }

        private void OpenFileDecryptButton_Click(object sender, RoutedEventArgs e)
        {
            FileToDecryptTextBox.Text = GetFileName();
        }

        private void OpenKeyFileButton_Click(object sender, RoutedEventArgs e)
        {
            KeyFileTextBox.Text = GetFileName();
        }

        private void OpenSignatureFileButton_Click(object sender, RoutedEventArgs e)
        {
            SignatureFileTextBox.Text = GetFileName();
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            ResultDecryptTextBox.Text = "";
            var filePath = FileToDecryptTextBox.Text;
            if (filePath.Equals(""))
            {
                MessageBox.Show("Pas de fichier sélectionné", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                ResultDecryptTextBox.Text = "Échec";
                return;
            }
            var keyFilePath = KeyFileTextBox.Text;
            if (keyFilePath.Equals(""))
            {
                MessageBox.Show("Pas de fichier de clé sélectionné", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                ResultDecryptTextBox.Text = "Échec";
                return;
            }
            var signatureFilePath = SignatureFileTextBox.Text;
            if (signatureFilePath.Equals(""))
            {
                MessageBox.Show("Pas de fichier de signature sélectionné", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                ResultDecryptTextBox.Text = "Échec";
                return;
            }
            var privateKey = new RSACryptoServiceProvider();
            try
            {
                privateKey.FromXmlString(PrivateKeyDecryptTextBox.Text);
            }
            catch (System.Security.XmlSyntaxException)
            {
                MessageBox.Show("Clé privée invalide.", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                ResultDecryptTextBox.Text = "Échec";
                return;
            }
            var publicKey = new RSACryptoServiceProvider();
            try
            {
                publicKey.FromXmlString(PublicKeyDecryptTextBox.Text);
            }
            catch (System.Security.XmlSyntaxException)
            {
                MessageBox.Show("Clé publique invalide.", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                ResultDecryptTextBox.Text = "Échec";
                return;
            }

            var startFileName = filePath.LastIndexOf("\\") + 1;
            var folderName = EncryptFolder +
                             filePath.Substring(startFileName, filePath.LastIndexOf(".") - startFileName) + @"\";
            Directory.CreateDirectory(folderName);

        }

        private ICryptoTransform DecryptKey(RSACryptoServiceProvider privateKey, string keyFile, string folderName)
        {
            var rjndl = new RijndaelManaged { KeySize = 256, BlockSize = 256, Mode = CipherMode.CBC };
            var lenKey = new byte[4];
            var lenIV = new byte[4];
            ICryptoTransform transform;
            using (var keyInFs = new FileStream(keyFile, FileMode.Open))
            {
                keyInFs.Seek(0, SeekOrigin.Begin);
                keyInFs.Read(lenKey, 0, 3);
                keyInFs.Seek(4, SeekOrigin.Begin);
                keyInFs.Read(lenIV, 0, 3);

                var lKey = BitConverter.ToInt32(lenKey, 0);
                var lIV = BitConverter.ToInt32(lenIV, 0);

                var encryptedKey = new byte[lKey];
                var iv = new byte[lIV];

                var decryptedKey = privateKey.Decrypt(encryptedKey, false);
                transform = rjndl.CreateDecryptor(decryptedKey, iv);
            }
            return transform;
        }

        private static string GetFileName()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog();
            var result = dlg.ShowDialog();
            return result == true ? dlg.FileName : "";
        }
    }
}
