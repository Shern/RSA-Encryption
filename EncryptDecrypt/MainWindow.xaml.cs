using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;

namespace EncryptDecrypt
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private const string EncryptFolder = @"C:\CSI4539\Encrypt\";
        private const string DecryptFolder = @"C:\CSI4539\Decrypt\";

        public MainWindow()
        {
            InitializeComponent();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        #region Generate Key Tab

        /// <summary>
        /// Generate a RSA key of size 2048 and display the public key and the private key in the corresponding text boxes
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void GenerateButton_Click(object sender, RoutedEventArgs e)
        {
            var rsaKey = new RSACryptoServiceProvider(2048) {PersistKeyInCsp = false};
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

        #endregion

        #region Encrypt Tab

        private void OpenFileEncryptButton_Click(object sender, RoutedEventArgs e)
        {
            FileToEncryptTextBox.Text = GetFileName();
        }

        /// <summary>
        /// Start the encryption process. Verify if keys are valid. Files are created in C:\CSI4539\Encrypt\file-name\ .
        /// The files produced are the encrypted file (with a .enc extension), key.txt and signature.txt.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            ResultEncryptTextBox.Text = "";
            var filePath = FileToEncryptTextBox.Text;
            if (filePath.Equals(""))
            {
                ShowErrorDialog("Pas de fichier sélectionné.", ResultEncryptTextBox);
                return;
            }
            var privateKey = new RSACryptoServiceProvider();
            try
            {
                privateKey.FromXmlString(PrivateKeyEncryptTextBox.Text);
            }
            catch (System.Security.XmlSyntaxException)
            {
                ShowErrorDialog("Clé privée invalide.", ResultEncryptTextBox);
                return;
            }
            var publicKey = new RSACryptoServiceProvider();
            try
            {
                publicKey.FromXmlString(PublicKeyEncryptTextBox.Text);
            }
            catch (System.Security.XmlSyntaxException)
            {
                ShowErrorDialog("Clé public invalide.", ResultEncryptTextBox);
                return;
            }
            
            var startFileName = filePath.LastIndexOf("\\") + 1;
            var folderName = EncryptFolder +
                             filePath.Substring(startFileName, filePath.LastIndexOf(".") - startFileName) + @"\";
            Directory.CreateDirectory(folderName);
            HashFile(privateKey, filePath, folderName);
            EncryptFile(publicKey, FileToEncryptTextBox.Text, folderName);
        }

        /// <summary>
        /// Hash the file and generated a signature file by encrypting the hash with the private key.
        /// </summary>
        /// <param name="privateKey">The private key of the sender.</param>
        /// <param name="file">The path to the file to hash.</param>
        /// <param name="folderName">The folder in which the signature file is saved.</param>
        private static void HashFile(AsymmetricAlgorithm privateKey, string file, string folderName)
        {
            var fileBytes = File.ReadAllBytes(file);
            SHA256 sha256 = new SHA256Managed();
            var hashedFile = sha256.ComputeHash(fileBytes);
            var rsaFormatter = new RSAPKCS1SignatureFormatter(privateKey);
            rsaFormatter.SetHashAlgorithm("SHA256");
            var signedHashedValue = rsaFormatter.CreateSignature(hashedFile);
            File.WriteAllBytes(folderName + "Signature.txt", signedHashedValue);
        }

        /// <summary>
        /// Generates a random symmetric Rijndael key and encrypt it with the public key of the receiver. 
        /// Saves this encrypted key with the IV in key.txt. After that, encrypts the file with the symmetric key
        /// by using the Rijndael algorithm with a block and key sizes of 256 bits and using the Cipher-Block Chaining 
        /// cipher mode.
        /// </summary>
        /// <param name="publicKey">The public key of the receiver.</param>
        /// <param name="file">The path to the file to encrypt.</param>
        /// <param name="folderName">The folder in which the key file and the encrypted file are saved.</param>
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

            // Encrypt the file in a new file by using the symmetric key
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

        #endregion

        #region Decrypt Tab

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

        /// <summary>
        /// Start the decryptioin process. Verifies the files and the keys inputed but not completely. 
        /// Decrypts the key, then decrypts the file, and verify the signature after that.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            ResultDecryptTextBox.Text = "";
            var filePath = FileToDecryptTextBox.Text;
            if (filePath.Equals(""))
            {
                ShowErrorDialog("Pas de fichier sélectionné.", ResultDecryptTextBox);
                return;
            }
            var keyFilePath = KeyFileTextBox.Text;
            if (keyFilePath.Equals(""))
            {
                ShowErrorDialog("Pas de fichier de clé sélectionné.", ResultDecryptTextBox);
                return;
            }
            var signatureFilePath = SignatureFileTextBox.Text;
            if (signatureFilePath.Equals(""))
            {
                ShowErrorDialog("Pas de fichier de signature sélectionné.", ResultDecryptTextBox);
                return;
            }
            var privateKey = new RSACryptoServiceProvider();
            try
            {
                privateKey.FromXmlString(PrivateKeyDecryptTextBox.Text);
            }
            catch (System.Security.XmlSyntaxException)
            {
                ShowErrorDialog("Clé privée invalide.", ResultDecryptTextBox);
                return;
            }
            var publicKey = new RSACryptoServiceProvider();
            try
            {
                publicKey.FromXmlString(PublicKeyDecryptTextBox.Text);
            }
            catch (System.Security.XmlSyntaxException)
            {
                ShowErrorDialog("Clé publique invalide.", ResultDecryptTextBox);
                return;
            }

            var startFileName = filePath.LastIndexOf("\\") + 1;
            var folderName = DecryptFolder + filePath.Substring(startFileName, filePath.LastIndexOf(".") - startFileName) + @"\";
            Directory.CreateDirectory(folderName);

            // Get the decrypted key
            bool isSignatureValid;
            try
            {
                var key = DecryptKey(privateKey, keyFilePath);

                // Get the path of the decrypted file
                try
                {
                    var decryptedFilePath = DecryptFile(key, filePath, folderName);

                    // Verify if the hash of the decrypted file is the same as the decrypted signature
                    try
                    {
                        isSignatureValid = VerifySignature(publicKey, decryptedFilePath, signatureFilePath);
                    }
                    catch (Exception ex)
                    {
                        ShowErrorDialog("Le fichier de signature est invalide.", ResultDecryptTextBox);
                        return;
                    }
                }
                catch (Exception ex)
                {
                    ShowErrorDialog("Erreur lors du déchiffrement du fichier.", ResultDecryptTextBox);
                    return;
                }
            }
            catch (Exception ex)
            {
                ShowErrorDialog("Le fichier de clé est invalide.", ResultDecryptTextBox);
                return;
            }

            if (isSignatureValid)
            {
                ResultDecryptTextBox.Text = "Succès";
                Process.Start(folderName);
            }
            else
            {
                ShowErrorDialog("La signature est invalide (le fichier a peut-être été modifié).", ResultDecryptTextBox);
            }
        }

        /// <summary>
        /// Decrypt the key contained in the key.txt file. 
        /// </summary>
        /// <param name="privateKey">The private key of the receiver.</param>
        /// <param name="keyFile">The path to the key.txt file.</param>
        /// <returns>An ICryptoTransform object initiated with the key and the IV contained in key.txt.</returns>
        private static ICryptoTransform DecryptKey(RSACryptoServiceProvider privateKey, string keyFile)
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

                keyInFs.Seek(8, SeekOrigin.Begin);
                keyInFs.Read(encryptedKey, 0, lKey);
                keyInFs.Seek(8 + lKey, SeekOrigin.Begin);
                keyInFs.Read(iv, 0, lIV);

                var decryptedKey = privateKey.Decrypt(encryptedKey, false);
                transform = rjndl.CreateDecryptor(decryptedKey, iv);
            }
            return transform;
        }

        /// <summary>
        /// Decrypts the file and save the decrypted file in ..\file-name\file-name.txt
        /// </summary>
        /// <param name="key">The symmetric key and the IV in a ICryptoTransform object.</param>
        /// <param name="file">The path the to encrypted file.</param>
        /// <param name="folderName">The folder in which the decrypted file is to be saved.</param>
        /// <returns>The path to the decrypted file.</returns>
        private static string DecryptFile(ICryptoTransform key, string file, string folderName)
        {
            var startFileName = file.LastIndexOf("\\") + 1;
            var outFileName = folderName + file.Substring(startFileName, file.LastIndexOf(".") - startFileName) + ".txt";

            using (var inFs = new FileStream(file, FileMode.Open))
            {
                using (var outFs = new FileStream(outFileName, FileMode.Create))
                {
                    var blockSizeBytes = key.InputBlockSize / 8;
                    var data = new byte[blockSizeBytes];

                    inFs.Seek(0, SeekOrigin.Begin);

                    using (var outStreamDecrypted = new CryptoStream(outFs, key, CryptoStreamMode.Write))
                    {
                        int count;
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            outStreamDecrypted.Write(data, 0, count);

                        }
                        while (count > 0);

                        outStreamDecrypted.FlushFinalBlock();
                        outStreamDecrypted.Close();
                    }
                    outFs.Close();
                }
                inFs.Close();
            }
            return outFileName;
        }

        /// <summary>
        /// Verifies the signature by hashing the decrypted file and comparing the hash with the decrypted signature sent by the sender.
        /// </summary>
        /// <param name="publicKey">The public key of the sender.</param>
        /// <param name="file">The path to the decrypted file.</param>
        /// <param name="signatureFile">The path to the signature sent by the sender.</param>
        /// <returns>Indicates if the signature is the same.</returns>
        private static bool VerifySignature(AsymmetricAlgorithm publicKey, string file, string signatureFile)
        {
            var fileBytes = File.ReadAllBytes(file);
            SHA256 sha256 = new SHA256Managed();
            var hashedFile = sha256.ComputeHash(fileBytes);
            var signatureBytes = File.ReadAllBytes(signatureFile);
            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(publicKey);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            return rsaDeformatter.VerifySignature(hashedFile, signatureBytes);
        }

        #endregion

        /// <summary>
        /// Open a OpenFileDialog.
        /// </summary>
        /// <returns>The path to the selected file.</returns>
        private static string GetFileName()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog();
            var result = dlg.ShowDialog();
            return result == true ? dlg.FileName : "";
        }

        private static void ShowErrorDialog(string errorMessage, TextBlock resultTextBlock)
        {
            MessageBox.Show(errorMessage, "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
            resultTextBlock.Text = "Échec";
        }
    }
}
