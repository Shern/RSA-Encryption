using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptDecrypt
{
    class AsymetricKeyManager
    {
        public static void SaveKeyInContainer(string containerName)
        {
            var cp = new CspParameters {KeyContainerName = containerName};
            var rsaKeys = new RSACryptoServiceProvider(cp);
        }

        public static RSACryptoServiceProvider GetKeyFromContainer(string containerName)
        {
            var cp = new CspParameters { KeyContainerName = containerName };
            return new RSACryptoServiceProvider(cp);
        }

        public static void DeleteKeyFromContainer(string containerName)
        {
            var cp = new CspParameters { KeyContainerName = containerName };
            var rsaKeys = new RSACryptoServiceProvider(cp) {PersistKeyInCsp = false};
            rsaKeys.Clear();
        }
    }
}
