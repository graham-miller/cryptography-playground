using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptographyPlayground.CryptographyWalkthrough
{
    // Ref.: https://docs.microsoft.com/en-us/dotnet/standard/security/walkthrough-creating-a-cryptographic-application

    public class Implementation
    {
        public bool CryptoServiceProviderIsPublicOnly => _rsaCryptoServiceProvider.PublicOnly;

        public void CreateAsymmetricKey()
        {
            _rsaCryptoServiceProvider = new RSACryptoServiceProvider(CspParameters) {PersistKeyInCsp = true};
        }

        public void EncryptFile(string inputFileName, string outputFileName)
        {
            var symmetricAlgorithm = GetSymmetricAlgorithm();
            
            // Use RSACryptoServiceProvider to encrypt the Rijndael key.
            var encryptedKey = _rsaCryptoServiceProvider.Encrypt(symmetricAlgorithm.Key, false);


            using (var outputFileStream = new FileStream(outputFileName, FileMode.Create))
            {
                // Write the following to the output file
                // - Key length (4 bytes)
                // - IV length (4 bytes)
                // - Encrypted key
                // - IV
                outputFileStream.Write(BitConverter.GetBytes(encryptedKey.Length), 0, 4);
                outputFileStream.Write(BitConverter.GetBytes(symmetricAlgorithm.IV.Length), 0, 4);
                outputFileStream.Write(encryptedKey, 0, encryptedKey.Length);
                outputFileStream.Write(symmetricAlgorithm.IV, 0, symmetricAlgorithm.IV.Length);

                // Write cipher text using a CryptoStream
                using (var cryptoStream = new CryptoStream(outputFileStream, symmetricAlgorithm.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    // By encrypting a chunk at a time, you can save memory and accommodate large files, blockSizeBytes can be any arbitrary size.
                    var blockSizeBytes = symmetricAlgorithm.BlockSize / 8;
                    var data = new byte[blockSizeBytes];

                    using (var inputFileStream = new FileStream(inputFileName, FileMode.Open))
                    {
                        int bytesRead;
                        while ((bytesRead = inputFileStream.Read(data, 0, blockSizeBytes)) > 0)
                        {
                            cryptoStream.Write(data, 0, bytesRead);
                        }
                    }
                }
            }
        }

        public void DecryptFile(string inputFileName, string outputFileName)
        {
            using (var inputFileStream = new FileStream(inputFileName, FileMode.Open))
            {
                // Read from the input file
                // - Key length (4 bytes)
                // - IV length (4 bytes)
                // - Encrypted key
                // - IV
                var keyLength = BitConverter.ToInt32(inputFileStream.ReadBytes(4));
                var ivLength = BitConverter.ToInt32(inputFileStream.ReadBytes(4));
                var decryptedKey = _rsaCryptoServiceProvider.Decrypt(inputFileStream.ReadBytes(keyLength), false);
                var iv = inputFileStream.ReadBytes(ivLength);

                var symmetricAlgorithm = GetSymmetricAlgorithm();

                using (var outputFileStream = new FileStream(outputFileName, FileMode.Create))
                using (var cryptoStream = new CryptoStream(outputFileStream, symmetricAlgorithm.CreateDecryptor(decryptedKey, iv), CryptoStreamMode.Write))
                {
                    // By encrypting a chunk at a time, you can save memory and accommodate large files, blockSizeBytes can be any arbitrary size.
                    var blockSizeBytes = symmetricAlgorithm.BlockSize / 8;
                    var data = new byte[blockSizeBytes];

                    int bytesRead;
                    while ((bytesRead = inputFileStream.Read(data, 0, blockSizeBytes)) > 0)
                    {
                        cryptoStream.Write(data, 0, bytesRead);
                    }
                }
            }
        }

        public void ExportPublicKey(string fileName)
        {
            File.WriteAllText(fileName, _rsaCryptoServiceProvider.ToXmlString(false));
        }

        public void ImportPublicKey(string fileName)
        {
            _rsaCryptoServiceProvider = new RSACryptoServiceProvider(CspParameters) {PersistKeyInCsp = true};
            _rsaCryptoServiceProvider.FromXmlString(File.ReadAllText(fileName));
        }

        public void GetPrivateKey()
        {
            _rsaCryptoServiceProvider = new RSACryptoServiceProvider(CspParameters) {PersistKeyInCsp = true};
        }

        private static SymmetricAlgorithm GetSymmetricAlgorithm()
        {
            return new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128, //256;
                Mode = CipherMode.CBC
            };
        }

        private const string KeyPairContainerName = "Key01";

        private static readonly CspParameters CspParameters = new CspParameters { KeyContainerName = KeyPairContainerName };

        private RSACryptoServiceProvider _rsaCryptoServiceProvider;
    }
}