using System;
using System.IO;
using System.Security.Cryptography;
using NUnit.Framework;

namespace CryptographyPlayground.CryptographyWalkthrough
{
    // Ref.: https://docs.microsoft.com/en-us/dotnet/standard/security/walkthrough-creating-a-cryptographic-application

    public class TestHarness
    {
        private const string KeyPairContainerName = "Key01";
        private const string PlainText = "The greatest glory in living lies not in never falling, but in rising every time we fall.";

        private static readonly CspParameters CspParameters = new CspParameters {KeyContainerName = KeyPairContainerName};
        private static readonly string OutputDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "CertificatePlayground2");
        private static readonly string PublicKeyFile = Path.Combine(OutputDirectory, "RSA PublicKey.txt");
        private static readonly string OriginalFile = Path.Combine(OutputDirectory, "original.txt");
        private static readonly string EncryptedFile = Path.Combine(OutputDirectory, "encrypted.enc");
        private static readonly string DecryptedFile = Path.Combine(OutputDirectory, "decrypted.txt");

        private RSACryptoServiceProvider _rsaCryptoServiceProvider;

        [SetUp]
        public void SetUp()
        {
            DeleteOutputDirectory();
            Directory.CreateDirectory(OutputDirectory);
            File.WriteAllText(OriginalFile, PlainText);
        }

        [TearDown]
        public void TearDown()
        {
            DeleteOutputDirectory();
        }

        [Test]
        public void CreateKeys_Encrypt_Decrypt()
        {
            // Create keys
            CreateAsymmetricKey();
            Assert.That(_rsaCryptoServiceProvider.PublicOnly, Is.False);

            ExportPublicKey();

            // Encrypt
            EncryptFile(OriginalFile, EncryptedFile);

            // Decrypt
            DecryptFile(EncryptedFile, DecryptedFile);

            Assert.That(File.ReadAllText(DecryptedFile), Is.EqualTo(PlainText));
        }

        [Test]
        public void EncryptUsingPublicKey_DecryptUsingPrivateKey()
        {
            // Create Keys, export, only import public
            CreateAsymmetricKey();
            ExportPublicKey();
            ImportPublicKey();

            Assert.That(_rsaCryptoServiceProvider.PublicOnly, Is.True);

            // Encrypt
            EncryptFile(OriginalFile, EncryptedFile);

            // Decrypt should fail (no private key)
            try
            {
                DecryptFile(EncryptedFile, DecryptedFile);
                Assert.Fail();
            }
            catch (Exception exception)
            {
                Assert.That(exception.Message, Is.EqualTo("Key does not exist."));
            }

            // Get private key, decryption now works
            GetPrivateKey();
            Assert.That(_rsaCryptoServiceProvider.PublicOnly, Is.False);

            DecryptFile(EncryptedFile, DecryptedFile);
            Assert.That(File.ReadAllText(DecryptedFile), Is.EqualTo(PlainText));
        }

        private void CreateAsymmetricKey()
        {
            _rsaCryptoServiceProvider = new RSACryptoServiceProvider(CspParameters) {PersistKeyInCsp = true};
        }

        private void EncryptFile(string inputFileName, string outputFileName)
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

        private void DecryptFile(string inputFileName, string outputFileName)
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

        private static SymmetricAlgorithm GetSymmetricAlgorithm()
        {
            return new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128, //256;
                Mode = CipherMode.CBC
            };
        }

        public void ExportPublicKey()
        {
            File.WriteAllText(PublicKeyFile, _rsaCryptoServiceProvider.ToXmlString(false));
        }

        private void ImportPublicKey()
        {
            _rsaCryptoServiceProvider = new RSACryptoServiceProvider(CspParameters) {PersistKeyInCsp = true};
            _rsaCryptoServiceProvider.FromXmlString(File.ReadAllText(PublicKeyFile));
        }

        private void GetPrivateKey()
        {
            _rsaCryptoServiceProvider = new RSACryptoServiceProvider(CspParameters) {PersistKeyInCsp = true};
        }

        private static void DeleteOutputDirectory()
        {
            if (Directory.Exists(OutputDirectory)) Directory.Delete(OutputDirectory, recursive: true);
        }
    }

    internal static class StreamExtensions
    {
        public static byte[] ReadBytes(this Stream stream, int count)
        {
            var buffer = new byte[count];
            stream.Read(buffer, 0, count);
            return buffer;
        }
    }
}