using System;
using System.IO;
using NUnit.Framework;

namespace CryptographyPlayground.CryptographyWalkthrough.Runners
{
    // Ref.: https://docs.microsoft.com/en-us/dotnet/standard/security/walkthrough-creating-a-cryptographic-application

    public class TestHarness
    {
        private const string PlainText = "The greatest glory in living lies not in never falling, but in rising every time we fall.";

        private static readonly string OutputDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "CertificatePlayground2");
        private static readonly string PublicKeyFile = Path.Combine(OutputDirectory, "RSA PublicKey.txt");
        private static readonly string OriginalFile = Path.Combine(OutputDirectory, "original.txt");
        private static readonly string EncryptedFile = Path.Combine(OutputDirectory, "encrypted.enc");
        private static readonly string DecryptedFile = Path.Combine(OutputDirectory, "decrypted.txt");

        private Implementation _sut;

        [SetUp]
        public void SetUp()
        {
            DeleteOutputDirectory();
            Directory.CreateDirectory(OutputDirectory);
            File.WriteAllText(OriginalFile, PlainText);

            _sut = new Implementation();
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
            _sut.CreateAsymmetricKey();
            Assert.That(_sut.CryptoServiceProviderIsPublicOnly, Is.False);

            _sut.ExportPublicKey(PublicKeyFile);

            // Encrypt
            _sut.EncryptFile(OriginalFile, EncryptedFile);

            // Decrypt
            _sut.DecryptFile(EncryptedFile, DecryptedFile);

            Assert.That(File.ReadAllText(DecryptedFile), Is.EqualTo(PlainText));
        }

        [Test]
        public void EncryptUsingPublicKey_DecryptUsingPrivateKey()
        {
            // Create Keys, export, only import public
            _sut.CreateAsymmetricKey();
            _sut.ExportPublicKey(PublicKeyFile);
            _sut.ImportPublicKey(PublicKeyFile);

            Assert.That(_sut.CryptoServiceProviderIsPublicOnly, Is.True);

            // Encrypt
            _sut.EncryptFile(OriginalFile, EncryptedFile);

            // Decrypt should fail (no private key)
            try
            {
                _sut.DecryptFile(EncryptedFile, DecryptedFile);
                Assert.Fail();
            }
            catch (Exception exception)
            {
                Assert.That(exception.Message, Is.EqualTo("Key does not exist."));
            }

            // Get private key, decryption now works
            _sut.GetPrivateKey();
            Assert.That(_sut.CryptoServiceProviderIsPublicOnly, Is.False);

            _sut.DecryptFile(EncryptedFile, DecryptedFile);
            Assert.That(File.ReadAllText(DecryptedFile), Is.EqualTo(PlainText));
        }

        private static void DeleteOutputDirectory()
        {
            if (Directory.Exists(OutputDirectory)) Directory.Delete(OutputDirectory, recursive: true);
        }
    }
}