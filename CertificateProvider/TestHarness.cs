using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;

namespace CryptographyPlayground.CertificateProvider
{
    public class TestHarness
    {
        // Ref.: https://stackoverflow.com/a/50138133/1826
        // Ref.: http://paulstovell.com/blog/x509certificate2 (Eight tips for working with X.509 certificates in .NET)
        // Ref.: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2?view=netframework-4.8 (Encrypt/Decrypt file)

        private const string CertificateName = "CertificateName";
        private const string Password = "Password";
        private const string PlainText = "The greatest glory in living lies not in never falling, but in rising every time we fall";

        private string _directory;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            _directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "CertificatePlayground1");

            if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);

            Directory.CreateDirectory(_directory);
        }

        [Test]
        public void CreateAndExportCertificate()
        {
            var cert = CreateCertificate();

            File.WriteAllBytes(Path.Combine(_directory, "Hello.cer"), cert.Export(X509ContentType.Cert));
            File.WriteAllBytes(Path.Combine(_directory, "Hello.pfx"), cert.Export(X509ContentType.Pkcs12, (string)null));
        }

        [Test]
        public void EncryptAndDecryptFile()
        {
            var original = Path.Combine(_directory, "original.txt");
            var encrypted = Path.Combine(_directory, "encrypted.txt");
            var decrypted = Path.Combine(_directory, "decrypted.txt");

            File.WriteAllText(original, PlainText);

            var cert = CreateCertificate();
            EncrypterDecrypter.EncryptFile(original, encrypted, cert.PublicKey.Key);

            EncrypterDecrypter.DecryptFile(encrypted, decrypted, (RSACryptoServiceProvider)cert.PrivateKey);
        }


        private X509Certificate2 CreateCertificate()
        {

            var distinguishedName = new X500DistinguishedName($"CN={CertificateName}");

            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
                request.CertificateExtensions.Add(CreateSubjectAlternativeName());

                var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));

                certificate.FriendlyName = CertificateName;

                return new X509Certificate2(certificate.Export(X509ContentType.Pfx, Password), Password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            }
        }

        private X509Extension CreateSubjectAlternativeName()
        {
            var builder = new SubjectAlternativeNameBuilder();
            builder.AddIpAddress(IPAddress.Loopback);
            builder.AddIpAddress(IPAddress.IPv6Loopback);
            builder.AddDnsName("localhost");
            builder.AddDnsName(Environment.MachineName);

            return builder.Build();
        }
    }
}