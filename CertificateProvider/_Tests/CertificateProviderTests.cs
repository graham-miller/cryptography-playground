using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NUnit.Framework;
using Constants = CryptographyPlayground.Shared.Constants;

namespace CryptographyPlayground.CertificateProvider._Tests
{
    [TestFixture]
    public class CertificateProviderTests
    {
        // Ref.: https://stackoverflow.com/a/50138133/1826
        // Ref.: http://paulstovell.com/blog/x509certificate2 (Eight tips for working with X.509 certificates in .NET)
        // Ref.: https://github.com/dotnet/corefx/blob/master/Documentation/architecture/cross-platform-cryptography.md#x509store (Cross-Platform Cryptography, also https://stackoverflow.com/a/57937687/1826)
        [Test]
        public void SignAndVerifyData()
        {
            // create the certificates
            var pfx = CertificateProvider.GenerateSelfSignedCertificate("Graham Miller");
            Assert.That(pfx.HasPrivateKey, Is.True);

            var cer = new X509Certificate2(pfx.Export(X509ContentType.Cert));
            Assert.That(cer.HasPrivateKey, Is.False);

            // sign data
            var signer = (RSA)pfx.PrivateKey;
            var signature = signer.SignData(Constants.PlainBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // verify data
            var verifier = (RSA)cer.PublicKey.Key;
            var isVerified = verifier.VerifyData(Constants.PlainBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.That(isVerified, Is.True);

            // don't verify tampered with data
            isVerified = verifier.VerifyData(Constants.DifferentPlainBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.That(isVerified, Is.False);
        }

        [Test]
        public void VerifyCertificate()
        {
            // create certificates
            var caCertificate = CertificateProvider.GenerateCertificateAuthorityCertificate("Certificate Authority - Graham Miller");
            var leafCertificate = CertificateProvider.GenerateSignedCertificate("Graham Miller", caCertificate);
            Assert.That(caCertificate.Verify(), Is.False);
            Assert.That(leafCertificate.Verify(), Is.False);
            Assert.That(Verify(leafCertificate), Is.False);

            AddCertificateToStore(caCertificate);
            Assert.That(caCertificate.Verify(), Is.True);
            Assert.That(leafCertificate.Verify(), Is.False);
            Assert.That(Verify(leafCertificate), Is.True);

            RemoveCertificateFromStore(caCertificate);
            Assert.That(caCertificate.Verify(), Is.False);
            Assert.That(leafCertificate.Verify(), Is.False);
            Assert.That(Verify(leafCertificate), Is.False);
        }

        [Test]
        public void Ocsp()
        {
            var caCertificate = CertificateProvider.GenerateCertificateAuthorityCertificate("Certificate Authority - Graham Miller");
            var leafCertificate = CertificateProvider.GenerateSignedCertificateWithOcsp("Graham Miller", caCertificate);

            Verify(leafCertificate);

        }

        [Test]
        public void OcspFromSelfSignedCertificate()
        {
            var caCertificate = CertificateProvider.GenerateCertificateAuthorityCertificate("Certificate Authority - Graham Miller");
            var leafCertificate = CertificateProvider.GenerateSignedCertificateWithOcsp("Graham Miller", caCertificate);
            WriteCertificateExtensions(leafCertificate);
        }

        [Test]
        public void OcspFromStackOverflowCertificate()
        {
            var certificate = new X509Certificate2(@"C:\Users\Graham Miller\desktop\StackOverflow.cer");
            WriteCertificateExtensions(certificate);
        }

        private static void WriteCertificateExtensions(X509Certificate2 certificate)
        {
            foreach (var extension in certificate.Extensions)
            {
                // Create an AsnEncodedData object using the extensions information.
                var asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                Console.WriteLine($"Extension type: {extension.Oid.FriendlyName}");
                Console.WriteLine($"Oid value: {asndata.Oid.Value}");
                Console.WriteLine($"Raw data length: {asndata.RawData.Length}");
                Console.WriteLine(Environment.NewLine);
                Console.WriteLine(asndata.Format(true));
                Console.WriteLine(Environment.NewLine);
            }
        }

        private static bool Verify(X509Certificate2 certificate)
        {
            Console.WriteLine($"Certificate serial number: {certificate.SerialNumber}");

            using (var chain = new X509Chain
            {
                ChainPolicy = new X509ChainPolicy
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    //VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid,
                    //UrlRetrievalTimeout = new TimeSpan(0, 1, 0)
                }
            })
            {
                var valid = false;

                try
                {
                    valid = chain.Build(certificate);
                    Console.WriteLine($"Chain building status: {valid}");

                    if (!valid)
                        foreach (var chainStatus in chain.ChainStatus)
                            Console.WriteLine($"Chain error: {chainStatus.Status} {chainStatus.StatusInformation}");
                }
                catch (Exception exception)
                {
                    Console.WriteLine(exception.ToString());
                }

                return valid;
            }
        }

        private static void AddCertificateToStore(X509Certificate2 certificate)
        {
            var store = GetCertificateStore(OpenFlags.ReadWrite);
            store.Add(certificate);
            store.Close();
        }

        private static void RemoveCertificateFromStore(X509Certificate2 certificate)
        {
            var store = GetCertificateStore(OpenFlags.ReadWrite);

            foreach (var item in store.Certificates.Find(X509FindType.FindBySubjectName, certificate.FriendlyName, false))
                store.Remove(item);

            store.Close();
        }

        private static X509Store GetCertificateStore(OpenFlags openFlags)
        {
            var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(openFlags);

            return store;
        }

        private static void WriteCertificateExtensions2(X509Certificate2 certificate)
        {
            foreach (var extension in certificate.Extensions)
            {
                Console.WriteLine(extension.Oid.FriendlyName + "(" + extension.Oid.Value + ")");

                if (extension.Oid.FriendlyName == "Key Usage")
                {
                    var ext = (X509KeyUsageExtension) extension;
                    Console.WriteLine(ext.KeyUsages);
                }
                else if (extension.Oid.FriendlyName == "Basic Constraints")
                {
                    var ext = (X509BasicConstraintsExtension) extension;
                    Console.WriteLine(ext.CertificateAuthority);
                    Console.WriteLine(ext.HasPathLengthConstraint);
                    Console.WriteLine(ext.PathLengthConstraint);
                }
                else if (extension.Oid.FriendlyName == "Subject Key Identifier")
                {
                    var ext = (X509SubjectKeyIdentifierExtension) extension;
                    Console.WriteLine(ext.SubjectKeyIdentifier);
                }
                else if (extension.Oid.FriendlyName == "Enhanced Key Usage")
                {
                    var ext = (X509EnhancedKeyUsageExtension) extension;
                    var oids = ext.EnhancedKeyUsages;
                    foreach (var oid in oids)
                    {
                        Console.WriteLine(oid.FriendlyName + "(" + oid.Value + ")");
                    }
                }
                else
                {
                    var asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                    Console.WriteLine($"Extension type: {extension.Oid.FriendlyName}");
                    Console.WriteLine($"Oid value: {asndata.Oid.Value}");
                    Console.WriteLine($"Raw data length: {asndata.RawData.Length}");
                    Console.WriteLine(Environment.NewLine);
                    Console.WriteLine(asndata.Format(true));
                    Console.WriteLine(Environment.NewLine);
                }
            }
        }
    }
}
