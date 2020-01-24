using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CryptographyPlayground.Shared;
using NUnit.Framework;

namespace CryptographyPlayground.CertificateProvider._Runners
{
    [TestFixture]
    public class CreateCertificatesTests
    {
        [Test]
        public void SignAndVerifyData()
        {
            // create the certificates
            var pfx = CertificateGenerator.GenerateSelfSignedCertificate("Graham Miller");
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
            var caCertificate = CertificateGenerator.GenerateCertificateAuthorityCertificate("Certificate Authority - Graham Miller");
            var leafCertificate = CertificateGenerator.GenerateSignedCertificate("Graham Miller", caCertificate);
            Assert.That(caCertificate.Verify(), Is.False);
            Assert.That(leafCertificate.Verify(), Is.False);

            AddCertificateToStore(caCertificate);
            Assert.That(caCertificate.Verify(), Is.True);
            Assert.That(leafCertificate.Verify(), Is.False);

            RemoveCertificateFromStore(caCertificate);
            Assert.That(caCertificate.Verify(), Is.False);
            Assert.That(leafCertificate.Verify(), Is.False);
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

        private const string Password = "password";
    }
}
