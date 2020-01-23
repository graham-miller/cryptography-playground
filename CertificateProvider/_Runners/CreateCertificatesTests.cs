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
            // create the certificates
            var pfx = CertificateGenerator.GenerateSelfSignedCertificate("Graham Miller");
            Assert.That(pfx.HasPrivateKey, Is.True);

            var cer = new X509Certificate2(pfx.Export(X509ContentType.Cert));
            Assert.That(cer.HasPrivateKey, Is.False);

            var result = cer.Verify();

            Assert.That(result, Is.True);

        }

        private const string Password = "password";
    }
}
