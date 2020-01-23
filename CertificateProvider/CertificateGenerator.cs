﻿using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptographyPlayground.CertificateProvider
{
    public class CertificateGenerator
    {
        // Ref.: https://stackoverflow.com/a/50138133/1826
        private X509Certificate2 GenerateSelfSignedCertificate(string commonName) // subject is the entity validated or verified by the certificate
        {
            var distinguishedName = new X500DistinguishedName($"CN={commonName}");
            // Could contain:
            // CN= common name, the end­entity being covered, example, a website or www.example.com
            // C= country
            // ST= state or province within country
            // L= location, nominally an address but ambiguously used except in EV certificates where it is rigorously defined
            // OU= organizational unit name, a company division name or similar sub­structure
            // O= organization name,

            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DataEncipherment | 
                    X509KeyUsageFlags.KeyEncipherment | 
                    X509KeyUsageFlags.DigitalSignature, false));


                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                        new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

                // I think only required if using for SSL?
                //request.CertificateExtensions.Add(LocalSubjectAlternativeName());

                var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));

                certificate.FriendlyName = commonName;

                return certificate;

                // Why do this?
                //return new X509Certificate2(certificate.Export(X509ContentType.Pfx, "WeNeedASaf3rPassword"), "WeNeedASaf3rPassword", X509KeyStorageFlags.MachineKeySet);
            }
        }

        private X509Extension LocalSubjectAlternativeName()
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
