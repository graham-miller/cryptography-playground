using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptographyPlayground.CertificateProvider
{
    public static class X509Certificate2Extensions
    {
        /// <summary>
        /// Export a certificate to a PEM format string
        /// </summary>
        /// <param name="certificate">The certificate to export</param>
        /// <returns>A PEM encoded string</returns>
        public static string ExportToPem(this X509Certificate2 certificate)
        {
            var builder = new StringBuilder();
            var content = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
            var lineCount = Math.Ceiling((double) content.Length / CharPerLine);

            builder.AppendLine("-----BEGIN CERTIFICATE-----");

            for (var index = 0; index < lineCount; index++)
            {
                var lineLength = (index+1) * CharPerLine > content.Length
                    ? content.Length - index * CharPerLine
                    : CharPerLine;

                builder.AppendLine(content.Substring(index * CharPerLine, lineLength));
            }

            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        // Certificates content has 64 characters per lines
        private const int CharPerLine = 64;
    }
}
