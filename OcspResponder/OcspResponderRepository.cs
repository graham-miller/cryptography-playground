using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using OcspResponder.Core;

namespace OcspResponder
{
    public class OcspResponderRepository : IOcspResponderRepository
    {
        public Task<bool> SerialExists(string serial, X509Certificate2 issuerCertificate)
        {
            throw new NotImplementedException();
        }

        public Task<CertificateRevocationStatus> SerialIsRevoked(string serial, X509Certificate2 issuerCertificate)
        {
            throw new NotImplementedException();
        }

        public Task<CaCompromisedStatus> IsCaCompromised(X509Certificate2 caCertificate)
        {
            throw new NotImplementedException();
        }

        public Task<AsymmetricAlgorithm> GetResponderPrivateKey(X509Certificate2 caCertificate)
        {
            throw new NotImplementedException();
        }

        public Task<X509Certificate2[]> GetChain(X509Certificate2 issuerCertificate)
        {
            throw new NotImplementedException();
        }

        public Task<DateTimeOffset> GetNextUpdate()
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<X509Certificate2>> GetIssuerCertificates()
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
