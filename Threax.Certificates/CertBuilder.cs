using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Threax.Certificates
{
    public class CertBuilder
    {
        public static X509Certificate2 CreateSelfSignedHttpsCert(String cn, int expirationYears = 25)
        {
            using (var rsa = RSA.Create()) // generate asymmetric key pair
            {
                var request = new CertificateRequest($"cn={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                //Thanks to Muscicapa Striata for these settings at
                //https://stackoverflow.com/questions/42786986/how-to-create-a-valid-self-signed-x509certificate2-programmatically-not-loadin
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

                //Create the cert
                using (var cert = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-2)), new DateTimeOffset(DateTime.UtcNow.AddYears(expirationYears))))
                {
                    //It seems like the cert we create above won't actually work. It must be using stuff from the RSA created
                    //above, exporting the cert and reloading it fixes the issue.
                    return new X509Certificate2(cert.Export(X509ContentType.Pfx));
                }
            }
        }
    }
}
