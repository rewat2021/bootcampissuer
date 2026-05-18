using IssuerAPI.Service;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using SimpleBase;

namespace IssuerAPI.Util
{
    public class Utilities
    {
        public string CheckHttps(string url)
        {

            Uri uri = new Uri(url);

            // Get the scheme from the URL
            string scheme = uri.Scheme;
            return "https";

        }

        public bool IsValidUrl(string url)
        {
            return Uri.TryCreate(url, UriKind.Absolute, out Uri result)
                   && (result.Scheme == Uri.UriSchemeHttp || result.Scheme == Uri.UriSchemeHttps);
        }

        public string GetDID(IWebHostEnvironment _env)
        {
            VCService serv = new VCService();
            PemReader pemReaderPublic = new PemReader(new StringReader(serv.GetKey(false, _env)));
            Ed25519PublicKeyParameters publicKeyEd25519 = (Ed25519PublicKeyParameters)pemReaderPublic.ReadObject();

            byte[] privateKeyBytes = publicKeyEd25519.GetEncoded();
            byte[] multicodecPrefix = new byte[] { 0xED, 0x01 };

            byte[] privateKeyWithPrefix = new byte[multicodecPrefix.Length + privateKeyBytes.Length];

            Buffer.BlockCopy(multicodecPrefix, 0, privateKeyWithPrefix, 0, multicodecPrefix.Length);
            Buffer.BlockCopy(privateKeyBytes, 0, privateKeyWithPrefix, multicodecPrefix.Length, privateKeyBytes.Length);

            //var privateKeyString = "z" + Base58.Bitcoin.Encode(publicKeyEd25519.GetEncoded());
            var privateKeyString = "z" + Base58.Bitcoin.Encode(privateKeyWithPrefix);
            var entityDID = "did:key:" + privateKeyString + "#" + privateKeyString;

            return entityDID;
        }
    }
}
