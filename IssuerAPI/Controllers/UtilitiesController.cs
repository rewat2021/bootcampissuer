using IssuerAPI.Models;
using IssuerAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.OpenSsl;
using IssuerAPI.Util;
using NLog;
using IssuerAPI.Service;

namespace IssuerAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Tags("Utilities")]
    public class UtilitiesController : ControllerBase
    {
        private readonly IWebHostEnvironment _env;
        private readonly Oid4VciOptions _options;
        private IConfiguration _config;
        private string credentialOfferId = null;
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        public UtilitiesController(IConfiguration config, IWebHostEnvironment env, IOptions<Oid4VciOptions> options)
        {
            _config = config;
            _env = env;
            _options = options.Value;
        }

        [Route("/resolveDID")]
        [HttpGet]
        public async Task<IActionResult> ResolveDID(string didKey)
        {
            VCService serv = new VCService();

            try
            {
                var result = await serv.ResolveDID(didKey);

                if (result == null)
                {
                    return StatusCode(500, new
                    {
                        success = false,
                        message = "Can not resolve did"
                    });
                }

                return Ok(new
                {
                    success = true,
                    data = result
                });
            }
            catch (Exception e)
            {
                return StatusCode(500, new
                {
                    success = false,
                    message = e.Message
                });
            }
        }

        // C-03: restored at request, now admin-only. These sign with the issuer's own private key /
        // expose the issuer DID on demand — must never be reachable anonymously. Previously these had
        // no [Authorize] at all, which is exactly what let anyone impersonate the issuer.
        [Authorize(Roles = "admin")]
        [Route("/generate-jwt-ed25519")]
        [HttpPost]
        public string GenerateJWTEd25519(string nonce, string? credentialConfigurationId = null) //, string iss)
        {
            VCService serv = new VCService();
            PemReader pemReaderPrivate = new PemReader(new StringReader(serv.GetKey(true, _env)));
            Ed25519PrivateKeyParameters key = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();
            Utilities util = new Utilities();

            JsonSerializerOptions JsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true
            };
            var header = new Dictionary<string, object>()
            {
                {
                    "alg", "EdDSA"
                },
                {
                    //"typ", "JWT"
                    "typ", "openid4vci-proof+jwt"
                },
                {
                    "kid",util.GetDID(_env)
                },
            };

            if ((string)header["alg"] == "none" || string.IsNullOrEmpty((string)header["alg"]))
            {
                return "Error";
            }

            if ((string)header["typ"] == "none" || string.IsNullOrEmpty((string)header["typ"]))
            {
                return "Error";
            }

            // org.iso.18013.5.1.mDL (mso_mdoc) requires a P-256 device public key in the proof's
            // "jwk" header — see CredentialController's mdoc branch and Appendix A.2
            // (cryptographic_binding_methods_supported: ["cose_key"]). This is separate from "kid",
            // which is only used to verify the proof JWT's own signature. Real wallets supply their
            // own device key here; for Swagger-driven testing we generate a throwaway P-256 key pair
            // on the fly so the mDL flow can be exercised end-to-end.
            if (string.Equals(credentialConfigurationId, "org.iso.18013.5.1.mDL", StringComparison.Ordinal))
            {
                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                ECParameters ecParams = ecdsa.ExportParameters(false);
                header["jwk"] = new Dictionary<string, string>
                {
                    { "kty", "EC" },
                    { "crv", "P-256" },
                    { "x", WebEncoders.Base64UrlEncode(ecParams.Q.X) },
                    { "y", WebEncoders.Base64UrlEncode(ecParams.Q.Y) },
                };
            }

            // H-11: use the same canonical issuer base URL as everywhere else, instead of trusting
            // Request.Scheme/Host directly.
            var baseUrl = IssuerController.GetBaseUrl(HttpContext, _options);

            var payloadData = new Dictionary<string, string>()
            {
                {
                    "aud", baseUrl
                },
                {
                    "iat", ((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds().ToString()
                },
                {
                    "nonce",nonce
                },
            };

            if (payloadData["aud"] == "" || string.IsNullOrEmpty(payloadData["aud"]))
            {
                return "Error";
            }

            if (payloadData["iat"] == "" || string.IsNullOrEmpty(payloadData["iat"]))
            {
                return "Error";
            }

            if (int.TryParse(payloadData["aud"], out _))
            {
                return "Error";
            }

            if (int.TryParse(payloadData["iat"], out int result))
            {
                if (result <= 0)
                {
                    return "Error";
                }
            }

            var headerJson = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header, JsonOptions)));
            var payloadJson = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payloadData, JsonOptions)));

            var signingString = $"{headerJson}.{payloadJson}";
            var payloadBytes = Encoding.UTF8.GetBytes(signingString);

            var signer = new Ed25519Signer();
            signer.Init(true, key);
            signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);

            var signature = WebEncoders.Base64UrlEncode(signer.GenerateSignature());

            string jwt = $"{headerJson}.{payloadJson}.{signature}";
            return jwt;
        }

        [Authorize(Roles = "admin")]
        [HttpPost]
        [Route("/did/create")]
        [Tags("DID")]
        public IActionResult CreateDid()
        {
            try
            {
                VCService vcServ = new VCService();
                // กลับมาใช้ did:key (_GetDID) ให้ตรงกับ flow ออก VC จริง (CredentialController) และ
                // status list (IssuerController) ที่สลับกลับมาแล้ว — wallet มองไม่เห็น/resolve did:web ไม่ได้
                string did = vcServ._GetDID(_env);

                return Ok(new
                {
                    did = did,
                    status = "200"
                });
            }
            catch (Exception ex)
            {
                // H-04: don't leak ex.Message to the caller, log server-side instead.
                logger.Error(ex, "CreateDid error");
                return BadRequest(new { error = "request_failed", status = "400" });
            }
        }
    }
}
