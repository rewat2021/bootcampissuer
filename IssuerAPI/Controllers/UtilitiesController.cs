using IssuerAPI.Models;
using IssuerAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
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
        public string GenerateJWTEd25519(string nonce) //, string iss)
        {
            VCService serv = new VCService();
            PemReader pemReaderPrivate = new PemReader(new StringReader(serv.GetKey(true, _env)));
            Ed25519PrivateKeyParameters key = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();
            Utilities util = new Utilities();

            JsonSerializerOptions JsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true
            };
            var header = new Dictionary<string, string>()
            {
                {
                    "alg", "EdDSA"
                },
                {
                    "typ", "JWT"
                },
                {
                    "kid",util.GetDID(_env)
                },
            };

            if (header["alg"] == "none" || string.IsNullOrEmpty(header["alg"]))
            {
                return "Error";
            }

            if (header["typ"] == "none" || string.IsNullOrEmpty(header["typ"]))
            {
                return "Error";
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
