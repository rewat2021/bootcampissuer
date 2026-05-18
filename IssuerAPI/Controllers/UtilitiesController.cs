using IssuerAPI.Models;
using IssuerAPI.Service;
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
                    "alg", "EdDSA" //FT.IC.CI.I.H.IB.013 { default EdDSA}, FT.IC.CI.I.H.IB.017 { none }
                },
                {
                    "typ", "JWT" //FT.IC.CI.I.H.IB.014 { default JWT }, FT.IC.CI.I.H.IB.018 { none }
                },
                {
                    "kid",util.GetDID(_env)
                },
            };

            if (header["alg"] == "none" || string.IsNullOrEmpty(header["alg"]))
            {
                return "Error";
            }

            if (header["typ"] == "none" || string.IsNullOrEmpty(header["typ"])) //openid4vci-proof+jwt
            {
                return "Error";
            }


            // string url = serv.CheckHttps(HttpContext.Request.GetDisplayUrl());
            var baseUrl = $"{Request.Scheme}://{Request.Host}";

            var payloadData = new Dictionary<string, string>()
            {
                {
                    "aud", baseUrl //iss
                },
                {
                    "iat", ((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds().ToString() //FT.IC.CI.I.H.IB.028 
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
            //var payloadJson = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));

            var signingString = $"{headerJson}.{payloadJson}";
            var payloadBytes = Encoding.UTF8.GetBytes(signingString);

            var signer = new Ed25519Signer();
            signer.Init(true, key);
            signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);

            var signature = WebEncoders.Base64UrlEncode(signer.GenerateSignature());

            string jwt = $"{headerJson}.{payloadJson}.{signature}";
            return jwt;
        }

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
                logger.Error($"CreateDid error: {ex.Message}");
                return BadRequest(new { error = ex.Message, status = "400" });
            }
        }
    }
}
