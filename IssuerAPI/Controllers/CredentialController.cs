using IssuerAPI.Models;
using IssuerAPI.Service;
using IssuerAPI.Util;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NLog;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Utilities;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace IssuerAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    [Tags("Credenital Issuance")]
    public class CredentialController : ControllerBase
    {
        private readonly IWebHostEnvironment _env;
        private readonly Oid4VciOptions _options;
        private IConfiguration _config;
        private string credentialOfferId = null;
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private string urlBase => $"{Request.Scheme}://{Request.Host}";

        public CredentialController(IConfiguration config, IWebHostEnvironment env, IOptions<Oid4VciOptions> options)
        {
            _config = config;
            _env = env;
            _options = options.Value;
        }

        [HttpPost]
        [Route("/credential")]
        public IActionResult Credential([FromBody] IssuanceRequest request)
        {
            //logs.Add(JsonSerializer.Serialize(new { message = "Accept Request ✅" }, new JsonSerializerOptions { WriteIndented = true }));
            VCService serv = new VCService();
            DBService dbServ = new DBService();
            string proof = request.proof.jwt;
            string registerId = serv.getProofByNonce(proof);
            string walletid = null;
            string vcFormat = null;

            logger.Info("Start Credential");
            logger.Info($"registerid => {registerId}");
            logger.Info($"proof => {request.proof}");

            string vcDocType = dbServ.GetDocumentType(registerId);
            if (vcDocType == null)
            {
                return BadRequest(new
                {
                    message = "Issue VC – VC Issuance Request Fail, not found Document Type",
                    status = 400,
                });
            }
            //Request.Headers.TryGetValue("UserId", out var clientId);
            //AppContextHelper.UserId = AppContextHelper.UserId == null ? clientId : AppContextHelper.UserId;
            //AppContextHelper.UserId = AppContextHelper.UserId == null ? registerId : AppContextHelper.UserId;
            //logs.Add(JsonSerializer.Serialize(request, new JsonSerializerOptions { WriteIndented = true }));

            if (!ModelState.IsValid)
            {
                var item = new ApiLogs
                {
                    message = "Issue VC – VC Issuance Request Fail ❌)",
                    status = 400,
                    error = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList()
                };
                //logs.Add(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
                //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Holder, AppConstant.Issuer, "FT.IC.AU.H.I.VB.002, FT.IC.CI.H.I.VB.010", $"Error validate => {JsonSerializer.Serialize(item)}", "400", null);
                return BadRequest(new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error
                });
            }

            //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Holder, AppConstant.Issuer, "FT.IC.AU.H.I.VB.002", $"Authorization_Response => {JsonSerializer.Serialize(request)}", "200", null);
            //if (string.IsNullOrEmpty(request.credential_configuration_id))
            //{
            //    return BadRequest(new
            //    {
            //        error = "invalid_request",
            //        error_description = "credential_configuration_id is required"
            //    });
            //}

            // แทนที่ block เดิมที่ return BadRequest
            logger.Info($"credential_configuration_id => {request.credential_configuration_id}");
            if (string.IsNullOrEmpty(request.credential_configuration_id))
            {
                request.credential_configuration_id = vcDocType; // fallback จาก DB
            }
            logger.Info($"credential_configuration_id => {request.credential_configuration_id}");
            /*if (string.IsNullOrEmpty(request.credential_configuration_id))// && string.IsNullOrEmpty(request.format))
            {
                var item = new ApiLogs
                {
                    message = "Issue VC – VC Issuance Request Fail ❌)",
                    status = 500,
                    error = new List<string> { "credential_identifier or format is null" }
                };
                
                return BadRequest(new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error
                });
            }
            if (!string.IsNullOrEmpty(request.credential_configuration_id))// && !string.IsNullOrEmpty(request.format))
            {
                var item = new ApiLogs
                {
                    message = "Issue VC – VC Issuance Request Fail ❌)",
                    status = 500,
                    error = new List<string> { "‘credential_identifier’ and ‘format’ MUST NOT be used simultaneously" }
                };
                
                return BadRequest(new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error
                });
            }*/
            //logs.Add(JsonSerializer.Serialize(request, new JsonSerializerOptions { WriteIndented = true }));
            // Retrieve the Authorization header
            var authorizationHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();

            if (authorizationHeader == null || !authorizationHeader.StartsWith("Bearer "))
            {
                var item = new ApiLogs
                {
                    message = "Issue VC – VC Issuance Request Fail ❌",
                    status = 401,
                    error = new List<string> { "Authorization header is either missing or invalid." }
                };
                //logs.Add(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
                return Unauthorized(item);
            }

            // Extract the token part
            var token = authorizationHeader.Substring("Bearer ".Length).Trim();

            // Here you can validate the token using your custom validation logic
            bool isValid = serv.IsTokenValid(_config, token); // Replace with your validation method

            if (!isValid)
            {
                var item = new ApiLogs
                {
                    message = "Issue VC – VC Issuance Request Fail ❌",
                    status = 401,
                    error = new List<string> { "Token is invalid" }
                };
                //logs.Add(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
                return Unauthorized(item);
            }
            //logs.Add(JsonSerializer.Serialize(new { message = "Return VC ✅" }, new JsonSerializerOptions { WriteIndented = true }));
            //logs.Add(JsonSerializer.Serialize(new ApiLogs
            //{
            //    message = "Issue VC – VC Issuance Request Pass ✅",
            //    status = 200,
            //    error = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList()
            //}, new JsonSerializerOptions { WriteIndented = true }));

            string _credential = null;
            string _nonce = null;

            string issuerid = null;
            JsonResult jResult = null;
            try
            {

                string jwt = request.proof.jwt;
                string[] parts = jwt.Split('.');
                // Decode the header and payload
                string headerJson = serv.Base64UrlDecodeToString(parts[0]);
                Console.WriteLine($">>> proof header: {headerJson}"); // ดู log ใน docker
                logger.Info($">>> proof header: {headerJson}");
                using JsonDocument doc = JsonDocument.Parse(headerJson);
                string kid = doc.RootElement.GetProperty("kid").GetString();

                //check field alg
                string alg = doc.RootElement.GetProperty("alg").GetString();
                Console.WriteLine($">>> alg value: '{alg}'");
                logger.Info($">>> alg value: '{alg}'");
                if (string.IsNullOrEmpty(alg))
                {
                    var error = new
                    {
                        credential = _credential,
                        c_nonce = _nonce,
                        statustext = "invalid encryption parameters alg",
                        status = "400",
                    };
                    //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.013", JsonSerializer.Serialize(error), "400", null);
                    return BadRequest(error);
                }

                //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.013", $"field algorithm parameters : {alg}", "200", null);

                List<string> alglist = new List<string> { "EdDSA", "ES256", "ES256K", "RS256", "none" };
                if (!alglist.Contains(alg))
                {
                    var error = new
                    {
                        credential = _credential,
                        c_nonce = _nonce,
                        statustext = "invalid encryption parameters, type alg mis value",
                        status = "400",
                    };
                    //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.017", JsonSerializer.Serialize(error), "400", null);
                    return BadRequest(error);
                }
                //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.017", $"algorithm type : {alg}", "200", null);

                //check field typ
                string typ = doc.RootElement.GetProperty("typ").GetString();
                if (string.IsNullOrEmpty(typ))
                {
                    var error = new
                    {
                        credential = _credential,
                        c_nonce = _nonce,
                        statustext = "invalid encryption parameters typ",
                        status = "400",
                    };
                    //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.014", JsonSerializer.Serialize(error), "400", null);
                    return BadRequest(error);
                }
                //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.014", $"encryption parameters typ : {typ}", "200", null);

                logger.Info($"typ => {typ}");
                List<string> typlist = new List<string> { "JWT", "jwt", "openid4vci-proof+jwt" };
                if (!typlist.Contains(typ))
                {
                    var error = new
                    {
                        credential = _credential,
                        c_nonce = _nonce,
                        statustext = "invalid encryption parameters typ, must be JWT",
                        status = "400",
                    };

                    //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.018", JsonSerializer.Serialize(error), "400", null);
                    return BadRequest(error);
                }
                //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.018", $"type data encryption : {typ}", "200", null);
                logger.Info($"parts[1] => {parts[1]}");
                string payloadJson = serv.Base64UrlDecodeToString(parts[1]);
                using JsonDocument docPayload = JsonDocument.Parse(payloadJson);
                string aud = docPayload.RootElement.GetProperty("aud").GetString();
                logger.Info($"aud => {aud}");
                //FT.IC.CI.I.H.IB.027
                List<string> audlist = new List<string> { "none", "-" };
                if (string.IsNullOrEmpty(aud))
                {
                    var error = new
                    {
                        credential = _credential,
                        c_nonce = _nonce,
                        statustext = "the aud parameters is not set",
                        status = "400",
                    };

                    //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.027", JsonSerializer.Serialize(error), "400", null);
                    return BadRequest(error);
                }

                if (audlist.Contains(aud))
                {
                    var error = new
                    {
                        credential = _credential,
                        c_nonce = _nonce,
                        statustext = "the aud parameters is not set",
                        status = "400",
                    };
                    //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.027", JsonSerializer.Serialize(error), "400", null);
                    return BadRequest(error);
                }

                bool isValidUrl = Uri.TryCreate(aud, UriKind.Absolute, out Uri uriResult)
                          && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);

                if (!isValidUrl)
                {
                    var error = new
                    {
                        credential = _credential,
                        c_nonce = _nonce,
                        statustext = "the aud parameters is invalid",
                        status = "400",
                    };
                    // ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.027, FT.IC.CI.I.H.IB.029, FT.IC.CI.I.H.IB.031", JsonSerializer.Serialize(error), "400", null);
                    return BadRequest(error);
                }
                //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.027, FT.IC.CI.I.H.IB.029, FT.IC.CI.I.H.IB.031", $"parameter aud : {aud}", "200", null);

                //string iat = docPayload.RootElement.GetProperty("iat").GetString();
                JsonElement root = docPayload.RootElement;
                long striat = 0;
                if (root.TryGetProperty("iat", out JsonElement iatElement) && iatElement.ValueKind != JsonValueKind.Null)// && iatElement.ValueKind != JsonValueKind.String)
                {

                    if (iatElement.ValueKind == JsonValueKind.String)
                    {
                        var t = iatElement.GetString();
                        striat = Convert.ToInt64(t);
                    }
                    else
                    {
                        striat = iatElement.GetInt64();
                    }

                    //docPayload.RootElement.GetProperty("iat").GetInt64();
                }

                logger.Info($"striat => {striat.ToString()}");
                string iat = striat == 0 ? null : striat.ToString();
                List<string> iatlist = new List<string> { "none", "-" };
                if (string.IsNullOrEmpty(iat))
                {
                    var error = new
                    {
                        credential = _credential,
                        c_nonce = _nonce,
                        statustext = "the iat parameters is not set",
                        status = "400",
                    };
                    // ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.028, FT.IC.CI.I.H.IB.030, FT.IC.CI.I.H.IB.032", "the iat parameters is not set", "400", null);
                    return BadRequest(error);
                }

                if (audlist.Contains(iat))
                {
                    var error = new
                    {
                        credential = _credential,
                        c_nonce = _nonce,
                        statustext = "the aud parameters is not set",
                        status = "400",
                    };
                    // ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.028, FT.IC.CI.I.H.IB.030, FT.IC.CI.I.H.IB.032", "the iat parameters is not set", "400", null);
                    return BadRequest(error);
                }

                try
                {
                    DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(long.Parse(iat));
                    DateTime dateTime = dateTimeOffset.UtcDateTime;


                    bool isValid_iat = serv.IsValidNumericDate(long.Parse(iat));
                    if (!isValid_iat)
                    {
                        var error = new
                        {
                            credential = _credential,
                            c_nonce = _nonce,
                            statustext = "the iat parameters is invalid",
                            status = "400",
                        };
                        //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.028, FT.IC.CI.I.H.IB.030, FT.IC.CI.I.H.IB.032", "the iat parameters is invalid", "400", null);
                        return BadRequest(error);
                    }
                }
                catch (Exception e)
                {
                    var error = new
                    {
                        credential = _credential,
                        c_nonce = _nonce,
                        statustext = "the iat parameters is invalid",
                        status = "400",
                    };
                    // ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.028, FT.IC.CI.I.H.IB.030, FT.IC.CI.I.H.IB.032", "the iat parameters is invalid", "400", null);
                    return BadRequest(error);
                }
                //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, "FT.IC.CI.I.H.IB.028, FT.IC.CI.I.H.IB.030, FT.IC.CI.I.H.IB.032", $"the iat parameters : {iat}", "200", null);

                // Retrieve the did:key part
                walletid = kid.Split('#')[0];

                issuerid = serv._GetDID(_env);
                string _docType = null;
                // ✅ เพิ่ม dc+sd-jwt cases
                // ── SD-JWT path (แยกออกมาก่อน switch เดิม) ──────────────────
                logger.Info($"vcDocType => {vcDocType}");
                if (vcDocType.EndsWith("dc+sd-jwt"))
                {
                    _credential = vcDocType switch
                    {
                        "TranscriptCredential_dc+sd-jwt" => serv.GenerateTranscriptSdJwt(issuerid, walletid, _env, urlBase),
                        "BootCampCredential_dc+sd-jwt" => serv.GenerateBootCampSdJwt(issuerid, walletid, _env, urlBase),
                        // "IDCard_dc+sd-jwt" => serv.GenerateIDCardSdJwt(issuerid, walletid, _env, urlBase),
                        // "Iso18013DriversLicenseCredential_dc+sd-jwt" => serv.GenerateDriversLicenseSdJwt(issuerid, walletid, _env, urlBase),
                        _ => throw new Exception($"Unsupported credential type: {vcDocType}")
                    };
                    _nonce = registerId;
                    logger.Info($">>> SD-JWT: {_credential?.Substring(0, Math.Min(100, _credential?.Length ?? 0))}");
                    logger.Info($">>> Contains ~: {_credential?.Contains('~')}");
                    logger.Info($">>> Tilde count: {_credential?.Count(c => c == '~')}");
                    
                }
                else
                {
                    var data = vcDocType switch
                    {
                        // jwt_vc_json เดิม — คงไว้
                        "TranscriptCredential_jwt_vc_json" => serv.GenerateTranscriptVC(issuerid, walletid),
                        "IDCardCredential_jwt_vc_json" => serv.GenerateIDCardVC(issuerid, walletid),


                        _ => throw new Exception($"Unsupported credential type: {vcDocType}")
                    };

                    jResult = data;
                    var options = new JsonSerializerOptions
                    {
                        WriteIndented = false,
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                    };
                    string json = JsonSerializer.Serialize(data.Value, options);


                    PemReader pemReaderPrivate = new PemReader(new StringReader(serv.GetKey(true, _env)));
                    Ed25519PrivateKeyParameters privateKeyEd25519 = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();
                    _credential = serv.GenerateJWTEd25519(json, issuerid, privateKeyEd25519);
                    _nonce = registerId; //serv.GenStateId();
                }

                vcFormat = vcDocType.EndsWith("dc+sd-jwt") ? "dc+sd-jwt" : "jwt_vc_json";
                logger.Info($"format => {vcFormat}");

            }
            catch (Exception e)
            {
                var error = new
                {
                    format = vcFormat,
                    credential = _credential,//  _credential,
                    c_nonce = _nonce,
                    statustext = $"{e.Message}, {e.InnerException}",
                    status = "400",
                    msg = jResult
                };

                dbServ.SaveIssueVCLog(issuerid, walletid, _nonce, _credential, vcFormat, "failed");
                return BadRequest(error);
            }


            var res = new
            {
                format = vcFormat,
                credential = _credential,
                c_nonce = _nonce,
                c_nonce_expires = 86400,
                notification_id = "",
                status = "200",

            };

            logger.Info(JsonSerializer.Serialize(res));
            Console.WriteLine("Success");
            dbServ.SaveIssueVCLog(issuerid, walletid, _nonce, _credential, vcFormat, "success");
            //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, AppContextHelper.credentialOfferId, $"credential response => {_credential}", "200", AppContextHelper.credentialOfferId);
            //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, AppContextHelper.credentialOfferId, $"End Issue VC", "200", AppContextHelper.credentialOfferId);

            //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Holder, AppConstant.Issuer, "FT.IC.CI.H.I.VB.001, FT.IC.CI.H.I.VB.004", $"Credential response : {res}", "200", AppContextHelper.credentialOfferId);

            //logs.Add(JsonSerializer.Serialize(new { message = res }, new JsonSerializerOptions { WriteIndented = true }));
            return Ok(res);
        }
    }
}
