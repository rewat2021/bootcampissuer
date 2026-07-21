using IssuerAPI.Models;
using IssuerAPI.Service;
using IssuerAPI.Util;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Utilities;
using QRCoder;
using SimpleBase;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace IssuerAPI.Controllers
{
    [ApiController]
    [Tags("Credential Offer")]
    [Route("[controller]")]
    public class CredentialOfferController : ControllerBase
    {
        private readonly IWebHostEnvironment _env;
        private readonly Oid4VciOptions _options;
        private IConfiguration _config;
        private string credentialOfferId = null;


        public CredentialOfferController(IConfiguration config, IWebHostEnvironment env, IOptions<Oid4VciOptions> options)
        {
            _config = config;
            _env = env;
            _options = options.Value;
        }


        [HttpPost("/credential-offer")]
        public IActionResult GenerateCredentialOfferQr([FromBody] GenerateQrRequest request)
        {

            //for SD-JWT
            //string credentialConfigurationId = request.DocumentType switch
            //{
            //    DocumentType.Transcript => "TranscriptCredential_dc+sd-jwt",
            //    DocumentType.IdCard => "IDCard_dc+sd-jwt",
            //    DocumentType.DriverLicense => "Iso18013DriversLicenseCredential_dc+sd-jwt",
            //    DocumentType.BootCamp => "BootCampCredential_dc+sd-jwt",
            //    _ => throw new ArgumentOutOfRangeException()
            //};

            List<string> credentialConfigurationIds = new();

            if (request.DocumentType == DocumentType.DriverLicense)
            {
                // ใบขับขี่ -> ออกทั้ง mDoc และ SD-JWT พร้อมกัน
                credentialConfigurationIds.Add("org.iso.18013.5.1.mDL");                    // mso_mdoc
                credentialConfigurationIds.Add("Iso18013DriversLicenseCredential_dc+sd-jwt"); // dc+sd-jwt
            }
            else
            {
                // เอกสารอื่น -> ออกแค่ SD-JWT ตามเดิม
                string credentialConfigurationId = request.DocumentType switch
                {
                    DocumentType.Transcript => "TranscriptCredential_dc+sd-jwt",
                    DocumentType.IdCard => "IDCard_dc+sd-jwt",
                    DocumentType.BootCamp => "BootCampCredential_dc+sd-jwt",
                    _ => throw new ArgumentOutOfRangeException()
                };
                credentialConfigurationIds.Add(credentialConfigurationId);
            }


            string stateId = Guid.NewGuid().ToString();
            VCService serv = new VCService();

            string guid = new Service.VCService().GetGUID();
            string url = serv.CheckHttps(HttpContext.Request.GetDisplayUrl());
            var baseUrl = _config["BASE_URL"] ?? $"{Request.Scheme}://{Request.Host}";
            //CredentialOffer credentialOffer = new CredentialOffer();
            //credentialOffer.credential_issuer = baseUrl;
            //credentialOffer.credential_configuration_ids = new List<string>();
            //credentialOffer.credential_configuration_ids.Add(credentialConfigurationId);

            grant grant = new grant();
            byte[] random = new Byte[8];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(random);

            var preAuthorizedCode = SetPreAuthorizedCode(guid, baseUrl);//WebEncoders.Base64UrlEncode(random);
            grant.UrnIetfParamsOauthGrantTypePreAuthorizedCode = new grant.grant_value();
            grant.UrnIetfParamsOauthGrantTypePreAuthorizedCode.pre_authorized_code = "sX2CpoKx";//preAuthorizedCode;
                                                                                                //credentialOffer.grants = grant;

            var _credentialOffer = new
            {
                credential_issuer = baseUrl,
                credential_configuration_ids = credentialConfigurationIds.ToArray(), //new[] { credentialConfigurationId },
                grants = new Dictionary<string, object>
                {
                    {
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        new Dictionary<string, object>
                        {
                            { "pre-authorized_code", preAuthorizedCode }
                        }
                    }
                }
            };

            
            var offer = Newtonsoft.Json.JsonConvert.SerializeObject(_credentialOffer);
            string credentialOfferUrl = "openid-credential-offer://?credential_offer_uri=" + Uri.EscapeDataString($"{baseUrl}/openid4vc/credentialOffer?id={guid}");


            //save dbrequest vc
            DBService dbServ = new DBService();
            dbServ.SaveRequestCredential(guid, credentialConfigurationIds, preAuthorizedCode);

            //string credentialOfferUrl =
            //    $"{baseUrl}/openid4vc/credentialoffer?id={stateId}";

            string QRCode = serv.GenerateQrCodeBase64(credentialOfferUrl);

            var response = new GenerateQrResponse
            {
                CredentialOffer = _credentialOffer,
                CredentialOfferUri = credentialOfferUrl,
                QrText = QRCode
            };

            return Ok(response);
        }

        private string SetPreAuthorizedCode(string id, string credential_issuer)
        {
            VCService serv = new VCService();
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            AuthorizedCode payload = new AuthorizedCode();
            payload.Iss = credential_issuer;
            payload.Aud = "TOKEN";
            payload.Sub = id;

            //JsonResult jres = Json(payload);
            var json = System.Text.Json.JsonSerializer.Serialize(payload, options);

            string header = $"{{\"alg\": \"EdDSA\"}}";
            var payloadJson = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(json));
            var headerJson = Convert.ToBase64String(Encoding.UTF8.GetBytes(header))
                .Replace("+", "-") // Replace '+' with '-'
                .Replace("/", "_") // Replace '/' with '_'
                .TrimEnd('=');     // Remove padding characters ('=')
            var signingString = headerJson + "." + payloadJson;
            var payloadBytes = Encoding.UTF8.GetBytes(signingString);

            PemReader pemReaderPrivate = new PemReader(new StringReader(serv.GetKey(true, _env)));
            Ed25519PrivateKeyParameters privateKeyEd25519 = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();

            var signer = new Ed25519Signer();
            signer.Init(true, privateKeyEd25519);
            signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);


            string encodedSignature = WebEncoders.Base64UrlEncode(signer.GenerateSignature());

            return $"{headerJson}.{payloadJson}.{encodedSignature}";
        }

        [HttpGet("/openid4vc/credentialOffer")]
        public IActionResult CredentialOffer([FromQuery] string id)
        {
            DBService serv = new DBService();
            Utilities util = new Utilities();
            credentialOfferId = id;
            var baseUrl = $"{Request.Scheme}://{Request.Host}";

            // ✅ เปลี่ยนจาก GetDocumentType (เอกพจน์) เป็น GetDocumentTypes (พหูพจน์ — deserialize แล้ว)
            List<string> credentialConfigurationIds = serv.GetDocumentTypes(id);

            if (credentialConfigurationIds == null || credentialConfigurationIds.Count == 0)
            {
                return BadRequest(new { message = "invalid credential_configuration_ids ❌" });
            }

            AccessCode accessCode = serv.getPreAuthorizedByRegisID(id);

            var credentialOffer = new
            {
                credential_issuer = baseUrl,
                credential_configuration_ids = credentialConfigurationIds,   // ✅ ใส่ list ตรง ๆ ไม่ห่อซ้ำ
                grants = new Dictionary<string, object>
        {
            {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                new Dictionary<string, object>
                {
                    { "pre-authorized_code", accessCode.authoriseCode }
                }
            }
        }
            };

            if (string.IsNullOrEmpty(credentialOffer.credential_issuer))
            {
                return BadRequest(new { message = "invalid credential_issuer ❌" });
            }

            return Ok(credentialOffer);
        }
        //public IActionResult CredentialOffer([FromQuery] string id)//, string docType)
        //{
        //    DBService serv = new DBService();
        //    Utilities util = new Utilities();



        //    credentialOfferId = id;
        //    var baseUrl = $"{Request.Scheme}://{Request.Host}";

        //    string credentialConfigurationId = serv.GetDocumentType(id);

        //    AccessCode accessCode = serv.getPreAuthorizedByRegisID(id);
        //    var credentialOffer = new
        //    {
        //        credential_issuer = baseUrl,
        //        credential_configuration_ids = new[] { credentialConfigurationId },
        //        grants = new Dictionary<string, object>
        //        {
        //            {
        //                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        //                new Dictionary<string, object>
        //                {
        //                    { "pre-authorized_code", accessCode.authoriseCode }
        //                }
        //            }
        //        }
        //    };

        //    var offer = System.Text.Json.JsonSerializer.Serialize(credentialOffer);


        //    string credential_issuer = null;

        //    if (string.IsNullOrEmpty(credentialOffer.credential_issuer) || credentialOffer.credential_configuration_ids == null ||
        //        credentialOffer.credential_configuration_ids.Length == 0)
        //    {
        //        return BadRequest(new
        //        {
        //            message = "invalid credential_issuer ❌"
        //        });
        //    }


        //    //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Holder, AppConstant.Issuer, "FT.IC.CO.H.I.VB.005", $"Credential Offer => {credential_issuer}", "200", id);

        //    return Ok(credentialOffer);
        //}
    }
}
