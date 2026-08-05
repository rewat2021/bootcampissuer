using IssuerAPI.Models;
using IssuerAPI.Service;
using IssuerAPI.Services;
using IssuerAPI.Util;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
        private readonly ILogger<CredentialConfigService> _logger;

        public CredentialOfferController(IConfiguration config, IWebHostEnvironment env, IOptions<Oid4VciOptions> options, ILogger<CredentialConfigService> logger)
        {
            _config = config;
            _env = env;
            _options = options.Value;
            _logger = logger;
        }

        [HttpPost("/credential-offer")]
        public IActionResult GenerateCredentialOfferQr([FromBody] GenerateQrRequest request)
        {


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
                    _ => throw new ArgumentOutOfRangeException()
                };
                credentialConfigurationIds.Add(credentialConfigurationId);
            }


            string stateId = Guid.NewGuid().ToString();
            VCService serv = new VCService();

            string guid = new Service.VCService().GetGUID();
            string url = serv.CheckHttps(HttpContext.Request.GetDisplayUrl());
            var baseUrl = _config["BASE_URL"] ?? $"{Request.Scheme}://{Request.Host}";


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

        // Same-device (ใหม่): wallet เปิด browser มาที่นี่ตรงๆ หลัง login สำเร็จ
        // (เรียกจาก AccountController.Login เมื่อตรวจพบว่า ReturnUrl เป็น wallet callback)
        // ไม่ต้องโชว์ QR — redirect ด้วย custom scheme ตรงไปหา wallet เลย เพราะ wallet อยู่เครื่องเดียวกันอยู่แล้ว
        [ApiExplorerSettings(IgnoreApi = true)]
        [HttpGet("/credential-offer/redirect")]
        public IActionResult RedirectToWallet([FromQuery] DocumentType documentType)
        {
            //var subject = User.FindFirstValue(ClaimTypes.NameIdentifier);
            //if (string.IsNullOrEmpty(subject))
            //    return Unauthorized(new { error = "unauthorized" });

            var built = BuildOffer(documentType, null);
            _logger.LogInformation($"start credential offer same device");

            // openid-credential-offer:// คือ scheme ที่ wallet ลงทะเบียนดักจับไว้อยู่แล้ว
            // ไม่ต้องมี redirect_uri ของ wallet เองเพิ่มเติม — OS จับ scheme นี้แล้วเปิดแอปให้ตรงๆ
            return Redirect($"walletapp://callback?{built.CredentialOfferUrl}");
        }

        // ผูก logic การสร้าง offer ไว้ที่เดียว ให้ทั้ง cross-device (QR) และ same-device (redirect) เรียกใช้ร่วมกัน
        private (object CredentialOfferObject, string CredentialOfferUrl) BuildOffer(DocumentType documentType, string subject)
        {
            List<string> credentialConfigurationIds = new();

            if (documentType == DocumentType.DriverLicense)
            {
                // ใบขับขี่ -> ออกทั้ง mDoc และ SD-JWT พร้อมกัน
                credentialConfigurationIds.Add("org.iso.18013.5.1.mDL");
                credentialConfigurationIds.Add("Iso18013DriversLicenseCredential_dc+sd-jwt");
            }
            else
            {
                string credentialConfigurationId = documentType switch
                {
                    DocumentType.Transcript => "TranscriptCredential_dc+sd-jwt",
                    DocumentType.IdCard => "IDCard_dc+sd-jwt",
                    _ => throw new ArgumentOutOfRangeException(nameof(documentType))
                };
                credentialConfigurationIds.Add(credentialConfigurationId);
            }

            VCService serv = new VCService();
            string guid = serv.GetGUID();
            var baseUrl = _config["BASE_URL"] ?? $"{Request.Scheme}://{Request.Host}";

            // แก้ bug เดิม: ใช้ code ที่ generate จริง ไม่ใช้ค่า hardcode
            var preAuthorizedCode = SetPreAuthorizedCode(guid, baseUrl);

            var credentialOfferObject = new
            {
                credential_issuer = baseUrl,
                credential_configuration_ids = credentialConfigurationIds.ToArray(),
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

            string credentialOfferUrl = "credential_offer_uri=" +
                Uri.EscapeDataString($"{baseUrl}/openid4vc/credentialOffer?id={guid}");

            // ผูก subject เข้ากับ request ที่บันทึกไว้ — ต้องเพิ่ม parameter subject ใน DBService.SaveRequestCredential
            // เพื่อให้ตอนออก VC จริงรู้ว่าเป็นของ user คนไหน (เดิมไม่มีการผูกกับ user เลย)
            DBService dbServ = new DBService();
            dbServ.SaveRequestCredential(guid, credentialConfigurationIds, preAuthorizedCode);//, subject);

            return (credentialOfferObject, credentialOfferUrl);
        }

        private string SetPreAuthorizedCode(string id, string credential_issuer)
        {
            VCService serv = new VCService();
            var options = new JsonSerializerOptions { WriteIndented = true };

            AuthorizedCode payload = new AuthorizedCode();
            payload.Iss = credential_issuer;
            payload.Aud = "TOKEN";
            payload.Sub = id;

            var json = JsonSerializer.Serialize(payload, options);

            string header = $"{{\"alg\": \"EdDSA\"}}";
            var payloadJson = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(json));
            var headerJson = Convert.ToBase64String(Encoding.UTF8.GetBytes(header))
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
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

        // ของเดิม ไม่เปลี่ยน — wallet เรียกที่นี่ตอน resolve credential_offer_uri (by reference)
        [HttpGet("/openid4vc/credentialOffer")]
        public IActionResult CredentialOffer([FromQuery] string id)
        {
            DBService serv = new DBService();
            var baseUrl = $"{Request.Scheme}://{Request.Host}";

            List<string> credentialConfigurationIds = serv.GetDocumentTypes(id);

            if (credentialConfigurationIds == null || credentialConfigurationIds.Count == 0)
            {
                return BadRequest(new { message = "invalid credential_configuration_ids ❌" });
            }

            AccessCode accessCode = serv.getPreAuthorizedByRegisID(id);

            var credentialOffer = new
            {
                credential_issuer = baseUrl,
                credential_configuration_ids = credentialConfigurationIds,
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
    }
}
