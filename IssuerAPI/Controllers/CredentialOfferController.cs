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

        // Lets the QR page decide, before asking for any QR, whether this citizen already has a PID
        // VC on record. If not, the page skips document-type selection entirely and goes straight to
        // requesting the PID VC (IdCard) — same DB check GenerateCredentialOfferQr enforces below.
        [Authorize]
        [HttpGet("/credential-offer/pid-status")]
        public IActionResult PidStatus()
        {
            Response.Headers["Cache-Control"] = "no-store";

            var subject = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(subject))
            {
                return Unauthorized(new { error = "unauthorized" });
            }

            try
            {
                bool hasPidVc = new DBService().HasBeenIssuedPidVc(subject);
                return Ok(new { has_pid_vc = hasPidVc });
            }
            catch (Exception ex)
            {
                // H-04 style: never let this leak a raw 500/empty body to the QR page's fetch() call —
                // HasBeenIssuedPidVc already fails closed and logs internally, but guard here too in
                // case something else in this action throws.
                NLog.LogManager.GetCurrentClassLogger().Error(ex, "PidStatus failed");
                return Ok(new { has_pid_vc = false });
            }
        }

        // C-05: creating a credential offer/pre-authorized code binds it to a signed-in user's
        // registerId — must not be callable anonymously.
        [Authorize]
        [HttpPost("/credential-offer")]
        public IActionResult GenerateCredentialOfferQr([FromBody] GenerateQrRequest request)
        {
            // H-12
            Response.Headers["Cache-Control"] = "no-store";

            // C-05: record which authenticated caller requested this offer (dbusers.Id for
            // staff/password login, ThaID citizen PID otherwise). [Authorize] guarantees a
            // ClaimsPrincipal, so this should never actually be empty — defensive check anyway,
            // consistent with RedirectToWallet below.
            var subject = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(subject))
            {
                return Unauthorized(new { error = "unauthorized" });
            }

            // Flow requirement (TEMPORARILY DISABLED per request — re-enable by uncommenting the
            // block below): every document request must start from PID VC (the ID card credential)
            // already being issued to this citizen's wallet. Requesting the PID VC itself is exempt
            // (that's how you get one in the first place); everything else would be blocked until
            // this citizen has one on record. DB-side check only — proves the issuer already issued a
            // PID VC to this subject, not that the wallet currently still holds it.
            //
            // Audit note (C-05): this does NOT fully satisfy C-05's "authoritative data" requirement —
            // Transcript/DriverLicense/etc. are still generated from mock/hardcoded subject data, not
            // an authoritative record. What this DOES guarantee is that no document can be requested
            // at all until the citizen has gone through PID VC issuance first, so C-05 remains open in
            // the audit until credential generation itself reads real per-subject data.
            DBService dbServ = new DBService();
            // if (request.DocumentType != DocumentType.IdCard && !dbServ.HasBeenIssuedPidVc(subject))
            // {
            //     return BadRequest(new
            //     {
            //         error = "pid_vc_required",
            //         error_description = "a PID VC (ID card credential) must be issued to this wallet before requesting other documents"
            //     });
            // }

            List<string> credentialConfigurationIds = new();

            if (request.DocumentType == DocumentType.DriverLicense)
            {
                // H-08 (fixed): mso_mdoc issuance now extracts a real P-256 device key from the
                // wallet's proof (jwk header) instead of binding to null — safe to advertise again.
                credentialConfigurationIds.Add("org.iso.18013.5.1.mDL");                     // mso_mdoc
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
            var baseUrl = IssuerController.GetBaseUrl(HttpContext, _options);

            // M-04: the actual pre-authorized_code used below is generated by SetPreAuthorizedCode().
            // A separate, unused `grant` object with a hard-coded sample code ("sX2CpoKx") used to be
            // built here and thrown away — dead code that risked someone "fixing" the wrong path.
            var preAuthorizedCode = SetPreAuthorizedCode(guid, baseUrl);

            //save dbrequest vc
            dbServ.SaveRequestCredential(guid, credentialConfigurationIds, preAuthorizedCode, subject, GetThaIdProfileFromClaims());

            // tx_code (companion PIN) — only for this cross-device (QR) flow. Anyone who sees/screenshots
            // the QR before the legitimate wallet scans it would otherwise be able to redeem the code
            // themselves; requiring a PIN shown separately (not encoded in the QR itself) closes that
            // gap. Same-device (RedirectToWallet/BuildOffer) doesn't set this — no QR there to intercept.
            string txCode = DBService.GenerateTxCode();
            dbServ.SetTxCode(guid, txCode);

            var preAuthGrant = new Dictionary<string, object>
            {
                { "pre-authorized_code", preAuthorizedCode },
                { "tx_code", new { length = 6, input_mode = "numeric", description = "กรอกรหัส 6 หลักที่แสดงบนหน้าจอ" } }
            };

            var _credentialOffer = new
            {
                credential_issuer = baseUrl,
                credential_configuration_ids = credentialConfigurationIds.ToArray(), //new[] { credentialConfigurationId },
                grants = new Dictionary<string, object>
                {
                    { "urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant }
                }
            };


            var offer = Newtonsoft.Json.JsonConvert.SerializeObject(_credentialOffer);
            string credentialOfferUrl = "openid-credential-offer://?credential_offer_uri=" + Uri.EscapeDataString($"{baseUrl}/openid4vc/credentialOffer?id={guid}");

            //string credentialOfferUrl =
            //    $"{baseUrl}/openid4vc/credentialoffer?id={stateId}";

            string QRCode = serv.GenerateQrCodeBase64(credentialOfferUrl);

            var response = new GenerateQrResponse
            {
                CredentialOffer = _credentialOffer,
                CredentialOfferUri = credentialOfferUrl,
                QrText = QRCode,
                ExpiresIn = (int)DBService.PreAuthorizedCodeTtl.TotalSeconds,
                RequestId = guid,
                TxCode = txCode
            };

            return Ok(response);
        }

        // Cross-device flow: the QR page polls this while the QR is on screen to find out once the
        // wallet has scanned it, redeemed the pre-authorized_code, and successfully called
        // /credential — at which point the page swaps to a "ออกเอกสารสำเร็จแล้ว" screen instead of
        // leaving a stale QR up. Scoped to the caller's own subject (see
        // HasCredentialBeenIssuedForOffer) so this can't be used to probe other people's offers.
        [Authorize]
        [HttpGet("/credential-offer/status")]
        public IActionResult OfferStatus([FromQuery] string id)
        {
            Response.Headers["Cache-Control"] = "no-store";

            var subject = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(subject))
            {
                return Unauthorized(new { error = "unauthorized" });
            }

            if (string.IsNullOrWhiteSpace(id))
            {
                return BadRequest(new { error = "invalid_request", error_description = "id is required" });
            }

            try
            {
                bool issued = new DBService().HasCredentialBeenIssuedForOffer(id, subject);
                return Ok(new { issued });
            }
            catch (Exception ex)
            {
                NLog.LogManager.GetCurrentClassLogger().Error(ex, "OfferStatus failed");
                return Ok(new { issued = false });
            }
        }

        // Same-device (ใหม่): wallet เปิด browser มาที่นี่ตรงๆ หลัง login สำเร็จ
        // (เรียกจาก AccountController.Login เมื่อตรวจพบว่า ReturnUrl เป็น wallet callback)
        // ไม่ต้องโชว์ QR — redirect ด้วย custom scheme ตรงไปหา wallet เลย เพราะ wallet อยู่เครื่องเดียวกันอยู่แล้ว
        // C-05
        [Authorize]
        [ApiExplorerSettings(IgnoreApi = true)]
        [HttpGet("/credential-offer/redirect")]
        public IActionResult RedirectToWallet([FromQuery] DocumentType documentType)
        {
            var subject = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(subject))
                return Unauthorized(new { error = "unauthorized" });

            // Same PID-VC-first requirement as GenerateCredentialOfferQr above — TEMPORARILY DISABLED,
            // see the comment there for why/how to re-enable.
            // if (documentType != DocumentType.IdCard && !new DBService().HasBeenIssuedPidVc(subject))
            // {
            //     return BadRequest(new
            //     {
            //         error = "pid_vc_required",
            //         error_description = "a PID VC (ID card credential) must be issued to this wallet before requesting other documents"
            //     });
            // }

            var built = BuildOffer(documentType, subject);
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
                // H-08 (fixed): mso_mdoc now binds a real device key extracted from the wallet's proof.
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
            var baseUrl = IssuerController.GetBaseUrl(HttpContext, _options);

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

            // C-05: subject now actually persisted (DBService.SaveRequestCredential / Dbrequest.Subject)
            // instead of being computed and thrown away.
            DBService dbServ = new DBService();
            dbServ.SaveRequestCredential(guid, credentialConfigurationIds, preAuthorizedCode, subject, GetThaIdProfileFromClaims());

            return (credentialOfferObject, credentialOfferUrl);
        }

        // C-05 (partial): rebuild the ThaID profile from the claims AccountController.ThaiIDCallback
        // put on the cookie (title/given/family/birthdate/gender), so it can be persisted against this
        // offer's registerId. Returns null for staff/password logins (no ThaID claims present) — those
        // callers keep falling back to mock data downstream, same behavior as before this change.
        private ThaIDCheckStateResponse GetThaIdProfileFromClaims()
        {
            var givenName = User.FindFirstValue(ClaimTypes.GivenName);
            var surname = User.FindFirstValue(ClaimTypes.Surname);
            if (string.IsNullOrWhiteSpace(givenName) && string.IsNullOrWhiteSpace(surname))
            {
                return null;
            }

            return new ThaIDCheckStateResponse
            {
                TitleNameTh = User.FindFirstValue("thaid_title"),
                FirstNameTh = givenName,
                LastNameTh = surname,
                BirthDate = User.FindFirstValue(ClaimTypes.DateOfBirth),
                Gender = User.FindFirstValue(ClaimTypes.Gender),
                Address = User.FindFirstValue(ClaimTypes.StreetAddress),
                DateOfIssuance = User.FindFirstValue("thaid_date_of_issuance"),
                DateOfExpiry = User.FindFirstValue("thaid_date_of_expiry"),
                TitleNameEn = User.FindFirstValue("thaid_title_en"),
                FirstNameEn = User.FindFirstValue("thaid_given_name_en"),
                LastNameEn = User.FindFirstValue("thaid_family_name_en")
            };
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
            // H-12
            Response.Headers["Cache-Control"] = "no-store";

            DBService serv = new DBService();
            var baseUrl = IssuerController.GetBaseUrl(HttpContext, _options);

            List<string> credentialConfigurationIds = serv.GetDocumentTypes(id);

            if (credentialConfigurationIds == null || credentialConfigurationIds.Count == 0)
            {
                return BadRequest(new { message = "invalid credential_configuration_ids ❌" });
            }

            AccessCode accessCode = serv.getPreAuthorizedByRegisID(id);

            // H-10: getPreAuthorizedByRegisID now returns an empty authoriseCode once the code is
            // expired or already consumed (same TTL/consumed policy as /token). Previously this
            // wasn't checked here at all, so the endpoint would happily hand back a credential offer
            // whose "pre-authorized_code" was silently null/stale for an unauthenticated, indefinitely
            // repeatable GET.
            if (string.IsNullOrEmpty(accessCode?.authoriseCode))
            {
                return BadRequest(new { message = "pre-authorized_code is invalid, expired, or already used ❌" });
            }

            // tx_code — this is the endpoint a real wallet actually calls to resolve credential_offer_uri
            // (the QR only encodes a link to here), so this is where the tx_code requirement must show up
            // for it to take effect. Mirrors whatever GenerateCredentialOfferQr decided when the offer was
            // created (PIN set only for cross-device/QR offers) — read back from the stored hash rather
            // than re-deciding here, so this endpoint can't drift out of sync with what was promised.
            var preAuthGrant = new Dictionary<string, object>
            {
                { "pre-authorized_code", accessCode.authoriseCode }
            };
            if (serv.HasTxCode(id))
            {
                preAuthGrant["tx_code"] = new { length = 6, input_mode = "numeric", description = "กรอกรหัส 6 หลักที่แสดงบนหน้าจอ" };
            }

            var credentialOffer = new
            {
                credential_issuer = baseUrl,
                credential_configuration_ids = credentialConfigurationIds,
                grants = new Dictionary<string, object>
                {
                    { "urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant }
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
