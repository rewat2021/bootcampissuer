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
        private string urlBase => IssuerController.GetBaseUrl(HttpContext, _options);

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
            // H-12: credential responses carry key material / PII — must never be cached.
            Response.Headers["Cache-Control"] = "no-store";
            Response.Headers["Pragma"] = "no-cache";

            VCService serv = new VCService();
            DBService dbServ = new DBService();

            // H-01: OID4VCI 1.0 Final §8.2 — exactly one proof, submitted as proofs.jwt[0]. Spec-exact,
            // no pre-final "proof" singular fallback.
            List<string> proofJwts = request.proofs?.jwt;
            if (proofJwts == null || proofJwts.Count != 1 || string.IsNullOrWhiteSpace(proofJwts[0]))
            {
                return BadRequest(new { error = "invalid_proof", error_description = "exactly one proofs.jwt entry is required" });
            }
            string proof = proofJwts[0];

            // C-02: resolve registerId from the *verified* access token's "sub" claim, not from an
            // unauthenticated value pulled out of the proof. Previously the proof's own "nonce" claim
            // was used as a database lookup key for the grant, and the token was only checked against
            // that result afterward — i.e. the proof (unauthenticated at this point) picked which
            // grant to use, and the token merely rubber-stamped it. The token is now the sole source
            // of truth for which grant this request belongs to; the proof's "nonce" claim is checked
            // purely for freshness/replay further down, after its signature is verified.
            var authorizationHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();
            if (authorizationHeader == null || !authorizationHeader.StartsWith("Bearer "))
            {
                return Unauthorized(new { error = "invalid_token", error_description = "Authorization header is either missing or invalid." });
            }
            var token = authorizationHeader.Substring("Bearer ".Length).Trim();
            string registerId = serv.ValidateTokenAndGetSubject(_config, token);
            if (registerId == null)
            {
                return Unauthorized(new { error = "invalid_token", error_description = "Token is invalid or expired" });
            }

            string walletid = null;
            string vcFormat = null;

            logger.Info("Start Credential");
            logger.Info($"registerid => {registerId}");

            // ยังคงดึงมาเป็น List<string> เหมือนเดิม — คือ "รายการที่ authorize ไว้ทั้งหมด"
            List<string> allowedDocTypes = dbServ.GetDocumentTypes(registerId);
            if (allowedDocTypes == null || allowedDocTypes.Count == 0)
            {
                return BadRequest(new { error = "invalid_credential_request", error_description = "no document type authorized for this request" });
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(new
                {
                    error = "invalid_request",
                    error_description = string.Join("; ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))
                });
            }

            // ── เลือก 1 config id จาก request — ไม่ใช่เอา list มาทั้งก้อน ──
            logger.Info($"credential_configuration_id (from request) => {request.credential_configuration_id}");

            string selectedDocType;

            if (string.IsNullOrEmpty(request.credential_configuration_id))
            {
                // ไม่ได้ระบุมา → fallback ได้เฉพาะกรณีมี config id เดียวใน list เท่านั้น (เช่น transcript)
                // ถ้ามีหลายตัว (เช่นใบขับขี่ mDL+SD-JWT) ต้องบังคับให้ wallet ระบุมาเสมอ ไม่งั้นไม่รู้ว่าจะออกใบไหน
                if (allowedDocTypes.Count == 1)
                {
                    selectedDocType = allowedDocTypes[0];
                }
                else
                {
                    return BadRequest(new
                    {
                        error = "invalid_credential_request",
                        error_description = "credential_configuration_id is required when multiple formats are available"
                    });
                }
            }
            else
            {
                // ตรวจว่า id ที่ wallet ขอมา อยู่ใน list ที่ authorize ไว้จริงไหม
                selectedDocType = allowedDocTypes.FirstOrDefault(d => d == request.credential_configuration_id);

                if (selectedDocType == null)
                {
                    return BadRequest(new
                    {
                        error = "invalid_credential_request",
                        error_description = $"credential_configuration_id '{request.credential_configuration_id}' is not authorized for this request"
                    });
                }
            }

            logger.Info($"selectedDocType => {selectedDocType}");

            string _credential = null;
            string _nonce = null;
            string issuerid = null;

            try
            {
                string jwt = proof;
                string[] parts = jwt.Split('.');
                if (parts.Length != 3)
                {
                    return BadRequest(new { error = "invalid_proof", error_description = "proof JWT is malformed" });
                }

                string headerJson = serv.Base64UrlDecodeToString(parts[0]);
                using JsonDocument doc = JsonDocument.Parse(headerJson);

                // C-03 (proof header hygiene): reject x5c — nothing in this issuer trusts a caller-
                // supplied certificate chain. "jwk" is allowed: for mso_mdoc issuance the wallet
                // conveys its separate P-256 device key this way (ISO 18013-5 requires ES256/P-256 for
                // device-key binding, which the wallet's Ed25519 did:key cannot provide). Note this
                // does NOT weaken proof signature verification — the signature below is still checked
                // exclusively against the did:key resolved from "kid", never against this "jwk".
                if (doc.RootElement.TryGetProperty("x5c", out _))
                {
                    return BadRequest(new { error = "invalid_proof", error_description = "x5c proof header is not supported" });
                }

                if (!doc.RootElement.TryGetProperty("kid", out JsonElement kidElement) || string.IsNullOrEmpty(kidElement.GetString()))
                {
                    return BadRequest(new { error = "invalid_proof", error_description = "kid header is required" });
                }
                string kid = kidElement.GetString();

                // Appendix F.1: alg MUST NOT be "none", and must be an algorithm the issuer actually
                // implements verification for. Ed25519 did:key (EdDSA) is the primary holder key type;
                // ES256 (P-256 did:key) is also supported for wallets whose key material is P-256-only
                // (e.g. hardware-backed/secure-enclave keys that can't produce Ed25519 signatures).
                string alg = doc.RootElement.TryGetProperty("alg", out JsonElement algElement) ? algElement.GetString() : null;
                bool algIsEdDsa = string.Equals(alg, "EdDSA", StringComparison.Ordinal);
                bool algIsEs256 = string.Equals(alg, "ES256", StringComparison.Ordinal);
                if (!algIsEdDsa && !algIsEs256)
                {
                    return BadRequest(new { error = "invalid_proof", error_description = "unsupported or missing proof alg (EdDSA or ES256 required)" });
                }

                // Appendix F.1: typ MUST be openid4vci-proof+jwt.
                string typ = doc.RootElement.TryGetProperty("typ", out JsonElement typElement) ? typElement.GetString() : null;
                if (!string.Equals(typ, "openid4vci-proof+jwt", StringComparison.Ordinal))
                {
                    return BadRequest(new { error = "invalid_proof", error_description = "typ must be openid4vci-proof+jwt" });
                }

                string payloadJson = serv.Base64UrlDecodeToString(parts[1]);
                using JsonDocument docPayload = JsonDocument.Parse(payloadJson);
                JsonElement root = docPayload.RootElement;

                // Appendix F.1: "iss" MUST NOT be present for a pre-authorized-code flow without a
                // client_id (this issuer never hands out a client_id to wallets).
                if (root.TryGetProperty("iss", out JsonElement issElement) && issElement.ValueKind != JsonValueKind.Null)
                {
                    return BadRequest(new { error = "invalid_proof", error_description = "iss must not be set" });
                }

                // Appendix F.1: "aud" MUST equal the credential issuer identifier exactly.
                string aud = root.TryGetProperty("aud", out JsonElement audElement) ? audElement.GetString() : null;
                if (string.IsNullOrEmpty(aud) || !string.Equals(aud, urlBase, StringComparison.Ordinal))
                {
                    return BadRequest(new { error = "invalid_proof", error_description = "aud does not match credential issuer identifier" });
                }

                long striat = 0;
                if (root.TryGetProperty("iat", out JsonElement iatElement) && iatElement.ValueKind != JsonValueKind.Null)
                {
                    striat = iatElement.ValueKind == JsonValueKind.String
                        ? Convert.ToInt64(iatElement.GetString())
                        : iatElement.GetInt64();
                }

                if (striat == 0 || !serv.IsValidNumericDate(striat))
                {
                    return BadRequest(new { error = "invalid_proof", error_description = "iat is missing, stale, or in the future" });
                }

                walletid = kid.Split('#')[0];
                // กลับมาใช้ did:key (_GetDID) — did:web ทำให้ wallet บางตัวมองไม่เห็น/resolve ไม่ได้
                // (GetDidWebId ยังอยู่เผื่อใช้ในอนาคต)
                issuerid = serv._GetDID(_env);

                // C-01: decode the wallet's did:key (from kid) and actually verify the proof JWT
                // signature against it. Previously *any* syntactically valid JWT was accepted — the
                // signature bytes were never checked, so anyone could forge a proof for any wallet.
                // Dispatch on "alg" — EdDSA (did:key z6Mk..., raw Ed25519 key) and ES256 (did:key
                // zDn..., compressed P-256 point) use entirely different key encodings and signature
                // algorithms, so accepting "ES256" above without branching here would mean the alg
                // check passes but the actual signature is never genuinely verified against it.
                bool sigOk;
                string proofVerifyError;
                if (algIsEdDsa)
                {
                    byte[] holderPublicKey = serv.DecodeEd25519DidKey(walletid);
                    if (holderPublicKey == null)
                    {
                        return BadRequest(new { error = "invalid_proof", error_description = "kid is not a valid Ed25519 did:key" });
                    }
                    sigOk = serv.VerifyEd25519Jws(jwt, holderPublicKey, out proofVerifyError);
                }
                else
                {
                    byte[] holderPublicKey = serv.DecodeP256DidKey(walletid);
                    if (holderPublicKey == null)
                    {
                        return BadRequest(new { error = "invalid_proof", error_description = "kid is not a valid P-256 did:key" });
                    }
                    sigOk = serv.VerifyES256Jws(jwt, holderPublicKey, out proofVerifyError);
                }

                if (!sigOk)
                {
                    logger.Warn($"proof JWT signature verification failed: {proofVerifyError}");
                    return BadRequest(new { error = "invalid_proof", error_description = "proof JWT signature verification failed" });
                }

                // C-04 / H-01: the proof's "nonce" claim must be a server-issued nonce (from /nonce or
                // /token's c_nonce) that hasn't expired or already been spent. Consumed here — after
                // signature verification, so an attacker without a valid holder signature can't burn
                // through nonces as a denial-of-service against the legitimate wallet — and before any
                // credential is generated, so a replayed proof (same nonce reused) is rejected
                // regardless of which credential_configuration_id it's replayed against.
                string proofNonce = root.TryGetProperty("nonce", out JsonElement nonceElement) ? nonceElement.GetString() : null;
                if (string.IsNullOrWhiteSpace(proofNonce))
                {
                    return BadRequest(new { error = "invalid_proof", error_description = "nonce is required" });
                }
                if (!dbServ.TryConsumeNonce(proofNonce))
                {
                    return BadRequest(new { error = "invalid_proof", error_description = "nonce is invalid, expired, or already used" });
                }

                // C-02: this specific (grant, credential_configuration_id) pair may be issued at most
                // once. The nonce check above already blocks literal proof replay; this blocks a
                // *fresh*, validly-signed, fresh-nonce request for a configuration this grant already
                // redeemed. Checked after the nonce is spent so a rejected duplicate doesn't leave the
                // nonce reusable.
                // The returned id also doubles as this credential's status list index (revocation) —
                // see VCService.BuildStatusClaim / BuildStatusListToken.
                int? issuedId = dbServ.TryMarkIssued(registerId, selectedDocType);
                if (issuedId == null)
                {
                    return BadRequest(new { error = "invalid_credential_request", error_description = "this credential configuration has already been issued for this grant" });
                }

                logger.Info($"selectedDocType => {selectedDocType}");

                // C-05 (partial): real ThaID profile captured at offer-creation time (null for
                // staff/password-issued offers, or offers predating this column) — only IDCard
                // generation below actually consumes it; every other doc type is untouched.
                var thaIdProfile = dbServ.GetRequestProfile(registerId);

                if (selectedDocType.EndsWith("dc+sd-jwt"))
                {
                    _credential = selectedDocType switch
                    {
                        "TranscriptCredential_dc+sd-jwt" => serv.GenerateTranscriptSdJwt(issuerid, walletid, _env, urlBase, issuedId.Value),
                        "BootCampCredential_dc+sd-jwt" => serv.GenerateBootCampSdJwt(issuerid, walletid, _env, urlBase, issuedId.Value),
                        "IDCard_dc+sd-jwt" => serv.GenerateIDCardSdJwt(issuerid, walletid, _env, urlBase, issuedId.Value, thaIdProfile),
                        "Iso18013DriversLicenseCredential_dc+sd-jwt" => serv.GenerateDriversLicenseSdJwt(issuerid, walletid, _env, urlBase, issuedId.Value),
                        _ => throw new Exception($"Unsupported credential type: {selectedDocType}")
                    };
                    _nonce = registerId;
                }
                else if (selectedDocType == "org.iso.18013.5.1.mDL")
                {
                    // H-08 (fixed): the device key MUST come from the wallet's own proof, never be
                    // null/fabricated. cryptographic_binding_methods_supported for this format is
                    // "cose_key" (Appendix A.2.2) — ISO 18013-5 requires an EC P-256 device key, which
                    // is why the wallet includes a "jwk" alongside "kid" in the proof header (the
                    // proof JWT itself is still Ed25519-signed and verified via "kid" above; "jwk" only
                    // conveys the separate device key to bind into the mdoc, it is not trusted for
                    // anything else).
                    if (!doc.RootElement.TryGetProperty("jwk", out JsonElement jwkElement))
                    {
                        return BadRequest(new { error = "invalid_proof", error_description = "jwk header (P-256 device key) is required for mso_mdoc" });
                    }

                    string kty = jwkElement.TryGetProperty("kty", out JsonElement ktyEl) ? ktyEl.GetString() : null;
                    string crv = jwkElement.TryGetProperty("crv", out JsonElement crvEl) ? crvEl.GetString() : null;
                    if (!string.Equals(kty, "EC", StringComparison.Ordinal) || !string.Equals(crv, "P-256", StringComparison.Ordinal))
                    {
                        return BadRequest(new { error = "invalid_proof", error_description = "jwk must be an EC P-256 key for mso_mdoc" });
                    }

                    byte[] deviceKeyX, deviceKeyY;
                    try
                    {
                        deviceKeyX = WebEncoders.Base64UrlDecode(jwkElement.GetProperty("x").GetString());
                        deviceKeyY = WebEncoders.Base64UrlDecode(jwkElement.GetProperty("y").GetString());
                    }
                    catch
                    {
                        return BadRequest(new { error = "invalid_proof", error_description = "jwk x/y are missing or malformed" });
                    }

                    if (deviceKeyX.Length != 32 || deviceKeyY.Length != 32)
                    {
                        return BadRequest(new { error = "invalid_proof", error_description = "jwk x/y must be 32-byte P-256 coordinates" });
                    }

                    _credential = serv.GenerateDriverLicenseMdoc(issuerid, walletid, _env, deviceKeyX, deviceKeyY);
                    _nonce = registerId;
                }
                else
                {
                    var data = selectedDocType switch
                    {
                        "TranscriptCredential_jwt_vc_json" => serv.GenerateTranscriptVC(issuerid, walletid),
                        "IDCardCredential_jwt_vc_json" => serv.GenerateIDCardVC(issuerid, walletid, thaIdProfile),
                        _ => throw new Exception($"Unsupported credential type: {selectedDocType}")
                    };

                    var jsonOptions = new JsonSerializerOptions
                    {
                        WriteIndented = false,
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                    };
                    string json = JsonSerializer.Serialize(data.Value, jsonOptions);

                    PemReader pemReaderPrivate = new PemReader(new StringReader(serv.GetKey(true, _env)));
                    Ed25519PrivateKeyParameters privateKeyEd25519 = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();
                    _credential = serv.GenerateJWTEd25519(json, issuerid, privateKeyEd25519);
                    _nonce = registerId;
                }

                vcFormat = selectedDocType == "org.iso.18013.5.1.mDL" ? "mso_mdoc"
                         : selectedDocType.EndsWith("dc+sd-jwt") ? "dc+sd-jwt"
                         : "jwt_vc_json";
                logger.Info($"format => {vcFormat}");
            }
            catch (Exception e)
            {
                // H-04: don't leak exception details (e.Message/InnerException) to callers.
                logger.Error(e, "Credential issuance failed");
                dbServ.SaveIssueVCLog(issuerid, walletid, _nonce, _credential, vcFormat, "failed");
                return BadRequest(new { error = "credential_request_denied", error_description = "the credential request could not be processed" });
            }

            // H-03: final Credential Response shape — a "credentials" array of {credential}, no
            // legacy top-level format/c_nonce/status/notification_id fields.
            var res = new
            {
                credentials = new[] { new { credential = _credential } }
            };

            dbServ.SaveIssueVCLog(issuerid, walletid, _nonce, _credential, vcFormat, "success");
            return Ok(res);
        }

        // M-04: a full duplicate, pre-fix copy of this method used to be kept here as a commented-out
        // block ("in case we need to revert"). Deleted — that's what version control (git history) is
        // for, and keeping a second near-identical implementation around (even inert) made it easy to
        // accidentally edit the wrong copy.
    }
}
