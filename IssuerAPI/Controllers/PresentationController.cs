using IssuerAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using NLog;
using IssuerAPI.Models;
using System.Security.Claims;
using System.Text;

namespace IssuerAPI.Controllers
{
    // OID4VP: this issuer acting as a (lightweight) Verifier of the citizen's PID VC before it will
    // issue a Standard VC — see Sequence Diagram - P2 v.1.4.md, "Initiation and OID4VP Authentication"
    // + "PID VC Verification and Trust Validation" (steps 1-18). Deliberately a separate controller
    // from CredentialOfferController/CredentialController (which implement the *issuance* side, OID4VCI)
    // — this is a different protocol (OID4VP) and a different role (verifier, not issuer), even though
    // both run inside the same project per instruction.
    //
    // Scope note: this is a from-scratch MVP, not a general-purpose verifier. It only knows how to
    // verify one specific credential shape — this issuer's own dc+sd-jwt PID VC format (see
    // VCService.GenerateIDCardSdJwt) — and only accepts did:web-issued PID VCs (the diagram's DID
    // Resolver step assumes did:web). Trust Registry is a config-driven allowlist, not a real service
    // integration (see appsettings.json "Verifier:TrustedPidIssuers").
    [ApiController]
    [Tags("Presentation (OID4VP)")]
    [Route("[controller]")]
    public class PresentationController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly Oid4VciOptions _options;
        private readonly IWebHostEnvironment _env;
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public PresentationController(IConfiguration config, IOptions<Oid4VciOptions> options, IWebHostEnvironment env)
        {
            _config = config;
            _options = options.Value;
            _env = env;
        }

        // Step 3: Issuer -> Holder Wallet, "request authentication (via OID4VP to present PID VC)".
        // Called by CredentialOfferController's flow (or directly) once the citizen has picked a
        // non-PID document type — returns a scannable QR (cross-device) that points the wallet at the
        // authorization request. Mirrors CredentialOfferController.GenerateCredentialOfferQr's
        // by-reference pattern (request_uri instead of embedding the whole request in the QR itself,
        // since dcql_query can get long).
        [Authorize]
        [HttpPost("/presentation-request")]
        public IActionResult CreatePresentationRequest()
        {
            Response.Headers["Cache-Control"] = "no-store";

            var registerId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(registerId))
            {
                return Unauthorized(new { error = "unauthorized" });
            }

            VCService serv = new VCService();
            DBService dbServ = new DBService();

            string state = serv.GetGUID();
            string nonce = serv.GetGUID();
            dbServ.CreatePresentationRequest(state, nonce, registerId);

            var baseUrl = IssuerController.GetBaseUrl(HttpContext, _options);
            string verifierId = serv._GetDID(_env); // same did:key identity this issuer issues credentials under (did:web reverted — wallets couldn't resolve it)

            string requestUri = $"{baseUrl}/presentation-request/{state}";
            string authorizeUrl = "openid4vp://?" +
                $"client_id={Uri.EscapeDataString(verifierId)}" +
                $"&request_uri={Uri.EscapeDataString(requestUri)}";

            string qrCode = serv.GenerateQrCodeBase64(authorizeUrl);

            return Ok(new
            {
                authorize_uri = authorizeUrl,
                request_uri = requestUri,
                qr_text = qrCode,
                state,
                expires_in = (int)DBService.PresentationRequestTtl.TotalSeconds
            });
        }

        // Step 3 (resolution): wallet fetches the actual authorization request object by reference.
        // DCQL (Digital Credentials Query Language) asks for this issuer's own PID VC shape/vct — see
        // class-level scope note. response_mode "direct_post" per OID4VP: the wallet POSTs vp_token
        // straight to response_uri below rather than a browser redirect, since there's no user agent
        // continuity to rely on in the cross-device QR case.
        [AllowAnonymous]
        [HttpGet("/presentation-request/{state}")]
        public IActionResult GetPresentationRequest(string state)
        {
            Response.Headers["Cache-Control"] = "no-store";

            DBService dbServ = new DBService();
            var item = dbServ.GetPresentationRequest(state);
            if (item == null || item.Status != "pending" ||
                (item.CreateDate.HasValue && DateTime.UtcNow - item.CreateDate.Value > DBService.PresentationRequestTtl))
            {
                return NotFound(new { error = "invalid_request", error_description = "presentation request not found, expired, or already used" });
            }

            var baseUrl = IssuerController.GetBaseUrl(HttpContext, _options);
            VCService serv = new VCService();
            string verifierId = serv._GetDID(_env);
            string expectedVctSuffix = _config["Verifier:ExpectedPidVct"] ?? "/credentials/IDCard";

            var response = new
            {
                response_type = "vp_token",
                client_id = verifierId,
                response_mode = "direct_post",
                response_uri = $"{baseUrl}/presentation-response",
                nonce = item.Nonce,
                state = item.State,
                dcql_query = new
                {
                    credentials = new[]
                    {
                        new
                        {
                            id = "pid",
                            format = "dc+sd-jwt",
                            meta = new { vct_values = new[] { $"{baseUrl}{expectedVctSuffix}" } },
                            claims = new[] { new { path = new[] { "id_number" } } }
                        }
                    }
                }
            };

            return Ok(response);
        }

        // Step 7: Holder Wallet -> Issuer, "Submit VP". Runs the full PID VC Verification and Trust
        // Validation chain (steps 8-15) before returning success/failure. Own frontend polls
        // GetPresentationStatus below to find out the result (the wallet gets an immediate HTTP
        // response here, but that's a machine-to-machine call — the citizen's own browser/session
        // isn't part of this request).
        [AllowAnonymous]
        [HttpPost("/presentation-response")]
        public async Task<IActionResult> PresentationResponse([FromForm] string vp_token, [FromForm] string state)
        {
            Response.Headers["Cache-Control"] = "no-store";

            DBService dbServ = new DBService();
            var item = dbServ.GetPresentationRequest(state);
            if (item == null || item.Status != "pending")
            {
                return BadRequest(new { error = "invalid_request", error_description = "state is invalid, expired, or already used" });
            }
            if (item.CreateDate.HasValue && DateTime.UtcNow - item.CreateDate.Value > DBService.PresentationRequestTtl)
            {
                dbServ.TryMarkPresentationFailed(state, "expired");
                return BadRequest(new { error = "invalid_request", error_description = "presentation request expired" });
            }

            var (ok, holderDid, pidIssuerDid, failReason) = await VerifyPresentation(vp_token, item.Nonce);

            if (!ok)
            {
                dbServ.TryMarkPresentationFailed(state, failReason);
                // Step 16-17: record verification failure event (Audit Trail) + notify failure.
                dbServ.SaveIssueVCLog(pidIssuerDid, holderDid, state, null, "PID_Presentation", "failed");
                logger.Warn($"presentation verification failed, state={state}: {failReason}");
                return BadRequest(new { error = "invalid_request", error_description = failReason });
            }

            string verifiedPid = _lastVerifiedPid; // set by VerifyPresentation — see note there
            dbServ.TryMarkPresentationVerified(state, verifiedPid);
            // Step 27-equivalent for this sub-flow: record successful verification event.
            dbServ.SaveIssueVCLog(pidIssuerDid, holderDid, state, null, "PID_Presentation", "success");

            return Ok(new { });
        }

        // Step 18 (success path) / our own frontend: poll this instead of the wallet callback above to
        // find out when a citizen's browser session should move on to the actual Standard VC offer.
        // Mirrors CredentialOfferController.OfferStatus's polling pattern.
        [Authorize]
        [HttpGet("/presentation-request/{state}/status")]
        public IActionResult GetPresentationStatus(string state)
        {
            Response.Headers["Cache-Control"] = "no-store";

            var registerId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(registerId))
            {
                return Unauthorized(new { error = "unauthorized" });
            }

            DBService dbServ = new DBService();
            var item = dbServ.GetPresentationRequest(state);
            if (item == null || item.RegisterId != registerId)
            {
                return NotFound(new { error = "invalid_request" });
            }

            return Ok(new
            {
                status = item.Status, // pending | verified | failed
                failure_reason = item.FailureReason
            });
        }

        // Set as a side-channel by VerifyPresentation because C# doesn't have a clean way to bundle a
        // 5th "out" value onto an async tuple return without a dedicated result type — pragmatic choice
        // for this MVP, not a concurrency-safe pattern (fine here: PresentationResponse is the only
        // caller, and it reads this immediately after awaiting VerifyPresentation on the same request).
        private string _lastVerifiedPid;

        // Steps 8-15: verify VP Proof of Possession, resolve+verify the PID VC's issuer signature,
        // check Trust Registry (allowlist), check VC Status Registry (revocation). Returns
        // (ok, holderDid-for-logging, pidIssuerDid-for-logging, failureReason).
        private async Task<(bool ok, string holderDid, string pidIssuerDid, string failReason)> VerifyPresentation(string vpToken, string expectedNonce)
        {
            var (vcJwt, disclosures, kbJwt, splitError) = VerifierService.SplitVpToken(vpToken);
            if (splitError != null)
            {
                return (false, null, null, splitError);
            }

            // ── Parse the issuer-signed PID VC itself ──────────────────────────────────
            string[] vcParts = vcJwt.Split('.');
            JObject vcPayload;
            try
            {
                string vcPayloadJson = Encoding.UTF8.GetString(Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(vcParts[1]));
                vcPayload = JObject.Parse(vcPayloadJson);
            }
            catch (Exception ex)
            {
                return (false, null, null, $"could not parse presented credential: {ex.Message}");
            }

            string pidIssuerDid = vcPayload["iss"]?.ToString();
            string vct = vcPayload["vct"]?.ToString();
            string holderKid = vcPayload["cnf"]?["kid"]?.ToString();

            string expectedVctSuffix = _config["Verifier:ExpectedPidVct"] ?? "/credentials/IDCard";
            if (string.IsNullOrEmpty(vct) || !vct.EndsWith(expectedVctSuffix, StringComparison.Ordinal))
            {
                return (false, holderKid, pidIssuerDid, "presented credential is not a PID VC");
            }

            // ── Step 9-10: resolve PID Issuer DID (did:web) ────────────────────────────
            var verifierSvc = new VerifierService();
            var (issuerKey, issuerKeyType, resolveError) = await verifierSvc.ResolveDidWebKeyAsync(pidIssuerDid);
            if (resolveError != null)
            {
                return (false, holderKid, pidIssuerDid, $"could not resolve PID issuer DID: {resolveError}");
            }

            // ── Step 11: verify PID VC format and signature ────────────────────────────
            VCService serv = new VCService();
            bool vcSigOk;
            string vcSigErr;
            if (issuerKeyType == "Ed25519")
                vcSigOk = serv.VerifyEd25519Jws(vcJwt, issuerKey, out vcSigErr);
            else
                vcSigOk = serv.VerifyES256Jws(vcJwt, issuerKey, out vcSigErr);
            if (!vcSigOk)
            {
                return (false, holderKid, pidIssuerDid, $"PID VC signature verification failed: {vcSigErr}");
            }

            // Confirm every disclosed claim actually belongs to this credential as originally signed
            // (its hash appears in _sd), not something appended after the fact.
            var sdHashes = vcPayload["_sd"]?.ToObject<List<string>>() ?? new List<string>();
            foreach (var disclosure in disclosures)
            {
                if (!VerifierService.DisclosureMatchesSdArray(disclosure, sdHashes))
                {
                    return (false, holderKid, pidIssuerDid, "a disclosed claim does not match the credential's _sd digests");
                }
            }

            // ── Step 12-13: Trust Registry (allowlist) ─────────────────────────────────
            var trustedIssuers = _config.GetSection("Verifier:TrustedPidIssuers").Get<string[]>() ?? Array.Empty<string>();
            if (!trustedIssuers.Contains(pidIssuerDid, StringComparer.Ordinal))
            {
                return (false, holderKid, pidIssuerDid, "PID issuer is not in the trusted registry");
            }

            // ── Step 14-15: VC Status Registry (revocation) ────────────────────────────
            var statusList = vcPayload["status"]?["status_list"];
            if (statusList != null)
            {
                string statusUri = statusList["uri"]?.ToString();
                int statusIdx = statusList["idx"]?.ToObject<int>() ?? -1;
                var (revOk, revoked, revError) = await verifierSvc.CheckRevocationAsync(statusUri, statusIdx);
                if (!revOk)
                {
                    return (false, holderKid, pidIssuerDid, $"could not check revocation status: {revError}");
                }
                if (revoked)
                {
                    return (false, holderKid, pidIssuerDid, "PID VC has been revoked");
                }
            }

            // ── Step 8: verify VP Proof of Possession (Key Binding JWT) ────────────────
            var (cnfKey, cnfKeyType, cnfError) = VerifierService.JwkToRawKey(vcPayload["cnf"]?["jwk"] as JObject);
            if (cnfError != null)
            {
                return (false, holderKid, pidIssuerDid, $"could not read holder binding key: {cnfError}");
            }

            string[] kbParts = kbJwt.Split('.');
            JObject kbPayload;
            try
            {
                string kbPayloadJson = Encoding.UTF8.GetString(Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(kbParts[1]));
                kbPayload = JObject.Parse(kbPayloadJson);
            }
            catch (Exception ex)
            {
                return (false, holderKid, pidIssuerDid, $"could not parse Key Binding JWT: {ex.Message}");
            }

            string verifierId = serv._GetDID(_env);

            string kbAud = kbPayload["aud"]?.ToString();
            string kbNonce = kbPayload["nonce"]?.ToString();
            if (!string.Equals(kbAud, verifierId, StringComparison.Ordinal))
            {
                return (false, holderKid, pidIssuerDid, "Key Binding JWT aud does not match this verifier");
            }
            if (!string.Equals(kbNonce, expectedNonce, StringComparison.Ordinal))
            {
                return (false, holderKid, pidIssuerDid, "Key Binding JWT nonce does not match the issued presentation request");
            }

            bool kbSigOk;
            string kbSigErr;
            if (cnfKeyType == "Ed25519")
                kbSigOk = serv.VerifyEd25519Jws(kbJwt, cnfKey, out kbSigErr);
            else
                kbSigOk = serv.VerifyES256Jws(kbJwt, cnfKey, out kbSigErr);
            if (!kbSigOk)
            {
                return (false, holderKid, pidIssuerDid, $"Key Binding JWT (holder PoP) signature verification failed: {kbSigErr}");
            }

            // ── Extract the disclosed PID for the caller's own record-keeping ─────────
            _lastVerifiedPid = ExtractDisclosedClaim(disclosures, "id_number");

            return (true, holderKid, pidIssuerDid, null);
        }

        private static string ExtractDisclosedClaim(List<string> disclosures, string claimName)
        {
            foreach (var d in disclosures)
            {
                try
                {
                    string json = Encoding.UTF8.GetString(Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(d));
                    var arr = JArray.Parse(json);
                    if (arr.Count == 3 && arr[1].ToString() == claimName)
                    {
                        return arr[2].ToString();
                    }
                }
                catch
                {
                    // malformed disclosure — already would have failed the _sd hash check above, ignore here
                }
            }
            return null;
        }
    }
}
