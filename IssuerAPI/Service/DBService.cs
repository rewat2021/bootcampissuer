using IssuerAPI.Databases;
using IssuerAPI.Models;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace IssuerAPI.Service
{
    public class DBService
    {
        // H-10 / C-04: pre-authorized codes are meant to be redeemed immediately by the wallet right
        // after the offer is scanned — 2 minutes is enough slack for scanning, not an indefinitely-
        // valid code. Public so CredentialOfferController can report an accurate countdown/expiry to
        // the QR page instead of a duplicated magic number.
        public static readonly TimeSpan PreAuthorizedCodeTtl = TimeSpan.FromMinutes(2);

        // C-04 / H-01: how long a server-issued nonce (from /nonce or /token's c_nonce) remains
        // redeemable. Public so TokenController/IssuerController can report an accurate
        // c_nonce_expires_in instead of a made-up number.
        public static readonly TimeSpan NonceTtl = TimeSpan.FromMinutes(5);

        // Issues a fresh, random, single-use nonce and persists it so TryConsumeNonce can later
        // verify a proof JWT's "nonce" claim is one we actually handed out, unexpired, and not
        // already spent. Used by both POST /nonce and the c_nonce returned from /token.
        public string IssueNonce()
        {
            string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

            using (IssuerDbContext context = new IssuerDbContext())
            {
                context.Dbnonces.Add(new Dbnonce
                {
                    Nonce = nonce,
                    ExpiresAt = DateTime.UtcNow.Add(NonceTtl),
                    Used = false,
                    CreatedAt = DateTime.UtcNow
                });
                context.SaveChanges();
            }

            return nonce;
        }

        // Atomically marks a nonce as used via a single conditional UPDATE, the same pattern as
        // ConsumePreAuthorizedCode — two concurrent /credential requests racing on the same nonce
        // can't both succeed. Returns false if the nonce doesn't exist, is expired, or was already
        // used, all of which mean the proof presenting it must be rejected as invalid/replayed.
        public bool TryConsumeNonce(string nonce)
        {
            if (string.IsNullOrWhiteSpace(nonce)) return false;

            using (IssuerDbContext context = new IssuerDbContext())
            {
                int affected = context.Dbnonces
                    .Where(n => n.Nonce == nonce && !n.Used && n.ExpiresAt > DateTime.UtcNow)
                    .ExecuteUpdate(setters => setters.SetProperty(n => n.Used, true));

                return affected > 0;
            }
        }

        // C-02: track which (grant, credential_configuration_id) pairs have already been issued, so
        // one access token cannot be used to obtain the same credential configuration more than once
        // (a driving-licence grant authorizing both org.iso.18013.5.1.mDL and the dc+sd-jwt format can
        // still yield one of each — they're different configuration IDs). Relies on the dbissuedcredential
        // table's own unique constraint on (register_id, credential_configuration_id) for atomicity —
        // two concurrent requests for the same pair can't both win, no read-then-write race window.
        //
        // Returns the new row's Id on success (null on duplicate/failure) — this Id doubles as the
        // credential's status list index (see VCService.BuildStatusClaim/BuildStatusListToken), so the
        // caller has everything it needs to embed a "status" claim in the credential it's about to
        // generate without a second round trip.
        public int? TryMarkIssued(string registerId, string credentialConfigurationId)
        {
            if (string.IsNullOrWhiteSpace(registerId) || string.IsNullOrWhiteSpace(credentialConfigurationId))
                return null;

            using (IssuerDbContext context = new IssuerDbContext())
            {
                var row = new Dbissuedcredential
                {
                    RegisterId = registerId,
                    CredentialConfigurationId = credentialConfigurationId,
                    IssuedAt = DateTime.UtcNow
                };
                context.Dbissuedcredentials.Add(row);

                try
                {
                    context.SaveChanges();
                    return row.Id;
                }
                catch (DbUpdateException)
                {
                    // Unique constraint violation: this pair was already issued, or a concurrent
                    // request just won the race.
                    return null;
                }
            }
        }

        // Flips a previously-issued credential to revoked. Does NOT delete the dbissuedcredential row
        // — that row is the audit trail and (via its Id) the status list index a verifier may already
        // be relying on; deleting it would just orphan the index. Revocation only takes effect for
        // verifiers once they actually re-fetch /status-list/1, same as any status list scheme.
        public bool RevokeCredential(int id)
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                int affected = context.Dbissuedcredentials
                    .Where(c => c.Id == id && !c.Revoked)
                    .ExecuteUpdate(setters => setters
                        .SetProperty(c => c.Revoked, true)
                        .SetProperty(c => c.RevokedAt, DateTime.UtcNow));
                return affected > 0;
            }
        }

        // Backs VCService.BuildStatusListToken: every issued credential's Id (== its status list
        // index) and whether it's currently revoked. Ordered by Id so the caller can build a
        // contiguous bitstring straightforwardly.
        public List<(int Id, bool Revoked)> GetStatusListEntries()
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                return context.Dbissuedcredentials
                    .OrderBy(c => c.Id)
                    .Select(c => new { c.Id, c.Revoked })
                    .AsEnumerable()
                    .Select(c => (c.Id, c.Revoked))
                    .ToList();
            }
        }

        // The credential_configuration_id that represents this citizen's PID (Person Identification
        // Data) VC — the Thai national ID card. Every other document (transcript, driver license,
        // ...) requires the holder to already have this in their wallet before it can be requested.
        public const string PidCredentialConfigurationId = "IDCard_dc+sd-jwt";

        // Simple DB-side check: has *this citizen* (identified by Dbrequest.Subject — the persistent
        // ThaID PID / staff user id, not the per-offer RegisterId, which is a fresh GUID every time a
        // new QR is generated) ever actually completed issuance of a PID VC? Joins
        // Dbissuedcredentials (proof a credential was actually issued, not just offered) back to
        // Dbrequests to resolve which citizen each RegisterId belongs to.
        // Note: this only proves the issuer handed out a PID VC at some point — it does not prove the
        // wallet still holds it (that would require an OID4VP presentation check instead).
        public bool HasBeenIssuedPidVc(string subject)
        {
            if (string.IsNullOrWhiteSpace(subject))
                return false;

            try
            {
                using (IssuerDbContext context = new IssuerDbContext())
                {
                    bool found = (from ic in context.Dbissuedcredentials
                                  join r in context.Dbrequests on ic.RegisterId equals r.RegisterId
                                  where r.Subject == subject
                                        && ic.CredentialConfigurationId == PidCredentialConfigurationId
                                  select ic.Id).Any();

                    if (!found)
                    {
                        // Diagnostic only, no behavior change: dump which subjects actually have a PID
                        // VC on record so a mismatch (e.g. different login flow producing a different
                        // NameIdentifier for what should be the same citizen) is visible in logs
                        // instead of just "not found" with no way to tell why.
                        var pidHolders = (from ic in context.Dbissuedcredentials
                                           join r in context.Dbrequests on ic.RegisterId equals r.RegisterId
                                           where ic.CredentialConfigurationId == PidCredentialConfigurationId
                                           select new { r.RegisterId, r.Subject }).ToList();

                        string dump = pidHolders.Count == 0
                            ? "(no PID VC has ever been issued in this DB)"
                            : string.Join(", ", pidHolders.Select(h => $"registerId={h.RegisterId} subject={h.Subject}"));

                        NLog.LogManager.GetCurrentClassLogger().Info(
                            $"HasBeenIssuedPidVc: no match for subject=\"{subject}\". Existing PID VC records: {dump}");
                    }

                    return found;
                }
            }
            catch (Exception ex)
            {
                // Fail closed: if this check can't be evaluated (e.g. schema drift — Dbrequests.Subject
                // or the dbissuedcredential table missing/out of sync on this DB), treat the citizen as
                // not having a PID VC yet rather than silently letting the PID-first requirement lapse.
                // Logged so a broken query shows up as "everyone stuck on PID VC" in the logs, not a
                // raw 500 with no explanation.
                NLog.LogManager.GetCurrentClassLogger().Warn(ex, "HasBeenIssuedPidVc: query failed, failing closed (treating as no PID VC)");
                return false;
            }
        }

        // Cross-device QR flow: lets the QR page poll whether the wallet has actually finished
        // issuance for the specific offer it's showing (not just "has this citizen ever gotten
        // anything" — that's HasBeenIssuedPidVc above). Scoped to the caller's own subject so one
        // signed-in user can't poll another user's offer status by guessing/observing a registerId.
        public bool HasCredentialBeenIssuedForOffer(string registerId, string subject)
        {
            if (string.IsNullOrWhiteSpace(registerId) || string.IsNullOrWhiteSpace(subject))
                return false;

            try
            {
                using (IssuerDbContext context = new IssuerDbContext())
                {
                    bool belongsToSubject = context.Dbrequests
                        .Any(r => r.RegisterId == registerId && r.Subject == subject);
                    if (!belongsToSubject)
                        return false;

                    return context.Dbissuedcredentials.Any(ic => ic.RegisterId == registerId);
                }
            }
            catch (Exception ex)
            {
                NLog.LogManager.GetCurrentClassLogger().Warn(ex, "HasCredentialBeenIssuedForOffer: query failed");
                return false;
            }
        }

        public AccessCode getPreAuthorizedCode(string pre_authorized_code, out string registerId)
        {
            AccessCode result = new AccessCode();
            registerId = null;

            if (string.IsNullOrEmpty(pre_authorized_code)) return result;

            // M-01: pre_authorized_code is attacker-controlled input straight off the wire (the Token
            // Request). Previously this split on '.' and indexed tokenArr[0]/[1] immediately — a code
            // with no '.' (or only one) threw an unhandled IndexOutOfRangeException here, and this
            // method is called from TokenController *before* its try/catch block, so the exception
            // wasn't caught anywhere and surfaced as a raw unhandled-exception response. Any malformed
            // input now just falls through to the same empty AccessCode the caller already treats as
            // invalid_grant — no exception, no internals leaked.
            try
            {
                var tokenArr = pre_authorized_code.Split('.');
                if (tokenArr.Length != 3)
                {
                    return result;
                }

                string Payload = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(tokenArr[1]));
                AuthorizedCode model = System.Text.Json.JsonSerializer.Deserialize<AuthorizedCode>(Payload);
                if (model == null || string.IsNullOrEmpty(model.Sub))
                {
                    return result;
                }

                string id = GetRegisterId(model.Sub);
                if (id == null)
                {
                    return result;
                }

                using (IssuerDbContext context = new IssuerDbContext())
                {
                    var item = context.Dbrequests.Where(i => i.RegisterId.Equals(id)).FirstOrDefault();
                    if (item != null)
                    {
                        // C-04: item.PreAuthorizedCode is nulled out by ConsumePreAuthorizedCode once the
                        // code has been redeemed at /token — treat a null/blank stored code as "already
                        // used", regardless of what code string the caller presents.
                        bool alreadyConsumed = string.IsNullOrEmpty(item.PreAuthorizedCode);
                        bool expired = item.CreateDate.HasValue && DateTime.UtcNow - item.CreateDate.Value > PreAuthorizedCodeTtl;

                        if (!alreadyConsumed && !expired)
                        {
                            result.authoriseCode = item.PreAuthorizedCode;
                        }

                        result.C_Nonce = model.Sub;
                        result.RegisterId = id;
                        result.CredentialType = item.CredentialId;
                    }
                }

                registerId = id;
                return result;
            }
            catch (Exception)
            {
                // Malformed base64url, invalid JSON, wrong payload shape, etc. — same treatment as
                // "not found": caller rejects with invalid_grant.
                registerId = null;
                return new AccessCode();
            }
        }

        // C-04: atomically mark a pre-authorized code as consumed. Uses a single conditional
        // UPDATE (ExecuteUpdate) keyed on RegisterId + the exact code value still being present, so
        // two concurrent /token requests racing on the same code can't both succeed — only the first
        // UPDATE actually matches a row and returns affected-rows > 0.
        public bool ConsumePreAuthorizedCode(string registerId, string expectedCode)
        {
            if (string.IsNullOrEmpty(registerId) || string.IsNullOrEmpty(expectedCode)) return false;

            using (IssuerDbContext context = new IssuerDbContext())
            {
                int affected = context.Dbrequests
                    .Where(i => i.RegisterId == registerId && i.PreAuthorizedCode == expectedCode)
                    .ExecuteUpdate(setters => setters.SetProperty(i => i.PreAuthorizedCode, (string)null));

                return affected > 0;
            }
        }


        // tx_code (OID4VCI pre-authorized_code flow PIN) — companion secret to the pre-authorized_code
        // itself, so possessing the QR image/link alone isn't sufficient to redeem it (audit finding:
        // "QR/pre-authorized-code replay is an explicit threat" — tx_code is the protocol's documented
        // mitigation). Only wired up for cross-device (QR) offers — see CredentialOfferController.
        // GenerateCredentialOfferQr — same-device (RedirectToWallet) skips this since the wallet
        // receives the offer via direct in-app redirect, never a scannable/interceptable QR image.
        private static string HashTxCode(string plainCode)
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(plainCode));
            return Convert.ToHexString(hash); // uppercase hex, fixed 64 chars for SHA-256
        }

        // 6-digit numeric PIN — matches OID4VCI's tx_code "input_mode": "numeric" example and is short
        // enough to type on a phone keyboard without being trivially guessable within a 2-minute TTL.
        public static string GenerateTxCode()
        {
            return RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        }

        public void SetTxCode(string registerId, string plainCode)
        {
            if (string.IsNullOrEmpty(registerId) || string.IsNullOrEmpty(plainCode)) return;

            using (IssuerDbContext context = new IssuerDbContext())
            {
                context.Dbrequests
                    .Where(i => i.RegisterId == registerId)
                    .ExecuteUpdate(setters => setters.SetProperty(i => i.TxCodeHash, HashTxCode(plainCode)));
            }
        }

        // Returns true if the code is correct OR if this offer never had a tx_code set in the first
        // place (same-device offers, or offers created before this feature existed) — false only means
        // "a tx_code was required for this offer and the supplied one didn't match".
        public bool VerifyTxCode(string registerId, string suppliedCode)
        {
            if (string.IsNullOrEmpty(registerId)) return false;

            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.FirstOrDefault(i => i.RegisterId.Equals(registerId));
                if (item == null) return false;
                if (string.IsNullOrEmpty(item.TxCodeHash)) return true; // no PIN required for this offer

                if (string.IsNullOrEmpty(suppliedCode)) return false;
                return string.Equals(item.TxCodeHash, HashTxCode(suppliedCode), StringComparison.Ordinal);
            }
        }

        public bool HasTxCode(string registerId)
        {
            if (string.IsNullOrEmpty(registerId)) return false;

            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.FirstOrDefault(i => i.RegisterId.Equals(registerId));
                return !string.IsNullOrEmpty(item?.TxCodeHash);
            }
        }

        // How long an OID4VP presentation request (PresentationController) stays redeemable — same
        // rationale/value as PreAuthorizedCodeTtl: long enough to scan/consent, not indefinite.
        public static readonly TimeSpan PresentationRequestTtl = TimeSpan.FromMinutes(2);

        public void CreatePresentationRequest(string state, string nonce, string registerId)
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                context.Dbpresentationrequests.Add(new Dbpresentationrequest
                {
                    State = state,
                    Nonce = nonce,
                    RegisterId = registerId,
                    Status = "pending",
                    CreateDate = DateTime.UtcNow
                });
                context.SaveChanges();
            }
        }

        public Dbpresentationrequest GetPresentationRequest(string state)
        {
            if (string.IsNullOrEmpty(state)) return null;

            using (IssuerDbContext context = new IssuerDbContext())
            {
                return context.Dbpresentationrequests.FirstOrDefault(r => r.State == state);
            }
        }

        // Atomically flips a still-pending request to verified/failed — mirrors TryConsumeNonce's
        // "only the first caller wins" pattern (ExecuteUpdate's WHERE re-checks Status server-side) so
        // a request can't be marked twice, e.g. by a retried/duplicated presentation response.
        public bool TryMarkPresentationVerified(string state, string verifiedPid)
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                int affected = context.Dbpresentationrequests
                    .Where(r => r.State == state && r.Status == "pending")
                    .ExecuteUpdate(setters => setters
                        .SetProperty(r => r.Status, "verified")
                        .SetProperty(r => r.VerifiedPid, verifiedPid)
                        .SetProperty(r => r.VerifiedAt, DateTime.UtcNow));
                return affected > 0;
            }
        }

        public bool TryMarkPresentationFailed(string state, string reason)
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                int affected = context.Dbpresentationrequests
                    .Where(r => r.State == state && r.Status == "pending")
                    .ExecuteUpdate(setters => setters
                        .SetProperty(r => r.Status, "failed")
                        .SetProperty(r => r.FailureReason, reason)
                        .SetProperty(r => r.VerifiedAt, DateTime.UtcNow));
                return affected > 0;
            }
        }

        public AccessCode getPreAuthorizedByRegisID(string registerId)
        {
            AccessCode result = new AccessCode();

            if (string.IsNullOrEmpty(registerId)) return result;

            string id = registerId;
            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.Where(i => i.RegisterId.Equals(id)).FirstOrDefault();
                if (item != null)
                {
                    // H-10: this backs GET /openid4vc/credentialOffer (offer-by-reference), which
                    // anyone holding the offer's guid can poll repeatedly and unauthenticated. Previously
                    // it returned item.PreAuthorizedCode unconditionally, forever — including after the
                    // code had already been consumed at /token (still non-null-looking to a caller that
                    // doesn't know it was nulled... actually it IS nulled by ConsumePreAuthorizedCode, so
                    // consumed codes already came back empty) but with NO expiry check at all, so a
                    // TTL-expired-but-never-redeemed code was still handed out indefinitely. Apply the
                    // exact same consumed/expired policy getPreAuthorizedCode enforces at /token, so the
                    // offer resolution endpoint can't outlive the code it's resolving.
                    bool alreadyConsumed = string.IsNullOrEmpty(item.PreAuthorizedCode);
                    bool expired = item.CreateDate.HasValue && DateTime.UtcNow - item.CreateDate.Value > PreAuthorizedCodeTtl;

                    if (!alreadyConsumed && !expired)
                    {
                        result.authoriseCode = item.PreAuthorizedCode;
                    }

                    result.RegisterId = id;
                }
            }

            return result;
        }

        public string GetRegisterId(string credentialId)
        {
            string result = null;
            using (IssuerDbContext context = new IssuerDbContext())
            {
                var items = context.Dbrequests.Where(i => i.RegisterId.Equals(credentialId)).FirstOrDefault();

                if (items != null)
                {
                    result = items.RegisterId;
                }

            }
            return result;
        }

        public List<string> GetDocumentTypes(string registerId)
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.FirstOrDefault(i => i.RegisterId.Equals(registerId));

                if (item == null || string.IsNullOrEmpty(item.CredentialId))
                    return new List<string>();

                try
                {
                    return Newtonsoft.Json.JsonConvert.DeserializeObject<List<string>>(item.CredentialId)
                           ?? new List<string>();
                }
                catch (Newtonsoft.Json.JsonException)
                {
                    // เผื่อกรณี CredentialId เก่าที่เคยเก็บเป็น plain string เดี่ยว (ไม่ใช่ JSON array)
                    // ก่อนที่จะปรับ schema มาเป็น List<string> — กัน exception ตอน migrate ข้อมูลเก่า
                    return new List<string> { item.CredentialId };
                }
            }
        }

        //public void SaveRequestCredential(string guid, List<string> credentialConfigurationIds, string preAuthorizedCode)
        //{
        //    using (IssuerDbContext context = new IssuerDbContext())
        //    {
        //        var item = context.Dbrequests.Where(i => i.RegisterId.Equals(guid)).FirstOrDefault();
        //        if (item == null)
        //        {
        //            item = new Dbrequest();
        //            item.RegisterId = guid;
        //            item.PreAuthorizedCode = preAuthorizedCode;
        //            item.CredentialId = requestvc;
        //            item.CreateDate = DateTime.UtcNow;

        //            context.Dbrequests.Add(item);
        //            context.SaveChanges();
        //        }
        //    }
        //}

        // C-05: subject is the authenticated caller's identifier (User.FindFirstValue(ClaimTypes.
        // NameIdentifier) — dbusers.Id for staff/password login, ThaID citizen PID otherwise), passed
        // in by CredentialOfferController now that offer creation requires [Authorize]. Optional
        // parameter (defaults null) so existing internal callers that don't have a principal in scope
        // still compile; every controller call site should pass it going forward.
        // C-05 (partial): optional real ThaID profile (title/name/birthdate/gender from the id_token,
        // read back out of the ClaimsPrincipal by CredentialOfferController) persisted alongside the
        // request so GenerateIDCardVC/GenerateIDCardSdJwt can use it at issuance time instead of mock
        // data. null for staff/password logins — nothing to store, mock data keeps being used.
        public void SaveRequestCredential(string guid, List<string> credentialConfigurationIds, string preAuthorizedCode, string subject = null, ThaIDCheckStateResponse profile = null)
        {
            if (credentialConfigurationIds == null || credentialConfigurationIds.Count == 0)
                throw new ArgumentException("credentialConfigurationIds must contain at least one value.");

            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.FirstOrDefault(i => i.RegisterId.Equals(guid));
                if (item == null)
                {
                    item = new Dbrequest
                    {
                        RegisterId = guid,
                        PreAuthorizedCode = preAuthorizedCode,
                        CredentialId = Newtonsoft.Json.JsonConvert.SerializeObject(credentialConfigurationIds), // ["org.iso.18013.5.1.mDL","...sd-jwt"]
                        CreateDate = DateTime.UtcNow,
                        Subject = subject,
                        TitleTh = profile?.TitleNameTh,
                        FirstNameTh = profile?.FirstNameTh,
                        LastNameTh = profile?.LastNameTh,
                        BirthDate = profile?.BirthDate,
                        Gender = profile?.Gender,
                        Address = profile?.Address,
                        DateOfIssuance = profile?.DateOfIssuance,
                        DateOfExpiry = profile?.DateOfExpiry,
                        TitleEn = profile?.TitleNameEn,
                        FirstNameEn = profile?.FirstNameEn,
                        LastNameEn = profile?.LastNameEn
                    };
                    context.Dbrequests.Add(item);
                    context.SaveChanges();
                }
            }
        }

        // C-05 (partial): read back the real ThaID profile stored against this registerId at
        // offer-creation time, so credential generation can use it instead of hardcoded mock data.
        // Returns null if no profile was captured (staff/password login, or offer predates this
        // column) — callers must fall back to mock data in that case, same as before.
        public ThaIDCheckStateResponse GetRequestProfile(string registerId)
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.FirstOrDefault(i => i.RegisterId.Equals(registerId));
                if (item == null || (string.IsNullOrWhiteSpace(item.FirstNameTh) && string.IsNullOrWhiteSpace(item.LastNameTh)))
                {
                    return null;
                }

                return new ThaIDCheckStateResponse
                {
                    PID = item.Subject,
                    TitleNameTh = item.TitleTh,
                    FirstNameTh = item.FirstNameTh,
                    LastNameTh = item.LastNameTh,
                    BirthDate = item.BirthDate,
                    Gender = item.Gender,
                    Address = item.Address,
                    DateOfIssuance = item.DateOfIssuance,
                    DateOfExpiry = item.DateOfExpiry,
                    TitleNameEn = item.TitleEn,
                    FirstNameEn = item.FirstNameEn,
                    LastNameEn = item.LastNameEn
                };
            }
        }

        public void SaveIssueVCLog(string issuerid, string walletid, string _nonce, string _credential, string vcDocType, string statuscode)
        {
            Guid id = new Guid();
            try
            {
                IssuerDbContext issuerContext = new IssuerDbContext();
                // M-02: do not retain the raw issued credential in application logs/DB — only the
                // event metadata needed to audit issuance (who, what type, when, outcome). If a
                // credential copy is ever genuinely needed for recovery, that must be a separate,
                // purpose-documented, encrypted, access-controlled store — not this log table.
                var log = new Dbissuerlog
                {

                    TeamId = _nonce,
                    CredentialType = vcDocType,
                    HolderDid = walletid,
                    IssuerDid = issuerid,
                    OfferId = _nonce,
                    Status = statuscode,
                    CredentialPayload = null,
                    CreatedAt = DateTime.Now
                };
                issuerContext.Dbissuerlogs.Add(log);
                issuerContext.SaveChanges();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Save VC to DB error: {e.Message}");
            }
        }

        // Backs the admin issuance log page (LogsController). Most recent first — this is an audit
        // view, not a paged report, so a simple bounded Take() is enough for now.
        public List<Dbissuerlog> GetRecentIssuerLogs(int limit = 200)
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                return context.Dbissuerlogs
                    .OrderByDescending(l => l.CreatedAt)
                    .Take(limit)
                    .ToList();
            }
        }

        // Backs the admin "credential status / revoke" page (LogsController.Credentials). Unlike
        // GetRecentIssuerLogs (a plain audit trail of issuance attempts), this queries
        // dbissuedcredential directly — the table that actually holds Revoked/RevokedAt and doubles
        // as each credential's status list index.
        public List<Dbissuedcredential> GetRecentIssuedCredentials(int limit = 200)
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                return context.Dbissuedcredentials
                    .OrderByDescending(c => c.Id)
                    .Take(limit)
                    .ToList();
            }
        }

    }
}
