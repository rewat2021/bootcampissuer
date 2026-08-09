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
        // after the offer is scanned — 10 minutes is generous slack, not an indefinitely-valid code.
        private static readonly TimeSpan PreAuthorizedCodeTtl = TimeSpan.FromMinutes(10);

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
        public bool TryMarkIssued(string registerId, string credentialConfigurationId)
        {
            if (string.IsNullOrWhiteSpace(registerId) || string.IsNullOrWhiteSpace(credentialConfigurationId))
                return false;

            using (IssuerDbContext context = new IssuerDbContext())
            {
                context.Dbissuedcredentials.Add(new Dbissuedcredential
                {
                    RegisterId = registerId,
                    CredentialConfigurationId = credentialConfigurationId,
                    IssuedAt = DateTime.UtcNow
                });

                try
                {
                    context.SaveChanges();
                    return true;
                }
                catch (DbUpdateException)
                {
                    // Unique constraint violation: this pair was already issued, or a concurrent
                    // request just won the race.
                    return false;
                }
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
        public void SaveRequestCredential(string guid, List<string> credentialConfigurationIds, string preAuthorizedCode, string subject = null)
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
                        Subject = subject
                    };
                    context.Dbrequests.Add(item);
                    context.SaveChanges();
                }
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

    }
}
