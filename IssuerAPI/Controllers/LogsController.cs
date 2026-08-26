using IssuerAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IssuerAPI.Controllers
{
    // Admin-only: issuance logs carry holder/issuer DIDs and offer ids for every credential request
    // (success and failure) — same access tier as CredentialConfigController, not for anonymous or
    // citizen-role access.
    [Authorize(Roles = "admin")]
    public class LogsController : Controller
    {
        [HttpGet("/Logs")]
        [HttpGet("/Logs/Index")]
        public IActionResult Index()
        {
            DBService dbServ = new DBService();
            var logs = dbServ.GetRecentIssuerLogs(200);
            return View(logs);
        }

        // Separate from Index: this lists dbissuedcredential rows (the table that actually carries
        // Revoked/RevokedAt and doubles as the status list index), so an admin can revoke a specific
        // issued credential.
        [HttpGet("/Logs/Credentials")]
        public IActionResult Credentials()
        {
            DBService dbServ = new DBService();
            var creds = dbServ.GetRecentIssuedCredentials(200);
            return View(creds);
        }

        // Revocation only takes effect for a verifier once it re-fetches /status-list/1 — flipping
        // this flag doesn't reach into the wallet or invalidate anything already cached by a verifier.
        // Only meaningful for dc+sd-jwt rows right now (see VCService.BuildStatusClaim) — revoking an
        // mDL/jwt_vc_json row just records intent, nothing currently checks it.
        [HttpPost("/Logs/Credentials/{id:int}/revoke")]
        [ValidateAntiForgeryToken]
        public IActionResult Revoke(int id)
        {
            DBService dbServ = new DBService();
            dbServ.RevokeCredential(id);
            return RedirectToAction("Credentials");
        }
    }
}
