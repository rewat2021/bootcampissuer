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
    [Route("[controller]")]
    [Tags("Metadata")]
    public class IssuerController : ControllerBase
    {
        private readonly IWebHostEnvironment _env;
        private readonly Oid4VciOptions _options;
        private IConfiguration _config;
        private string credentialOfferId = null;
       

        public IssuerController(IConfiguration config, IWebHostEnvironment env, IOptions<Oid4VciOptions> options)
        {
            _config = config;
            _env = env;
            _options = options.Value;
        }

        

        // H-05 (full fix): OID4VCI 1.0 Final §12.2.4 defines /.well-known/openid-credential-issuer as
        // a document distinct from OAuth 2.0 Authorization Server metadata (RFC 8414). Only the
        // parameters §12.2.4 actually defines are published here: credential_issuer (REQUIRED),
        // credential_endpoint (REQUIRED), nonce_endpoint (OPTIONAL, implemented), and
        // credential_configurations_supported (REQUIRED). `authorization_servers` is intentionally
        // omitted — per spec, omitting it means "the entity providing the Credential Issuer is also
        // acting as the Authorization Server", which is true here (this app serves /token itself), so
        // no self-reference is needed. AS-only fields (issuer, scopes_supported,
        // response_types_supported, response_modes_supported, grant_types_supported,
        // subject_types_supported, id_token_signing_alg_values_supported, token_endpoint) moved to
        // ReadAuthorizationServerMetadata() below, at the correct RFC 8414 well-known URI.
        [AllowAnonymous]
        [HttpGet("/.well-known/openid-credential-issuer")]
        public async Task<IActionResult> ReadJsonAsync()
        {
            Response.Headers["Cache-Control"] = "no-store";

            var baseUrl = GetBaseUrl(HttpContext, _options);
            VCService vcServ = new VCService();

            var credentialConfigurations = await vcServ.LoadCredentialConfigurationsAsync(_env, baseUrl);

            var response = new JsonObject
            {
                ["credential_issuer"] = baseUrl,
                ["credential_endpoint"] = $"{baseUrl}/credential",
                ["nonce_endpoint"] = $"{baseUrl}/nonce",
                ["credential_configurations_supported"] = credentialConfigurations
            };

            return new JsonResult(response);
        }

        // H-05 (full fix): OAuth 2.0 Authorization Server Metadata (RFC 8414). This issuer also acts
        // as its own Authorization Server (it serves /token itself), so these fields are published
        // here — the correct, spec-defined location for them — rather than mixed into the Credential
        // Issuer Metadata document above.
        [AllowAnonymous]
        [HttpGet("/.well-known/oauth-authorization-server")]
        public IActionResult ReadAuthorizationServerMetadata()
        {
            Response.Headers["Cache-Control"] = "no-store";

            var baseUrl = GetBaseUrl(HttpContext, _options);

            var response = new JsonObject
            {
                ["issuer"] = baseUrl,
                ["token_endpoint"] = $"{baseUrl}/token",
                ["grant_types_supported"] = new JsonArray(
                    "authorization_code",
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ),
                ["response_types_supported"] = new JsonArray("code", "vp_token", "id_token"),
                ["response_modes_supported"] = new JsonArray("query", "fragment"),
                ["scopes_supported"] = new JsonArray("openid"),
                ["subject_types_supported"] = new JsonArray("public"),
                ["id_token_signing_alg_values_supported"] = new JsonArray("ES256")
            };

            return new JsonResult(response);
        }

        // did:web identity for this issuer — same Ed25519 key as did:key (_GetDID), served as a DID
        // Document at the standard did:web resolution location. Additive, not a replacement: existing
        // did:key-based flows (proof kid, credential iss, mdoc IssuerAuth) are untouched.
        [AllowAnonymous]
        [HttpGet("/.well-known/did.json")]
        public IActionResult DidWebDocument()
        {
            var baseUrl = GetBaseUrl(HttpContext, _options);
            VCService vcServ = new VCService();
            var doc = vcServ.BuildDidWebDocument(_env, baseUrl);
            return new JsonResult(doc);
        }

        // IETF Token Status List — served for the credentials that embed a "status" claim (see
        // VCService.BuildStatusClaim, wired into the dc+sd-jwt generators). Must be anonymous: any
        // verifier checking whether a presented credential is revoked needs to fetch this, not just
        // this issuer's own logged-in users. Not cached at the response level — VCService already
        // sets a 24h "exp" on the token itself, which is what a well-behaved verifier should honor.
        [AllowAnonymous]
        [HttpGet("/status-list/1")]
        public IActionResult StatusList1()
        {
            var baseUrl = GetBaseUrl(HttpContext, _options);
            VCService vcServ = new VCService();
            // กลับมาใช้ did:key (_GetDID) — ให้ตรงกับ iss ของ VC ที่ CredentialController ออกไปแล้ว
            // (สลับกลับตามที่ CredentialController สลับกลับ ไม่งั้น status list กับ VC จะอ้าง issuer คนละ DID กัน)
            string issuerid = vcServ._GetDID(_env);
            string token = vcServ.BuildStatusListToken(issuerid, _env, baseUrl);
            return Content(token, "application/statuslist+jwt");
        }

        // H-01: OID4VCI 1.0 Final §7 — Nonce Endpoint. Issues a fresh c_nonce a wallet embeds in its
        // proof JWT "nonce" claim. The nonce is now persisted (DBService.IssueNonce) and checked for
        // single use at /credential (DBService.TryConsumeNonce) — previously this endpoint generated
        // a random value but never stored it, so nothing actually enforced freshness/replay.
        // Anonymous/unauthenticated per spec (it hands out a nonce, nothing sensitive).
        [AllowAnonymous]
        [HttpPost("/nonce")]
        public IActionResult Nonce()
        {
            Response.Headers["Cache-Control"] = "no-store";

            DBService dbServ = new DBService();
            var nonce = dbServ.IssueNonce();

            return new JsonResult(new { c_nonce = nonce, c_nonce_expires_in = (int)DBService.NonceTtl.TotalSeconds });
        }

        // H-11: single canonical way to compute the issuer's own base URL, shared by every
        // controller that needs it (CredentialController.urlBase, CredentialOfferController, here).
        // Prefers an explicitly configured identifier (Oid4Vci:CredentialIssuerIdentifier) so the
        // value used in credential "iss"/proof "aud" checks doesn't depend on which Host header a
        // caller happened to send; falls back to X-Forwarded-Proto/Host, which is only trustworthy
        // because Program.cs restricts ForwardedHeadersOptions to known proxies (see H-11 fix there).
        internal static string GetBaseUrl(HttpContext context, Oid4VciOptions options)
        {
            if (!string.IsNullOrWhiteSpace(options?.CredentialIssuerIdentifier))
            {
                return options.CredentialIssuerIdentifier.TrimEnd('/');
            }

            var scheme = context.Request.Headers["X-Forwarded-Proto"].FirstOrDefault()
                         ?? context.Request.Scheme;

            var host = context.Request.Headers["X-Forwarded-Host"].FirstOrDefault()
                       ?? context.Request.Host.Value;

            return $"{scheme}://{host}";
        }

        //private string GetDID()
        //{
        //    VCService serv = new VCService();
        //    PemReader pemReaderPublic = new PemReader(new StringReader(serv.GetKey(false, _env)));
        //    Ed25519PublicKeyParameters publicKeyEd25519 = (Ed25519PublicKeyParameters)pemReaderPublic.ReadObject();

        //    byte[] privateKeyBytes = publicKeyEd25519.GetEncoded();
        //    byte[] multicodecPrefix = new byte[] { 0xED, 0x01 };

        //    byte[] privateKeyWithPrefix = new byte[multicodecPrefix.Length + privateKeyBytes.Length];

        //    Buffer.BlockCopy(multicodecPrefix, 0, privateKeyWithPrefix, 0, multicodecPrefix.Length);
        //    Buffer.BlockCopy(privateKeyBytes, 0, privateKeyWithPrefix, multicodecPrefix.Length, privateKeyBytes.Length);

        //    //var privateKeyString = "z" + Base58.Bitcoin.Encode(publicKeyEd25519.GetEncoded());
        //    var privateKeyString = "z" + Base58.Bitcoin.Encode(privateKeyWithPrefix);
        //    var entityDID = "did:key:" + privateKeyString + "#" + privateKeyString;

        //    return entityDID;
        //}

        

    }
}
