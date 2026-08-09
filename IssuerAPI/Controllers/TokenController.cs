using IssuerAPI.Models;
using IssuerAPI.Service;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NLog;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace IssuerAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Tags("Authorization & Token")]
    public class TokenController : ControllerBase
    {

        private readonly IWebHostEnvironment _env;
        private readonly Oid4VciOptions _options;
        private IConfiguration _config;
        private string credentialOfferId = null;
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public TokenController(IConfiguration config, IWebHostEnvironment env, IOptions<Oid4VciOptions> options)
        {
            _config = config;
            _env = env;
            _options = options.Value;
        }

        [Route("/token")]
        [HttpPost]
        public IActionResult Token([FromForm] TokenExchangePreAuthRequest request)
        {
            // H-12: token responses carry credentials — must never be cached.
            Response.Headers["Cache-Control"] = "no-store";
            Response.Headers["Pragma"] = "no-cache";

            // H-04: standard OAuth 2.0 (RFC 6749 §5.2) error shape: { error, error_description }.
            if (string.IsNullOrWhiteSpace(request.GrantType))
            {
                return BadRequest(new { error = "invalid_request", error_description = "grant_type is required" });
            }

            if (request.GrantType != "urn:ietf:params:oauth:grant-type:pre-authorized_code")
            {
                return BadRequest(new { error = "unsupported_grant_type" });
            }

            if (string.IsNullOrWhiteSpace(request.PreAuthorizedCode))
            {
                return BadRequest(new { error = "invalid_request", error_description = "pre-authorized_code is required" });
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(new
                {
                    error = "invalid_request",
                    error_description = string.Join("; ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))
                });
            }

            DBService dbServ = new DBService();
            AccessCode accessCode = dbServ.getPreAuthorizedCode(request.PreAuthorizedCode, out string registerId);

            // C-04: pre-authorized codes must be single-use. getPreAuthorizedCode already refuses to
            // return a code that's expired or already been consumed (authoriseCode comes back null),
            // and ConsumePreAuthorizedCode below atomically marks it used so a second /token call with
            // the same code — even racing in parallel — can't mint a second access token.
            if (string.IsNullOrEmpty(accessCode?.authoriseCode) || !accessCode.authoriseCode.Equals(request.PreAuthorizedCode))
            {
                return new JsonResult(new { error = "invalid_grant", error_description = "pre-authorized_code is invalid, expired, or already used" })
                {
                    StatusCode = 400
                };
            }

            bool consumed = dbServ.ConsumePreAuthorizedCode(registerId, request.PreAuthorizedCode);
            if (!consumed)
            {
                // Someone else (or a concurrent retry) consumed it first.
                return new JsonResult(new { error = "invalid_grant", error_description = "pre-authorized_code is invalid, expired, or already used" })
                {
                    StatusCode = 400
                };
            }

            try
            {
                string privateKeyBase64 = _config["Jwt:PrivateKey"];
                if (string.IsNullOrEmpty(privateKeyBase64))
                {
                    logger.Error("Jwt:PrivateKey not configured");
                    return StatusCode(500, new { error = "server_error" });
                }

                byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
                var ecdsa = ECDsa.Create();
                ecdsa.ImportECPrivateKey(privateKeyBytes, out _);
                var ecdsaSecurityKey = new ECDsaSecurityKey(ecdsa);

                var tokenHandler = new JwtSecurityTokenHandler();

                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, accessCode.RegisterId),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                // H-13: short-lived access token — 5 minutes is enough for the wallet to immediately
                // turn around and call /credential; it should not remain usable indefinitely.
                var tokenLifetime = TimeSpan.FromMinutes(5);

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.UtcNow.Add(tokenLifetime),
                    Audience = $"{_config["Jwt:Issuer"]}/credential",
                    Issuer = _config["Jwt:Issuer"],
                    SigningCredentials = new SigningCredentials(ecdsaSecurityKey, SecurityAlgorithms.EcdsaSha256)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                string tokenString = tokenHandler.WriteToken(token);

                // C-04 / H-01: c_nonce used to just echo back accessCode.C_Nonce, which is the same
                // static value as the grant's RegisterId (reused for the life of the grant, never
                // expired or marked used). Issue a real single-use nonce instead — see
                // DBService.IssueNonce/TryConsumeNonce, checked when the wallet later calls
                // /credential.
                string cNonce = dbServ.IssueNonce();

                // H-07: authorization_details must contain one object per authorized
                // credential_configuration_id, not the whole stored JSON array dumped into a single
                // credential_configuration_id string. accessCode.CredentialType is that raw stored
                // value (Dbrequest.CredentialId — see DBService.SaveRequestCredential /
                // GetDocumentTypes), a JSON array of the config IDs this grant authorizes. This issuer
                // doesn't implement per-dataset credential_identifiers (Appendix example shows that as
                // an additional optional field under one config) — the Credential Request always
                // selects by credential_configuration_id directly, so authorization_details omits it.
                List<string> authorizedConfigIds;
                try
                {
                    authorizedConfigIds = Newtonsoft.Json.JsonConvert.DeserializeObject<List<string>>(accessCode.CredentialType)
                                           ?? new List<string>();
                }
                catch (Newtonsoft.Json.JsonException)
                {
                    // Legacy rows that predate storing a JSON array (a single bare config id string).
                    authorizedConfigIds = new List<string> { accessCode.CredentialType };
                }

                var response = new
                {
                    access_token = tokenString,
                    token_type = "Bearer",
                    expires_in = (int)tokenLifetime.TotalSeconds,
                    c_nonce = cNonce,
                    c_nonce_expires_in = (int)DBService.NonceTtl.TotalSeconds,
                    authorization_details = authorizedConfigIds.Select(id => new
                    {
                        type = "openid_credential",
                        credential_configuration_id = id
                    }).ToArray()
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                // H-04: don't leak ex.Message to the caller.
                logger.Error(ex, "Token exchange failed");
                return StatusCode(500, new { error = "server_error" });
            }
        }
    }
}
