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

        

        [AllowAnonymous]
        [HttpGet("/.well-known/openid-credential-issuer")]
        public async Task<IActionResult> ReadJsonAsync()
        {
            var baseUrl = GetBaseUrl(HttpContext);
            VCService vcServ = new VCService();


            var credentialConfigurations = await vcServ.LoadCredentialConfigurationsAsync(_env, baseUrl); //await LoadCredentialConfigurationsAsync(baseUrl);

            var response = new JsonObject
            {
                ["issuer"] = baseUrl,
                ["pushed_authorization_request_endpoint"] = $"{baseUrl}/par",
                ["scopes_supported"] = new JsonArray("openid"),
                ["response_types_supported"] = new JsonArray("code", "vp_token", "id_token"),
                ["response_modes_supported"] = new JsonArray("query", "fragment"),
                ["grant_types_supported"] = new JsonArray(
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ),
                ["subject_types_supported"] = new JsonArray("public"),
                ["id_token_signing_alg_values_supported"] = new JsonArray("ES256"),
                ["credential_issuer"] = baseUrl,
                ["authorization_servers"] = new JsonArray(baseUrl),
                ["credential_endpoint"] = $"{baseUrl}/credential",
                ["token_endpoint"] = $"{baseUrl}/token",
                ["batch_credential_endpoint"] = $"{baseUrl}/batch_credential",
                ["deferred_credential_endpoint"] = $"{baseUrl}/credential_deferred",
                ["credential_configurations_supported"] = credentialConfigurations
            };

            return new JsonResult(response);
        }

        

        private static string GetBaseUrl(HttpContext context)
        {
            var scheme = context.Request.Headers["X-Forwarded-Proto"].FirstOrDefault()
                         ?? context.Request.Scheme;

            var host = context.Request.Headers["X-Forwarded-Host"].FirstOrDefault()
                       ?? context.Request.Host.Value;

            return $"{scheme}://{host}";
        }

        private async Task<JsonNode> LoadCredentialConfigurationsAsync(string baseUrl) 
        {
            var filePath = Path.Combine(_env.ContentRootPath, _options.CredentialConfigurationsFile);

            if (!System.IO.File.Exists(filePath))
            {
                return new JsonObject();
            }

            var json = await System.IO.File.ReadAllTextAsync(filePath);
            json = json.Replace("{IssuerUrl}", baseUrl);
            var node = JsonNode.Parse(json);
            return node ?? new JsonObject();
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
