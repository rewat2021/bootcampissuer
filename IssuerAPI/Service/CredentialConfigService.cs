using IssuerAPI.Models;
using Microsoft.Extensions.Options;
using System.Text.Json.Nodes;

namespace IssuerAPI.Services
{
    /// <summary>
    /// อ่าน claims config จาก App_Data/credential-configurations-supported.json
    /// ใช้ตอนออก VC เพื่อรู้ว่า field ไหนเป็น SD claim
    /// </summary>
    public class CredentialConfigService
    {
        private readonly IWebHostEnvironment              _env;
        private readonly Oid4VciOptions                   _options;
        private readonly ILogger<CredentialConfigService> _logger;

        public CredentialConfigService(
            IWebHostEnvironment env,
            IOptions<Oid4VciOptions> options,
            ILogger<CredentialConfigService> logger)
        {
            _env     = env;
            _options = options.Value;
            _logger  = logger;
        }

        private string ConfigFilePath() =>
            Path.Combine(_env.ContentRootPath, _options.CredentialConfigurationsFile);

        // H-06: claims now live under credential_metadata.claims as an OID4VCI 1.0 Final Appendix B.2
        // array of { path: [...], mandatory, sd, display }. Normalize to fieldName -> claim-node so
        // callers below don't need to know which shape (array vs legacy top-level object) was on disk.
        public Dictionary<string, JsonNode?>? GetClaims(string credentialType)
        {
            try
            {
                string path = ConfigFilePath();
                if (!File.Exists(path)) return null;

                string json   = File.ReadAllText(path);
                var    config = JsonNode.Parse(json)?.AsObject();
                var    typeNode = config?[credentialType];
                if (typeNode == null) return null;

                var claimsNode = typeNode["credential_metadata"]?["claims"] ?? typeNode["claims"];

                var result = new Dictionary<string, JsonNode?>();

                if (claimsNode is JsonArray claimsArray)
                {
                    foreach (var item in claimsArray)
                    {
                        string? fieldName = (item?["path"] as JsonArray)?.FirstOrDefault()?.GetValue<string>();
                        if (!string.IsNullOrEmpty(fieldName))
                            result[fieldName] = item;
                    }
                }
                else if (claimsNode is JsonObject claimsObject)
                {
                    foreach (var (fieldName, claimNode) in claimsObject)
                        result[fieldName] = claimNode;
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to read credential config for type '{type}'", credentialType);
                return null;
            }
        }

        // ── ดึงชื่อ SD claims (sd = true) ─────────────────────────────────────
        public List<string> GetSdClaimNames(string credentialType)
        {
            var claims = GetClaims(credentialType);
            if (claims == null) return new();

            return claims
                .Where(kv => kv.Value?["sd"]?.GetValue<bool>() == true)
                .Select(kv => kv.Key)
                .ToList();
        }

        // ── ดึงชื่อ Non-SD claims (sd = false) ────────────────────────────────
        public List<string> GetNonSdClaimNames(string credentialType)
        {
            var claims = GetClaims(credentialType);
            if (claims == null) return new();

            return claims
                .Where(kv => kv.Value?["sd"]?.GetValue<bool>() != true)
                .Select(kv => kv.Key)
                .ToList();
        }

        // ── แยก SD / Non-SD claims จาก raw data ───────────────────────────────
        /// <summary>
        /// รับ rawData (ข้อมูลนักศึกษา) แล้ว filter ตาม config
        /// return sdClaims (selective disclose) และ nonSdClaims (ฝังใน payload ตรงๆ)
        /// </summary>
        public (Dictionary<string, object> sdClaims, Dictionary<string, object> nonSdClaims)
            SplitClaims(string credentialType, Dictionary<string, object> rawData)
        {
            var sdClaims    = new Dictionary<string, object>();
            var nonSdClaims = new Dictionary<string, object>();

            var claims = GetClaims(credentialType);
            if (claims == null)
            {
                // fallback: ถ้าไม่มี config ให้ทุก field เป็น SD
                foreach (var kv in rawData) sdClaims[kv.Key] = kv.Value;
                return (sdClaims, nonSdClaims);
            }

            foreach (var (fieldName, claimNode) in claims)
            {
                if (!rawData.TryGetValue(fieldName, out var value))
                {
                    bool mandatory = claimNode?["mandatory"]?.GetValue<bool>() == true;
                    if (mandatory)
                        _logger.LogWarning("Mandatory field '{field}' not found in raw data", fieldName);
                    continue;
                }

                bool isSd = claimNode?["sd"]?.GetValue<bool>() == true;
                if (isSd)
                    sdClaims[fieldName] = value;
                else
                    nonSdClaims[fieldName] = value;
            }

            return (sdClaims, nonSdClaims);
        }
    }
}
