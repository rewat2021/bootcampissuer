using IssuerAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace IssuerAPI.Controllers
{
    // ── Request Models ─────────────────────────────────────────────────────────

    public class UpsertClaimsRequest
    {
        /// <summary>
        /// Claims dictionary ตาม OID4VCI 1.0 Final
        /// Key   = field name (เช่น student_id, full_name)
        /// Value = claim metadata
        /// </summary>
        public Dictionary<string, ClaimConfigInput> Claims { get; set; } = new();
    }

    /// <summary>
    /// ตาม OID4VCI 1.0 Final §12.2.4 — Credential Issuer Metadata Parameters
    /// "claims" เป็น object ไม่ใช่ array
    /// field ที่รองรับ: mandatory, display
    /// "sd" ไม่ใช่ส่วนหนึ่งของ OID4VCI Metadata (เป็น SD-JWT level)
    /// </summary>
    public class ClaimConfigInput
    {
        /// <summary>true = Wallet ต้องขอ claim นี้เสมอ (default: false)</summary>
        public bool Mandatory { get; set; } = false;

        /// <summary>Display label สำหรับ Wallet UI (optional)</summary>
        public List<ClaimDisplayInput>? Display { get; set; }
    }

    public class ClaimDisplayInput
    {
        public string? Name { get; set; }
        public string? Locale { get; set; }
    }

    public class AddFieldRequest
    {
        public string FieldName { get; set; } = "";

        /// <summary>true = Wallet ต้องขอ claim นี้เสมอ</summary>
        public bool Mandatory { get; set; } = false;

        public string? LabelEn { get; set; }
        public string? LabelTh { get; set; }
    }

    public class RemoveFieldRequest
    {
        public string CredentialType { get; set; } = "";
        public string FieldName { get; set; } = "";
    }

    public class AddCredentialTypeRequest
    {
        public string CredentialType { get; set; } = "";
        public string Format { get; set; } = "dc+sd-jwt";
        public string? Vct { get; set; }
        public List<string> SigningAlg { get; set; } = new() { "EdDSA" };
        public Dictionary<string, ClaimConfigInput> Claims { get; set; } = new();
    }

    // ── Controller ─────────────────────────────────────────────────────────────

    [ApiController]
    [Route("api/[controller]")]
    [Tags("Credential Config")]
    public class CredentialConfigController : ControllerBase
    {
        private readonly IWebHostEnvironment _env;
        private readonly Oid4VciOptions _options;

        const string credentialType = "BootCampCredential_dc+sd-jwt";

        private static readonly JsonSerializerOptions _jsonOpts = new()
        {
            WriteIndented = true
        };

        public CredentialConfigController(
            IWebHostEnvironment env,
            IOptions<Oid4VciOptions> options)
        {
            _env = env;
            _options = options.Value;
        }

        // ── helpers ───────────────────────────────────────────────────────────

        private string ConfigFilePath() =>
            Path.Combine(_env.ContentRootPath, _options.CredentialConfigurationsFile);

        private async Task<JsonObject> LoadConfigAsync()
        {
            string path = ConfigFilePath();
            if (!System.IO.File.Exists(path))
                return new JsonObject();

            string json = await System.IO.File.ReadAllTextAsync(path);
            return JsonNode.Parse(json)?.AsObject() ?? new JsonObject();
        }

        private async Task SaveConfigAsync(JsonObject config)
        {
            string path = ConfigFilePath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string json = JsonSerializer.Serialize(config, _jsonOpts);
            await System.IO.File.WriteAllTextAsync(path, json);
        }

        // ─────────────────────────────────────────────────────────────────────
        // GET api/credential-config/types
        // ─────────────────────────────────────────────────────────────────────
        [HttpGet("types")]
        public async Task<IActionResult> GetAllTypes()
        {
            var config = await LoadConfigAsync();
            var types = config.Select(kv => new
            {
                key = kv.Key,
                format = config[kv.Key]?["format"]?.GetValue<string>()
            }).ToList();

            return Ok(new { count = types.Count, types });
        }

        // ─────────────────────────────────────────────────────────────────────
        // PUT api/credential-config/claims
        // แทนที่ claims ทั้งชุด — ตาม OID4VCI 1.0 Final object format
        //
        // Body example:
        // {
        //   "claims": {
        //     "student_id": { "mandatory": true,  "display": [{"name":"รหัสนักศึกษา","locale":"th"}] },
        //     "full_name":  { "mandatory": true,  "display": [{"name":"ชื่อ-นามสกุล","locale":"th"}] },
        //     "gpa":        { "mandatory": false }
        //   }
        // }
        // ─────────────────────────────────────────────────────────────────────
        [HttpPut("claims")]
        public async Task<IActionResult> UpsertClaims([FromBody] UpsertClaimsRequest request)
        {
            if (request.Claims == null || request.Claims.Count == 0)
                return BadRequest(new { error = "Claims ต้องมีอย่างน้อย 1 field" });

            try
            {
                var config = await LoadConfigAsync();

                if (config[credentialType] is not JsonObject cred)
                    return NotFound(new { error = $"ไม่พบ credential type '{credentialType}'" });

                // ✅ OID4VCI 1.0 Final: claims เป็น object { fieldName: { mandatory, display } }
                var claimsObj = BuildClaimsObject(request.Claims);
                cred["claims"] = claimsObj;

                await SaveConfigAsync(config);

                return Ok(new
                {
                    success = true,
                    credentialType,
                    claimsUpdated = request.Claims.Count,
                    claims = claimsObj
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // POST api/credential-config/claims/add-field
        // เพิ่ม/อัปเดต field เดียว
        //
        // Body example:
        // {
        //   "fieldName": "graduation_date",
        //   "mandatory": false,
        //   "labelEn": "Graduation Date",
        //   "labelTh": "วันสำเร็จการศึกษา"
        // }
        // ─────────────────────────────────────────────────────────────────────
        [HttpPost("claims/add-field")]
        public async Task<IActionResult> AddField([FromBody] AddFieldRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.FieldName))
                return BadRequest(new { error = "FieldName is required" });

            try
            {
                var config = await LoadConfigAsync();

                if (config[credentialType] is not JsonObject cred)
                    return NotFound(new { error = $"ไม่พบ credential type '{credentialType}'" });

                // ✅ ดึง claims object หรือสร้างใหม่
                if (cred["claims"] is not JsonObject claimsObj)
                {
                    claimsObj = new JsonObject();
                    cred["claims"] = claimsObj;
                }

                bool isUpdate = claimsObj.ContainsKey(request.FieldName);

                // ✅ สร้าง claim node ตาม OID4VCI 1.0 Final
                var fieldNode = new JsonObject
                {
                    ["mandatory"] = request.Mandatory
                };

                var displayArr = new JsonArray();
                if (!string.IsNullOrEmpty(request.LabelEn))
                    displayArr.Add(new JsonObject { ["name"] = request.LabelEn, ["locale"] = "en" });
                if (!string.IsNullOrEmpty(request.LabelTh))
                    displayArr.Add(new JsonObject { ["name"] = request.LabelTh, ["locale"] = "th" });

                if (displayArr.Count > 0)
                    fieldNode["display"] = displayArr;

                // ✅ upsert โดยใช้ field name เป็น key โดยตรง
                claimsObj[request.FieldName] = fieldNode;

                await SaveConfigAsync(config);

                return Ok(new
                {
                    success = true,
                    credentialType,
                    fieldName = request.FieldName,
                    action = isUpdate ? "updated" : "added",
                    field = fieldNode
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // DELETE api/credential-config/claims/remove-field
        // ─────────────────────────────────────────────────────────────────────
        [HttpDelete("claims/remove-field")]
        public async Task<IActionResult> RemoveField([FromBody] RemoveFieldRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.CredentialType))
                return BadRequest(new { error = "CredentialType is required" });

            if (string.IsNullOrWhiteSpace(request.FieldName))
                return BadRequest(new { error = "FieldName is required" });

            try
            {
                var config = await LoadConfigAsync();

                if (config[request.CredentialType] is not JsonObject cred)
                    return NotFound(new { error = $"ไม่พบ credential type '{request.CredentialType}'" });

                // ✅ claims เป็น object — ลบด้วย key โดยตรง
                if (cred["claims"] is not JsonObject claimsObj)
                    return NotFound(new { error = "ไม่พบ claims object" });

                if (!claimsObj.ContainsKey(request.FieldName))
                    return NotFound(new { error = $"ไม่พบ field '{request.FieldName}'" });

                claimsObj.Remove(request.FieldName);
                await SaveConfigAsync(config);

                return Ok(new
                {
                    success = true,
                    credentialType = request.CredentialType,
                    fieldName = request.FieldName,
                    message = "ลบ field สำเร็จ"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Helper: สร้าง claims JsonObject ตาม OID4VCI 1.0 Final
        //
        // Output:
        // {
        //   "student_id": { "mandatory": true,  "display": [...] },
        //   "full_name":  { "mandatory": true,  "display": [...] },
        //   "gpa":        { "mandatory": false }
        // }
        // ─────────────────────────────────────────────────────────────────────
        private static JsonObject BuildClaimsObject(Dictionary<string, ClaimConfigInput> claims)
        {
            var obj = new JsonObject();

            foreach (var (fieldName, claim) in claims)
            {
                var fieldNode = new JsonObject
                {
                    ["mandatory"] = claim.Mandatory
                };

                if (claim.Display?.Count > 0)
                {
                    var displayArr = new JsonArray();
                    foreach (var d in claim.Display)
                    {
                        var dNode = new JsonObject();
                        if (!string.IsNullOrEmpty(d.Name)) dNode["name"] = d.Name;
                        if (!string.IsNullOrEmpty(d.Locale)) dNode["locale"] = d.Locale;
                        displayArr.Add(dNode);
                    }
                    fieldNode["display"] = displayArr;
                }

                obj[fieldName] = fieldNode;
            }

            return obj;
        }
    }
}
