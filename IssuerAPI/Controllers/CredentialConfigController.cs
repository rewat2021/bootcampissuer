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
        /// <summary>ชื่อ credential type key เช่น BootCampCredential_dc+sd-jwt</summary>
        //public string CredentialType { get; set; } = "";

        /// <summary>
        /// Claims dictionary
        /// Key = field name (เช่น student_id, full_name)
        /// Value = claim config
        /// </summary>
        public Dictionary<string, ClaimConfigInput> Claims { get; set; } = new();
    }

    public class ClaimConfigInput
    {
        public bool Mandatory { get; set; } = true;
        public bool Sd { get; set; } = true;
        public List<ClaimDisplayInput>? Display { get; set; }
    }

    public class ClaimDisplayInput
    {
        public string? Name { get; set; }
        public string? Locale { get; set; }
    }

    public class AddFieldRequest
    {
        /// <summary>ชื่อ credential type key เช่น BootCampCredential_dc+sd-jwt</summary>
        //public string CredentialType { get; set; } = "";
        public string FieldName { get; set; } = "";
        public bool Mandatory { get; set; } = true;
        public bool Sd { get; set; } = true;
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
        const string credentialType = "BootCampCredential_dc+sd-jwt"; // ✅ fix

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

        // ── helper: path ของ config file ──────────────────────────────────────
        private string ConfigFilePath() =>
            Path.Combine(_env.ContentRootPath, _options.CredentialConfigurationsFile);

        // ── helper: อ่าน config file → JsonObject ─────────────────────────────
        private async Task<JsonObject> LoadConfigAsync()
        {
            string path = ConfigFilePath();
            if (!System.IO.File.Exists(path))
                return new JsonObject();

            string json = await System.IO.File.ReadAllTextAsync(path);
            return JsonNode.Parse(json)?.AsObject() ?? new JsonObject();
        }

        // ── helper: บันทึก config ─────────────────────────────────────────────
        private async Task SaveConfigAsync(JsonObject config)
        {
            string path = ConfigFilePath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            // ✅ ใช้ JsonSerializer.Serialize แทน ToJsonString
            string json = JsonSerializer.Serialize(config, _jsonOpts);
            await System.IO.File.WriteAllTextAsync(path, json);
        }

        // ─────────────────────────────────────────────────────────────────────
        // GET api/credential-config/types
        // ดู credential types ทั้งหมด
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
        // GET api/credential-config/claims/{credentialType}
        // ดู claims ของ credential type นั้น
        // ─────────────────────────────────────────────────────────────────────
        //[HttpGet("claims/{credentialType}")]
        //public async Task<IActionResult> GetClaims(string credentialType)
        //{
        //    if (string.IsNullOrWhiteSpace(credentialType))
        //        return BadRequest(new { error = "credentialType is required" });

        //    var config = await LoadConfigAsync();

        //    if (config[credentialType] is not JsonObject cred)
        //        return NotFound(new { error = $"ไม่พบ credential type '{credentialType}'" });

        //    var claims = cred["claims"];
        //    return Ok(new { credentialType, claims });
        //}

        // ─────────────────────────────────────────────────────────────────────
        // PUT api/credential-config/claims
        // อัปเดต claims ทั้งชุดของ credential type (OID4VCI 1.0 array format)
        // ─────────────────────────────────────────────────────────────────────
        [HttpPut("claims")]
        public async Task<IActionResult> UpsertClaims([FromBody] UpsertClaimsRequest request)
        {
            
            if (request.Claims == null || request.Claims.Count == 0)
                return BadRequest(new { error = "Claims ต้องมีอย่างน้อย 1 field" });

            try
            {
                var config = await LoadConfigAsync();
                var cs = config;

                if (cs[credentialType] is not JsonObject cred)
                    return NotFound(new { error = $"ไม่พบ credential type '{credentialType}'" });

                // ✅ สร้าง claims เป็น array format ตาม OID4VCI 1.0
                var claimsArray = BuildClaimsArray(request.Claims);
                cred["claims"] = claimsArray;

                await SaveConfigAsync(config);

                return Ok(new
                {
                    success = true,
                    credentialType,
                    claimsUpdated = request.Claims.Count,
                    claims = claimsArray
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // POST api/credential-config/claims/add-field
        // เพิ่ม/อัปเดต field เดียว (OID4VCI 1.0 array format)
        // ─────────────────────────────────────────────────────────────────────
        [HttpPost("claims/add-field")]
        public async Task<IActionResult> AddField([FromBody] AddFieldRequest request)
        {

            if (string.IsNullOrWhiteSpace(request.FieldName))
                return BadRequest(new { error = "FieldName is required" });

            try
            {
                var config = await LoadConfigAsync();
                var cs = config;

                if (cs[credentialType] is not JsonObject cred)
                    return NotFound(new { error = $"ไม่พบ credential type '{credentialType}'" });
                

                // ✅ ดึง claims array หรือสร้างใหม่
                JsonArray claimsArray;
                if (cred["claims"] is JsonArray existingArray)
                {
                    claimsArray = existingArray;
                }
                else
                {
                    claimsArray = new JsonArray();
                    cred["claims"] = claimsArray;
                }

                // ✅ ตรวจว่า field นี้มีอยู่แล้วหรือไม่ (ดูจาก path[0])
                JsonObject? existingField = null;
                int existingIndex = -1;
                for (int i = 0; i < claimsArray.Count; i++)
                {
                    var item = claimsArray[i] as JsonObject;
                    var path = item?["path"]?.AsArray();
                    if (path?.Count > 0 && path[0]?.GetValue<string>() == request.FieldName)
                    {
                        existingField = item;
                        existingIndex = i;
                        break;
                    }
                }

                // ✅ สร้าง field node ตาม OID4VCI 1.0
                var fieldNode = new JsonObject
                {
                    ["path"] = new JsonArray { request.FieldName },
                    ["mandatory"] = request.Mandatory,
                    ["sd"] = request.Sd
                };

                var displayArr = new JsonArray();
                if (!string.IsNullOrEmpty(request.LabelEn))
                    displayArr.Add(new JsonObject { ["name"] = request.LabelEn, ["locale"] = "en" });
                if (!string.IsNullOrEmpty(request.LabelTh))
                    displayArr.Add(new JsonObject { ["name"] = request.LabelTh, ["locale"] = "th" });
                if (displayArr.Count > 0)
                    fieldNode["display"] = displayArr;

                // ✅ update หรือ append
                if (existingIndex >= 0)
                    claimsArray[existingIndex] = fieldNode;
                else
                    claimsArray.Add(fieldNode);

                await SaveConfigAsync(config);

                return Ok(new
                {
                    success = true,
                    credentialType,
                    fieldName = request.FieldName,
                    action = existingIndex >= 0 ? "updated" : "added",
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
        // ลบ field จาก claims array
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

                if (cred["claims"] is not JsonArray claimsArray)
                    return NotFound(new { error = "ไม่พบ claims array" });

                // ✅ หา field จาก path[0]
                int removeIndex = -1;
                for (int i = 0; i < claimsArray.Count; i++)
                {
                    var item = claimsArray[i] as JsonObject;
                    var path = item?["path"]?.AsArray();
                    if (path?.Count > 0 && path[0]?.GetValue<string>() == request.FieldName)
                    {
                        removeIndex = i;
                        break;
                    }
                }

                if (removeIndex < 0)
                    return NotFound(new { error = $"ไม่พบ field '{request.FieldName}'" });

                claimsArray.RemoveAt(removeIndex);
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
        // POST api/credential-config/type
        // เพิ่ม credential type ใหม่ (dc+sd-jwt format)
        // ─────────────────────────────────────────────────────────────────────
        //[HttpPost("type")]
        //public async Task<IActionResult> AddCredentialType([FromBody] AddCredentialTypeRequest request)
        //{
        //    if (string.IsNullOrWhiteSpace(request.CredentialType))
        //        return BadRequest(new { error = "CredentialType is required" });

        //    try
        //    {
        //        var config = await LoadConfigAsync();

        //        string baseUrl = $"{Request.Scheme}://{Request.Host}";
        //        string vct = request.Vct ?? $"{baseUrl}/credentials/{request.CredentialType}";

        //        var algArr = new JsonArray();
        //        foreach (var a in request.SigningAlg) algArr.Add(a);

        //        var credNode = new JsonObject
        //        {
        //            ["format"] = request.Format,
        //            ["vct"] = vct,
        //            ["cryptographic_binding_methods_supported"] = new JsonArray("jwk", "did"),
        //            ["credential_signing_alg_values_supported"] = algArr,
        //            ["claims"] = BuildClaimsArray(request.Claims)
        //        };

        //        config[request.CredentialType] = credNode;
        //        await SaveConfigAsync(config);

        //        return Ok(new
        //        {
        //            success = true,
        //            credentialType = request.CredentialType,
        //            config = credNode
        //        });
        //    }
        //    catch (Exception ex)
        //    {
        //        return StatusCode(500, new { error = ex.Message });
        //    }
        //}

        // ─────────────────────────────────────────────────────────────────────
        // DELETE api/credential-config/type/{credentialType}
        // ลบ credential type
        // ─────────────────────────────────────────────────────────────────────
        //[HttpDelete("type/{credentialType}")]
        //public async Task<IActionResult> RemoveCredentialType(string credentialType)
        //{
        //    if (string.IsNullOrWhiteSpace(credentialType))
        //        return BadRequest(new { error = "credentialType is required" });

        //    try
        //    {
        //        var config = await LoadConfigAsync();

        //        if (!config.ContainsKey(credentialType))
        //            return NotFound(new { error = $"ไม่พบ credential type '{credentialType}'" });

        //        config.Remove(credentialType);
        //        await SaveConfigAsync(config);

        //        return Ok(new { success = true, credentialType, message = "ลบ credential type สำเร็จ" });
        //    }
        //    catch (Exception ex)
        //    {
        //        return StatusCode(500, new { error = ex.Message });
        //    }
        //}

        // ─────────────────────────────────────────────────────────────────────
        // Helper: สร้าง claims JsonArray ตาม OID4VCI 1.0 format
        // [{"path": ["fieldName"], "mandatory": true, "sd": true, "display": [...]}]
        // ─────────────────────────────────────────────────────────────────────
        private static JsonArray BuildClaimsArray(Dictionary<string, ClaimConfigInput> claims)
        {
            var array = new JsonArray();

            foreach (var (fieldName, claim) in claims)
            {
                var fieldNode = new JsonObject
                {
                    ["path"] = new JsonArray { fieldName },
                    ["mandatory"] = claim.Mandatory,
                    ["sd"] = claim.Sd
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

                array.Add(fieldNode);
            }

            return array;
        }
    }
}
