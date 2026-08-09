using IssuerAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;

namespace IssuerAPI.Controllers
{
    // ── Request Models ─────────────────────────────────────────────────────────

    public class UpsertClaimsRequest
    {
        /// <summary>
        /// Claims dictionary
        /// Key   = field name (เช่น student_id, full_name)
        /// Value = claim metadata
        /// </summary>
        public Dictionary<string, ClaimConfigInput> Claims { get; set; } = new();
    }

    /// <summary>
    /// H-06 fix: OID4VCI 1.0 Final Appendix B.2 — a claims description object used in Credential
    /// Issuer metadata has "path" (REQUIRED, a claims path pointer array — Appendix C) and
    /// "mandatory"/"display" (OPTIONAL). The whole set lives under credential_metadata.claims as a
    /// non-empty ARRAY, not as a top-level "claims" object keyed by field name.
    /// "sd" is this application's own non-standard extension (not part of OID4VCI), used only to
    /// decide selective-disclosure placement when generating the SD-JWT — see
    /// VCService.GenerateBootCampSdJwt.
    /// </summary>
    public class ClaimConfigInput
    {
        /// <summary>true = Credential Issuer will always include this claim (default: false)</summary>
        public bool Mandatory { get; set; } = false;

        /// <summary>Display label สำหรับ Wallet UI (optional)</summary>
        public List<ClaimDisplayInput>? Display { get; set; }

        /// <summary>true = selectively disclosable in the SD-JWT (this app's own extension, default: true)</summary>
        public bool Sd { get; set; } = true;
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

    // C-03: this endpoint rewrites credential-configurations-supported.json — an unauthenticated
    // caller with write access here can change what claims/formats the issuer advertises and hands
    // out. Admin-only.
    [ApiController]
    [Route("api/[controller]")]
    [Tags("Credential Config")]
    [Authorize(Roles = "admin")]
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

        // M-05: serializes every load-modify-save cycle against this file through one process-wide
        // lock, so two concurrent PUT requests can't both load the same snapshot, edit different
        // parts, and have whichever saves last silently clobber the other's change (lost update).
        // This is a single-instance mitigation (an in-process semaphore, not a distributed lock) —
        // sufficient for this single-Kestrel-process deployment, not for a load-balanced farm sharing
        // this file across processes/machines.
        private static readonly SemaphoreSlim _configFileLock = new(1, 1);

        private async Task<JsonObject> LoadConfigAsync()
        {
            string path = ConfigFilePath();
            if (!System.IO.File.Exists(path))
                return new JsonObject();

            string json = await System.IO.File.ReadAllTextAsync(path);
            return JsonNode.Parse(json)?.AsObject() ?? new JsonObject();
        }

        // M-05: atomic replace. The full candidate document is written to a temp file first, then
        // File.Move'd over the real path — on the same volume this is an atomic filesystem rename, so
        // a crash or concurrent reader mid-operation always sees either the complete old file or the
        // complete new file, never a truncated/partial one (the previous File.WriteAllTextAsync
        // straight to the live path truncates-then-writes in place, which a process kill or full disk
        // could leave half-written). Also refuses to save a document with fewer top-level entries than
        // it started with, as a guard against a bug elsewhere silently dropping unrelated credential
        // types, and re-parses the serialized JSON before it ever touches disk.
        private async Task SaveConfigAsync(JsonObject config, int expectedMinEntryCount)
        {
            if (config == null || config.Count < expectedMinEntryCount)
            {
                throw new InvalidOperationException(
                    $"refusing to save credential configuration: expected at least {expectedMinEntryCount} top-level entries, got {config?.Count ?? 0}");
            }

            string path = ConfigFilePath();
            string directory = Path.GetDirectoryName(path)!;
            Directory.CreateDirectory(directory);

            string json = JsonSerializer.Serialize(config, _jsonOpts);

            // Validate the document round-trips as parsable JSON before it touches disk at all.
            JsonNode.Parse(json);

            string tempPath = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
            await System.IO.File.WriteAllTextAsync(tempPath, json);
            System.IO.File.Move(tempPath, path, overwrite: true);
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
        // แทนที่ claims ทั้งชุด — H-06: OID4VCI 1.0 Final Appendix B.2 array format,
        // stored under credential_metadata.claims
        //
        // Body example:
        // {
        //   "claims": {
        //     "student_id": { "mandatory": true, "sd": true, "display": [{"name":"รหัสนักศึกษา","locale":"th"}] },
        //     "full_name":  { "mandatory": true, "sd": true, "display": [{"name":"ชื่อ-นามสกุล","locale":"th"}] },
        //     "gpa":        { "mandatory": false, "sd": true }
        //   }
        // }
        // ─────────────────────────────────────────────────────────────────────
        [HttpPut("claims")]
        public async Task<IActionResult> UpsertClaims([FromBody] UpsertClaimsRequest request)
        {
            if (request.Claims == null || request.Claims.Count == 0)
                return BadRequest(new { error = "Claims ต้องมีอย่างน้อย 1 field" });

            // M-05: hold the lock for the entire load-modify-save cycle, not just the write — an
            // atomic write alone doesn't stop two concurrent requests from both loading the same
            // snapshot and the second one's save still overwriting the first's change.
            await _configFileLock.WaitAsync();
            try
            {
                var config = await LoadConfigAsync();
                int originalEntryCount = config.Count;

                if (config[credentialType] is not JsonObject cred)
                    return NotFound(new { error = $"ไม่พบ credential type '{credentialType}'" });

                // H-06: claims เป็น array of claims-description objects ({path, mandatory, display}),
                // เก็บใต้ credential_metadata.claims ไม่ใช่ top-level object แบบเดิม
                var claimsArray = BuildClaimsArray(request.Claims);

                if (cred["credential_metadata"] is not JsonObject credentialMetadata)
                {
                    credentialMetadata = new JsonObject();
                    cred["credential_metadata"] = credentialMetadata;
                }
                credentialMetadata["claims"] = claimsArray;

                // ลบ top-level "claims" เก่าทิ้งถ้ามี (รูปแบบก่อนแก้ H-06)
                cred.Remove("claims");

                await SaveConfigAsync(config, originalEntryCount);

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
            finally
            {
                _configFileLock.Release();
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
        //[HttpPost("claims/add-field")]
        //public async Task<IActionResult> AddField([FromBody] AddFieldRequest request)
        //{
        //    if (string.IsNullOrWhiteSpace(request.FieldName))
        //        return BadRequest(new { error = "FieldName is required" });

        //    try
        //    {
        //        var config = await LoadConfigAsync();

        //        if (config[credentialType] is not JsonObject cred)
        //            return NotFound(new { error = $"ไม่พบ credential type '{credentialType}'" });

        //        // ✅ ดึง claims object หรือสร้างใหม่
        //        if (cred["claims"] is not JsonObject claimsObj)
        //        {
        //            claimsObj = new JsonObject();
        //            cred["claims"] = claimsObj;
        //        }

        //        bool isUpdate = claimsObj.ContainsKey(request.FieldName);

        //        // ✅ สร้าง claim node ตาม OID4VCI 1.0 Final
        //        var fieldNode = new JsonObject
        //        {
        //            ["mandatory"] = request.Mandatory
        //        };

        //        var displayArr = new JsonArray();
        //        if (!string.IsNullOrEmpty(request.LabelEn))
        //            displayArr.Add(new JsonObject { ["name"] = request.LabelEn, ["locale"] = "en" });
        //        if (!string.IsNullOrEmpty(request.LabelTh))
        //            displayArr.Add(new JsonObject { ["name"] = request.LabelTh, ["locale"] = "th" });

        //        if (displayArr.Count > 0)
        //            fieldNode["display"] = displayArr;

        //        // ✅ upsert โดยใช้ field name เป็น key โดยตรง
        //        claimsObj[request.FieldName] = fieldNode;

        //        await SaveConfigAsync(config);

        //        return Ok(new
        //        {
        //            success = true,
        //            credentialType,
        //            fieldName = request.FieldName,
        //            action = isUpdate ? "updated" : "added",
        //            field = fieldNode
        //        });
        //    }
        //    catch (Exception ex)
        //    {
        //        return StatusCode(500, new { error = ex.Message });
        //    }
        //}

        // ─────────────────────────────────────────────────────────────────────
        // DELETE api/credential-config/claims/remove-field
        // ─────────────────────────────────────────────────────────────────────
        //[HttpDelete("claims/remove-field")]
        //public async Task<IActionResult> RemoveField([FromBody] RemoveFieldRequest request)
        //{
        //    if (string.IsNullOrWhiteSpace(request.CredentialType))
        //        return BadRequest(new { error = "CredentialType is required" });

        //    if (string.IsNullOrWhiteSpace(request.FieldName))
        //        return BadRequest(new { error = "FieldName is required" });

        //    try
        //    {
        //        var config = await LoadConfigAsync();

        //        if (config[request.CredentialType] is not JsonObject cred)
        //            return NotFound(new { error = $"ไม่พบ credential type '{request.CredentialType}'" });

        //        // ✅ claims เป็น object — ลบด้วย key โดยตรง
        //        if (cred["claims"] is not JsonObject claimsObj)
        //            return NotFound(new { error = "ไม่พบ claims object" });

        //        if (!claimsObj.ContainsKey(request.FieldName))
        //            return NotFound(new { error = $"ไม่พบ field '{request.FieldName}'" });

        //        claimsObj.Remove(request.FieldName);
        //        await SaveConfigAsync(config);

        //        return Ok(new
        //        {
        //            success = true,
        //            credentialType = request.CredentialType,
        //            fieldName = request.FieldName,
        //            message = "ลบ field สำเร็จ"
        //        });
        //    }
        //    catch (Exception ex)
        //    {
        //        return StatusCode(500, new { error = ex.Message });
        //    }
        //}

        // ─────────────────────────────────────────────────────────────────────
        // Helper: สร้าง claims JsonArray ตาม OID4VCI 1.0 Final Appendix B.2
        //
        // Output:
        // [
        //   { "path": ["student_id"], "mandatory": true,  "sd": true, "display": [...] },
        //   { "path": ["full_name"],  "mandatory": true,  "sd": true, "display": [...] },
        //   { "path": ["gpa"],        "mandatory": false, "sd": true }
        // ]
        // ─────────────────────────────────────────────────────────────────────
        private static JsonArray BuildClaimsArray(Dictionary<string, ClaimConfigInput> claims)
        {
            var arr = new JsonArray();

            foreach (var (fieldName, claim) in claims)
            {
                var claimNode = new JsonObject
                {
                    ["path"] = new JsonArray(fieldName),
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
                    claimNode["display"] = displayArr;
                }

                arr.Add(claimNode);
            }

            return arr;
        }
    }
}
