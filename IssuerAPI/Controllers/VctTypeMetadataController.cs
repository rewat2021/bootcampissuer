// ============================================================
// VctTypeMetadataController.cs
// SD-JWT VC Type Metadata Endpoint — ASP.NET Core [ApiController]
//
// Route: GET /credentials/{type}
// Spec:  draft-ietf-oauth-sd-jwt-vc-15, Section 5
// ============================================================

using IssuerAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Net.Http;

namespace IssuerAPI.Controllers;


// ============================================================
// 2. Controller
// ============================================================

[ApiController]
[Produces("application/json")]
[Tags("Selective Disclosure")]
public class VctTypeMetadataController : ControllerBase
{
    private string BASE => $"{Request.Scheme}://{Request.Host}";


    private readonly IWebHostEnvironment _env;
    private readonly Oid4VciOptions _options;

    public VctTypeMetadataController(
        IWebHostEnvironment env,
        IOptions<Oid4VciOptions> options)
    {
        _env = env;
        _options = options.Value;
    }

    // ----------------------------------------------------------
    // GET /credentials/TranscriptCredential
    // ----------------------------------------------------------
    [HttpGet("credentials/TranscriptCredential")]
    [HttpGet(".well-known/vct/credentials/TranscriptCredential")]
    [ProducesResponseType(typeof(VctTypeMetadata), StatusCodes.Status200OK)]
    public IActionResult GetTranscriptCredential()
    {
        var metadata = new VctTypeMetadata
        {
            Vct         = $"{BASE}/credentials/TranscriptCredential",
            Name        = "TranscriptCredential",
            Description = "Academic transcript issued by an educational institution",
            Display =
            [
                new()
                {
                    Lang        = "th",
                    Name        = "ใบแสดงผลการเรียน",
                    Description = "ใบแสดงผลการเรียนที่ออกโดยสถาบันการศึกษา",
                    Rendering   = new()
                    {
                        Simple = new()
                        {
                            Logo            = new() { Uri = $"{BASE}/assets/transcript-logo.png", AltText = "Transcript Logo" },
                            BackgroundColor = "#1a3c6e",
                            TextColor       = "#ffffff",
                        }
                    }
                },
                new() { Lang = "en", Name = "Academic Transcript" }
            ],
            Claims =
            [
                Claim("student_id",       mandatory: true,  sd: true,  th: "รหัสนักศึกษา",       en: "Student ID"),
                Claim("full_name",        mandatory: true,  sd: true,  th: "ชื่อ-นามสกุล",       en: "Full Name"),
                Claim("faculty",          mandatory: true,  sd: true,  th: "คณะ / สาขาวิชา",      en: "Faculty / Major"),
                Claim("gpa",              mandatory: false, sd: true,  th: "เกรดเฉลี่ย",          en: "GPA"),
                //Claim("grades",           mandatory: false, sd: true,  th: "ผลการเรียน",          en: "Grades"),
                Claim("graduation_date",  mandatory: false, sd: true,  th: "วันสำเร็จการศึกษา",   en: "Graduation Date"),
                Claim("institution_name", mandatory: true,  sd: false, th: "ชื่อสถาบัน",          en: "Institution Name"),
                Claim("degree",           mandatory: true,  sd: true,  th: "วุฒิการศึกษา",        en: "Degree / Qualification"),
            ]
        };

        return Ok(metadata);
    }

    //[HttpGet("credentials/BootCampCredential")]
    //[HttpGet(".well-known/vct/credentials/BootCampCredential")]
    //[ProducesResponseType(typeof(VctTypeMetadata), StatusCodes.Status200OK)]
    //public IActionResult GetBootCampCredential()
    //{
    //    var metadata = new VctTypeMetadata
    //    {
    //        Vct = $"{BASE}/credentials/BootCampCredential",
    //        Name = "BootCampCredential",
    //        Description = "Academic transcript issued by an educational institution",
    //        Display =
    //        [
    //            new()
    //            {
    //                Lang        = "th",
    //                Name        = "ใบแสดงผลการเรียน",
    //                Description = "ใบแสดงผลการเรียนที่ออกโดยสถาบันการศึกษา",
    //                Rendering   = new()
    //                {
    //                    Simple = new()
    //                    {
    //                        Logo            = new() { Uri = $"{BASE}/assets/transcript-logo.png", AltText = "Transcript Logo" },
    //                        BackgroundColor = "#1a3c6e",
    //                        TextColor       = "#ffffff",
    //                    }
    //                }
    //            },
    //            new() { Lang = "en", Name = "BootCamp" }
    //        ],
    //        Claims =
    //        [
    //            Claim("student_id",       mandatory: true,  sd: true,  th: "รหัสนักศึกษา",       en: "Student ID"),
    //            Claim("full_name",        mandatory: true,  sd: true,  th: "ชื่อ-นามสกุล",       en: "Full Name"),
    //            Claim("faculty",          mandatory: true,  sd: true,  th: "คณะ / สาขาวิชา",      en: "Faculty / Major"),
    //            Claim("gpa",              mandatory: false, sd: true,  th: "เกรดเฉลี่ย",          en: "GPA"),
    //            //Claim("grades",           mandatory: false, sd: true,  th: "ผลการเรียน",          en: "Grades"),
    //            Claim("graduation_date",  mandatory: false, sd: true,  th: "วันสำเร็จการศึกษา",   en: "Graduation Date"),
    //            Claim("institution_name", mandatory: true,  sd: false, th: "ชื่อสถาบัน",          en: "Institution Name"),
    //            Claim("degree",           mandatory: true,  sd: true,  th: "วุฒิการศึกษา",        en: "Degree / Qualification"),
    //        ]
    //    };

    //    return Ok(metadata);
    //}

    [HttpGet("credentials/BootCampCredential")]
    [HttpGet(".well-known/vct/credentials/BootCampCredential")]
    public async Task<IActionResult> GetBootCampCredential()
    {
        try
        {
            // ใช้ path จาก options (App_Data/credential-configurations-supported.json)
            // Path.Combine รองรับทั้ง Windows (\) และ Linux/Mac (/) โดยอัตโนมัติ
            var configPath = Path.Combine(_env.ContentRootPath, _options.CredentialConfigurationsFile);

            if (!System.IO.File.Exists(configPath))
                return StatusCode(500, new { error = $"File not found: {configPath}" });

            var json = await System.IO.File.ReadAllTextAsync(configPath);
            var root = JsonNode.Parse(json);

            // credential-configurations-supported.json มี key อยู่ที่ root โดยตรง
            var configurations = root?.AsObject();
            if (configurations == null)
                return StatusCode(500, new { error = "Cannot parse credential-configurations-supported.json" });

            // หา BootCampCredential_dc+sd-jwt
            JsonNode? credentialConfig = null;
            foreach (var (key, value) in configurations)
            {
                if (key.Contains("BootCampCredential", StringComparison.OrdinalIgnoreCase)
                    && key.Contains("dc+sd-jwt", StringComparison.OrdinalIgnoreCase))
                {
                    credentialConfig = value;
                    break;
                }
            }


            if (credentialConfig == null)
                return NotFound(new { error = "BootCampCredential_dc+sd-jwt not found" });

            var claims = new List<ClaimMetadata>();
            var claimsNode = credentialConfig["claims"];

            // Object: { "fullname": { "mandatory": true, ... } }
            if (claimsNode is JsonObject claimsObj)
            {
                foreach (var (fieldName, fieldValue) in claimsObj)
                {
                    bool mandatory = fieldValue?["mandatory"]?.GetValue<bool>() ?? true;
                    bool sd = fieldValue?["sd"]?.GetValue<bool>() ?? true;

                    string th = fieldName;
                    string en = fieldName;

                    if (fieldValue?["display"] is JsonArray displayArr)
                    {
                        foreach (var d in displayArr)
                        {
                            string? locale = d?["locale"]?.GetValue<string>();
                            string? name = d?["name"]?.GetValue<string>();
                            if (name == null || name == "string") continue; // skip placeholder
                            if (locale == "th") th = name;
                            if (locale == "en") en = name;
                        }
                    }

                    claims.Add(Claim(fieldName, mandatory: mandatory, sd: sd, th: th, en: en));
                }
            }
            // Array: [ { "path": ["student_id"], ... } ]
            else if (claimsNode is JsonArray claimsArr)
            {
                foreach (var c in claimsArr)
                {
                    string path = "";
                    if (c?["path"] is JsonArray pathArr && pathArr.Count > 0)
                        path = pathArr[0]?.GetValue<string>() ?? "";

                    bool mandatory = c?["mandatory"]?.GetValue<bool>() ?? true;
                    bool sd = c?["sd"]?.GetValue<bool>() ?? true;

                    string th = path;
                    string en = path;

                    if (c?["display"] is JsonArray displayArr)
                    {
                        foreach (var d in displayArr)
                        {
                            string? locale = d?["locale"]?.GetValue<string>();
                            string? name = d?["name"]?.GetValue<string>();
                            if (name == null || name == "string") continue; // skip placeholder
                            if (locale == "th") th = name;
                            if (locale == "en") en = name;
                        }
                    }

                    claims.Add(Claim(path, mandatory: mandatory, sd: sd, th: th, en: en));
                }
            }

            var metadata = new VctTypeMetadata
            {
                Vct = $"{BASE}/credentials/BootCampCredential",
                Name = "BootCampCredential",
                Description = "BootCamp Credential",
                Display =
                [
                    new() { Lang = "en", Name = "BootCamp" },
                new() { Lang = "th", Name = "BootCamp" }
                ],
                Claims = claims
            };

            return Ok(metadata);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = ex.Message, stackTrace = ex.StackTrace });
        }
    }



    // ----------------------------------------------------------
    // GET /credentials/IDCard
    // ----------------------------------------------------------
    [HttpGet("credentials/IDCard")]
    [HttpGet(".well-known/vct/credentials/IDCard")]
    [ProducesResponseType(typeof(VctTypeMetadata), StatusCodes.Status200OK)]
    public IActionResult GetIDCard()
    {
        var metadata = new VctTypeMetadata
        {
            Vct         = $"{BASE}/credentials/IDCard",
            Name        = "IDCard",
            Description = "Thai national identity card",
            Display =
            [
                new()
                {
                    Lang        = "th",
                    Name        = "บัตรประชาชน",
                    Description = "บัตรประจำตัวประชาชนไทย",
                    Rendering   = new()
                    {
                        Simple = new()
                        {
                            Logo            = new() { Uri = $"{BASE}/assets/idcard-logo.png", AltText = "ID Card Logo" },
                            BackgroundColor = "#003580",
                            TextColor       = "#ffffff",
                        }
                    }
                },
                new() { Lang = "en", Name = "National ID Card" }
            ],
            Claims =
            [
                Claim("id_number",   mandatory: true,  sd: true,  th: "เลขบัตรประชาชน", en: "ID Number"),
                Claim("full_name",   mandatory: true,  sd: true,  th: "ชื่อ-นามสกุล",   en: "Full Name"),
                Claim("birthdate",   mandatory: true,  sd: true,  th: "วันเกิด",         en: "Date of Birth"),
                Claim("address",     mandatory: false, sd: false, th: "ที่อยู่",          en: "Address"),
                Claim("expiry_date", mandatory: true,  sd: true,  th: "วันหมดอายุ",      en: "Expiry Date"),
                Claim("nationality", mandatory: true,  sd: true,  th: "สัญชาติ",         en: "Nationality"),
                Claim("photo",       mandatory: false, sd: true,  th: "รูปถ่าย",          en: "Photo"),
            ]
        };

        return Ok(metadata);
    }

    // ----------------------------------------------------------
    // GET /credentials/Iso18013DriversLicenseCredential
    // ----------------------------------------------------------
    [HttpGet("credentials/Iso18013DriversLicenseCredential")]
    [HttpGet(".well-known/vct/credentials/Iso18013DriversLicenseCredential")]
    [ProducesResponseType(typeof(VctTypeMetadata), StatusCodes.Status200OK)]
    public IActionResult GetDriversLicense()
    {
        var metadata = new VctTypeMetadata
        {
            Vct         = $"{BASE}/credentials/Iso18013DriversLicenseCredential",
            Name        = "Iso18013DriversLicenseCredential",
            Description = "Thai driver's license (ISO 18013 compatible)",
            Display =
            [
                new()
                {
                    Lang        = "th",
                    Name        = "ใบขับขี่",
                    Description = "ใบอนุญาตขับรถ กรมการขนส่งทางบก",
                    Rendering   = new()
                    {
                        Simple = new()
                        {
                            Logo            = new() { Uri = $"{BASE}/assets/license-logo.png", AltText = "Driver License Logo" },
                            BackgroundColor = "#2e7d32",
                            TextColor       = "#ffffff",
                        }
                    }
                },
                new() { Lang = "en", Name = "Driver's License" }
            ],
            Claims =
            [
                Claim("license_number",     mandatory: true,  sd: true,  th: "เลขใบขับขี่",       en: "License Number"),
                Claim("full_name",          mandatory: true,  sd: true,  th: "ชื่อ-นามสกุล",      en: "Full Name"),
                Claim("birthdate",          mandatory: true,  sd: true,  th: "วันเกิด",            en: "Date of Birth"),
                Claim("address",            mandatory: false, sd: true,  th: "ที่อยู่",             en: "Address"),
                Claim("license_class",      mandatory: true,  sd: true,  th: "ประเภทใบขับขี่",     en: "License Class"),
                Claim("issue_date",         mandatory: true,  sd: false, th: "วันที่ออกใบขับขี่",  en: "Issue Date"),
                Claim("expiry_date",        mandatory: true,  sd: true,  th: "วันหมดอายุ",         en: "Expiry Date"),
                Claim("vehicle_categories", mandatory: false, sd: false, th: "ประเภทยานพาหนะ",    en: "Vehicle Categories"),
            ]
        };

        return Ok(metadata);
    }

    

    // ── helper: แปลง JsonObject claims → List<ClaimMetadata> ─────────────────
    private static List<ClaimMetadata> ParseClaims(JsonObject claimsNode)
    {
        var result = new List<ClaimMetadata>();

        foreach (var (fieldName, claimNode) in claimsNode)
        {
            bool mandatory = claimNode?["mandatory"]?.GetValue<bool>() ?? true;
            bool sd = claimNode?["sd"]?.GetValue<bool>() ?? true;

            var displayList = new List<ClaimDisplayMetadata>();

            if (claimNode?["display"] is JsonArray displayArr)
            {
                foreach (var d in displayArr)
                {
                    string? locale = d?["locale"]?.GetValue<string>()
                                  ?? d?["lang"]?.GetValue<string>();
                    string? label = d?["name"]?.GetValue<string>()
                                  ?? d?["label"]?.GetValue<string>();

                    if (label != null)
                        displayList.Add(new ClaimDisplayMetadata
                        {
                            Lang = locale ?? "en",
                            Label = label
                        });
                }
            }

            // fallback ถ้าไม่มี display
            if (displayList.Count == 0)
                displayList.Add(new ClaimDisplayMetadata { Lang = "en", Label = fieldName });

            result.Add(new ClaimMetadata
            {
                Path = new List<string> { fieldName },
                Mandatory = mandatory,
                Sd = sd,
                Display = displayList
            });
        }

        return result;
    }

    // ── helper: อ่าน claims จาก credential-configurations-supported.json ─────
    private async Task<JsonObject?> LoadClaimsFromConfig(string credentialTypeKey)
    {
        string path = Path.Combine(_env.ContentRootPath, _options.CredentialConfigurationsFile);
        if (!System.IO.File.Exists(path)) return null;

        string json = await System.IO.File.ReadAllTextAsync(path);
        var config = JsonNode.Parse(json)?.AsObject();
        return config?[credentialTypeKey]?["claims"]?.AsObject();
    }

    // ----------------------------------------------------------
    // Helper — สร้าง ClaimMetadata แบบ bilingual (th + en)
    // ----------------------------------------------------------
    private static ClaimMetadata Claim(
    string path,
    bool mandatory,
    bool sd,
    string th,
    string en) => new()
    {
        Path = new List<string> { path },  // ← แค่บรรทัดนี้
        Mandatory = mandatory,
        Sd = sd,
        Display =
    [
        new ClaimDisplayMetadata { Lang = "th", Label = th },
        new ClaimDisplayMetadata { Lang = "en", Label = en },
    ]
    };
}
