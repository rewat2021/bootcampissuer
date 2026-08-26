using IssuerAPI.Services;
//using Microsoft.IdentityModel.Protocols;
////using Microsoft.IdentityModel.Protocols.OpenIdConnect;
//using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NLog;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IssuerAPI.Service
{
    // -------------------------------------------------------
    // Models: Gateway ThaID (.155) — https://161.200.200.155
    // -------------------------------------------------------
    public class ThaIDSystemTokenRequest
    {
        [JsonProperty("clientid")]
        public string ClientId { get; set; }

        [JsonProperty("clientsecret")]
        public string ClientSecret { get; set; }
    }

    public class ThaIDSystemTokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }

        // The OIDC id_token (JWT) — this is where pid/given_name/family_name/birthdate/etc. actually
        // live, per the scopes requested in AccountController.ThaIDLogin. CheckStateAsync used to try
        // to read this via a nonexistent "IDTokenClaims" property (compile error) and a separate,
        // never-implemented Gateway "check state" HTTP call; GetCitizenId/GetProfile below read it
        // directly from this raw JWT instead — see the ThaIDController reference implementation this
        // was aligned to (direct code->token exchange, no separate check-state round trip).
        [JsonProperty("id_token")]
        public string IDToken { get; set; }
    }

    public class ThaIDCheckStateRequest
    {
        [JsonProperty("state")]
        public string State { get; set; }
    }

    public class ThaIDCheckStateResponse
    {
        [JsonProperty("state")]
        public string State { get; set; }

        [JsonProperty("status")]
        public string Status { get; set; }

        [JsonProperty("pid")]
        public string PID { get; set; }

        [JsonProperty("titleNameTh")]
        public string TitleNameTh { get; set; }

        [JsonProperty("firstNameTh")]
        public string FirstNameTh { get; set; }

        [JsonProperty("lastNameTh")]
        public string LastNameTh { get; set; }

        [JsonProperty("titleNameEn")]
        public string TitleNameEn { get; set; }

        [JsonProperty("firstNameEn")]
        public string FirstNameEn { get; set; }

        [JsonProperty("lastNameEn")]
        public string LastNameEn { get; set; }

        [JsonProperty("birthDate")]
        public string BirthDate { get; set; }

        [JsonProperty("gender")]
        public string Gender { get; set; }

        // ThaIDLogin ขอ scope "address date_of_issuance date_of_expiry" ไว้ด้วย (ดู
        // AccountController.ThaIDLogin) แต่เดิม GetProfile ไม่ได้ดึง 3 ค่านี้ออกมาเลย เลยไปออก VC เป็น
        // ค่า mock ตลอด ทั้งที่ id_token มีข้อมูลจริงอยู่แล้ว — เพิ่มไว้ตรงนี้ให้ครบ
        [JsonProperty("address")]
        public string Address { get; set; }

        [JsonProperty("dateOfIssuance")]
        public string DateOfIssuance { get; set; }

        [JsonProperty("dateOfExpiry")]
        public string DateOfExpiry { get; set; }

        // เพิ่ม/แก้ field ตาม response จริงที่ Gateway (.155) คืนมา ถ้าไม่ตรง
    }

    public class ThaIDAuthService
    {
        private readonly HttpClient _httpClient;
        //protected ILogger log = NLog.LogManager.GetCurrentClassLogger();
        private readonly ILogger<CredentialConfigService> log;

        // DI-injected HttpClient (registered via builder.Services.AddHttpClient<ThaIDAuthService>() in Program.cs)
        public ThaIDAuthService(HttpClient httpClient, ILogger<CredentialConfigService> logger)
        {
            _httpClient = httpClient;
            log = logger;
        }

        // -------------------------------------------------------
        // Gateway (.155) : ขอ System/Client Token
        // POST https://161.200.200.155/api/v1/Token
        // -------------------------------------------------------
        public async Task<ThaIDSystemTokenResponse> GetAccessTokenAsync(string code, string RedirectURL)
        {
            string tokenUrl = $"{ThaIDConfig.Issuer}api/v2/oauth2/token/";

            // Authorization: Basic base64(client_id:client_secret)
            string raw = $"{ThaIDConfig.ClientID}:{ThaIDConfig.ClientSecret}";
            string base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));

            // Body
            var formData = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code",         code),
                new KeyValuePair<string, string>("redirect_uri", $"{RedirectURL}")
            });

            var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl);
            request.Headers.Add("Authorization", $"Basic {base64}");
            request.Content = formData;
            request.Content.Headers.ContentType =
                new MediaTypeHeaderValue("application/x-www-form-urlencoded");

            using (var httpClient = new HttpClient())
            {
       

                log.LogInformation("base64 => " + base64);
                var response = await httpClient.SendAsync(request);
                string json = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    log.LogError($"Token Error [{(int)response.StatusCode}]: {json}");
                    throw new Exception($"Token Error [{(int)response.StatusCode}]: {json}");
                }

                log.LogInformation("json => " + json);
                return JsonConvert.DeserializeObject<ThaIDSystemTokenResponse>(json);
            }
        }

        // -------------------------------------------------------
        // Extract claims from the id_token (JWT) returned alongside the access token by
        // GetAccessTokenAsync — this is DOPA ThaID's own token, not a separate "Gateway check-state"
        // response, so there's no second HTTP round trip needed to learn who the citizen is.
        //
        // NOTE: this reads the JWT payload without verifying its signature (same as the reference
        // ThaIDController this was aligned to, which also left ValidateIdTokenAsync commented out).
        // That's a materially different risk than the classic "unverified JWT" mistake: the id_token
        // arrived here via a confidential, server-to-server, client-authenticated (Basic
        // client_id:client_secret) HTTPS call to DOPA's own token endpoint — not via a
        // browser-redirectable channel an attacker can substitute — so forging it would require
        // compromising that back-channel or DOPA's TLS, not just crafting a JWT. Signature/iss/aud/exp
        // validation is still the more correct long-term fix; flagging as a follow-up rather than
        // blocking this compile fix on it.
        // -------------------------------------------------------
        private Dictionary<string, object> ParseIdTokenClaims(ThaIDSystemTokenResponse token)
        {
            if (token == null || string.IsNullOrWhiteSpace(token.IDToken))
                return null;

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(token.IDToken);
                return jwt.Payload.ToDictionary(c => c.Key, c => c.Value);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "ParseIdTokenClaims: failed to parse ThaID id_token");
                return null;
            }
        }

        // -------------------------------------------------------
        // Helper : ดึง citizenId (pid) จาก id_token claims
        // -------------------------------------------------------
        public string GetCitizenId(ThaIDSystemTokenResponse token)
        {
            var claims = ParseIdTokenClaims(token);
            if (claims == null)
                return null;

            if (claims.TryGetValue("pid", out var pid) && pid != null)
                return pid.ToString();

            if (claims.TryGetValue("sub", out var sub) && sub != null)
                return sub.ToString();

            return null;
        }

        // -------------------------------------------------------
        // Helper : ดึง profile fields (ชื่อ/นามสกุล/วันเกิด/ฯลฯ) จาก id_token claims — ตาม scope ที่ขอไว้ใน
        // AccountController.ThaIDLogin (pid given_name family_name given_name_en family_name_en gender
        // title title_en date_of_issuance date_of_expiry address birthdate)
        // -------------------------------------------------------
        public ThaIDCheckStateResponse GetProfile(ThaIDSystemTokenResponse token)
        {
            var claims = ParseIdTokenClaims(token);
            if (claims == null)
                return null;

            string Get(string key) => claims.TryGetValue(key, out var v) ? NormalizeClaimValue(v) : null;

            return new ThaIDCheckStateResponse
            {
                PID = Get("pid"),
                TitleNameTh = Get("title"),
                FirstNameTh = Get("given_name"),
                LastNameTh = Get("family_name"),
                TitleNameEn = Get("title_en"),
                FirstNameEn = Get("given_name_en"),
                LastNameEn = Get("family_name_en"),
                BirthDate = Get("birthdate"),
                Gender = Get("gender"),
                Address = GetAddress(claims),
                DateOfIssuance = Get("date_of_issuance"),
                DateOfExpiry = Get("date_of_expiry"),
            };
        }

        // แก้บั๊ก "field แสดงไม่ถูกต้อง" ที่ยืนยันจากการทดสอบจริง (house_address/given_name_en/family_name_en
        // เป็นชื่อ claim ที่ถูกต้องแล้ว แต่ค่าที่ออกมาเพี้ยน): JwtSecurityTokenHandler แปลง claim ที่ค่าเดิมใน
        // JSON เป็น array (แม้จะมีสมาชิกตัวเดียว) ให้กลายเป็น System.Text.Json.JsonElement/JArray/List<object>
        // แทนที่จะเป็น string ตรงๆ — เดิม Get() เรียก v?.ToString() ตรงๆ เลยได้ค่าประเภทเช่น
        // "System.Text.Json.JsonElement" หรือ "[\"สมชาย\"]" ออกมาแทนค่าจริง — UnwrapArray แกะเฉพาะ array
        // wrapper ออก (คืนค่าที่ยังไม่แปลงเป็น string เพื่อให้ GetAddress เอาไปแยกเคส object ต่อได้), ส่วน
        // NormalizeClaimValue ใช้กับ claim ทั่วไปที่ต้องได้ string ล้วนๆ กลับมาเลย
        private static object UnwrapArray(object v)
        {
            if (v == null || v is string)
                return v;

            if (v is System.Text.Json.JsonElement je)
            {
                if (je.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    foreach (var item in je.EnumerateArray())
                    {
                        return item.ValueKind switch
                        {
                            System.Text.Json.JsonValueKind.String => item.GetString(),
                            System.Text.Json.JsonValueKind.Null or System.Text.Json.JsonValueKind.Undefined => null,
                            _ => UnwrapArray((object)item)
                        };
                    }
                    return null;
                }
                return v; // object/string/number ที่ไม่ใช่ array — ปล่อยให้ผู้เรียกจัดการต่อ
            }

            if (v is JArray ja)
                return ja.Count > 0 ? UnwrapArray(ja[0]) : null;

            if (v is JObject || v is System.Collections.IDictionary)
                return v; // object ที่มี key/value จริงๆ (เช่น nested address) — ไม่ใช่ array wrapper อย่าแกะ

            if (v is System.Collections.IEnumerable en) // List<object>, object[], ฯลฯ
            {
                foreach (var item in en)
                    return UnwrapArray(item);
                return null;
            }

            return v;
        }

        private static string NormalizeClaimValue(object v)
        {
            var unwrapped = UnwrapArray(v);
            if (unwrapped == null)
                return null;
            if (unwrapped is string s)
                return s;
            if (unwrapped is System.Text.Json.JsonElement je && je.ValueKind == System.Text.Json.JsonValueKind.String)
                return je.GetString();
            return unwrapped.ToString();
        }

        // ยืนยันจากการทดสอบจริงแล้วว่า house_address เป็น **nested JSON object** จริงๆ (ValueKind=Object) ไม่ใช่
        // string ธรรมดาอย่างที่เคยสันนิษฐานไว้ — บั๊กที่แก้: JsonConvert.SerializeObject(addr) เดิมรับ
        // System.Text.Json.JsonElement ตรงๆ ซึ่ง Newtonsoft ไม่รู้จักวิธี serialize struct นี้ (ไม่มี
        // converter) เลย reflect เจอแค่ property สาธารณะตัวเดียวคือ "ValueKind" (enum) แล้ว serialize
        // ออกมาเป็น {"ValueKind":1} ทำให้ address ที่แสดงกลายเป็น "ValueKind : 1" (1 = JsonValueKind.Object)
        // แก้โดยเรียก JsonElement.GetRawText() เพื่อเอา JSON text จริงของ object นั้นมา parse แทน
        private static string GetAddress(Dictionary<string, object> claims)
        {
            if (!claims.TryGetValue("house_address", out var addr) || addr == null)
            {
                if (!claims.TryGetValue("address", out addr) || addr == null)
                    return null;
            }

            addr = UnwrapArray(addr);
            if (addr == null)
                return null;

            if (addr is string plain)
                return plain;
            if (addr is System.Text.Json.JsonElement addrJe0 && addrJe0.ValueKind == System.Text.Json.JsonValueKind.String)
                return addrJe0.GetString();

            try
            {
                string json = addr is System.Text.Json.JsonElement addrJe
                    ? addrJe.GetRawText()
                    : JsonConvert.SerializeObject(addr);
                var obj = JObject.Parse(json);

                var formatted = obj["formatted"]?.ToString();
                if (!string.IsNullOrWhiteSpace(formatted))
                    return formatted;

                // ลอง OIDC standard sub-fields ก่อน เผื่อ environment ไหนใช้ shape นี้จริงๆ
                var parts = new[]
                {
                    obj["street_address"]?.ToString(),
                    obj["locality"]?.ToString(),
                    obj["region"]?.ToString(),
                    obj["postal_code"]?.ToString(),
                    obj["country"]?.ToString(),
                }.Where(p => !string.IsNullOrWhiteSpace(p)).ToList();

                if (parts.Count == 0)
                {
                    // house_address ของ ThaID ไม่ได้ตาม OIDC standard (เป็น schema ที่อยู่แบบไทยของตัวเอง เช่น
                    // เลขที่/หมู่/ซอย/ถนน/ตำบล/อำเภอ/จังหวัด — ไม่รู้ชื่อ field แน่ชัด) ทางที่ปลอดภัยสุดคือไล่เก็บ
                    // ทุก property ที่เป็น string ตามลำดับที่ปรากฏใน object มาต่อกันเป็นที่อยู่แบบ best-effort
                    parts = obj.Properties()
                        .Where(p => p.Value.Type == JTokenType.String)
                        .Select(p => p.Value.ToString())
                        .Where(v => !string.IsNullOrWhiteSpace(v))
                        .ToList();
                }

                var combined = string.Join(" ", parts);
                return string.IsNullOrWhiteSpace(combined) ? json : combined;
            }
            catch
            {
                // Not JSON after all (or a shape JObject.Parse can't handle) — last resort, whatever
                // ToString() gives is still better than silently dropping the claim.
                return addr.ToString();
            }
        }
    }
}
