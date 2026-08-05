using IssuerAPI.Services;
//using Microsoft.IdentityModel.Protocols;
////using Microsoft.IdentityModel.Protocols.OpenIdConnect;
//using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
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
        public async Task<ThaIDSystemTokenResponse> GetSystemTokenAsync()
        {
            string url = $"{ThaIDConfig.GatewayBaseUrl}/api/v1/Token";

            var payload = new ThaIDSystemTokenRequest
            {
                ClientId = ThaIDConfig.ClientID,
                ClientSecret = ThaIDConfig.ClientSecret
            };

            string json = JsonConvert.SerializeObject(payload);

            using (var request = new HttpRequestMessage(HttpMethod.Post, url))
            {
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.SendAsync(request);
                string responseBody = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    log.LogError($"GetSystemToken Error [{(int)response.StatusCode}]: {responseBody}");
                    throw new Exception($"GetSystemToken Error [{(int)response.StatusCode}]: {responseBody}");
                }

                log.LogInformation("GetSystemToken response => " + responseBody);
                return JsonConvert.DeserializeObject<ThaIDSystemTokenResponse>(responseBody);
            }
        }

        // -------------------------------------------------------
        // Gateway (.155) : Check State (ได้ PID + citizen data กลับมา)
        // POST https://161.200.200.155/api/v1/ThaID
        // Authorization = access_token จาก GetSystemTokenAsync (raw token ไม่มี "Bearer " prefix)
        // -------------------------------------------------------
        public async Task<ThaIDCheckStateResponse> CheckStateAsync(string state, string systemAccessToken)
        {
            string url = $"{ThaIDConfig.GatewayBaseUrl}/api/v1/ThaID";

            var payload = new ThaIDCheckStateRequest { State = state };
            string json = JsonConvert.SerializeObject(payload);

            using (var request = new HttpRequestMessage(HttpMethod.Post, url))
            {
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.TryAddWithoutValidation("Authorization", systemAccessToken);
                request.Content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.SendAsync(request);
                string responseBody = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    log.LogError($"CheckState Error [{(int)response.StatusCode}]: {responseBody}");
                    throw new Exception($"CheckState Error [{(int)response.StatusCode}]: {responseBody}");
                }

                log.LogInformation("CheckState response => " + responseBody);
                return JsonConvert.DeserializeObject<ThaIDCheckStateResponse>(responseBody);
            }
        }

        // -------------------------------------------------------
        // Helper : ดึง citizenId จาก CheckState response
        // -------------------------------------------------------
        public string GetCitizenId(ThaIDCheckStateResponse stateResult)
        {
            return stateResult?.PID;
        }
    }
}
