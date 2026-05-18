using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using static IssuerAPI.Controllers.IssuerController;
using static IssuerAPI.Models.grant;

namespace IssuerAPI.Models
{
    public class GenerateQrRequest
    {
        public DocumentType DocumentType { get; set; }
    }

    public class Grants
    {
        [JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code")]
        public PreAuthorizedCodeGrantType? UrnIetfParamsOauthGrantTypePreAuthorizedCode { get; set; } = null;
        public AuthorizationCode? authorization_code { get; set; } = null;
    }

    public class AuthorizationCode
    {
        public string? issuer_state { get; set; }
        public string? authorization_server { get; set; }
    }

    public class PreAuthorizedCodeGrantType
    {
        [JsonProperty("pre-authorized_code")]
        public string? pre_authorized_code { get; set; }
        public TxCode? tx_code { get; set; }
    }

    public class TxCode
    {
        public int? length { get; set; }
        public string input_mode { get; set; } = string.Empty;
        public string description { get; set; } = string.Empty;
    }

    public class CredentialRequest
    {

        public string credential_issuer { get; set; }

        public List<string> credential_configuration_ids { get; set; }
        public string? credential_identifier { get; set; }

        public Grants? grants { get; set; } = new Grants();
    }

    public class AuthorizationRequest5_1_2
    {
        public string response_type { get; set; }
        public string type { get; set; }
        public string client_id { get; set; }
        public string? redirect_uri { get; set; }
        public string? scope { get; set; }
        public string? state { get; set; }
        public string? wallet_issuer { get; set; }
        public string? user_hint { get; set; }
        public string? issuer_state { get; set; }
    }

    public class AuthorizationRequest5_1_1
    {
        public string type { get; set; }
        public string? credential_configuration_id { get; set; }
        public string? format { get; set; }
    }

    public class AuthorizationResponse
    {
        public string code { get; set; }
        public string state { get; set; }
        public string? redirect_uri { get; set; }
    }

    public class TokenExchangeRequest
    {
        public string grant_type { get; set; }
        public string code { get; set; }
        public string redirect_uri { get; set; }
        public string client_id { get; set; }
    }

    public class TokenExchangePreAuthRequest
    {
        [FromForm(Name = "grant_type")]
        public string? GrantType { get; set; } = string.Empty;

        [FromForm(Name = "pre-authorized_code")]
        public string? PreAuthorizedCode { get; set; } = string.Empty;

        [FromForm(Name = "tx_code")]
        [JsonProperty("tx_code", NullValueHandling = NullValueHandling.Ignore)]
        public string? TxCode { get; set; } = string.Empty;
        

        //[FromForm(Name = "issu")]
        //public string? TxCode { get; set; } = string.Empty;
    }

    public class TokenExchangeResponse
    {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string? scope { get; set; }
        public string? state { get; set; }
        public AuthorizationDetails? authorization_details { get; set; }
    }

    public class AuthorizationDetails
    {
        public string type { get; set; }
        public string credential_configuration_id { get; set; }
        public List<string> credential_identifiers { get;}
    }

    public class IssuanceRequest
    {
        public string? credential_configuration_id { get; set; }//credential_identifier { get; set; }
        public Proof? proof { get; set; }
        //public string? format { get; set; }
       
        //public CredentialResponseEncryption? credential_response_encryption { get; set; }
    }

    public class IssueVcRequest
    {
        [JsonProperty("userId")]
        public string UserId { get; set; }

        [JsonProperty("proof")]
        public Proof Proof { get; set; }

        [JsonProperty("format")]
        public string format { get; set; }

        [JsonProperty("credential_definition")]
        public CredentialDefinitionDto CredentialDefinition { get; set; }
    }

    public class CredentialDefinitionDto
    {
        [JsonProperty("types")]
        public List<string> Types { get; set; }
    }
    public class Proof
    {
        public string proof_type { get; set; }
        public string jwt { get; set; }
    }

    public class CredentialResponseEncryption
    {
        public Jwk jwk { get; set; }
        public string alg { get; set; }
        public string enc { get; set; }
    }

    public class Jwk
    {
        public string kty { get; set; }
        public string use { get; set; }
        public string kid { get; set; }
    }

    public class IssuanceResponse
    {
        public string? credential { get; set; }
        public string? credentials { get; set; }
        public string? c_nonce { get; set; }
        public double? c_nonce_expires { get; set; }
        public string? notification_id { get; set; }
        public string? transaction_id { get; set; }
    }

    public class AuthorizationDetail
    {
        public List<string> type { get; set; }
        public string credential_configuration_id { get; set; }
        public List<string> credential_identifiers { get; set; }
    }

    public class TokenResponse
    {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string? c_nonce { get; set; }
        public int? c_nonce_expires_in { get; set; }
        public string? scope { get; set; }
        public string? state { get; set; }
        public List<AuthorizationDetail>? authorization_details { get; set; }
    }

    public class ApiLogs
    {
        public string message { get; set; }
        public int status { get; set; }
        public List<string> error { get; set; }
    }
    public class CredentialOffer
    {
        public string credential_issuer { get; set; }
        public List<string> credential_configuration_ids { get; set; }
        public grant grants { get; set; }

    }
    public class grant
    {
        public grant()
        {
            UrnIetfParamsOauthGrantTypePreAuthorizedCode = new grant_value();
            authorization_code = new Authorization_Code();
        }


        [JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code")]
        //[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public grant_value UrnIetfParamsOauthGrantTypePreAuthorizedCode { get; set; }
        public class grant_value
        {
            [JsonProperty("pre-authorized_code")]
            public string pre_authorized_code { get; set; }
        }
        public Authorization_Code authorization_code { get; set; }
        public class Authorization_Code
        {
            public string issuer_state { get; set; }
        }

    }

    public class TxtCode
    {
        public int length { get; set; }
        public string input_mode { get; set; }
        public string description { get; set; }
    }

    public class AuthorizedCode
    {
        [JsonProperty("sub")]
        public string Sub { get; set; }
        [JsonProperty("iss")]
        public string Iss { get; set; }
        [JsonProperty("aud")]
        public string Aud { get; set; }
    }

    public class AccessCode
    {
        public string RegisterId { get; set; }
        public string C_Nonce { get; set; }
        public string CredentialType { get; set; }
        public string authoriseCode { get; set; }
    }

    [System.Text.Json.Serialization.JsonConverter (typeof(JsonStringEnumConverter))]
    public enum DocumentType
    {
        Transcript,
        IdCard,
        DriverLicense,
        BootCamp
    }

    public class GenerateQrResponse
    {
        public object CredentialOffer { get; set; }
        public string CredentialOfferUri { get; set; }
        public string QrText { get; set; }
    }
}
