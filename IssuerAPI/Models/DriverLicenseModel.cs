using System.Text.Json.Serialization;

namespace IssuerAPI.Models
{
    public class DriverLicenseModel
    {
    }

    public class _JwtPayloadModelDrivingLicence
    {
        public _JwtPayloadModelDrivingLicence()
        {
            context = new List<string>
        {
            "https://www.w3.org/2018/credentials/v1",
            "https://openid.net/specs/openid4vci-1_0.html#context"
        };

            type = new List<string> { "VerifiableCredential", "DrivingLicenceCredential" };

            issuer = new issuer();                                   // ใช้ class issuer เดิมได้เลย
            credentialSubject = new _credentialSubjectDrivingLicence();
            credentialStatus = new CredentialStatus();                // ใช้ class เดิมได้เลย
            credentialSchema = new CredentialSchema();                // ใช้ class เดิมได้เลย
        }

        [JsonPropertyName(@"@context")]
        public List<string> context { get; set; }

        public string id { get; set; }
        public List<string> type { get; set; }
        public issuer issuer { get; set; }
        public string issuanceDate { get; set; }
        public string expirationDate { get; set; }
        public _credentialSubjectDrivingLicence credentialSubject { get; set; }

        public CredentialStatus credentialStatus { get; set; }
        public CredentialSchema credentialSchema { get; set; }
    }

    public class DrivingLicenceSubject
    {
        public string Id { get; set; }                          // wallet id (holder)
        public string FamilyName { get; set; }
        public string GivenName { get; set; }
        public string BirthDate { get; set; }
        public string IssueDate { get; set; }
        public string ExpiryDate { get; set; }
        public string IssuingCountry { get; set; }
        public string IssuingAuthority { get; set; }
        public string DocumentNumber { get; set; }
        public string Portrait { get; set; }
        public List<DrivingPrivilege> DrivingPrivileges { get; set; } = new();
        public string UnDistinguishingSign { get; set; }
        public string AdministrativeNumber { get; set; }
        public string Sex { get; set; }
        public int Height { get; set; }
        public int Weight { get; set; }
        public string EyeColour { get; set; }
        public string HairColour { get; set; }
        public string BirthPlace { get; set; }
        public string ResidentAddress { get; set; }
        public string ResidentCity { get; set; }
        public string ResidentState { get; set; }
        public string ResidentPostalCode { get; set; }
        public string ResidentCountry { get; set; }
        public string BiometricTemplate { get; set; }
        public string GivenNameNationalCharacter { get; set; }
        public string SignatureUsualMark { get; set; }
    }

    public class DrivingPrivilege
    {
        [JsonPropertyName("category")]
        public string Category { get; set; }

        [JsonPropertyName("restrictions")]
        public List<string> Restrictions { get; set; } = new();

        [JsonPropertyName("conditions")]
        public List<string> Conditions { get; set; } = new();
    }

    public class _credentialSubjectDrivingLicence
    {
        public string id { get; set; }   // wallet id (holder)

        [JsonPropertyName("family_name")]
        public string FamilyName { get; set; }

        [JsonPropertyName("given_name")]
        public string GivenName { get; set; }

        [JsonPropertyName("birth_date")]
        public string BirthDate { get; set; }

        [JsonPropertyName("issue_date")]
        public string IssueDate { get; set; }

        [JsonPropertyName("expiry_date")]
        public string ExpiryDate { get; set; }

        [JsonPropertyName("issuing_country")]
        public string IssuingCountry { get; set; }

        [JsonPropertyName("issuing_authority")]
        public string IssuingAuthority { get; set; }

        [JsonPropertyName("document_number")]
        public string DocumentNumber { get; set; }

        [JsonPropertyName("portrait")]
        public string Portrait { get; set; }

        [JsonPropertyName("driving_privileges")]
        public List<DrivingPrivilege> DrivingPrivileges { get; set; } = new();

        [JsonPropertyName("un_distinguishing_sign")]
        public string UnDistinguishingSign { get; set; }

        [JsonPropertyName("administrative_number")]
        public string AdministrativeNumber { get; set; }

        [JsonPropertyName("sex")]
        public string Sex { get; set; }

        [JsonPropertyName("height")]
        public int Height { get; set; }

        [JsonPropertyName("weight")]
        public int Weight { get; set; }

        [JsonPropertyName("eye_colour")]
        public string EyeColour { get; set; }

        [JsonPropertyName("hair_colour")]
        public string HairColour { get; set; }

        [JsonPropertyName("birth_place")]
        public string BirthPlace { get; set; }

        [JsonPropertyName("resident_address")]
        public string ResidentAddress { get; set; }

        [JsonPropertyName("resident_city")]
        public string ResidentCity { get; set; }

        [JsonPropertyName("resident_state")]
        public string ResidentState { get; set; }

        [JsonPropertyName("resident_postal_code")]
        public string ResidentPostalCode { get; set; }

        [JsonPropertyName("resident_country")]
        public string ResidentCountry { get; set; }

        [JsonPropertyName("biometric_template")]
        public string BiometricTemplate { get; set; }

        [JsonPropertyName("given_name_national_character")]
        public string GivenNameNationalCharacter { get; set; }

        [JsonPropertyName("signature_usual_mark")]
        public string SignatureUsualMark { get; set; }
    }

    public class vcModelDrivingLicence
    {
        public string iss { get; set; }
        public string sub { get; set; }
        public _JwtPayloadModelDrivingLicence vc { get; set; }
        public string jti { get; set; }
        public long iat { get; set; }
        public long nbf { get; set; }
    }
}
