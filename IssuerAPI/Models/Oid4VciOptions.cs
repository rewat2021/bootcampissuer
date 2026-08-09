namespace IssuerAPI.Models
{
    public class Oid4VciOptions
    {
        public string ParPath { get; set; } = "/par";
        public string CredentialPath { get; set; } = "/credential";
        public string BatchCredentialPath { get; set; } = "/batch_credential";
        public string DeferredCredentialPath { get; set; } = "/credential_deferred";
        public string CredentialConfigurationsFile { get; set; } = "App_Data/credential-configurations-supported.json";

        // H-11: explicit, configured issuer identifier (appsettings.json: Oid4Vci:CredentialIssuerIdentifier).
        // Falls back to X-Forwarded-Proto/Host (behind trusted reverse proxy only, see Program.cs) when unset.
        public string? CredentialIssuerIdentifier { get; set; }
    }
}
