namespace IssuerAPI.Models
{
    public class Oid4VciOptions
    {
        public string ParPath { get; set; } = "/par";
        public string CredentialPath { get; set; } = "/credential";
        public string BatchCredentialPath { get; set; } = "/batch_credential";
        public string DeferredCredentialPath { get; set; } = "/credential_deferred";
        public string CredentialConfigurationsFile { get; set; } = "App_Data/credential-configurations-supported.json";
    }
}
