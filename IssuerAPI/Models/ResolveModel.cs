using Newtonsoft.Json;
using System.Text.Json.Serialization;

namespace IssuerAPI.Models
{
    public class JwtModel
    {
        public string Header { get; set; }
        public string Payload { get; set; }
        public string Signature { get; set; }
    }
    public class VPModel
    {
        public VPModel()
        {
            context = new List<string>();
            context.Add("https://www.w3.org/ns/did/v1");
            context.Add("https://w3id.org/security/suites/jws-2020/v1");

            type = new List<string>();
            type.Add("VerifiablePresentation");
            type.Add("TranscriptCredential");

            verifiableCredential = new JwtPayloadModel();
            proof = new proof();
        }
        [JsonPropertyName(@"@context")]
        public List<string> context { get; set; }
        public List<string> type { get; set; }
        public JwtPayloadModel verifiableCredential { get; set; }
        public proof proof { get; set; }

    }

    public class _VPModel
    {
        public _VPModel()
        {
            vp = new VPPayload();
            //proof = new proof();
        }

        public string sub { get; set; }
        public long nbf { get; set; }
        public long iat { get; set; }
        public string jti { get; set; }
        public string iss { get; set; }
        public string nonce { get; set; }
        public string aud { get; set; }

        public VPPayload vp { get; set; }

        //public proof proof { get; set; }
    }

    public class VPPayload
    {
        public VPPayload()
        {
            context = new List<string>();
            context.Add("https://www.w3.org/ns/did/v1");
            //context.Add("https://w3id.org/security/suites/jws-2020/v1");

            type = new List<string>();
            type.Add("VerifiablePresentation");
            //type.Add("TranscriptCredential");
            verifiableCredential = new List<string>();
        }

        [JsonPropertyName(@"@context")]
        public List<string> context { get; set; }
        public List<string> type { get; set; }
        public string id { get; set; }
        public string holder { get; set; }
        public List<string> verifiableCredential { get; set; }
    }
    public class JwtPayloadModel
    {
        public JwtPayloadModel()
        {
            context = new List<string>();
            context.Add("https://www.w3.org/ns/credentials/v2");
            context.Add("https://www.w3.org/ns/credentials/examples/v2");

            type = new List<string>();
            type.Add("VerifiableCredential");
            type.Add("TranscriptCredential");

            proof = new proof();
            /*proof.type = "EdDSA";
            proof.proofPurpose = "assertionMethod";*/

            issuer = new issuer();
            credentialSubject = new credentialSubject();
        }
        [JsonPropertyName(@"@context")]
        public List<string> context { get; set; }

        public string id { get; set; }
        public List<string> type { get; set; }
        public issuer issuer { get; set; }
        public string issuanceDate { get; set; }
        public string expireDate { get; set; }
        public credentialSubject credentialSubject { get; set; }
        public proof proof { get; set; }
    }
    

    public class JwtPayloadNewTonModel
    {
        public JwtPayloadNewTonModel()
        {
            context = new List<string>();
            context.Add("https://www.w3.org/ns/credentials/v2");
            context.Add("https://www.w3.org/ns/credentials/examples/v2");

            type = new List<string>();
            type.Add("VerifiableCredential");
            type.Add("TranscriptCredential");

            proof = new proof();
            /*proof.type = "EdDSA";
            proof.proofPurpose = "assertionMethod";*/

            issuer = new issuer();
            credentialSubject = new credentialSubject();
        }
        /*[JsonPropertyName(@"@context")]*/
        [JsonProperty(PropertyName = @"@context")]
        public List<string> context { get; set; }

        public string id { get; set; }
        public List<string> type { get; set; }
        public issuer issuer { get; set; }
        public string issuanceDate { get; set; }
        public string expireDate { get; set; }
        public credentialSubject credentialSubject { get; set; }
        public proof proof { get; set; }
    }
    public class proof
    {
        public string type { get; set; }
        public string created { get; set; }
        public string proofPurpose { get; set; }
        public string verificationMethod { get; set; }
        public string jws { get; set; }
    }
    public class issuer
    {
        public string id { get; set; }
        public string name { get; set; }
    }
    public class credentialSubject
    {
        public string id { get; set; }
        public string student { get; set; }
        public string gpa { get; set; }
    }

    public class DIDDocModel
    {
        public DIDDocModel()
        {
            context = "https://www.context.org";
            verificationMethod = new List<verificationMethod>();
            assertionMethod = new List<string>();
        }

        [JsonPropertyName(@"@context")]
        public string context { get; set; }
        public string id { get; set; }
        public List<verificationMethod> verificationMethod { get; set; }
        public List<string> assertionMethod { get; set; }

    }
    public class verificationMethod
    {
        public verificationMethod()
        {
            publicKeyJwk = new publicKeyJwk();
        }
        public string id { set; get; }
        public string type { set; get; }
        public publicKeyJwk publicKeyJwk { set; get; }
    }
    public class publicKeyJwk
    {
        public publicKeyJwk()
        {
            kty = "OKP";
            crv = "Ed25519";
            alg = "EdDSA";
        }
        public string kty { set; get; }
        public string crv { set; get; }
        /*public string x { set; get; }
            
        public string y { set; get; }*/
        public string alg { set; get; }
    }

    public class VerifiablePresentation
    {
        [JsonPropertyName("@context")]
        public List<string> Context { get; set; }

        [JsonPropertyName("type")]
        public List<string> Type { get; set; }

        [JsonPropertyName("id")]
        public string Id { get; set; }

        [JsonPropertyName("holder")]
        public string Holder { get; set; }

        [JsonPropertyName("verifiableCredential")]
        public List<string> VerifiableCredential { get; set; }
    }

    public class Root
    {
        [JsonPropertyName("sub")]
        public string Sub { get; set; }

        [JsonPropertyName("nbf")]
        public long Nbf { get; set; }

        [JsonPropertyName("iat")]
        public long Iat { get; set; }

        [JsonPropertyName("jti")]
        public string Jti { get; set; }

        [JsonPropertyName("iss")]
        public string Iss { get; set; }

        [JsonPropertyName("nonce")]
        public string Nonce { get; set; }

        [JsonPropertyName("aud")]
        public string Aud { get; set; }

        [JsonPropertyName("vp")]
        public VerifiablePresentation Vp { get; set; }
    }

}