using IssuerAPI.Models;
using Newtonsoft.Json;
using System.Text.Json.Serialization;


namespace IssuerAPI.Models
{

    public class _JwtPayloadModel
    {
        public _JwtPayloadModel()
        {
            context = new List<string>();
            context.Add("https://www.w3.org/ns/credentials/v2");
            context.Add("https://www.w3.org/ns/credentials/examples/v2");

            type = new List<string>();
            type.Add("VerifiableCredential");
            type.Add("TranscriptCredential");



            issuer = new issuer();
            credentialSubject = new _credentialSubject();
            credentialStatus = new CredentialStatus();
            credentialSchema = new CredentialSchema();
        }

        [JsonPropertyName(@"@context")]
        public List<string> context { get; set; }

        public string id { get; set; }
        public List<string> type { get; set; }
        public issuer issuer { get; set; }
        public string issuanceDate { get; set; }
        //public string expireDate { get; set; }
        public _credentialSubject credentialSubject { get; set; }

        public CredentialStatus credentialStatus { get; set; }
        public CredentialSchema credentialSchema { get; set; }

    }
    //public class JwtPayloadNewTonModel
    //{
    //    public JwtPayloadNewTonModel()
    //    {
    //        context = new List<string>();
    //        context.Add("https://www.w3.org/ns/credentials/v2");
    //        context.Add("https://www.w3.org/ns/credentials/examples/v2");

    //        type = new List<string>();
    //        type.Add("VerifiableCredential");
    //        type.Add("TranscriptCredential");

    //        proof = new proof();
    //        /*proof.type = "EdDSA";
    //        proof.proofPurpose = "assertionMethod";*/

    //        issuer = new issuer();
    //        credentialSubject = new credentialSubject();
    //        credentialStatus = new CredentialStatus();
    //        credentialSchema = new CredentialSchema();
    //    }
    //    /*[JsonPropertyName(@"@context")]*/
    //    [JsonProperty(PropertyName = @"@context")]
    //    public List<string> context { get; set; }

    //    public string id { get; set; }
    //    public List<string> type { get; set; }
    //    public issuer issuer { get; set; }
    //    public string issuanceDate { get; set; }
    //    public string expireDate { get; set; }
    //    public credentialSubject credentialSubject { get; set; }
    //    public proof proof { get; set; }

    //    public CredentialStatus credentialStatus { get; set; }
    //    public CredentialSchema credentialSchema { get; set; }
    //}
}
//public class proof
//{
//    public string type { get; set; }
//    public string created { get; set; }
//    public string proofPurpose { get; set; }
//    public string verificationMethod { get; set; }
//    public string jws { get; set; }
//}
public class issuer
{
    public string id { get; set; }
    public string name { get; set; }
}
public class _credentialSubject
{
    //[JsonProperty(PropertyName = @"@context")]
    [JsonPropertyName("@context")]
    public List<Object> context { get; set; }
    public string id { get; set; }
    // public string student { get; set; }
    // public string gpa { get; set; }

    [JsonPropertyName("teda:documentContext")]
    public DocumentContextDetail documentContext { get; set; }

    [JsonPropertyName("teda:documentInformation")]
    public TedaDocumentInformation tedadocumentInformation { get; set; }

    [JsonPropertyName("educationalOrganization")]
    public OrganizationDetails educationalOrganization { get; set; }

    //[JsonProperty(PropertyName = @"teda:student")]
    [JsonPropertyName("teda:student")]
    public TedaStudent tedastudent { get; set; }

    public CourseList courseList { get; set; }

    [JsonPropertyName("teda:academicSummary")]
    public AcademicSummaryDetails academicSummary { get; set; }

    public List<AdditionalInformation> additionalInformation { get; set; }


    public _credentialSubject()
    {
        context = new List<Object> {
         "http://schema.org/",
          new ContextMapping{   Schema = "http://schema.org" },
          new ContextETDA{  TedaSchema = "https://schemas-uat.teda.th/teda/teda-objects/common/verified-credential/transcript/schema/" }
        };

        //context.Add("http://schema.org/");
        //context.Add("https://schemas-uat.teda.th/teda/teda-objects/common/verified-credential/transcript/schema/");

        documentContext = new DocumentContextDetail();

        tedadocumentInformation = new TedaDocumentInformation();

        tedastudent = new TedaStudent();

        educationalOrganization = new OrganizationDetails();

        courseList = new CourseList();

        academicSummary = new AcademicSummaryDetails();

        additionalInformation = new List<AdditionalInformation>();
    }

}

public class ContextMapping
{

    [JsonPropertyName("sch")]
    public string Schema { get; set; }


}
public class ContextETDA
{
    [JsonPropertyName("teda")]
    public string TedaSchema { get; set; }
}

public class Identifier
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("value")]
    public string Value { get; set; }
}

public class IdentifierDocument
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }
    [JsonPropertyName("propertyID")]
    public string PropertyID { get; set; }
    [JsonPropertyName("value")]
    public string Value { get; set; }
}

#region DocumentContext

//public class DocumentContext
//{
//    [JsonPropertyName("teda:documentContext")]
//    public DocumentContextDetail ContextDetail { get; set; }
//}
public class DocumentContextDetail
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("identifier")]
    public List<Identifier> Identifiers { get; set; } // List of identifiers

    [JsonPropertyName("schemaVersion")]
    public string SchemaVersion { get; set; }

    [JsonPropertyName("author")]
    public Author Author { get; set; }

    // Constructor to initialize the Identifier list
    public DocumentContextDetail()
    {
        Identifiers = new List<Identifier>();
    }
}

//public class Identifier
//{
//    [JsonPropertyName("@type")]
//    public string Type { get; set; }

//    [JsonPropertyName("name")]
//    public string Name { get; set; }

//    [JsonPropertyName("value")]
//    public string Value { get; set; }
//}

public class Author
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }
}

#endregion

#region DocumentInformation
public class DocumentInformation
{

    public TedaDocumentInformation TedaDocumentInformation { get; set; }
}

public class TedaDocumentInformation
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }
    [JsonPropertyName("identifier")] 
    public IdentifierDocument Identifier { get; set; }
    [JsonPropertyName("name")]
    public string Name { get; set; }
    [JsonPropertyName("additionalType")]
    public string AdditionalType { get; set; }
    [JsonPropertyName("educationalUse")]
    public string EducationalUse { get; set; }
    [JsonPropertyName("datePublished")]
    public string DatePublished { get; set; }
    [JsonPropertyName("description")]
    public string Description { get; set; }
    [JsonPropertyName("inLanguage")]
    public Language InLanguage { get; set; }
}

public class Language
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }
    [JsonPropertyName("name")]
    public string Name { get; set; }
    [JsonPropertyName("alternateName")]
    public string AlternateName { get; set; }
}
#endregion

#region Student
//public class Student
//{
//    [JsonPropertyName("teda:student")]
//    public TedaStudent TedaStudent { get; set; }

//}

public class TedaStudent
{
    public TedaStudent()
    {
        ResidentCountryOrTerritory = new ResidentCountryOrTerritory();
        ProgramContext = new ProgramContext();
    }

    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("identifier")]
    public Identifier Identifier { get; set; }

    [JsonPropertyName("honorificPrefix")]
    public string HonorificPrefix { get; set; }

    [JsonPropertyName("givenName")]
    public string GivenName { get; set; }

    [JsonPropertyName("familyName")]
    public string FamilyName { get; set; }

    [JsonPropertyName("gender")]
    public string Gender { get; set; }

    [JsonPropertyName("birthDate")]
    public string BirthDate { get; set; }

    [JsonPropertyName("nationality")]
    public string Nationality { get; set; }

    [JsonPropertyName("image")]
    public string Image { get; set; }

    [JsonPropertyName("teda:residentCountryOrTerritory")]
    public ResidentCountryOrTerritory ResidentCountryOrTerritory { get; set; }

    [JsonPropertyName("teda:facultyName")]
    public string FacultyName { get; set; }

    [JsonPropertyName("teda:programContext")]
    public ProgramContext ProgramContext { get; set; }
}
public class ResidentCountryOrTerritory
{
    //[JsonPropertyName("teda:residentCountryOrTerritory")]
    //public string residentCountryOrTerritory { get;set; }

    [JsonPropertyName("@type")]
    public string Type { get; set; }
    public string addressCountry { get; set; }
    //


}

public class PostalAddress
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("streetAddress")]
    public string StreetAddress { get; set; }

    [JsonPropertyName("addressLocality")]
    public string AddressLocality { get; set; }

    [JsonPropertyName("addressRegion")]
    public string AddressRegion { get; set; }

    [JsonPropertyName("postalCode")]
    public string PostalCode { get; set; }

    [JsonPropertyName("addressCountry")]
    public string AddressCountry { get; set; }
}

public class ProgramContext
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("identifier")]
    public Identifier Identifier { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("programType")]
    public List<ProgramType> ProgramType { get; set; }

    [JsonPropertyName("endDate")]
    public string EndDate { get; set; }

    [JsonPropertyName("numberOfCredits")]
    public int NumberOfCredits { get; set; }

    [JsonPropertyName("programPrerequisites")]
    public ProgramPrerequisites ProgramPrerequisites { get; set; }

    [JsonPropertyName("educationalCredentialAwarded")]
    public string EducationalCredentialAwarded { get; set; }

    public ProgramContext()
    {
        ProgramType = new List<ProgramType>();
    }
}

public class ProgramType
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("termCode")]
    public string TermCode { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

}

public class ProgramPrerequisites
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("educationalLevel")]
    public string EducationalLevel { get; set; }

    [JsonPropertyName("recognizedBy")]
    public string RecognizedBy { get; set; }
}
#endregion

#region educationalOrganization
//public class EducationalOrganization
//{
//    [JsonPropertyName("educationalOrganization")]
//    public OrganizationDetails OrganizationDetails { get; set; }
//}

public class OrganizationDetails
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }
    [JsonPropertyName("identifier")]
    public Identifier Identifier { get; set; }
    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("teda:schoolLevel")]
    public string SchoolLevel { get; set; }
    [JsonPropertyName("address")]
    public PostalAddress Address { get; set; }

    [JsonPropertyName("subOrganization")]
    public SubOrganization SubOrganization { get; set; }

    [JsonPropertyName("teda:registrar")]
    public Registrar Registrar { get; set; }
}


public class SubOrganization
{
    [JsonPropertyName("identifier")]
    public Identifier Identifier { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("address")]
    public PostalAddress Address { get; set; }
}

public class Registrar
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("identifier")]
    public Identifier Identifier { get; set; }

    [JsonPropertyName("jobTitle")]
    public string JobTitle { get; set; }

    [JsonPropertyName("honorificPrefix")]
    public string HonorificPrefix { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("email")]
    public string Email { get; set; }
}
#endregion


#region Courselist
public class CourseList
{
    [JsonPropertyName("itemListElement")]
    public List<Course> ItemList { get; set; }

    [JsonPropertyName("@type")]
    public string Type { get; set; }

    public CourseList()
    {
        Type = "ItemList";
        ItemList = new List<Course>();
    }
}

public class ItemList
{
    public List<Course> Courses { get; set; }

    public ItemList()
    {
        Courses = new List<Course>();
    }
}

public class Course
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("courseCode")]
    public string CourseCode { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("additionalType")]
    public string AdditionalType { get; set; }

    [JsonPropertyName("description")]
    public string Description { get; set; }

    [JsonPropertyName("numberOfCredits")]
    public int NumberOfCredits { get; set; }

    [JsonPropertyName("teda:creditEarned")]
    public int CreditEarned { get; set; }

    [JsonPropertyName("teda:grade")]
    public int Grade { get; set; }

    [JsonPropertyName("teda:gradeText")]
    public string GradeText { get; set; }

    [JsonPropertyName("teda:pointEarned")]
    public int PointEarned { get; set; }

    [JsonPropertyName("@graph")]
    public List<EducationalOccupationalProgram> Graph { get; set; }
}

public class EducationalOccupationalProgram
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    public string ProgramType { get; set; }

    public string TermsPerYear { get; set; }

    public string TimeToComplete { get; set; }

    public ProgramPrerequisites ProgramPrerequisites { get; set; }

    public string TermDuration { get; set; }

    public CollegeOrUniversity Provider { get; set; }

    public string Description { get; set; }

    public string OccupationalCategory { get; set; }

    public string Url { get; set; }

    public Course HasCourse { get; set; }
}


public class CollegeOrUniversity
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    public string Name { get; set; }

    public Identifier Identifier { get; set; }
}

#endregion 

#region additional
public class AdditionalInformation
{
    [JsonPropertyName("additionalInformation")]
    public List<AdditionalInfo> InfoList { get; set; }
}

public class AdditionalInfo
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("@graph")]
    public List<GraphItem> GraphItems { get; set; }
}

public class GraphItem
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("award")]
    public string Award { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("about")]
    public string About { get; set; }

    [JsonPropertyName("text")]
    public string Text { get; set; }
}
#endregion

#region academicSummary
//public class AcademicSummary
//{
//    [JsonPropertyName("teda:academicSummary")]
//    public AcademicSummaryDetails SummaryDetails { get; set; }

//}

public class AcademicSummaryDetails
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("teda:semesterSummary")]
    public List<SemesterSummary> SemesterSummaries { get; set; }

    [JsonPropertyName("teda:totalCreditValue")]
    public int TotalCreditValue { get; set; }

    [JsonPropertyName("teda:totalCreditEarned")]
    public int TotalCreditEarned { get; set; }

    [JsonPropertyName("teda:totalCreditCalculated")]
    public int TotalCreditCalculated { get; set; }

    [JsonPropertyName("teda:totalPointEarned")]
    public int TotalPointEarned { get; set; }

    [JsonPropertyName("teda:totalGPAX")]
    public double TotalGPAX { get; set; }

    [JsonPropertyName("teda:remark")]
    public string Remark { get; set; }

    public AcademicSummaryDetails()
    {
        SemesterSummaries = new List<SemesterSummary>();
        Remark = "";
    }
}

public class SemesterSummary
{
    [JsonPropertyName("@type")]
    public string Type { get; set; }

    [JsonPropertyName("teda:educationTypeSystem")]
    public string EducationTypeSystem { get; set; }

    [JsonPropertyName("teda:semesterName")]
    public string SemesterName { get; set; }

    [JsonPropertyName("teda:semesterStatus")]
    public string SemesterStatus { get; set; }

    [JsonPropertyName("teda:year")]
    public string Year { get; set; }

    [JsonPropertyName("teda:semesterCreditValue")]
    public int SemesterCreditValue { get; set; }

    [JsonPropertyName("teda:semesterCreditEarned")]
    public int SemesterCreditEarned { get; set; }

    [JsonPropertyName("teda:semesterCreditCalculated")]
    public int SemesterCreditCalculated { get; set; }

    [JsonPropertyName("teda:semesterPointEarned")]
    public int SemesterPointEarned { get; set; }

    [JsonPropertyName("teda:semesterGPA")]
    public double SemesterGPA { get; set; }

    [JsonPropertyName("teda:semesterGPAX")]
    public double SemesterGPAX { get; set; }

    [JsonPropertyName("teda:remark")]
    public string Remark { get; set; }
}
#endregion

public class CredentialStatus
{
    [JsonPropertyName("id")]
    public string Id { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; }

    [JsonPropertyName("statusPurpose")]
    public string StatusPurpose { get; set; }

    [JsonPropertyName("statusListIndex")]
    public string StatusListIndex { get; set; }

    [JsonPropertyName("statusListCredential")]
    public string StatusListCredential { get; set; }
}

public class CredentialSchema
{
    public string id { get; set; }
    public string type { get; set; }
    //"credentialSchema": {
    //  "id": "https://schemas-uat.teda.th/teda/teda-objects/common/verified-credential/transcript/-/blob/main/schema/transcript_vc_schema.json",
    //  "type": "JsonSchema"
    //}
}
public class vcModel
{
    public string iss { get; set; }
    public string sub { get; set; }

    public _JwtPayloadModel vc { get; set; }



    public string jti { get; set; }
    public long iat { get; set; }
    public long nbf { get; set; }



}
/*using System.Text.Json.Serialization;

namespace EtdaVCIssuer.Models
{
    public class JwtPayloadModel
    {
        public string University { get; set; }
        public string Student { get; set; }
        public string GPA { get; set; }
        *//*public string id { get; set; }*//*

    }
}*/