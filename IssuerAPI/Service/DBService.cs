using IssuerAPI.Databases;
using IssuerAPI.Models;
using Microsoft.AspNetCore.WebUtilities;
using System.Net;
using System.Text;

namespace IssuerAPI.Service
{
    public class DBService
    {

        public AccessCode getPreAuthorizedCode(string pre_authorized_code, out string registerId)
        {
            VCService serv = new VCService();
            AccessCode result = new AccessCode();
            registerId = null;

            //var result = new JwtModel();
            if (string.IsNullOrEmpty(pre_authorized_code)) return result;
            var tokenArr = pre_authorized_code.Split('.');
            string Header = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(tokenArr[0]));
            string Payload = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(tokenArr[1]));
            AuthorizedCode model = System.Text.Json.JsonSerializer.Deserialize<AuthorizedCode>(Payload);

            string id = GetRegisterId(model.Sub);
            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.Where(i => i.RegisterId.Equals(id)).FirstOrDefault();// && i.Params.Equals("pre-authorized_code") && i.StateId.Equals(model.Sub)).FirstOrDefault();
                if (item != null)
                {
                    result.authoriseCode = item.PreAuthorizedCode;
                    result.C_Nonce = model.Sub;
                    result.RegisterId = id;
                    result.CredentialType = item.CredentialId;
                }
            }
            registerId = id;
            return result;


        }


        public AccessCode getPreAuthorizedByRegisID(string registerId)
        {
            VCService serv = new VCService();
            AccessCode result = new AccessCode();

            //var result = new JwtModel();
            if (string.IsNullOrEmpty(registerId)) return result;
          

            string id = registerId;
            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.Where(i => i.RegisterId.Equals(id)).FirstOrDefault();// && i.Params.Equals("pre-authorized_code") && i.StateId.Equals(model.Sub)).FirstOrDefault();
                if (item != null)
                {
                    result.authoriseCode = item.PreAuthorizedCode;
                    //result.C_Nonce = model.Sub;
                    result.RegisterId = id;
                }
            }
            registerId = id;
            return result;


        }

        public string GetRegisterId(string credentialId)
        {
            string result = null;
            using (IssuerDbContext context = new IssuerDbContext())
            {
                var items = context.Dbrequests.Where(i => i.RegisterId.Equals(credentialId)).FirstOrDefault();

                if (items != null)
                {
                    result = items.RegisterId;
                }

            }
            return result;
        }

        public List<string> GetDocumentTypes(string registerId)
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.FirstOrDefault(i => i.RegisterId.Equals(registerId));

                if (item == null || string.IsNullOrEmpty(item.CredentialId))
                    return new List<string>();

                try
                {
                    return Newtonsoft.Json.JsonConvert.DeserializeObject<List<string>>(item.CredentialId)
                           ?? new List<string>();
                }
                catch (Newtonsoft.Json.JsonException)
                {
                    // เผื่อกรณี CredentialId เก่าที่เคยเก็บเป็น plain string เดี่ยว (ไม่ใช่ JSON array)
                    // ก่อนที่จะปรับ schema มาเป็น List<string> — กัน exception ตอน migrate ข้อมูลเก่า
                    return new List<string> { item.CredentialId };
                }
            }
        }

        //public void SaveRequestCredential(string guid, List<string> credentialConfigurationIds, string preAuthorizedCode)
        //{
        //    using (IssuerDbContext context = new IssuerDbContext())
        //    {
        //        var item = context.Dbrequests.Where(i => i.RegisterId.Equals(guid)).FirstOrDefault();
        //        if (item == null)
        //        {
        //            item = new Dbrequest();
        //            item.RegisterId = guid;
        //            item.PreAuthorizedCode = preAuthorizedCode;
        //            item.CredentialId = requestvc;
        //            item.CreateDate = DateTime.UtcNow;

        //            context.Dbrequests.Add(item);
        //            context.SaveChanges();
        //        }
        //    }
        //}

        public void SaveRequestCredential(string guid, List<string> credentialConfigurationIds, string preAuthorizedCode)
        {
            if (credentialConfigurationIds == null || credentialConfigurationIds.Count == 0)
                throw new ArgumentException("credentialConfigurationIds must contain at least one value.");

            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.FirstOrDefault(i => i.RegisterId.Equals(guid));
                if (item == null)
                {
                    item = new Dbrequest
                    {
                        RegisterId = guid,
                        PreAuthorizedCode = preAuthorizedCode,
                        CredentialId = Newtonsoft.Json.JsonConvert.SerializeObject(credentialConfigurationIds), // ["org.iso.18013.5.1.mDL","...sd-jwt"]
                        CreateDate = DateTime.UtcNow
                    };
                    context.Dbrequests.Add(item);
                    context.SaveChanges();
                }
            }
        }

        public void SaveIssueVCLog(string issuerid, string walletid, string _nonce, string _credential, string vcDocType, string statuscode)
        {
            Guid id = new Guid();
            try
            {
                IssuerDbContext issuerContext = new IssuerDbContext();
                var log = new Dbissuerlog
                {

                    TeamId = _nonce,
                    CredentialType = vcDocType,
                    HolderDid = walletid,
                    IssuerDid = issuerid,
                    OfferId = _nonce,
                    Status = statuscode,
                    CredentialPayload = _credential,
                    CreatedAt = DateTime.Now
                };
                issuerContext.Dbissuerlogs.Add(log);
                issuerContext.SaveChanges();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Save VC to DB error: {e.Message}");
            }
        }

    }
}
