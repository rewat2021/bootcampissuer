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

        public string GetDocumentType(string registerId)
        {
            string result = null;
            using (IssuerDbContext context = new IssuerDbContext())
            {
                var items = context.Dbrequests.Where(i => i.RegisterId.Equals(registerId)).FirstOrDefault();

                if (items != null)
                {
                    result = items.CredentialId;
                }

            }
            return result;
        }

        public void SaveRequestCredential(string guid, string requestvc, string preAuthorizedCode)
        {
            using (IssuerDbContext context = new IssuerDbContext())
            {
                var item = context.Dbrequests.Where(i => i.RegisterId.Equals(guid)).FirstOrDefault();
                if (item == null)
                {
                    item = new Dbrequest();
                    item.RegisterId = guid;
                    item.PreAuthorizedCode = preAuthorizedCode;
                    item.CredentialId = requestvc;
                    item.CreateDate = DateTime.UtcNow;

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
