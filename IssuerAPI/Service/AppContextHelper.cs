using IssuerAPI.Databases;
using IssuerAPI.Models;
using IssuerAPI.Util;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
//using ToyotaService.Constants;
using System.Security.Claims;
using System.Data;
using System.IO.Pipelines;


namespace IssuerAPI.Service
{
    public static class AppContextHelper
    {
        private static IHttpContextAccessor _contextAccessor;
        private static ISession _session => _contextAccessor.HttpContext.Session;
        public static HttpContext _httpContext => _contextAccessor.HttpContext;
        //private static NLog.ILogger log = NLog.LogManager.GetCurrentClassLogger();
        

		public static void Configure(IHttpContextAccessor httpContextAccessor)
        {
            _contextAccessor = httpContextAccessor;
        }

        //For web
        public static Dbregister User
        {
            get
            {
                return _session.Get<Dbregister>("user"); 
            }
            set
            {
                _session.Set("user", value);
            }
        }

        public static string UserId
        {
            get
            {
                return _session.Get<string>("UserId");
            }
            set
            {
                _session.Set("UserId", value);
            }
        }

        public static string credentialOfferId
        {
            get
            {
                return _session.Get<string>("credentialOfferId");
            }
            set
            {
                _session.Set("credentialOfferId", value);
            }
        }

        public static List<string> AuthorityCode
        {
            get
            {
                return _session.Get<List<string>>("authoritycode");
            }
            set
            {
                _session.Set("authoritycode", value);
            }
        }

        public static string FullName
        {
            get
            {
                return _session.Get<string>("fullname");
            }
            set
            {
                _session.Set("fullname", value);
            }
        }


        public static string LoginMessage
        {
            get
            {
                return _session.Get<string>("loginmessage");
            }
            set
            {
                _session.Set("loginmessage", value);
            }
        }


        public static async Task<bool> Login(AuthenUser authuser)
        {


			//string PW = Utilities.CryptoHelpers.IDMEncrypt(authuser.password);
			
			//DataTable dt = accServ.GetLogin(authuser.username, PW);
			using (IssuerDbContext _dbcontext = new IssuerDbContext())
			{

				var user = _dbcontext.Dbregisters.Where(i => i.Id.Equals(authuser.username)).FirstOrDefault();
				if (user != null)
				{
					FullName = user.RegisterName;
                    UserId = user.Id.ToString();
                    User = user;
					return true;
				}
				else
				{
					LoginMessage = "Not found user";
					return false;
				}
			}
			
        }

        public static void Logout()
        {
            _contextAccessor.HttpContext.SignOutAsync();
            _session.Clear();
        }

        public static bool HasAuthority(string Code)
        {
            if (AuthorityCode != null
                && !string.IsNullOrEmpty(Code)
                && AuthorityCode.Contains(Code)) return true;
            return false;
        }

        public static bool HasGroupAuthority(string GroupCode)
        {
            if (AuthorityCode != null
                && !string.IsNullOrEmpty(GroupCode))
            {
                foreach (var Code in AuthorityCode)
                {
                    if (Code.StartsWith(GroupCode)) return true;
                }
            }
            return false;
        }
    }

}
