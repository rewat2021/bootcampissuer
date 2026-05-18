using System.ComponentModel.DataAnnotations;

namespace IssuerAPI.Models
{
	public class AuthenUser
	{
		[Required(ErrorMessage = "Username is required")]
		public string username { get; set; }
	}

	public class Register
	{
        public string UnitId { get; set; }
        public string Contact { get; set; }
        public string RegName { get; set; }
        public ulong IsIssuer { get; set; }
        public ulong IsHolder { get; set; }
        public ulong IsVerifier { get; set; }
        public ulong IsAdmin { get; set; }

    }
}
