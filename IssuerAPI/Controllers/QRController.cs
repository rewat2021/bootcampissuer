using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IssuerAPI.Controllers
{
    [Authorize]
    public class QRController : Controller
    {
        
        public IActionResult QRCode()
        {
            return View();
        }
    }
}
