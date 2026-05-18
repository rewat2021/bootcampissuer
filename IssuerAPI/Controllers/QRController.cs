using Microsoft.AspNetCore.Mvc;

namespace IssuerAPI.Controllers
{
    public class QRController : Controller
    {
        public IActionResult QRCode()
        {
            return View();
        }
    }
}
