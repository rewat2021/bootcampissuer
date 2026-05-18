using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IssuerAPI.Models;
using IssuerAPI.Service;

namespace IssuerAPI.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Login()
        {
            //if (AppContextHelper.User != null) return RedirectToAction("IndexNew", "Home");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login(AuthenUser user, string? ReturnUrl)
        {
            if (ModelState.IsValid)
            {
                //var loginResult = AppContextHelper.Login(user);
                //var admin = AppContextHelper.User.IsAdmin;

                return RedirectToAction("QRCode", "QR");
            }
            if (user.username != null) ModelState.AddModelError("ErrorMsg", "Invalid Username");
            //log.Info($"Fail to log in as {user.username} (Session : {HttpContext.Session.Id})");
            return View();
        }
    }
}
