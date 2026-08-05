using IssuerAPI.Databases;
using IssuerAPI.Models;
using IssuerAPI.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Web;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ILogger = NLog.ILogger;


public class AccountController : Controller
{

    private static readonly string[] AllowedWalletRedirectSchemes = { "walletapp://" };
    protected ILogger log = NLog.LogManager.GetCurrentClassLogger();

    private readonly ThaIDAuthService _service;

    private const string PendingReturnCookie = "thaiid_pending_return";

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login(string? ReturnUrl, DocumentType? documentType)
    {
        ViewBag.ReturnUrl = ReturnUrl;
        ViewBag.DocumentType = documentType; // ต้องส่งต่อผ่าน hidden field ใน view เพื่อรอด POST กลับมา
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(AuthenUser user, string? ReturnUrl, DocumentType? documentType)
    {


        ViewBag.ReturnUrl = ReturnUrl;
        ViewBag.DocumentType = documentType;

        if (!ModelState.IsValid)
        {
            return View(user);
        }

        using var context = new IssuerDbContext();

        var dbUser = context.Dbusers
            .FirstOrDefault(u => u.Username == user.username);

        if (dbUser == null || !VerifyPassword(user.password, dbUser.Password))
        {
            ModelState.AddModelError("ErrorMsg", "Invalid Username or Password");
            //log.Info($"Fail to log in as {user.username} (Session : {HttpContext.Session.Id})");
            return View(user);
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, dbUser.Username),
            new Claim(ClaimTypes.NameIdentifier, dbUser.Id.ToString()),
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = false,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(60)
        };

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        

        // เพิ่มเงื่อนไขนี้ไว้ก่อนของเดิม — เช็ค same-device ก่อน
        if (!string.IsNullOrEmpty(ReturnUrl) && IsAllowedWalletRedirect(ReturnUrl))
        {
            // เช็คตรงนี้แทนการ fallback เงียบๆ เป็น Transcript
            if (documentType == null)
            {
                ModelState.AddModelError("ErrorMsg", "documentType is required for wallet-initiated requests");
                return View(user);
            }

            return RedirectToAction("RedirectToWallet", "CredentialOffer",
                new { documentType = documentType.Value });
        }

        if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
        {
            return Redirect(ReturnUrl);
        }
        return RedirectToAction("QRCode", "QR");

    }

    private bool IsAllowedWalletRedirect(string url)
    {
        return AllowedWalletRedirectSchemes.Any(scheme =>
            url.StartsWith(scheme, StringComparison.OrdinalIgnoreCase));
    }

    [HttpPost]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }

    [AllowAnonymous]
    public IActionResult AccessDenied()
    {
        return View();
    }

    private bool VerifyPassword(string inputPassword, string storedPassword)
    {
        return inputPassword == storedPassword;
        // return BCrypt.Net.BCrypt.Verify(inputPassword, storedPassword);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ThaIDLogin(string? ReturnUrl, DocumentType? documentType)
    {
        ViewBag.ReturnUrl = ReturnUrl;
        ViewBag.DocumentType = documentType; // ต้องส่งต่อผ่าน hidden field ใน view เพื่อรอด POST กลับมา
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    [Route("thaiid/login")]
    public IActionResult ThaIDLogin(string? ReturnUrl, DocumentType? documentType, string? error = null)
    {
        try
        {
            string clientId = ThaIDConfig.ClientID;

            // Gateway (.155) endpoint ที่แสดงหน้า QR ให้ user สแกนด้วยแอป ThaID
            string authUrl = $"{ThaIDConfig.GatewayBaseUrl}/auth/index?clientid={clientId}&role=Issuer&ReturnUrl={ReturnUrl}&documentType={documentType}";

            // เก็บ returnUrl/documentType ไว้ใน cookie ชั่วคราว (HttpOnly, อายุสั้น)
            // เพราะ browser จะออกจากหน้า .205 ไปที่ .155 แล้ววนกลับมาที่ ThaiIDCallback
            // โดยไม่มีทางส่ง custom parameter ผ่าน .155/ThaID ไปกลับมาได้เอง
            var pending = new { ReturnUrl = ReturnUrl, DocumentType = documentType };
            Response.Cookies.Append(PendingReturnCookie, JsonConvert.SerializeObject(pending), new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTimeOffset.UtcNow.AddMinutes(10)
            });

            return Redirect(authUrl);

            //string state = Guid.NewGuid().ToString("N");
            //string clientId = ThaIDConfig.ClientID;
            //string clientSecret = ThaIDConfig.ClientSecret;
            //string redirectUri = $"{Request.Scheme}://{Request.Host}" + ThaIDConfig.RedirectURL;
            //string scope = ThaIDConfig.Scope;
            //string Issuer = ThaIDConfig.Issuer + "api/v2/oauth2/auth/?";

            //log.Info($"redirect_uri => {redirectUri}");
            //string authUrl = Issuer +
            //                   "response_type=code" +
            //                   "&client_id=" + clientId +
            //                   "&redirect_uri=" + HttpUtility.UrlEncode(redirectUri) +
            //                   "&scope=" + HttpUtility.UrlEncode(scope) + "%20openid" +
            //                   "&state=" + state;

            //return Redirect(authUrl);


            //return Redirect(Issuer +
            //            $"auth/?response_type=code&client_id={clientId}&redirect_uri={HttpUtility.UrlEncode(redirectUri)}&scope=pid%20given_name%20middle_name%20family_name%20given_name_en%20middle_name_en%20family_name_en&state={state}");
        }
        catch (Exception ex)
        {
            log.Error("ThaID.Login => " + ex.ToString());
            return RedirectToAction("ThaIDLogin", "Account",
                new { error = "ไม่สามารถเชื่อมต่อ ThaiID ได้" });
        }
    }

    [HttpGet]
    [AllowAnonymous]
    [Route("api/thaid/callback")]
    public async Task<IActionResult> ThaiIDCallback(string code, string state, string error = null)
    {
        try
        {
            log.Info("ThaiIDCallback => " + code);

            // 1) ตรวจ error จาก provider
            if (!string.IsNullOrWhiteSpace(error))
            {
                return RedirectToAccountLogin("ThaiID ส่งค่ากลับมาผิดพลาด: " + error);
            }

            // 2) ตรวจ code
            if (string.IsNullOrWhiteSpace(code))
            {
                return StatusCode(400, "Authorization code not found");
            }

            // 3) ตรวจ state
            if (string.IsNullOrWhiteSpace(state))
            {
                return RedirectToAccountLogin("ไม่พบ state จาก ThaiID");
            }

            // 4) ขอ system token จาก Gateway (.155)
            var systemToken = await _service.GetSystemTokenAsync();
            if (systemToken == null || string.IsNullOrWhiteSpace(systemToken.AccessToken))
            {
                log.Error("GetSystemTokenAsync failed for state check");
                return RedirectToAccountLogin("ไม่สามารถขอ system token สำหรับตรวจสอบ state ได้");
            }

            // 5) check state ที่ Gateway (.155) -> ได้ PID + citizen data กลับมา
            var stateResult = await _service.CheckStateAsync(state, systemToken.AccessToken);
            if (stateResult == null || string.IsNullOrWhiteSpace(stateResult.PID))
            {
                log.Error("CheckStateAsync failed or PID missing => state=" + state);
                return RedirectToAccountLogin("ไม่สามารถยืนยันตัวตนผ่าน ThaID ได้ (state ไม่ถูกต้องหรือหมดอายุ)");
            }

            log.Info("CheckState PID => " + stateResult.PID);
            string citizenId = stateResult.PID;

            // 6) อ่าน returnUrl/documentType ที่เก็บไว้ก่อนไป .155
            string? pendingReturnUrl = null;
            DocumentType? pendingDocumentType = null;

            if (Request.Cookies.TryGetValue(PendingReturnCookie, out var pendingJson) &&
                !string.IsNullOrWhiteSpace(pendingJson))
            {
                var pending = JsonConvert.DeserializeAnonymousType(pendingJson,
                    new { ReturnUrl = (string?)null, DocumentType = (DocumentType?)null });
                pendingReturnUrl = pending?.ReturnUrl;
                pendingDocumentType = pending?.DocumentType;
                Response.Cookies.Delete(PendingReturnCookie);
            }

            // 7) สร้าง claims จาก PID แล้ว sign-in cookie ให้ user
            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, citizenId),
                };

            var fullNameTh = $"{stateResult.FirstNameTh} {stateResult.LastNameTh}".Trim();
            if (!string.IsNullOrWhiteSpace(fullNameTh))
            {
                claims.Add(new Claim(ClaimTypes.Name, fullNameTh));
            }

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                IsPersistent = false,
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(60)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            // 8) ตัดสินใจ redirect ปลายทาง
            if (!string.IsNullOrEmpty(pendingReturnUrl) && IsAllowedWalletRedirect(pendingReturnUrl))
            {
                if (pendingDocumentType == null)
                {
                    return RedirectToAccountLogin("documentType is required for wallet-initiated requests");
                }

                return RedirectToAction("RedirectToWallet", "CredentialOffer",
                    new { documentType = pendingDocumentType.Value });
            }

            if (!string.IsNullOrEmpty(pendingReturnUrl) && Url.IsLocalUrl(pendingReturnUrl))
            {
                return Redirect(pendingReturnUrl);
            }

            // 9) fallback : ส่งต่อไปหน้าขอ VC พร้อม citizenId
            return RedirectToAction("RequestVC", "Services", new { citizenId });
        }
        catch (Exception ex)
        {
            log.Error("ThaiIDCallback => " + ex.Message);
            return RedirectToAccountLogin("เกิดข้อผิดพลาดระหว่างเข้าสู่ระบบด้วย ThaID");
        }
    }

    private IActionResult RedirectToAccountLogin(string errorMessage)
    {
        return RedirectToAction("ThaIDLogin", "Account", new { error = errorMessage });
    }


    [HttpGet]
    [AllowAnonymous]
    [Route("Account/ThaIDSignIn")]
    public async Task<IActionResult> ThaIDSignIn(string pid, string? ReturnUrl, DocumentType? documentType)
    {
        if (string.IsNullOrWhiteSpace(pid))
        {
            return RedirectToAction("ThaIDLogin", "Account", new { error = "ไม่พบข้อมูลยืนยันตัวตน" });
        }

        var claims = new List<Claim> { new Claim(ClaimTypes.NameIdentifier, pid) };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = false,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(60)
        };

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        // คำนวณปลายทางสุดท้ายไว้ก่อน แต่ยังไม่ redirect ทันที
        string finalUrl;
        if (!string.IsNullOrEmpty(ReturnUrl) && IsAllowedWalletRedirect(ReturnUrl))
        {
            if (documentType == null)
            {
                return RedirectToAction("ThaIDLogin", "Account",
                    new { error = "documentType is required for wallet-initiated requests" });
            }
            finalUrl = Url.Action("RedirectToWallet", "CredentialOffer", new { documentType = documentType.Value })!;
        }
        else if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
        {
            finalUrl = ReturnUrl;
        }
        else
        {
            finalUrl = Url.Action("QRCode", "QR")!;
        }

        // ★ ใช้หน้า HTML เล็กๆ ทำ client-side redirect แทน HTTP redirect ตรงๆ ★
        // เพื่อให้แน่ใจว่า cookie ถูก set/commit เสร็จสมบูรณ์ก่อน browser จะ navigate ต่อ
        string html = $@"
<!DOCTYPE html>
<html lang=""th"">
<head>
    <meta charset=""UTF-8"" />
    <meta http-equiv=""refresh"" content=""0;url={finalUrl}"" />
    <title>กำลังเข้าสู่ระบบ</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: ""Sarabun"", ""Noto Sans Thai"", Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #f5f6fa;
        }}
        .waiting-card {{
            text-align: center;
            padding: 40px;
        }}
        .spinner {{
            width: 56px;
            height: 56px;
            margin: 0 auto 24px;
            border: 5px solid #e0e4f5;
            border-top-color: #14276e;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        h1 {{
            font-size: 18px;
            color: #0a1f6b;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        p {{
            font-size: 14px;
            color: #8a8a8a;
        }}
    </style>
</head>
<body>
    <div class=""waiting-card"">
        <div class=""spinner""></div>
        <h1>กำลังเข้าสู่ระบบ</h1>
        <p>กรุณารอสักครู่...</p>
    </div>

    <script>
        window.location.replace(""{finalUrl}"");
    </script>
</body>
</html>";

        return Content(html, "text/html");

    }




    //[HttpGet]
    //[AllowAnonymous]
    //[Route("Account/ThaIDSignIn")]
    //public async Task<IActionResult> ThaIDSignIn(string pid, string? ReturnUrl, DocumentType? documentType)
    //{
    //    if (string.IsNullOrWhiteSpace(pid))
    //    {
    //        return RedirectToAction("ThaIDLogin", "Account", new { error = "ไม่พบข้อมูลยืนยันตัวตน" });
    //    }

    //    // sign-in cookie ให้ user ก่อน (แทนการเช็ค username/password เหมือนของเดิม
    //    // เพราะ pid ที่ได้มา ผ่านการยืนยันตัวตนจริงจาก ThaID แล้ว)
    //    var claims = new List<Claim>
    //    {
    //        new Claim(ClaimTypes.NameIdentifier, pid)
    //    };

    //    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    //    var authProperties = new AuthenticationProperties
    //    {
    //        IsPersistent = false,
    //        ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(60)
    //    };

    //    await HttpContext.SignInAsync(
    //        CookieAuthenticationDefaults.AuthenticationScheme,
    //        new ClaimsPrincipal(claimsIdentity),
    //        authProperties);

    //    // -------------------------------------------------------
    //    // เช็ค same-device / cross-device เหมือนของเดิม (จาก Login แบบ username/password)
    //    // -------------------------------------------------------

    //    // Cross-device: ReturnUrl เป็น wallet scheme (walletapp://...)
    //    log.Info($"returnurl => {ReturnUrl}");
    //    if (!string.IsNullOrEmpty(ReturnUrl) && IsAllowedWalletRedirect(ReturnUrl))
    //    {
    //        if (documentType == null)
    //        {
    //            // ไม่มี View(user) ให้ return แบบเดิมแล้ว (ไม่ใช่ POST form) — ส่ง error กลับไปหน้า login แทน
    //            return RedirectToAction("ThaIDLogin", "Account",
    //                new { error = "documentType is required for wallet-initiated requests" });
    //        }

    //        return RedirectToAction("RedirectToWallet", "CredentialOffer",
    //            new { documentType = documentType.Value });
    //    }

    //    // Same-device: ReturnUrl เป็น local URL ปกติ
    //    if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
    //    {
    //        return Redirect(ReturnUrl);
    //    }

    //    // Fallback: ไม่มี ReturnUrl เลย → ไปหน้า QRCode ตามปกติ
    //    return RedirectToAction("QRCode", "QR");
    //}
}