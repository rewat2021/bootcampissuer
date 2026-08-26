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

    // _service was declared readonly but never assigned anywhere in this class — with no
    // constructor at all, it stayed null, so any _service.* call in ThaiIDCallback would throw
    // NullReferenceException the first time anyone actually completed the ThaID flow.
    // ThaIDAuthService is already registered for DI in Program.cs
    // (builder.Services.AddHttpClient<ThaIDAuthService>();), so the framework injects it here.
    public AccountController(ThaIDAuthService service)
    {
        _service = service;
    }

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
            // C-03: dbusers is this issuer's staff/admin login (username+password), distinct from the
            // ThaID citizen login used by wallet holders. Grant the admin role here so
            // [Authorize(Roles="admin")] endpoints (CredentialConfigController) are reachable by staff.
            new Claim(ClaimTypes.Role, "admin"),
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

        // Staff/admin (username+password) login has no citizen-facing landing page of its own —
        // admin work happens via the CredentialConfigController API, exercised through Swagger.
        // Send them there instead of the citizen "request VC" QR page.
        return Redirect("/swagger");

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

    // C-06: this used to compare passwords with plain `==` — meaning `users.password` in the
    // database was plaintext (confirmed: the committed db/init.sql seed had a real password stored
    // as literally "1234"). BCrypt.Verify handles its own salt extraction from the stored hash, so
    // no separate salt column/config is needed. Existing rows with a plaintext value in `password`
    // will fail to verify (BCrypt.Verify throws/returns false on a non-BCrypt hash) — that's
    // intentional; those accounts must be reset with a properly hashed password, not silently
    // grandfathered in as valid.
    private bool VerifyPassword(string inputPassword, string storedPassword)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(inputPassword, storedPassword);
        }
        catch (BCrypt.Net.SaltParseException)
        {
            // storedPassword isn't a valid BCrypt hash (e.g. a legacy plaintext row) — treat as a
            // failed login rather than throwing a 500 back to the caller.
            return false;
        }
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
            //string clientId = ThaIDConfig.ClientID;

            // Gateway (.155) endpoint ที่แสดงหน้า QR ให้ user สแกนด้วยแอป ThaID
            //string authUrl = $"{ThaIDConfig.GatewayBaseUrl}/auth/index?clientid={clientId}&role=Issuer&ReturnUrl={ReturnUrl}&documentType={documentType}";

            // เก็บ returnUrl/documentType ไว้ใน cookie ชั่วคราว (HttpOnly, อายุสั้น) เพราะ browser จะออกจาก
            // หน้านี้ไปที่ ThaID แล้ววนกลับมาที่ ThaiIDCallback โดยไม่มีทางส่ง custom parameter ผ่าน ThaID ไป-
            // กลับมาได้เอง (ThaID ส่งกลับมาแค่ code/state ที่มันควบคุมเอง)
            //
            // บั๊กที่แก้: บล็อกนี้เคย comment ทิ้งไว้ทั้งก้อน — แปลว่า ReturnUrl/documentType ที่รับเข้ามาถูก
            // ทิ้งไปเฉยๆ ไม่เคยถูกเก็บที่ไหนเลย ผลคือ ThaiIDCallback อ่าน cookie ไม่เจอทุกครั้ง (pendingReturnUrl
            // เป็น null เสมอ) จึง fall through ไปทาง fallback (/QR/QRCode) ตลอด ไม่ว่าจะ login มาจาก flow
            // same-device (wallet เปิด browser มาขอ redirect ตรง) หรือไม่ก็ตาม — same-device เลยเห็น QR
            // page เหมือน cross-device ทุกครั้ง ทั้งที่ควรจะ redirect ตรงไป wallet เลยโดยไม่ต้อง scan
            if (!string.IsNullOrEmpty(ReturnUrl) || documentType != null)
            {
                var pending = new { ReturnUrl = ReturnUrl, DocumentType = documentType };
                Response.Cookies.Append(PendingReturnCookie, JsonConvert.SerializeObject(pending), new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTimeOffset.UtcNow.AddMinutes(10)
                });
            }

            string state = Guid.NewGuid().ToString("N");
            string clientId = ThaIDConfig.ClientID;
            string clientSecret = ThaIDConfig.ClientSecret;
            string redirectUri = $"{Request.Scheme}://{Request.Host}" + ThaIDConfig.RedirectURL;
            string scope = ThaIDConfig.Scope;
            string Issuer = ThaIDConfig.Issuer + "api/v2/oauth2/auth/?";

            log.Info($"redirect_uri => {redirectUri}");
            scope = "pid%20given_name%20family_name%20given_name_en%20family_name_en%20gender%20title%20title_en%20date_of_issuance%20date_of_expiry%20address%20birthdate";
            string authUrl = Issuer +
                               "response_type=code" +
                               "&client_id=" + clientId +
                               "&redirect_uri=" + HttpUtility.UrlEncode(redirectUri) +
                               "&scope=" + scope + "%20openid" +
                               "&state=" + state;
            //HttpUtility.UrlEncode(scope) 
            return Redirect(authUrl);


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

            // 4) แลก code -> token กับ DOPA ThaID โดยตรง (endpoint เดียวกับที่ ThaIDLogin ยิงไป authorize)
            string redirectUri = $"{Request.Scheme}://{Request.Host}" + ThaIDConfig.RedirectURL;
            var token = await _service.GetAccessTokenAsync(code, $"{redirectUri}");
            if (token == null || string.IsNullOrWhiteSpace(token.IDToken))
            {
                log.Error("GetAccessTokenAsync failed or id_token missing");
                return RedirectToAccountLogin("ไม่สามารถขอ token จาก ThaiID ได้");
            }

            // 5) ดึง PID + ข้อมูลส่วนตัวจาก claims ใน id_token โดยตรง — ไม่ต้องเรียก Gateway แยกอีกรอบ
            // (จุดนี้เดิมเรียก CheckStateAsync ซึ่ง compile ไม่ผ่าน: อ้าง ThaIDSystemTokenResponse.IDTokenClaims
            // ที่ไม่มีอยู่จริง และ return type ไม่ตรงกับ signature ที่ประกาศไว้)
            string citizenId = _service.GetCitizenId(token);
            if (string.IsNullOrWhiteSpace(citizenId))
            {
                log.Error("GetCitizenId failed or pid/sub missing from id_token => state=" + state);
                return RedirectToAccountLogin("ไม่สามารถยืนยันตัวตนผ่าน ThaID ได้ (ไม่พบ PID ใน id_token)");
            }
            var stateResult = _service.GetProfile(token);

            log.Info("id_token PID => " + citizenId);

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

            var fullNameTh = $"{stateResult?.FirstNameTh} {stateResult?.LastNameTh}".Trim();
            if (!string.IsNullOrWhiteSpace(fullNameTh))
            {
                claims.Add(new Claim(ClaimTypes.Name, fullNameTh));
            }

            // C-05 (partial): carry the rest of the ThaID profile (title/given/family/birthdate/gender)
            // through as claims too, not just the display name — CredentialOfferController reads these
            // back at offer-creation time and persists them against the registerId so credential
            // issuance (GenerateIDCardVC/SdJwt) can use real data instead of hardcoded mock values.
            // Standard ClaimTypes used where one exists; "thaid_title" is a custom type since there's
            // no ClaimTypes equivalent for a Thai honorific prefix.
            if (!string.IsNullOrWhiteSpace(stateResult?.TitleNameTh))
                claims.Add(new Claim("thaid_title", stateResult.TitleNameTh));
            if (!string.IsNullOrWhiteSpace(stateResult?.FirstNameTh))
                claims.Add(new Claim(ClaimTypes.GivenName, stateResult.FirstNameTh));
            if (!string.IsNullOrWhiteSpace(stateResult?.LastNameTh))
                claims.Add(new Claim(ClaimTypes.Surname, stateResult.LastNameTh));
            if (!string.IsNullOrWhiteSpace(stateResult?.BirthDate))
                claims.Add(new Claim(ClaimTypes.DateOfBirth, stateResult.BirthDate));
            if (!string.IsNullOrWhiteSpace(stateResult?.Gender))
                claims.Add(new Claim(ClaimTypes.Gender, stateResult.Gender));
            // ThaIDLogin ขอ scope "address date_of_issuance date_of_expiry" ไว้ด้วย — เพิ่ม claims ให้ครบ
            // (custom claim types: ไม่มี ClaimTypes มาตรฐานสำหรับ 3 ค่านี้)
            if (!string.IsNullOrWhiteSpace(stateResult?.Address))
                claims.Add(new Claim(ClaimTypes.StreetAddress, stateResult.Address));
            if (!string.IsNullOrWhiteSpace(stateResult?.DateOfIssuance))
                claims.Add(new Claim("thaid_date_of_issuance", stateResult.DateOfIssuance));
            if (!string.IsNullOrWhiteSpace(stateResult?.DateOfExpiry))
                claims.Add(new Claim("thaid_date_of_expiry", stateResult.DateOfExpiry));
            // ชื่อภาษาอังกฤษ — ThaID ให้มาด้วย (title_en/given_name_en/family_name_en) แต่ก่อนหน้านี้
            // GetProfile() ดึงมาอยู่แล้ว (TitleNameEn/FirstNameEn/LastNameEn) เพียงแต่ไม่เคยส่งต่อผ่าน claims
            // ลงไปถึง VC เลย — เพิ่ม custom claim type เพราะ ClaimTypes.GivenName/Surname ถูกใช้กับชื่อไทยแล้ว
            if (!string.IsNullOrWhiteSpace(stateResult?.TitleNameEn))
                claims.Add(new Claim("thaid_title_en", stateResult.TitleNameEn));
            if (!string.IsNullOrWhiteSpace(stateResult?.FirstNameEn))
                claims.Add(new Claim("thaid_given_name_en", stateResult.FirstNameEn));
            if (!string.IsNullOrWhiteSpace(stateResult?.LastNameEn))
                claims.Add(new Claim("thaid_family_name_en", stateResult.LastNameEn));

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

            // 9) fallback : ส่งต่อไปหน้าขอเอกสาร (QR) — เดิม redirect ไป "Services/RequestVC" ซึ่งไม่มี
            // controller/action นี้อยู่จริงในโปรเจกต์เลย (404 "No webpage was found" ทุกครั้งที่ login
            // ตรงๆ ผ่าน ThaID โดยไม่ได้มาจาก wallet-initiated flow) — เปลี่ยนไปหน้า /QR/QRCode ซึ่งเป็นหน้า
            // ขอเอกสารจริงที่ใช้งานได้ (ต้อง [Authorize] อยู่แล้ว และตอนนี้มีคุกกี้ที่เพิ่ง sign-in ไปพร้อมแล้ว)
            return RedirectToAction("QRCode", "QR");
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


    // SECURITY (removed): this used to be an [AllowAnonymous] GET action
    // ("Account/ThaIDSignIn?pid=...") that signed the caller in as whatever "pid" was passed in the
    // query string, with zero verification that they'd actually authenticated via ThaID — a full
    // authentication bypass (anyone could impersonate any citizen by ID number). Confirmed nothing in
    // this project ever called it (no link, redirect, or JS reference anywhere) — ThaiIDCallback above
    // already signs the user in directly and correctly after verifying the code/token with ThaID, so
    // this was dead, exploitable code left over from adapting an older reference implementation.
    // Removed rather than fixed since it served no purpose here.
}