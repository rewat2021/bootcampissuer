using IssuerAPI.Service;
using IssuerAPI.Models;
using IssuerAPI.Databases;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.OpenApi.Models;
using NLog;
using NLog.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.Cookies;

var logger = LogManager.Setup()
                       .LoadConfigurationFromFile("nlog.config")
                       .GetCurrentClassLogger();

var builder = WebApplication.CreateBuilder(args);

ThaIDConfig.Configure(builder.Configuration);
builder.Services.Configure<Oid4VciOptions>(
    builder.Configuration.GetSection("Oid4Vci"));

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "ใส่ access token แบบนี้: Bearer {token}",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor |
        ForwardedHeaders.XForwardedProto |
        ForwardedHeaders.XForwardedHost;

    // H-11: clearing KnownNetworks/KnownProxies makes ASP.NET Core trust X-Forwarded-* from ANY
    // caller, so an attacker hitting the app directly (bypassing the real reverse proxy) could spoof
    // X-Forwarded-Host/Proto and influence baseUrl (issuer identifier, redirect targets, credential
    // "iss"/"sub" URLs, etc). Only trust forwarded headers from proxy IPs listed in config
    // (ReverseProxy:KnownProxies, e.g. the IIS/nginx box in front of Kestrel). If nothing is
    // configured, fall back to framework defaults (loopback only) rather than "trust everyone".
    var knownProxies = builder.Configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>();
    if (knownProxies != null)
    {
        foreach (var ip in knownProxies)
        {
            if (System.Net.IPAddress.TryParse(ip, out var addr))
            {
                options.KnownProxies.Add(addr);
            }
        }
    }
});

//builder.Services.AddAuthentication("IssuerCookie")
//    .AddCookie("IssuerCookie", options =>
//    {
//        options.LoginPath = "/Account/Login"; // ถ้าไม่ login จะ redirect มานี่
//    });
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/ThaIDLogin";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
        options.SlidingExpiration = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // ใช้ Always ถ้าบังคับ HTTPS
    });

builder.Services.AddHttpClient<ThaIDAuthService>();

builder.Services.AddControllersWithViews()
    .AddJsonOptions(opts =>
    {
        opts.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        opts.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
        opts.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    });

var AllowSpecificOriginWithCredentials = "AllowSpecificOriginWithCredentials";
builder.Services.AddCors(options =>
{

    options.AddPolicy(AllowSpecificOriginWithCredentials,
                policy =>
                {
                    policy.WithOrigins(new string[] { "https://wallet-test.etda.or.th", "https://issuer-cu-test.etda.or.th", "https://issuer.zenithcomp.co.th",
                        "https://vc-testtool.etda.or.th", "https://vc-testtool-test.etda.or.th" }) // Replace with your allowed origins
                           .AllowAnyHeader()
                           .AllowAnyMethod();
                    //.AllowCredentials(); // This enables Access-Control-Allow-Credentials
                });

});

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();
// Clear default logging
builder.Logging.ClearProviders();

// Add NLog
builder.Host.UseNLog();

var app = builder.Build();

// C-06 follow-up: db/init.sql no longer seeds a `users` row (the old one committed a real name,
// email, and a PLAINTEXT password to source control — see AccountController.VerifyPassword for the
// matching BCrypt fix). That leaves a chicken-and-egg problem for a brand-new deployment: there is
// no way to log in to create the first staff/admin account through the app itself. This runs once
// at startup, only creates a user if the `users` table is completely empty, and only if both
// bootstrap env vars are actually set (so it's a silent no-op on every deployment after the first).
// Password is hashed with BCrypt before it ever touches the database — never stored/logged raw.
try
{
    string bootstrapUsername = Environment.GetEnvironmentVariable("ADMIN_BOOTSTRAP_USERNAME");
    string bootstrapPassword = Environment.GetEnvironmentVariable("ADMIN_BOOTSTRAP_PASSWORD");
    if (!string.IsNullOrWhiteSpace(bootstrapUsername) && !string.IsNullOrWhiteSpace(bootstrapPassword))
    {
        using var seedContext = new IssuerDbContext();
        if (!seedContext.Dbusers.Any())
        {
            seedContext.Dbusers.Add(new Dbuser
            {
                FirstName = "Admin",
                LastName = "Bootstrap",
                Username = bootstrapUsername,
                Email = $"{bootstrapUsername}@localhost.invalid",
                Password = BCrypt.Net.BCrypt.HashPassword(bootstrapPassword),
                CreatedAt = DateTime.UtcNow
            });
            seedContext.SaveChanges();
            logger.Info($"Admin bootstrap: created first staff user '{bootstrapUsername}' (users table was empty).");
        }
    }
}
catch (Exception ex)
{
    // Never let a bootstrap failure block the app from starting — worst case, no admin user exists
    // yet and someone has to create one manually (e.g. via a direct DB insert with a BCrypt hash).
    logger.Error(ex, "Admin bootstrap failed");
}

app.UseForwardedHeaders();

if (app.Environment.IsDevelopment() || app.Environment.IsProduction())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}



app.UseHttpsRedirection();


app.UseStaticFiles();

app.UseRouting();

app.UseSession();
app.UseCors(AllowSpecificOriginWithCredentials);

app.UseAuthentication();   // 🔥 ต้องมาก่อน Authorization
app.UseAuthorization();




app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=ThaIDLogin}");

app.MapControllers();



app.Run();
