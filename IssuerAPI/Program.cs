
using IssuerAPI.Models;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using NLog;
using NLog.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

var logger = LogManager.Setup()
                       .LoadConfigurationFromFile("nlog.config")
                       .GetCurrentClassLogger();

var builder = WebApplication.CreateBuilder(args);


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

    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddAuthentication("IssuerCookie")
    .AddCookie("IssuerCookie", options =>
    {
        options.LoginPath = "/Account/Login"; // ถ้าไม่ login จะ redirect มานี่
    });

builder.Services.AddControllers()
    .AddJsonOptions(opts =>
    {
        opts.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        opts.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
        opts.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    });

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();
// Clear default logging
builder.Logging.ClearProviders();

// Add NLog
builder.Host.UseNLog();

var app = builder.Build();

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

app.UseAuthentication();   // 🔥 ต้องมาก่อน Authorization
app.UseAuthorization();


// แทนที่ block เดิมที่ใช้ Redirect
//app.MapGet("/.well-known/vct/credentials/{type}", async (string type, HttpContext ctx) =>
//{
//    var baseUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}";

//    // forward request ไปที่ path /credentials/{type} โดยตรง
//    ctx.Request.Path = $"/credentials/{type}";
//    ctx.Request.RouteValues["type"] = type;

//    // เรียก controller endpoint โดยตรง ไม่ redirect
//    var dispatcher = ctx.RequestServices.GetRequiredService<IHttpContextFactory>();
//    await ctx.Response.SendFileAsync(""); // ไม่ใช้วิธีนี้
//});

app.MapControllers();



app.Run();
