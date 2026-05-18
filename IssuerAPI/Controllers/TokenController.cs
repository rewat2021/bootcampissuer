using IssuerAPI.Models;
using IssuerAPI.Service;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace IssuerAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Tags("Authorization & Token")]
    public class TokenController : ControllerBase
    {

        private readonly IWebHostEnvironment _env;
        private readonly Oid4VciOptions _options;
        private IConfiguration _config;
        private string credentialOfferId = null;

        public TokenController(IConfiguration config, IWebHostEnvironment env, IOptions<Oid4VciOptions> options)
        {
            _config = config;
            _env = env;
            _options = options.Value;
        }

        [Route("/token")]
        [HttpPost]
        public IActionResult Token([FromForm] TokenExchangePreAuthRequest request)
        {
            //case FT.IC.AU.H.I.VB.002 => EUT holder work IssuerVC
            string key = "sX2CpoKx";
            //logs.Clear();

            //get value pre-authorized code from db
            DBService dbServ = new DBService();
            if (string.IsNullOrEmpty(request.PreAuthorizedCode))
            {
                var item = new ApiLogs
                {
                    message = "Issue VC – Token Exchange (Token Exchange Request Fail ❌)",
                    status = 400,
                    error = new List<string> { "pre-authorized_code is Require" }
                };
                // logs.Add(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
                return BadRequest(new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error
                });
            }
            AccessCode accessCode = dbServ.getPreAuthorizedCode(request.PreAuthorizedCode, out string registerId);
            key = accessCode.authoriseCode;
            string RegisterId = registerId;
            string ErrorDetails = null;

            //logs.Add(JsonSerializer.Serialize(new { message = "Accept Request ✅" }, new JsonSerializerOptions { WriteIndented = true }));
            //logs.Add(JsonSerializer.Serialize(request, new JsonSerializerOptions { WriteIndented = true }));

            if (request.GrantType != "urn:ietf:params:oauth:grant-type:pre-authorized_code")
            {
                // ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Holder, AppConstant.Issuer, "FT.IC.TE.H.I.VB.005", "unsupported_grant_type", "400", key);
                return BadRequest(new
                {
                    message = "unsupported_grant_type",
                    status = 400,
                });
            }

            // ต้องมี pre-authorized_code
            if (string.IsNullOrWhiteSpace(request.PreAuthorizedCode))
            {
                // ErrorDetails = System.Text.Json.JsonSerializer.Serialize(new { error = "invalid_request", error_description = "Missing pre-authorized_code" });
                // ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Holder, AppConstant.Issuer, "FT.IC.TE.H.I.VB.005", ErrorDetails, "400", key);
                return BadRequest(new
                {
                    message = "Missing pre-authorized_code",
                    status = 400,
                    error = new List<string> { "invalid_request" }
                });
            }

            /*
             * รอ ui ว่าต้องมี pin code
             * if (string.IsNullOrWhiteSpace(request.TxCode))
            {
                //ErrorDetails = System.Text.Json.JsonSerializer.Serialize(new { error = "invalid_request", error_description = "tx_code is required" });
                //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Holder, AppConstant.Issuer, "FT.IC.TE.H.I.VB.005", ErrorDetails, "400", key);
                return BadRequest(new
                {
                    message = "tx_code is required",
                    status = 400,
                    error = new List<string> { "invalid_request" }
                });
            }*/


            if (request.GrantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code" && string.IsNullOrEmpty(request.PreAuthorizedCode))
            {
                var item = new ApiLogs
                {
                    message = "Issue VC – Token Exchange (Token Exchange Request Fail ❌)",
                    status = 400,
                    error = new List<string> { "pre-authorized_code is Require" }
                };
                //logs.Add(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
                return BadRequest(new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error
                });
            }
            if (string.IsNullOrEmpty(request.GrantType))
            {
                var item = new ApiLogs
                {
                    message = "Issue VC – Token Exchange (Token Exchange Request Fail ❌)",
                    status = 400,
                    error = new List<string> { "grant_type is Require" }
                };
                //logs.Add(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
                return BadRequest(new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error
                });
            }
            if (request.GrantType != "urn:ietf:params:oauth:grant-type:pre-authorized_code" && !(Uri.IsWellFormedUriString(request.GrantType, UriKind.Absolute)))
            {
                var item = new ApiLogs
                {
                    message = "Issue VC – Token Exchange (Token Exchange Request Fail ❌)",
                    status = 400,
                    error = new List<string> { "grant_type is invalid" }
                };
                // logs.Add(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
                return new JsonResult(new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error
                })
                {
                    StatusCode = 400
                };
            }
            if (!ModelState.IsValid)
            {
                var item = new ApiLogs
                {
                    message = "Issue VC – Token Exchange (Token Exchange Request Fail ❌)",
                    status = 400,
                    error = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList()
                };
                //logs.Add(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
                return new JsonResult(new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error
                })
                {
                    StatusCode = 400
                };
            }
            //logs.Add(JsonSerializer.Serialize(new { message = "Return Token ✅" }, new JsonSerializerOptions { WriteIndented = true }));
            //logs.Add(JsonSerializer.Serialize(new ApiLogs
            //{
            //    message = "Issue VC – Token Exchange (Token Exchange Request Pass ✅)",
            //    status = 200,
            //    error = new List<string>()
            //}, new JsonSerializerOptions { WriteIndented = true }));



            // Validate the pre-authorized code
            if (string.IsNullOrEmpty(key))
            {
                var item = new ApiLogs
                {
                    error = new List<string> { "Invalid pre-authorized_code" },
                    message = "Issue VC – Token Exchange (Token Exchange Request Fail ❌)",
                    status = 401
                };
                //logs.Add(JsonSerializer.Serialize(new ApiLogs
                //{
                //    message = item.message,
                //    status = item.status,
                //    error = item.error
                //}, new JsonSerializerOptions { WriteIndented = true }));
                return new JsonResult(Unauthorized(new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error
                }));
            }

            if (!key.Equals(request.PreAuthorizedCode))
            {
                var item = new ApiLogs
                {
                    error = new List<string> { "Invalid pre-authorized_code" },
                    message = "Issue VC – Token Exchange (Token Exchange Request Fail ❌)",
                    status = 401
                };
                //logs.Add(JsonSerializer.Serialize(new ApiLogs
                //{
                //    message = item.message,
                //    status = item.status,
                //    error = item.error
                //}, new JsonSerializerOptions { WriteIndented = true }));
                return new JsonResult(Unauthorized(new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error
                }));
            }

            try
            {
                // Retrieve the Base64 encoded private key from configuration
                string privateKeyBase64 = _config["Jwt:PrivateKey"];
                if (string.IsNullOrEmpty(privateKeyBase64))
                {
                    var item = new ApiLogs
                    {
                        error = new List<string> { "Private key not configured" },
                        message = "Issue VC – Token Exchange (Token Exchange Request Fail ❌)",
                        status = 500
                    };
                    //logs.Add(JsonSerializer.Serialize(new ApiLogs
                    //{
                    //    message = item.message,
                    //    status = item.status,
                    //    error = item.error
                    //}, new JsonSerializerOptions { WriteIndented = true }));
                    return StatusCode(500, new
                    {
                        message = item.message,
                        status = item.status,
                        error = item.error
                    });
                }

                // Convert Base64 string back to byte array
                byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

                // Create an ECDsa instance with the private key
                var ecdsa = ECDsa.Create();
                ecdsa.ImportECPrivateKey(privateKeyBytes, out _);

                // Create a new ECDsaSecurityKey
                var ecdsaSecurityKey = new ECDsaSecurityKey(ecdsa);

                // Define token parameters
                var tokenHandler = new JwtSecurityTokenHandler();

                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, accessCode.RegisterId),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.UtcNow.AddHours(1),
                    Audience = $"{_config["Jwt:Issuer"]}/credential", // Set the audience claim here
                    Issuer = _config["Jwt:Issuer"], // Set the issuer claim here
                    SigningCredentials = new SigningCredentials(ecdsaSecurityKey, SecurityAlgorithms.EcdsaSha256)
                };

                // Create and write the token
                var token = tokenHandler.CreateToken(tokenDescriptor);
                string tokenString = tokenHandler.WriteToken(token);

                var response = new
                {
                    access_token = tokenString,
                    token_type = "Bearer",
                    expires_in = (int)TimeSpan.FromHours(1).TotalSeconds, // Token expiration time in seconds
                    c_nonce = accessCode.C_Nonce, // Replace with actual nonce value if needed
                    c_nonce_expires_in = (int)TimeSpan.FromHours(1).TotalSeconds, // Nonce expiration time in seconds

                    authorization_details = new[]
                    {
                        new
                        {
                            type = "openid_credential",
                            credential_configuration_id = $"{accessCode.CredentialType}"
                        }
                        
                    }


                };


                //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Issuer, AppConstant.Holder, null, $"access token => {JsonSerializer.Serialize(response)}", "200", null);
                //ActionLog.InsertLogAction(AppContextHelper.UserId, AppConstant.Holder, AppConstant.Issuer, "FT.IC.TE.H.I.VB.001, FT.IC.TE.H.I.VB.002, FT.IC.TE.H.I.VB.003", $"access token => {JsonSerializer.Serialize(response)}", "200", null);



                return Ok(response);
                //return new JsonResult(new { response });
            }
            catch (Exception ex)
            {

                var item = new ApiLogs
                {
                    message = "Issue VC – Token Exchange (Token Exchange Request Fail ❌)",
                    status = 500,
                    error = new List<string> { ex.Message }
                };
                //  logs.Add(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
                return StatusCode(500, new
                {
                    message = item.message,
                    status = item.status,
                    error = item.error,
                });
            }
        }
    }
}
