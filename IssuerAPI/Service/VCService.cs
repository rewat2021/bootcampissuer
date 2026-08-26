using IssuerAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using NSec.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using QRCoder;
using SimpleBase;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using PeterO.Cbor;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography;
using System.Numerics;


namespace IssuerAPI.Service
{
    
    public class JWSModel
    {
        public string header { get; set; }
        public string payload { get; set; }
        public string proof { get; set; }
        public string publicKey { get; set; }
        public string didkey { get; set; }  
        public string vptoken { get; set; }
        public string vctoken { get; set; }

        public string statusCode { get; set; }
        public string statusName { get; set; }

        public JWSModel(string header, string payload, string proof)
        {
            this.header = header;
            this.payload = payload;
            this.proof = proof;
        }
        public JWSModel()
        {
            //
        }
    }

    public class VCService
    {
        public JWSModel jwsModel { get; set; }
        public VCService()
        {
            jwsModel = new JWSModel(null, null, null);
        }

        public string GenerateIssuerDID()
        {
            byte versionByte = 1;
            var prefix = "z";
            byte[] random = new Byte[17];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(random);
            random[0] = versionByte;
            var msi = prefix + Base58.Bitcoin.Encode(random);
            var legalEntityDID = "did:tbsi:" + msi;

            return legalEntityDID;
        }

        public string Base64UrlDecodeToString(string input)
        {
            string base64 = input.Replace('-', '+').Replace('_', '/');

            // Pad with '=' characters if necessary
            while (base64.Length % 4 != 0)
            {
                base64 += '=';
            }

            byte[] bytes = Convert.FromBase64String(base64);
            return Encoding.UTF8.GetString(bytes);
        }

        public byte[] Base64UrlDecode(string base64Url)
        {
            // Replace '-' with '+' and '_' with '/'
            string base64 = base64Url.Replace('-', '+').Replace('_', '/');

            // Pad with '=' to make the length a multiple of 4
            switch (base64.Length % 4)
            {
                case 2:
                    base64 += "==";
                    break;
                case 3:
                    base64 += "=";
                    break;
            }

            // Convert from Base64 to bytes
            return Convert.FromBase64String(base64);
        }

        public string CheckHttps(string Protocol)
        {

            string result = null;
            if ((Protocol == null) | Protocol == "0")
            {
                result = "http://";
            }

            else
            {
                result = "https://";
            }

            return result;
        }

        public  string GenerateQrCodeBase64(string data)
        {
            QRCodeGenerator qRCodeGenerator = new QRCodeGenerator();
            var QRData = qRCodeGenerator.CreateQrCode(data, QRCoder.QRCodeGenerator.ECCLevel.Q);
            QRCoder.Base64QRCode base64qr = new QRCoder.Base64QRCode(QRData);
            var result = base64qr.GetGraphic(7);
            return result;
        }

        public async Task<string> ResolveDID(string key)
        {
            string publickey = null;
            try
            {
                HttpClient client = new HttpClient();
                string url = $"https://resolver-test.etda.or.th/1.0/identifiers/{key}";
                // Set request headers if needed (e.g., Accept)
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                HttpResponseMessage response = await client.GetAsync(url);
                response.EnsureSuccessStatusCode();

                // Read and deserialize the response content

                string jsonResponse = await response.Content.ReadAsStringAsync();
                JsonDocument document = JsonDocument.Parse(jsonResponse);
                JsonElement root = document.RootElement;

                foreach (JsonElement method in root.GetProperty("verificationMethod").EnumerateArray())
                {
                    // Extracting "publicKeyJwk" object inside "verificationMethod"
                    JsonElement publicKeyJwk = method.GetProperty("publicKeyJwk");
                    publickey = publicKeyJwk.GetProperty("x").GetString();
                }


            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }

            return publickey;
        }

        public string ResolveStateID(string jws)
        {
            string headerJson = Base64UrlDecodeToString(jws);
            using JsonDocument doc = JsonDocument.Parse(headerJson);
            string stateid = doc.RootElement.GetProperty("jti").GetString();

            return stateid;
        }

        public string GenStateId()
        {
            byte versionByte = 1;
            byte[] random = new Byte[8];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(random);
            random[0] = versionByte;
            return Base58.Bitcoin.Encode(random);
        }

        public JwtModel DecodeJWT(string token)
        {
            var result = new JwtModel();
            if (string.IsNullOrEmpty(token)) return result;
            var tokenArr = token.Split('.');
            result.Header = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(tokenArr[0]));
            result.Payload = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(tokenArr[1]));
            return result;
        }

        public JWSModel ResolvePublicKey(string jws)
        {
            bool isValid = false;
            JWSModel result = new JWSModel();


            var parts = jws.Split('.');
            if (parts.Length != 3)
                throw new ArgumentException("Invalid JWS format.");

            try
            {
                // Decode the Base64Url components
                byte[] header = WebEncoders.Base64UrlDecode(parts[0]);
                byte[] payload_ = WebEncoders.Base64UrlDecode(parts[1]);
                byte[] signature = WebEncoders.Base64UrlDecode(parts[2]);

                string headerJson = Base64UrlDecodeToString(parts[0]);
                using JsonDocument doc = JsonDocument.Parse(headerJson);
                string kid = doc.RootElement.GetProperty("kid").GetString();

                result.header = parts[0];
                result.payload = parts[1];
                result.proof = parts[2];
                result.didkey = kid; 
                if (kid.IndexOf('#') > 0)
                {
                    result.didkey = kid.Split('#')[0];
                }
                


            }
            catch (Exception e)
            {
                result.statusCode = "400";
                result.statusName = e.Message;
                return result;
                //logs.Add(JsonSerializer.Serialize("Error => " + e.Message, new JsonSerializerOptions { WriteIndented = true }));
            }
            return result;
        }
        

        public bool VerifyJWS(string jws, string publicKey, out string ErrMsg)
        {
            ErrMsg = null;
            bool isValid = false;
            string jws_text = jws;            

            //string base64 = publicKey;
            byte[] base64Encode = Base64UrlDecode(publicKey);

            var parts = jws.Split('.');
            if (parts.Length != 3)
                throw new ArgumentException("Invalid JWS format.");

            try
            {
                // Decode the Base64Url components
                byte[] header = WebEncoders.Base64UrlDecode(parts[0]);
                byte[] payload_ = WebEncoders.Base64UrlDecode(parts[1]);
                byte[] signature = WebEncoders.Base64UrlDecode(parts[2]);

                jwsModel.header = parts[0];
                jwsModel.payload = parts[1];
                jwsModel.proof = parts[2];

                // Reconstruct the signed data (Header + '.' + Payload)
                byte[] signedData = System.Text.Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);

                // Create the Ed25519 public key from the provided Base64-encoded string
                var key = PublicKey.Import(SignatureAlgorithm.Ed25519, base64Encode, KeyBlobFormat.RawPublicKey);

                // Verify the signature
                isValid = SignatureAlgorithm.Ed25519.Verify(key, signedData, signature);
                if(!isValid)
                {
                    ErrMsg = "vp_token is invalid";
                }
            }
            catch (Exception e)
            {
                ErrMsg = e.Message;
                return false;
            }
            return isValid;

        }


        public string VerifyVCToken(string vp_payload)
        {
            string vc_token = null;

            try
            {
                // Decode the Base64Url components
                string payload = Base64UrlDecodeToString(vp_payload);
                Root rootObject = JsonSerializer.Deserialize<Root>(payload);

                vc_token = rootObject.Vp.VerifiableCredential[0];


            }
            catch (Exception e)
            {
                //ErrMsg = e.Message;
                //return false;
            }
            return vc_token;
        }

        public string GetKey(bool isPrivate, IWebHostEnvironment _env, string keyType)
        {
            var client = "Tester";
            string privateKeyDbKey = $"{keyType}_privateKey";
            string publicKeyDbKey = $"{keyType}_publicKey";

            var privateKey = Database.Read(client, privateKeyDbKey, _env);
            var publicKey = Database.Read(client, publicKeyDbKey, _env);

            if (string.IsNullOrEmpty(privateKey) || string.IsNullOrEmpty(publicKey))
            {
                // สร้าง ECDSA P-256 key pair ใหม่ — คนละคู่จาก Ed25519 ที่ GetKey เดิมสร้าง
                // เพราะ mdoc (ISO 18013-5) บังคับต้องใช้ ES256 เท่านั้น
                using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                privateKey = ecdsa.ExportPkcs8PrivateKeyPem();
                publicKey = ecdsa.ExportSubjectPublicKeyInfoPem();

                Database.Write(client, privateKeyDbKey, privateKey, _env);
                Database.Write(client, publicKeyDbKey, publicKey, _env);
            }

            return isPrivate ? privateKey : publicKey;
        }

        public string GetKey(bool isPrivate, IWebHostEnvironment _env)
        {
            var client = "Tester";
            var privateKey = "";
            var publicKey = "";

            privateKey = Database.Read(client, "privateKey", _env);
            publicKey = Database.Read(client, "publicKey", _env);

            if (string.IsNullOrEmpty(privateKey) || string.IsNullOrEmpty(publicKey))
            {
                var keyPairGenerator = new Ed25519KeyPairGenerator();
                keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                var keyPair = keyPairGenerator.GenerateKeyPair();

                var privateKeyEd25519 = (Ed25519PrivateKeyParameters)keyPair.Private;
                var publicKeyEd25519 = (Ed25519PublicKeyParameters)keyPair.Public;

                using (var memoryStream = new MemoryStream())
                {
                    var pemWriter = new PemWriter(new StreamWriter(memoryStream));
                    pemWriter.WriteObject(privateKeyEd25519);
                    pemWriter.Writer.Flush();
                    privateKey = Encoding.UTF8.GetString(memoryStream.ToArray());
                }
                var temp = Convert.ToBase64String(publicKeyEd25519.GetEncoded());
                using (var memoryStream = new MemoryStream())
                {
                    var pemWriter = new PemWriter(new StreamWriter(memoryStream));
                    pemWriter.WriteObject(publicKeyEd25519);
                    pemWriter.Writer.Flush();
                    publicKey = Encoding.UTF8.GetString(memoryStream.ToArray());
                }


                Database.Write(client, "privateKey", privateKey, _env);
                Database.Write(client, "publicKey", publicKey, _env);
            }

            if (isPrivate) return privateKey;
            else return publicKey;
        }

        public string GetSubKey(bool isPrivate, IWebHostEnvironment _env)
        {
            var client = "Tester";
            var privateKey = "";
            var publicKey = "";

            privateKey = Database.Read(client, "subPrivate", _env);
            publicKey = Database.Read(client, "subPublic", _env);

            if (string.IsNullOrEmpty(privateKey) || string.IsNullOrEmpty(publicKey))
            {
                var keyPairGenerator = new Ed25519KeyPairGenerator();
                keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                var keyPair = keyPairGenerator.GenerateKeyPair();

                var privateKeyEd25519 = (Ed25519PrivateKeyParameters)keyPair.Private;
                var publicKeyEd25519 = (Ed25519PublicKeyParameters)keyPair.Public;

                using (var memoryStream = new MemoryStream())
                {
                    var pemWriter = new PemWriter(new StreamWriter(memoryStream));
                    pemWriter.WriteObject(privateKeyEd25519);
                    pemWriter.Writer.Flush();
                    privateKey = Encoding.UTF8.GetString(memoryStream.ToArray());
                }
                var temp = Convert.ToBase64String(publicKeyEd25519.GetEncoded());
                using (var memoryStream = new MemoryStream())
                {
                    var pemWriter = new PemWriter(new StreamWriter(memoryStream));
                    pemWriter.WriteObject(publicKeyEd25519);
                    pemWriter.Writer.Flush();
                    publicKey = Encoding.UTF8.GetString(memoryStream.ToArray());
                }


                Database.Write(client, "subPrivate", privateKey, _env);
                Database.Write(client, "subPublic", publicKey, _env);
            }

            if (isPrivate) return privateKey;
            else return publicKey;
        }

        public string _GetDID(IWebHostEnvironment _env)
        {
            var client = "Tester";
            //var privateKey = Database.Read(client, "privateKey", _env);
            var publicKey = Database.Read(client, "publicKey", _env);
            var diddoc = Database.ReadDID(client, "DID", _env);

            if (string.IsNullOrEmpty(diddoc))
            {
                VCService serv = new VCService();
                PemReader pemReaderPublic = new PemReader(new StringReader(serv.GetKey(false, _env)));
                Ed25519PublicKeyParameters publicKeyEd25519 = (Ed25519PublicKeyParameters)pemReaderPublic.ReadObject();

                byte[] publicKeyBytes = publicKeyEd25519.GetEncoded();
                byte[] multicodecPrefix = new byte[] { 0xED, 0x01 };

                byte[] privateKeyWithPrefix = new byte[multicodecPrefix.Length + publicKeyBytes.Length];

                Buffer.BlockCopy(multicodecPrefix, 0, privateKeyWithPrefix, 0, multicodecPrefix.Length);
                Buffer.BlockCopy(publicKeyBytes, 0, privateKeyWithPrefix, multicodecPrefix.Length, publicKeyBytes.Length);

                var privateKeyString = "z" + Base58.Bitcoin.Encode(privateKeyWithPrefix);
                diddoc = "did:key:" + privateKeyString;// + "#" + privateKeyString;

                Database.Write(client, "DID", diddoc, _env);
            }


            return diddoc;
        }

        // did:web counterpart to _GetDID (did:key), same Ed25519 key material — different identifier
        // scheme, not a replacement. did:web binds the DID to this issuer's actual HTTPS domain
        // (resolved by fetching /.well-known/did.json over TLS) instead of being a bare
        // self-certifying identifier, which some institutional verifiers expect/prefer for issuer
        // trust. Existing did:key-based issuance, proof verification, and mdoc IssuerAuth are
        // unaffected — this is purely an additional, alternate identity for the same key.
        //
        // did:web has no path segments here (baseUrl is scheme+host[:port] only, no sub-path), so the
        // DID document is served at the plain /.well-known/did.json location per the did:web spec.
        public string GetDidWebId(string baseUrl)
        {
            var uri = new Uri(baseUrl);
            string hostPart = uri.IsDefaultPort ? uri.Host : $"{uri.Host}%3A{uri.Port}";
            return $"did:web:{hostPart}";
        }

        public JsonObject BuildDidWebDocument(IWebHostEnvironment _env, string baseUrl)
        {
            string didWeb = GetDidWebId(baseUrl);

            PemReader pemReaderPublic = new PemReader(new StringReader(GetKey(false, _env)));
            Ed25519PublicKeyParameters publicKeyEd25519 = (Ed25519PublicKeyParameters)pemReaderPublic.ReadObject();
            byte[] publicKeyBytes = publicKeyEd25519.GetEncoded();

            // Same multicodec (0xED 0x01 = Ed25519 public key) + base58btc multibase encoding used by
            // did:key above — this yields the identical "z6Mk..." string, just carried as
            // publicKeyMultibase here instead of embedded in the DID itself.
            byte[] multicodecPrefix = new byte[] { 0xED, 0x01 };
            byte[] prefixed = new byte[multicodecPrefix.Length + publicKeyBytes.Length];
            Buffer.BlockCopy(multicodecPrefix, 0, prefixed, 0, multicodecPrefix.Length);
            Buffer.BlockCopy(publicKeyBytes, 0, prefixed, multicodecPrefix.Length, publicKeyBytes.Length);
            string publicKeyMultibase = "z" + Base58.Bitcoin.Encode(prefixed);

            string keyId = $"{didWeb}#key-1";

            var verificationMethod = new JsonObject
            {
                ["id"] = keyId,
                ["type"] = "Ed25519VerificationKey2020",
                ["controller"] = didWeb,
                ["publicKeyMultibase"] = publicKeyMultibase
            };

            return new JsonObject
            {
                ["@context"] = new JsonArray(
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/ed25519-2020/v1"
                ),
                ["id"] = didWeb,
                ["verificationMethod"] = new JsonArray(verificationMethod),
                ["authentication"] = new JsonArray(keyId),
                ["assertionMethod"] = new JsonArray(keyId)
            };
        }


        public bool IsTokenValid(IConfiguration _config, string token)
        {
            try
            {
                // Retrieve the Base64 encoded private key from configuration
                string privateKeyBase64 = _config["Jwt:PrivateKey"];
                if (string.IsNullOrEmpty(privateKeyBase64))
                {
                    // Log or handle the error as needed
                    return false;
                }

                // Convert Base64 string back to byte array
                byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

                // Create an ECDsa instance with the private key
                var ecdsa = ECDsa.Create();
                ecdsa.ImportECPrivateKey(privateKeyBytes, out _);

                // Create a new ECDsaSecurityKey (you could also derive the public key from this)
                var ecdsaSecurityKey = new ECDsaSecurityKey(ecdsa);

                // Set up validation parameters
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = ecdsaSecurityKey,
                    ValidateIssuer = true,
                    ValidIssuer = _config["Jwt:Issuer"], // The expected issuer
                    ValidateAudience = true,
                    ValidAudience = $"{_config["Jwt:Issuer"]}/credential", //"everyone", // The expected audience
                    // C-04: access tokens now carry a short (5 min, see TokenController) lifetime and
                    // must actually be enforced — accepting expired tokens defeats the point of a
                    // short-lived token entirely.
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(30)
                };

                // Validate the token
                var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                // If token is valid, return true
                return validatedToken != null;
            }
            catch (Exception ex)
            {
                // Log or handle the exception as needed
                return false;
            }
        }

        // C-02: used by CredentialController to cross-check that the "sub" claim bound into the
        // access token at /token time matches the registerId this /credential request is trying to
        // issue against, so a token issued for one pre-authorized grant can't be replayed to pull a
        // different holder's document type. Returns null if the token doesn't validate.
        public string? ValidateTokenAndGetSubject(IConfiguration _config, string token)
        {
            try
            {
                string privateKeyBase64 = _config["Jwt:PrivateKey"];
                if (string.IsNullOrEmpty(privateKeyBase64))
                {
                    NLog.LogManager.GetCurrentClassLogger().Warn("ValidateTokenAndGetSubject: Jwt:PrivateKey is not configured");
                    return null;
                }

                byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
                var ecdsa = ECDsa.Create();
                ecdsa.ImportECPrivateKey(privateKeyBytes, out _);
                var ecdsaSecurityKey = new ECDsaSecurityKey(ecdsa);

                var tokenHandler = new JwtSecurityTokenHandler();
                // JwtSecurityTokenHandler remaps short inbound claim types to long claim URIs by
                // default (e.g. "sub" -> ClaimTypes.NameIdentifier) unless told not to. That silent
                // rename is why FindFirst(JwtRegisteredClaimNames.Sub) below could return null even for
                // a token that validated successfully (no exception thrown, nothing to log) — the "sub"
                // claim is still there, just renamed. Keep the raw JWT claim names as-is.
                tokenHandler.MapInboundClaims = false;

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = ecdsaSecurityKey,
                    ValidateIssuer = true,
                    ValidIssuer = _config["Jwt:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = $"{_config["Jwt:Issuer"]}/credential",
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(30)
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                string sub = principal.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value;
                if (sub == null)
                {
                    // Token validated fine (signature/issuer/audience/lifetime all passed — no
                    // exception) but has no "sub" claim under that exact name. Dump every claim type
                    // actually present so the mismatch is visible instead of guessing again.
                    string claimDump = string.Join(", ", principal.Claims.Select(c => $"{c.Type}={c.Value}"));
                    NLog.LogManager.GetCurrentClassLogger().Warn(
                        $"ValidateTokenAndGetSubject: token validated but no 'sub' claim found. Claims present: [{claimDump}]");
                }
                return sub;
            }
            catch (Exception ex)
            {
                // The client only ever sees the generic "Token is invalid or expired" (H-04 — no
                // internals leaked), but that made this completely unobservable server-side too.
                // Log the real reason (expired vs bad signature vs iss/aud mismatch vs malformed) so
                // it's actually diagnosable from server logs instead of guessing.
                NLog.LogManager.GetCurrentClassLogger().Warn(ex, "ValidateTokenAndGetSubject: token rejected");
                return null;
            }
        }

        public string GetGUID()
        {
            Guid guid = Guid.NewGuid();
            return guid.ToString();
        }

        public bool IsValidJson(string jsonString)
        {
            if (string.IsNullOrWhiteSpace(jsonString))
            {
                return false; // Null or empty string is not valid JSON
            }

            try
            {
                using (JsonDocument.Parse(jsonString))
                {
                    return true; // Successfully parsed, it's valid JSON
                }
            }
            catch (JsonException)
            {
                return false; // Parsing failed, not valid JSON
            }
            catch (Exception)
            {
                return false; // Catch other unexpected errors
            }
        }

        public bool IsValidNonce(string? nonce)
        {
            // Check if the nonce is null, empty, or whitespace
            if (string.IsNullOrWhiteSpace(nonce))
            {
                return false; // Nonce is undefined
            }


            // Check for valid format (e.g., base64 or alphanumeric)
            string base64Pattern = @"^[a-zA-Z0-9-_]+$";
            if (!Regex.IsMatch(nonce, base64Pattern))
            {
                return false; // Nonce format is invalid
            }

            return true; // Nonce is valid
        }

        public  bool IsValidPresentationDefinition(string? presentationDefinitionJson)
        {
            if (string.IsNullOrWhiteSpace(presentationDefinitionJson))
            {
                Console.WriteLine("Error: presentation_definition is undefined or null.");
                return false;
            }

            try
            {
                // Parse the JSON
                using var document = JsonDocument.Parse(presentationDefinitionJson);
                var root = document.RootElement;

                // Validate 'id'
                if (!root.TryGetProperty("id", out JsonElement idElement) ||
                    string.IsNullOrWhiteSpace(idElement.GetString()))
                {
                    Console.WriteLine("Error: Missing or invalid 'id' in presentation_definition.");
                    return false;
                }

                // Validate 'input_descriptors'
                if (!root.TryGetProperty("input_descriptors", out JsonElement inputDescriptorsElement) ||
                    inputDescriptorsElement.ValueKind != JsonValueKind.Array ||
                    inputDescriptorsElement.GetArrayLength() == 0)
                {
                    Console.WriteLine("Error: Missing or invalid 'input_descriptors' in presentation_definition.");
                    return false;
                }

                // Validate each input descriptor
                foreach (var descriptor in inputDescriptorsElement.EnumerateArray())
                {
                    if (!descriptor.TryGetProperty("id", out JsonElement descriptorIdElement) ||
                        string.IsNullOrWhiteSpace(descriptorIdElement.GetString()))
                    {
                        Console.WriteLine("Error: Invalid 'id' in input_descriptor.");
                        return false;
                    }

                    if (!descriptor.TryGetProperty("format", out JsonElement formatElement) ||
                        !formatElement.TryGetProperty("jwt_vc_json", out JsonElement jwtVcJson) ||
                        !jwtVcJson.TryGetProperty("alg", out JsonElement algElement) ||
                        algElement.ValueKind != JsonValueKind.Array ||
                        algElement.GetArrayLength() == 0)
                    {
                        Console.WriteLine("Error: Invalid 'format' in input_descriptor.");
                        return false;
                    }

                    if (!descriptor.TryGetProperty("constraints", out JsonElement constraintsElement) ||
                        !constraintsElement.TryGetProperty("fields", out JsonElement fieldsElement) ||
                        fieldsElement.ValueKind != JsonValueKind.Array ||
                        fieldsElement.GetArrayLength() == 0)
                    {
                        Console.WriteLine("Error: Invalid 'constraints' in input_descriptor.");
                        return false;
                    }

                    foreach (var field in fieldsElement.EnumerateArray())
                    {
                        if (!field.TryGetProperty("path", out JsonElement pathElement) ||
                            pathElement.ValueKind != JsonValueKind.Array ||
                            pathElement.GetArrayLength() == 0 ||
                            !field.TryGetProperty("filter", out JsonElement filterElement) ||
                            !filterElement.TryGetProperty("pattern", out JsonElement patternElement) ||
                            string.IsNullOrWhiteSpace(patternElement.GetString()))
                        {
                            Console.WriteLine("Error: Invalid 'field' in constraints.");
                            return false;
                        }
                    }
                }

                return true; // All checks passed
            }
            catch (JsonException)
            {
                Console.WriteLine("Error: Invalid JSON format for presentation_definition.");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error: {ex.Message}");
                return false;
            }
        }

        public string GenerateJWTEd25519(string payload, string issuerid, Ed25519PrivateKeyParameters key)
        {
            string header = $"{{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"{issuerid}\"}}";
            var payloadJson = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
            var headerJson = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(header))
                .Replace("+", "-") // Replace '+' with '-'
                .Replace("/", "_") // Replace '/' with '_'
                .TrimEnd('=');     // Remove padding characters ('=')
            var signingString = headerJson + "." + payloadJson; //$"{headerJson}.{payloadJson}";
            var payloadBytes = Encoding.UTF8.GetBytes(signingString);


            var signer = new Ed25519Signer();
            signer.Init(true, key);
            signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);


            string encodedSignature = WebEncoders.Base64UrlEncode(signer.GenerateSignature());


            return $"{headerJson}.{payloadJson}.{encodedSignature}";

            
        }

        // Appendix F.1 / §13.8 of OID4VCI 1.0 Final: "iat" in a wallet proof JWT is used by the issuer to
        // detect stale/replayed proofs. A window that tolerates up to 10 years in the future (the old
        // behavior here) makes "iat" freshness checking meaningless. Use a tight window instead: a
        // few minutes of clock skew tolerance in either direction.
        private const int ProofIatClockSkewToleranceSeconds = 300;
        private const int ProofIatMaxAgeSeconds = 300;

        public bool IsValidNumericDate(long numericDate)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long earliestAllowed = now - ProofIatMaxAgeSeconds - ProofIatClockSkewToleranceSeconds;
            long latestAllowed = now + ProofIatClockSkewToleranceSeconds;

            return numericDate >= earliestAllowed && numericDate <= latestAllowed;
        }

        // C-01: decode a did:key (multicodec 0xED 0x01 = Ed25519 public key, base58btc "z..."
        // multibase-encoded) into the raw 32-byte Ed25519 public key so the wallet's proof JWT
        // signature can actually be verified against it.
        public byte[]? DecodeEd25519DidKey(string didKey)
        {
            if (string.IsNullOrWhiteSpace(didKey)) return null;

            const string prefix = "did:key:";
            if (!didKey.StartsWith(prefix, StringComparison.Ordinal)) return null;

            string multibaseValue = didKey.Substring(prefix.Length);
            if (multibaseValue.Length == 0 || multibaseValue[0] != 'z') return null; // 'z' = base58btc

            byte[] decoded;
            try
            {
                decoded = Base58.Bitcoin.Decode(multibaseValue.Substring(1)).ToArray();
            }
            catch
            {
                return null;
            }

            // multicodec varint prefix for Ed25519 public key is 0xED 0x01
            if (decoded.Length != 34 || decoded[0] != 0xED || decoded[1] != 0x01)
            {
                return null;
            }

            byte[] rawKey = new byte[32];
            Buffer.BlockCopy(decoded, 2, rawKey, 0, 32);
            return rawKey;
        }

        // C-01: verify the Ed25519 signature over a compact JWS (header.payload.signature) against
        // the given raw 32-byte public key. This is the check that was completely missing before —
        // any syntactically well-formed proof JWT was accepted regardless of who (if anyone) signed it.
        public bool VerifyEd25519Jws(string jws, byte[] rawPublicKey, out string errMsg)
        {
            errMsg = null;
            try
            {
                if (rawPublicKey == null || rawPublicKey.Length != 32)
                {
                    errMsg = "invalid public key";
                    return false;
                }

                string[] parts = jws.Split('.');
                if (parts.Length != 3)
                {
                    errMsg = "malformed JWS";
                    return false;
                }

                byte[] signature = WebEncoders.Base64UrlDecode(parts[2]);
                byte[] signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

                var algorithm = SignatureAlgorithm.Ed25519;
                var publicKey = NSec.Cryptography.PublicKey.Import(algorithm, rawPublicKey, KeyBlobFormat.RawPublicKey);

                bool ok = algorithm.Verify(publicKey, signingInput, signature);
                if (!ok) errMsg = "signature verification failed";
                return ok;
            }
            catch (Exception ex)
            {
                errMsg = ex.Message;
                return false;
            }
        }

        // NIST P-256 (secp256r1) curve parameters, used only to decompress a did:key-encoded P-256
        // point (see DecodeP256DidKey below). y^2 = x^3 - 3x + b (mod p).
        private static readonly BigInteger P256_P = new BigInteger(
            Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
            isUnsigned: true, isBigEndian: true);
        private static readonly BigInteger P256_B = new BigInteger(
            Convert.FromHexString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
            isUnsigned: true, isBigEndian: true);

        private static byte[] ToFixedBigEndian(BigInteger value, int length)
        {
            byte[] raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (raw.Length == length) return raw;
            if (raw.Length > length) return raw[(raw.Length - length)..];
            byte[] padded = new byte[length];
            Array.Copy(raw, 0, padded, length - raw.Length, raw.Length);
            return padded;
        }

        // Decompresses a SEC1-compressed P-256 point (0x02/0x03 || 32-byte x) into an uncompressed
        // point (0x04 || 32-byte x || 32-byte y). did:key encodes P-256 keys in compressed form, but
        // .NET's ECParameters/ECPoint API only accepts explicit X/Y — there's no built-in decompress.
        // Internal (not private): VerifierService reuses this for did:web P-256 keys too, since
        // did:web's publicKeyMultibase uses the exact same compressed-point encoding as did:key.
        internal static byte[]? DecompressP256Point(byte[] compressed)
        {
            if (compressed == null || compressed.Length != 33 || (compressed[0] != 0x02 && compressed[0] != 0x03))
                return null;

            try
            {
                var x = new BigInteger(compressed[1..], isUnsigned: true, isBigEndian: true);

                // y^2 = x^3 - 3x + b (mod p)
                var rhs = ((BigInteger.ModPow(x, 3, P256_P) - 3 * x + P256_B) % P256_P + P256_P) % P256_P;

                // P-256's prime p ≡ 3 (mod 4), so a square root (if one exists) is rhs^((p+1)/4) mod p.
                var y = BigInteger.ModPow(rhs, (P256_P + 1) / 4, P256_P);

                // Verify rhs actually was a quadratic residue (x was really on the curve), not just
                // blindly trust the computed root.
                if (BigInteger.ModPow(y, 2, P256_P) != rhs) return null;

                bool computedYIsOdd = !y.IsEven;
                bool wantOddY = compressed[0] == 0x03;
                if (computedYIsOdd != wantOddY)
                {
                    y = P256_P - y;
                }

                byte[] result = new byte[65];
                result[0] = 0x04;
                Array.Copy(compressed, 1, result, 1, 32);
                Array.Copy(ToFixedBigEndian(y, 32), 0, result, 33, 32);
                return result;
            }
            catch
            {
                return null;
            }
        }

        // ES256 counterpart to DecodeEd25519DidKey. did:key P-256 keys use multicodec 0x1200
        // (varint-encoded as 0x80 0x24) over a 33-byte SEC1-compressed public key point, versus
        // Ed25519's 0xED 0x01 over a raw 32-byte key. Returns a 65-byte uncompressed point
        // (0x04 || X || Y) suitable for ECParameters.Q, or null if the kid isn't a valid P-256 did:key.
        public byte[]? DecodeP256DidKey(string didKey)
        {
            if (string.IsNullOrWhiteSpace(didKey)) return null;

            const string prefix = "did:key:";
            if (!didKey.StartsWith(prefix, StringComparison.Ordinal)) return null;

            string multibaseValue = didKey.Substring(prefix.Length);
            if (multibaseValue.Length == 0 || multibaseValue[0] != 'z') return null; // 'z' = base58btc

            byte[] decoded;
            try
            {
                decoded = Base58.Bitcoin.Decode(multibaseValue.Substring(1)).ToArray();
            }
            catch
            {
                return null;
            }

            // multicodec varint prefix for a P-256 (compressed) public key is 0x80 0x24 (= 0x1200)
            if (decoded.Length != 35 || decoded[0] != 0x80 || decoded[1] != 0x24)
            {
                return null;
            }

            byte[] compressed = new byte[33];
            Buffer.BlockCopy(decoded, 2, compressed, 0, 33);
            return DecompressP256Point(compressed);
        }

        // ES256 counterpart to VerifyEd25519Jws. rawPublicKey must be a 65-byte uncompressed P-256
        // point (0x04 || X || Y) as returned by DecodeP256DidKey. JWS ES256 signatures are the raw
        // IEEE P1363 concatenation (R || S, 32 bytes each) — NOT ASN.1 DER — per RFC 7518 §3.4.
        public bool VerifyES256Jws(string jws, byte[] rawPublicKey, out string errMsg)
        {
            errMsg = null;
            try
            {
                if (rawPublicKey == null || rawPublicKey.Length != 65 || rawPublicKey[0] != 0x04)
                {
                    errMsg = "invalid public key";
                    return false;
                }

                string[] parts = jws.Split('.');
                if (parts.Length != 3)
                {
                    errMsg = "malformed JWS";
                    return false;
                }

                byte[] signature = WebEncoders.Base64UrlDecode(parts[2]);
                if (signature.Length != 64)
                {
                    errMsg = "invalid signature length (expected 64-byte IEEE P1363 R||S)";
                    return false;
                }

                byte[] signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

                var ecParams = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = rawPublicKey[1..33],
                        Y = rawPublicKey[33..65]
                    }
                };

                using var ecdsa = ECDsa.Create(ecParams);
                bool ok = ecdsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                if (!ok) errMsg = "signature verification failed";
                return ok;
            }
            catch (Exception ex)
            {
                errMsg = ex.Message;
                return false;
            }
        }

        // Builds the "cnf" (confirmation) claim embedded in issued credentials for holder binding.
        // Previously this was always `{ kid = walletid }` — a reference to the wallet's did:key that
        // requires the verifier to resolve did:key itself. Some verifiers instead expect the public
        // key material embedded directly (RFC 7800 "jwk" member) rather than doing that resolution.
        // Both forms describe the exact same, already-proof-verified key (see C-01 in
        // CredentialController — walletid only ever reaches here after its proof JWT signature was
        // verified against it), so embedding both is strictly more compatible, not a weaker claim.
        // Dispatches on whether walletid decodes as an Ed25519 or P-256 did:key (this issuer only
        // ever hands out did:key holder identifiers of one of those two types — see the proof alg
        // check in CredentialController).
        public object BuildCnf(string didKey)
        {
            byte[] ed25519Key = DecodeEd25519DidKey(didKey);
            if (ed25519Key != null)
            {
                return new
                {
                    kid = didKey,
                    jwk = new
                    {
                        kty = "OKP",
                        crv = "Ed25519",
                        x = WebEncoders.Base64UrlEncode(ed25519Key)
                    }
                };
            }

            byte[] p256Key = DecodeP256DidKey(didKey); // 65-byte uncompressed: 0x04 || X(32) || Y(32)
            if (p256Key != null)
            {
                return new
                {
                    kid = didKey,
                    jwk = new
                    {
                        kty = "EC",
                        crv = "P-256",
                        x = WebEncoders.Base64UrlEncode(p256Key[1..33]),
                        y = WebEncoders.Base64UrlEncode(p256Key[33..65])
                    }
                };
            }

            // Shouldn't happen in practice — CredentialController already validated didKey decodes
            // successfully before any credential generator is ever called. Fall back to a reference
            // only rather than throwing mid-issuance.
            return new { kid = didKey };
        }

        // Credential status per IETF "Token Status List" (referenced by SD-JWT VC for revocation).
        // statusListIndex is the dbissuedcredential row's own Id — assigned by TryMarkIssued at the
        // moment this specific credential instance was recorded as issued, so it's stable and unique
        // per issued credential without a separate counter/table.
        public object BuildStatusClaim(int statusListIndex, string baseUrl)
        {
            return new
            {
                status_list = new
                {
                    idx = statusListIndex,
                    uri = $"{baseUrl}/status-list/1"
                }
            };
        }

        // Builds and signs the Status List Token that /status-list/1 serves. One bit per issued
        // credential (bits=1: 0=valid, 1=revoked), indexed by dbissuedcredential.Id, packed
        // MSB-first per byte, DEFLATE-compressed (raw deflate, no zlib/gzip header — that's what the
        // spec's "lst" expects), base64url-encoded. Signed the same way every other Ed25519 JWT in
        // this issuer is (see GenerateJWTEd25519) — a verifier resolves the signing key the same way
        // it already does for credentials (this issuer's did:key/did:web).
        public string BuildStatusListToken(string issuerid, IWebHostEnvironment _env, string baseUrl)
        {
            var entries = new DBService().GetStatusListEntries();
            int maxId = entries.Count == 0 ? 0 : entries.Max(e => e.Id);

            // 1 bit per index, index 0 is a throwaway (dbissuedcredential.Id starts at 1) — simpler
            // than remapping indices, costs one wasted bit.
            var bits = new System.Collections.BitArray(maxId + 1);
            foreach (var (id, revoked) in entries)
            {
                bits[id] = revoked;
            }

            byte[] packed = new byte[(bits.Length + 7) / 8];
            for (int i = 0; i < bits.Length; i++)
            {
                if (bits[i])
                {
                    packed[i / 8] |= (byte)(1 << (7 - (i % 8))); // MSB-first within each byte
                }
            }

            using var compressedStream = new MemoryStream();
            using (var deflate = new System.IO.Compression.DeflateStream(compressedStream, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
            {
                deflate.Write(packed, 0, packed.Length);
            }
            string lst = WebEncoders.Base64UrlEncode(compressedStream.ToArray());

            DateTime now = DateTime.UtcNow;
            var payload = new
            {
                iss = issuerid,
                sub = $"{baseUrl}/status-list/1",
                iat = ((DateTimeOffset)now).ToUnixTimeSeconds(),
                exp = ((DateTimeOffset)now.AddDays(1)).ToUnixTimeSeconds(), // short-lived — verifiers re-fetch, not cache indefinitely
                status_list = new
                {
                    bits = 1,
                    lst = lst
                }
            };

            string header = $"{{\"alg\":\"EdDSA\",\"typ\":\"statuslist+jwt\",\"kid\":\"{issuerid}\"}}";
            var options = new JsonSerializerOptions { WriteIndented = false };
            string payloadJson = JsonSerializer.Serialize(payload, options);

            string headerB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(header));
            string payloadB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            string signingInput = $"{headerB64}.{payloadB64}";

            PemReader pemReaderPrivate = new PemReader(new StringReader(GetKey(true, _env)));
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();
            var signer = new Ed25519Signer();
            signer.Init(true, privateKey);
            byte[] signingBytes = Encoding.UTF8.GetBytes(signingInput);
            signer.BlockUpdate(signingBytes, 0, signingBytes.Length);
            string encodedSignature = WebEncoders.Base64UrlEncode(signer.GenerateSignature());

            return $"{headerB64}.{payloadB64}.{encodedSignature}";
        }

        public async Task<(bool isValid, string presentation_definition)> CheckPresentationDefinition(string presentation_definition_uri)
        {
            string presentation_definition = null;
            //call back uri
            using (var client = new HttpClient())
            {
                // Send the GET request
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                HttpResponseMessage response = await client.GetAsync(presentation_definition_uri);

                // Check if the response was successful
                response.EnsureSuccessStatusCode();

                // Read and process the response content
                var responseString = await response.Content.ReadAsStringAsync();
                presentation_definition = responseString;
                if (string.IsNullOrEmpty(responseString))
                {
                    //logs.Add(JsonSerializer.Serialize(new { message = "Fail presentation_definition", status = "400" }, new JsonSerializerOptions { WriteIndented = true }));
                    //return BadRequest();
                    return new(false, null);
                }

                //logs.Add(JsonSerializer.Serialize(new { message = presentation_definition, status = "200" }, new JsonSerializerOptions { WriteIndented = true }));
                return new(true, presentation_definition);


            }
        }

        // M-04: IsExpectedDomain() and the static openid-credential-issuer*.json files it pointed at
        // were dead code — no route ever called this method. The live, single source of truth for
        // issuer metadata is App_Data/credential-configurations-supported.json, served dynamically by
        // IssuerController.ReadJsonAsync(). Removed to avoid anyone mistaking the static files for a
        // real, maintained metadata path.

        // C-02 / C-04 / H-01: this used to resolve the credential grant by reading the "nonce" claim
        // out of an *unverified* proof and looking it up directly as a RegisterId — i.e. the
        // unauthenticated proof picked which grant to use, with the access token only checked
        // against that result afterward. CredentialController now resolves the grant from the
        // verified access token's "sub" claim instead (ValidateTokenAndGetSubject), and validates the
        // proof's "nonce" claim separately as a single-use server-issued nonce (DBService.
        // TryConsumeNonce) — freshness/replay checking, not grant lookup. Removed.


        public JsonResult GenerateTranscriptVC(string issuerid, string walletid) 
        {

            _JwtPayloadModel model = new _JwtPayloadModel();
            var token = new JsonResult(new { Ok = "" });

            try
            {

                model.issuer.id = issuerid; //GetLegalEntityDID();

                model.issuer.name = "Chulalongkorn University";//UniversityName;

                Guid newGuid = Guid.NewGuid();

                model.id = model.issuer.id;
                model.id = $"urn:uuid:{newGuid}";
                model.issuanceDate = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffffffK");


                vcModel payload = new vcModel();
                DateTime currentTime = DateTime.UtcNow;
                long unixTime = ((DateTimeOffset)currentTime).ToUnixTimeSeconds();
                DateTime end = currentTime.AddMinutes(30);
                long endTime = ((DateTimeOffset)end).ToUnixTimeSeconds();
                payload.iss = issuerid; // "did:key:z6MkjoRhq1jSNJdLiruSXrFFxagqrztZaXHqHGUTKJbcNywp";
                payload.sub = walletid; //wallet id
                payload.vc = model;
                payload.jti = $"urn:uuid:{newGuid}";
                payload.iat = unixTime;
                payload.nbf = unixTime;// 1730005968; // endTime;
                token = new JsonResult(payload);
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                };


                //add details
                model.credentialSubject.id = walletid;//wallet id

                DocumentContextDetail context = new DocumentContextDetail();
                context.Type = "DigitalDocument";
                context.Identifiers.Add(new Identifier()
                {
                    Type = "PropertyValue",
                    Name = "OID",
                    Value = "2.16.764.1.4.1.1.8.1.1"
                });
                context.SchemaVersion = "1.0";
                context.Author = new Author();
                context.Author.Type = "Organization";
                context.Author.Name = "ETDA";
                payload.vc.credentialSubject.documentContext = context;

                TedaDocumentInformation docInform = new TedaDocumentInformation();
                docInform.Type = "DigitalDocument";
                docInform.Identifier = new IdentifierDocument();
                docInform.Identifier.Type = "PropertyValue";
                docInform.Identifier.PropertyID = "Transcript ID";
                docInform.Identifier.Value = "123456";
                docInform.Name = "Transcript Name";
                docInform.AdditionalType = "รหัสระบุประเภทเอกสาร";
                docInform.EducationalUse = "วัตถุประสงค์";
                docInform.DatePublished = "Issue Date";
                docInform.Description = "Description of the document";

                docInform.InLanguage = new Language();
                docInform.InLanguage.Name = "Thai";
                docInform.InLanguage.Type = "Language";
                docInform.InLanguage.AlternateName = "th";
                payload.vc.credentialSubject.tedadocumentInformation = docInform;


                TedaStudent item = new TedaStudent();
                item.Type = "Person";
                item.Identifier = new Identifier();
                item.Identifier.Type = "PropertyValue";
                item.Identifier.Name = "StudenID";
                item.Identifier.Value = "123456";

                item.HonorificPrefix = "นางสาว";
                item.GivenName = "ทดสอบ";
                item.FamilyName = "เอกสารดิจิตัล";
                item.Gender = "1";
                item.BirthDate = "2015-01-30";
                item.Nationality = "TH";

                ResidentCountryOrTerritory res = new ResidentCountryOrTerritory();
                res.Type = "PostalAddress";
                res.addressCountry = "TH";
                item.ResidentCountryOrTerritory = res;
                item.Image = "data:image/jpeg;base64,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"; //"/examples/jvanzweden_s.jpg";
                item.FacultyName = "คณะวิศวกรรมศาสตร์";

                ProgramContext program = new ProgramContext();
                program.Type = "EducationalOccupationalProgram";
                program.Identifier = new Identifier();
                program.Identifier.Type = "PropertyValue";
                program.Identifier.Name = "ProgramID";
                program.Identifier.Value = "123456";
                program.Name = "ชื่อหลักสูตร";
                program.ProgramType.Add(new ProgramType()
                {
                    Type = "DefinedTerm",
                    Name = "กลุ่มสาขาหลัก",
                    TermCode = "Major"

                });
                program.EndDate = "2023-01-01";
                program.NumberOfCredits = 8;
                program.EducationalCredentialAwarded = "เกียรตินิยมอันดับ 1";

                program.ProgramPrerequisites = new ProgramPrerequisites();
                program.ProgramPrerequisites.Type = "EducationalOccupationalCredential";
                program.ProgramPrerequisites.EducationalLevel = "ป.ตรี";
                program.ProgramPrerequisites.RecognizedBy = "สถาบันการศึกษาก่อนหน้า";

                item.ProgramContext = program;
                payload.vc.credentialSubject.tedastudent = item;


                AcademicSummaryDetails academicSummary = new AcademicSummaryDetails();
                academicSummary.Type = "teda:AcademicSummary";

                SemesterSummary summary = new SemesterSummary();
                summary.Type = "teda:semester";
                summary.EducationTypeSystem = "ทวิภาค";
                summary.SemesterStatus = "ปกติ";
                summary.SemesterName = "ภาคการศึกษา1";
                summary.Year = "2023";
                summary.SemesterCreditValue = 60;
                summary.SemesterCreditEarned = 45;
                summary.SemesterCreditCalculated = 46;
                summary.SemesterPointEarned = 120;
                summary.SemesterGPA = 3.8;
                summary.SemesterGPAX = 3.8;
                summary.Remark = "";
                payload.vc.credentialSubject.academicSummary = academicSummary;
                payload.vc.credentialSubject.academicSummary.SemesterSummaries.Add(summary);


                OrganizationDetails orgEdu = new OrganizationDetails();
                orgEdu.Type = "EducationalOrganization";
                orgEdu.Identifier = new Identifier();
                orgEdu.Identifier.Type = "PropertyValue";
                orgEdu.Identifier.Name = "OrganizationID";
                orgEdu.Identifier.Value = "123456";
                orgEdu.Name = "Chulalongkorn University";
                orgEdu.SchoolLevel = "ปริญญาตรี";
                orgEdu.Address = new PostalAddress();
                orgEdu.Address.Type = "PostalAddress";
                orgEdu.Address.StreetAddress = "Street Address";
                orgEdu.Address.AddressLocality = "City";
                orgEdu.Address.AddressRegion = "State/Region";
                orgEdu.Address.PostalCode = "Postal Code";
                orgEdu.Address.AddressCountry = "Country";

                orgEdu.SubOrganization = new SubOrganization();
                orgEdu.SubOrganization.Identifier = new Identifier();
                orgEdu.SubOrganization.Identifier.Type = "PropertyValue";
                orgEdu.SubOrganization.Identifier.Name = "CampusID";
                orgEdu.SubOrganization.Identifier.Value = "123456";
                orgEdu.SubOrganization.Name = "Campu Name";
                orgEdu.SubOrganization.Address = new PostalAddress();
                orgEdu.SubOrganization.Address.Type = "PostalAddress";
                orgEdu.SubOrganization.Address.StreetAddress = "Street Address";
                orgEdu.SubOrganization.Address.AddressLocality = "City";
                orgEdu.SubOrganization.Address.AddressRegion = "State/Region";
                orgEdu.SubOrganization.Address.PostalCode = "Postal Code";
                orgEdu.SubOrganization.Address.AddressCountry = "Country";

                orgEdu.Registrar = new Registrar();
                orgEdu.Registrar.Type = "Person";
                orgEdu.Registrar.Identifier = new Identifier();
                orgEdu.Registrar.Identifier.Type = "PropertyValue";
                orgEdu.Registrar.Identifier.Name = "Registrar ID";
                orgEdu.Registrar.Identifier.Value = "123456";

                orgEdu.Registrar.JobTitle = "นายทะเบียน";
                orgEdu.Registrar.HonorificPrefix = "นางสาว";
                orgEdu.Registrar.HonorificPrefix = "นางสาว";
                orgEdu.Registrar.Name = "ชื่อ-นามสกุลนายทะเบียน";
                orgEdu.Registrar.Email = "email";

                CourseList courseList = new CourseList();
                Course course = new Course();
                course.Type = "Course";
                course.CourseCode = "Course Code";
                course.Name = "Computer Science 101";
                course.AdditionalType = "หมวดวิชาเทคโนโลยีสารสนเทศ";
                course.Description = "Course Description";
                course.NumberOfCredits = 1;
                course.CreditEarned = 3;
                course.Grade = 4;
                course.GradeText = "A";
                course.PointEarned = 12;
                courseList.ItemList.Add(course);


                CredentialStatus credentialStatus = new CredentialStatus();
                credentialStatus.Id = "https://example.com/credentials/status/3#94567";
                credentialStatus.Type = "BitstringStatusListEntry";
                credentialStatus.StatusPurpose = "revocation";
                credentialStatus.StatusListIndex = "94567";
                credentialStatus.StatusListCredential = "https://example.com/credentials/status/3";
                payload.vc.credentialStatus = credentialStatus;

                CredentialSchema credentialSchema = new CredentialSchema();
                credentialSchema.id = "https://schemas-uat.teda.th/teda/teda-objects/common/verified-credential/transcript/-/blob/main/schema/transcript_vc_schema.json";
                credentialSchema.type = "JsonSchema";
                payload.vc.credentialSchema = credentialSchema;

                payload.vc.credentialSubject.educationalOrganization = orgEdu;

                var writeToken = JsonSerializer.Serialize(model, options);
                //**Database.Write(client, "VC", writeToken);


            }
            catch (Exception e)
            {
                //
                token = new JsonResult(new { error = e.Message})
                {
                    StatusCode = 400
                };
            }

            return token;

        }

        public JsonResult GenerateDriverLicenseVC(string issuerid, string walletid)
        {
            var token = new JsonResult(new { Ok = "" });

            try
            {
                Guid newGuid = Guid.NewGuid();
                DateTime currentTime = DateTime.UtcNow;
                long unixTime = ((DateTimeOffset)currentTime).ToUnixTimeSeconds();

                _JwtPayloadModelDrivingLicence model = new _JwtPayloadModelDrivingLicence();
                model.issuer.id = issuerid;
                model.issuer.name = "กรมการขนส่งทางบก";
                model.id = $"urn:uuid:{newGuid}";
                model.issuanceDate = currentTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
                model.expirationDate = currentTime.AddYears(10).ToString("yyyy-MM-ddTHH:mm:ssZ");

                vcModelDrivingLicence payload = new vcModelDrivingLicence();
                payload.iss = issuerid;
                payload.sub = walletid;
                payload.vc = model;
                payload.jti = $"urn:uuid:{newGuid}";
                payload.iat = unixTime;
                payload.nbf = unixTime;

                var subject = model.credentialSubject;   // แก้ไขตัวที่ constructor สร้างไว้แล้ว แทนสร้างใหม่
                subject.id = walletid;
                subject.FamilyName = "เอกสารดิจิตัล";
                subject.GivenName = "นางสาวทดสอบ";
                subject.GivenNameEng = "Testing";
                subject.FamilyNameEng = "DocumentDigital";
                subject.BirthDate = "1987-06-10";
                subject.IssueDate = "2023-01-01";
                subject.ExpiryDate = "2033-01-01";
                subject.IssuingCountry = "TH";
                subject.IssuingAuthority = "กรมการขนส่งทางบก";
                subject.DocumentNumber = "123456789";
                // Mock/test data — no real portrait image available here. Previously this was the
                // literal placeholder text "base64_encoded_image_string", which is not valid base64
                // (contains '_' among other issues). GenerateDriverLicenseMdoc calls
                // Convert.FromBase64String on this value, so the placeholder crashed every mDL
                // request with "The input is not a valid Base-64 string...". Leaving it empty is safe
                // for both paths: GenerateDriverLicenseMdoc only embeds "portrait" when non-empty
                // (it's an optional claim), and the SD-JWT path just emits an empty string claim.
                subject.Portrait = "data:image/jpeg;base64,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";
                subject.DrivingPrivileges = new List<DrivingPrivilege>
                {
                    new DrivingPrivilege { Category = "รถยนต์ส่วนบุคคล", Restrictions = new() { "ขับขี่เฉพาะเวลากลางวัน" }, Conditions = new() { "ต้องสวมแว่นตาเมื่อขับขี่" } },
                    new DrivingPrivilege { Category = "รถจักรยานยนต์", Restrictions = new() { "ต้องสวมหมวกกันน็อค" }, Conditions = new() }
                };
                subject.UnDistinguishingSign = "TH";
                subject.AdministrativeNumber = "987654321";
                subject.Sex = "หญิง";
                subject.Height = 175;
                subject.Weight = 70;
                subject.EyeColour = "น้ำตาล";
                subject.HairColour = "ดำ";
                subject.BirthPlace = "กรุงเทพมหานคร";
                subject.ResidentAddress = "123/45 ถนนสุขุมวิท";
                subject.ResidentCity = "กรุงเทพมหานคร";
                subject.ResidentState = "กรุงเทพมหานคร";
                subject.ResidentPostalCode = "10110";
                subject.ResidentCountry = "TH";
                subject.BiometricTemplate = "data:image/jpeg;base64,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";
                subject.GivenNameNationalCharacter = "ทดสอบ";
                subject.SignatureUsualMark = "base64_encoded_signature_image";

                model.credentialStatus.Id = "https://example.com/credentials/status/3#94567";
                model.credentialStatus.Type = "BitstringStatusListEntry";
                model.credentialStatus.StatusPurpose = "revocation";
                model.credentialStatus.StatusListIndex = "94567";
                model.credentialStatus.StatusListCredential = "https://example.com/credentials/status/3";

                model.credentialSchema.id = "https://gitlab.com/ETDATH-TEDA-Schema-UAT/teda-objects/common/verified-credential/drivinglicence/-/blob/main/schema/drivingLicence-schema.json";
                model.credentialSchema.type = "JsonSchema";

                var options = new JsonSerializerOptions { WriteIndented = true };
                var writeToken = JsonSerializer.Serialize(model, options);
                //**Database.Write(client, "VC", writeToken);

                token = new JsonResult(payload);
            }
            catch (Exception e)
            {
                token = new JsonResult(new { error = e.Message }) { StatusCode = 400 };
            }

            return token;
        }


        // C-05 (partial): optional real ThaID profile (from DBService.GetRequestProfile, sourced from
        // the id_token at login) — when present, overrides the id_number/name/gender/birthdate fields
        // below that used to be hardcoded literals for every issuance. "religion" is removed entirely
        // (DOPA/ThaID never sends it, real or mock).
        public JsonResult GenerateIDCardVC(string issuerid, string walletid, ThaIDCheckStateResponse profile = null)
        {

            _JwtPayloadModel model = new _JwtPayloadModel();
            var token = new JsonResult(new { Ok = "" });

            try
            {

                model.issuer.id = issuerid; //GetLegalEntityDID();

                model.issuer.name = "กรมการปกครอง";//UniversityName;

                Guid newGuid = Guid.NewGuid();

                model.id = model.issuer.id;
                model.id = $"urn:uuid:{newGuid}";
                model.issuanceDate = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffffffK");


                vcModel payload = new vcModel();
                DateTime currentTime = DateTime.UtcNow;
                long unixTime = ((DateTimeOffset)currentTime).ToUnixTimeSeconds();
                DateTime end = currentTime.AddMinutes(30);
                long endTime = ((DateTimeOffset)end).ToUnixTimeSeconds();
                payload.iss = issuerid; // "did:key:z6MkjoRhq1jSNJdLiruSXrFFxagqrztZaXHqHGUTKJbcNywp";
                payload.sub = walletid; //wallet id
                payload.vc = model;
                payload.jti = $"urn:uuid:{newGuid}";
                payload.iat = unixTime;
                payload.nbf = unixTime;// 1730005968; // endTime;
                token = new JsonResult(payload);
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                };


                //add details
                model.credentialSubject.id = walletid;//wallet id

                DocumentContextDetail context = new DocumentContextDetail();
                context.Type = "DigitalDocument";
                context.Identifiers.Add(new Identifier()
                {
                    Type = "PropertyValue",
                    Name = "OID",
                    Value = "2.16.764.1.4.1.1.8.1.1"
                });
                context.SchemaVersion = "1.0";
                context.Author = new Author();
                context.Author.Type = "Organization";
                context.Author.Name = "ETDA";
                payload.vc.credentialSubject.documentContext = context;

                TedaDocumentInformation docInform = new TedaDocumentInformation();
                docInform.Type = "DigitalDocument";
                docInform.Identifier = new IdentifierDocument();
                docInform.Identifier.Type = "PropertyValue";
                docInform.Identifier.PropertyID = "PID ID";
                docInform.Identifier.Value = !string.IsNullOrWhiteSpace(profile?.PID) ? profile.PID : "1234567890123";
                docInform.Name = "PID Name";
                docInform.AdditionalType = "รหัสระบุประเภทเอกสาร";
                docInform.EducationalUse = "วัตถุประสงค์";
                docInform.DatePublished = "Issue Date";
                docInform.Description = "Description of the document";

                docInform.InLanguage = new Language();
                docInform.InLanguage.Name = "Thai";
                docInform.InLanguage.Type = "Language";
                docInform.InLanguage.AlternateName = "th";
                payload.vc.credentialSubject.tedadocumentInformation = docInform;


                TedaStudent item = new TedaStudent();
                item.Type = "Person";
                item.Identifier = new Identifier();
                item.Identifier.Type = "PropertyValue";
                item.Identifier.Name = "IDNumber";
                item.Identifier.Value = !string.IsNullOrWhiteSpace(profile?.PID) ? profile.PID : "1234567890123";

                item.HonorificPrefix = !string.IsNullOrWhiteSpace(profile?.TitleNameTh) ? profile.TitleNameTh : "นางสาว";
                item.GivenName = !string.IsNullOrWhiteSpace(profile?.FirstNameTh) ? profile.FirstNameTh : "ทดสอบ";
                item.FamilyName = !string.IsNullOrWhiteSpace(profile?.LastNameTh) ? profile.LastNameTh : "เอกสารดิจิตัล";
                item.Gender = !string.IsNullOrWhiteSpace(profile?.Gender) ? profile.Gender : "1";
                item.BirthDate = !string.IsNullOrWhiteSpace(profile?.BirthDate) ? profile.BirthDate : "2015-01-30";
                item.Nationality = "TH";

                ResidentCountryOrTerritory res = new ResidentCountryOrTerritory();
                res.Type = "PostalAddress";
                res.addressCountry = "TH";
                item.ResidentCountryOrTerritory = res;
                item.Image = "/examples/jvanzweden_s.jpg";
                item.FacultyName = "คณะวิศวกรรมศาสตร์";

                ProgramContext program = new ProgramContext();
                program.Type = "EducationalOccupationalProgram";
                program.Identifier = new Identifier();
                program.Identifier.Type = "PropertyValue";
                program.Identifier.Name = "ProgramID";
                program.Identifier.Value = "1234567890123";
                program.Name = "ชื่อหลักสูตร";
                program.ProgramType.Add(new ProgramType()
                {
                    Type = "DefinedTerm",
                    Name = "กลุ่มสาขาหลัก",
                    TermCode = "Major"

                });
                program.EndDate = "2023-01-01";
                program.NumberOfCredits = 8;
                program.EducationalCredentialAwarded = "เกียรตินิยมอันดับ 1";

                program.ProgramPrerequisites = new ProgramPrerequisites();
                program.ProgramPrerequisites.Type = "EducationalOccupationalCredential";
                program.ProgramPrerequisites.EducationalLevel = "ป.ตรี";
                program.ProgramPrerequisites.RecognizedBy = "สถาบันการศึกษาก่อนหน้า";

                item.ProgramContext = program;
                payload.vc.credentialSubject.tedastudent = item;


                AcademicSummaryDetails academicSummary = new AcademicSummaryDetails();
                academicSummary.Type = "teda:AcademicSummary";

                SemesterSummary summary = new SemesterSummary();
                summary.Type = "teda:semester";
                summary.EducationTypeSystem = "ทวิภาค";
                summary.SemesterStatus = "ปกติ";
                summary.SemesterName = "ภาคการศึกษา1";
                summary.Year = "2023";
                summary.SemesterCreditValue = 60;
                summary.SemesterCreditEarned = 45;
                summary.SemesterCreditCalculated = 46;
                summary.SemesterPointEarned = 120;
                summary.SemesterGPA = 3.8;
                summary.SemesterGPAX = 3.8;
                summary.Remark = "";
                payload.vc.credentialSubject.academicSummary = academicSummary;
                payload.vc.credentialSubject.academicSummary.SemesterSummaries.Add(summary);


                OrganizationDetails orgEdu = new OrganizationDetails();
                orgEdu.Type = "EducationalOrganization";
                orgEdu.Identifier = new Identifier();
                orgEdu.Identifier.Type = "PropertyValue";
                orgEdu.Identifier.Name = "OrganizationID";
                orgEdu.Identifier.Value = "123456";
                orgEdu.Name = "University Name";
                orgEdu.SchoolLevel = "ปริญญาตรี";
                orgEdu.Address = new PostalAddress();
                orgEdu.Address.Type = "PostalAddress";
                orgEdu.Address.StreetAddress = "Street Address";
                orgEdu.Address.AddressLocality = "City";
                orgEdu.Address.AddressRegion = "State/Region";
                orgEdu.Address.PostalCode = "Postal Code";
                orgEdu.Address.AddressCountry = "Country";

                orgEdu.SubOrganization = new SubOrganization();
                orgEdu.SubOrganization.Identifier = new Identifier();
                orgEdu.SubOrganization.Identifier.Type = "PropertyValue";
                orgEdu.SubOrganization.Identifier.Name = "CampusID";
                orgEdu.SubOrganization.Identifier.Value = "123456";
                orgEdu.SubOrganization.Name = "Campu Name";
                orgEdu.SubOrganization.Address = new PostalAddress();
                orgEdu.SubOrganization.Address.Type = "PostalAddress";
                orgEdu.SubOrganization.Address.StreetAddress = "Street Address";
                orgEdu.SubOrganization.Address.AddressLocality = "City";
                orgEdu.SubOrganization.Address.AddressRegion = "State/Region";
                orgEdu.SubOrganization.Address.PostalCode = "Postal Code";
                orgEdu.SubOrganization.Address.AddressCountry = "Country";

                orgEdu.Registrar = new Registrar();
                orgEdu.Registrar.Type = "Person";
                orgEdu.Registrar.Identifier = new Identifier();
                orgEdu.Registrar.Identifier.Type = "PropertyValue";
                orgEdu.Registrar.Identifier.Name = "Registrar ID";
                orgEdu.Registrar.Identifier.Value = "123456";

                orgEdu.Registrar.JobTitle = "นายทะเบียน";
                orgEdu.Registrar.HonorificPrefix = "นางสาว";
                orgEdu.Registrar.HonorificPrefix = "นางสาว";
                orgEdu.Registrar.Name = "ชื่อ-นามสกุลนายทะเบียน";
                orgEdu.Registrar.Email = "email";

                CourseList courseList = new CourseList();
                Course course = new Course();
                course.Type = "Course";
                course.CourseCode = "Course Code";
                course.Name = "Computer Science 101";
                course.AdditionalType = "หมวดวิชาเทคโนโลยีสารสนเทศ";
                course.Description = "Course Description";
                course.NumberOfCredits = 1;
                course.CreditEarned = 3;
                course.Grade = 4;
                course.GradeText = "A";
                course.PointEarned = 12;
                courseList.ItemList.Add(course);


                CredentialStatus credentialStatus = new CredentialStatus();
                credentialStatus.Id = "https://example.com/credentials/status/3#94567";
                credentialStatus.Type = "BitstringStatusListEntry";
                credentialStatus.StatusPurpose = "revocation";
                credentialStatus.StatusListIndex = "94567";
                credentialStatus.StatusListCredential = "https://example.com/credentials/status/3";
                payload.vc.credentialStatus = credentialStatus;

                CredentialSchema credentialSchema = new CredentialSchema();
                credentialSchema.id = "https://schemas-uat.teda.th/teda/teda-objects/common/verified-credential/transcript/-/blob/main/schema/transcript_vc_schema.json";
                credentialSchema.type = "JsonSchema";
                payload.vc.credentialSchema = credentialSchema;

                payload.vc.credentialSubject.educationalOrganization = orgEdu;

                var writeToken = JsonSerializer.Serialize(model, options);
                //**Database.Write(client, "VC", writeToken);


            }
            catch (Exception e)
            {
                //
                token = new JsonResult(new { error = e.Message })
                {
                    StatusCode = 400
                };
            }

            return token;

        }

        public string GenerateTranscriptSdJwt(string issuerid, string walletid, IWebHostEnvironment _env, string UrlBase, int statusListIndex)
        {
            // ── 1. ดึง private key (Ed25519) เหมือนเดิม ──────────────
            PemReader pemReaderPrivate = new PemReader(new StringReader(GetKey(true, _env)));
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();

            // ── 2. ดึงข้อมูล transcript จาก GenerateTranscriptVC เดิม ─
            //      (ในอนาคตให้โหลดจาก DB แทน)
            var vcResult = GenerateTranscriptVC(issuerid, walletid);
            var vcPayload = vcResult.Value as vcModel ?? throw new Exception("GenerateTranscriptVC failed");

            var student = vcPayload.vc.credentialSubject.tedastudent;
            var school = vcPayload.vc.credentialSubject.educationalOrganization;
            var program = student?.ProgramContext;
            var institutionName = vcPayload?.vc.issuer.name;
            var academic = vcPayload.vc.credentialSubject.academicSummary;

            // ── 3. สร้าง Disclosures (SD claims) ─────────────────────
            //      แต่ละ Disclosure = base64url([salt, claim_name, value])
            var sdClaims = new Dictionary<string, object>
            {
                ["student_id"] = student?.Identifier?.Value ?? "",
                ["full_name"] = $"{student?.HonorificPrefix}{student?.GivenName} {student?.FamilyName}",
                ["faculty"] = student?.FacultyName ?? "",
                ["gpa"] = academic?.SemesterSummaries?.FirstOrDefault()?.SemesterGPA ?? 0,
                //["grades"] = BuildGradesArray(vcPayload.vc.credentialSubject),
                ["graduation_date"] = program?.EndDate ?? "",
                ["degree"] = school?.SchoolLevel ?? "",
                ["institution_name"] = institutionName,
            };

            // institution_name เป็น Non-SD (ไม่ผ่าน Disclosure — ฝังใน payload โดยตรง)
            //string institutionName = 

            // ── 4. สร้าง Disclosure objects และเก็บ hash ─────────────
            var disclosures = new List<string>();   // base64url encoded disclosures
            var sdHashes = new List<string>();   // sha-256 hash ของแต่ละ disclosure

            using var sha256 = System.Security.Cryptography.SHA256.Create();

            foreach (var (claimName, claimValue) in sdClaims)
            {
                // salt = random 16 bytes → base64url
                var saltBytes = new byte[16];
                System.Security.Cryptography.RandomNumberGenerator.Fill(saltBytes);
                string salt = Base64UrlEncode(saltBytes);

                // Disclosure array: [salt, claim_name, value]
                var discArray = new object[] { salt, claimName, claimValue };
                // ✅ ใหม่
                string discJson = System.Text.Json.JsonSerializer.Serialize(discArray,
                    new System.Text.Json.JsonSerializerOptions
                    {
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default
                    });
                string discEncoded = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(discJson));

                // hash ของ disclosure → ใส่ใน _sd array
                byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(discEncoded));
                string hashB64 = Base64UrlEncode(hashBytes);

                disclosures.Add(discEncoded);
                sdHashes.Add(hashB64);
            }

            // ── 5. สร้าง JWT payload ──────────────────────────────────
            DateTime now = DateTime.UtcNow;
            long iat = ((DateTimeOffset)now).ToUnixTimeSeconds();
            long exp = ((DateTimeOffset)now.AddYears(5)).ToUnixTimeSeconds();
            string jti = $"urn:uuid:{Guid.NewGuid()}";

            // cnf (confirmation) — holder binding ด้วย did:key ของ wallet
            // walletid มาจาก kid ใน proof JWT (เป็น did:key หรือ did:tbsi)
            var cnf = BuildCnf(walletid);

            var payload = new
            {
                iss = issuerid,
                sub = walletid,
                vct = $"{UrlBase}/credentials/TranscriptCredential",
                jti = jti,
                iat = iat,
                exp = exp,
                institution_name = institutionName,   // Non-SD — แสดงเสมอ
                _sd = sdHashes,           // hashes ของ SD claims
                _sd_alg = "sha-256",
                cnf = cnf,
                status = BuildStatusClaim(statusListIndex, UrlBase),
                issued = now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                issuanceDate = now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            };

            // ── 6. Sign ด้วย Ed25519 (เหมือน GenerateJWTEd25519 เดิม) ─
            string header = $"{{\"alg\":\"EdDSA\",\"typ\":\"dc+sd-jwt\",\"kid\":\"{issuerid}\"}}";

            var options = new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = false,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            };

            string payloadJson = System.Text.Json.JsonSerializer.Serialize(payload, options);
            string headerB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(header))
                .Replace("+", "-") // Replace '+' with '-'
                .Replace("/", "_") // Replace '/' with '_'
                .TrimEnd('=');     // Remove padding characters ('=')
            string payloadB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            string signingInput = $"{headerB64}.{payloadB64}";
            byte[] signingBytes = Encoding.UTF8.GetBytes(signingInput);

            var signer = new Ed25519Signer();
            signer.Init(true, privateKey);
            signer.BlockUpdate(signingBytes, 0, signingBytes.Length);
            string encodedSignature = WebEncoders.Base64UrlEncode(signer.GenerateSignature());


            // ── 7. ประกอบ SD-JWT string ───────────────────────────────
            // รูปแบบ: header.payload.sig~disc1~disc2~...~
            string sdJwt = $"{headerB64}.{payloadB64}.{encodedSignature}";
            foreach (var disc in disclosures)
            {
                sdJwt += $"~{disc}";
            }
            sdJwt += "~";   // trailing tilde (ไม่มี KB-JWT ฝั่ง issuer)

            return sdJwt;
        }

        public string GenerateDriversLicenseSdJwt(string issuerid, string walletid, IWebHostEnvironment _env, string UrlBase, int statusListIndex)
        {
            // ── 1. ดึง private key (Ed25519) เหมือนเดิม ──────────────
            PemReader pemReaderPrivate = new PemReader(new StringReader(GetKey(true, _env)));
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();

            // ── 2. ดึงข้อมูลใบขับขี่จาก GenerateDriverLicenseVC (ที่แก้ไว้แล้วให้ return vcModelDrivingLicence) ─
            var vcResult = GenerateDriverLicenseVC(issuerid, walletid);
            var vcPayload = vcResult.Value as vcModelDrivingLicence
                ?? throw new Exception("GenerateDriverLicenseVC failed");

            var subject = vcPayload.vc.credentialSubject;              // _credentialSubjectDrivingLicence
            var institutionName = vcPayload.vc.issuer.name;             // "กรมการขนส่งทางบก"

            // ── 3. สร้าง Disclosures (SD claims) — map ตาม schema drivingLicence-vc.json ─
            var sdClaims = new Dictionary<string, object>
            {
                ["family_name"] = subject.FamilyName,
                ["given_name"] = subject.GivenName,
                ["birth_date"] = subject.BirthDate,
                ["document_number"] = subject.DocumentNumber,
                ["issue_date"] = subject.IssueDate,
                ["expiry_date"] = subject.ExpiryDate,
                ["resident_address"] = subject.ResidentAddress,
                ["driving_privileges"] = subject.DrivingPrivileges,   // ✅ field สำคัญที่หายไปในโค้ดเดิม
                ["portrait"] = subject.Portrait,
            };

            // issuing_authority + issuing_country เป็น Non-SD (แสดงเสมอ ไม่ต้องซ่อน)

            // ── 4. สร้าง Disclosure objects และเก็บ hash ─────────────
            var disclosures = new List<string>();
            var sdHashes = new List<string>();
            using var sha256 = System.Security.Cryptography.SHA256.Create();

            foreach (var (claimName, claimValue) in sdClaims)
            {
                var saltBytes = new byte[16];
                System.Security.Cryptography.RandomNumberGenerator.Fill(saltBytes);
                string salt = Base64UrlEncode(saltBytes);

                var discArray = new object[] { salt, claimName, claimValue };
                string discJson = System.Text.Json.JsonSerializer.Serialize(discArray,
                    new System.Text.Json.JsonSerializerOptions
                    {
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default
                    });
                string discEncoded = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(discJson));

                byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(discEncoded));
                string hashB64 = Base64UrlEncode(hashBytes);

                disclosures.Add(discEncoded);
                sdHashes.Add(hashB64);
            }

            // ── 5. สร้าง JWT payload ──────────────────────────────────
            DateTime now = DateTime.UtcNow;
            long iat = ((DateTimeOffset)now).ToUnixTimeSeconds();
            long exp = ((DateTimeOffset)now.AddYears(5)).ToUnixTimeSeconds();
            string jti = $"urn:uuid:{Guid.NewGuid()}";
            var cnf = BuildCnf(walletid);

            var payload = new
            {
                iss = issuerid,
                sub = walletid,
                vct = $"{UrlBase}/credentials/DrivingLicence",   // ✅ แก้จาก IDCard เป็น DrivingLicence
                jti = jti,
                iat = iat,
                exp = exp,
                issuing_authority = subject.IssuingAuthority,     // Non-SD — แสดงเสมอ
                issuing_country = subject.IssuingCountry,         // Non-SD — แสดงเสมอ
                institution_name = institutionName,               // Non-SD
                _sd = sdHashes,
                _sd_alg = "sha-256",
                cnf = cnf,
                status = BuildStatusClaim(statusListIndex, UrlBase),
                issued = now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                issuanceDate = now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            };

            // ── 6. Sign ด้วย Ed25519 (เหมือนเดิม ไม่ต้องแก้) ─
            string header = $"{{\"alg\":\"EdDSA\",\"typ\":\"dc+sd-jwt\",\"kid\":\"{issuerid}\"}}";

            var options = new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = false,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            };

            string payloadJson = System.Text.Json.JsonSerializer.Serialize(payload, options);
            string headerB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(header))
                .Replace("+", "-").Replace("/", "_").TrimEnd('=');
            string payloadB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            string signingInput = $"{headerB64}.{payloadB64}";
            byte[] signingBytes = Encoding.UTF8.GetBytes(signingInput);

            var signer = new Ed25519Signer();
            signer.Init(true, privateKey);
            signer.BlockUpdate(signingBytes, 0, signingBytes.Length);
            string encodedSignature = WebEncoders.Base64UrlEncode(signer.GenerateSignature());

            // ── 7. ประกอบ SD-JWT string ───────────────────────────────
            string sdJwt = $"{headerB64}.{payloadB64}.{encodedSignature}";
            foreach (var disc in disclosures)
                sdJwt += $"~{disc}";
            sdJwt += "~";

            return sdJwt;
        }

        // C-05 (partial): optional real ThaID profile, forwarded to GenerateIDCardVC and also used
        // directly below for the "birthdate" SD claim (which used to be a hardcoded literal string,
        // never even sourced from the mock student object). "religion" is removed entirely — DOPA
        // doesn't send it via ThaID.
        public string GenerateIDCardSdJwt(string issuerid, string walletid, IWebHostEnvironment _env, string UrlBase, int statusListIndex, ThaIDCheckStateResponse profile = null)
        {
            // ── 1. ดึง private key (Ed25519) เหมือนเดิม ──────────────
            PemReader pemReaderPrivate = new PemReader(new StringReader(GetKey(true, _env)));
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();

            // ── 2. ดึงข้อมูล transcript จาก GenerateIDCardVC เดิม ─
            //      (ในอนาคตให้โหลดจาก DB แทน)
            var vcResult = GenerateIDCardVC(issuerid, walletid, profile);
            var vcPayload = vcResult.Value as vcModel ?? throw new Exception("GenerateIDCardVC failed");

            var student = vcPayload.vc.credentialSubject.tedastudent;
            var school = vcPayload.vc.credentialSubject.educationalOrganization;
            var program = student?.ProgramContext;
            var institutionName = vcPayload?.vc.issuer.name;
            var academic = vcPayload.vc.credentialSubject.academicSummary;

            // ── 3. สร้าง Disclosures (SD claims) ─────────────────────
            //      แต่ละ Disclosure = base64url([salt, claim_name, value])
            var sdClaims = new Dictionary<string, object>
            {
                ["id_number"] = student?.Identifier?.Value ?? "",
                ["full_name"] = $"{student?.HonorificPrefix}{student?.GivenName} {student?.FamilyName}",
                // ชื่อภาษาอังกฤษ — ThaID ให้ title_en/given_name_en/family_name_en มาด้วย (ดู
                // ThaIDAuthService.GetProfile) ประกอบตรงนี้เหมือน full_name ฝั่งไทย ไม่มีค่าจริงก็ fallback mock
                ["full_name_en"] = !string.IsNullOrWhiteSpace(profile?.FirstNameEn) || !string.IsNullOrWhiteSpace(profile?.LastNameEn)
                    ? $"{profile?.TitleNameEn} {profile?.FirstNameEn} {profile?.LastNameEn}".Trim()
                    : "Miss Testing Digital Document",
                ["birthdate"] = !string.IsNullOrWhiteSpace(profile?.BirthDate) ? profile.BirthDate : "10 มิ.ย. 2530",
                // ThaIDLogin ขอ scope "date_of_issuance"/"date_of_expiry"/"address" ไว้ด้วย (ดู
                // AccountController.ThaIDLogin + ThaIDAuthService.GetProfile) — ใช้ค่าจริงถ้ามี ไม่งั้น
                // fallback เป็น mock เหมือนเดิม. "issue_date" ("วันออกบัตร") เพิ่มใหม่ตรงนี้ — ก่อนหน้านี้
                // capture DateOfIssuance ไว้ใน profile/DB แล้วแต่ไม่เคยเอามาออกเป็น claim จริงเลย
                ["issue_date"] = !string.IsNullOrWhiteSpace(profile?.DateOfIssuance) ? profile.DateOfIssuance : "11 มิ.ย. 2570",
                ["expiry_date"] = !string.IsNullOrWhiteSpace(profile?.DateOfExpiry) ? profile.DateOfExpiry : "11 มิ.ย. 2575",
                // "ที่อยู่ตามบัตร" — ที่อยู่ตามทะเบียนบ้าน/บัตรประชาชนจาก ThaID id_token claim "address"
                ["address"] = !string.IsNullOrWhiteSpace(profile?.Address) ? profile.Address : "123 ซ.พหลโยธิน 2 ถ.พหลโยธิน สามเสนใน พญาไท กทม. 11000",
                // "religion" ตัดออก — กรมการปกครอง (DOPA) ไม่มีข้อมูลนี้ส่งมาให้ผ่าน ThaID เลย
            };

            // institution_name เป็น Non-SD (ไม่ผ่าน Disclosure — ฝังใน payload โดยตรง)
            //string institutionName = 

            // ── 4. สร้าง Disclosure objects และเก็บ hash ─────────────
            var disclosures = new List<string>();   // base64url encoded disclosures
            var sdHashes = new List<string>();   // sha-256 hash ของแต่ละ disclosure

            using var sha256 = System.Security.Cryptography.SHA256.Create();

            foreach (var (claimName, claimValue) in sdClaims)
            {
                // salt = random 16 bytes → base64url
                var saltBytes = new byte[16];
                System.Security.Cryptography.RandomNumberGenerator.Fill(saltBytes);
                string salt = Base64UrlEncode(saltBytes);

                // Disclosure array: [salt, claim_name, value]
                var discArray = new object[] { salt, claimName, claimValue };
                // ✅ ใหม่
                string discJson = System.Text.Json.JsonSerializer.Serialize(discArray,
                    new System.Text.Json.JsonSerializerOptions
                    {
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default
                    });
                string discEncoded = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(discJson));

                // hash ของ disclosure → ใส่ใน _sd array
                byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(discEncoded));
                string hashB64 = Base64UrlEncode(hashBytes);

                disclosures.Add(discEncoded);
                sdHashes.Add(hashB64);
            }

            // ── 5. สร้าง JWT payload ──────────────────────────────────
            DateTime now = DateTime.UtcNow;
            long iat = ((DateTimeOffset)now).ToUnixTimeSeconds();
            long exp = ((DateTimeOffset)now.AddYears(5)).ToUnixTimeSeconds();
            string jti = $"urn:uuid:{Guid.NewGuid()}";

            // cnf (confirmation) — holder binding ด้วย did:key ของ wallet
            // walletid มาจาก kid ใน proof JWT (เป็น did:key หรือ did:tbsi)
            var cnf = BuildCnf(walletid);

            var payload = new
            {
                iss = issuerid,
                sub = walletid,
                vct = $"{UrlBase}/credentials/IDCard",
                jti = jti,
                iat = iat,
                exp = exp,
                institution_name = institutionName,   // Non-SD — แสดงเสมอ
                _sd = sdHashes,           // hashes ของ SD claims
                _sd_alg = "sha-256",
                cnf = cnf,
                status = BuildStatusClaim(statusListIndex, UrlBase),
                issued = now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                issuanceDate = now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            };

            // ── 6. Sign ด้วย Ed25519 (เหมือน GenerateJWTEd25519 เดิม) ─
            string header = $"{{\"alg\":\"EdDSA\",\"typ\":\"dc+sd-jwt\",\"kid\":\"{issuerid}\"}}";

            var options = new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = false,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            };

            string payloadJson = System.Text.Json.JsonSerializer.Serialize(payload, options);
            string headerB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(header))
                .Replace("+", "-") // Replace '+' with '-'
                .Replace("/", "_") // Replace '/' with '_'
                .TrimEnd('=');     // Remove padding characters ('=')
            string payloadB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            string signingInput = $"{headerB64}.{payloadB64}";
            byte[] signingBytes = Encoding.UTF8.GetBytes(signingInput);

            var signer = new Ed25519Signer();
            signer.Init(true, privateKey);
            signer.BlockUpdate(signingBytes, 0, signingBytes.Length);
            string encodedSignature = WebEncoders.Base64UrlEncode(signer.GenerateSignature());


            // ── 7. ประกอบ SD-JWT string ───────────────────────────────
            // รูปแบบ: header.payload.sig~disc1~disc2~...~
            string sdJwt = $"{headerB64}.{payloadB64}.{encodedSignature}";
            foreach (var disc in disclosures)
            {
                sdJwt += $"~{disc}";
            }
            sdJwt += "~";   // trailing tilde (ไม่มี KB-JWT ฝั่ง issuer)

            return sdJwt;
        }

        /// <summary>
        /// สร้าง SD-JWT สำหรับ BootCampCredential
        /// claims อ่านจาก credential-configurations-supported.json แบบ dynamic
        /// ค่าของ claims ใช้ mock data (สำหรับ demo)
        /// </summary>
        public string GenerateBootCampSdJwt(string issuerid,
            string walletid,
            IWebHostEnvironment _env,
            string UrlBase,
            int statusListIndex)
        {
            // ── 1. ดึง private key (Ed25519) ─────────────────────────
            PemReader pemReaderPrivate = new PemReader(new StringReader(GetKey(true, _env)));
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();

            // ── 2. อ่าน claims config จากไฟล์ ────────────────────────
            const string CREDENTIAL_TYPE = "BootCampCredential_dc+sd-jwt";
            string configPath = Path.Combine(_env.ContentRootPath, "App_Data/credential-configurations-supported.json");
            string configJson = File.ReadAllText(configPath);

            var configNode = System.Text.Json.Nodes.JsonNode.Parse(configJson)?.AsObject();

            // H-06: OID4VCI 1.0 Final Appendix B.2 — the "claims" array lives under
            // credential_metadata.claims, each entry being { "path": [...], "mandatory": bool }
            // (plus this app's own non-standard "sd" extension key). Prefer that location; fall back
            // to a top-level "claims" for older/hand-edited config entries.
            var claimsNode = configNode?[CREDENTIAL_TYPE]?["credential_metadata"]?["claims"]
                           ?? configNode?[CREDENTIAL_TYPE]?["claims"];


            // ── 3. อ่าน claims จาก array format (OID4VCI 1.0) ─────────
            var mockData = new Dictionary<string, object>();
            var sdFlags = new Dictionary<string, bool>();

            if (claimsNode is System.Text.Json.Nodes.JsonArray claimsArray)
            {
                // format ใหม่: [{"path": ["FirstName"], "mandatory": true, "sd": true}]
                foreach (var item in claimsArray)
                {
                    var path = item?["path"]?.AsArray();
                    string fieldName = path?.FirstOrDefault()?.GetValue<string>();
                    bool isSd = item?["sd"]?.GetValue<bool>() ?? true;

                    if (!string.IsNullOrEmpty(fieldName))
                    {
                        mockData[fieldName] = $"[{fieldName}]";
                        sdFlags[fieldName] = isSd;
                    }
                }
            }
            else if (claimsNode?[""] is System.Text.Json.Nodes.JsonObject oldFormat)
            {
                // format เก่า: {"": {"FirstName": {"sd": true}}}
                foreach (var (fieldName, claimNode) in oldFormat)
                {
                    bool isSd = claimNode?["sd"]?.GetValue<bool>() ?? true;
                    mockData[fieldName] = $"[{fieldName}]";
                    sdFlags[fieldName] = isSd;
                }
            }
            else if (claimsNode is System.Text.Json.Nodes.JsonObject claimsObj)
            {
                // format ปัจจุบัน: {"full_name": {"mandatory": true, "sd": true}, ...}
                foreach (var (fieldName, claimNode) in claimsObj)
                {
                    bool isSd = claimNode?["sd"]?.GetValue<bool>() ?? true;
                    mockData[fieldName] = $"[{fieldName}]";
                    sdFlags[fieldName] = isSd;
                }
            }

            // ── 4. แยก SD claims และ Non-SD claims ───────────────────
            var sdClaims = new Dictionary<string, object>();
            var nonSdClaims = new Dictionary<string, object>();

            foreach (var (fieldName, value) in mockData)
            {
                if (sdFlags.TryGetValue(fieldName, out bool isSd) && !isSd)
                    nonSdClaims[fieldName] = value;
                else
                    sdClaims[fieldName] = value;
            }

            // ── 5. สร้าง Disclosures จาก SD claims ───────────────────
            var disclosures = new List<string>();
            var sdHashes = new List<string>();

            using var sha256 = System.Security.Cryptography.SHA256.Create();

            foreach (var (claimName, claimValue) in sdClaims)
            {
                var saltBytes = new byte[16];
                System.Security.Cryptography.RandomNumberGenerator.Fill(saltBytes);
                string salt = Base64UrlEncode(saltBytes);

                var discArray = new object[] { salt, claimName, claimValue };
                string discJson = System.Text.Json.JsonSerializer.Serialize(discArray,
                    new System.Text.Json.JsonSerializerOptions
                    {
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default
                    });
                string discEncoded = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(discJson));

                byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(discEncoded));
                string hashB64 = Base64UrlEncode(hashBytes);

                disclosures.Add(discEncoded);
                sdHashes.Add(hashB64);
            }

            // ── 6. สร้าง JWT payload ──────────────────────────────────
            DateTime now = DateTime.UtcNow;
            long iat = ((DateTimeOffset)now).ToUnixTimeSeconds();
            long exp = ((DateTimeOffset)now.AddYears(5)).ToUnixTimeSeconds();
            string jti = $"urn:uuid:{Guid.NewGuid()}";

            var payloadDict = new Dictionary<string, object>
            {
                ["iss"] = issuerid,
                ["sub"] = walletid,
                ["vct"] = $"{UrlBase}/credentials/BootCampCredential",
                ["jti"] = jti,
                ["iat"] = iat,
                ["exp"] = exp,
                ["_sd"] = sdHashes,
                ["_sd_alg"] = "sha-256",
                ["cnf"] = BuildCnf(walletid),
                ["status"] = BuildStatusClaim(statusListIndex, UrlBase),
                ["issued"] = now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["issuanceDate"] = now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            };

            // เพิ่ม Non-SD claims เข้า payload โดยตรง
            foreach (var (k, v) in nonSdClaims)
                payloadDict[k] = v;

            // ── 7. Sign ด้วย Ed25519 ──────────────────────────────────
            string header = $"{{\"alg\":\"EdDSA\",\"typ\":\"dc+sd-jwt\",\"kid\":\"{issuerid}\"}}";

            var options = new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = false,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            };

            string payloadJson = System.Text.Json.JsonSerializer.Serialize(payloadDict, options);
            string headerB64 = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(header));
            string payloadB64 = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(payloadJson));
            string signingInput = $"{headerB64}.{payloadB64}";

            var signer = new Ed25519Signer();
            signer.Init(true, privateKey);
            signer.BlockUpdate(System.Text.Encoding.UTF8.GetBytes(signingInput), 0, signingInput.Length);
            string encodedSignature = Base64UrlEncode(signer.GenerateSignature());

            // ── 8. ประกอบ SD-JWT string ───────────────────────────────
            string sdJwt = $"{headerB64}.{payloadB64}.{encodedSignature}";
            foreach (var disc in disclosures)
                sdJwt += $"~{disc}";
            sdJwt += "~";

            
            return sdJwt;
        }


        // ──────────────────────────────────────────────────────────────
        // Helper — สร้าง grades array จาก credentialSubject
        // ──────────────────────────────────────────────────────────────
        private static List<object> BuildGradesArray(dynamic credentialSubject)
        {
            var result = new List<object>();
            try
            {
                var courses = credentialSubject?.courseList?.ItemList;
                if (courses == null) return result;
                foreach (var c in courses)
                {
                    result.Add(new
                    {
                        subject_code = c.CourseCode,
                        subject_name = c.Name,
                        credits = c.NumberOfCredits,
                        grade = c.GradeText,
                    });
                }
            }
            catch { }
            return result;
        }

        // ──────────────────────────────────────────────────────────────
        // Helper — Base64Url encode (ไม่มี padding)
        // ──────────────────────────────────────────────────────────────
        private static string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }
        
        /*ttt*/
        public async Task<JsonNode> LoadCredentialConfigurationsAsync(IWebHostEnvironment _env, string baseUrl)
        {
            Oid4VciOptions _options = new Oid4VciOptions();
            var filePath = Path.Combine(_env.ContentRootPath, _options.CredentialConfigurationsFile);

            if (!System.IO.File.Exists(filePath))
            {
                return new JsonObject();
            }

            var json = await System.IO.File.ReadAllTextAsync(filePath);

            // Bug fix: {IssuerUrl} was substituted with a raw string.Replace, so any character in
            // baseUrl that needs JSON escaping (a stray '"' or '\' from a malformed/attacker-
            // influenced Host/X-Forwarded-Host header, before the H-11 trusted-proxy fix) could
            // corrupt the surrounding JSON string and crash JsonNode.Parse below with an unhandled
            // exception — exactly the "'/' is invalid after a value" crash seen in production.
            // baseUrl is now JSON-escaped before being spliced into the template.
            string escapedBaseUrl = System.Text.Json.JsonSerializer.Serialize(baseUrl);
            escapedBaseUrl = escapedBaseUrl.Substring(1, escapedBaseUrl.Length - 2); // strip the surrounding quotes JsonSerializer adds
            json = json.Replace("{IssuerUrl}", escapedBaseUrl);

            // M-01 fix: a malformed credential-configurations-supported.json (bad manual edit, bad
            // admin update via CredentialConfigController, etc.) must not crash the whole metadata
            // endpoint with an unhandled 500. Fail closed to an empty configuration set and log
            // server-side instead.
            try
            {
                var node = JsonNode.Parse(json);
                return node ?? new JsonObject();
            }
            catch (System.Text.Json.JsonException ex)
            {
                NLog.LogManager.GetCurrentClassLogger().Error(ex,
                    "credential-configurations-supported.json is not valid JSON; serving an empty credential_configurations_supported set");
                return new JsonObject();
            }
        }


        public string GenerateDriverLicenseMdoc(string issuerid, string walletid, IWebHostEnvironment _env, byte[] deviceKeyX, byte[] deviceKeyY)
        {
            // ── 1. ดึง private key ── ต้องเป็น ECDSA P-256 (ES256) แยกจาก Ed25519 ของ SD-JWT ──
            //     ISO 18013-5 Table B.1 บังคับ issuerAuth ต้องใช้ ES256/ES384/ES512 เท่านั้น
            ECDsa issuerKey = LoadEcdsaKey(GetKey(true, _env, keyType: "mdoc-issuer"));

            // ── 2. ดึงข้อมูลใบขับขี่จาก GenerateDriverLicenseVC (แหล่งข้อมูลกลางเดียวกับ SD-JWT) ─
            var vcResult = GenerateDriverLicenseVC(issuerid, walletid);
            var vcPayload = vcResult.Value as vcModelDrivingLicence
                ?? throw new Exception("GenerateDriverLicenseVC failed");

            var subject = vcPayload.vc.credentialSubject;   // _credentialSubjectDrivingLicence

            // ── 3. สร้าง IssuerSignedItem ต่อ data element พร้อม random salt + digest ─
            var nameSpaceItems = new List<CBORObject>();
            var digestMap = CBORObject.NewMap();
            int digestId = 0;

            using var sha256 = SHA256.Create();

            CBORObject AddItem(string elementId, CBORObject value)
            {
                byte[] salt = RandomNumberGenerator.GetBytes(16);

                var item = CBORObject.NewMap();
                item.Add("digestID", digestId);
                item.Add("random", salt);
                item.Add("elementIdentifier", elementId);
                item.Add("elementValue", value);

                // ISO 18013-5 บังคับห่อ item ด้วย CBOR tag 24 (encoded CBOR data item)
                byte[] itemBytes = item.EncodeToBytes();
                CBORObject tagged = CBORObject.FromObjectAndTag(itemBytes, 24);

                byte[] digest = sha256.ComputeHash(tagged.EncodeToBytes());
                digestMap.Add(digestId, digest);

                nameSpaceItems.Add(tagged);
                digestId++;
                return tagged;
            }

            // helper สำหรับแปลง driving_privileges เป็น CBOR array ตาม ISO 18013-5
            CBORObject BuildDrivingPrivilegesCbor(List<DrivingPrivilege> privileges)
            {
                var arr = CBORObject.NewArray();
                foreach (var p in privileges ?? new List<DrivingPrivilege>())
                {
                    var entry = CBORObject.NewMap();
                    entry.Add("vehicle_category_code", MapCategoryToIsoCode(p.Category));
                    entry.Add("issue_date", subject.IssueDate);
                    entry.Add("expiry_date", subject.ExpiryDate);
                    arr.Add(entry);
                }
                return arr;
            }

            // ── 4. เติม field ตาม namespace org.iso.18013.5.1 ──
            AddItem("family_name", CBORObject.FromObject(subject.FamilyName));
            AddItem("given_name", CBORObject.FromObject(subject.GivenName));
            AddItem("birth_date", CBORObject.FromObject(subject.BirthDate));
            AddItem("document_number", CBORObject.FromObject(subject.DocumentNumber));
            AddItem("issue_date", CBORObject.FromObject(subject.IssueDate));
            AddItem("expiry_date", CBORObject.FromObject(subject.ExpiryDate));
            AddItem("issuing_country", CBORObject.FromObject(subject.IssuingCountry));
            AddItem("issuing_authority", CBORObject.FromObject(subject.IssuingAuthority));
            AddItem("un_distinguishing_sign", CBORObject.FromObject(subject.UnDistinguishingSign));
            AddItem("driving_privileges", BuildDrivingPrivilegesCbor(subject.DrivingPrivileges));
            AddItem("sex", CBORObject.FromObject(MapSexToIsoCode(subject.Sex)));
            AddItem("resident_address", CBORObject.FromObject(subject.ResidentAddress));

            if (!string.IsNullOrEmpty(subject.Portrait))
            {
                // portrait ต้องเป็น CBOR byte string (bstr) ไม่ใช่ tstr
                // subject.Portrait may be a data URI ("data:image/jpeg;base64,/9j/...") rather than
                // raw base64 — Convert.FromBase64String only accepts the latter and throws
                // FormatException on the "data:image/jpeg;base64," prefix (':' '/' ';' aren't valid
                // base64 characters). Strip the prefix if present.
                string portraitBase64 = subject.Portrait;
                int commaIdx = portraitBase64.IndexOf(',');
                if (portraitBase64.StartsWith("data:", StringComparison.OrdinalIgnoreCase) && commaIdx >= 0)
                {
                    portraitBase64 = portraitBase64[(commaIdx + 1)..];
                }

                try
                {
                    byte[] portraitBytes = Convert.FromBase64String(portraitBase64);
                    AddItem("portrait", CBORObject.FromObject(portraitBytes));
                }
                catch (FormatException ex)
                {
                    // Portrait is optional — don't fail the whole mDL over malformed image data.
                    NLog.LogManager.GetCurrentClassLogger().Warn(ex, "GenerateDriverLicenseMdoc: subject.Portrait is not valid base64/data-URI, skipping portrait element");
                }
            }

            // ── 5. สร้าง valueDigests + deviceKeyInfo + validityInfo ──
            var valueDigests = CBORObject.NewMap();
            valueDigests.Add("org.iso.18013.5.1", digestMap);

            if (deviceKeyX == null || deviceKeyY == null)
                throw new ArgumentException("deviceKeyX/deviceKeyY are required to bind mdoc to the wallet's device key.");

            var deviceKeyCoseMap = CBORObject.NewMap();
            deviceKeyCoseMap.Add(1, 2);           // kty: EC2
            deviceKeyCoseMap.Add(-1, 1);          // crv: P-256
            deviceKeyCoseMap.Add(-2, deviceKeyX); // x
            deviceKeyCoseMap.Add(-3, deviceKeyY); // y

            DateTime now = DateTime.UtcNow;
            var validityInfo = CBORObject.NewMap();
            validityInfo.Add("signed", now.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            validityInfo.Add("validFrom", now.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            validityInfo.Add("validUntil", now.AddYears(10).ToString("yyyy-MM-ddTHH:mm:ssZ"));

            var mso = CBORObject.NewMap();
            mso.Add("version", "1.0");
            mso.Add("digestAlgorithm", "SHA-256");
            mso.Add("docType", "org.iso.18013.5.1.mDL");
            mso.Add("valueDigests", valueDigests);
            mso.Add("deviceKeyInfo", CBORObject.NewMap().Add("deviceKey", deviceKeyCoseMap));
            mso.Add("validityInfo", validityInfo);

            byte[] msoBytes = mso.EncodeToBytes();
            CBORObject msoTagged = CBORObject.FromObjectAndTag(msoBytes, 24);

            // ── 6. เซ็น MSO ด้วย COSE_Sign1 (ES256) — ใช้ built-in .NET System.Security.Cryptography.Cose ──
            // Bug fix: -8 is COSE alg EdDSA, not ES256 — was mismatched against issuerKey, which is an
            // ECDSA P-256 key (LoadEcdsaKey above). ISO 18013-5 Table B.1 requires ES256/ES384/ES512
            // for IssuerAuth; the correct COSE algorithm identifier for ES256 is -7.
            var protectedHeaders = new CoseHeaderMap();
            protectedHeaders.Add(CoseHeaderLabel.Algorithm, -7); // ES256

            byte[] issuerAuth = CoseSign1Message.SignEmbedded(
                embeddedContent: msoTagged.EncodeToBytes(),
                signer: new CoseSigner(issuerKey, HashAlgorithmName.SHA256, protectedHeaders)
            );

            // ── 7. ประกอบ IssuerSigned object สุดท้าย ──
            var nameSpaceArray = CBORObject.NewArray();
            foreach (var item in nameSpaceItems)
                nameSpaceArray.Add(item);

            var nameSpacesMap = CBORObject.NewMap();
            nameSpacesMap.Add("org.iso.18013.5.1", nameSpaceArray);

            var issuerSigned = CBORObject.NewMap();
            issuerSigned.Add("nameSpaces", nameSpacesMap);
            issuerSigned.Add("issuerAuth", CBORObject.DecodeFromBytes(issuerAuth));

            byte[] mdocBytes = issuerSigned.EncodeToBytes();

            // ── 8. base64url-encode สำหรับใส่ใน credential response ──
            return Base64UrlEncode(mdocBytes);
        }

        // ── Helper: ECDSA P-256 key loader (คนละคู่จาก Ed25519 ของ SD-JWT) ──
        //
        // NOT ecdsa.ImportFromPem(pem): on Windows, that goes through ECDsaCng's PKCS8 blob import
        // (CngPkcs8.ImportPkcs8PrivateKey -> CngKey.Import), which is where this specific key
        // (PKCS8 PEM from ecdsa.ExportPkcs8PrivateKeyPem() in GetKey) throws
        // "CryptographicException: The system cannot find the file specified" — a known .NET-on-
        // Windows CNG quirk with PKCS8 EC key import, not a problem with the key material itself
        // (the Jwt:PrivateKey ECDSA key elsewhere in this app loads fine via the SEC1-based
        // ImportECPrivateKey, a different, unaffected CNG code path). Parsed with BouncyCastle
        // instead (already a dependency here, and its PKCS8 parser never touches CNG at all), then
        // handed to .NET as raw curve parameters via ECDsa.Create(ECParameters) — which uses CNG's
        // ImportParameters path, not the broken PKCS8 blob path.
        private ECDsa LoadEcdsaKey(string pem)
        {
            var pemReader = new PemReader(new StringReader(pem));
            object keyObject = pemReader.ReadObject();

            ECPrivateKeyParameters privateKeyParams = keyObject switch
            {
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair => (ECPrivateKeyParameters)pair.Private,
                ECPrivateKeyParameters priv => priv,
                _ => throw new InvalidOperationException("LoadEcdsaKey: PEM did not contain an EC private key")
            };

            var domainParams = privateKeyParams.Parameters;
            var publicPoint = domainParams.G.Multiply(privateKeyParams.D).Normalize();

            int fieldSize = (domainParams.Curve.FieldSize + 7) / 8; // 32 bytes for P-256
            byte[] dRaw = privateKeyParams.D.ToByteArrayUnsigned();
            byte[] d = new byte[fieldSize];
            Array.Copy(dRaw, 0, d, fieldSize - dRaw.Length, dRaw.Length);

            var ecParameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = d,
                Q = new ECPoint
                {
                    X = publicPoint.AffineXCoord.GetEncoded(),
                    Y = publicPoint.AffineYCoord.GetEncoded()
                }
            };

            return ECDsa.Create(ecParameters);
        }

        // ── Helper: mapping sex ตาม ISO 5218 ──
        private int MapSexToIsoCode(string sex) => sex switch
        {
            "ชาย" => 1,
            "หญิง" => 2,
            _ => 0
        };

        // ── Helper: mapping ประเภทรถเป็นรหัส ISO 18013-5 vehicle category ──
        private string MapCategoryToIsoCode(string thaiCategory)
        {
            if (string.IsNullOrEmpty(thaiCategory)) return "B";
            if (thaiCategory.Contains("รถจักรยานยนต์")) return "A";
            if (thaiCategory.Contains("รถบรรทุก")) return "C";
            if (thaiCategory.Contains("รถยนต์ส่วนบุคคล")) return "B";
            return "B";
        }
    }


}
