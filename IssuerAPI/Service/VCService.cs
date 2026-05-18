using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using NSec.Cryptography;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using SimpleBase;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using IssuerAPI.Models;
using QRCoder;


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
                    ValidateLifetime = false, //default true
                    ClockSkew = TimeSpan.Zero // To avoid time discrepancies
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

        public bool IsValidNumericDate(long numericDate)
        {
            // Define reasonable bounds for Unix timestamps
            long minValidTimestamp = 0; // January 1, 1970
            long maxValidTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + (60 * 60 * 24 * 365 * 10); // 10 years in the future

            // Check if the numericDate is within the valid range
            return numericDate >= minValidTimestamp && numericDate <= maxValidTimestamp;
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

        public string IsExpectedDomain(HttpRequest request)
        {
            string domain = request.Host.Host; //Request.Host.Host;
            string filejson = null;
            filejson = "openid-credential-issuer.json";
            if (domain == "vc-testtool-test.etda.or.th")
            {
                filejson = "openid-credential-issuer-test.json";
            }
            else
            {
                filejson = "openid-credential-issuer.json";
            }

            return filejson;
        }

        public string getProofByNonce(string proof)
        {
            DBService vCServ = new DBService();
            string jwt = proof;
            string[] parts = jwt.Split('.');

            // Decode the header and payload
            string payload = Base64UrlDecodeToString(parts[1]);
            using JsonDocument doc = JsonDocument.Parse(payload);
            string nonce = doc.RootElement.GetProperty("nonce").GetString();
            string id = vCServ.GetRegisterId(nonce);

            return id;
        }


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

                item.HonorificPrefix = "นาย";
                item.GivenName = "ทดสอบ";
                item.FamilyName = "เอกสารดิจิตัล";
                item.Gender = "1";
                item.BirthDate = "2015-01-30";
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


        public JsonResult GenerateIDCardVC(string issuerid, string walletid)
        {

            _JwtPayloadModel model = new _JwtPayloadModel();
            var token = new JsonResult(new { Ok = "" });

            try
            {

                model.issuer.id = issuerid; //GetLegalEntityDID();

                model.issuer.name = "Department Of Provincial Administration";//UniversityName;

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
                docInform.Identifier.Value = "123456";
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
                item.Identifier.Name = "StudenID";
                item.Identifier.Value = "123456";

                item.HonorificPrefix = "นาย";
                item.GivenName = "ทดสอบ";
                item.FamilyName = "เอกสารดิจิตัล";
                item.Gender = "1";
                item.BirthDate = "2015-01-30";
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

        public string GenerateTranscriptSdJwt(string issuerid, string walletid, IWebHostEnvironment _env, string UrlBase)
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
            var cnf = new { kid = walletid };

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
            string UrlBase)
        {
            // ── 1. ดึง private key (Ed25519) ─────────────────────────
            PemReader pemReaderPrivate = new PemReader(new StringReader(GetKey(true, _env)));
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)pemReaderPrivate.ReadObject();

            // ── 2. อ่าน claims config จากไฟล์ ────────────────────────
            const string CREDENTIAL_TYPE = "BootCampCredential_dc+sd-jwt";
            string configPath = Path.Combine(_env.ContentRootPath, "App_Data/credential-configurations-supported.json");
            string configJson = File.ReadAllText(configPath);

            var configNode = System.Text.Json.Nodes.JsonNode.Parse(configJson)?.AsObject();
            var claimsNode = configNode?[CREDENTIAL_TYPE]?["claims"];


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
                ["cnf"] = new { kid = walletid },
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

    }


}
