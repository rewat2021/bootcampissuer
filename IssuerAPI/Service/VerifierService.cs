using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json.Linq;
using SimpleBase;
using System.IO.Compression;
using System.Text;

namespace IssuerAPI.Service
{
    // Backs PresentationController — everything the Issuer needs to act as a (lightweight) OID4VP
    // Verifier of a presented PID VC, per Sequence Diagram - P2 v.1.4.md steps 8-15:
    //   - resolve the PID issuer's did:web and extract its public key (steps 9-10)
    //   - check that issuer's did:web against a trusted allowlist ("Trust Registry", steps 12-13)
    //   - fetch and check the PID VC's IETF Token Status List entry ("VC Status Registry", steps 14-15)
    // Signature/PoP verification itself (steps 8, 11) reuses VCService's existing
    // VerifyEd25519Jws/VerifyES256Jws — this class only adds the "resolve a key I don't already have"
    // and "fetch someone else's status list" pieces that didn't exist anywhere in this issuer before
    // (every existing DID/status-list helper only ever produced this issuer's own identity/status list,
    // never consumed another party's).
    public class VerifierService
    {
        private readonly HttpClient _httpClient;

        public VerifierService(HttpClient httpClient = null)
        {
            _httpClient = httpClient ?? new HttpClient();
        }

        // Consumer-side counterpart to VCService.BuildDidWebDocument (which only ever builds *this*
        // issuer's own DID document). Fetches https://{host}/.well-known/did.json for an arbitrary
        // did:web DID, reads the first verificationMethod's publicKeyMultibase, and decodes it back to
        // raw key bytes — same multicodec convention (0xED 0x01 = Ed25519, 0x80 0x24 = P-256) this
        // issuer's own did:key/did:web already use, since that's the only encoding this issuer's
        // verification logic (VerifyEd25519Jws/VerifyES256Jws) knows how to consume.
        public async Task<(byte[] key, string keyType, string error)> ResolveDidWebKeyAsync(string did)
        {
            if (string.IsNullOrWhiteSpace(did) || !did.StartsWith("did:web:", StringComparison.Ordinal))
            {
                return (null, null, "only did:web PID issuers are supported");
            }

            // did:web:example.com -> https://example.com/.well-known/did.json
            // did:web:example.com%3A8443 -> https://example.com:8443/.well-known/did.json
            // (path-form did:web, e.g. did:web:example.com:issuer, is not supported — this issuer's
            // own did:web never uses path segments either, see VCService.GetDidWebId.)
            string hostPart = did.Substring("did:web:".Length).Replace("%3A", ":", StringComparison.OrdinalIgnoreCase);
            string url = $"https://{hostPart}/.well-known/did.json";

            string json;
            try
            {
                json = await _httpClient.GetStringAsync(url);
            }
            catch (Exception ex)
            {
                return (null, null, $"failed to fetch DID document: {ex.Message}");
            }

            JObject doc;
            try
            {
                doc = JObject.Parse(json);
            }
            catch (Exception ex)
            {
                return (null, null, $"DID document is not valid JSON: {ex.Message}");
            }

            var vm = doc["verificationMethod"]?.FirstOrDefault();
            string multibase = vm?["publicKeyMultibase"]?.ToString();
            if (string.IsNullOrEmpty(multibase) || multibase[0] != 'z')
            {
                return (null, null, "DID document has no usable publicKeyMultibase");
            }

            byte[] decoded;
            try
            {
                decoded = Base58.Bitcoin.Decode(multibase.Substring(1)).ToArray();
            }
            catch (Exception ex)
            {
                return (null, null, $"publicKeyMultibase is not valid base58btc: {ex.Message}");
            }

            // Ed25519: multicodec 0xED 0x01 + 32-byte raw key.
            if (decoded.Length == 34 && decoded[0] == 0xED && decoded[1] == 0x01)
            {
                return (decoded[2..], "Ed25519", null);
            }

            // P-256: multicodec varint 0x80 0x24 (=0x1200) + 33-byte SEC1-compressed point. Decompress
            // via VCService (already has the exact same P-256 curve-math logic for did:key P-256).
            if (decoded.Length == 35 && decoded[0] == 0x80 && decoded[1] == 0x24)
            {
                byte[] compressed = decoded[2..];
                byte[] uncompressed = VCService.DecompressP256Point(compressed);
                if (uncompressed == null)
                {
                    return (null, null, "P-256 publicKeyMultibase did not decompress to a valid curve point");
                }
                return (uncompressed, "P-256", null);
            }

            return (null, null, "unsupported key type in publicKeyMultibase (only Ed25519/P-256 supported)");
        }

        // "VC Status Registry" check (steps 14-15): fetch the IETF Token Status List JWT at
        // statusListUri and read the bit at idx. Mirrors VCService.BuildStatusListToken's exact
        // encoding (1 bit/index, MSB-first within each byte, raw DEFLATE, base64url) since that's the
        // only Token Status List producer this issuer's ecosystem has — a different implementation
        // would need to follow the same IETF draft regardless.
        //
        // NOTE: does not verify the status list JWT's own signature — doing so would need to resolve
        // *its* issuer's key too (status list "iss" is not necessarily the same key we just resolved
        // for the credential itself, per spec they're allowed to differ). Documented gap, not silently
        // skipped: treat this as "did the registry say revoked", not a fully authenticated check.
        public async Task<(bool ok, bool revoked, string error)> CheckRevocationAsync(string statusListUri, int idx)
        {
            if (string.IsNullOrWhiteSpace(statusListUri))
            {
                return (false, false, "credential has no status claim to check");
            }

            string token;
            try
            {
                token = await _httpClient.GetStringAsync(statusListUri);
            }
            catch (Exception ex)
            {
                return (false, false, $"failed to fetch status list: {ex.Message}");
            }

            string[] parts = token.Split('.');
            if (parts.Length != 3)
            {
                return (false, false, "status list token is not a well-formed JWT");
            }

            JObject payload;
            try
            {
                string payloadJson = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(parts[1]));
                payload = JObject.Parse(payloadJson);
            }
            catch (Exception ex)
            {
                return (false, false, $"status list payload could not be parsed: {ex.Message}");
            }

            string lst = payload["status_list"]?["lst"]?.ToString();
            if (string.IsNullOrEmpty(lst))
            {
                return (false, false, "status list token has no status_list.lst");
            }

            byte[] packed;
            try
            {
                byte[] compressed = WebEncoders.Base64UrlDecode(lst);
                using var input = new MemoryStream(compressed);
                using var deflate = new DeflateStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                deflate.CopyTo(output);
                packed = output.ToArray();
            }
            catch (Exception ex)
            {
                return (false, false, $"status list bitstring could not be decompressed: {ex.Message}");
            }

            int byteIndex = idx / 8;
            if (byteIndex < 0 || byteIndex >= packed.Length)
            {
                // Index out of range == not represented in the list == treat as not-revoked rather
                // than failing the whole check; a too-new/out-of-range idx is a data issue, not
                // evidence of revocation.
                return (true, false, null);
            }

            bool revoked = (packed[byteIndex] & (1 << (7 - (idx % 8)))) != 0; // MSB-first, matches BuildStatusListToken
            return (true, revoked, null);
        }

        // Splits an SD-JWT+KB vp_token ("<issuer-signed JWT>~<disclosure>~...~<disclosure>~<KB-JWT>")
        // into its parts. Format matches exactly what VCService's own *Generate*Sd*Jwt methods produce
        // when they issue a credential (see e.g. GenerateIDCardSdJwt) — this is the inverse operation,
        // parsing one instead of building one. A vp_token always ends in a KB-JWT segment (holder
        // proof-of-possession is mandatory for presentation, unlike a bare issued credential which may
        // have zero disclosures and no KB-JWT yet).
        public static (string vcJwt, List<string> disclosures, string kbJwt, string error) SplitVpToken(string vpToken)
        {
            if (string.IsNullOrWhiteSpace(vpToken))
            {
                return (null, null, null, "vp_token is empty");
            }

            var segments = vpToken.Split('~');
            if (segments.Length < 2)
            {
                return (null, null, null, "vp_token must contain at least an issuer-signed JWT and a KB-JWT separated by '~'");
            }

            string vcJwt = segments[0];
            string kbJwt = segments[^1];
            var disclosures = segments[1..^1].Where(s => !string.IsNullOrEmpty(s)).ToList();

            if (vcJwt.Split('.').Length != 3 || kbJwt.Split('.').Length != 3)
            {
                return (null, null, null, "vp_token's credential or KB-JWT segment is not a well-formed JWT");
            }

            return (vcJwt, disclosures, kbJwt, null);
        }

        // Recomputes the digest each disclosure hashes to and confirms it actually appears in the
        // credential's own "_sd" array — i.e. the disclosure genuinely came from the credential as
        // originally signed by the issuer, not something the presenter tacked on afterward. Same
        // salt/name/value array + sha-256 + base64url scheme VCService's Generate*SdJwt methods use to
        // build disclosures in the first place.
        public static bool DisclosureMatchesSdArray(string disclosureB64Url, IEnumerable<string> sdHashes)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(disclosureB64Url));
            string hashB64 = WebEncoders.Base64UrlEncode(hashBytes);
            return sdHashes.Contains(hashB64, StringComparer.Ordinal);
        }

        // Converts a "cnf.jwk" (RFC 7800 / holder binding) into the raw key bytes
        // VerifyEd25519Jws/VerifyES256Jws expect. Only OKP/Ed25519 and EC/P-256 are supported — the
        // only two key types this issuer's own VCService.BuildCnf ever embeds, and the only two this
        // issuer's proof/signature verification code knows how to check.
        public static (byte[] key, string keyType, string error) JwkToRawKey(JObject jwk)
        {
            if (jwk == null)
            {
                return (null, null, "cnf has no jwk");
            }

            string kty = jwk["kty"]?.ToString();
            string crv = jwk["crv"]?.ToString();

            if (kty == "OKP" && crv == "Ed25519")
            {
                string x = jwk["x"]?.ToString();
                if (string.IsNullOrEmpty(x)) return (null, null, "OKP jwk missing x");
                return (WebEncoders.Base64UrlDecode(x), "Ed25519", null);
            }

            if (kty == "EC" && crv == "P-256")
            {
                string x = jwk["x"]?.ToString();
                string y = jwk["y"]?.ToString();
                if (string.IsNullOrEmpty(x) || string.IsNullOrEmpty(y)) return (null, null, "EC jwk missing x/y");
                byte[] xBytes = WebEncoders.Base64UrlDecode(x);
                byte[] yBytes = WebEncoders.Base64UrlDecode(y);
                byte[] point = new byte[65];
                point[0] = 0x04;
                Buffer.BlockCopy(xBytes, 0, point, 1, 32);
                Buffer.BlockCopy(yBytes, 0, point, 33, 32);
                return (point, "P-256", null);
            }

            return (null, null, $"unsupported jwk kty/crv: {kty}/{crv}");
        }
    }
}
