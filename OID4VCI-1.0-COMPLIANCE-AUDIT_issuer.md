# OID4VCI 1.0 Final Compliance and Security Audit — Issuer SDK

**Project:** `issuer-sdk`  
**Audited revision:** `1eba3e053c271581b4ca4c30120334974c45ce19`  
**Audit date:** 2026-08-06  
**Normative baseline:** [OpenID for Verifiable Credential Issuance 1.0 Final, 16 September 2025](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)  
**Method:** Static, end-to-end review of the implemented metadata, Credential Offer, Pre-Authorized Code token exchange, proof processing, credential issuance, storage, and configuration surfaces. Ponytail was used to favor the smallest secure remediation: delete unsupported claims and routes, use the platform's validated JWT/OAuth facilities, and avoid custom protocol machinery.

## Executive conclusion

**Result: FAIL — not compliant with OID4VCI 1.0 Final and unsafe to deploy as an issuer.**

The implementation resembles a mixture of pre-final OID4VCI drafts and custom behavior. More importantly, its central proof-of-possession control is absent: the Credential Endpoint only decodes the proof JWT and never verifies its signature. It explicitly accepts `alg: none`. A caller can therefore choose a wallet identifier and nonce without possessing the corresponding private key.

The access token, offer, subject, credential configuration, and proof are also not bound into one authorization transaction. Pre-authorized codes can be exchanged repeatedly, access-token lifetime validation is disabled, offer creation is unauthenticated, and the issued claims are synthetic rather than loaded from an authorized subject record. These are issuance-integrity failures, not cosmetic interoperability problems.

Do not claim OID4VCI 1.0 conformance or expose this service to untrusted clients until every Critical and High finding is fixed and independently tested.

| Severity | Count | Meaning |
|---|---:|---|
| Critical | 6 | Credential forgery, unauthorized issuance, key misuse, replay, or secret exposure |
| High | 13 | Normative protocol failure or serious interoperability/security weakness |
| Medium | 5 | Reliability, maintainability, or assurance weakness |
| **Total** | **24** | Open findings |

## Scope and limitations

Reviewed components include:

- `api/IssuerAPI/Controllers/IssuerController.cs`
- `api/IssuerAPI/Controllers/CredentialOfferController.cs`
- `api/IssuerAPI/Controllers/TokenController.cs`
- `api/IssuerAPI/Controllers/CredentialController.cs`
- `api/IssuerAPI/Controllers/CredentialConfigController.cs`
- `api/IssuerAPI/Controllers/UtilitiesController.cs`
- `api/IssuerAPI/Service/VCService.cs`
- `api/IssuerAPI/Service/DBService.cs`
- `api/IssuerAPI/App_Data/credential-configurations-supported.json`
- application settings, database initialization data, and the TypeScript `sdk` package

This is a source audit, not a certification. A build was attempted with the locally available .NET 8 SDK, but the project targets .NET 9 and failed with `NETSDK1045` before compilation. No OIDF conformance suite, external wallet interoperability test, TLS deployment test, or cryptographic validation of generated SD-JWT VC/mdoc artifacts was therefore completed. The source-level security defects below are directly evidenced and do not depend on that build limitation.

## Critical defects

### C-01 — Wallet proof JWTs are not cryptographically verified

**Evidence**

- `CredentialController.cs:50-51` passes the supplied JWT to `getProofByNonce` before validating the access token or request.
- `VCService.cs:727-739` only splits and base64url-decodes the JWT payload.
- `CredentialController.cs:160-237` manually reads header and payload fields but never verifies the JWS signature.
- `CredentialController.cs:174` explicitly includes `none` in the accepted algorithm list.
- The resulting unverified `kid` becomes the credential's holder identifier at `CredentialController.cs:237`.

OID4VCI requires `alg` not to be `none` and requires the issuer to verify the JWT using the key identified by exactly one of `kid`, `jwk`, or `x5c`; the general proof verification rules also require a valid asymmetric signature. See [Appendix F.1, JWT proof type](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-jwt-proof-type) and [Appendix F.4, Verifying Proof](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-verifying-proof).

**Impact:** An attacker can fabricate a proof, claim another wallet/DID, and receive a credential bound to attacker-chosen or nonexistent key material. This defeats the primary holder-binding guarantee.

**Required fix**

1. Delete the manual JWT parsing/allow-list path and reject `none`, MAC algorithms, unsupported algorithms, duplicate key-reference headers, private JWK material, and missing proof fields.
2. Use one established JOSE verifier already supported by the .NET platform/dependencies. Resolve `kid` under a strict DID-method/trust policy, or validate the supplied public `jwk`/`x5c` as applicable.
3. Verify the signature before reading the proof as authorization input.
4. Bind the issued credential to the exact verified public key, not to a string obtained by splitting `kid`.

**Acceptance test:** A valid proof succeeds; altered payload/signature, `alg:none`, symmetric `alg`, unresolvable `kid`, private JWK, multiple key-reference headers, and a signature made by a different key all fail with `invalid_proof` and no credential is created or logged.

### C-02 — Access token, issuance transaction, proof, and requested credential are not bound together

**Evidence**

- `CredentialController.cs:50-60` selects the database issuance record from the unverified proof nonce.
- `CredentialController.cs:127-151` only checks that the bearer token is generally valid.
- The token's `sub`, `jti`, and authorized credential dataset/configuration are never compared with the selected database record, proof key, or request.
- `CredentialController.cs:111-122` checks the configuration only against the record selected through the attacker-controlled nonce.

OID4VCI states that the Credential Endpoint issues the approved Credential Dataset on presentation of the access token representing that approval. See [Section 8, Credential Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-endpoint).

**Impact:** Any valid token can potentially be combined with another observed or guessed issuance nonce to obtain a credential authorized by a different transaction.

**Required fix:** Create one server-side issuance grant record containing subject/dataset ID, allowed configuration IDs, access-token identifier or authorization reference, status, expiry, and proof-key binding. Resolve authorization only from the validated access token, then require the request and verified proof to match that same grant. Perform issuance and consumption atomically.

**Acceptance test:** Swapping the token, proof, nonce, configuration ID, or subject reference between two valid issuance transactions always fails and produces no credential.

### C-03 — Unauthenticated administrative and private-key signing endpoints are exposed

**Evidence**

- `CredentialConfigController.cs:145-176` exposes `PUT /api/CredentialConfig/claims` without authorization and writes the live configuration file.
- `UtilitiesController.cs:71-159` exposes `POST /generate-jwt-ed25519` without authorization and signs a caller-controlled nonce using the issuer private key.
- `UtilitiesController.cs:166-183` exposes `POST /did/create` without authorization and accesses issuer key/DID functionality.

**Impact:** An unauthenticated caller can alter issuer metadata/claim descriptions and use the service as a signing oracle. Depending on key reuse, the oracle can undermine other issuer protocols and key trust.

**Required fix:** Delete development utility routes from production. If configuration mutation is genuinely required, move it behind strong administrator authentication/authorization, CSRF protection where cookie authentication is used, audit logging, schema validation, and immutable deployment configuration. Use separate keys per protocol purpose and prohibit arbitrary signing.

**Acceptance test:** These routes do not exist in production. Administrative configuration changes require an authorized administrator and cannot cause invalid issuer metadata.

### C-04 — Replay protections are ineffective

**Evidence**

- `Dbrequest` stores only the pre-authorized code, configuration list, and creation time (`DBService.cs:135-147`); it has no expiry/consumed state.
- `TokenController.cs:165-208` compares the submitted code but never consumes it atomically.
- The same code can therefore produce unlimited access tokens.
- Access tokens declare a one-hour expiry (`TokenController.cs:255-272`), but `VCService.cs:488` sets `ValidateLifetime = false`.
- The proof nonce is the reusable issuance/register identifier; there is no Nonce Endpoint, freshness store, or proof replay record.

The final specification calls out Pre-Authorized Code replay and recommends transaction-code or equivalent protections; proof creation time must be within an acceptable window. It also treats bearer tokens longer than five minutes as long-lived unless sender-constrained. See [Section 13.6.1, Replay Prevention](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-replay-prevention), [Section 13.8, Proof replay](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-proof-replay), and [Section 13.10, Protecting the Access Token](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-protecting-the-access-token).

**Impact:** Stolen QR codes, pre-authorized codes, access tokens, and proofs remain reusable. One authorization can yield multiple credentials.

**Required fix:** Store hashed, high-entropy opaque codes with short expiry and one-time status; consume them in the same database transaction that creates the token. Enable token lifetime validation. Use a short-lived access token (five minutes or less) or sender-constrain it. Implement the final Nonce Endpoint and one-time/short-window proof tracking. Rate-limit offer resolution, token, nonce, and credential endpoints.

**Acceptance test:** Concurrent exchange of one pre-authorized code yields exactly one success; expired codes/tokens fail; replay of an accepted proof fails; a credential authorization cannot issue more instances than permitted.

### C-05 — Issuance is not bound to an authenticated subject or authoritative data

**Evidence**

- `POST /credential-offer` has no authorization (`CredentialOfferController.cs:39-120`).
- The same-device route has its subject lookup and authorization commented out (`CredentialOfferController.cs:127-134`).
- `BuildOffer` receives `null`; comments acknowledge that subject binding is missing, and `SaveRequestCredential` does not store a subject (`CredentialOfferController.cs:190-193`).
- Credential generators create fixed/sample identity, transcript, ID-card, and driving-licence data rather than reading an authorized subject dataset.

**Impact:** An anonymous caller can initiate issuance, and the server can issue synthetic identity credentials that were never authorized for a verified person. Even perfect protocol framing would not make those claims trustworthy.

**Required fix:** Require an authenticated, authorized issuer-side business action before creating an offer. Persist only a reference to an immutable authoritative Credential Dataset and subject, not client-supplied claims. At issuance, load that exact authorized dataset and record consent/approval. Do not expose sample generators in production.

**Acceptance test:** Anonymous offer creation fails; changing client inputs cannot alter subject claims; the issued claims exactly match the approved authoritative record.

### C-06 — Private keys, client secrets, credentials, and personal data are committed

**Evidence**

- `api/IssuerAPI/appsettings.json` contains an access-token signing private key and external client secrets.
- `api/IssuerAPI/privateKey.txt`, `publicKey.txt`, and `DID.txt` are tracked.
- `api/db/init.sql` contains seeded account/issuance data and credential/log schema; the repository history must be treated as exposed.
- `DBService.cs:151-170` stores complete issued credentials in `CredentialPayload`; `CredentialController.cs:316` logs the complete successful response.

**Impact:** Anyone with repository or log/database access may impersonate the issuer, access external services, replay credentials, or obtain personal data and selective-disclosure material.

**Required fix:** Immediately rotate every committed private key, client secret, API key, password, and affected credential. Remove secret and production-like personal/credential data from the current tree and repository history using an approved history-rewrite process. Load secrets from a managed secret store. Log only opaque event IDs and outcomes; encrypt strictly necessary records with retention/deletion controls.

**Acceptance test:** Secret scanning passes over the full Git history; old keys/secrets are rejected; logs and database rows do not contain raw access tokens, proofs, credentials, disclosures, or unnecessary personal data.

## High-severity defects

### H-01 — Credential Request uses a pre-final `proof` shape and has no final Nonce Endpoint

`IssueVCModel.cs:122-129` accepts singular `proof.jwt`. OID4VCI 1.0 Final defines `proofs` as an object containing exactly one proof-type member whose value is a non-empty array. The current service cannot accept a conforming request and cannot issue one credential per verified key. See [Section 8.2, Credential Request](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-request).

The implementation requires a nonce in practice but has no `POST` Nonce Endpoint and publishes no `nonce_endpoint`. A server that requires a `c_nonce` in proofs **MUST** offer that endpoint. See [Section 7, Nonce Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-nonce-endpoint).

**Fix:** Replace `proof` with the final `proofs` model, implement only the proof types actually supported, add and advertise the Nonce Endpoint, return unpredictable `c_nonce` values with `Cache-Control: no-store`, and support a bounded proof array only if batch issuance is intentionally supported.

### H-02 — Required JWT proof claims are validated incorrectly

`CredentialController.cs:180-207` accepts `typ` values `JWT`/`jwt` and accepts any HTTP(S) URL as `aud`. The final values are exact: `typ` must be `openid4vci-proof+jwt`, and `aud` must equal the Credential Issuer Identifier. `iat` must be a number and fresh; the current `IsValidNumericDate` policy permits an unreasonably broad interval. The code does not enforce exactly one of `kid`, `jwk`, or `x5c`, algorithm-to-metadata consistency, or anonymous pre-authorized-flow `iss` omission.

**Fix:** Enforce Appendix F.1/F.4 exactly after signature verification, with a small server-configured clock-skew/freshness window.

### H-03 — Successful Credential Response is not the final response format

`CredentialController.cs:306-318` returns top-level `format`, singular `credential`, `c_nonce`, `c_nonce_expires`, `status`, and an empty `notification_id`. Final immediate issuance uses `credentials: [{ "credential": ... }]`; the count corresponds to accepted proof keys. `notification_id` is meaningful only when notifications are supported. Credential responses should be uncacheable. See [Section 8.3, Credential Response](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-response).

**Fix:** Return only the final `credentials` array and any genuinely supported optional fields, set `Cache-Control: no-store`, and remove legacy nonce/status/format fields.

### H-04 — Token and Credential errors are non-standard and sometimes use the wrong HTTP status

`TokenController.cs` returns custom `message`, numeric `status`, and an array-valued `error`; invalid codes use `new JsonResult(Unauthorized(...))` at lines 180-207, which can serialize an `UnauthorizedObjectResult` inside an HTTP 200 response. The final token errors use RFC 6749 top-level string codes such as `invalid_request`, `invalid_grant`, `unsupported_grant_type`, and `invalid_client` with HTTP 400 as specified. See [Section 6.3, Token Error Response](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-token-error-response).

Credential errors likewise do not use `invalid_credential_request`, `unknown_credential_configuration`, `invalid_proof`, or RFC 6750 bearer errors. See [Section 8.3.1, Credential Error Response](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-error-response).

**Fix:** Centralize minimal OAuth/OID4VCI error mapping with correct status, content type, `Cache-Control: no-store`, and optional safe `error_description`.

### H-05 — Issuer metadata mixes resource-server and authorization-server metadata and advertises nonexistent features

`IssuerController.cs:57-76` publishes OIDC/OAuth fields such as `issuer`, response types, and ID-token algorithms alongside Credential Issuer metadata. It advertises `/par`, `/batch_credential`, and `/credential_deferred`, but no matching controller routes exist. In OID4VCI 1.0 Final, multi-key batch support is advertised with `batch_credential_issuance` and handled at the Credential Endpoint, not by the legacy `batch_credential_endpoint` field.

**Fix:** Publish only truthful Credential Issuer metadata at this endpoint. Move authorization-server metadata to its RFC 8414 endpoint. Delete unsupported fields; add a feature only after its endpoint and conformance tests exist.

### H-06 — Most credential configurations use obsolete or malformed metadata

`credential-configurations-supported.json` contains hundreds of entries using legacy `cryptographic_suites_supported`, top-level `types`, top-level `display`/`claims`, array/object claim shapes inconsistently, `RSA` rather than a precise JOSE algorithm, and configurations the issuance code cannot produce. The live unauthenticated config API incorrectly claims final metadata uses a claims object, while final `credential_metadata.claims` is a non-empty array of claim-description objects with `path`. See [Section 12.2.4, Credential Issuer Metadata Parameters](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-issuer-metadata-p) and [Appendix B.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-claims-description-for-issue).

**Fix:** Delete every configuration not implemented and tested. For each remaining format, use the exact final profile fields: `format`, precise binding methods and signing algorithms, `proof_types_supported`, format-specific fields (`vct`, `doctype`, or `credential_definition`), and `credential_metadata`.

### H-07 — Token authorization details do not identify authorized credentials correctly

`DBService.cs:142` stores the allowed configuration IDs as a JSON array string. `TokenController.cs:276-284` then returns that entire JSON text as one `credential_configuration_id`, rather than returning valid authorization details and optional `credential_identifiers`. The access token itself contains only `sub` and `jti`, and the Credential Endpoint does not enforce a server-side permission set derived from it.

**Fix:** Store configuration IDs relationally or as validated structured JSON. Return one authorization-details object per authorized configuration, or return dataset-specific `credential_identifiers` when applicable. Enforce the same grant server-side at the Credential Endpoint.

### H-08 — The advertised mdoc path always fails and never binds the device key

`CredentialController.cs:255-259` calls `GenerateDriverLicenseMdoc(..., null, null)`. `VCService.cs:1951-1952` immediately rejects null device-key coordinates. The offer and metadata nevertheless advertise `org.iso.18013.5.1.mDL`.

**Fix:** Remove mdoc from metadata/offers now. Re-add it only after extracting the verified COSE/JWK device key from a supported proof, producing a standards-valid MSO/IssuerSigned object, and passing independent ISO 18013-5 verification vectors.

### H-09 — Advertised credential formats and algorithms do not match implementation

The metadata advertises a very large set of `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc`, old `jwt_vc`, `vc+sd-jwt`, SD-JWT VC, and mdoc configurations, while `CredentialController.cs:243-286` implements only a few hard-coded IDs. Some configurations advertise ES256 while generators sign EdDSA; generic `RSA` is not a JOSE algorithm identifier. Wallet negotiation will select combinations that fail or differ from the issued artifact.

**Fix:** Maintain one small source of truth generated from actually registered handlers. At startup, fail closed if a configuration's format, algorithms, bindings, proof types, or handler do not agree.

### H-10 — Pre-authorized offers lack an adequate authorization and lifecycle policy

Offer records have no expiry, subject/dataset binding, consumption state, transaction code, or issuance limit. `GET /openid4vc/credentialOffer` can retrieve the bearer pre-authorized code repeatedly. A transaction code is optional in the protocol, but some equivalent defense is necessary for identity credentials because QR/pre-authorized-code replay is an explicit threat.

**Fix:** Use short-lived, one-time, high-entropy opaque offer handles and pre-authorized codes; bind them to the approved dataset; add a separately delivered `tx_code` or another documented anti-replay/user-binding control for high-assurance credentials; return `Cache-Control: no-store`.

### H-11 — Issuer identifiers and endpoint URLs are inconsistent and attacker-influenced

Metadata uses forwarded host/scheme (`IssuerController.cs:84-92`), offer creation usually uses `BASE_URL`, offer retrieval uses `Request.Scheme/Host`, credential generation uses request host, and access tokens use configured issuer `edta`. `Program.cs:51-60` clears the known proxy/network lists, so untrusted forwarded headers can influence externally published issuer/audience URLs.

**Fix:** Configure one immutable external Credential Issuer Identifier and derive every metadata value, proof audience, offer value, token audience, and format issuer identifier from it. Trust forwarded headers only from explicit proxy IPs/networks. Reject HTTP in production.

### H-12 — Sensitive protocol responses are cacheable by default

The token, nonce-like, credential-offer-by-reference, and credential responses do not explicitly set the required/recommended no-store response headers. Complete credentials and bearer codes can consequently be retained by intermediary or client caches.

**Fix:** Add `Cache-Control: no-store` (and `Pragma: no-cache` where required for OAuth compatibility) to token, nonce, credential, deferred, and sensitive offer responses; test headers through the production reverse proxy.

### H-13 — One-hour bearer tokens are neither short-lived nor sender-constrained

`TokenController.cs:258-272` creates a bearer token lasting one hour and there is no DPoP/mTLS binding. The final security considerations generally treat access tokens over five minutes as long-lived and require that long-lived access tokens not be issued unless sender-constrained.

**Fix:** Prefer a single-purpose access token of five minutes or less with strict audience, issuer, expiry, and authorization claims. Add DPoP only if the deployment genuinely needs a longer reusable token.

## Medium-severity defects

### M-01 — Malformed inputs can cause unhandled exceptions and leak internals

The credential method dereferences `request.proof.jwt` before model validation, assumes three JWT segments and required JSON members, and includes `e.Message`/`e.InnerException` in responses (`CredentialController.cs:290-303`). `DBService.getPreAuthorizedCode` similarly parses untrusted JWT segments without safe structural validation.

**Fix:** Validate shape and limits before parsing, return the standard safe error, and log only an internal correlation ID. Never return stack/inner-exception details.

### M-02 — Full credentials and protocol identifiers are retained as application logs

Even after rotating committed material, `CredentialController.cs:316-317` and `DBService.cs:151-170` retain raw issued credentials and holder/offer identifiers. This conflicts with data minimization and increases breach impact.

**Fix:** Store issuance event ID, configuration ID, subject reference, status, and timestamps only. If recovery requires a credential copy, document the purpose, encrypt it with a separate managed key, strictly authorize access, and enforce short retention.

### M-03 — The advertised TypeScript SDK is empty and has no runnable tests

`sdk/src/index.ts` is zero bytes, package version is `1.0.0`, and its test script intentionally exits with failure. The API tree contains no automated protocol/security tests.

**Fix:** Do not publish or describe this as a working SDK. Either delete the package or implement the smallest supported client surface with request/response models and conformance fixtures. Add negative security tests before adding convenience abstractions.

### M-04 — Multiple stale metadata sources and dead protocol code obscure the live behavior

The repository contains static `openid-credential-issuer*.json` files, a very large active configuration file with legacy entries, duplicate/commented Credential Endpoint implementations, and dead offer code including a hard-coded sample code assignment. This creates a high risk that fixes are applied to an inactive path.

**Fix:** Keep one metadata source and one Credential Endpoint implementation. Delete inactive draft/test configurations and commented copies; use version control for history.

### M-05 — Configuration mutation is not atomic or deployment-safe

`CredentialConfigController` reads and rewrites the shared JSON file without concurrency control, validation of the complete document, or atomic replacement. Concurrent requests or a process interruption can lose/corrupt issuer metadata.

**Fix:** Prefer immutable deployment configuration. If runtime administration is essential, store versioned configuration in the database, validate the complete candidate, and commit it transactionally.

## Minimal remediation order

### Phase 0 — Contain immediately

1. Remove public access to the service or block `/credential`, `/token`, offer creation, configuration mutation, and utility signing routes.
2. Rotate all signing keys, external secrets, passwords, codes, and credentials exposed in the repository/history.
3. Remove raw credentials/proofs/tokens from logs and restrict existing database/log access.

### Phase 1 — Rebuild the trust boundary

1. Implement verified JWT proof processing once, using a maintained JOSE implementation.
2. Implement one atomic issuance-grant record binding subject dataset, configurations, code, token authorization, proof key, expiry, use limits, and status.
3. Make pre-authorized codes one-time and short-lived; enable access-token lifetime validation.
4. Require an authenticated issuer-side decision tied to authoritative subject data.

### Phase 2 — Implement the final protocol surface

1. Support final `proofs` and the Nonce Endpoint.
2. Return final token, credential, and error response shapes with no-store headers.
3. Publish separate, truthful Credential Issuer and Authorization Server metadata.
4. Keep only one proven credential format first—prefer the currently implemented `dc+sd-jwt` path—then add mdoc only after independent format tests pass.

### Phase 3 — Prove interoperability

1. Add focused positive and negative tests from the matrix below.
2. Build with the declared .NET 9 toolchain in CI from a clean checkout.
3. Run the relevant OpenID Foundation conformance tests and at least two independent wallets.
4. Obtain an independent cryptographic/security review before production issuance.

## Required regression and conformance matrix

| Area | Minimum tests |
|---|---|
| Metadata | exact issuer identifier; correct well-known path; only implemented endpoints/formats/algorithms; separate AS metadata; HTTPS |
| Offer | by-reference JSON media type; no-store; unique opaque handle; expiry; authorized dataset binding; unknown/expired/used handle rejected |
| Token | form encoding; correct grant; missing/wrong/expired/replayed code; concurrent exchange; `tx_code` cases if enabled; exact OAuth errors; no-store |
| Access token | exact issuer/audience; expiry enforced; wrong grant/config/subject rejected; replay/use-limit policy |
| Nonce | POST without bearer token; unpredictable value; expiry/use policy; no-store; concurrency |
| Proof | valid `kid`, `jwk`, and/or chosen supported modes; altered signature/payload; `alg:none`; symmetric/unsupported alg; wrong `typ`; wrong `aud`; stale/future `iat`; wrong/replayed nonce; private or duplicate key headers |
| Credential request | final `proofs` array; exactly one proof type; unknown configuration; token/config/dataset mismatch; malformed JSON; size limits |
| Credential response | final `credentials` array; correct count/key binding; correct format encoding; no-store; no empty notification ID |
| SD-JWT VC | issuer signature; `typ`; `vct`; disclosure digests; key binding; metadata/signing-algorithm agreement; independent verifier |
| mdoc | do not advertise until MSO, IssuerAuth, digests, validity, device key, and independent ISO verifier all pass |
| Operations | secret scan including history; no sensitive logs; trusted proxy test; rate limits; database atomicity; audit events |

## Definition of done

The owner should not close this audit merely because happy-path issuance works. Completion requires all of the following:

- Every Critical and High finding is fixed or the affected feature is removed from metadata and routing.
- The final OID4VCI request/response/error shapes are used without legacy aliases.
- Negative proof, replay, token-binding, and cross-transaction tests pass.
- Metadata is generated from the same small registry that dispatches issuance handlers.
- A clean .NET 9 build and automated tests pass in CI.
- Relevant OIDF conformance tests and independent wallet/credential verifiers pass.
- All exposed secrets are rotated and sensitive history/log/data cleanup is verified.

## Normative references

- [OID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [Section 4 — Credential Offer Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-offer-endpoint)
- [Section 6 — Token Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-token-endpoint)
- [Section 7 — Nonce Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-nonce-endpoint)
- [Section 8 — Credential Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-endpoint)
- [Section 12.2 — Credential Issuer Metadata](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-issuer-metadata)
- [Section 13 — Security Considerations](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-security-considerations)
- [Appendix A — Credential Format Profiles](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-format-profiles)
- [Appendix F — Proof Types](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-proof-types)
