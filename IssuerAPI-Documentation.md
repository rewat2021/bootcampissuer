# เอกสาร API — Issuer Service (bootcamp_issuer)

> สร้างจากการอ่านโค้ด controller จริงทั้งหมดในโปรเจกต์ (ไม่ใช่การเดาจาก spec) ปรับปรุงล่าสุดตามการแก้ไขในเซสชันนี้ (OID4VCI 1.0 Final compliance remediation + ฟีเจอร์ OID4VP verifier)
>
> Base URL (ค่าเริ่มต้น): มาจาก `Oid4Vci:CredentialIssuerIdentifier` ถ้าตั้งไว้ใน `appsettings.json` ไม่งั้น fallback เป็น `scheme://host` จาก request จริง (เชื่อ `X-Forwarded-*` เฉพาะจาก proxy ที่ config ไว้ใน `ReverseProxy:KnownProxies` เท่านั้น) — ดู `IssuerController.GetBaseUrl`
>
> หมายเหตุ: interactive Swagger UI ของ endpoint กลุ่ม REST/JSON เปิดอยู่แล้วที่ `/swagger` ทั้งใน Development และ Production

---

## ภาพรวม endpoint ทั้งหมด

| กลุ่ม | Method | Path | Auth |
|---|---|---|---|
| Metadata | GET | `/.well-known/openid-credential-issuer` | Anonymous |
| Metadata | GET | `/.well-known/oauth-authorization-server` | Anonymous |
| Metadata | GET | `/.well-known/did.json` | Anonymous |
| Metadata | GET | `/status-list/1` | Anonymous |
| Auth & Token | POST | `/nonce` | Anonymous |
| Auth & Token | POST | `/token` | Anonymous |
| Credential Issuance | POST | `/credential` | Bearer token |
| Credential Offer | POST | `/credential-offer` | Cookie (Authorize) |
| Credential Offer | GET | `/credential-offer/pid-status` | Cookie (Authorize) |
| Credential Offer | GET | `/credential-offer/status` | Cookie (Authorize) |
| Credential Offer | GET | `/credential-offer/redirect` | Cookie (Authorize) |
| Credential Offer | GET | `/openid4vc/credentialOffer` | Anonymous |
| SD-JWT VC Type Metadata | GET | `/credentials/TranscriptCredential` | Anonymous |
| SD-JWT VC Type Metadata | GET | `/credentials/BootCampCredential` | Anonymous |
| SD-JWT VC Type Metadata | GET | `/credentials/IDCard` | Anonymous |
| SD-JWT VC Type Metadata | GET | `/credentials/DrivingLicence` | Anonymous |
| Presentation (OID4VP) | POST | `/presentation-request` | Cookie (Authorize) |
| Presentation (OID4VP) | GET | `/presentation-request/{state}` | Anonymous |
| Presentation (OID4VP) | POST | `/presentation-response` | Anonymous |
| Presentation (OID4VP) | GET | `/presentation-request/{state}/status` | Cookie (Authorize) |
| Utilities | GET | `/resolveDID` | Anonymous |
| Utilities | POST | `/generate-jwt-ed25519` | Cookie (admin) |
| Utilities | POST | `/did/create` | Cookie (admin) |
| Credential Config (Admin) | GET | `/api/CredentialConfig/types` | Cookie (admin) |
| Credential Config (Admin) | PUT | `/api/CredentialConfig/claims` | Cookie (admin) |
| หน้าเว็บ (ไม่ใช่ JSON API) | GET/POST | `/Account/Login` | Anonymous |
| หน้าเว็บ | POST | `/Account/Logout` | Cookie |
| หน้าเว็บ | GET | `/Account/ThaIDLogin`, `/thaiid/login` | Anonymous |
| หน้าเว็บ | GET | `/api/thaid/callback` | Anonymous |
| หน้าเว็บ | GET | `/QR/QRCode` | Cookie |
| หน้าเว็บ | GET | `/Logs`, `/Logs/Credentials` | Cookie (admin) |
| หน้าเว็บ | POST | `/Logs/Credentials/{id}/revoke` | Cookie (admin) |

---

## ส่วนที่ 1 — OID4VCI Core (Metadata / Token / Credential / Nonce)

Endpoint กลุ่มนี้ implement ตาม [OpenID for Verifiable Credential Issuance 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)

### GET `/.well-known/openid-credential-issuer`

Credential Issuer Metadata ตาม §12.2.4 — `[AllowAnonymous]`, `Cache-Control: no-store`

**Response**
```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_endpoint": "https://issuer.example.com/credential",
  "nonce_endpoint": "https://issuer.example.com/nonce",
  "credential_configurations_supported": { "...": "อ่านจาก App_Data/credential-configurations-supported.json" }
}
```

หมายเหตุ: จงใจไม่ publish field ของ Authorization Server (issuer, scopes_supported, response_types_supported ฯลฯ) ในเอกสารนี้ — แยกไปอยู่ที่ `/.well-known/oauth-authorization-server` ตาม RFC 8414 แทน (เดิมเคยปนกันจนถูก audit ตีเป็น finding H-05)

### GET `/.well-known/oauth-authorization-server`

OAuth 2.0 Authorization Server Metadata (RFC 8414) — `[AllowAnonymous]`

**Response**
```json
{
  "issuer": "https://issuer.example.com",
  "token_endpoint": "https://issuer.example.com/token",
  "grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"],
  "response_types_supported": ["code", "vp_token", "id_token"],
  "response_modes_supported": ["query", "fragment"],
  "scopes_supported": ["openid"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"]
}
```

### GET `/.well-known/did.json`

DID Document สำหรับ did:web ของ issuer นี้ — `[AllowAnonymous]`. ปัจจุบัน flow ออก VC จริงใช้ **did:key** เป็นหลัก (สลับกลับจาก did:web แล้ว เพราะ wallet บางตัว resolve did:web ไม่ได้) endpoint นี้ยังเปิดค้างไว้เผื่อใช้ในอนาคต ไม่ได้ถูกอ้างอิงจาก flow ออก VC ปัจจุบัน

### GET `/status-list/1`

IETF Token Status List (`statuslist+jwt`) สำหรับเช็คสถานะเพิกถอน (revocation) ของ VC ที่มี `status` claim — `[AllowAnonymous]` (verifier ภายนอกต้องเรียกได้โดยไม่ login)

**Response**: `Content-Type: application/statuslist+jwt` — เป็น JWT ที่มี bit array บีบอัดแบบ raw DEFLATE, index ตรงกับ id ของ credential ที่ออกไป (ดู `DBService.TryMarkIssued`)

### POST `/nonce`

Nonce Endpoint ตาม §7 — ออก `c_nonce` ที่ wallet ต้องฝังใน proof JWT — `[AllowAnonymous]`, `Cache-Control: no-store`

**Response**
```json
{ "c_nonce": "…", "c_nonce_expires_in": 300 }
```

nonce เก็บลง DB และถูก consume แบบ single-use ตอนเรียก `/credential` (ป้องกัน proof replay)

### POST `/token`

Token Endpoint — แลก pre-authorized_code เป็น access token — `[AllowAnonymous]`, `Content-Type: application/x-www-form-urlencoded`

**Request (form fields)**

| field | บังคับ | หมายเหตุ |
|---|---|---|
| `grant_type` | ใช่ | ต้องเป็น `urn:ietf:params:oauth:grant-type:pre-authorized_code` เท่านั้น |
| `pre-authorized_code` | ใช่ | ได้จาก credential offer |
| `tx_code` | เฉพาะ offer แบบ cross-device/QR | PIN 6 หลักที่แสดงคู่กับ QR — offer แบบ same-device ไม่ต้องส่ง |

**Response (200)**
```json
{
  "access_token": "…",
  "token_type": "Bearer",
  "expires_in": 300,
  "c_nonce": "…",
  "c_nonce_expires_in": 300,
  "authorization_details": [
    { "type": "openid_credential", "credential_configuration_id": "IDCard_dc+sd-jwt" }
  ]
}
```

**Error (400, RFC 6749 §5.2 shape)**: `{ "error": "invalid_grant" | "invalid_request" | "unsupported_grant_type", "error_description": "…" }`

หมายเหตุความปลอดภัย: access token อายุ 5 นาทีเท่านั้น (เดิมเคย 1 ชั่วโมง), pre-authorized_code ใช้ได้ครั้งเดียว (consume แบบ atomic กันแข่งกันใช้พร้อมกัน), ตรวจ `tx_code` ก่อน consume code เสมอ

### POST `/credential`

Credential Endpoint ตาม §8 — endpoint หลักที่ wallet เรียกเพื่อขอรับ VC จริง — **ต้องมี `Authorization: Bearer <access_token>`**

**Request**
```json
{
  "credential_configuration_id": "IDCard_dc+sd-jwt",
  "proofs": { "jwt": ["<openid4vci-proof+jwt>"] }
}
```

ข้อกำหนดของ proof JWT (ตรวจสอบทุกข้อก่อนออก VC): header `alg` ต้องเป็น `EdDSA` หรือ `ES256` เท่านั้น (ปฏิเสธ `none` เด็ดขาด), header `typ` ต้องเป็น `openid4vci-proof+jwt` เป๊ะๆ, `kid` ต้องเป็น did:key ที่ decode ได้จริง, payload `aud` ต้องตรงกับ credential issuer identifier เป๊ะๆ, `iat` ต้องอยู่ในช่วงเวลาที่ยอมรับ, `nonce` ต้องเป็นค่าที่ออกจาก `/nonce` หรือ `/token` และยังไม่เคยถูกใช้ — **signature ของ proof JWT ถูก verify จริงกับ public key ที่ decode จาก `kid`** (ไม่ใช่แค่ decode payload เฉยๆ)

**Response (200)**
```json
{ "credentials": [ { "credential": "<issued VC string>" } ] }
```

**Response (mso_mdoc)**: ต้องมี header `jwk` (EC P-256, 32-byte x/y) แนบมาด้วยสำหรับผูก device key ของ mdoc

**Error (400)**: `{ "error": "invalid_proof" | "invalid_credential_request" | "credential_request_denied", "error_description": "…" }` — ไม่ leak internal exception message ออกไป

Credential type ที่ implement จริง (ตรงกับที่ประกาศใน metadata): `TranscriptCredential_dc+sd-jwt`, `BootCampCredential_dc+sd-jwt`, `IDCard_dc+sd-jwt`, `Iso18013DriversLicenseCredential_dc+sd-jwt`, `org.iso.18013.5.1.mDL`, `TranscriptCredential_jwt_vc_json`, `IDCardCredential_jwt_vc_json`

หมายเหตุ: `IDCard_dc+sd-jwt` และ `IDCardCredential_jwt_vc_json` ใช้ข้อมูลจริงจาก ThaID (ชื่อ/นามสกุล/วันเกิด/เพศ/ที่อยู่/วันออกบัตร/วันหมดอายุ) ถ้า login ผ่าน ThaID มา — เอกสารประเภทอื่น (Transcript/DriverLicense) ยังใช้ข้อมูล mock อยู่

---

## ส่วนที่ 2 — Credential Offer / QR Flow

โฟลว์การขอ VC ของผู้ใช้จริง (ผ่านหน้าเว็บ QR) — ทุก endpoint ในกลุ่มนี้ (ยกเว้นตัวสุดท้าย) ต้อง login ก่อน (cookie session จาก ThaID หรือ staff login)

### POST `/credential-offer`

สร้าง credential offer + QR code สำหรับ cross-device flow — `[Authorize]`

**Request**
```json
{ "documentType": "IdCard" }
```
ค่า `documentType` ที่รองรับ: `Transcript`, `IdCard`, `DriverLicense`

**Response (200)**
```json
{
  "credentialOffer": { "credential_issuer": "…", "credential_configuration_ids": ["IDCard_dc+sd-jwt"], "grants": { "…": "…" } },
  "credentialOfferUri": "openid-credential-offer://?credential_offer_uri=…",
  "qrText": "<base64 PNG>",
  "expiresIn": 120,
  "requestId": "…",
  "txCode": "123456"
}
```

`txCode` เป็น PIN 6 หลักที่ต้อง**แสดงแยกจาก QR** (เช่น พิมพ์อยู่ข้างๆ ภาพ QR) — เป็นมาตรการกันคนสวมรอยสแกน QR ที่หลุดออกไปก่อนเจ้าของตัวจริงจะสแกน (server เก็บแค่ SHA-256 hash ของ PIN นี้ ไม่เก็บ plaintext)

### GET `/credential-offer/pid-status`

เช็คว่าผู้ใช้คนนี้เคยได้รับ PID VC (บัตรประชาชน) ไปแล้วหรือยัง — `[Authorize]`

**Response**: `{ "has_pid_vc": true }`

### GET `/credential-offer/status?id={requestId}`

หน้า QR ใช้ poll endpoint นี้เพื่อรู้ว่า wallet สแกน+ออก VC สำเร็จหรือยัง — `[Authorize]`, scope เฉพาะ offer ของผู้ใช้ที่ login เองเท่านั้น

**Response**: `{ "issued": true }`

### GET `/credential-offer/redirect?documentType={type}`

Same-device flow — wallet เปิด browser มาที่นี่ตรงๆ (ไม่ต้องโชว์ QR) แล้ว redirect ด้วย custom scheme กลับไปหา wallet ทันที — `[Authorize]`

**Response**: HTTP redirect ไปที่ `walletapp://callback?credential_offer_uri=…`

### GET `/openid4vc/credentialOffer?id={requestId}`

Endpoint ที่ wallet เรียกจริงเพื่อ resolve `credential_offer_uri` (by-reference) — `[AllowAnonymous]` (wallet ไม่มี session กับ issuer)

**Response**
```json
{
  "credential_issuer": "…",
  "credential_configuration_ids": ["IDCard_dc+sd-jwt"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "…",
      "tx_code": { "length": 6, "input_mode": "numeric", "description": "กรอกรหัส 6 หลักที่แสดงบนหน้าจอ" }
    }
  }
}
```

`tx_code` field จะโผล่มาเฉพาะ offer ที่สร้างจากฝั่ง cross-device (QR) เท่านั้น

---

## ส่วนที่ 3 — SD-JWT VC Type Metadata

ตาม [draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) §5 — ให้ wallet ดึงไปแสดงผล (โลโก้/สี/ชื่อ claim แต่ละภาษา) ทั้งหมด `[AllowAnonymous]`, `GET`

| Path | Credential |
|---|---|
| `/credentials/TranscriptCredential` (alias: `.well-known/vct/credentials/TranscriptCredential`) | ใบแสดงผลการเรียน |
| `/credentials/BootCampCredential` (alias เดียวกัน) | อ่าน claims จาก `credential-configurations-supported.json` แบบ dynamic (ต่างจาก type อื่นที่ hardcode) |
| `/credentials/IDCard` | บัตรประชาชน |
| `/credentials/DrivingLicence` (alias: `.well-known/vct/credentials/Iso18013DriversLicenseCredential`) | ใบขับขี่ |

**รูปแบบ Response (ทุก path)**
```json
{
  "vct": "https://issuer.example.com/credentials/IDCard",
  "name": "IDCard",
  "description": "Thai national identity card",
  "display": [
    { "lang": "th", "name": "บัตรประชาชน", "description": "…", "rendering": { "simple": { "logo": {...}, "background_color": "#003580", "text_color": "#ffffff" } } },
    { "lang": "en", "name": "National ID Card" }
  ],
  "claims": [
    { "path": ["id_number"], "mandatory": true, "sd": true, "display": [{"lang":"th","label":"เลขบัตรประชาชน"},{"lang":"en","label":"ID Number"}] }
  ]
}
```

---

## ส่วนที่ 4 — Presentation (OID4VP Verifier)

ฟีเจอร์ใหม่ในเซสชันนี้ — issuer เล่นบทบาท **verifier** เพื่อตรวจสอบ PID VC ของผู้ถือก่อนออกเอกสารอื่น ตาม Sequence Diagram P2 (OID4VP) เป็น MVP: รองรับเฉพาะ dc+sd-jwt ที่ issuer ออกเอง และ PID issuer ที่ใช้ did:web เท่านั้น Trust Registry เป็น allowlist ใน config (`Verifier:TrustedPidIssuers`) ยังไม่ได้ผูกเข้ากับ flow ขอ Standard VC จริง (เป็นขั้นต่อไปที่ยังไม่ได้ทำ)

### POST `/presentation-request`

สร้าง OID4VP authorization request + QR ให้ wallet สแกน — `[Authorize]`

**Response**
```json
{
  "authorize_uri": "openid4vp://?client_id=did:key:…&request_uri=…",
  "request_uri": "https://issuer.example.com/presentation-request/{state}",
  "qr_text": "<base64 PNG>",
  "state": "…",
  "expires_in": 120
}
```

### GET `/presentation-request/{state}`

Wallet resolve authorization request object ตัวเต็ม (by-reference) — `[AllowAnonymous]`

**Response**
```json
{
  "response_type": "vp_token",
  "client_id": "did:key:…",
  "response_mode": "direct_post",
  "response_uri": "https://issuer.example.com/presentation-response",
  "nonce": "…",
  "state": "…",
  "dcql_query": {
    "credentials": [
      { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["https://issuer.example.com/credentials/IDCard"] }, "claims": [{ "path": ["id_number"] }] }
    ]
  }
}
```

### POST `/presentation-response`

Wallet ส่ง `vp_token` กลับมาที่นี่ (`response_mode: direct_post`) — `[AllowAnonymous]`, `Content-Type: application/x-www-form-urlencoded`

**Request (form)**: `vp_token`, `state`

ขั้นตอนตรวจสอบภายใน (ต้องผ่านทุกข้อ): แยก vp_token เป็น VC JWT + disclosures + Key Binding JWT → resolve PID issuer DID (did:web) → verify signature ของ PID VC → เช็ค disclosure hash แต่ละอันตรงกับ `_sd` ใน VC จริง → เช็ค issuer อยู่ใน trusted allowlist → เช็คสถานะเพิกถอนถ้า VC มี status claim → verify Key Binding JWT (`aud`/`nonce` ตรง + signature ตรงกับ `cnf` key ของผู้ถือ)

**Response**: `200 {}` เมื่อผ่าน, `400 { "error": "invalid_request", "error_description": "<เหตุผลที่ verify ไม่ผ่าน>" }` เมื่อไม่ผ่าน

### GET `/presentation-request/{state}/status`

หน้าเว็บของ issuer เอง poll endpoint นี้เพื่อรู้ผลการ verify — `[Authorize]`, scope เฉพาะเจ้าของ state เท่านั้น

**Response**: `{ "status": "pending" | "verified" | "failed", "failure_reason": "…" }`

---

## ส่วนที่ 5 — Utilities / Admin

### GET `/resolveDID?didKey={did}`

Resolve did:key เป็น public key (สำหรับ debug/testing) — `[AllowAnonymous]` (แค่ resolve ค่า ไม่มีข้อมูลอ่อนไหว)

### POST `/generate-jwt-ed25519`

สร้าง proof JWT ตัวอย่างเพื่อทดสอบ flow ผ่าน Swagger (เซ็นด้วย private key ของ issuer เอง) — **`[Authorize(Roles = "admin")]` เท่านั้น** (เดิมเคยเปิด anonymous จนกลายเป็นช่องโหว่ signing oracle — แก้แล้ว)

**Request (query string)**: `nonce`, `credentialConfigurationId` (optional — ถ้าเป็น `org.iso.18013.5.1.mDL` จะแนบ P-256 device key ตัวอย่างให้อัตโนมัติ)

**Response**: proof JWT string ตรงรูปแบบ OID4VCI (header/payload/signature)

### POST `/did/create`

คืนค่า did:key ปัจจุบันของ issuer — **`[Authorize(Roles = "admin")]` เท่านั้น** (เดิมเคยเปิด anonymous — แก้แล้ว)

**Response**: `{ "did": "did:key:…", "status": "200" }`

### GET `/api/CredentialConfig/types`

ดูรายชื่อ credential type + format ที่ตั้งค่าไว้ใน `credential-configurations-supported.json` — `[Authorize(Roles = "admin")]`

### PUT `/api/CredentialConfig/claims`

แก้ไข claims ของ `BootCampCredential_dc+sd-jwt` (เขียนไฟล์ config จริง แบบ atomic + lock กันแก้พร้อมกันชนกัน) — `[Authorize(Roles = "admin")]`

**Request**
```json
{
  "claims": {
    "student_id": { "mandatory": true, "sd": true, "display": [{ "name": "รหัสนักศึกษา", "locale": "th" }] },
    "gpa": { "mandatory": false, "sd": true }
  }
}
```

---

## ส่วนที่ 6 — หน้าเว็บ (Session-based, ไม่ใช่ JSON REST API)

หน้ากลุ่มนี้ return เป็น HTML view (Razor) ไม่ใช่ JSON — ใช้ cookie session ผ่าน ASP.NET Core Identity/Cookie Authentication ไม่ใช่ Bearer token แบบกลุ่ม OID4VCI

| Path | คำอธิบาย |
|---|---|
| `GET/POST /Account/Login` | หน้า login แบบ username/password สำหรับ staff/admin (สิทธิ์ admin ให้อัตโนมัติหลัง login สำเร็จ) |
| `POST /Account/Logout` | ออกจากระบบ |
| `GET /Account/ThaIDLogin`, `GET /thaiid/login` | เริ่ม OAuth flow ไปยัง DOPA ThaID gateway |
| `GET /api/thaid/callback` | ThaID redirect กลับมาที่นี่หลัง login สำเร็จ (ต้องเปิด public ผ่าน internet เสมอ — ดูหมายเหตุด้านล่าง) |
| `GET /QR/QRCode` | หน้าแสดง QR ให้สแกนขอ VC (ต้อง login ก่อน) |
| `GET /Logs`, `GET /Logs/Credentials` | หน้า audit log การออก VC (admin เท่านั้น) |
| `POST /Logs/Credentials/{id}/revoke` | เพิกถอน VC ที่ออกไปแล้ว (admin เท่านั้น, มีผลก็ต่อเมื่อ verifier มา fetch `/status-list/1` ใหม่) |

**หมายเหตุสำคัญ — `/api/thaid/callback`**: endpoint นี้ตั้งใจเป็น `[AllowAnonymous]` และต้องเข้าถึงได้จากอินเทอร์เน็ตสาธารณะเสมอ เพราะเป็น OAuth `redirect_uri` ที่ DOPA ThaID gateway จะ redirect เบราว์เซอร์ของผู้ใช้กลับมา ตอนนั้นเบราว์เซอร์ยังไม่เคย login กับ issuer เลย จึง require auth ไม่ได้ — ความปลอดภัยอยู่ที่การแลก code กับ DOPA เองฝั่ง server แล้วตรวจผลลัพธ์ ไม่ใช่การปิด anonymous access

---

## ภาคผนวก A — DocumentType enum

```csharp
public enum DocumentType { Transcript, IdCard, DriverLicense }
```

## ภาคผนวก B — รูปแบบ Error มาตรฐาน

Endpoint กลุ่ม OID4VCI/OID4VP ทั้งหมดใช้รูปแบบ error เดียวกัน (RFC 6749 §5.2 / OID4VCI §8.3.1 style):

```json
{ "error": "<error_code>", "error_description": "<คำอธิบายที่ปลอดภัย ไม่ leak internal exception>" }
```

`error_code` ที่ใช้จริง: `invalid_request`, `invalid_grant`, `unsupported_grant_type`, `invalid_token`, `invalid_proof`, `invalid_credential_request`, `credential_request_denied`, `unauthorized`, `server_error`

## ภาคผนวก C — Response header ที่บังคับ

ทุก endpoint ที่ตอบข้อมูลอ่อนไหว (token, credential, offer, nonce, presentation) ใส่ `Cache-Control: no-store` (และบางจุดเพิ่ม `Pragma: no-cache`) เพื่อกัน caching โดย intermediary/browser

## ภาคผนวก D — สรุประดับสิทธิ์ (Authorization)

| ระดับ | ใช้กับ |
|---|---|
| Anonymous | Metadata ทุก endpoint, `/token`, `/nonce`, `/credential`* , `/openid4vc/credentialOffer`, SD-JWT VC Type Metadata ทั้งหมด, `/presentation-request/{state}` (GET), `/presentation-response`, `/resolveDID`, หน้า login/ThaID callback |
| Cookie (ผู้ใช้ทั่วไป, `[Authorize]`) | `/credential-offer/*`, `/presentation-request` (POST), `/presentation-request/{state}/status`, `/QR/QRCode` |
| Cookie (`[Authorize(Roles="admin")]`) | `/generate-jwt-ed25519`, `/did/create`, `/api/CredentialConfig/*`, `/Logs/*` |
| Bearer access token | `/credential` (ตรวจสอบ signature จริง ไม่ใช่แค่ decode) |

\* `/credential` ไม่ใช่ anonymous จริง — ต้องมี `Authorization: Bearer` header แต่ไม่ใช้ cookie session
