# คู่มือ Deploy บน Docker — Issuer Service (bootcamp_issuer)

อัปเดตล่าสุดหลังแก้ C-06 (secret ทั้งหมดย้ายไป `.env`, `db/init.sql` เหลือแค่ schema เปล่า, Dockerfile แก้เป็น .NET 9)

---

## 0. เตรียมของก่อนเริ่ม

- เครื่องมี Docker + Docker Compose (v2 ขึ้นไป)
- ไฟล์ `.env` ที่ root โปรเจกต์ (อยู่คู่กับ `docker-compose.yml`) — **ต้องกรอกค่าจริงให้ครบก่อนขั้นตอนที่ 3** ไม่งั้น container จะไม่ยอม start (`MYSQL_ROOT_PASSWORD`) หรือ start ได้แต่ endpoint หลักพัง (`Jwt__PrivateKey`, `ThaIDConfig__ClientID/ClientSecret`)
- ค่าที่ต้องกรอกใน `.env` (ดูรายละเอียดที่มาของแต่ละค่าในบทสนทนาก่อนหน้า):

| ตัวแปร | มาจากไหน |
|---|---|
| `CONNECTION_STRING` | connection string MySQL จริงที่จะใช้ (ชี้ไป `issuer-mysql` service ถ้าใช้ DB ที่ compose สร้างให้ หรือชี้ไปเซิร์ฟเวอร์จริงถ้าใช้ DB แยก) |
| `MYSQL_ROOT_PASSWORD` | ตั้งเอง — ใช้ตอน `issuer-mysql` container สร้าง root user ครั้งแรก |
| `Jwt__PrivateKey` | generate เองด้วยคำสั่ง PowerShell ด้านล่าง (ข้อ 2) |
| `ThaIDConfig__ClientID` / `ThaIDConfig__ClientSecret` | ขอใหม่จาก DOPA/Chula (ค่าเก่าหลุดไปแล้ว) |
| `ADMIN_BOOTSTRAP_USERNAME` / `ADMIN_BOOTSTRAP_PASSWORD` | ตั้งเอง — ใช้สร้างบัญชี staff/admin แรกอัตโนมัติตอน container boot ครั้งแรก (ดูข้อ 6) |
| `ASPNETCORE_ENVIRONMENT` | `Production` (ตั้งไว้แล้ว) |

---

## 1. Clone / pull โค้ดล่าสุด

```powershell
cd C:\project\ETDA\phase_III\bootcamp_issuer
git pull
```

---

## 2. สร้าง private key ใหม่สำหรับเซ็น access token

รันใน PowerShell แล้วเอาผลลัพธ์ไปใส่ `Jwt__PrivateKey` ใน `.env`:

```powershell
$ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName("nistP256"))
[Convert]::ToBase64String($ecdsa.ExportECPrivateKey())
```

---

## 3. สร้าง Docker network (ถ้ายังไม่มี)

`docker-compose.yml` ใช้ network ชื่อ `lab-network` แบบ `external: true` — ต้องสร้างเองก่อนครั้งแรก (ครั้งเดียวพอ ไม่ต้องสร้างซ้ำทุกครั้งที่ deploy):

```powershell
docker network create lab-network
```

---

## 4. Restore ฐานข้อมูล

มี 2 กรณี แล้วแต่ว่านี่คือการ deploy ใหม่ทั้งหมด หรือย้ายข้อมูลจากระบบเดิม:

### กรณี A — deploy ใหม่ ไม่มีข้อมูลเดิม (ปกติสำหรับ dev/lab)

ไม่ต้องทำอะไรเพิ่ม — พอ `issuer-mysql` container boot ครั้งแรก (เฉพาะตอนที่ volume `issuer-mysql-data` ยังว่างเปล่าเท่านั้น) มันจะรัน `db/init.sql` อัตโนมัติผ่าน `docker-entrypoint-initdb.d` ให้เองตามที่ตั้งไว้ใน `docker-compose.yml` — ได้ schema เปล่า (ตาราง `dbissuerlog`, `dbregister`, `dbrequest`, `users`) พร้อมใช้งาน ไม่มีข้อมูลทดสอบ/ข้อมูลจริงของใครติดมาด้วย

**ข้อควรรู้**: schema ใน `db/init.sql` เป็นแบบเก่ากว่าที่แอปตัวปัจจุบันต้องการ (ขาดหลายคอลัมน์ที่เพิ่มไปในเซสชันนี้ เช่น `Address`, `DateOfIssuance`, `TxCodeHash` ในตาราง `dbrequest`, และขาดตาราง `dbissuedcredential`/`dbnonce`/`dbpresentationrequest` ไปเลย) — ถ้าจะให้ฟีเจอร์ล่าสุด (tx_code, OID4VP verifier, status list revocation) ทำงานได้ครบ ต้องรัน EF Core migration หรือ ALTER TABLE เพิ่มเติมหลัง container ขึ้นแล้ว (ดูรายการ SQL ที่เคยให้ไว้ก่อนหน้าในบทสนทนานี้)

### กรณี B — ย้ายข้อมูลจากระบบเดิม (มี dump/backup อยู่แล้ว)

`init.sql` จะรันเฉพาะตอน volume ว่างเปล่าเท่านั้น ถ้ามี dump ไฟล์เดิม (`backup.sql`) ให้ restore เข้าไปแทนหลังจาก container DB ขึ้นแล้ว (ข้าม `init.sql` ไปเลยโดยลบ mapping นั้นออกชั่วคราว หรือปล่อยให้รันแล้ว restore ทับอีกที):

```powershell
# 1) ทำให้ issuer-mysql ขึ้นก่อนเฉยๆ (ยังไม่ต้อง start api)
docker compose up -d issuer-mysql

# 2) รอ healthcheck ผ่าน (ดูสถานะ)
docker compose ps

# 3) restore dump เข้าไป
docker exec -i issuer-mysql mysql -uroot -p"<MYSQL_ROOT_PASSWORD ของคุณ>" issuer < backup.sql
```

**สำคัญ**: ถ้า `backup.sql` เดิมมีข้อมูลจริง (PII, VC ที่ออกจริง, password) ต้องดูแลไฟล์นั้นแยกต่างหากให้ปลอดภัย (ไม่ commit เข้า git, เก็บใน storage ที่ควบคุมสิทธิ์เข้าถึง) — ตรรกะเดียวกับที่แก้ `db/init.sql` ไปตาม C-06

---

## 5. Build image

```powershell
docker compose build api
```

ควรผ่านแล้ว (แก้ `Dockerfile` เป็น .NET 9 SDK/runtime ให้ตรงกับ `IssuerAPI.csproj` แล้ว — ก่อนหน้านี้ build ไม่ผ่านเพราะ pin ไว้ที่ .NET 8)

---

## 6. Start ทุก service

```powershell
docker compose up -d
```

`api` service จะรอ `issuer-mysql` ผ่าน healthcheck ก่อน (ตั้งไว้ใน `depends_on: condition: service_healthy`) ถึงจะ start เอง

**ตอน boot ครั้งแรก**: ถ้าตั้ง `ADMIN_BOOTSTRAP_USERNAME`/`ADMIN_BOOTSTRAP_PASSWORD` ไว้ใน `.env` แอปจะสร้างบัญชี staff/admin แรกให้อัตโนมัติ (แค่ตอนที่ตาราง `users` ยังว่างเปล่าเท่านั้น — boot รอบถัดไปจะข้ามขั้นตอนนี้ไปเฉยๆ) ใช้ username/password คู่นี้ login ที่ `/Account/Login` ได้เลย แนะนำให้ตั้งรหัสผ่านชั่วคราวไว้ก่อน แล้วไปเปลี่ยนทีหลัง (ตอนนี้ยังไม่มีหน้าเปลี่ยนรหัสผ่านในแอป ต้องเปลี่ยนผ่าน DB โดยตรงด้วย BCrypt hash ใหม่)

---

## 7. ตรวจสอบว่าใช้งานได้

```powershell
docker compose ps
docker compose logs -f api
```

เช็คว่า container ไม่ restart loop แล้วลองเรียก:

```powershell
curl http://localhost:5002/.well-known/openid-credential-issuer
```

ควรได้ JSON metadata กลับมา (ไม่ใช่ error หรือ `credential_configurations_supported` ว่างเปล่า)

---

## 8. เปิดใช้งานจากภายนอก (port 455)

`docker-compose.yml` map container port 8080 ไปที่ host port `5002` เท่านั้น — ถ้าจะให้เข้าถึงผ่าน `https://issuer.zenithcomp.co.th:455` ตามที่ตั้งไว้ใน `appsettings.json` (`ThaIDConfig:GatewayBaseUrl`) ต้องมี reverse proxy (IIS/nginx) ฟัง port 455 แบบ HTTPS แล้ว forward เข้า `http://localhost:5002` — ส่วนนี้แยกจาก docker-compose เอง เป็นการตั้งค่าฝั่ง host/reverse proxy (เชื่อมกับที่เคยเปิด Windows Firewall port 455 ไว้ก่อนหน้านี้)

---

## สรุปคำสั่งทั้งหมด (ไล่ตามลำดับ)

```powershell
git pull
docker network create lab-network          # ครั้งแรกครั้งเดียว
# แก้ .env ให้ครบก่อน
docker compose build api
docker compose up -d issuer-mysql
docker compose ps                          # รอ healthy
# (ถ้ามี backup เดิม) docker exec -i issuer-mysql mysql -uroot -p"..." issuer < backup.sql
docker compose up -d
docker compose logs -f api
```
