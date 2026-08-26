# ขั้นตอนติดตั้งบน Docker + Restore DB (`Dump20260826.sql`)

> อ้างอิงจาก `docker-compose.yml`, `.env`, `db/init.sql` ปัจจุบันหลังแก้ C-06 (secret ทั้งหมดย้ายไป `.env`, schema เปล่า, Dockerfile เป็น .NET 9) — ดูภาพรวมเพิ่มเติมที่ `DOCKER-DEPLOYMENT-GUIDE.md`

---

## 0. เช็คให้ `.env` ครบก่อน

`.env` ต้องมีค่าจริงครบทุกตัวนี้ (ไม่ใช่ค่าว่าง) ก่อนเริ่ม:

| ตัวแปร | ใช้ทำอะไร |
|---|---|
| `CONNECTION_STRING` | ให้แอปต่อ MySQL |
| `MYSQL_ROOT_PASSWORD` | ให้ container `issuer-mysql` สร้าง root user ตอน boot ครั้งแรก |
| `Jwt__PrivateKey` | เซ็น access token |
| `ThaIDConfig__ClientID` / `ThaIDConfig__ClientSecret` | login ผ่าน ThaID |

---

## 1. วางไฟล์ dump

วาง `Dump20260826.sql` ไว้ที่ root โปรเจกต์ (ระดับเดียวกับ `docker-compose.yml`):

```
C:\project\ETDA\phase_III\bootcamp_issuer\Dump20260826.sql
```

ไฟล์นี้มีข้อมูลจริง (production-like) — **ห้าม commit เข้า git** ระวังอย่า `git add -A` ตอนที่ไฟล์นี้ยังอยู่ในโฟลเดอร์ ลบทิ้งหรือย้ายออกหลัง restore เสร็จก็ได้

---

## 2. สร้าง Docker network (ครั้งแรกครั้งเดียว)

```powershell
docker network create lab-network
```

ข้ามขั้นตอนนี้ได้ถ้าเคยสร้างไว้แล้ว (`docker network ls` เช็คได้)

---

## 3. Build image

```powershell
cd C:\project\ETDA\phase_III\bootcamp_issuer
docker compose build api
```

---

## 4. Start เฉพาะ MySQL ก่อน

```powershell
docker compose up -d issuer-mysql
docker compose ps
```

รอจน `issuer-mysql` ขึ้นสถานะ `healthy` (ประมาณ 30 วินาที) — ตอน boot ครั้งแรก `db/init.sql` จะรันอัตโนมัติสร้าง schema เปล่าให้ก่อน (รันแค่ครั้งเดียวตอน volume ว่างเปล่าเท่านั้น จะไม่รันซ้ำถ้ามีข้อมูลอยู่แล้ว)

---

## 5. Restore `Dump20260826.sql` เข้าไปทับ

Copy ไฟล์เข้า container ก่อนแล้วค่อย restore ข้างใน (เสถียรกว่าการ pipe ตรงๆ โดยเฉพาะไฟล์ dump ขนาดใหญ่):

```powershell
docker cp .\Dump20260826.sql issuer-mysql:/tmp/Dump20260826.sql
docker exec issuer-mysql sh -c "mysql -uroot -p'<MYSQL_ROOT_PASSWORD ของคุณ>' issuer < /tmp/Dump20260826.sql"
```

แทน `<MYSQL_ROOT_PASSWORD ของคุณ>` ด้วยค่าจริงจาก `.env` — dump ที่ export ด้วย `mysqldump` ปกติจะมี `DROP TABLE IF EXISTS` กำกับอยู่แล้ว จึงทับ schema เปล่าจากขั้นตอนที่ 4 ได้เลยโดยไม่ error

ลบไฟล์ dump ออกจาก container หลัง restore เสร็จ (ไม่จำเป็นต้องเก็บค้างไว้ข้างใน):

```powershell
docker exec issuer-mysql rm /tmp/Dump20260826.sql
```

---

## 6. Start ที่เหลือ (api)

```powershell
docker compose up -d
docker compose logs -f api
```

`api` จะรอ `issuer-mysql` healthy ก่อนถึง start เอง (ตั้งไว้ใน `depends_on: condition: service_healthy`)

---

## 7. ตรวจสอบว่าใช้งานได้

```powershell
docker compose ps
curl http://localhost:5002/.well-known/openid-credential-issuer
```

ควรได้ JSON metadata กลับมาปกติ (ไม่ error, `credential_configurations_supported` ไม่ว่างเปล่า) ลอง login ผ่านหน้าเว็บดูว่าข้อมูลเดิมจาก dump (user/request เก่า) ยังอยู่ครบ

---

## หมายเหตุ — schema เก่ากว่าปัจจุบันไหม

ถ้า `Dump20260826.sql` export มาจากฐานข้อมูลรุ่นเก่าที่ schema ยังไม่มีคอลัมน์ที่เพิ่มไปในเซสชันล่าสุด (เช่น `TxCodeHash`, `Address`, `DateOfIssuance`, `DateOfExpiry`, `TitleEn/FirstNameEn/LastNameEn` ในตาราง `dbrequest`, หรือตาราง `dbpresentationrequest`/`dbissuedcredential`/`dbnonce` ที่ไม่มีอยู่เลย) ต้องรัน `ALTER TABLE`/`CREATE TABLE` เพิ่มเติมหลัง restore เสร็จ ไม่งั้นฟีเจอร์ tx_code / OID4VP verifier / status list revocation จะ error เพราะหาคอลัมน์/ตารางไม่เจอ — ขอ SQL migration ชุดที่ตรงกับ schema ปัจจุบันได้ถ้าต้องการ

---

## สรุปคำสั่งทั้งหมด (ไล่ตามลำดับ)

```powershell
cd C:\project\ETDA\phase_III\bootcamp_issuer
docker network create lab-network              # ครั้งแรกครั้งเดียว
docker compose build api
docker compose up -d issuer-mysql
docker compose ps                               # รอ healthy
docker cp .\Dump20260826.sql issuer-mysql:/tmp/Dump20260826.sql
docker exec issuer-mysql sh -c "mysql -uroot -p'<MYSQL_ROOT_PASSWORD>' issuer < /tmp/Dump20260826.sql"
docker exec issuer-mysql rm /tmp/Dump20260826.sql
docker compose up -d
docker compose logs -f api
```
