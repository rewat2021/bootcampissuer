# คู่มือ Deploy บน Docker — Issuer Service 

เอกสารนี้รวมขั้นตอนติดตั้ง Docker (Windows/Linux) และ restore database จาก dump เข้าไว้ในที่เดียวแล้ว

---

## 0. เตรียมของก่อนเริ่ม

- มี MySQL server ที่ใช้งานได้อยู่แล้ว (ไม่ใช่ container ที่ compose สร้าง — ตัดออกไปแล้ว)
- ไฟล์ `.env` ที่ root โปรเจกต์ (อยู่คู่กับ `docker-compose.yml`) — **ต้องกรอกค่าจริงให้ครบก่อนเริ่ม** ไม่งั้น container start ได้แต่ endpoint หลักพัง

| ตัวแปร                                                  | มาจากไหน                                                                                                                                          |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CONNECTION_STRING`                                     | connection string MySQL server จริงที่มีอยู่แล้ว                                                                                                  |
| `Jwt__PrivateKey`                                       | generate เองด้วยคำสั่ง PowerShell ด้านล่าง (ข้อ 3)                                                                                                |
| `ThaIDConfig__ClientID`   | ClientID login ThaiD 
| `ThaIDConfig__ClientSecret`   | ClientSecret ThaiD
| `ASPNETCORE_ENVIRONMENT`                                | `Production`                                                                                                                                      |

---

## 1. ติดตั้ง Docker

ข้ามข้อนี้ได้ถ้าเครื่องมี Docker + Docker Compose (v2 ขึ้นไป) อยู่แล้ว

### Windows

1. ดาวน์โหลด Docker Desktop: https://www.docker.com/products/docker-desktop
2. ติดตั้งแบบ default (เปิดใช้ WSL2 backend ตามที่ตัวติดตั้งแนะนำ)
3. รีสตาร์ทเครื่องถ้าติดตั้งขอ
4. เปิด Docker Desktop รอจนสถานะเป็น "Engine running"
5. ตรวจสอบใน PowerShell:

```powershell
docker --version
docker compose version
```

### Linux (Ubuntu/Debian)

```bash
# ลบเวอร์ชันเก่าถ้ามี
sudo apt-get remove docker docker-engine docker.io containerd runc

# ติดตั้งผ่าน convenience script (ใช้ได้ทั้ง Ubuntu/Debian)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# ให้ user ปัจจุบันรัน docker ได้โดยไม่ต้อง sudo (ต้อง logout/login ใหม่ 1 ครั้ง)
sudo usermod -aG docker $USER

# ตรวจสอบ
docker --version
docker compose version
```

---

## 2. Clone / pull โค้ดล่าสุด

```powershell
git pull
```

---

## 3. สร้าง Docker network (ถ้ายังไม่มี)

```powershell
docker network create lab-network
```

---

## 4. Restore ข้อมูลเดิมเข้า MySQL server

**บริบท**: deployment นี้ต่อ MySQL server ภายนอกโดยตรงผ่าน `CONNECTION_STRING` ใน `.env` — ไม่มี container `issuer-mysql` ให้ restore เข้าไปแล้ว ดังนั้น "restore" คือ import dump เข้า MySQL server จริงที่มีอยู่แล้ว ไม่ใช่เข้า container

เตรียมของ: ไฟล์ dump (เช่น `Dump20260826.sql`), host/port/user/password ของ MySQL server ปลายทาง, สิทธิ์ `CREATE`/`DROP`/`INSERT` บนฐานข้อมูล `issuer`

### 4.1 เตรียม MySQL client

ถ้าเครื่องมี `mysql` client อยู่แล้ว ข้ามไป 5.2 ได้เลย ใช้คำสั่ง `mysql` ตรงจากเครื่องได้ทันที

ถ้าไม่มี ใช้ image `mysql:8.0` เป็น client ชั่วคราวแทน (Windows/Linux ใช้คำสั่งเดียวกันเพราะรันผ่าน Docker):

```bash
docker run -it --rm mysql:8.0 mysql -h<host> -P3306 -uroot -p"<password>" issuer
```

ทดสอบ login สำเร็จแล้ว `exit;` ออกมาเพื่อไป restore จริง

### 4.2 Restore dump

**มี `mysql` client ในเครื่อง — Windows (PowerShell)**

```powershell
cd C:\path\to\folder\ที่มีไฟล์ dump
Get-Content .\Dump20260826.sql | mysql -h<host> -P3306 -uroot -p"<password>" issuer
```

(ใช้ `Get-Content | mysql` แทน `<` ตรงๆ เพราะ PowerShell ตีความ `<` ต่างจาก cmd/bash)

**มี `mysql` client ในเครื่อง — Linux/macOS (bash)**

```bash
cd /path/to/folder-with-dump
mysql -h<host> -P3306 -uroot -p"<password>" issuer < Dump20260826.sql
```

**ไม่มี `mysql` client — ใช้ Docker แทน (Windows/Linux เหมือนกัน)**

```bash
docker run -it --rm -v "$(pwd)/Dump20260826.sql:/tmp/dump.sql" mysql:8.0 \
  sh -c 'mysql -h<host> -P3306 -uroot -p"<password>" issuer < /tmp/dump.sql'
```

PowerShell (แทน `$(pwd)` ด้วย `${PWD}`):

```powershell
docker run -it --rm -v "${PWD}/Dump20260826.sql:/tmp/dump.sql" mysql:8.0 `
  sh -c 'mysql -h<host> -P3306 -uroot -p"<password>" issuer < /tmp/dump.sql'
```

ไม่มี error พิมพ์ออกมาแปลว่า import ผ่าน (dump มี `DROP TABLE IF EXISTS` นำหน้าทุกตาราง ดังนั้นรันซ้ำได้แต่จะเขียนทับข้อมูลเดิมในตารางที่ชนกัน)

### 4.3 ตรวจสอบหลัง restore

```sql
USE issuer;
SHOW TABLES;
```

schema ปัจจุบันที่แอปต้องการมี 7 ตาราง ควรเห็นครบ: `dbissuedcredential`, `dbissuerlog`, `dbnonce`, `dbpresentationrequest`, `dbregister`, `dbrequest`, `dbusers`

ตรวจ row count คร่าวๆ ว่ามีข้อมูลจริง ไม่ใช่ตารางว่าง:

```sql
SELECT COUNT(*) FROM dbregister;
SELECT COUNT(*) FROM dbusers;
SELECT COUNT(*) FROM dbrequest;
```

### 4.4 กรณี deploy ใหม่ ไม่มี dump ให้ restore

รัน `db/init.sql` เองครั้งเดียวเพื่อสร้าง schema เปล่า (ไม่มี container คอยรันให้อัตโนมัติอีกต่อไปเพราะตัด `issuer-mysql` ออกแล้ว ไม่มี seed data ตาม C-06):

```powershell
mysql -h<host> -P3306 -uroot -p"<password>" < db\init.sql
```

ไฟล์นี้ schema สอดคล้องกับ dump ปัจจุบันอยู่แล้วรวม `dbpresentationrequest` ด้วย ไม่ต้องเทียบเองอีก

### 4.5 ชี้แอปให้ต่อ DB ที่เพิ่ง restore

แก้ `CONNECTION_STRING` ใน `.env` ให้ชี้ไปที่ host/port/user/password/database ที่ restore ไว้ข้างต้น:

```
CONNECTION_STRING=server=<host>;port=3306;database=issuer;user=root;password=<password>;sslmode=None
```

---

## 5. Build image

```powershell
docker compose build api
```

---

## 6. Start

```powershell
docker compose up -d
docker compose logs -f api
```

**ตอน boot ครั้งแรก**: ถ้าตั้ง `ADMIN_BOOTSTRAP_USERNAME`/`ADMIN_BOOTSTRAP_PASSWORD` ไว้ใน `.env` และตาราง `users` ยังว่างเปล่า แอปจะสร้างบัญชี staff/admin แรกให้อัตโนมัติ ใช้ login ที่ `/Account/Login` ได้เลย

---

## 7. ตรวจสอบว่าใช้งานได้

```powershell
docker compose ps
docker compose logs -f api
curl http://localhost:5002/.well-known/openid-credential-issuer
```

ควรได้ JSON metadata กลับมา (ไม่ใช่ error หรือ `credential_configurations_supported` ว่างเปล่า)

---

## สรุปคำสั่งทั้งหมด (ไล่ตามลำดับ)

```powershell
# 1. ติดตั้ง Docker (ข้ามถ้ามีแล้ว) — Windows: Docker Desktop / Linux: get.docker.com script

# 2. clone/pull
git pull
docker network create lab-network          # ครั้งแรกครั้งเดียว
# แก้ .env ให้ครบก่อน (CONNECTION_STRING, Jwt__PrivateKey, ThaIDConfig, ADMIN_BOOTSTRAP_*)

# 3. restore dump (ถ้ามี) หรือรัน db/init.sql (ถ้า deploy ใหม่)
mysql -h<host> -P3306 -uroot -p"<password>" issuer < Dump20260826.sql
mysql -h<host> -P3306 -uroot -p"<password>" -e "USE issuer; SHOW TABLES;"   # ตรวจครบ 7 ตาราง

# 4. build + start
docker compose build api
docker compose up -d
docker compose logs -f api
```
