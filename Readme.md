# ติดตั้ง Docker + Restore Database จาก Dump20260826.sql (Issuer Service)

รองรับทั้ง Windows และ Linux — ใช้คู่กับ [`DOCKER-DEPLOYMENT-GUIDE.md`](./DOCKER-DEPLOYMENT-GUIDE.md) ข้อ 4 (Restore ข้อมูลเดิมเข้า MySQL server)

**บริบทสำคัญ**: deployment นี้ต่อ MySQL server ภายนอกโดยตรงผ่าน `CONNECTION_STRING` ใน `.env` — ไม่มี container `issuer-mysql` ให้ restore เข้าไปแล้ว (ตัดออกจาก `docker-compose.yml`/`docker-compose.lab.yml`) ดังนั้น "restore" ในเอกสารนี้คือ import `Dump20260826.sql` เข้า MySQL server จริงที่มีอยู่แล้ว ไม่ใช่เข้า container

---

## 0. เตรียมของก่อนเริ่ม

- ไฟล์ `Dump20260826.sql`
- ข้อมูลเชื่อมต่อ MySQL server ปลายทาง: host, port (ปกติ 3306), user, password, ชื่อฐานข้อมูล (`issuer`)
- สิทธิ์ `CREATE`/`DROP`/`INSERT` บนฐานข้อมูลนั้น (dump มักมี `DROP TABLE IF EXISTS` นำหน้าแต่ละตาราง)

---

## 1. ติดตั้ง Docker

ใช้ Docker เป็นตัวรัน MySQL client เท่านั้น (ไม่ได้รัน MySQL server เอง) — ถ้าเครื่องมี `mysql` client อยู่แล้วข้ามไปข้อ 3 ได้เลย

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

## 2. เตรียม MySQL client

**ถ้าเครื่องมี `mysql` client อยู่แล้ว** ข้ามไปข้อ 3 ได้เลย ใช้คำสั่ง `mysql` ตรงจากเครื่องได้ทันที ไม่ต้องพึ่ง Docker

**ถ้าไม่มี** ใช้ image `mysql:8.0` เป็น client ชั่วคราวแทนการติดตั้งลงเครื่องจริง (ทั้ง Windows และ Linux ใช้คำสั่งเดียวกัน เพราะรันผ่าน Docker):

```bash
docker run -it --rm mysql:8.0 mysql -h<host> -P3306 -uroot -p"<password>" issuer
```

ทดสอบ login สำเร็จแล้ว `exit;` ออกมาเพื่อไป restore จริงในข้อ 3

---

## 3. Restore `Dump20260826.sql` เข้า MySQL server

### วิธีที่ 1 — มี `mysql` client ในเครื่องอยู่แล้ว

**Windows (PowerShell)**

```powershell
cd C:\path\to\folder\ที่มี\Dump20260826.sql
Get-Content .\Dump20260826.sql | mysql -h<host> -P3306 -uroot -p"<password>" issuer
```

(ใช้ `Get-Content | mysql` แทน `<` ตรงๆ เพราะ PowerShell ตีความ `<` ต่างจาก cmd/bash)

**Linux/macOS (bash)**

```bash
cd /path/to/folder-with-dump
mysql -h<host> -P3306 -uroot -p"<password>" issuer < Dump20260826.sql
```

### วิธีที่ 2 — ไม่มี `mysql` client, ใช้ Docker แทน (Windows/Linux เหมือนกัน)

mount ไฟล์ dump เข้า container แล้ว pipe เข้า `mysql` client ข้างในนั้น:

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

---

## 4. ตรวจสอบหลัง restore

เช็คว่าตารางครบและแอปใช้งานได้จริง — schema ปัจจุบันที่แอปต้องการมี 7 ตาราง:

```sql
USE issuer;
SHOW TABLES;
```

ควรเห็นครบ: `dbissuedcredential`, `dbissuerlog`, `dbnonce`, `dbregister`, `dbrequest`, `dbusers`

ตรวจ row count คร่าวๆ ว่ามีข้อมูลจริง ไม่ใช่ตารางว่าง:

```sql
SELECT COUNT(*) FROM dbregister;
SELECT COUNT(*) FROM dbusers;
SELECT COUNT(*) FROM dbrequest;
```

---

## 5. ชี้แอปให้ต่อ DB ที่เพิ่ง restore

แก้ `CONNECTION_STRING` ใน `.env` (root ของโปรเจกต์) ให้ชี้ไปที่ host/port/user/password/database ที่ restore ไว้ในข้อ 3:

```
CONNECTION_STRING=server=<host>;port=3306;database=issuer;user=root;password=<password>;sslmode=None
```

จากนั้น build/start container ตามลำดับใน `DOCKER-DEPLOYMENT-GUIDE.md` ข้อ 5-7 (`docker compose build api` → `docker compose up -d` → เช็ค `curl http://localhost:5002/.well-known/openid-credential-issuer`)

---

## สรุปคำสั่งทั้งหมด (ไล่ตามลำดับ)

```bash
# 1. ติดตั้ง Docker (Windows: Docker Desktop / Linux: get.docker.com script) — ข้ามถ้ามีแล้ว

# 2. restore dump (เลือกวิธีที่มี mysql client หรือใช้ Docker เป็น client)
mysql -h<host> -P3306 -uroot -p"<password>" issuer < Dump20260826.sql

# 3. ตรวจตารางครบ 7 ตาราง โดยเฉพาะ dbpresentationrequest
mysql -h<host> -P3306 -uroot -p"<password>" -e "USE issuer; SHOW TABLES;"

# 4. แก้ .env -> CONNECTION_STRING ให้ชี้ไป host เดียวกัน

# 5. build + start (ดู DOCKER-DEPLOYMENT-GUIDE.md ข้อ 5-7)
docker compose build api
docker compose up -d
docker compose logs -f api
```
