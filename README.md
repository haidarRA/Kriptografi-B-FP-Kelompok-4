# Kriptografi-B-FP-Kelompok-4

FP Kriptografi B Kelompok 4

## Pembagian Tugas:

### 1. TLS Infrastructure & Certificate Management

_Person 1 – TLS & CA Setup (Haidar_5027231063)_

- Membuat Certificate Authority (CA) lokal (OpenSSL)
- Generate dan tanda tangani sertifikat server & client
- Menyiapkan direktori certs/ dan dokumen panduan sertifikat
- Testing validasi mutual TLS (handshake, kepercayaan, trust store)

### 2. Server Side Development

_Person 2 – TLS Chat Server (Fidel_5027231063)_

- Membuat server socket berbasis TLS (Python ssl + socket)
- Konfigurasi ssl.SSLContext dengan sertifikat server & verifikasi klien
- Menerima koneksi dari banyak klien (threading/asynchronous)
- Validasi identitas klien berdasarkan sertifikat

_Person 3 – Server-side Chat Logic (Furqon_5027231024)_

- Menangani broadcast pesan dari satu klien ke semua klien lain
- Manajemen daftar klien aktif
- Logging pesan yang masuk (optional)
- Sistem handling disconnect & error handling

### 3. Client Side Development

_Person 4 – TLS Chat Client (Radit_5027231033)_

- Mengimplementasikan koneksi TLS ke server menggunakan ssl
- Menyediakan sertifikat & kunci privat untuk autentikasi
- Implementasi pengiriman pesan

_Person 5 – Client UI (CLI/GUI) (Almendo_5027221073)_

- Membuat tampilan antarmuka (CLI: input/output; atau GUI sederhana dengan Tkinter)
- Antarmuka untuk mengirim dan menampilkan pesan secara real-time
- Menampilkan status koneksi, error, notifikasi

### 4. Asynchronous Communication

_Person 6 – Asynchronous I/O (Client & Server) (Marcel_5027231044)_

- Refactor komunikasi (client/server) agar tidak blocking
- Menggunakan threading, select, atau asyncio agar komunikasi real-time
- Sinkronisasi pengiriman & penerimaan pesan di sisi klien/server

### 5. Message Security & Identity Verification

_Person 7 – Sertifikat dan Validasi Identity (Maulana_5027231010)_

- Mengekstrak dan menampilkan identitas dari sertifikat digital klien (CN, O, OU)
- Menolak koneksi klien yang sertifikatnya tidak valid
- Menambahkan whitelist user (opsional)

_Person 8 – End-to-End Security Enhancements (Jo_5027231067)_

- Verifikasi fingerprint sertifikat
- Implementasi layer keamanan tambahan (opsional: message signature atau integrity check)
- Deteksi MITM basic

### 6. Testing, Deployment & Documentation

Person 9 – QA & DevOps (Farand_5027231084)

- Menulis unit test (e.g. unittest, pytest) untuk modul TLS & komunikasi
- Menyusun instruksi setup (README)
- Automasi testing TLS handshake & koneksi klien
- Menyiapkan script run (run_server.py, run_client.py)
- Deployment lokal dan skenario uji (3 klien, 1 server)

## TLS Chat Server

Implementasi chat server yang aman menggunakan TLS dengan fitur:

- Server socket berbasis TLS (Python ssl + socket)
- Konfigurasi SSL dengan sertifikat server & verifikasi klien
- Dukungan multi-klien menggunakan threading
- Validasi identitas klien berdasarkan sertifikat

### Persyaratan

- Python 3.7+
- pyOpenSSL

### Instalasi

1. Install dependensi:

```bash
pip install -r requirements.txt
```

2. Generate sertifikat:

```bash
python generate_certs.py
```

### Penggunaan

1. Jalankan server:

```bash
python server.py
```

2. Jalankan client (dalam terminal terpisah):

```bash
python client.py
```

Untuk menghubungkan ke server di host lain:

```bash
python client.py <host>
```

### Fitur

- Koneksi aman menggunakan TLS
- Verifikasi sertifikat dua arah (mutual TLS)
- Broadcast pesan ke semua klien
- Notifikasi ketika klien bergabung/meninggalkan chat
- Logging untuk monitoring server

### Struktur File

- `server.py` - Implementasi server TLS
- `client.py` - Implementasi client TLS
- `generate_certs.py` - Script untuk menghasilkan sertifikat
- `certs/` - Direktori untuk menyimpan sertifikat
  - `ca.crt` - Sertifikat Certificate Authority
  - `server.crt` - Sertifikat server
  - `server.key` - Private key server
  - `client.crt` - Sertifikat client
  - `client.key` - Private key client
- `fingerprint_tool` - Script untuk verifikasi fingerprint
- `server_fingerprint` - Fingerprint Server

## Dokumentasi

![whitelist](/img/7-whitelist-server.png)
![whitelist](/img/7-whitelist-client.png)
![tampilan-GUI](/img/tampilan-GUI.png)
![image](https://github.com/user-attachments/assets/bf5c9575-aa89-43d5-97fe-db9d22c4f039)
![image](https://github.com/user-attachments/assets/8bd3680f-a965-4a38-9d3d-d7ab75263001)
![image](https://github.com/user-attachments/assets/0f82ce90-b8d8-457d-ad85-075e2c32464f)
![image](https://github.com/user-attachments/assets/ea385d43-7966-4e12-9eac-6a1baf28eaa7)

![image](https://github.com/user-attachments/assets/b7ee3458-49ef-429d-8d1f-be452adca995)
