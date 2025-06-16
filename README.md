# Kriptografi-B-FP-Kelompok-4

FP Kriptografi B Kelompok 4

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

## Dokumentasi

![whitelist](/img/7-whitelist-server.png)
![whitelist](/img/7-whitelist-client.png)
![tampilan-GUI](/img/tampilan-GUI.png)

### Setup Proyek Chat Terenkripsi TLS

Proyek ini mengimplementasikan sebuah sistem chat client-server sederhana dengan enkripsi TLS, validasi sertifikat, dan fitur keamanan tambahan.

#### Prasyarat

1.  **Python**: Versi 3.7 atau lebih tinggi.
2.  **OpenSSL**: Diperlukan untuk membuat sertifikat dan mendapatkan fingerprint. Pastikan `openssl` terinstall dan dapat diakses dari command line/terminal Anda.
    - Untuk Windows, Anda bisa menginstall OpenSSL dari [slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html) atau melalui package manager seperti Chocolatey (`choco install openssl`). Pastikan direktori `bin` dari instalasi OpenSSL ditambahkan ke PATH environment variable.
    - Untuk Linux (Debian/Ubuntu): `sudo apt-get update && sudo apt-get install openssl`
    - Untuk macOS (menggunakan Homebrew): `brew install openssl`
3.  **Modul Python**: Tidak ada modul eksternal selain yang ada di library standar Python yang diperlukan untuk fungsionalitas inti. Tkinter (biasanya disertakan dengan Python) diperlukan untuk GUI klien.

#### Struktur Direktori

```
Kriptografi-B-FP-Kelompok-4/
├── certs/                    # Direktori untuk menyimpan sertifikat dan kunci
│   ├── ca.crt
│   ├── ca.key
│   ├── server.crt
│   ├── server.key
│   ├── client1.crt
│   ├── client1.key
│   ├── client2.crt
│   ├── client2.key
│   ├── ... (sertifikat klien lainnya)
│   └── client_invalid.crt    # (Opsional, untuk testing - sertifikat tidak valid)
│   └── client_invalid.key    # (Opsional, untuk testing)
├── client.py                 # Skrip utama untuk klien chat
├── server.py                 # Skrip utama untuk server chat
├── generate_certs.py         # Skrip untuk membantu generate CA dan sertifikat (jika ada)
├── run_all.py                # Skrip untuk menjalankan server dan beberapa klien (untuk demo/testing)
├── test_chat.py              # Skrip unit test
├── requirements.txt          # (Jika ada dependensi eksternal di masa depan)
├── whitelist.txt             # Daftar Common Name (CN) klien yang diizinkan
├── chat_server.log           # Log output dari server
├── client.log                # Log output dari klien
└── README.md                 # File ini
```

#### 1. Pembuatan Sertifikat

Sistem ini memerlukan Certificate Authority (CA) dan sertifikat yang ditandatangani oleh CA tersebut untuk server dan setiap klien.

1.  **Buat Direktori `certs`**: Jika belum ada, buat direktori `certs` di root proyek.

2.  **Generate CA (Certificate Authority)**:

    ```bash
    openssl genrsa -out certs/ca.key 2048
    openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt -subj "/CN=MyChatAppCA/O=MyOrg/OU=SecurityDept"
    ```

    _(Anda akan diminta mengisi beberapa informasi untuk CA. Sesuaikan `subj` jika perlu.)_

3.  **Generate Sertifikat Server**:

    - Buat Key dan CSR (Certificate Signing Request) untuk Server:
      ```bash
      openssl genrsa -out certs/server.key 2048
      openssl req -new -key certs/server.key -out certs/server.csr -subj "/CN=localhost/O=MyOrgServer/OU=ChatServers"
      ```
      _(Ganti `CN=localhost` dengan hostname atau IP server jika akan diakses dari mesin lain. Untuk pengembangan lokal, `localhost` sudah cukup.)_
    - Tandatangani CSR Server dengan CA:
      ```bash
      openssl x509 -req -days 365 -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt
      ```

4.  **Generate Sertifikat Klien (ulangi untuk setiap klien)**:
    Misalnya untuk `client1`:

    - Buat Key dan CSR untuk Klien:
      ```bash
      openssl genrsa -out certs/client1.key 2048
      openssl req -new -key certs/client1.key -out certs/client1.csr -subj "/CN=client1/O=MyOrgClient/OU=ChatUsers"
      ```
      _(PENTING: `CN` (Common Name) di sini akan digunakan sebagai username klien dan untuk whitelist. Pastikan unik untuk setiap klien, contoh: `client1`, `client2`, `user_A`, dll.)_
    - Tandatangani CSR Klien dengan CA:
      `bash
    openssl x509 -req -days 365 -in certs/client1.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/client1.crt
    `
      Ulangi langkah ini untuk `client2`, `client3`, dst., dengan mengganti nama file dan `CN` yang sesuai (misal, `certs/client2.key`, `certs/client2.csr`, `certs/client2.crt`, dan `/CN=client2`).

    _Catatan: File `.csr` dan `.srl` (serial number) bisa dihapus setelah sertifikat (`.crt`) berhasil dibuat, namun tidak masalah jika tetap ada._

#### 2. Konfigurasi Whitelist

Buat file `whitelist.txt` di direktori root proyek. Isi file ini dengan Common Name (CN) dari sertifikat klien yang diizinkan untuk terhubung, satu CN per baris. Contoh:

```
client1
client2
user_A
```

Komentar bisa ditambahkan dengan menggunakan `#` di awal baris.

#### 3. Menjalankan Server

Buka terminal atau command prompt, navigasi ke direktori root proyek, dan jalankan:

```bash
python server.py
```

Server akan mulai berjalan dan mendengarkan koneksi di `0.0.0.0:8443` (default). Log akan ditampilkan di konsol dan juga disimpan di `chat_server.log`.

#### 4. Menjalankan Klien

Setiap klien memerlukan sertifikat dan kunci yang sesuai.

- **Mode GUI (Default)**:
  Buka terminal baru untuk setiap klien, navigasi ke direktori root, dan jalankan:

  ```bash
  # Untuk client1
  python client.py --cert client1

  # Untuk client2 (di terminal lain)
  python client.py --cert client2
  ```

  Ganti `client1` atau `client2` dengan nama file sertifikat klien yang sesuai (tanpa ekstensi `.crt` atau `.key`).
  Klien akan mencoba terhubung ke `localhost:8443` secara default.

- **Mode CLI (Command Line Interface)**:
  Tambahkan flag `--cli`:

  ```bash
  python client.py --cert client1 --cli
  ```

- **Opsi Tambahan Klien**:

  - `--host <hostname>`: Menentukan host server (default: `localhost`).
  - `--port <port_number>`: Menentukan port server (default: `8443`).
  - `--server_fingerprint <SHA256_fingerprint>`: (Opsional) Menentukan fingerprint SHA256 yang diharapkan dari sertifikat server untuk verifikasi tambahan (certificate pinning).

  Untuk mendapatkan fingerprint server (SHA256, format hex tanpa titik dua):

  ```bash
  openssl x509 -noout -fingerprint -sha256 -in certs/server.crt
  ```

  Salin bagian setelah `SHA256 Fingerprint=` dan hapus semua karakter `:`. Contoh: `A1B2C3...`

#### 5. Menjalankan Skenario Uji (Server dan Beberapa Klien)

Skrip `run_all.py` disediakan untuk memudahkan menjalankan server dan tiga klien (`client1`, `client2`, `client3`) secara otomatis dalam mode CLI. Skrip ini juga akan mencoba mendapatkan fingerprint server dan meneruskannya ke klien.

```bash
python run_all.py
```

Ini akan menjalankan proses di background atau di terminal yang sama (tergantung OS dan konfigurasi). Anda mungkin perlu menutupnya secara manual.

#### 6. Menjalankan Unit Tests

Unit test ditulis menggunakan modul `unittest` Python dan berada di `test_chat.py`.

1.  **Sertifikat Klien Tidak Valid (untuk testing)**:
    Beberapa tes memerlukan sertifikat klien yang _tidak_ ditandatangani oleh CA Anda untuk memverifikasi penolakan koneksi. Buat sertifikat self-signed atau sertifikat yang ditandatangani oleh CA lain dan letakkan sebagai `certs/client_invalid.crt` dan `certs/client_invalid.key`. Contoh perintah untuk membuat sertifikat self-signed (yang akan dianggap tidak valid oleh server kita):

    ```bash
    openssl genrsa -out certs/client_invalid.key 2048
    openssl req -new -key certs/client_invalid.key -out certs/client_invalid.csr -subj "/CN=invalid_client/O=Test/OU=TestUnit"
    openssl x509 -req -days 365 -in certs/client_invalid.csr -signkey certs/client_invalid.key -out certs/client_invalid.crt
    ```

2.  **Menjalankan Tes**:
    Navigasi ke direktori root proyek dan jalankan:
    ```bash
    python test_chat.py
    ```
    Tes akan dijalankan, dan hasilnya akan ditampilkan di konsol.

#### Fitur Utama

- Komunikasi terenkripsi TLS 1.2/1.3.
- Verifikasi sertifikat dua arah (klien memverifikasi server, server memverifikasi klien).
- Whitelist pengguna berdasarkan Common Name (CN) di sertifikat klien.
- Ekstraksi dan logging detail sertifikat (CN, O, OU).
- Verifikasi fingerprint sertifikat server di sisi klien (opsional, untuk mitigasi MITM).
- Komunikasi non-blocking menggunakan threading.
- Antarmuka pengguna grafis (GUI) dan mode baris perintah (CLI) untuk klien.
- Logging aktivitas server dan klien.
- Unit tests untuk fungsionalitas inti.
- Skrip untuk automasi menjalankan beberapa instance.

#### Troubleshooting

- **Error `[SSL: CERTIFICATE_VERIFY_FAILED]`**: Ini biasanya berarti sertifikat yang diterima tidak dapat diverifikasi terhadap CA yang dipercaya.
  - Pastikan `ca.crt` yang digunakan oleh klien sama dengan yang menandatangani `server.crt`.
  - Pastikan `ca.crt` yang digunakan oleh server sama dengan yang menandatangani sertifikat klien.
  - Pastikan Common Name (CN) di sertifikat server cocok dengan hostname yang coba dihubungi klien (jika `check_hostname=True`, meskipun saat ini `False` di kode).
  - Pastikan sertifikat belum kedaluwarsa.
- **Koneksi Ditolak (Connection Refused)**: Pastikan server sudah berjalan dan mendengarkan di host dan port yang benar.
- **Klien Ditolak dari Whitelist**: Pastikan CN di sertifikat klien (misal, `client1`) ada di file `whitelist.txt`.
- **`openssl` tidak ditemukan**: Pastikan OpenSSL terinstall dan path ke executable-nya ada di environment variable `PATH` sistem Anda.
- **Masalah GUI Tkinter**: Jika ada error terkait Tkinter, pastikan modul `tkinter` terinstall dengan benar bersama instalasi Python Anda (biasanya sudah termasuk, tapi bisa jadi tidak pada instalasi minimal).

---
