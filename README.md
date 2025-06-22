# Kriptografi-B-FP-Kelompok-4

## TLS Chat Infrastructure & Certificate Management

## Anggota

| Nama                     | NRP          |
| ------------------------ | ------------ |
| Maulana Ahmad Zahiri     | `5027231010` |
| Furqon Aryadana          | `5027231024` |
| Haidar Rafi Aqyla        | `5027231029` |
| Raditya Hardian Santoso  | `5027231033` |
| Dionisius Marcel         | `5027231044` |
| Danendra Fidel Khansa    | `5027231063` |
| Johanes Edward Nathanael | `5027231067` |
| Almendo Kambu            | `5027221073` |
| Farand Febriansyah       | `5027231084` |

## Pembagian Tugas

### _1. TLS Infrastructure & Certificate Management_

_Haidar (5027231029) – TLS & CA Setup_

- Membuat Certificate Authority (CA) lokal (OpenSSL)
- Generate dan tanda tangani sertifikat server & client
- Menyiapkan direktori certs/ dan dokumen panduan sertifikat
- Testing validasi mutual TLS (handshake, kepercayaan, trust store)

### _2. Server Side Development_

_Fidel (5027231063) – TLS Chat Server_

- Membuat server socket berbasis TLS (Python ssl + socket)
- Konfigurasi ssl.SSLContext dengan sertifikat server & verifikasi klien
- Menerima koneksi dari banyak klien (threading/asynchronous)
- Validasi identitas klien berdasarkan sertifikat

_Furqon (5027231024) – Server-side Chat Logic_

- Menangani broadcast pesan dari satu klien ke semua klien lain
- Manajemen daftar klien aktif
- Logging pesan yang masuk (optional)
- Sistem handling disconnect & error handling

### _3. Client Side Development_

_Radit (5027231033) – TLS Chat Client_

- Mengimplementasikan koneksi TLS ke server menggunakan ssl
- Menyediakan sertifikat & kunci privat untuk autentikasi
- Implementasi pengiriman pesan

_Almendo (5027221073) – Client UI (CLI/GUI)_

- Membuat tampilan antarmuka (CLI: input/output; atau GUI sederhana dengan Tkinter)
- Antarmuka untuk mengirim dan menampilkan pesan secara real-time
- Menampilkan status koneksi, error, notifikasi

### _4. Asynchronous Communication_

_Marcel (5027231044) – Asynchronous I/O (Client & Server)_

- Refactor komunikasi (client/server) agar tidak blocking
- Menggunakan threading, select, atau asyncio agar komunikasi real-time
- Sinkronisasi pengiriman & penerimaan pesan di sisi klien/server

### _5. Message Security & Identity Verification_

_Maulana (5027231010) – Sertifikat dan Validasi Identity_

- Mengekstrak dan menampilkan identitas dari sertifikat digital klien (CN, O, OU)
- Menolak koneksi klien yang sertifikatnya tidak valid
- Menambahkan whitelist user (opsional)

_Jo (5027231067) – End-to-End Security Enhancements_

- Verifikasi fingerprint sertifikat
- Implementasi layer keamanan tambahan (opsional: message signature atau integrity check)
- Deteksi MITM basic

### _6. Testing, Deployment & Documentation_

_Farand (5027231084) – QA & DevOps_

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
- Whitelist pengguna berbasis sertifikat
- Fingerprint server verification (MITM mitigation)
- Automasi skenario uji dengan skrip `run_all.py`

### Dasar Program TLS Chat

TLS Chat Server ini merupakan aplikasi komunikasi berbasis teks yang mengimplementasikan protokol **Transport Layer Security (TLS)** untuk memastikan **kerahasiaan (confidentiality)**, **keaslian (authenticity)**, dan **integritas (integrity)** data antara server dan klien.

TLS bekerja di atas TCP dan menyediakan saluran komunikasi yang aman menggunakan:

- **Enkripsi simetris** untuk menyandikan pesan.
- **Enkripsi asimetris** (RSA/ECDSA) untuk otentikasi dan negosiasi kunci.
- **Hashing** untuk menjamin integritas data.

Setiap klien wajib memiliki **sertifikat digital** yang ditandatangani oleh otoritas sertifikat (**CA**) internal untuk dapat bergabung ke server.

#### Penambahan Fitur Kompleks untuk Program TLS Chat:

- **Mutual TLS Authentication**: Setiap koneksi antara klien dan server menggunakan mutual TLS authentication, sehingga baik server maupun klien harus membuktikan identitasnya menggunakan sertifikat digital yang valid. Hal ini mencegah klien tidak sah dan server palsu.
- **Kontrol Akses Dinamis**: Server dapat menambah/menghapus pengguna secara dinamis melalui command `/add-user` dan `/delete-user`, yang secara otomatis memperbarui whitelist dan sertifikat digital tanpa perlu restart server.
- **Manajemen Grup dan Pesan Pribadi**: Sistem mendukung pembuatan grup chat, pesan grup, dan pesan pribadi (private message) dengan command khusus, serta sinkronisasi status anggota secara real-time.
- **Digital Signature & Message Integrity**: Setiap pesan yang dikirimkan oleh klien dapat ditandatangani secara digital menggunakan private key milik klien. Server akan memverifikasi tanda tangan digital ini menggunakan public key dari sertifikat klien. Dengan demikian, keaslian dan integritas pesan dapat dipastikan, serta mencegah pemalsuan pesan oleh pihak lain.
- **Log Aktivitas dan Audit**: Semua aktivitas penting (login, logout, pembuatan grup, penghapusan user, error, dsb) dicatat dalam log file, sehingga dapat dilakukan audit keamanan dan troubleshooting.

### Teori Dasar Kriptografi yang Mendukung

Sistem ini memanfaatkan prinsip-prinsip dasar dalam kriptografi sebagai berikut:

1. **Kriptografi Simetris**

   - Digunakan untuk mengenkripsi seluruh komunikasi setelah sesi TLS berhasil dibentuk.
   - Algoritma seperti AES digunakan untuk menjaga efisiensi dan kecepatan.

2. **Kriptografi Asimetris (RSA)**

   - Digunakan saat proses handshake TLS untuk autentikasi dan pertukaran kunci.
   - Setiap entitas memiliki _public key_ dan _private key_ yang digunakan untuk enkripsi dan tanda tangan digital.

3. **Sertifikat Digital & PKI (Public Key Infrastructure)**

   - Sertifikat digunakan untuk menjamin identitas entitas.
   - CA (Certificate Authority) menjadi entitas tepercaya yang menandatangani sertifikat server dan klien.

4. **TLS Handshake**

   - Proses negosiasi antara klien dan server yang mencakup:

     - Verifikasi sertifikat.
     - Negosiasi algoritma enkripsi.
     - Pertukaran kunci (Diffie-Hellman atau RSA).
     - Autentikasi dua arah (mutual authentication).

5. **Hash Function (SHA-256)**

   - Digunakan untuk menghasilkan fingerprint sertifikat.
   - Fingerprint memungkinkan klien memverifikasi bahwa sertifikat server tidak dimodifikasi (mitigasi MITM).

6. **Whitelist Berbasis Sertifikat**

   - Server hanya mengizinkan klien yang Common Name (CN)-nya terdapat dalam daftar whitelist.
   - Menambah lapisan kontrol akses dan pencegahan penyusup.

7. **Digital Signature (Tanda Tangan Digital)**

   - Setiap pesan yang dikirim klien dapat ditandatangani secara digital menggunakan private key milik klien. Server akan memverifikasi tanda tangan ini untuk memastikan keaslian dan integritas pesan.
   - Tanda tangan digital mencegah pemalsuan pesan dan memastikan pesan benar-benar dikirim oleh pemilik sertifikat.

8. **Man-in-the-Middle (MITM) Detection**

   - Klien dapat memverifikasi fingerprint sertifikat server sebelum membangun koneksi, sehingga dapat mendeteksi jika ada pihak ketiga yang mencoba menyisipkan diri di antara komunikasi (MITM attack).

9. **Asynchronous Communication**

   - Komunikasi antara server dan klien diimplementasikan secara asynchronous (menggunakan threading dan thread pool), sehingga setiap pesan dapat diproses secara real-time tanpa blocking.

10. **Certificate Revocation (Penghapusan Sertifikat)**
    - Server dapat menghapus pengguna dari whitelist dan menghapus sertifikat digitalnya secara otomatis, sehingga akses dapat dicabut secara instan.

### Kriptografi dan Algoritma yang Digunakan

TLS Chat ini menggunakan elemen-elemen kriptografi berikut:

1. **Asymmetric Cryptography (RSA)**

   - Digunakan untuk autentikasi awal dan pertukaran kunci.
   - Setiap entitas (server dan klien) memiliki **keypair**: `private key` dan `public key` yang terdapat dalam sertifikat digital.

2. **Digital Certificate**

   - File `.crt` dan `.key` disiapkan untuk masing-masing entitas.
   - Sertifikat ini memuat informasi identitas (CN) dan digunakan untuk **verifikasi mutual** antara server dan klien.

3. **TLS Handshake**

   - Proses awal saat koneksi dibangun, mencakup:

     - Verifikasi identitas dengan sertifikat.
     - Negosiasi cipher suite.
     - Pertukaran kunci simetris.
     - Pembuatan session key untuk komunikasi terenkripsi.

4. **Server Fingerprint Verification**

   - SHA-256 fingerprint dari sertifikat server digunakan untuk menghindari serangan **Man-In-The-Middle (MITM)**.
   - Klien dapat memverifikasi bahwa sertifikat server benar sesuai fingerprint.

5. **Whitelist Filtering**

   - Server hanya menerima klien yang Common Name (CN) sertifikatnya tercantum dalam `whitelist.txt`.
   - Ini menambah **kontrol akses berbasis identitas digital**.

6. **Digital Signature (RSA-PSS + SHA-256)**

   - Pesan dapat ditandatangani menggunakan algoritma RSA-PSS dengan hash SHA-256. Signature ini diverifikasi oleh server untuk memastikan pesan tidak diubah dan benar-benar berasal dari pengirim yang sah.

7. **Hashing untuk Integrity Check**

   - Setiap pesan yang ditandatangani juga disertai hash SHA-256 dari isi pesan, sehingga integritas pesan dapat diverifikasi secara independen.

8. **Certificate Management Automation**

   - Penambahan dan penghapusan user secara otomatis akan memicu pembuatan atau penghapusan sertifikat digital melalui skrip Python, sehingga manajemen identitas lebih aman dan efisien.

9. **Thread Pool Executor**

   - Untuk efisiensi pengiriman pesan broadcast, server menggunakan thread pool executor agar pengiriman ke banyak klien tetap responsif dan tidak bottleneck.

10. **Log Aktivitas dan Audit**
    - Semua aktivitas penting (login, logout, pembuatan grup, penghapusan user, error, dsb) dicatat dalam log file, sehingga dapat dilakukan audit keamanan dan troubleshooting.

### Persyaratan

- Python 3.7+
- OpenSSL (dapat dijalankan dari terminal)
- Tkinter (GUI klien)

### Struktur Direktori

```
Kriptografi-B-FP-Kelompok-4/
├── certs/                    # Sertifikat dan kunci
│   ├── ca.crt, ca.key
│   ├── server.crt, server.key
│   ├── client1.crt, client1.key
│   ├── client2.crt, client2.key
│   ├── client3.crt, client3.key
│   └── client_invalid.*      # Sertifikat testing tidak valid (opsional)
├── client.py                 # Skrip klien
├── server.py                 # Skrip server
├── generate_certs.py         # Generator sertifikat
├── run_all.py                # Jalankan server & 3 klien otomatis
├── whitelist.txt             # Daftar CN yang diizinkan (whitelist)
├── test_chat.py              # Unit test
├── requirements.txt          # Dependensi (opsional)
├── *.log                     # Log aktivitas
└── README.md                 # Dokumentasi
```

### Instalasi

1. Install dependensi:

```bash
pip install -r requirements.txt
```

2. Generate sertifikat:

```bash
python generate_certs.py
```

### Penggunaan Manual

#### Jalankan Server Secara Manual

```bash
python server.py
```

- Server akan berjalan di `localhost:8443`.
- Server akan menunggu koneksi dari klien.
- Hanya klien dengan sertifikat yang valid dan berada dalam whitelist yang bisa masuk.

#### Jalankan Klien Secara Manual

```bash
python client.py --cert client1
```

- `--cert client1` menunjukkan sertifikat dan private key klien yang digunakan (client1.crt dan client1.key).
- `--server_fingerprint` adalah fingerprint SHA-256 dari sertifikat server.
- Jika fingerprint tidak diberikan, verifikasi fingerprint akan dilewati (kurang aman).

### Penggunaan Otomatis dengan Skrip `run_all.py`

Skrip ini memudahkan proses demo/testing dengan cara:

1. Otomatis membaca **fingerprint SHA-256** dari `server.crt` menggunakan `openssl`.
2. Menjalankan **server** TLS (`server.py`).
3. Menjalankan **tiga klien** (client1, client2, client3) dengan sertifikat masing-masing.
4. Memberikan fingerprint server ke semua klien untuk verifikasi.

#### Jalankan Skrip:

```bash
python run_all.py
```

#### Setelah dijalankan:

- Server dan klien akan berjalan di background.
- Setiap klien akan langsung terhubung ke server menggunakan TLS.
- Semua komunikasi akan dienkripsi dan diverifikasi.
- Kamu bisa mengetik pesan dari masing-masing klien untuk melihat broadcast antar pengguna.
- Di akhir, terminal akan menampilkan prompt: `Tekan Enter untuk mencoba menghentikan server dan klien...`

  - Tekan Enter agar skrip mencoba menghentikan semua proses.

> **Catatan**: Jika proses tidak berhenti otomatis, kamu bisa menutup terminal secara manual atau menghentikan proses dari task manager.

### Konfigurasi Whitelist

Isi `whitelist.txt` dengan Common Name (CN) dari sertifikat klien yang diperbolehkan:

```
client1
client2
client3
```

### Unit Testing

Unit test tersedia di `test_chat.py` atau `tests/tests_tls.py`. Untuk menjalankannya:

```bash
pytest tests/tests_tls.py
```

Untuk membuat sertifikat tidak valid (optional, untuk pengujian penolakan koneksi):

```bash
openssl genrsa -out certs/client_invalid.key 2048
openssl req -new -key certs/client_invalid.key -out certs/client_invalid.csr -subj "/CN=invalid_client"
openssl x509 -req -days 365 -in certs/client_invalid.csr -signkey certs/client_invalid.key -out certs/client_invalid.crt
```

### Command yang dapat digunakan dalam chat

Berikut adalah daftar perintah (command) yang dapat digunakan pada aplikasi chat (GUI/CLI):

- **/help**
  - Menampilkan daftar semua perintah yang tersedia beserta penjelasannya.
- **/list**
  - Melihat daftar pengguna yang sedang online di server.
- **/time**
  - Melihat waktu server saat ini.
- **/history**
  - Melihat 10 pesan terakhir yang ada di server.
- **/quit**
  - Keluar dari chat dan memutuskan koneksi dengan server.
- **/pm <user> <pesan>**
  - Mengirim pesan pribadi (private message) ke pengguna tertentu.
  - Contoh: `/pm client2 Halo, apa kabar?`
- **/ghelp**
  - Menampilkan bantuan khusus untuk perintah grup chat.
- **/creategroup <nama_grup> <user1> <user2> ...**
  - Membuat grup chat baru dengan nama tertentu dan anggota yang dipilih.
  - Contoh: `/creategroup kelompok1 client1 client2`
- **/gmsg <nama_grup> <pesan>**
  - Mengirim pesan ke grup tertentu.
  - Contoh: `/gmsg kelompok1 Halo semua!`
- **/joingroup <nama_grup>**
  - Bergabung ke grup chat yang sudah ada.
  - Contoh: `/joingroup kelompok1`
- **/leavegroup <nama_grup>**
  - Keluar dari grup chat tertentu.
  - Contoh: `/leavegroup kelompok1`
- **/listgroups**
  - Melihat daftar semua grup chat yang aktif beserta anggotanya.
- **/add-user <nama_baru>**
  - Menambah pengguna baru ke whitelist dan otomatis membuatkan sertifikatnya.
  - Contoh: `/add-user client4`
- **/delete-user <nama_user>**
  - Menghapus pengguna dari whitelist dan menghapus sertifikatnya.
  - Contoh: `/delete-user client3`

> **Catatan:**
>
> - Semua perintah diawali dengan tanda `/` (slash).
> - Untuk perintah yang membutuhkan parameter (seperti nama user atau grup), pastikan penulisannya benar.
> - Fitur-fitur seperti grup chat, private message, dan manajemen user hanya dapat digunakan jika Anda memiliki hak akses yang sesuai dan user/grup yang dimaksud memang ada.

### Troubleshooting

- `openssl tidak ditemukan`: Pastikan sudah terinstall dan berada di PATH.
- `CERTIFICATE_VERIFY_FAILED`: Cek apakah ca.crt sesuai, dan CN ada dalam whitelist.
- GUI error: Pastikan Tkinter tersedia di Python.
- Klien tidak konek: Cek apakah `server.py` sedang aktif.
- Fingerprint mismatch: Pastikan fingerprint server yang digunakan sama dengan yang dimiliki klien.

### Dokumentasi & Tampilan dari Uji Coba Fiturnya

- Menyalakan Server
  ![whitelist](/img/7-whitelist-server.png)
- Masuk menjadi Klien
  ![whitelist](/img/7-whitelist-client.png)
- Tampilan GUI
  ![tampilan-GUI](/img/tampilan-GUI.png)
- Chat Komunal
  ![tampilan-GUI](/img/chatkomunal.png)
- Personal Message
  ![tampilan-GUI](/img/personalmessage.png)
- Add User dan Cert
  ![tampilan-GUI](/img/adduserdancert.png)
  ![tampilan-GUI](/img/adduserdancert2.png)
- Delete User dan Cert
  ![tampilan-GUI](/img/deleteuserdancert.png)
  ![tampilan-GUI](/img/deleteuserdancert2.png)
- Create Group
  ![tampilan-GUI](/img/creategroup.png)
- List Anggota Group
  ![tampilan-GUI](/img/listgroup.png)
- Group Chat
  ![tampilan-GUI](/img/groupchat.png)
- Log Chat Client
  ![tampilan-GUI](/img/logchatclient.png)
- Join Group
  ![tampilan-GUI](/img/joingroup.png)
- List Anggota Group After Join
  ![tampilan-GUI](/img/listgroupafterjoin.png)

---

Dengan skrip `run_all.py`, proses simulasi server dan 3 klien dapat dijalankan sekaligus secara otomatis, mendemonstrasikan implementasi sistem chat berbasis TLS secara lengkap dan efisien.
