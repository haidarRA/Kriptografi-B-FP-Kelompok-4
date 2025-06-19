# Kriptografi-B-FP-Kelompok-4


## TLS Chat Server

Implementasi chat server yang aman menggunakan TLS dengan fitur:

* Server socket berbasis TLS (Python ssl + socket)
* Konfigurasi SSL dengan sertifikat server & verifikasi klien
* Dukungan multi-klien menggunakan threading
* Validasi identitas klien berdasarkan sertifikat
* Whitelist pengguna berbasis sertifikat
* Fingerprint server verification (MITM mitigation)
* Automasi skenario uji dengan skrip `run_all.py`

### Persyaratan

* Python 3.7+
* OpenSSL (dapat dijalankan dari terminal)
* Tkinter (GUI klien)

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

* Server akan berjalan di `localhost:8443`.
* Server akan menunggu koneksi dari klien.
* Hanya klien dengan sertifikat yang valid dan berada dalam whitelist yang bisa masuk.

#### Jalankan Klien Secara Manual

```bash
python client.py --cert client1
```

* `--cert client1` menunjukkan sertifikat dan private key klien yang digunakan (client1.crt dan client1.key).
* `--server_fingerprint` adalah fingerprint SHA-256 dari sertifikat server.
* Jika fingerprint tidak diberikan, verifikasi fingerprint akan dilewati (kurang aman).

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

* Server dan klien akan berjalan di background.
* Setiap klien akan langsung terhubung ke server menggunakan TLS.
* Semua komunikasi akan dienkripsi dan diverifikasi.
* Kamu bisa mengetik pesan dari masing-masing klien untuk melihat broadcast antar pengguna.
* Di akhir, terminal akan menampilkan prompt: `Tekan Enter untuk mencoba menghentikan server dan klien...`

  * Tekan Enter agar skrip mencoba menghentikan semua proses.

> **Catatan**: Jika proses tidak berhenti otomatis, kamu bisa menutup terminal secara manual atau menghentikan proses dari task manager.

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

### Troubleshooting

* `openssl tidak ditemukan`: Pastikan sudah terinstall dan berada di PATH.
* `CERTIFICATE_VERIFY_FAILED`: Cek apakah ca.crt sesuai, dan CN ada dalam whitelist.
* GUI error: Pastikan Tkinter tersedia di Python.
* Klien tidak konek: Cek apakah `server.py` sedang aktif.
* Fingerprint mismatch: Pastikan fingerprint server yang digunakan sama dengan yang dimiliki klien.

### Dokumentasi & Tampilan

![whitelist](/img/7-whitelist-server.png)
![whitelist](/img/7-whitelist-client.png)
![tampilan-GUI](/img/tampilan-GUI.png)

---

Dengan skrip `run_all.py`, proses simulasi server dan 3 klien dapat dijalankan sekaligus secara otomatis, mendemonstrasikan implementasi sistem chat berbasis TLS secara lengkap dan efisien.
