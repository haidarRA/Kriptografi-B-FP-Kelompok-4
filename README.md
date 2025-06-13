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
