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
- `fingerprint_tool` - Script untuk verifikasi fingerprint
- `server_fingerprint` - Fingerprint Server

## Dokumentasi

![whitelist](/img/7-whitelist-server.png)
![whitelist](/img/7-whitelist-client.png)
![tampilan-GUI](/img/tampilan-GUI.png)
![image](https://github.com/user-attachments/assets/bf5c9575-aa89-43d5-97fe-db9d22c4f039)
![image](https://github.com/user-attachments/assets/8bd3680f-a965-4a38-9d3d-d7ab75263001)
![image](https://github.com/user-attachments/assets/0f82ce90-b8d8-457d-ad85-075e2c32464f)
![image](https://github.com/user-attachments/assets/b7ee3458-49ef-429d-8d1f-be452adca995)



