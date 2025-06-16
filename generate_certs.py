from OpenSSL import crypto
import os

# Global untuk unique serial numbers, dimulai dari 1001 (CA akan menggunakan 1000)
next_serial_number_val = 1001

def get_next_serial():
    global next_serial_number_val
    serial = next_serial_number_val
    next_serial_number_val += 1
    return serial

def create_certificate_authority():
    # Membuat direktori certs jika belum ada
    if not os.path.exists('certs'):
        os.makedirs('certs')

    # Cek apakah CA sudah ada, jika iya, tidak perlu buat ulang (opsional, bisa dihapus jika ingin selalu regenerate)
    ca_key_path = "certs/ca.key"
    ca_cert_path = "certs/ca.crt"
    if os.path.exists(ca_key_path) and os.path.exists(ca_cert_path):
        try:
            print("CA sudah ada, memuat dari file...")
            with open(ca_key_path, "rb") as f_key, open(ca_cert_path, "rb") as f_cert:
                ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f_key.read())
                ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f_cert.read())
            print("-> CA (ca.crt dan ca.key) dimuat.")
            return ca_key, ca_cert
        except Exception as e:
            print(f"Gagal memuat CA yang ada: {e}. Membuat CA baru.")
            # Hapus file yang mungkin rusak agar bisa dibuat ulang
            if os.path.exists(ca_key_path): os.remove(ca_key_path)
            if os.path.exists(ca_cert_path): os.remove(ca_cert_path)


    print("Membuat Certificate Authority (CA) baru...")
    # Membuat key CA
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    # Membuat sertifikat CA
    ca_cert = crypto.X509()
    ca_cert.get_subject().CN = "Chat CA"
    ca_cert.set_serial_number(1000) # Nomor seri tetap untuk CA
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10*365*24*60*60)  # Valid 10 tahun untuk CA
    ca_cert.set_issuer(ca_cert.get_subject()) # Self-signed
    ca_cert.set_pubkey(ca_key)
    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
        crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])
    # Untuk CA self-signed, authorityKeyIdentifier merujuk pada dirinya sendiri
    ca_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert)
    ])
    ca_cert.sign(ca_key, 'sha256')

    # Menyimpan CA key dan cert
    with open(ca_key_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
    with open(ca_cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
    print("-> CA (ca.crt dan ca.key) baru dibuat.")
    return ca_key, ca_cert

def create_certificate(name, ca_key, ca_cert, hostname="localhost", is_client_cert=False):
    # Cek apakah sertifikat sudah ada (opsional)
    key_path = f"certs/{name}.key"
    cert_path = f"certs/{name}.crt"
    # if os.path.exists(key_path) and os.path.exists(cert_path):
    #     print(f"Sertifikat untuk {name} sudah ada. Dilewati.")
    #     return

    # Membuat key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Membuat sertifikat
    cert = crypto.X509()
    cert.get_subject().CN = name
    
    # Menambahkan Subject Alternative Name (SAN)
    san_list_str = [f"DNS:{hostname}"]
    if hostname != "localhost": # Hindari duplikat DNS:localhost jika hostname adalah localhost
        san_list_str.append("DNS:localhost")
    san_list_str.append("IP:127.0.0.1")
    
    # Jika nama klien adalah nama DNS yang valid dan berbeda dari hostname, bisa ditambahkan juga
    # if is_client_cert and name != hostname and name != "localhost" and "." in name: # Cek sederhana untuk nama DNS
    #     san_list_str.append(f"DNS:{name}")

    san_extension = crypto.X509Extension(
        b"subjectAltName",
        critical=False, # SAN biasanya tidak kritis
        value=", ".join(san_list_str).encode()
    )
    
    # Ekstensi standar untuk sertifikat entitas (server/klien)
    extended_key_usage_val = b"serverAuth, clientAuth" if not is_client_cert else b"clientAuth"

    cert.add_extensions([
        san_extension,
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"), # Bukan CA
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
        crypto.X509Extension(b"extendedKeyUsage", False, extended_key_usage_val),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer:always", issuer=ca_cert)
    ])
    
    cert.set_serial_number(get_next_serial()) # Gunakan nomor seri unik
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Valid 1 tahun
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(ca_key, 'sha256')

    # Menyimpan key dan cert
    with open(key_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open(cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def main():
    ca_key, ca_cert = create_certificate_authority()
    print("") # Baris baru
    
    print("Membuat sertifikat untuk Server...")
    # Untuk server, hostname di SAN penting. 'localhost' adalah default umum.
    # Jika server Anda berjalan di, misal, 'chat.example.com', teruskan itu sebagai hostname.
    create_certificate("server", ca_key, ca_cert, hostname="localhost", is_client_cert=False)
    print("-> Server (server.crt dan server.key) dibuat/diperbarui.\n")
    
    client_names_from_whitelist = []
    whitelist_path = "whitelist.txt"

    if os.path.exists(whitelist_path):
        with open(whitelist_path, "r") as f:
            # Baca baris, hapus spasi ekstra, dan filter baris kosong atau komentar
            client_names_from_whitelist = [
                line.strip() for line in f 
                if line.strip() and not line.strip().startswith("#")
            ]
        
        if not client_names_from_whitelist:
            print(f"INFO: File '{whitelist_path}' ditemukan tapi kosong atau hanya berisi komentar.")
            print(f"      Tidak ada sertifikat klien yang akan dibuat dari whitelist.")
        else:
            print(f"Membaca daftar klien dari '{whitelist_path}' untuk pembuatan sertifikat...")
    else:
        print(f"PERINGATAN: File '{whitelist_path}' tidak ditemukan.")
        try:
            with open(whitelist_path, "w") as f_wl:
                f_wl.write("# Daftar nama klien yang diizinkan (satu per baris)\n")
                f_wl.write("# Baris yang diawali dengan # adalah komentar dan akan diabaikan.\n")
                f_wl.write("# Contoh:\n")
                f_wl.write("# client1\n")
                f_wl.write("# another_client\n")
            print(f"-> Contoh file '{whitelist_path}' telah dibuat untuk panduan.")
            print(f"   Harap isi '{whitelist_path}' dengan nama klien yang diinginkan dan jalankan skrip ini lagi untuk membuat sertifikat klien.")
        except IOError as e:
            print(f"ERROR: Tidak dapat membuat contoh '{whitelist_path}': {e}")
        # Jika whitelist baru dibuat, tidak ada klien untuk diproses pada run ini
        client_names_from_whitelist = []

    if client_names_from_whitelist:
        print("\nMembuat sertifikat untuk Klien (berdasarkan whitelist.txt)...")
        for client_name in client_names_from_whitelist:
            # Untuk sertifikat klien, CN adalah 'client_name'.
            # 'hostname' untuk SAN bisa 'localhost' atau spesifik jika klien mengekspos layanan.
            # Menggunakan 'localhost' untuk entri DNS SAN umumnya aman dan sederhana untuk sertifikat klien.
            create_certificate(client_name, ca_key, ca_cert, hostname="localhost", is_client_cert=True)
            print(f"-> Klien {client_name} ({client_name}.crt dan {client_name}.key) dibuat/diperbarui.")
        print("\nSertifikat klien selesai dibuat/diperbarui berdasarkan whitelist.")
    elif os.path.exists(whitelist_path): # Whitelist ada tapi kosong/hanya komentar
        print("Tidak ada nama klien valid di whitelist.txt, tidak ada sertifikat klien tambahan yang dibuat/diperbarui.")

    print("\nSelesai! Proses pembuatan sertifikat telah dijalankan.")
    certs_dir_abs = os.path.abspath('certs')
    print(f"Sertifikat disimpan di direktori '{certs_dir_abs}'.")
    if not os.path.exists(whitelist_path) or not client_names_from_whitelist:
         print(f"Harap periksa atau isi file '{os.path.abspath(whitelist_path)}' untuk mengelola sertifikat klien dan jalankan skrip ini lagi jika perlu.")

if __name__ == "__main__":
    main()