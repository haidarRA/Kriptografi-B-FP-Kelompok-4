from OpenSSL import crypto
import os

def create_certificate_authority():
    # Membuat direktori certs jika belum ada
    if not os.path.exists('certs'):
        os.makedirs('certs')

    # Membuat key CA
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    # Membuat sertifikat CA
    ca_cert = crypto.X509()
    ca_cert.get_subject().CN = "Chat CA"
    ca_cert.set_serial_number(1000)
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(365*24*60*60)  # Valid 1 tahun
    ca_cert.set_issuer(ca_cert.get_subject())
    ca_cert.set_pubkey(ca_key)
    ca_cert.sign(ca_key, 'sha256')

    # Menyimpan CA key dan cert
    with open("certs/ca.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
    with open("certs/ca.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))

    return ca_key, ca_cert

def create_certificate(name, ca_key, ca_cert, hostname="localhost"):
    # Membuat key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Membuat sertifikat
    cert = crypto.X509()
    cert.get_subject().CN = name
    
    # Menambahkan Subject Alternative Name
    san_list = [
        f"DNS:{hostname}",
        "DNS:localhost",
        "IP:127.0.0.1"
    ]
    san_extension = crypto.X509Extension(
        b"subjectAltName",
        False,
        ", ".join(san_list).encode()
    )
    cert.add_extensions([san_extension])
    
    cert.set_serial_number(1001)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Valid 1 tahun
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(ca_key, 'sha256')

    # Menyimpan key dan cert
    with open(f"certs/{name}.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open(f"certs/{name}.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def main():
    print("Membuat Certificate Authority (CA)...")
    ca_key, ca_cert = create_certificate_authority()
    print("-> CA (ca.crt) dibuat.\n")
    
    print("Membuat sertifikat untuk Server...")
    create_certificate("server", ca_key, ca_cert)
    print("-> Server (server.crt) dibuat.\n")
    
    # Membuat sertifikat untuk beberapa client
    client_names = ["client1", "client2", "client3"]
    print("Membuat sertifikat untuk Klien...")
    for client_name in client_names:
        create_certificate(client_name, ca_key, ca_cert)
        print(f"-> Klien {client_name} ({client_name}.crt) dibuat.")
    print("\nSelesai! Semua sertifikat telah dibuat di direktori 'certs'.")
    
    # Membuat whitelist.txt dengan daftar client yang diizinkan
    with open("whitelist.txt", "w") as f:
        for client_name in client_names:
            f.write(f"{client_name}\n")
    print("-> whitelist.txt telah dibuat dengan daftar client yang diizinkan.")

if __name__ == "__main__":
    main()