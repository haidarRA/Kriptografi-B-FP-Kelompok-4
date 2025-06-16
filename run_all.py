#!/usr/bin/env python
import subprocess
import os
import time

SERVER_SCRIPT = 'server.py'
CLIENT_SCRIPT = 'client.py'
SERVER_HOST = 'localhost'
SERVER_PORT = 8443

# Path ke direktori certs (asumsi skrip ini dijalankan dari root proyek)
CERTS_DIR = os.path.join(os.path.dirname(__file__), 'certs')
SERVER_CERT_PATH = os.path.join(CERTS_DIR, 'server.crt')

def get_server_fingerprint():
    """Mendapatkan fingerprint SHA-256 dari sertifikat server."""
    try:
        # Perintah openssl untuk mendapatkan fingerprint
        # Ini mungkin perlu disesuaikan tergantung pada OS dan instalasi openssl
        # Untuk Windows, Anda mungkin perlu path lengkap ke openssl.exe
        # atau pastikan openssl ada di PATH.
        # Contoh untuk Git Bash/Linux/macOS:
        # command = ['openssl', 'x509', '-noout', '-fingerprint', '-sha256', '-inform', 'pem', '-in', SERVER_CERT_PATH]
        # Untuk PowerShell di Windows, jika openssl diinstall via Chocolatey atau serupa:
        command = ['openssl', 'x509', '-noout', '-fingerprint', '-sha256', '-in', SERVER_CERT_PATH]
        
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        fingerprint_line = result.stdout.strip()
        # Outputnya biasanya: SHA256 Fingerprint=XX:YY:ZZ...
        fingerprint = fingerprint_line.split('=')[1].replace(':', '').lower()
        return fingerprint
    except FileNotFoundError:
        print(f"ERROR: openssl tidak ditemukan. Pastikan openssl terinstall dan ada di PATH.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Gagal mendapatkan fingerprint server: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return None
    except Exception as e:
        print(f"ERROR: Kesalahan tidak terduga saat mendapatkan fingerprint: {e}")
        return None

if __name__ == "__main__":
    server_fingerprint = get_server_fingerprint()
    if not server_fingerprint:
        print("Tidak dapat melanjutkan tanpa fingerprint server.")
        exit(1)

    print(f"Menggunakan fingerprint server: {server_fingerprint}")

    print("Menjalankan server...")
    # Untuk Windows, mungkin perlu 'python' atau 'py' secara eksplisit
    server_process = subprocess.Popen(['python', SERVER_SCRIPT])
    time.sleep(3)  # Beri waktu server untuk start

    print("Menjalankan client (client1)...")
    client1_process = subprocess.Popen([
        'python', CLIENT_SCRIPT, 
        '--cert', 'client1', 
        '--server_fingerprint', server_fingerprint
    ])

    print("Menjalankan client (client2)...")
    client2_process = subprocess.Popen([
        'python', CLIENT_SCRIPT, 
        '--cert', 'client2', 
        '--server_fingerprint', server_fingerprint
    ])

    print("Menjalankan client (client3)...")
    client3_process = subprocess.Popen([
        'python', CLIENT_SCRIPT, 
        '--cert', 'client3', 
        '--server_fingerprint', server_fingerprint
    ])

    print("\nSkrip run_all.py telah dijalankan.")
    print("Server dan 3 klien (CLI mode) seharusnya berjalan di terminal terpisah atau di background.")
    print("Tekan Ctrl+C di terminal ini TIDAK akan menghentikan server/klien secara otomatis.")
    print("Anda perlu menutupnya secara manual atau menghentikan prosesnya.")

    # Biarkan skrip ini berjalan agar proses anak tidak langsung mati jika ini adalah parent utama
    # Atau, kita bisa menunggu input untuk keluar
    try:
        input("Tekan Enter untuk mencoba menghentikan server dan klien (mungkin tidak selalu berhasil)...\n")
    except KeyboardInterrupt:
        print("Keluar...")
    finally:
        print("Mencoba menghentikan proses...")
        # Coba hentikan proses. Ini mungkin tidak selalu berhasil dengan baik.
        if server_process.poll() is None: server_process.terminate()
        if client1_process.poll() is None: client1_process.terminate()
        if client2_process.poll() is None: client2_process.terminate()
        if client3_process.poll() is None: client3_process.terminate()
        
        # Tunggu sebentar agar proses bisa berhenti
        time.sleep(2)
        
        if server_process.poll() is None: server_process.kill()
        if client1_process.poll() is None: client1_process.kill()
        if client2_process.poll() is None: client2_process.kill()
        if client3_process.poll() is None: client3_process.kill()
        print("Selesai.")
