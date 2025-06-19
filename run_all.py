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
        print(f"✅ Server fingerprint obtained: {fingerprint[:16]}...")
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

def check_security_dependencies():
    """Check if security dependencies are available"""
    try:
        import cryptography
        print("✅ Security dependencies available")
        return True
    except ImportError:
        print("⚠️ Security dependencies missing. Install with: pip install cryptography")
        print("   Application will run with basic security features only.")
        return False

if __name__ == "__main__":
    print("🚀 Starting TLS Chat Application with Enhanced Security")
    print("=" * 60)
    
    # Check security dependencies
    security_available = check_security_dependencies()
    
    # Get server fingerprint for MITM detection
    server_fingerprint = get_server_fingerprint()
    if not server_fingerprint:
        print("⚠️ Continuing without MITM detection (fingerprint unavailable)")
        server_fingerprint = ""

    print(f"🔐 Security Mode: {'Enhanced' if security_available else 'Basic'}")
    print(f"🔍 MITM Detection: {'Enabled' if server_fingerprint else 'Disabled'}")
    print("=" * 60)

    print("🖥️ Starting server...")
    # Untuk Windows, mungkin perlu 'python' atau 'py' secara eksplisit
    server_process = subprocess.Popen(['python', SERVER_SCRIPT])
    time.sleep(3)  # Beri waktu server untuk start

    clients = []
    client_names = ['client1', 'client2', 'client3']
    
    for client_name in client_names:
        print(f"👤 Starting client ({client_name})...")
        
        # Build client command with security features
        client_cmd = ['python', CLIENT_SCRIPT, '--cert', client_name]
        if server_fingerprint:
            client_cmd.extend(['--server_fingerprint', server_fingerprint])
        
        client_process = subprocess.Popen(client_cmd)
        clients.append(client_process)
        time.sleep(1)  # Stagger client starts

    print("\n✅ All components started successfully!")
    print("=" * 60)
    print("🔐 TLS Chat Application is now running with:")
    print(f"   • Server: {SERVER_HOST}:{SERVER_PORT}")
    print(f"   • Clients: {len(clients)} active")
    print(f"   • Security: {'Enhanced (Message Signing + MITM Detection)' if security_available else 'Basic (TLS only)'}")
    print(f"   • MITM Detection: {'Enabled' if server_fingerprint else 'Disabled'}")
    print("=" * 60)
    print("📋 Controls:")
    print("   • Each client has its own GUI window")
    print("   • Server logs are displayed in this terminal")
    print("   • Press Enter to shutdown all components")
    print("   • Or close individual client windows")

    # Biarkan skrip ini berjalan agar proses anak tidak langsung mati jika ini adalah parent utama
    # Atau, kita bisa menunggu input untuk keluar
    try:
        input("\n⏸️ Press Enter to shutdown server and all clients...\n")
    except KeyboardInterrupt:
        print("\n🛑 Ctrl+C detected. Shutting down...")
    finally:
        print("🔄 Attempting to stop all processes...")
        
        # Stop all clients first
        for i, client_process in enumerate(clients):
            if client_process.poll() is None:
                print(f"   Stopping client {i+1}...")
                client_process.terminate()
        
        # Stop server
        if server_process.poll() is None:
            print("   Stopping server...")
            server_process.terminate()
        
        # Wait for graceful shutdown
        time.sleep(2)
        
        # Force kill if still running
        for client_process in clients:
            if client_process.poll() is None:
                client_process.kill()
        
        if server_process.poll() is None:
            server_process.kill()
            
        print("✅ All processes terminated.")
        print("🔒 TLS Chat Application shutdown complete.")