import unittest
import subprocess
import time
import os
import ssl
import socket
import threading
import queue # Ditambahkan import queue
from client import TLSChatClient # Asumsi client.py ada di direktori yang sama atau di PYTHONPATH
from server import EnhancedTLSChatServer # Asumsi server.py ada di direktori yang sama

# Konfigurasi dasar
SERVER_HOST = 'localhost'
SERVER_PORT = 8444 # Gunakan port berbeda untuk testing agar tidak konflik
CERTS_DIR = 'certs' # Sesuaikan jika perlu
CA_CERT = os.path.join(CERTS_DIR, 'ca.crt')
SERVER_CERT = os.path.join(CERTS_DIR, 'server.crt')
SERVER_KEY = os.path.join(CERTS_DIR, 'server.key')
CLIENT1_CERT = os.path.join(CERTS_DIR, 'client1.crt')
CLIENT1_KEY = os.path.join(CERTS_DIR, 'client1.key')
CLIENT_INVALID_CERT = os.path.join(CERTS_DIR, 'client_invalid.crt') # Anda perlu membuat sertifikat ini
CLIENT_INVALID_KEY = os.path.join(CERTS_DIR, 'client_invalid.key') # dan key nya, yang tidak ditandatangani oleh CA Anda
WHITELIST_FILE = 'test_whitelist.txt'

# Helper untuk mendapatkan fingerprint (sama seperti di run_all.py, idealnya di-refactor ke modul utilitas)
def get_cert_fingerprint(cert_path):
    try:
        command = ['openssl', 'x509', '-noout', '-fingerprint', '-sha256', '-in', cert_path]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        fingerprint_line = result.stdout.strip()
        fingerprint = fingerprint_line.split('=')[1].replace(':', '').lower()
        return fingerprint
    except Exception as e:
        print(f"Gagal mendapatkan fingerprint untuk {cert_path}: {e}")
        return None

class TestChatFunctionality(unittest.TestCase):
    server_process = None
    server_thread = None
    chat_server = None
    server_fingerprint = None

    @classmethod
    def setUpClass(cls):
        # Buat file whitelist untuk testing
        with open(WHITELIST_FILE, 'w') as f:
            f.write("client1\n") # Hanya client1 yang diizinkan
            f.write("testuser\n")

        # Dapatkan fingerprint server
        cls.server_fingerprint = get_cert_fingerprint(SERVER_CERT)
        if not cls.server_fingerprint:
            raise Exception("Tidak dapat mendapatkan fingerprint server untuk testing.")

        # Jalankan server di thread terpisah
        cls.chat_server = EnhancedTLSChatServer(host=SERVER_HOST, port=SERVER_PORT)
        cls.chat_server.whitelist_file = WHITELIST_FILE # Gunakan whitelist test
        cls.chat_server.whitelist = cls.chat_server.load_whitelist() # Muat ulang whitelist
        
        cls.server_thread = threading.Thread(target=cls.chat_server.start)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1) # Beri waktu server untuk siap

    @classmethod
    def tearDownClass(cls):
        if cls.chat_server:
            cls.chat_server.stop() # Anda perlu menambahkan method stop() di EnhancedTLSChatServer
        if cls.server_thread and cls.server_thread.is_alive():
            cls.server_thread.join(timeout=1)
        if os.path.exists(WHITELIST_FILE):
            os.remove(WHITELIST_FILE)

    def setUp(self):
        # Klien akan diinisialisasi per test method jika perlu
        self.client = None

    def tearDown(self):
        if self.client and self.client.connected:
            self.client.send_message("/quit")
            time.sleep(0.5) # Beri waktu pesan quit diproses
            self.client.cleanup()

    def test_01_server_runs(self):
        # Cek apakah server listening
        try:
            s = socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=1)
            s.close()
            self.assertTrue(True, "Server berhasil berjalan dan menerima koneksi.")
        except Exception as e:
            self.fail(f"Server tidak berjalan atau tidak menerima koneksi: {e}")

    def test_02_successful_client_connection_whitelisted(self):
        self.client = TLSChatClient(host=SERVER_HOST, port=SERVER_PORT, 
                                    expected_server_fingerprint=self.server_fingerprint)
        # Setup sertifikat client secara manual untuk instance ini
        self.client.ssl_context.load_cert_chain(certfile=CLIENT1_CERT, keyfile=CLIENT1_KEY)
        
        self.client.connect() # connect() sekarang non-blocking untuk thread, tapi kita tunggu di sini
        # Perlu cara untuk menunggu koneksi berhasil atau gagal dalam test
        time.sleep(1) # Tunggu koneksi
        self.assertTrue(self.client.connected, "Klien (client1) gagal terhubung padahal ada di whitelist.")
        self.assertEqual(self.client.client_id, "client1", "Client ID tidak sesuai setelah koneksi.")

    def test_03_client_rejected_not_in_whitelist(self):
        # Asumsi client2.crt memiliki CN 'client2' yang tidak ada di test_whitelist.txt
        CLIENT2_CERT = os.path.join(CERTS_DIR, 'client2.crt')
        CLIENT2_KEY = os.path.join(CERTS_DIR, 'client2.key')
        
        self.client = TLSChatClient(host=SERVER_HOST, port=SERVER_PORT, 
                                    expected_server_fingerprint=self.server_fingerprint)
        self.client.ssl_context.load_cert_chain(certfile=CLIENT2_CERT, keyfile=CLIENT2_KEY)
        
        self.client.connect()
        time.sleep(1) # Tunggu proses koneksi
        self.assertFalse(self.client.connected, "Klien (client2) berhasil terhubung padahal tidak ada di whitelist.")

    def test_04_client_rejected_invalid_certificate(self):
        # Ini menguji penolakan oleh server karena sertifikat client tidak ditandatangani oleh CA server
        # Anda perlu membuat client_invalid.crt dan client_invalid.key yang tidak valid
        # Jika file tidak ada, skip test ini
        if not (os.path.exists(CLIENT_INVALID_CERT) and os.path.exists(CLIENT_INVALID_KEY)):
            self.skipTest("Sertifikat klien tidak valid (client_invalid.crt/key) tidak ditemukan. Skipping test.")

        self.client = TLSChatClient(host=SERVER_HOST, port=SERVER_PORT, 
                                    expected_server_fingerprint=self.server_fingerprint)
        try:
            self.client.ssl_context.load_cert_chain(certfile=CLIENT_INVALID_CERT, keyfile=CLIENT_INVALID_KEY)
            self.client.connect()
            time.sleep(1)
            # Koneksi SSL handshake harusnya gagal sebelum sampai ke logika aplikasi whitelist
            self.assertFalse(self.client.connected, "Klien dengan sertifikat tidak valid berhasil terhubung.")
        except ssl.SSLError as e:
            self.assertIn("certificate verify failed", str(e).lower(), "SSL handshake tidak gagal dengan error verifikasi sertifikat yang diharapkan.")
        except Exception as e:
            # Jika error lain, mungkin ada masalah setup
            self.fail(f"Koneksi dengan sertifikat tidak valid gagal dengan error tak terduga: {e}")

    def test_05_client_rejected_wrong_server_fingerprint(self):
        wrong_fingerprint = "a" * 64 # Fingerprint salah yang panjangnya sama
        self.client = TLSChatClient(host=SERVER_HOST, port=SERVER_PORT, 
                                    expected_server_fingerprint=wrong_fingerprint)
        self.client.ssl_context.load_cert_chain(certfile=CLIENT1_CERT, keyfile=CLIENT1_KEY)
        
        self.client.connect()
        time.sleep(1)
        self.assertFalse(self.client.connected, "Klien berhasil terhubung meskipun fingerprint server salah.")
        # Anda mungkin perlu memeriksa log klien untuk pesan error spesifik MITM

    def test_06_send_receive_message(self):
        self.client = TLSChatClient(host=SERVER_HOST, port=SERVER_PORT, 
                                    expected_server_fingerprint=self.server_fingerprint)
        self.client.ssl_context.load_cert_chain(certfile=CLIENT1_CERT, keyfile=CLIENT1_KEY)
        self.client.connect()
        time.sleep(1)
        self.assertTrue(self.client.connected, "Klien gagal terhubung untuk tes kirim/terima pesan.")

        test_message = "Hello from test_06_send_receive_message"
        self.client.send_message(test_message)
        
        # Beri waktu pesan untuk diterima dan diproses oleh server, lalu dibroadcast kembali
        # Ini adalah bagian yang tricky dalam testing async. Idealnya, client.py punya cara
        # untuk mendapatkan pesan yang diterima secara sinkron untuk testing.
        time.sleep(1) 
        
        # Cek message_queue client. Ini butuh client.message_queue bisa diakses
        # atau metode helper di client untuk mendapatkan pesan terakhir.
        received_message = None
        try:
            # Kita mengharapkan server memformatnya sebagai "client1: pesan"
            # dan juga pesan join "📢 client1 telah bergabung ke chat"
            # Kita cari pesan spesifik kita
            while not self.client.message_queue.empty():
                msg_in_queue = self.client.message_queue.get_nowait()
                if test_message in msg_in_queue and f"{self.client.client_id}:" in msg_in_queue:
                    received_message = msg_in_queue
                    break
        except queue.Empty:
            pass
        
        self.assertIsNotNone(received_message, "Klien tidak menerima kembali pesannya.")
        self.assertIn(test_message, received_message, "Pesan yang diterima tidak sesuai.")

# Perlu menambahkan metode start() dan stop() ke EnhancedTLSChatServer
# Contoh implementasi (tambahkan ke server.py):
"""
    def start(self):
        # Metode ini akan menjalankan accept_connections di loop utama server
        # Mirip dengan apa yang ada di if __name__ == "__main__": di server.py
        logger.info(f"Test Server memulai di {self.host}:{self.port}")
        self.server_socket.settimeout(1.0) # Agar bisa diinterupsi
        self.running = True
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                wrapped_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                
                # Handle client connection in a new thread
                thread = threading.Thread(target=self.handle_client, args=(wrapped_socket, client_address))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue # Kembali cek self.running
            except Exception as e:
                if self.running:
                    logger.error(f"Error saat accept koneksi: {e}")
                break # Keluar loop jika ada error lain saat running
        logger.info("Test Server berhenti.")

    def stop(self):
        logger.info("Menghentikan Test Server...")
        self.running = False
        # Menutup socket server akan menyebabkan accept() gagal, membantu keluar dari loop
        if self.server_socket:
            self.server_socket.close()
        # Menutup koneksi klien yang aktif
        with self.clients_lock:
            for client_id, client_socket in list(self.clients.items()): # list() untuk copy
                try:
                    client_socket.shutdown(socket.SHUT_RDWR)
                    client_socket.close()
                except Exception as e:
                    logger.warning(f"Error saat menutup socket klien {client_id}: {e}")
            self.clients.clear()
            self.client_names.clear()
"""

if __name__ == '__main__':
    print("Pastikan Anda telah membuat sertifikat client_invalid.crt dan client_invalid.key yang TIDAK ditandatangani oleh CA Anda untuk menjalankan semua tes.")
    print("Contoh membuat sertifikat self-signed (tidak valid untuk CA kita):")
    print("  openssl genrsa -out certs/client_invalid.key 2048")
    print("  openssl req -new -key certs/client_invalid.key -out certs/client_invalid.csr -subj \"/CN=invalid_client/O=Test/OU=TestUnit\"")
    print("  openssl x509 -req -days 365 -in certs/client_invalid.csr -signkey certs/client_invalid.key -out certs/client_invalid.crt")
    print("\nMenjalankan unit tests...")
    unittest.main()
