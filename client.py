import ssl
import socket
import threading
import logging
import sys
import os
import time # Ditambahkan untuk mengatasi error linting
from datetime import datetime
from typing import Optional
import queue # Ditambahkan
from concurrent.futures import ThreadPoolExecutor, Executor # Ditambahkan

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('client.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class TLSChatClient:
    def __init__(self, host: str = 'localhost', port: int = 8443):
        self.host = host
        self.port = port
        self.connected = False
        self.client_id = None
        self.cert_info = None
        
        # Antrian untuk pesan keluar, untuk sinkronisasi pengiriman
        self.send_queue = queue.Queue() # Ditambahkan
        # Executor untuk mengirim pesan dari antrian secara asynchronous
        self.send_executor: Executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='ClientSender') # Ditambahkan
        
        # Konfigurasi SSL Context
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.check_hostname = False
        
        # Load sertifikat
        try:
            self.ssl_context.load_verify_locations('certs/ca.crt')
            self.ssl_context.load_cert_chain(
                certfile='certs/client.crt',
                keyfile='certs/client.key'
            )
        except Exception as e:
            logger.error(f"Error loading sertifikat: {e}")
            sys.exit(1)
        
        # Membuat socket client
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_socket = None

    def verify_server_certificate(self) -> bool:
        """Verifikasi sertifikat server"""
        try:
            cert = self.ssl_socket.getpeercert()
            if not cert:
                logger.error("Server tidak memiliki sertifikat yang valid")
                return False
                
            # Verifikasi fingerprint
            fingerprint = self.ssl_socket.getpeercert(binary_form=True)
            if not fingerprint:
                logger.error("Tidak dapat mendapatkan fingerprint sertifikat server")
                return False
                
            logger.info("Sertifikat server valid")
            return True
        except Exception as e:
            logger.error(f"Error verifikasi sertifikat: {e}")
            return False

    def get_certificate_info(self) -> Optional[dict]:
        """Mendapatkan informasi sertifikat client"""
        try:
            cert = self.ssl_socket.getpeercert()
            if not cert:
                return None
                
            return {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'version': cert['version'],
                'notBefore': cert['notBefore'],
                'notAfter': cert['notAfter']
            }
        except Exception as e:
            logger.error(f"Error mendapatkan info sertifikat: {e}")
            return None

    def connect(self):
        try:
            # Wrap socket dengan SSL
            self.ssl_socket = self.ssl_context.wrap_socket(
                self.socket,
                server_hostname=self.host
            )
            
            # Koneksi ke server
            self.ssl_socket.connect((self.host, self.port))
            
            # Verifikasi sertifikat server
            if not self.verify_server_certificate():
                raise Exception("Verifikasi sertifikat server gagal")
            
            # Dapatkan info sertifikat
            self.cert_info = self.get_certificate_info()
            if self.cert_info:
                self.client_id = self.cert_info['subject'].get('commonName', 'unknown')
            
            self.connected = True
            logger.info(f"Terhubung ke server sebagai {self.client_id}")
            
            # Tampilkan status koneksi
            self.print_connection_status()
            
            # Memulai thread untuk menerima pesan
            receive_thread = threading.Thread(target=self.receive_messages, name="ClientReceiveThread")
            receive_thread.daemon = True
            receive_thread.start()
            
            # Memulai thread untuk mengirim pesan dari antrian
            send_processor_thread = threading.Thread(target=self.process_send_queue, name="ClientSendProcessorThread")
            send_processor_thread.daemon = True
            send_processor_thread.start()
            
            # Loop utama untuk input pengguna
            self.message_loop()
                
        except Exception as e:
            logger.error(f"Error koneksi: {e}")
        finally:
            self.cleanup()

    def print_connection_status(self):
        """Menampilkan status koneksi dan info sertifikat"""
        print("\n" + "="*50)
        print(f"Status Koneksi: {'Terhubung' if self.connected else 'Terputus'}")
        print(f"Server: {self.host}:{self.port}")
        print(f"Client ID: {self.client_id}")
        if self.cert_info:
            print("\nInfo Sertifikat:")
            print(f"  Subject: {self.cert_info['subject']}")
            print(f"  Valid dari: {self.cert_info['notBefore']}")
            print(f"  Valid sampai: {self.cert_info['notAfter']}")
        print("="*50 + "\n")

    def message_loop(self):
        """Loop utama untuk input pengguna dan menambahkan pesan ke antrian kirim."""
        while self.connected:
            try:
                message = input() # Ini adalah blocking I/O, yang baik untuk input pengguna
                if not message:
                    continue
                    
                if message.lower() == '/quit':
                    self.send_queue.put('/quit') # Kirim melalui antrian
                    # Beri waktu send_processor_thread untuk mengirim pesan /quit
                    time.sleep(0.5) # Sedikit penundaan untuk memastikan pesan terkirim
                    break # Keluar dari loop input pengguna
                elif message.lower() == '/status':
                    self.print_connection_status()
                elif message.lower() == '/cert':
                    if self.cert_info:
                        print("\nInfo Sertifikat Client:")
                        for key, value in self.cert_info.items():
                            print(f"  {key}: {value}")
                    else:
                        print("Tidak dapat mendapatkan info sertifikat")
                else:
                    self.send_queue.put(message) # Tambahkan ke antrian, jangan langsung kirim
                    
            except KeyboardInterrupt:
                print("\nMengakhiri koneksi...")
                break
            except Exception as e:
                logger.error(f"Error dalam message loop: {e}")
                break

    def receive_messages(self):
        """Thread untuk menerima pesan dari server (blocking I/O di sini tidak apa-apa karena di thread terpisah)."""
        try:
            while self.connected:
                try:
                    message = self.ssl_socket.recv(1024).decode('utf-8')
                    if not message:
                        logger.info("Server menutup koneksi atau tidak ada data.")
                        break
                    print(message)
                except ssl.SSLError as e:
                    logger.error(f"SSL Error: {e}")
                    break
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error menerima pesan: {e}")
                    break
        finally:
            self.connected = False
            logger.info("Receive thread terminated.")
            # Mungkin perlu memberi tahu loop utama untuk berhenti jika belum
            # Namun, biasanya input() akan error atau KeyboardInterrupt akan menangani ini.

    def _actual_send(self, message: str):
        """Fungsi pengiriman aktual yang akan dijalankan oleh executor."""
        try:
            if not self.connected:
                # Tidak perlu raise exception, cukup log dan return jika tidak terhubung
                logger.warning("Attempted to send while not connected.")
                return
            self.ssl_socket.sendall(message.encode('utf-8')) # Menggunakan sendall
            if message.lower() == '/quit':
                # Setelah mengirim /quit, klien harusnya berhenti
                self.connected = False # Set connected ke False untuk menghentikan loop lain
        except Exception as e:
            logger.error(f"Error mengirim pesan (async): {e}")
            self.connected = False # Jika ada error pengiriman, anggap koneksi terputus

    def process_send_queue(self):
        """Memproses antrian pesan keluar dan mengirimkannya menggunakan executor."""
        while self.connected or not self.send_queue.empty(): # Proses hingga antrian kosong bahkan jika disconnected
            try:
                message = self.send_queue.get(timeout=1) # Timeout agar thread bisa berhenti jika connected=False
                if message:
                    # self.send_executor.submit(self._actual_send, message)
                    # Langsung panggil saja karena send_executor hanya punya 1 worker
                    # dan kita ingin pengiriman berurutan.
                    # Jika kita submit, urutan tidak dijamin jika ada banyak submit cepat.
                    # Untuk pengiriman berurutan dari queue oleh satu worker, lebih baik panggil langsung.
                    self._actual_send(message)
                    if message.lower() == '/quit':
                        break # Keluar dari loop pemrosesan antrian setelah mengirim /quit
                self.send_queue.task_done()
            except queue.Empty:
                if not self.connected:
                    break # Keluar jika tidak terhubung dan antrian kosong
                continue
            except Exception as e:
                logger.error(f"Error processing send queue: {e}")
                # Jika ada error di sini, mungkin perlu menghentikan koneksi
                self.connected = False
                break
        logger.info("Send processor thread terminated.")

    def send_message(self, message: str):
        """Menambahkan pesan ke antrian kirim (deprecated, gunakan self.send_queue.put)."""
        # Fungsi ini sekarang digantikan dengan langsung .put() ke self.send_queue
        # Bisa dihapus atau ditandai deprecated
        if not self.connected:
            logger.warning("Tidak terhubung ke server, pesan tidak dimasukkan ke antrian.")
            return
        self.send_queue.put(message)

    def cleanup(self):
        """Membersihkan resources"""
        logger.info("Cleaning up client resources...")
        self.connected = False # Pastikan semua loop berhenti

        # Beri tahu send_processor_thread untuk berhenti jika masih berjalan
        # (misalnya jika loop input pengguna berhenti karena KeyboardInterrupt)
        # Ini bisa dilakukan dengan menambahkan item khusus ke antrian atau hanya mengandalkan self.connected
        # Jika send_queue.get() memiliki timeout, itu akan berhenti ketika self.connected menjadi False.

        # Shutdown executor
        logger.info("Shutting down send executor...")
        self.send_executor.shutdown(wait=True) # Menunggu task pengiriman selesai
        logger.info("Send executor shutdown complete.")

        try:
            if self.ssl_socket:
                self.ssl_socket.close()
            if self.socket:
                self.socket.close()
        except Exception as e:
            logger.error(f"Error saat cleanup: {e}")
        finally:
            self.connected = False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = 'localhost'
        
    client = TLSChatClient(host=host)
    client.connect() # Ini akan memblokir hingga message_loop selesai atau error
    logger.info("Client program finished.")