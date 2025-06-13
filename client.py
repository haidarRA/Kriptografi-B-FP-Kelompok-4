import ssl
import socket
import threading
import logging
import sys
import os
from datetime import datetime
from typing import Optional

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
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Loop utama untuk mengirim pesan
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
        """Loop utama untuk mengirim pesan"""
        while self.connected:
            try:
                message = input()
                if not message:
                    continue
                    
                if message.lower() == '/quit':
                    self.send_message('/quit')
                    break
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
                    self.send_message(message)
                    
            except KeyboardInterrupt:
                print("\nMengakhiri koneksi...")
                break
            except Exception as e:
                logger.error(f"Error dalam message loop: {e}")
                break

    def receive_messages(self):
        """Thread untuk menerima pesan"""
        try:
            while self.connected:
                try:
                    message = self.ssl_socket.recv(1024).decode('utf-8')
                    if not message:
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

    def send_message(self, message: str):
        """Mengirim pesan ke server"""
        try:
            if not self.connected:
                raise Exception("Tidak terhubung ke server")
            self.ssl_socket.send(message.encode('utf-8'))
        except Exception as e:
            logger.error(f"Error mengirim pesan: {e}")
            self.connected = False

    def cleanup(self):
        """Membersihkan resources"""
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
    client.connect() 