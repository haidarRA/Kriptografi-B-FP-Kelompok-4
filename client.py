import ssl
import socket
import threading
import logging
import sys

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TLSChatClient:
    def __init__(self, host: str = 'localhost', port: int = 8443):
        self.host = host
        self.port = port
        
        # Konfigurasi SSL Context
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.check_hostname = False  # Nonaktifkan hostname checking
        self.ssl_context.load_verify_locations('certs/ca.crt')
        self.ssl_context.load_cert_chain(
            certfile='certs/client.crt',
            keyfile='certs/client.key'
        )
        
        # Membuat socket client
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_socket = self.ssl_context.wrap_socket(
            self.socket,
            server_hostname=host
        )

    def connect(self):
        try:
            self.ssl_socket.connect((self.host, self.port))
            logger.info("Terhubung ke server")
            
            # Memulai thread untuk menerima pesan
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Loop utama untuk mengirim pesan
            while True:
                message = input()
                if message.lower() == 'quit':
                    break
                self.send_message(message)
                
        except Exception as e:
            logger.error(f"Error koneksi: {e}")
        finally:
            self.ssl_socket.close()

    def receive_messages(self):
        try:
            while True:
                message = self.ssl_socket.recv(1024).decode('utf-8')
                if not message:
                    break
                print(message)
        except Exception as e:
            logger.error(f"Error menerima pesan: {e}")

    def send_message(self, message: str):
        try:
            self.ssl_socket.send(message.encode('utf-8'))
        except Exception as e:
            logger.error(f"Error mengirim pesan: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = 'localhost'
        
    client = TLSChatClient(host=host)
    client.connect() 