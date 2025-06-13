import ssl
import socket
import threading
import logging
from typing import Dict, List

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TLSChatServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 8443):
        self.host = host
        self.port = port
        self.clients: Dict[str, ssl.SSLSocket] = {}
        self.client_names: Dict[ssl.SSLSocket, str] = {}
        
        # Konfigurasi SSL Context
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.check_hostname = False  # Nonaktifkan hostname checking
        self.ssl_context.load_cert_chain(
            certfile='certs/server.crt',
            keyfile='certs/server.key'
        )
        self.ssl_context.load_verify_locations('certs/ca.crt')
        
        # Membuat socket server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        # Membungkus socket dengan SSL
        self.ssl_socket = self.ssl_context.wrap_socket(
            self.server_socket,
            server_side=True
        )
        
        logger.info(f"Server berjalan di {host}:{port}")

    def handle_client(self, client_socket: ssl.SSLSocket, client_address: tuple):
        try:
            # Mendapatkan informasi sertifikat klien
            cert = client_socket.getpeercert()
            client_id = cert['subject'][0][0][1]  # Mengambil CN dari sertifikat
            self.clients[client_id] = client_socket
            self.client_names[client_socket] = client_id
            
            logger.info(f"Klien terhubung: {client_id}")
            self.broadcast(f"{client_id} telah bergabung ke chat", exclude=client_socket)
            
            while True:
                try:
                    message = client_socket.recv(1024).decode('utf-8')
                    if not message:
                        break
                    
                    logger.info(f"Pesan dari {client_id}: {message}")
                    self.broadcast(f"{client_id}: {message}", exclude=client_socket)
                    
                except ssl.SSLError as e:
                    logger.error(f"SSL Error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            self.remove_client(client_socket, client_id)

    def remove_client(self, client_socket: ssl.SSLSocket, client_id: str):
        if client_id in self.clients:
            del self.clients[client_id]
        if client_socket in self.client_names:
            del self.client_names[client_socket]
        client_socket.close()
        self.broadcast(f"{client_id} telah meninggalkan chat")
        logger.info(f"Klien terputus: {client_id}")

    def broadcast(self, message: str, exclude: ssl.SSLSocket = None):
        for client_id, client_socket in self.clients.items():
            if client_socket != exclude:
                try:
                    client_socket.send(message.encode('utf-8'))
                except Exception as e:
                    logger.error(f"Error broadcasting ke {client_id}: {e}")

    def start(self):
        try:
            while True:
                client_socket, client_address = self.ssl_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            logger.info("Server dihentikan")
        finally:
            self.ssl_socket.close()

if __name__ == "__main__":
    server = TLSChatServer()
    server.start() 