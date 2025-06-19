import ssl
import socket
import threading
import logging
import sys
import json
from typing import Dict, List
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Import security enhancements
try:
    from security_enhancements import MessageSecurity
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    print("WARNING: Security enhancements not available. Install cryptography: pip install cryptography")

# Konfigurasi logging yang lebih komprehensif
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler('chat_server.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class EnhancedTLSChatServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 8443):
        self.host = host
        self.port = port
        self.clients: Dict[str, ssl.SSLSocket] = {}
        self.client_names: Dict[ssl.SSLSocket, str] = {}
        self.client_join_time: Dict[str, datetime] = {}
        self.client_security: Dict[str, MessageSecurity] = {}  # Store client security objects
        self.whitelist_file = 'whitelist.txt'
        self.whitelist = self.load_whitelist()
        self.message_history: List[Dict] = []
        self.max_history = 100
        self.banned_clients: List[str] = []

        self.send_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix='BroadcastSender')

        # Konfigurasi SSL Context
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.check_hostname = False
        self.ssl_context.load_cert_chain(certfile='certs/server.crt', keyfile='certs/server.key')
        self.ssl_context.load_verify_locations('certs/ca.crt')

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))

        self.clients_lock = threading.Lock()
        self.history_lock = threading.Lock()
        self.running = False
        
        security_status = "with enhanced security" if SECURITY_AVAILABLE else "with basic security"
        logger.info(f"Server diinisialisasi untuk {self.host}:{self.port} {security_status}")

    def load_whitelist(self) -> set:
        """Membaca daftar pengguna yang diizinkan dari file."""
        allowed_users = set()
        try:
            with open(self.whitelist_file, 'r') as f:
                for line in f:
                    user = line.strip()
                    if user and not user.startswith('#'):
                        allowed_users.add(user)
            logger.info(f"Whitelist berhasil dimuat dari '{self.whitelist_file}'. {len(allowed_users)} pengguna diizinkan.")
        except FileNotFoundError:
            logger.warning(f"File whitelist '{self.whitelist_file}' tidak ditemukan.")
        except Exception as e:
            logger.error(f"Gagal memuat whitelist: {e}")
        return allowed_users

    def handle_client(self, client_socket: ssl.SSLSocket, client_address: tuple):
        """Menangani koneksi dari satu klien."""
        client_id = None
        try:
            # === BAGIAN TUGAS #7: VALIDASI IDENTITAS & WHITELIST ===
            cert = client_socket.getpeercert()
            if not cert:
                logger.warning(f"Koneksi dari {client_address} tanpa sertifikat.")
                return

            subject_info = dict(x[0] for x in cert.get('subject', []))
            client_cn = subject_info.get('commonName')
            client_o = subject_info.get('organizationName', 'N/A')
            client_ou = subject_info.get('organizationalUnitName', 'N/A')

            if not client_cn:
                logger.warning(f"DITOLAK: Koneksi dari {client_address} tidak memiliki Common Name (CN).")
                return

            client_id = client_cn
            logger.info(f"Menerima koneksi dari: ID={client_id}, Org={client_o}, Unit={client_ou}")

            if client_id not in self.whitelist:
                logger.warning(f"DITOLAK: '{client_id}' tidak ada di whitelist.")
                try:
                    client_socket.sendall(f"ERROR: Pengguna '{client_id}' tidak terdaftar.".encode('utf-8'))
                except Exception:
                    pass
                return

            # Initialize message security for this client if available
            if SECURITY_AVAILABLE:
                try:
                    cert_path = f'certs/{client_id}.crt'
                    key_path = f'certs/{client_id}.key'
                    import os
                    if os.path.exists(cert_path) and os.path.exists(key_path):
                        self.client_security[client_id] = MessageSecurity(cert_path, key_path)
                        logger.info(f"🔐 Message security initialized for {client_id}")
                    else:
                        logger.warning(f"Certificate files not found for {client_id}, security disabled")
                        self.client_security[client_id] = None
                except Exception as e:
                    logger.warning(f"Failed to initialize security for {client_id}: {e}")
                    self.client_security[client_id] = None
            else:
                self.client_security[client_id] = None

            logger.info(f"DITERIMA: '{client_id}' berhasil melewati validasi whitelist.")

            with self.clients_lock:
                if client_id in self.clients:
                    logger.warning(f"DITOLAK: '{client_id}' sudah terhubung.")
                    client_socket.sendall(b"ERROR: Akun ini sudah digunakan dari lokasi lain.")
                    return
                if client_id in self.banned_clients:
                    logger.warning(f"DITOLAK: '{client_id}' adalah pengguna yang dibanned.")
                    client_socket.sendall(b"ERROR: Anda telah dibanned dari server.")
                    return
                
                self.clients[client_id] = client_socket
                self.client_names[client_socket] = client_id
                self.client_join_time[client_id] = datetime.now()

            logger.info(f"Klien terhubung: {client_id} dari {client_address}")
            self.send_welcome_message(client_socket, client_id)
            self.send_recent_history(client_socket)
            self.broadcast(f"📢 {client_id} telah bergabung.", exclude_socket=client_socket)
            
            while self.running and client_id in self.clients:
                try:
                    data = client_socket.recv(4096)  # Increased buffer for signed messages
                    if not data:
                        break
                    
                    raw_message = data.decode('utf-8').strip()
                    if not raw_message:
                        continue
                    
                    # ✅ FIXED: Ekstrak pesan original untuk command checking
                    original_message = self.extract_original_message(raw_message, client_id)
                    
                    # Check if it's a command first (BEFORE processing)
                    if original_message.startswith('/'):
                        self.handle_command(client_socket, client_id, original_message)
                    else:
                        # Process as regular message with security features
                        processed_message = self.process_message(raw_message, client_id)
                        self.broadcast(processed_message, exclude_socket=client_socket)

                except (ssl.SSLError, socket.timeout):
                    continue
                except (ConnectionResetError, BrokenPipeError):
                    logger.warning(f"Koneksi dengan '{client_id}' terputus secara tiba-tiba.")
                    break
        except Exception as e:
            logger.error(f"Error pada handle_client untuk {client_address}: {e}")
        finally:
            self.remove_client(client_socket, client_id)

    def extract_original_message(self, raw_message: str, client_id: str) -> str:
        """Extract original message content (for command detection)"""
        try:
            if self.client_security.get(client_id):
                # Try to extract from signed message
                try:
                    data = json.loads(raw_message)
                    if 'message_data' in data and 'content' in data['message_data']:
                        return data['message_data']['content']
                except (json.JSONDecodeError, KeyError):
                    pass
            # Fallback to raw message
            return raw_message
        except Exception:
            return raw_message

    def process_message(self, raw_message: str, client_id: str) -> str:
        """Process incoming message - verify signature if present"""
        try:
            if self.client_security.get(client_id):
                # Try to verify as signed message
                verified_data = self.client_security[client_id].verify_message(raw_message)
                
                if verified_data['verified']:
                    # Message signature verified
                    security_indicator = "🔐✅"
                    logger.info(f"Verified signed message from {client_id}")
                    return f"{security_indicator} [{verified_data['sender']}] {verified_data['content']}"
                else:
                    # Message signature failed or unsigned
                    security_indicator = "⚠️"
                    logger.warning(f"Unverified message from {client_id}")
                    return f"{security_indicator} [{verified_data.get('sender', client_id)}] {verified_data['content']}"
            else:
                # No security initialized - treat as regular message
                return f"[{client_id}] {raw_message}"
                
        except Exception as e:
            logger.error(f"Error processing message from {client_id}: {e}")
            # Fallback to regular message
            return f"[{client_id}] {raw_message}"

    def remove_client(self, client_socket: ssl.SSLSocket, client_id: str):
        """Menghapus klien dari daftar aktif dan menutup koneksi."""
        if client_id is None:
            return
            
        with self.clients_lock:
            if client_id in self.clients:
                del self.clients[client_id]
                del self.client_names[client_socket]
                if client_id in self.client_join_time:
                    del self.client_join_time[client_id]
                if client_id in self.client_security:
                    del self.client_security[client_id]
                
                logger.info(f"Koneksi untuk '{client_id}' ditutup.")
                self.broadcast(f"📢 {client_id} telah keluar.")
        try:
            client_socket.close()
        except Exception:
            pass

    def broadcast(self, message: str, exclude_socket: ssl.SSLSocket = None):
        """Mengirim pesan ke semua klien yang terhubung."""
        logger.info(f"BROADCAST: {message}")
        with self.history_lock:
            self.message_history.append({'timestamp': datetime.now(), 'content': message})
            if len(self.message_history) > self.max_history:
                self.message_history.pop(0)

        with self.clients_lock:
            clients_to_broadcast = list(self.clients.values())

        for client_sock in clients_to_broadcast:
            if client_sock != exclude_socket:
                self.send_executor.submit(self._send_message_to_client, client_sock, message)

    def _send_message_to_client(self, client_socket: ssl.SSLSocket, message: str):
        """Helper untuk mengirim pesan di thread terpisah."""
        try:
            client_socket.sendall(message.encode('utf-8'))
        except Exception:
            pass
            
    def send_welcome_message(self, client_socket: ssl.SSLSocket, client_id: str):
        """Mengirim pesan selamat datang ke klien baru."""
        security_status = "🔐 Enhanced" if self.client_security.get(client_id) else "⚠️ Basic"
        welcome_msg = f"""
🎉 Selamat datang {client_id}! (Security: {security_status})
📋 Perintah yang tersedia: /help, /list, /time, /history, /quit
🔐 Message signing: {'Enabled' if self.client_security.get(client_id) else 'Disabled'}
"""
        try:
            client_socket.sendall(welcome_msg.encode('utf-8'))
        except Exception as e:
            logger.error(f"Gagal mengirim pesan selamat datang ke {client_id}: {e}")
    
    def send_recent_history(self, client_socket: ssl.SSLSocket):
        """Mengirim riwayat pesan terakhir ke klien baru."""
        with self.history_lock:
            recent_messages = self.message_history[-10:]
        if recent_messages:
            history_str = "\n--- 10 Pesan Terakhir ---\n"
            for msg in recent_messages:
                history_str += f"{msg['content']}\n"
            history_str += "------------------------\n"
            try:
                client_socket.sendall(history_str.encode('utf-8'))
            except Exception as e:
                logger.error(f"Gagal mengirim histori pesan: {e}")

    def handle_command(self, client_socket: ssl.SSLSocket, client_id: str, command: str):
        """Menangani perintah khusus dari klien."""
        parts = command.lower().split()
        cmd = parts[0]
        response = ""
        
        logger.info(f"Processing command '{cmd}' from {client_id}")  # Debug log
        
        if cmd == '/help':
            response = "Perintah: /help, /list, /time, /history, /quit"
        elif cmd == '/list':
            with self.clients_lock:
                users_info = []
                for user_id in self.clients.keys():
                    security_status = "🔐" if self.client_security.get(user_id) else "⚠️"
                    users_info.append(f"{security_status}{user_id}")
                users = ", ".join(users_info)
                response = f"Pengguna online ({len(self.clients)}): {users}"
        elif cmd == '/time':
            response = f"Waktu server: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        elif cmd == '/history':
            self.send_recent_history(client_socket)
            return
        elif cmd == '/quit':
            response = "Sampai jumpa!"
        else:
            response = f"Perintah tidak dikenal: {cmd}. Ketik /help untuk daftar perintah."
        
        if response:
            try:
                logger.info(f"Sending command response to {client_id}: {response}")  # Debug log
                client_socket.sendall(response.encode('utf-8'))
            except Exception as e:
                logger.error(f"Gagal mengirim respon command ke {client_id}: {e}")

    def start(self):
        """Metode utama untuk menjalankan server dan menerima koneksi."""
        self.server_socket.listen(5)
        self.running = True
        security_info = "🔐 Enhanced Security Mode" if SECURITY_AVAILABLE else "⚠️ Basic Security Mode"
        logger.info(f"🚀 Server berjalan dan mendengarkan di {self.host}:{self.port} ({security_info})")

        try:
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    ssl_client = self.ssl_context.wrap_socket(client_socket, server_side=True)
                    
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(ssl_client, client_address),
                        name=f"Client-{client_address[1]}"
                    )
                    thread.daemon = True
                    thread.start()
                except (ssl.SSLError, OSError) as e:
                    if self.running:
                        logger.error(f"Error saat menerima koneksi: {e}")
        finally:
            self.stop()

    def stop(self):
        """Menghentikan server dan membersihkan semua resource."""
        if not self.running:
            return
        logger.info("🛑 Menghentikan server...")
        self.running = False

        with self.clients_lock:
            clients_to_close = list(self.clients.values())
            logger.info(f"Menutup {len(clients_to_close)} koneksi klien aktif...")
            for sock in clients_to_close:
                try:
                    sock.close()
                except Exception:
                    pass
        
        try:
            self.server_socket.close()
            logger.info("Socket server utama ditutup.")
        except Exception:
            pass

        self.send_executor.shutdown(wait=True)
        logger.info("✅ Server berhasil dihentikan.")

if __name__ == "__main__":
    server = EnhancedTLSChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nCtrl+C terdeteksi. Menghentikan server.")
    finally:
        server.stop()