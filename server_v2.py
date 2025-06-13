import ssl
import socket
import threading
import logging
import json
import time
import sys
from typing import Dict, List
from datetime import datetime

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
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
        self.message_history: List[Dict] = []
        self.max_history = 100
        self.banned_clients: List[str] = []

        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.check_hostname = False
        self.ssl_context.load_cert_chain(
            certfile='certs/server.crt',
            keyfile='certs/server.key'
        )
        self.ssl_context.load_verify_locations('certs/ca.crt')

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        self.clients_lock = threading.Lock()
        self.history_lock = threading.Lock()

        logger.info(f"Enhanced Server berjalan di {host}:{port}")

    def handle_client(self, client_socket: ssl.SSLSocket, client_address: tuple):
        client_id = None
        try:
            cert = client_socket.getpeercert()
            if not cert:
                logger.warning(f"Koneksi tanpa sertifikat dari {client_address}")
                client_socket.close()
                return

            client_id = cert['subject'][0][0][1]

            if client_id in self.banned_clients:
                logger.warning(f"Klien banned mencoba koneksi: {client_id}")
                client_socket.send("ERROR: Anda telah dibanned dari server".encode('utf-8'))
                client_socket.close()
                return

            with self.clients_lock:
                if client_id in self.clients:
                    logger.warning(f"Klien sudah terhubung: {client_id}")
                    client_socket.send("ERROR: Anda sudah terhubung dari tempat lain".encode('utf-8'))
                    client_socket.close()
                    return

                self.clients[client_id] = client_socket
                self.client_names[client_socket] = client_id
                self.client_join_time[client_id] = datetime.now()

            logger.info(f"Klien terhubung: {client_id} dari {client_address}")

            self.send_welcome_message(client_socket, client_id)
            self.send_recent_history(client_socket)

            join_msg = f"📢 {client_id} telah bergabung ke chat"
            self.broadcast_and_log(join_msg, exclude=client_socket, msg_type="JOIN")

            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break

                    message = data.decode('utf-8').strip()
                    if not message:
                        continue

                    if message.startswith('/'):
                        self.handle_command(client_socket, client_id, message)
                    else:
                        formatted_msg = f"{client_id}: {message}"
                        self.broadcast_and_log(formatted_msg, exclude=client_socket,
                                               msg_type="MESSAGE", sender=client_id)

                except ssl.SSLError as e:
                    logger.error(f"SSL Error dari {client_id}: {e}")
                    break
                except socket.timeout:
                    logger.warning(f"Timeout dari {client_id}")
                    break
                except Exception as e:
                    logger.error(f"Error handling message dari {client_id}: {e}")
                    break

        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
        finally:
            if client_id:
                self.remove_client(client_socket, client_id)

    def send_welcome_message(self, client_socket: ssl.SSLSocket, client_id: str):
        try:
            welcome_msg = f"""
🎉 Selamat datang {client_id}!
📋 Perintah yang tersedia:
   /help - Tampilkan bantuan
   /list - Lihat daftar pengguna online
   /time - Lihat waktu server
   /history - Lihat 10 pesan terakhir
   /quit - Keluar dari chat
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            client_socket.send(welcome_msg.encode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending welcome message: {e}")

    def send_recent_history(self, client_socket: ssl.SSLSocket):
        try:
            with self.history_lock:
                recent_messages = self.message_history[-10:]

            if recent_messages:
                history_msg = "\n📜 10 Pesan Terakhir:\n" + "─" * 30 + "\n"
                for msg in recent_messages:
                    timestamp = msg['timestamp'].strftime("%H:%M")
                    history_msg += f"[{timestamp}] {msg['content']}\n"
                history_msg += "─" * 30 + "\n"
                client_socket.send(history_msg.encode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending history: {e}")

    def handle_command(self, client_socket: ssl.SSLSocket, client_id: str, command: str):
        try:
            cmd = command.lower().split()[0]

            if cmd == '/help':
                help_msg = """
📋 Perintah yang tersedia:
   /help - Tampilkan bantuan ini
   /list - Lihat daftar pengguna online
   /time - Lihat waktu server
   /history - Lihat 10 pesan terakhir
   /quit - Keluar dari chat
"""
                client_socket.send(help_msg.encode('utf-8'))

            elif cmd == '/list':
                with self.clients_lock:
                    online_users = list(self.clients.keys())
                list_msg = f"👥 Pengguna Online ({len(online_users)}): " + ", ".join(online_users)
                client_socket.send(list_msg.encode('utf-8'))

            elif cmd == '/time':
                time_msg = f"🕒 Waktu Server: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                client_socket.send(time_msg.encode('utf-8'))

            elif cmd == '/history':
                self.send_recent_history(client_socket)

            elif cmd == '/quit':
                client_socket.send("👋 Sampai jumpa!".encode('utf-8'))
                client_socket.close()

            else:
                client_socket.send(f"❌ Perintah tidak dikenal: {cmd}".encode('utf-8'))

        except Exception as e:
            logger.error(f"Error handling command {command} dari {client_id}: {e}")

    def broadcast_and_log(self, message: str, exclude: ssl.SSLSocket = None,
                         msg_type: str = "BROADCAST", sender: str = "SYSTEM"):
        logger.info(f"[{msg_type}] {message}")

        with self.history_lock:
            self.message_history.append({
                'timestamp': datetime.now(),
                'content': message,
                'type': msg_type,
                'sender': sender
            })
            if len(self.message_history) > self.max_history:
                self.message_history.pop(0)

        with self.clients_lock:
            disconnected_clients = []
            for client_id, client_socket in self.clients.items():
                if client_socket != exclude:
                    try:
                        client_socket.send(message.encode('utf-8'))
                    except Exception as e:
                        logger.error(f"Error broadcasting ke {client_id}: {e}")
                        disconnected_clients.append(client_id)

            for client_id in disconnected_clients:
                if client_id in self.clients:
                    socket_to_remove = self.clients[client_id]
                    self.remove_client(socket_to_remove, client_id)

    def remove_client(self, client_socket: ssl.SSLSocket, client_id: str):
        try:
            with self.clients_lock:
                if client_id in self.clients:
                    del self.clients[client_id]
                if client_socket in self.client_names:
                    del self.client_names[client_socket]
                if client_id in self.client_join_time:
                    join_time = self.client_join_time[client_id]
                    duration = datetime.now() - join_time
                    logger.info(f"Klien {client_id} terhubung selama {duration}")
                    del self.client_join_time[client_id]

            try:
                client_socket.close()
            except:
                pass

            leave_msg = f"📢 {client_id} telah meninggalkan chat"
            self.broadcast_and_log(leave_msg, msg_type="LEAVE")
            logger.info(f"Klien terputus: {client_id}")

        except Exception as e:
            logger.error(f"Error removing client {client_id}: {e}")

    def get_server_stats(self):
        with self.clients_lock:
            return {
                'active_clients': len(self.clients),
                'client_list': list(self.clients.keys()),
                'total_messages': len(self.message_history)
            }

    def start(self):
        try:
            logger.info("🚀 Enhanced TLS Chat Server dimulai...")
            logger.info("📊 Fitur tambahan: Commands, History, Better Logging, Error Handling")

            while True:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_socket.settimeout(300)
                    ssl_client = self.ssl_context.wrap_socket(client_socket, server_side=True)

                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(ssl_client, client_address),
                        name=f"ClientThread-{client_address[0]}:{client_address[1]}"
                    )
                    client_thread.start()

                except Exception as e:
                    logger.error(f"Error menerima koneksi klien: {e}")
        except KeyboardInterrupt:
            logger.info("Server dimatikan oleh user.")
        finally:
            self.server_socket.close()


if __name__ == "__main__":
    server = EnhancedTLSChatServer()
    server.start()
