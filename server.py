import ssl
import socket
import threading
import logging
import json
import time
import sys
from typing import Dict, List
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, Executor

# Konfigurasi logging yang lebih komprehensif
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
        
        # ThreadPoolExecutor untuk mengirim pesan broadcast secara asynchronous
        self.send_executor: Executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix='BroadcastSender') # Ditambahkan
        
        # Konfigurasi SSL Context
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.check_hostname = False
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
        
        # Lock untuk thread safety
        self.clients_lock = threading.Lock()
        self.history_lock = threading.Lock()
        
        logger.info(f"Enhanced Server berjalan di {host}:{port}")

    def handle_client(self, client_socket: ssl.SSLSocket, client_address: tuple):
        client_id = None
        try:
            # Enhanced certificate validation
            cert = client_socket.getpeercert()
            if not cert:
                logger.warning(f"Koneksi tanpa sertifikat dari {client_address}")
                client_socket.close()
                return
                
            client_id = cert['subject'][0][0][1]
            
            # Check if client is banned
            if client_id in self.banned_clients:
                logger.warning(f"Klien banned mencoba koneksi: {client_id}")
                client_socket.send("ERROR: Anda telah dibanned dari server".encode('utf-8'))
                client_socket.close()
                return
            
            # Check if client already connected
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
            
            # Send welcome message dan history
            self.send_welcome_message(client_socket, client_id)
            self.send_recent_history(client_socket)
            
            # Broadcast join notification
            join_msg = f"📢 {client_id} telah bergabung ke chat"
            self.broadcast_and_log(join_msg, exclude=client_socket, msg_type="JOIN")
            
            # Main message loop
            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                        
                    message = data.decode('utf-8').strip()
                    if not message:
                        continue
                    
                    # Handle special commands
                    if message.startswith('/'):
                        self.handle_command(client_socket, client_id, message)
                    else:
                        # Regular message
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
        """Mengirim pesan selamat datang ke klien baru"""
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
        """Mengirim riwayat pesan terakhir ke klien baru"""
        try:
            with self.history_lock:
                recent_messages = self.message_history[-10:]  # 10 pesan terakhir
            
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
        """Handle special commands dari klien"""
        try:
            cmd_parts = command.lower().split()
            cmd = cmd_parts[0]
            
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
                # client_socket.close() # Penutupan akan ditangani oleh finally di handle_client
                # Tidak perlu memanggil remove_client di sini, akan ditangani oleh finally di handle_client
                # setelah loop utama di handle_client berakhir karena socket ditutup oleh client atau recv gagal.
                # Cukup pastikan client loop berhenti.
                # Untuk memaksa client loop berhenti, kita bisa mengirim sinyal shutdown atau biarkan recv gagal.
                # Cara paling sederhana adalah membiarkan client menutup koneksi setelah menerima pesan /quit.
                # Atau, server bisa menutupnya setelah mengirim pesan.
                # Jika server menutupnya di sini, pastikan handle_client menangani error dengan baik.
                # Untuk saat ini, kita biarkan client yang menutup setelah menerima pesan.
                # Jika ingin server yang menutup:
                # try:
                #     client_socket.shutdown(socket.SHUT_RDWR)
                # except OSError:
                #     pass # Socket mungkin sudah ditutup
                # client_socket.close()

            else:
                client_socket.send(f"❌ Perintah tidak dikenal: {cmd}".encode('utf-8'))
                
        except Exception as e:
            logger.error(f"Error handling command {command} dari {client_id}: {e}")

    def _send_message_to_client(self, client_socket: ssl.SSLSocket, recipient_id: str, message: str):
        """Mengirim pesan ke satu klien; digunakan oleh executor."""
        try:
            client_socket.sendall(message.encode('utf-8')) # Menggunakan sendall
        except Exception as e:
            logger.error(f"Error broadcasting (async) ke {recipient_id}: {e}")
            # Jika pengiriman gagal, klien mungkin terputus. Hapus klien.
            # Pastikan remove_client aman dipanggil dari berbagai thread (sudah menggunakan lock).
            self.remove_client(client_socket, recipient_id)

    def broadcast_and_log(self, message: str, exclude: ssl.SSLSocket = None, 
                         msg_type: str = "BROADCAST", sender: str = "SYSTEM"):
        """Broadcast pesan dan simpan ke history, menggunakan executor untuk pengiriman."""
        # Log message
        logger.info(f"[{msg_type}] {message}")
        
        # Save to history
        with self.history_lock:
            self.message_history.append({
                'timestamp': datetime.now(),
                'content': message,
                'type': msg_type,
                'sender': sender
            })
            
            # Keep only recent messages
            if len(self.message_history) > self.max_history:
                self.message_history.pop(0)
        
        # Broadcast to all clients using ThreadPoolExecutor
        with self.clients_lock:
            # Buat salinan daftar klien untuk diiterasi, jika self.clients bisa berubah saat iterasi
            # karena remove_client dipanggil oleh _send_message_to_client
            # Namun, karena kita mengambil client_socket dan client_id sebelum submit, ini aman.
            
            clients_to_send = []
            for r_id, r_socket in self.clients.items():
                if r_socket != exclude:
                    clients_to_send.append((r_socket, r_id))

        for client_sock, recipient_id_val in clients_to_send:
            self.send_executor.submit(self._send_message_to_client, client_sock, recipient_id_val, message)
            
            # Logika disconnected_clients yang lama dihapus karena penanganan error ada di _send_message_to_client

    def remove_client(self, client_socket: ssl.SSLSocket, client_id: str):
        """Remove client dengan error handling yang lebih baik"""
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
        """Mendapatkan statistik server"""
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
                    
                    # Set socket timeout untuk mencegah hanging
                    client_socket.settimeout(300)  # 5 menit timeout
                    
                    # Wrap dengan SSL
                    ssl_client = self.ssl_context.wrap_socket(client_socket, server_side=True)
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(ssl_client, client_address),
                        name=f"ClientThread-{client_address[0]}:{client_address[1]}"
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except ssl.SSLError as e:
                    logger.error(f"SSL Error saat menerima koneksi: {e}")
                except Exception as e:
                    logger.error(f"Error saat menerima koneksi: {e}")
                    
        except KeyboardInterrupt:
            logger.info("🛑 Server dihentikan oleh pengguna")
        except Exception as e:
            logger.error(f"Fatal error: {e}")
        finally:
            self.cleanup()

    def cleanup(self):
        """Cleanup resources saat server shutdown"""
        logger.info("🧹 Membersihkan resources...")
        
        # Shutdown executor
        logger.info("Shutting down send executor...")
        self.send_executor.shutdown(wait=True) # Menunggu task yang ada selesai
        logger.info("Send executor shutdown complete.")

        with self.clients_lock:
            for client_id, client_socket in self.clients.items():
                try:
                    client_socket.send("🛑 Server sedang shutdown...".encode('utf-8'))
                    client_socket.close()
                except:
                    pass
        
        try:
            self.server_socket.close()
        except:
            pass
            
        logger.info("✅ Server cleanup selesai")

if __name__ == "__main__":
    server = EnhancedTLSChatServer()
    server.start()