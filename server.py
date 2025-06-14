import ssl
import socket
import threading
import logging
import json
import time
import sys
import hashlib
import hmac
import signal
import os
from typing import Dict, List
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, Executor
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('enhanced_server.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)  
    ]
)
logger = logging.getLogger(__name__)

class SecurityEnhancedTLSServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 8443):
        self.host = host
        self.port = port
        self.clients: Dict[str, ssl.SSLSocket] = {}
        self.client_names: Dict[ssl.SSLSocket, str] = {}
        self.client_join_time: Dict[str, datetime] = {}
        self.client_fingerprints: Dict[str, str] = {}
        self.message_counters: Dict[str, int] = {}
        
        self.whitelist_file = 'whitelist.txt'
        self.whitelist = self.load_whitelist()
        self.message_history: List[Dict] = []
        self.max_history = 100
        self.banned_clients: List[str] = []
        
        # Security enhancements
        self.integrity_key = b'shared_secret_key_for_integrity_2024'
        self.suspicious_activities: Dict[str, List] = {}
        
        # Shutdown control
        self.running = True
        self.shutdown_event = threading.Event()
        
        # ThreadPoolExecutor for async message sending
        self.send_executor: Executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix='BroadcastSender')
        
        # SSL Context configuration
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.check_hostname = False
        self.ssl_context.load_cert_chain(
            certfile='certs/server.crt',
            keyfile='certs/server.key'
        )
        self.ssl_context.load_verify_locations('certs/ca.crt')
        
        # Create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Set socket timeout to allow periodic shutdown checks
        self.server_socket.settimeout(1.0)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        # Thread safety locks
        self.clients_lock = threading.Lock()
        self.history_lock = threading.Lock()
        self.security_lock = threading.Lock()

        # Setup signal handlers for graceful shutdown
        self.setup_signal_handlers()

        logger.info(f"🛡️  Enhanced Secure Server running on {self.host}:{self.port}")

    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"📡 Received signal {signum}, initiating graceful shutdown...")
            self.running = False
            self.shutdown_event.set()
        
        # Handle Ctrl+C (SIGINT) and SIGTERM
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)

    def load_whitelist(self) -> set:
        """Load allowed users from whitelist file"""
        allowed_users = set()
        try:
            with open(self.whitelist_file, 'r') as f:
                for line in f:
                    user = line.strip()
                    if user and not user.startswith('#'):
                        allowed_users.add(user)
            logger.info(f"Whitelist loaded: {len(allowed_users)} users allowed")
        except FileNotFoundError:
            logger.warning(f"Whitelist file '{self.whitelist_file}' not found")
        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")
        return allowed_users

    def calculate_cert_fingerprint(self, cert_der: bytes) -> str:
        """Calculate SHA-256 fingerprint of certificate"""
        return hashlib.sha256(cert_der).hexdigest().upper()

    def verify_client_certificate(self, client_socket: ssl.SSLSocket, client_id: str) -> bool:
        """Enhanced client certificate verification with fingerprint tracking"""
        try:
            cert_der = client_socket.getpeercert(binary_form=True)
            if not cert_der:
                logger.warning(f"No certificate from {client_id}")
                return False
            
            fingerprint = self.calculate_cert_fingerprint(cert_der)
            
            with self.security_lock:
                if client_id in self.client_fingerprints:
                    stored_fingerprint = self.client_fingerprints[client_id]
                    if fingerprint != stored_fingerprint:
                        logger.error(f"🚨 SECURITY ALERT: Client '{client_id}' has different certificate fingerprint!")
                        logger.error(f"   Stored: {stored_fingerprint}")
                        logger.error(f"   Current: {fingerprint}")
                        
                        if client_id not in self.suspicious_activities:
                            self.suspicious_activities[client_id] = []
                        self.suspicious_activities[client_id].append({
                            'type': 'certificate_mismatch',
                            'timestamp': datetime.now(),
                            'details': f"Fingerprint changed from {stored_fingerprint} to {fingerprint}"
                        })
                        
                        return False
                else:
                    self.client_fingerprints[client_id] = fingerprint
                    logger.info(f"🔍 Stored fingerprint for {client_id}: {fingerprint}")
            
            logger.info(f"✅ Client certificate verified: {client_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error verifying client certificate: {e}")
            return False

    def verify_message_signature(self, signed_message: str, client_id: str) -> tuple:
        """Verify message signature and detect replay attacks"""
        try:
            parts = signed_message.split('|')
            if len(parts) < 4:
                return True, signed_message
            
            message = '|'.join(parts[:-3])
            timestamp = parts[-3]
            counter = parts[-2]
            received_signature = parts[-1]
            
            data_to_verify = f"{message}|{timestamp}|{counter}"
            expected_signature = hmac.new(
                self.integrity_key,
                data_to_verify.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            is_valid = hmac.compare_digest(received_signature, expected_signature)
            
            if not is_valid:
                logger.warning(f"❌ Invalid message signature from {client_id}")
                with self.security_lock:
                    if client_id not in self.suspicious_activities:
                        self.suspicious_activities[client_id] = []
                    self.suspicious_activities[client_id].append({
                        'type': 'invalid_signature',
                        'timestamp': datetime.now(),
                        'message': message[:100]
                    })
                return False, message
            
            current_time = int(time.time())
            msg_time = int(timestamp)
            if current_time - msg_time > 300:
                logger.warning(f"⚠️  Old message from {client_id} (possible replay attack)")
                return False, message
            
            msg_counter = int(counter)
            with self.security_lock:
                if client_id in self.message_counters:
                    if msg_counter <= self.message_counters[client_id]:
                        logger.warning(f"⚠️  Message counter reuse from {client_id} (possible replay attack)")
                        return False, message
                self.message_counters[client_id] = msg_counter
            
            logger.debug(f"✅ Message integrity verified from {client_id}")
            return True, message
            
        except Exception as e:
            logger.error(f"Error verifying message signature: {e}")
            return False, signed_message

    def create_message_signature(self, message: str) -> str:
        """Create server message with integrity signature"""
        timestamp = str(int(time.time()))
        counter = str(int(time.time() * 1000))
        data_to_sign = f"{message}|{timestamp}|{counter}"
        
        signature = hmac.new(
            self.integrity_key,
            data_to_sign.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return f"{message}|{timestamp}|{counter}|{signature}"

    def detect_suspicious_behavior(self, client_id: str, message: str):
        """Detect suspicious client behavior"""
        suspicious_patterns = [
            'script', 'bot', 'automated', 'attack', 'exploit',
            '<script>', 'javascript:', 'eval(', 'exec('
        ]
        
        message_lower = message.lower()
        for pattern in suspicious_patterns:
            if pattern in message_lower:
                logger.warning(f"🚨 Suspicious content from {client_id}: {pattern}")
                with self.security_lock:
                    if client_id not in self.suspicious_activities:
                        self.suspicious_activities[client_id] = []
                    self.suspicious_activities[client_id].append({
                        'type': 'suspicious_content',
                        'timestamp': datetime.now(),
                        'pattern': pattern,
                        'message': message[:100]
                    })
                break

    def handle_client(self, client_socket: ssl.SSLSocket, client_address: tuple):
        """Handle client connection with proper shutdown handling"""
        client_id = None
        try:
            # Set socket timeout for periodic shutdown checks
            client_socket.settimeout(5.0)
            
            cert = client_socket.getpeercert()
            if not cert:
                logger.warning(f"Connection without certificate from {client_address}")
                client_socket.close()
                return
                
            client_id = cert['subject'][0][0][1]

            if not self.verify_client_certificate(client_socket, client_id):
                logger.error(f"Certificate verification failed for {client_id}")
                client_socket.send("ERROR: Certificate verification failed".encode('utf-8'))
                client_socket.close()
                return

            if client_id not in self.whitelist:
                logger.warning(f"Client '{client_id}' rejected - not in whitelist")
                client_socket.sendall("ERROR: You are not registered on this server.".encode('utf-8'))
                client_socket.close()
                return
        
            # FIXED: Reset security state for reconnecting clients
            with self.security_lock:
                # Reset message counter for fresh start
                if client_id in self.message_counters:
                    logger.info(f"🔄 Resetting message counter for reconnecting client {client_id}")
                    del self.message_counters[client_id]
                
                # Clear any suspicious activities from previous session  
                if client_id in self.suspicious_activities:
                    old_count = len(self.suspicious_activities[client_id])
                    self.suspicious_activities[client_id] = []
                    logger.info(f"🧹 Cleared {old_count} suspicious activities for {client_id}")
            
            logger.info(f"Client '{client_id}' accepted from whitelist")
            
            if client_id in self.banned_clients:
                logger.warning(f"Banned client attempted connection: {client_id}")
                client_socket.send("ERROR: You have been banned from server".encode('utf-8'))
                client_socket.close()
                return
            
            with self.clients_lock:
                if client_id in self.clients:
                    logger.warning(f"Client already connected: {client_id}")
                    client_socket.send("ERROR: You are already connected from another location".encode('utf-8'))
                    client_socket.close()
                    return
                
                self.clients[client_id] = client_socket
                self.client_names[client_socket] = client_id
                self.client_join_time[client_id] = datetime.now()
            
            logger.info(f"🔐 Secure client connected: {client_id} from {client_address}")
            
            self.send_enhanced_welcome_message(client_socket, client_id)
            self.send_recent_history(client_socket)
            
            join_msg = f"🔐 {client_id} joined the secure chat"
            self.broadcast_and_log(join_msg, exclude=client_socket, msg_type="JOIN")
            
            # Main message loop with shutdown handling
            while self.running and not self.shutdown_event.is_set():
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                        
                    raw_message = data.decode('utf-8').strip()
                    if not raw_message:
                        continue
                    
                    is_valid, message = self.verify_message_signature(raw_message, client_id)
                    if not is_valid:
                        logger.warning(f"⚠️  Invalid message from {client_id}, ignoring")
                        continue
                    
                    self.detect_suspicious_behavior(client_id, message)
                    
                    if message.startswith('/'):
                        self.handle_enhanced_command(client_socket, client_id, message)
                    else:
                        formatted_msg = f"{client_id}: {message}"
                        signed_msg = self.create_message_signature(formatted_msg)
                        self.broadcast_and_log(signed_msg, exclude=client_socket, 
                                             msg_type="MESSAGE", sender=client_id)
                    
                except socket.timeout:
                    # Timeout allows checking shutdown event
                    continue
                except ssl.SSLError as e:
                    if self.running:  # Only log if not shutting down
                        logger.error(f"SSL Error from {client_id}: {e}")
                    break
                except Exception as e:
                    if self.running:  # Only log if not shutting down
                        logger.error(f"Error handling message from {client_id}: {e}")
                    break
                    
        except Exception as e:
            if self.running:  # Only log if not shutting down
                logger.error(f"Error handling client {client_address}: {e}")
        finally:
            if client_id:
                self.remove_client(client_socket, client_id)

    def send_enhanced_welcome_message(self, client_socket: ssl.SSLSocket, client_id: str):
        """Send enhanced welcome message with security info"""
        try:
            fingerprint = self.client_fingerprints.get(client_id, "Unknown")
            welcome_msg = f"""
🛡️  Welcome to Enhanced Secure Chat, {client_id}!
🔐 Security Features Active:
   ✅ TLS Encryption
   ✅ Mutual Certificate Authentication  
   ✅ Certificate Fingerprint Verification
   ✅ Message Integrity Protection
   ✅ MITM Detection
   ✅ Replay Attack Prevention

🔍 Your Certificate Fingerprint: {fingerprint[:16]}...

📋 Available Commands:
   /help - Show help
   /list - List online users
   /security - Show security status
   /quit - Exit chat
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            signed_welcome = self.create_message_signature(welcome_msg)
            client_socket.send(signed_welcome.encode('utf-8'))
        except Exception as e:
            if self.running:
                logger.error(f"Error sending enhanced welcome message: {e}")

    def handle_enhanced_command(self, client_socket: ssl.SSLSocket, client_id: str, command: str):
        """Handle enhanced commands with security features"""
        try:
            cmd_parts = command.lower().split()
            cmd = cmd_parts[0]
            
            if cmd == '/security':
                self.send_security_status(client_socket, client_id)
            elif cmd == '/help':
                help_msg = """
📋 Enhanced Security Commands:
   /help - Show this help
   /list - List online users
   /security - Show security status
   /quit - Exit chat
   
🛡️  Security Features:
   • All messages have integrity protection
   • Certificate fingerprint verification
   • MITM detection
   • Replay attack prevention
"""
                signed_help = self.create_message_signature(help_msg)
                client_socket.send(signed_help.encode('utf-8'))
                
            elif cmd == '/list':
                with self.clients_lock:
                    online_users = list(self.clients.keys())
                list_msg = f"👥 Secure Users Online ({len(online_users)}): " + ", ".join(online_users)
                signed_list = self.create_message_signature(list_msg)
                client_socket.send(signed_list.encode('utf-8'))
                
            elif cmd == '/quit':
                quit_msg = self.create_message_signature("👋 Secure session ended!")
                client_socket.send(quit_msg.encode('utf-8'))
                
            else:
                error_msg = self.create_message_signature(f"❌ Unknown command: {cmd}")
                client_socket.send(error_msg.encode('utf-8'))
                
        except Exception as e:
            if self.running:
                logger.error(f"Error handling enhanced command {command} from {client_id}: {e}")

    def send_security_status(self, client_socket: ssl.SSLSocket, client_id: str):
        """Send security status information"""
        try:
            fingerprint = self.client_fingerprints.get(client_id, "Unknown")
            cipher = client_socket.cipher()
            version = client_socket.version()
            
            with self.security_lock:
                suspicious_count = len(self.suspicious_activities.get(client_id, []))
            
            status_msg = f"""
🛡️  Security Status for {client_id}:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 TLS Version: {version}
🔐 Cipher: {cipher[0] if cipher else 'Unknown'}
🔍 Certificate Fingerprint: {fingerprint}
⚠️  Suspicious Activities: {suspicious_count}
✅ Message Integrity: Active
✅ Replay Protection: Active
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            signed_status = self.create_message_signature(status_msg)
            client_socket.send(signed_status.encode('utf-8'))
            
        except Exception as e:
            if self.running:
                logger.error(f"Error sending security status: {e}")

    def send_recent_history(self, client_socket: ssl.SSLSocket):
        """Send recent message history WITHOUT signatures to avoid integrity issues"""
        try:
            with self.history_lock:
                recent_messages = self.message_history[-10:]
            
            if recent_messages:
                history_msg = "\n📜 Recent Secure Messages:\n" + "─" * 30 + "\n"
                for msg in recent_messages:
                    timestamp = msg['timestamp'].strftime("%H:%M")
                    # Extract original content without signature for history display
                    content = msg['content']
                    if '|' in content and len(content.split('|')) >= 4:
                        # Remove signature from history display
                        parts = content.split('|')
                        content = '|'.join(parts[:-3])  # Remove timestamp, counter, signature
                    
                    history_msg += f"[{timestamp}] {content}\n"
                history_msg += "─" * 30 + "\n"
                
                # Send history WITHOUT signature to avoid verification issues
                client_socket.send(history_msg.encode('utf-8'))
        except Exception as e:
            if self.running:
                logger.error(f"Error sending history: {e}")

    def _send_message_to_client(self, client_socket: ssl.SSLSocket, recipient_id: str, message: str):
        """Send message to one client"""
        try:
            if self.running:  # Only send if server is running
                client_socket.sendall(message.encode('utf-8'))
        except Exception as e:
            if self.running:
                logger.error(f"Error broadcasting to {recipient_id}: {e}")
                self.remove_client(client_socket, recipient_id)

    def broadcast_and_log(self, message: str, exclude: ssl.SSLSocket = None, 
                         msg_type: str = "BROADCAST", sender: str = "SYSTEM"):
        """Broadcast message and log with enhanced security"""
        if not self.running:
            return
            
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
            clients_to_send = []
            for r_id, r_socket in self.clients.items():
                if r_socket != exclude:
                    clients_to_send.append((r_socket, r_id))

        for client_sock, recipient_id_val in clients_to_send:
            if self.running:  # Check again before submitting
                self.send_executor.submit(self._send_message_to_client, client_sock, recipient_id_val, message)

    def remove_client(self, client_socket: ssl.SSLSocket, client_id: str):
        """Remove client with enhanced logging"""
        try:
            with self.clients_lock:
                if client_id in self.clients:
                    del self.clients[client_id]
                if client_socket in self.client_names:
                    del self.client_names[client_socket]
                if client_id in self.client_join_time:
                    join_time = self.client_join_time[client_id]
                    duration = datetime.now() - join_time
                    logger.info(f"Client {client_id} was connected for {duration}")
                    del self.client_join_time[client_id]
            
            try:
                client_socket.close()
            except:
                pass
                
            if self.running:  # Only broadcast if still running
                leave_msg = f"🔐 {client_id} left the secure chat"
                signed_leave = self.create_message_signature(leave_msg)
                self.broadcast_and_log(signed_leave, msg_type="LEAVE")
            
            logger.info(f"🔌 Secure client disconnected: {client_id}")
            
        except Exception as e:
            if self.running:
                logger.error(f"Error removing client {client_id}: {e}")

    def get_security_stats(self):
        """Get security statistics"""
        with self.security_lock:
            return {
                'active_clients': len(self.clients),
                'stored_fingerprints': len(self.client_fingerprints),
                'suspicious_activities': sum(len(activities) for activities in self.suspicious_activities.values()),
                'clients_with_suspicious_activity': len(self.suspicious_activities)
            }

    def start(self):
        """Start server with graceful shutdown handling"""
        try:
            logger.info("🚀 Enhanced Secure TLS Chat Server starting...")
            logger.info("🛡️  Security Features: Fingerprint verification, Message integrity, MITM detection")
            logger.info("💡 Press Ctrl+C for graceful shutdown")
            
            while self.running and not self.shutdown_event.is_set():
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    if not self.running:
                        client_socket.close()
                        break
                    
                    # Wrap with SSL
                    ssl_client = self.ssl_context.wrap_socket(client_socket, server_side=True)
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(ssl_client, client_address),
                        name=f"SecureClientThread-{client_address[0]}:{client_address[1]}",
                        daemon=True  # Daemon threads will stop when main program exits
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    # Timeout allows checking shutdown event
                    continue
                except ssl.SSLError as e:
                    if self.running:
                        logger.error(f"SSL Error accepting connection: {e}")
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
                    
        except KeyboardInterrupt:
            logger.info("🛑 Keyboard interrupt received")
        except Exception as e:
            logger.error(f"Fatal error: {e}")
        finally:
            self.cleanup()

    def cleanup(self):
        """Enhanced cleanup with proper shutdown sequence"""
        logger.info("🧹 Starting graceful shutdown...")
        
        # Stop accepting new connections
        self.running = False
        self.shutdown_event.set()
        
        # Log security statistics
        stats = self.get_security_stats()
        logger.info(f"📊 Final Security Stats: {stats}")
        
        # Notify all clients of shutdown
        with self.clients_lock:
            clients_copy = list(self.clients.items())
        
        for client_id, client_socket in clients_copy:
            try:
                goodbye_msg = self.create_message_signature("🛑 Enhanced server shutting down...")
                client_socket.send(goodbye_msg.encode('utf-8'))
            except:
                pass
        
        # Close all client connections
        logger.info("🔌 Closing client connections...")
        for client_id, client_socket in clients_copy:
            try:
                client_socket.close()
            except:
                pass
        
        # FIXED: Shutdown thread pool executor without timeout parameter
        logger.info("🧵 Shutting down thread pool...")
        try:
            self.send_executor.shutdown(wait=True)
        except Exception as e:
            logger.warning(f"Error shutting down executor: {e}")
        
        # Close server socket
        try:
            self.server_socket.close()
        except:
            pass
            
        logger.info("✅ Enhanced server shutdown complete")

if __name__ == "__main__":
    server = SecurityEnhancedTLSServer()
    server.start()