import ssl
import socket
import threading
import logging
import hashlib
import hmac
import json
import time
import sys
import base64
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import os

# Enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('enhanced_client.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SecurityEnhancedTLSClient:
    def __init__(self, host: str = 'localhost', port: int = 8443):
        self.host = host
        self.port = port
        self.client_socket = None
        self.ssl_socket = None
        self.is_connected = False
        self.receive_thread = None
        
        # Security enhancement attributes
        self.expected_server_fingerprint = None
        self.session_key = None
        self.message_counter = 0
        self.server_cert_fingerprint = None
        
        # Message integrity secret (shared with server)
        self.integrity_key = b'shared_secret_key_for_integrity_2024'
        
        # Load expected server fingerprint if exists
        self.load_server_fingerprint()
        
        # SSL Context configuration
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.check_hostname = False
        self.ssl_context.load_cert_chain(
            certfile='certs/client.crt',
            keyfile='certs/client.key'
        )
        self.ssl_context.load_verify_locations('certs/ca.crt')

    def load_server_fingerprint(self):
        """Load expected server certificate fingerprint from file"""
        try:
            with open('server_fingerprint.txt', 'r') as f:
                self.expected_server_fingerprint = f.read().strip()
                logger.info("✅ Server fingerprint dimuat dari file")
        except FileNotFoundError:
            logger.warning("⚠️  File server fingerprint tidak ditemukan - akan melakukan verifikasi manual")

    def save_server_fingerprint(self, fingerprint: str):
        """Save server certificate fingerprint to file"""
        try:
            with open('server_fingerprint.txt', 'w') as f:
                f.write(fingerprint)
            logger.info("💾 Server fingerprint disimpan ke file")
        except Exception as e:
            logger.error(f"❌ Gagal menyimpan fingerprint: {e}")

    def calculate_cert_fingerprint(self, cert_der: bytes) -> str:
        """Calculate SHA-256 fingerprint of certificate"""
        return hashlib.sha256(cert_der).hexdigest().upper()

    def verify_server_certificate(self) -> bool:
        """Enhanced server certificate verification with fingerprint checking"""
        try:
            # Get server certificate
            cert_der = self.ssl_socket.getpeercert(binary_form=True)
            if not cert_der:
                logger.error("❌ No certificate received from server")
                return False
            
            # Calculate fingerprint
            current_fingerprint = self.calculate_cert_fingerprint(cert_der)
            self.server_cert_fingerprint = current_fingerprint
            
            logger.info(f"🔍 Server Certificate Fingerprint: {current_fingerprint}")
            
            # Check against expected fingerprint
            if self.expected_server_fingerprint:
                if current_fingerprint == self.expected_server_fingerprint:
                    logger.info("✅ Server certificate fingerprint VALID")
                    return True
                else:
                    logger.error("❌ MITM DETECTION: Server certificate fingerprint MISMATCH!")
                    logger.error(f"Expected: {self.expected_server_fingerprint}")
                    logger.error(f"Received: {current_fingerprint}")
                    
                    # Ask user decision
                    response = input("⚠️  PERINGATAN KEAMANAN: Fingerprint sertifikat tidak cocok!\n"
                                   "Ini bisa mengindikasikan serangan MITM.\n"
                                   "Lanjutkan koneksi? (yes/no): ").lower()
                    
                    if response in ['yes', 'y']:
                        logger.warning("⚠️  User memilih melanjutkan koneksi meskipun fingerprint berbeda")
                        return True
                    else:
                        logger.info("🛡️  Koneksi dibatalkan demi keamanan")
                        return False
            else:
                # First time connection - save fingerprint
                logger.info("📝 First time connection - menyimpan fingerprint server")
                self.save_server_fingerprint(current_fingerprint)
                return True
                
        except Exception as e:
            logger.error(f"❌ Error verifying server certificate: {e}")
            return False

    def create_message_signature(self, message: str) -> str:
        """Create HMAC signature for message integrity"""
        timestamp = str(int(time.time()))
        counter = str(self.message_counter)
        data_to_sign = f"{message}|{timestamp}|{counter}"
        
        signature = hmac.new(
            self.integrity_key,
            data_to_sign.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        self.message_counter += 1
        return f"{message}|{timestamp}|{counter}|{signature}"

    def verify_message_signature(self, signed_message: str) -> tuple:
        """Verify message signature and return (is_valid, original_message)"""
        try:
            parts = signed_message.split('|')
            if len(parts) < 4:
                return True, signed_message  # Message without signature
            
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
                logger.warning(f"❌ Message signature verification failed")
                return False, message
            
            # FIXED: Check if this is a history message - skip timestamp validation
            history_indicators = ["Recent Secure Messages", "Welcome to Enhanced", "[2", "📜", "─", "━"]
            is_history = any(indicator in message for indicator in history_indicators)
            
            if not is_history:
                # Check timestamp only for live messages (not history)
                current_time = int(time.time())
                msg_time = int(timestamp)
                if current_time - msg_time > 300:  # 5 minutes
                    logger.warning("⚠️  Pesan terlalu lama (possible replay attack)")
                    return False, message
            
            if not is_history:
                logger.debug(f"✅ Message integrity verified: {message[:50]}...")
            
            return True, message
            
        except Exception as e:
            logger.error(f"Error verifying message signature: {e}")
            return False, signed_message

    def detect_mitm_indicators(self):
        """Detect basic MITM indicators"""
        indicators = []
        
        # Check certificate details
        try:
            cert = self.ssl_socket.getpeercert()
            if cert:
                not_before = cert.get('notBefore', '')
                not_after = cert.get('notAfter', '')
                
                if not_before and not_after:
                    logger.info(f"Certificate validity: {not_before} to {not_after}")
            
        except Exception as e:
            logger.error(f"Error checking certificate details: {e}")
            indicators.append("Could not verify certificate details")
        
        # Check TLS version and cipher
        try:
            version = self.ssl_socket.version()
            cipher = self.ssl_socket.cipher()
            
            if version not in ['TLSv1.2', 'TLSv1.3']:
                indicators.append(f"Weak TLS version: {version}")
            
            if cipher and 'RC4' in cipher[0]:
                indicators.append("Weak cipher detected")
                
        except Exception as e:
            logger.error(f"Error checking TLS details: {e}")
        
        return indicators

    def connect(self):
        """Enhanced connect with security checks"""
        try:
            # FIXED: Reset message counter for new connection
            self.message_counter = 0
            logger.info("🔄 Reset message counter for new connection")
            
            logger.info(f"🔐 Connecting to enhanced secure server {self.host}:{self.port}")
            
            # Create socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Wrap with SSL
            self.ssl_socket = self.ssl_context.wrap_socket(
                self.client_socket,
                server_hostname=self.host
            )
            
            # Connect
            self.ssl_socket.connect((self.host, self.port))
            
            # Enhanced security verification
            logger.info("🔍 Performing enhanced security verification...")
            
            # 1. Verify server certificate fingerprint
            if not self.verify_server_certificate():
                logger.error("❌ Server certificate verification failed")
                self.disconnect()
                return False
            
            # 2. Detect MITM indicators
            mitm_indicators = self.detect_mitm_indicators()
            if mitm_indicators:
                logger.warning("⚠️  MITM indicators detected:")
                for indicator in mitm_indicators:
                    logger.warning(f"   - {indicator}")
                
                response = input("Lanjutkan koneksi meskipun ada indikator MITM? (yes/no): ").lower()
                if response not in ['yes', 'y']:
                    logger.info("🛡️  Koneksi dibatalkan karena indikator MITM")
                    self.disconnect()
                    return False
            
            # 3. Log connection details
            cipher = self.ssl_socket.cipher()
            version = self.ssl_socket.version()
            logger.info(f"🔐 TLS Version: {version}")
            logger.info(f"🔐 Cipher: {cipher[0] if cipher else 'Unknown'}")
            logger.info(f"🔐 Server Fingerprint: {self.server_cert_fingerprint}")
            
            self.is_connected = True
            logger.info("✅ Enhanced secure connection established!")
            
            # Start receive thread
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
            
            return True
            
        except ssl.SSLError as e:
            logger.error(f"❌ SSL Error: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Connection error: {e}")
            return False

    def receive_messages(self):
        """Enhanced message receiving with integrity verification"""
        while self.is_connected:
            try:
                data = self.ssl_socket.recv(1024)
                if not data:
                    break
                
                message = data.decode('utf-8')
                
                # Check if message has signature format
                if '|' in message and len(message.split('|')) >= 4:
                    is_valid, original_message = self.verify_message_signature(message)
                    if is_valid:
                        # Don't show ✅ for history messages to keep display clean
                        if any(indicator in original_message for indicator in ["📜", "Welcome", "─", "━"]):
                            print(original_message)
                        else:
                            print(f"✅ {original_message}")
                    else:
                        print(f"⚠️  [INTEGRITY FAILED] {original_message}")
                else:
                    # Message without signature (system message or history)
                    print(message)
                
            except ssl.SSLError as e:
                logger.error(f"SSL Error receiving message: {e}")
                break
            except Exception as e:
                logger.error(f"Error receiving message: {e}")
                break
        
        self.is_connected = False

    def send_message(self, message: str):
        """Enhanced message sending with integrity protection"""
        if not self.is_connected:
            logger.error("❌ Not connected to server")
            return False
        
        try:
            # Add signature for integrity protection
            signed_message = self.create_message_signature(message)
            
            self.ssl_socket.send(signed_message.encode('utf-8'))
            return True
            
        except Exception as e:
            logger.error(f"❌ Error sending message: {e}")
            return False

    def disconnect(self):
        """Disconnect from server"""
        self.is_connected = False
        
        try:
            if self.ssl_socket:
                self.ssl_socket.close()
            if self.client_socket:
                self.client_socket.close()
        except:
            pass
        
        logger.info("🔌 Disconnected from server")

    def start_chat(self):
        """Start interactive chat with enhanced security"""
        if not self.connect():
            return
        
        print("\n" + "="*60)
        print("🛡️  ENHANCED SECURE CHAT CLIENT")
        print("🔐 Features: Fingerprint verification, Message integrity, MITM detection")
        print("Commands: /quit to exit")
        print("="*60 + "\n")
        
        try:
            while self.is_connected:
                message = input()
                if message.lower() == '/quit':
                    break
                
                if message.strip():
                    if not self.send_message(message):
                        break
                    
        except KeyboardInterrupt:
            logger.info("Chat interrupted by user")
        finally:
            self.disconnect()

if __name__ == "__main__":
    client = SecurityEnhancedTLSClient()
    client.start_chat()