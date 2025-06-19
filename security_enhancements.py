import hashlib
import hmac
import json
import time
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography import x509  # ✅ Tambahan import yang missing
import logging

logger = logging.getLogger(__name__)

class MessageSecurity:
    def __init__(self, cert_path: str, key_path: str):
        """Initialize with certificate and private key paths"""
        try:
            # Load private key for signing
            with open(key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            
            # ✅ FIXED: Load certificate for public key
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
                self.certificate = x509.load_pem_x509_certificate(cert_data)  # ✅ Perbaikan disini
                self.public_key = self.certificate.public_key()
            
            logger.info("MessageSecurity initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize MessageSecurity: {e}")
            raise

    def sign_message(self, message: str, sender_id: str) -> str:
        """Sign a message and return JSON string with signature"""
        try:
            timestamp = time.time()
            message_data = {
                'content': message,
                'sender': sender_id,
                'timestamp': timestamp
            }
            
            # Create message hash
            message_bytes = json.dumps(message_data, sort_keys=True).encode('utf-8')
            message_hash = hashlib.sha256(message_bytes).hexdigest()
            
            # Create digital signature
            signature = self.private_key.sign(
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            signed_message = {
                'message_data': message_data,
                'signature': signature.hex(),
                'hash': message_hash
            }
            
            return json.dumps(signed_message)
            
        except Exception as e:
            logger.error(f"Failed to sign message: {e}")
            # Fallback: return unsigned message
            return json.dumps({'message_data': {'content': message, 'sender': sender_id, 'timestamp': time.time()}})

    def verify_message(self, signed_message_json: str, sender_public_key=None) -> dict:
        """Verify message signature and return message data"""
        try:
            signed_data = json.loads(signed_message_json)
            
            # Check if message is signed
            if 'signature' not in signed_data:
                # Unsigned message - just return the content
                return {
                    'verified': False,
                    'content': signed_data.get('message_data', {}).get('content', ''),
                    'sender': signed_data.get('message_data', {}).get('sender', 'Unknown'),
                    'timestamp': signed_data.get('message_data', {}).get('timestamp', time.time())
                }
            
            message_data = signed_data['message_data']
            signature = bytes.fromhex(signed_data['signature'])
            original_hash = signed_data['hash']
            
            # Verify integrity
            message_bytes = json.dumps(message_data, sort_keys=True).encode('utf-8')
            current_hash = hashlib.sha256(message_bytes).hexdigest()
            
            if current_hash != original_hash:
                logger.warning("Message integrity check failed")
                return {'verified': False, 'content': message_data.get('content', ''), 'sender': message_data.get('sender', 'Unknown')}
            
            # Verify signature (use sender's public key if provided, otherwise use own)
            public_key = sender_public_key if sender_public_key else self.public_key
            
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return {
                'verified': True,
                'content': message_data['content'],
                'sender': message_data['sender'],
                'timestamp': message_data['timestamp']
            }
            
        except (InvalidSignature, json.JSONDecodeError) as e:
            logger.warning(f"Message verification failed: {e}")
            # Try to extract content anyway
            try:
                data = json.loads(signed_message_json)
                return {
                    'verified': False,
                    'content': data.get('message_data', {}).get('content', signed_message_json),
                    'sender': data.get('message_data', {}).get('sender', 'Unknown')
                }
            except:
                return {'verified': False, 'content': signed_message_json, 'sender': 'Unknown'}
        except Exception as e:
            logger.error(f"Unexpected error in message verification: {e}")
            return {'verified': False, 'content': signed_message_json, 'sender': 'Unknown'}


class MITMDetector:
    def __init__(self):
        self.known_fingerprints = {}
        self.security_events = []
    
    def verify_server_fingerprint(self, ssl_socket, expected_fingerprint: str = None) -> bool:
        """Basic MITM detection through server fingerprint verification"""
        try:
            # Get peer certificate
            cert = ssl_socket.getpeercert(binary_form=True)
            if not cert:
                self.log_security_event("NO_CERTIFICATE", {"reason": "Server provided no certificate"})
                return False
            
            # Calculate current fingerprint
            current_fingerprint = hashlib.sha256(cert).hexdigest().lower()
            
            # Check against expected fingerprint
            if expected_fingerprint and current_fingerprint != expected_fingerprint.lower():
                self.log_security_event("FINGERPRINT_MISMATCH", {
                    'expected': expected_fingerprint,
                    'actual': current_fingerprint
                })
                return False
            
            # Store/check against known fingerprint
            server_id = ssl_socket.getpeername()
            if server_id in self.known_fingerprints:
                if self.known_fingerprints[server_id] != current_fingerprint:
                    self.log_security_event("FINGERPRINT_CHANGED", {
                        'server': server_id,
                        'previous': self.known_fingerprints[server_id],
                        'current': current_fingerprint
                    })
                    return False
            else:
                self.known_fingerprints[server_id] = current_fingerprint
                logger.info(f"Server fingerprint stored: {current_fingerprint[:16]}...")
            
            return True
            
        except Exception as e:
            self.log_security_event("VERIFICATION_ERROR", {'error': str(e)})
            return False
    
    def log_security_event(self, event_type: str, details: dict):
        """Log security events"""
        event = {
            'timestamp': time.time(),
            'type': event_type,
            'details': details
        }
        self.security_events.append(event)
        logger.warning(f"SECURITY EVENT: {event_type} - {details}")