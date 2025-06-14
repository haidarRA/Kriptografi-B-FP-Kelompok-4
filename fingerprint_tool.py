import hashlib
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import argparse
import sys

def calculate_cert_fingerprint(cert_path: str) -> str:
    """Calculate SHA-256 fingerprint of certificate file"""
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        
        # Parse certificate
        cert = x509.load_pem_x509_certificate(cert_data)
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        
        # Calculate fingerprint
        fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
        return fingerprint
    
    except Exception as e:
        print(f"Error calculating fingerprint: {e}")
        return None

def get_remote_cert_fingerprint(host: str, port: int) -> str:
    """Get certificate fingerprint from remote server"""
    try:
        # Create SSL context that doesn't verify certificates (for fingerprint checking)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert_chain()[0].public_bytes(serialization.Encoding.DER)
                fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
                return fingerprint
                
    except Exception as e:
        print(f"Error getting remote certificate: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Certificate Fingerprint Tool')
    parser.add_argument('--file', '-f', help='Calculate fingerprint of certificate file')
    parser.add_argument('--remote', '-r', help='Get fingerprint from remote server (host:port)')
    parser.add_argument('--verify', '-v', nargs=2, metavar=('cert_file', 'expected_fingerprint'), 
                       help='Verify certificate against expected fingerprint')
    
    args = parser.parse_args()
    
    if args.file:
        print(f"📄 Calculating fingerprint for: {args.file}")
        fingerprint = calculate_cert_fingerprint(args.file)
        if fingerprint:
            print(f"🔍 SHA-256 Fingerprint: {fingerprint}")
            print(f"🔍 Formatted: {':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))}")
        else:
            sys.exit(1)
    
    elif args.remote:
        try:
            host, port = args.remote.split(':')
            port = int(port)
            print(f"🌐 Getting certificate from: {host}:{port}")
            fingerprint = get_remote_cert_fingerprint(host, port)
            if fingerprint:
                print(f"🔍 Remote SHA-256 Fingerprint: {fingerprint}")
                print(f"🔍 Formatted: {':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))}")
            else:
                sys.exit(1)
        except ValueError:
            print("❌ Invalid format. Use host:port")
            sys.exit(1)
    
    elif args.verify:
        cert_file, expected = args.verify
        print(f"🔒 Verifying certificate: {cert_file}")
        actual = calculate_cert_fingerprint(cert_file)
        if actual:
            print(f"📄 Certificate fingerprint: {actual}")
            print(f"🎯 Expected fingerprint:   {expected.upper()}")
            if actual == expected.upper():
                print("✅ Certificate fingerprint MATCHES - Verified!")
            else:
                print("❌ Certificate fingerprint MISMATCH - SECURITY WARNING!")
                sys.exit(1)
        else:
            sys.exit(1)
    
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python fingerprint_tool.py -f certs/server.crt")
        print("  python fingerprint_tool.py -r localhost:8443")
        print("  python fingerprint_tool.py -v certs/server.crt ABC123...")

if __name__ == "__main__":
    main()