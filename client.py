import ssl
import socket
import threading
import logging
import sys
import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
from typing import Optional
import queue
import argparse
import hashlib # Ditambahkan untuk fingerprint

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
    def __init__(self, host: str = 'localhost', port: int = 8443, gui_mode: bool = False, expected_server_fingerprint: Optional[str] = None): # Ditambahkan expected_server_fingerprint
        self.host = host
        self.port = port
        self.connected = False
        self.client_id = None
        self.cert_info = None
        self.gui_mode = gui_mode
        self.gui = None
        self.previous_connection_status = None
        self.expected_server_fingerprint = expected_server_fingerprint # Ditambahkan
        
        # Queue untuk komunikasi antara threads
        self.message_queue = queue.Queue()
        self.log_queue = queue.Queue()
        
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
            if not gui_mode:
                sys.exit(1)
        
        # Membuat socket client
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_socket = None

    def set_gui(self, gui):
        """Set GUI reference"""
        self.gui = gui

    def log_message(self, message: str, level: str = "INFO"):
        """Log message ke console dan GUI"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {level}: {message}"
        
        if level == "ERROR":
            logger.error(message)
        elif level == "WARNING":
            logger.warning(message)
        else:
            logger.info(message)
        
        # Kirim ke GUI jika ada
        if self.gui_mode and self.gui:
            self.log_queue.put(formatted_message)

    def verify_server_certificate(self) -> bool:
        """Verifikasi sertifikat server, termasuk fingerprint jika disediakan.""" # Deskripsi diperbarui
        try:
            cert_der = self.ssl_socket.getpeercert(binary_form=True)
            if not cert_der:
                self.log_message("Server tidak menyediakan sertifikat (binary form).", "ERROR")
                return False

            # Calculate SHA-256 fingerprint
            sha256_fingerprint = hashlib.sha256(cert_der).hexdigest()
            self.log_message(f"Fingerprint SHA-256 sertifikat server: {sha256_fingerprint}", "INFO")

            if self.expected_server_fingerprint:
                if sha256_fingerprint.lower() == self.expected_server_fingerprint.lower():
                    self.log_message("Fingerprint sertifikat server cocok dengan yang diharapkan.", "INFO")
                    return True
                else:
                    self.log_message(f"PERINGATAN MITM? Fingerprint server ({sha256_fingerprint}) TIDAK COCOK dengan yang diharapkan ({self.expected_server_fingerprint}).", "ERROR")
                    return False
            else:
                # Jika tidak ada fingerprint yang diharapkan, anggap valid jika sertifikat ada (CA check sudah dilakukan oleh SSLContext)
                self.log_message("Tidak ada fingerprint server yang diharapkan untuk diverifikasi. Mengandalkan validasi CA.", "WARNING")
                return True
                
        except Exception as e:
            self.log_message(f"Error verifikasi sertifikat server: {e}", "ERROR")
            return False

    def get_certificate_info(self) -> Optional[dict]:
        """Mendapatkan informasi sertifikat client"""
        try:
            # Dapatkan sertifikat client, bukan server
            cert = self.ssl_socket.getpeercert(binary_form=False)
            if not cert:
                return None
                
            # Pastikan kita mendapatkan informasi dari sertifikat client
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            
            # Log untuk debugging
            self.log_message(f"Certificate subject: {subject}")
            self.log_message(f"Certificate issuer: {issuer}")
            
            return {
                'subject': subject,
                'issuer': issuer,
                'version': cert['version'],
                'notBefore': cert['notBefore'],
                'notAfter': cert['notAfter']
            }
        except Exception as e:
            self.log_message(f"Error mendapatkan info sertifikat: {e}", "ERROR")
            return None

    def connect(self):
        """Melakukan koneksi ke server"""
        try:
            # Pastikan socket dalam keadaan bersih
            if self.socket:
                self.socket.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Wrap socket dengan SSL
            self.ssl_socket = self.ssl_context.wrap_socket(
                self.socket,
                server_hostname=self.host
            )
            
            # Set timeout untuk koneksi
            self.ssl_socket.settimeout(10)
            
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
            self.log_message(f"Terhubung ke server sebagai {self.client_id}")
            
            # Tampilkan status koneksi hanya jika berubah (untuk CLI)
            if not self.gui_mode and self.previous_connection_status != self.connected:
                self.print_connection_status()
                self.previous_connection_status = self.connected
            
            # Memulai thread untuk menerima pesan
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()

            # Memulai thread untuk mengirim pesan dari input pengguna (jika CLI)
            if not self.gui_mode:
                send_thread = threading.Thread(target=self.send_input_messages)
                send_thread.daemon = True
                send_thread.start()
            
        except Exception as e:
            self.log_message(f"Error koneksi: {e}", "ERROR")
            self.connected = False
            if not self.gui_mode and self.previous_connection_status != self.connected:
                self.previous_connection_status = self.connected
            # Pastikan socket ditutup jika koneksi gagal
            self.cleanup()
        finally:
            if not self.gui_mode:
                self.cleanup()

    def print_connection_status(self):
        """Menampilkan status koneksi dan info sertifikat (hanya untuk CLI)"""
        if self.gui_mode:
            return
            
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

    def send_input_messages(self):
        """Loop untuk mengirim pesan dari input pengguna (hanya untuk CLI)."""
        if self.gui_mode:
            return

        try:
            while self.connected:
                message = input("Anda: ") # Blocking input
                if not self.connected: # Cek koneksi lagi setelah input, karena bisa terputus saat menunggu input
                    break
                if message.strip():
                    self.send_message(message)
                if message.lower() == '/quit':
                    break
        except EOFError: # Terjadi jika input stream ditutup (misalnya, jika stdin dialihkan dan file berakhir)
            self.log_message("Input stream berakhir, menutup koneksi.", "INFO")
        except KeyboardInterrupt: # Ctrl+C
            self.log_message("Perintah keluar diterima (Ctrl+C), menutup koneksi.", "INFO")
        finally:
            if self.connected:
                self.send_message("/quit") # Kirim /quit jika belum
            self.cleanup()

    def receive_messages(self):
        """Menerima pesan dari server dan menampilkannya."""
        try:
            while self.connected:
                try:
                    # Set timeout pada socket receive agar tidak blocking selamanya
                    self.ssl_socket.settimeout(1.0) # Timeout 1 detik
                    data = self.ssl_socket.recv(1024)
                    if not data:
                        self.log_message("Koneksi ditutup oleh server.", "WARNING")
                        self.connected = False
                        break

                    message = data.decode('utf-8').strip()
                    if message.startswith("ERROR: Anda tidak terdaftar di server ini."):
                        self.log_message(message, "ERROR")
                        self.connected = False # Tandai sebagai tidak terkoneksi
                        if self.gui_mode and self.gui:
                            self.gui.show_error_and_close(message)
                        else:
                            print(f"SERVER: {message}")
                        break # Hentikan thread penerima
                    
                    if self.gui_mode and self.gui:
                        self.message_queue.put(message)
                    else:
                        print(f"{message}") # Cetak langsung untuk CLI
                        
                except socket.timeout:
                    # Timeout adalah normal, lanjutkan loop untuk memeriksa status koneksi
                    if not self.connected: # Jika koneksi terputus saat timeout
                        break
                    continue
                except ssl.SSLError as e:
                    if 'timed out' in str(e).lower() or 'Want read' in str(e):
                        logger.warning(f"SSL read timed out/want read, mencoba lagi.")
                        if not self.connected:
                            break
                        continue
                    self.log_message(f"SSL Error: {e}", "ERROR")
                    self.connected = False
                    break
                except Exception as e:
                    if self.connected: # Hanya log jika masih terkoneksi
                        self.log_message(f"Error menerima pesan: {e}", "ERROR")
                    self.connected = False
                    break
        finally:
            self.connected = False # Pastikan status connected diupdate
            if not self.gui_mode:
                print("Koneksi terputus. Tekan Enter untuk keluar.")
            elif self.gui_mode and self.gui:
                self.gui.update_connection_status(False)
            self.cleanup()

    def send_message(self, message: str):
        """Mengirim pesan ke server"""
        try:
            if not self.connected:
                raise Exception("Tidak terhubung ke server")
            
            self.ssl_socket.send(message.encode('utf-8'))
            self.log_message(f"Pesan terkirim: {message}")
            
        except Exception as e:
            self.log_message(f"Error mengirim pesan: {e}", "ERROR")
            self.connected = False

    def cleanup(self):
        """Membersihkan resource dan menutup koneksi"""
        try:
            if self.ssl_socket:
                try:
                    self.ssl_socket.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                self.ssl_socket.close()
                self.ssl_socket = None
            
            if self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                self.socket.close()
                self.socket = None
            
            self.connected = False
            self.client_id = None
            self.cert_info = None
            
        except Exception as e:
            self.log_message(f"Error saat cleanup: {e}", "ERROR")

    def get_connection_status(self) -> str:
        """Mendapatkan status koneksi untuk GUI"""
        if self.connected:
            return f"Terhubung ke {self.host}:{self.port} sebagai {self.client_id}"
        else:
            return f"Terputus dari {self.host}:{self.port}"

class ChatGUI:
    def __init__(self, client: TLSChatClient):
        self.client = client
        self.root = tk.Tk()
        self.root.title(f"Chat Client - {client.client_id}")
        self.root.geometry("800x600")
        self.setup_ui()
        
        # Start connection
        self.connect_thread = threading.Thread(target=self.client.connect)
        self.connect_thread.daemon = True
        self.connect_thread.start()
        
        # Start message processing
        self.process_messages()
        self.process_logs()
        
        # Setup window close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Chat display
        self.chat_display = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=20)
        self.chat_display.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.chat_display.config(state=tk.DISABLED)
        
        # Log display
        self.log_display = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=8)
        self.log_display.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.log_display.config(state=tk.DISABLED)
        
        # Message input
        self.message_input = ttk.Entry(main_frame)
        self.message_input.grid(row=2, column=0, sticky=(tk.W, tk.E))
        self.message_input.bind('<Return>', self.send_message)
        
        # Send button
        send_button = ttk.Button(main_frame, text="Kirim", command=self.send_message)
        send_button.grid(row=2, column=1, sticky=(tk.E))
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Status: Menghubungkan...")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=3)
        main_frame.rowconfigure(1, weight=1)

    def process_messages(self):
        """Process messages from queue"""
        try:
            while True:
                message = self.client.message_queue.get_nowait()
                self.add_message(message)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_messages)

    def process_logs(self):
        """Process logs from queue"""
        try:
            while True:
                log = self.client.log_queue.get_nowait()
                self.add_log(log)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_logs)

    def add_message(self, message: str):
        """Add message to chat display"""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)

    def add_log(self, log: str):
        """Add log to log display"""
        self.log_display.config(state=tk.NORMAL)
        self.log_display.insert(tk.END, log + "\n")
        self.log_display.see(tk.END)
        self.log_display.config(state=tk.DISABLED)

    def send_message(self, event=None):
        """Send message to server"""
        message = self.message_input.get().strip()
        if message:
            self.client.send_message(message)
            self.message_input.delete(0, tk.END)

    def on_closing(self):
        """Handle window closing"""
        if messagebox.askokcancel("Keluar", "Apakah Anda yakin ingin keluar?"):
            self.client.cleanup()
            self.root.destroy()

    def run(self):
        """Start the GUI main loop"""
        self.root.mainloop()

def main():
    parser = argparse.ArgumentParser(description='TLS Chat Client')
    parser.add_argument('--cert', type=str, default='client1',
                      help='Nama sertifikat yang akan digunakan (tanpa ekstensi .crt)')
    parser.add_argument('--host', type=str, default='localhost',
                      help='Host server')
    parser.add_argument('--port', type=int, default=8443,
                      help='Port server')
    parser.add_argument('--cli', action='store_true',
                      help='Gunakan mode CLI (tanpa GUI)')
    parser.add_argument('--server_fingerprint', type=str, default=None, # Argumen baru
                      help='Fingerprint SHA-256 yang diharapkan dari sertifikat server (hex)')
    args = parser.parse_args()
    
    # Buat client
    client = TLSChatClient(
        host=args.host, 
        port=args.port, 
        gui_mode=not args.cli,
        expected_server_fingerprint=args.server_fingerprint # Teruskan fingerprint
    )
    
    # Atur ulang SSL context untuk client instance agar menggunakan sertifikat yang benar
    try:
        client.ssl_context.load_verify_locations('certs/ca.crt')
        client.ssl_context.load_cert_chain(
            certfile=f'certs/{args.cert}.crt',
            keyfile=f'certs/{args.cert}.key'
        )
    except Exception as e:
        logger.error(f"Error loading sertifikat ({args.cert}): {e}")
        if not client.gui_mode:
            sys.exit(1)
        else:
            # Untuk GUI, kita mungkin ingin menangani ini di dalam GUI
            messagebox.showerror("Error Sertifikat", f"Gagal memuat sertifikat '{args.cert}.crt' atau '{args.cert}.key'. Pastikan file ada dan benar. Error: {e}")
            sys.exit(1)


    if client.gui_mode:
        gui = ChatGUI(client)
        client.set_gui(gui)
        gui.run()
    else:
        client.connect()

if __name__ == "__main__":
    main()