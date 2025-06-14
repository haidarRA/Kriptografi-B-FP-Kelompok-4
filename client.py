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
    def __init__(self, host: str = 'localhost', port: int = 8443, gui_mode: bool = False):
        self.host = host
        self.port = port
        self.connected = False
        self.client_id = None
        self.cert_info = None
        self.gui_mode = gui_mode
        self.gui = None
        self.previous_connection_status = None
        
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
        """Verifikasi sertifikat server"""
        try:
            cert = self.ssl_socket.getpeercert()
            if not cert:
                self.log_message("Server tidak memiliki sertifikat yang valid", "ERROR")
                return False
                
            # Verifikasi fingerprint
            fingerprint = self.ssl_socket.getpeercert(binary_form=True)
            if not fingerprint:
                self.log_message("Tidak dapat mendapatkan fingerprint sertifikat server", "ERROR")
                return False
                
            self.log_message("Sertifikat server valid")
            return True
        except Exception as e:
            self.log_message(f"Error verifikasi sertifikat: {e}", "ERROR")
            return False

    def get_certificate_info(self) -> Optional[dict]:
        """Mendapatkan informasi sertifikat client"""
        try:
            cert = self.ssl_socket.getpeercert()
            if not cert:
                return None
                
            return {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
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
            # Wrap socket dengan SSL
            self.ssl_socket = self.ssl_context.wrap_socket(
                self.socket,
                server_hostname=self.host
            )
            
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
            
            # Jika CLI mode, mulai message loop
            if not self.gui_mode:
                self.message_loop()
                
        except Exception as e:
            self.log_message(f"Error koneksi: {e}", "ERROR")
            self.connected = False
            if not self.gui_mode and self.previous_connection_status != self.connected:
                self.previous_connection_status = self.connected
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

    def message_loop(self):
        """Loop utama untuk mengirim pesan (CLI mode)"""
        while self.connected:
            try:
                message = input()
                if not message:
                    continue
                    
                if message.lower() == '/quit':
                    self.send_message('/quit')
                    break
                elif message.lower() == '/status':
                    self.print_connection_status()
                elif message.lower() == '/cert':
                    if self.cert_info:
                        print("\nInfo Sertifikat Client:")
                        for key, value in self.cert_info.items():
                            print(f"  {key}: {value}")
                    else:
                        print("Tidak dapat mendapatkan info sertifikat")
                else:
                    self.send_message(message)
                    
            except KeyboardInterrupt:
                print("\nMengakhiri koneksi...")
                break
            except Exception as e:
                self.log_message(f"Error dalam message loop: {e}", "ERROR")
                break

    def receive_messages(self):
        """Thread untuk menerima pesan"""
        try:
            while self.connected:
                try:
                    message = self.ssl_socket.recv(1024).decode('utf-8')
                    if not message:
                        break
                    
                    # Format pesan yang diterima
                    formatted_message = f"Pesan baru diterima: {message}"
                    
                    if self.gui_mode:
                        self.message_queue.put(formatted_message)
                    else:
                        print(formatted_message)
                        
                except ssl.SSLError as e:
                    self.log_message(f"SSL Error: {e}", "ERROR")
                    break
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log_message(f"Error menerima pesan: {e}", "ERROR")
                    break
        finally:
            self.connected = False
            if not self.gui_mode and self.previous_connection_status != self.connected:
                self.previous_connection_status = self.connected

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
        """Membersihkan resources"""
        try:
            if self.ssl_socket:
                self.ssl_socket.close()
            if self.socket:
                self.socket.close()
        except Exception as e:
            self.log_message(f"Error saat cleanup: {e}", "ERROR")
        finally:
            self.connected = False

    def get_connection_status(self) -> str:
        """Mendapatkan status koneksi untuk GUI"""
        if self.connected:
            return f"Terhubung ke {self.host}:{self.port} sebagai {self.client_id}"
        else:
            return f"Terputus dari {self.host}:{self.port}"

class ChatGUI:
    def __init__(self, client: TLSChatClient):
        self.client = client
        self.client.set_gui(self)
        
        # Membuat window utama
        self.root = tk.Tk()
        self.root.title("TLS Chat Client")
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.setup_ui()
        
        # Timer untuk update status dan pesan
        self.update_timer()
        
    def setup_ui(self):
        """Setup user interface"""
        # Frame utama
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Status Connection
        status_frame = ttk.LabelFrame(main_frame, text="Status Koneksi", padding="5")
        status_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)
        
        self.status_label = ttk.Label(status_frame, text="Belum terhubung", font=("Arial", 10))
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        # Connect/Disconnect Button
        self.connect_button = ttk.Button(status_frame, text="Connect", command=self.toggle_connection)
        self.connect_button.grid(row=0, column=1, sticky=tk.E)
        
        # Messages Display
        messages_frame = ttk.LabelFrame(main_frame, text="Pesan", padding="5")
        messages_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        messages_frame.columnconfigure(0, weight=1)
        messages_frame.rowconfigure(0, weight=1)
        
        self.messages_text = scrolledtext.ScrolledText(messages_frame, wrap=tk.WORD, height=15)
        self.messages_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.messages_text.config(state=tk.DISABLED)
        
        # Message Input
        input_frame = ttk.LabelFrame(main_frame, text="Kirim Pesan", padding="5")
        input_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        
        self.message_entry = ttk.Entry(input_frame, font=("Arial", 10))
        self.message_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)
        
        self.send_button = ttk.Button(input_frame, text="Kirim", command=self.send_message)
        self.send_button.grid(row=0, column=1)
        
        # Logs Display
        logs_frame = ttk.LabelFrame(main_frame, text="Log Aktivitas", padding="5")
        logs_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        logs_frame.columnconfigure(0, weight=1)
        logs_frame.rowconfigure(0, weight=1)
        
        self.logs_text = scrolledtext.ScrolledText(logs_frame, wrap=tk.WORD, height=10)
        self.logs_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.logs_text.config(state=tk.DISABLED)

    def update_timer(self):
        """Timer untuk update status dan pesan"""
        self.update_status()
        self.process_messages()
        self.process_logs()
        self.root.after(100, self.update_timer)  # Update setiap 100ms

    def update_status(self):
        """Update status koneksi"""
        status = self.client.get_connection_status()
        self.status_label.config(text=status)
        
        if self.client.connected:
            self.connect_button.config(text="Disconnect")
            self.send_button.config(state=tk.NORMAL)
            self.message_entry.config(state=tk.NORMAL)
        else:
            self.connect_button.config(text="Connect")
            self.send_button.config(state=tk.DISABLED)
            self.message_entry.config(state=tk.DISABLED)

    def process_messages(self):
        """Proses pesan yang diterima"""
        try:
            while True:
                message = self.client.message_queue.get_nowait()
                self.add_message(message)
        except queue.Empty:
            pass

    def process_logs(self):
        """Proses log yang diterima"""
        try:
            while True:
                log = self.client.log_queue.get_nowait()
                self.add_log(log)
        except queue.Empty:
            pass

    def add_message(self, message: str):
        """Tambahkan pesan ke display"""
        self.messages_text.config(state=tk.NORMAL)
        self.messages_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.messages_text.see(tk.END)
        self.messages_text.config(state=tk.DISABLED)

    def add_log(self, log: str):
        """Tambahkan log ke display"""
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.insert(tk.END, f"{log}\n")
        self.logs_text.see(tk.END)
        self.logs_text.config(state=tk.DISABLED)

    def toggle_connection(self):
        """Toggle koneksi"""
        if self.client.connected:
            self.client.cleanup()
            self.add_log("Koneksi diputus")
        else:
            # Jalankan koneksi di thread terpisah
            connect_thread = threading.Thread(target=self.client.connect)
            connect_thread.daemon = True
            connect_thread.start()

    def send_message(self, event=None):
        """Kirim pesan"""
        message = self.message_entry.get().strip()
        if message and self.client.connected:
            self.client.send_message(message)
            self.message_entry.delete(0, tk.END)
        elif not self.client.connected:
            messagebox.showwarning("Peringatan", "Tidak terhubung ke server!")

    def on_closing(self):
        """Handle window closing"""
        if self.client.connected:
            self.client.cleanup()
        self.root.destroy()

    def run(self):
        """Jalankan GUI"""
        self.root.mainloop()

def main():
    # Tentukan host dari argument
    host = 'localhost'
    if len(sys.argv) > 1:
        host = sys.argv[1]
    
    # Tentukan mode dari argument
    gui_mode = True  # Default ke GUI mode
    if len(sys.argv) > 2 and sys.argv[2] == '--cli':
        gui_mode = False
    
    # Buat client
    client = TLSChatClient(host=host, gui_mode=gui_mode)
    
    if gui_mode:
        # Jalankan GUI
        gui = ChatGUI(client)
        gui.run()
    else:
        # Jalankan CLI
        client.connect()

if __name__ == "__main__":
    main()