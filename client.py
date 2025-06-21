import ssl
import socket
import threading
import logging
import sys
import os
import argparse
import hashlib
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
from datetime import datetime
from typing import Optional
import queue
import json

# Import security enhancements
try:
    from security_enhancements import MessageSecurity, MITMDetector
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    print("WARNING: Security enhancements not available. Install cryptography: pip install cryptography")

# Konfigurasi logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
logger = logging.getLogger(__name__)

# Definisikan kelas TLSChatClient terlebih dahulu
class TLSChatClient:
    def __init__(self, host: str, port: int, cert_path: str, key_path: str, gui_queue: queue.Queue, expected_fingerprint: str = None):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.gui_queue = gui_queue
        self.expected_fingerprint = expected_fingerprint
        self.client_id = os.path.basename(cert_path).split('.')[0]
        self.ssl_socket: Optional[ssl.SSLSocket] = None
        self.stop_event = threading.Event()
        self.history_file = f"history_{self.client_id}.log"
        
        # Initialize security components
        self.message_security = None
        self.mitm_detector = None
        
        if SECURITY_AVAILABLE:
            try:
                self.message_security = MessageSecurity(cert_path, key_path)
                self.mitm_detector = MITMDetector()
                self._update_gui('log', "🔐 Security components initialized")
            except Exception as e:
                self._update_gui('log', f"⚠️ Security initialization failed: {e}")
        else:
            self._update_gui('log', "⚠️ Running without enhanced security features")

    def _update_gui(self, event_type: str, data: any):
        if self.gui_queue:
            self.gui_queue.put({'type': event_type, 'data': data})

    def run(self):
        try:
            self._update_gui('log', f"Mencoba menghubungkan ke {self.host}:{self.port}...")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations('certs/ca.crt')
            context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ssl_socket = context.wrap_socket(sock, server_hostname=self.host)
            self.ssl_socket.connect((self.host, self.port))
            
            # MITM Detection
            if self.mitm_detector and self.expected_fingerprint:
                if not self.mitm_detector.verify_server_fingerprint(self.ssl_socket, self.expected_fingerprint):
                    self._update_gui('log', "🚨 SECURITY WARNING: Server identity verification failed!")
                    self._update_gui('log', "❌ Possible MITM attack detected. Connection terminated.")
                    return
                else:
                    self._update_gui('log', "✅ Server identity verified successfully")
            elif self.expected_fingerprint:
                self._update_gui('log', "⚠️ MITM detection disabled (missing security components)")

            self.ssl_socket.settimeout(1.0)
            self._update_gui('connection_status', {'connected': True, 'client_id': self.client_id})

            while not self.stop_event.is_set():
                try:
                    data = self.ssl_socket.recv(4096)
                    if not data:
                        break
                    
                    raw_message = data.decode('utf-8').strip()
                    
                    # Coba periksa apakah ini pesan JSON (ditandatangani)
                    try:
                        json.loads(raw_message)
                        is_json = True
                    except json.JSONDecodeError:
                        is_json = False

                    if is_json and self.message_security:
                        # Ini adalah pesan JSON, proses sebagai pesan yang ditandatangani
                        verified_data = self.message_security.verify_message(raw_message)
                        if verified_data['verified']:
                            formatted_message = f"🔐✅ [{verified_data['sender']}] {verified_data['content']}"
                        else:
                            formatted_message = f"⚠️ [{verified_data.get('sender', 'Unknown')}] {verified_data['content']}"
                        
                        self._update_gui('message', formatted_message)
                        self.save_message_to_history(formatted_message)
                    else:
                        # Ini adalah pesan plaintext (sistem atau notifikasi)
                        messages = raw_message.split('\n')
                        for message in messages:
                            if message: 
                                self._update_gui('message', message)
                                # Hanya simpan ke riwayat jika ini benar-benar pesan chat
                                if self._is_plaintext_chat_message(message):
                                    self.save_message_to_history(message)

                except socket.timeout:
                    continue
                except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError):
                    break
        except Exception as e:
            self._update_gui('log', f"ERROR: {e}")
        finally:
            self.stop()

    def send_message(self, message: str):
        if self.is_running():
            try:
                if self.message_security:
                    # Send signed message
                    signed_message = self.message_security.sign_message(message, self.client_id)
                    self.ssl_socket.sendall(signed_message.encode('utf-8'))
                    self._update_gui('log', f"🔐 Message signed and sent: {message[:50]}...")
                else:
                    # Send regular message
                    self.ssl_socket.sendall(message.encode('utf-8'))
            except Exception as e:
                self._update_gui('log', f"ERROR saat mengirim: {e}")
                self.stop()

    def save_message_to_history(self, text: str):
        """Menyimpan satu baris teks ke file riwayat lokal dengan timestamp."""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(self.history_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {text.strip()}\n")
        except Exception as e:
            self._update_gui('log', f"Gagal menyimpan riwayat: {e}")

    def _is_plaintext_chat_message(self, message: str) -> bool:
        """Mengecek apakah pesan plaintext dari server adalah pesan chat, bukan sistem/info."""
        message = message.strip()
        
        # Pesan konfirmasi untuk diri sendiri (PM terkirim) tidak disimpan.
        if message.startswith('[PM ke'):
            return False
            
        # Pesan chat yang valid harus dimulai dengan '[' (dari grup, PM, atau broadcast)
        # dan mengandung ']' untuk menghindari false positive.
        if message.startswith('[') and ']' in message:
            return True
            
        # Semua pesan lain (help text, notifikasi 📢, error) dianggap bukan chat.
        return False

    def stop(self):
        if self.stop_event.is_set(): return
        self.stop_event.set()
        if self.ssl_socket:
            try:
                self.ssl_socket.close()
            except Exception: pass
        self._update_gui('connection_status', {'connected': False, 'client_id': None})
        self._update_gui('log', "Koneksi telah ditutup.")

    def is_running(self) -> bool:
        return not self.stop_event.is_set()


# Definisikan kelas ChatGUI setelah TLSChatClient
class ChatGUI(tk.Frame):
    def __init__(self, master: tk.Tk, client: TLSChatClient):
        super().__init__(master)
        self.master = master
        self.client = client
        self.pack(fill="both", expand=True, padx=15, pady=15)
        self.create_widgets()
        self.process_gui_queue()
        self.load_history()

    def create_widgets(self):
        # Configure grid weights
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=3) # chat display
        self.rowconfigure(2, weight=0) # input area
        self.rowconfigure(3, weight=1) # log display

        # Status Label
        self.status_label = ttk.Label(self, text="Status: Menghubungkan...", font=('Helvetica', 16, 'bold'))
        self.status_label.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        # Chat Display
        self.chat_display = scrolledtext.ScrolledText(
            self, state='disabled', wrap=tk.WORD, font=('Helvetica', 14),
            background='#f0f0f0', foreground='#000000', height=15
        )
        self.chat_display.grid(row=1, column=0, sticky="nsew", pady=(0, 10))

        # --- Main Input Frame (Buttons + Text Input) ---
        main_input_frame = ttk.Frame(self)
        main_input_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        main_input_frame.columnconfigure(0, weight=1)

        # --- Button Bar ---
        button_frame = ttk.Frame(main_input_frame)
        button_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        # Buttons are packed into this frame

        send_text = "🔐 Kirim" if self.client.message_security else "Kirim"
        self.send_button = ttk.Button(
            button_frame, text=send_text, command=self.send_message_from_gui, style='Accent.TButton'
        )
        self.send_button.pack(side=tk.RIGHT)

        self.delete_user_button = ttk.Button(
            button_frame, text="➖ Hapus User", command=self.delete_user, style='Accent.TButton'
        )
        self.delete_user_button.pack(side=tk.RIGHT, padx=5)

        self.add_user_button = ttk.Button(
            button_frame, text="➕ Tambah User", command=self.add_user, style='Accent.TButton'
        )
        self.add_user_button.pack(side=tk.RIGHT, padx=(0, 5))
        
        self.upload_button = ttk.Button(
            button_frame, text="📎 Kirim Gambar", command=self.upload_file, style='Accent.TButton'
        )
        self.upload_button.pack(side=tk.LEFT)
        self.upload_button.config(state='disabled')

        # --- Message Input Area ---
        self.message_input = tk.Text(
            main_input_frame, font=('Helvetica', 14), height=3, wrap=tk.WORD
        )
        self.message_input.grid(row=1, column=0, sticky="nsew") # Sits below the button frame
        self.message_input.bind("<Return>", self.send_message_from_gui)

        # Log Display
        self.log_display = scrolledtext.ScrolledText(
            self, state='disabled', wrap=tk.WORD, height=8, font=('Helvetica', 12),
            background='#f8f8f8', foreground='#333333'
        )
        self.log_display.grid(row=3, column=0, sticky="nsew")
        
        # Styles
        style = ttk.Style()
        style.configure('Accent.TButton', font=('Helvetica', 14))
        
        self.update_ui(False)

    def process_gui_queue(self):
        try:
            while True:
                update = self.client.gui_queue.get_nowait()
                event_type, data = update['type'], update['data']
                if event_type == 'log':
                    self.add_to_display(self.log_display, data)
                elif event_type == 'message':
                    self.add_to_display(self.chat_display, data)
                elif event_type == 'connection_status':
                    self.update_ui(data['connected'])
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_gui_queue)

    def add_to_display(self, display_widget: scrolledtext.ScrolledText, text: str):
        display_widget.config(state='normal')
        timestamp = datetime.now().strftime('%H:%M:%S')
        if display_widget == self.chat_display:
            display_widget.insert('end', f"[{timestamp}] {text}\n", 'message')
        else:
            display_widget.insert('end', f"[{timestamp}] {text}\n", 'log')
        display_widget.see('end')
        display_widget.config(state='disabled')
        
        # Configure tags for different message types
        display_widget.tag_configure('message', foreground='#000000')
        display_widget.tag_configure('log', foreground='#666666')
        display_widget.tag_configure('history', foreground='#404040', lmargin1=10, lmargin2=10)

    def update_ui(self, connected: bool):
        state = 'normal' if connected else 'disabled'
        self.message_input.config(state=state)
        self.send_button.config(state=state)
        self.add_user_button.config(state=state)
        self.delete_user_button.config(state=state)
        self.upload_button.config(state=state)  # Enable/disable file upload button

        # Security indicator in status
        security_indicator = "🔐" if self.client.message_security else "⚠️"
        status_text = f"Status: {security_indicator} Terhubung sebagai {self.client.client_id}" if connected else "Status: Terputus"
        self.status_label.config(text=status_text)
        
        if connected:
            self.status_label.config(foreground='green')
        else:
            self.status_label.config(foreground='red')

    def send_message_from_gui(self, event=None):
        message = self.message_input.get("1.0", tk.END).strip()
        if message and self.client.is_running():
            # Pesan tidak lagi ditampilkan langsung ke GUI dari sini,
            # biarkan server yang mengirim balik untuk konsistensi (misal: PM, Grup)
            self.client.send_message(message)
            
            # Simpan pesan 'You' secara lokal ke history file
            my_message = f"[You] {message}"
            if not message.startswith('/'): # Jangan simpan command ke history
                self.client.save_message_to_history(my_message)
                
            # Jika itu bukan command, tampilkan di GUI sebagai [You]
            if not message.startswith('/'):
                self.add_to_display(self.chat_display, my_message)

            self.message_input.delete("1.0", tk.END)
        
        return "break" # Mencegah tombol Return membuat baris baru di input

    def upload_file(self):
        # Fungsi ini dinonaktifkan sementara
        messagebox.showinfo("Info", "Fitur kirim file belum diimplementasikan sepenuhnya.")
        return

    def delete_user(self):
        """Meminta nama pengguna untuk dihapus dan mengirimkan perintah ke server."""
        if not self.client.is_running():
            return
        
        username_to_delete = simpledialog.askstring("Hapus Pengguna", "Masukkan nama pengguna yang akan dihapus:", parent=self.master)
        
        if username_to_delete and username_to_delete.strip():
            # Tampilkan dialog konfirmasi yang tegas
            if messagebox.askyesno("Konfirmasi Hapus", f"Apakah Anda yakin ingin menghapus pengguna '{username_to_delete.strip()}' secara permanen?\n\nSertifikat dan akses akan dicabut.\nTindakan ini tidak dapat diurungkan.", parent=self.master):
                command = f"/delete-user {username_to_delete.strip()}"
                self.client.send_message(command)
                self.add_to_display(self.log_display, f"Mengirim permintaan untuk menghapus pengguna: {username_to_delete.strip()}")
            else:
                self.add_to_display(self.log_display, "Penghapusan pengguna dibatalkan.")
        else:
            # Tidak perlu menampilkan pesan jika dialog hanya ditutup
            pass

    def add_user(self):
        """Meminta nama pengguna baru dan mengirimkan perintah ke server."""
        if not self.client.is_running():
            return
        
        new_username = simpledialog.askstring("Tambah Pengguna Baru", "Masukkan nama pengguna baru:", parent=self.master)
        
        if new_username and new_username.strip():
            command = f"/add-user {new_username.strip()}"
            self.client.send_message(command)
            self.add_to_display(self.log_display, f"Mengirim permintaan untuk menambah pengguna: {new_username.strip()}")
        else:
            self.add_to_display(self.log_display, "Penambahan pengguna dibatalkan.")

    def load_history(self):
        """Memuat riwayat chat dari file lokal dan menampilkannya."""
        try:
            if os.path.exists(self.client.history_file):
                with open(self.client.history_file, 'r', encoding='utf-8') as f:
                    history_content = f.read().strip()
                    if history_content:
                        self.add_to_display(self.chat_display, "--- Riwayat Chat Sebelumnya ---")
                        self.add_to_display(self.chat_display, history_content, 'history')
                        self.add_to_display(self.chat_display, "---------------------------------")
        except Exception as e:
            self.add_to_display(self.log_display, f"Gagal memuat riwayat: {e}")

    def on_closing(self):
        if messagebox.askokcancel("Keluar", "Apakah Anda yakin ingin keluar?"):
            self.client.stop()
            self.master.destroy()


def main():
    parser = argparse.ArgumentParser(description='TLS Chat Client')
    parser.add_argument('--cert', required=True, help='Nama sertifikat (tanpa .crt)')
    parser.add_argument('--server_fingerprint', help='Fingerprint SHA-256 server untuk verifikasi')
    args = parser.parse_args()

    cert_path = f'certs/{args.cert}.crt'
    key_path = f'certs/{args.cert}.key'
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"ERROR: File sertifikat atau kunci tidak ditemukan untuk '{args.cert}'")
        sys.exit(1)

    gui_queue = queue.Queue()
    client = TLSChatClient(
        host='localhost', port=8443,
        cert_path=cert_path, key_path=key_path,
        gui_queue=gui_queue,
        expected_fingerprint=args.server_fingerprint  # Now actually used!
    )

    # Jalankan client di thread terpisah
    client_thread = threading.Thread(target=client.run, daemon=True)
    client_thread.start()

    # Jalankan GUI di thread utama
    root = tk.Tk()
    title = f"🔐 Secure Chat - {os.path.basename(cert_path).split('.')[0]}" if SECURITY_AVAILABLE else f"Chat Client - {os.path.basename(cert_path).split('.')[0]}"
    root.title(title)
    root.geometry("900x700")  # Increased window size to accommodate larger fonts
    
    # Configure styles with LARGER FONTS
    style = ttk.Style()
    style.configure("TLabel", padding=8, font=('Helvetica', 14))  # Increased padding and font
    style.configure("TButton", padding=8, font=('Helvetica', 14))  # Increased padding and font
    style.configure("TEntry", padding=8, font=('Helvetica', 14))   # Increased padding and font
    
    app = ChatGUI(root, client)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()
