import ssl
import socket
import threading
import logging
import sys
import os
import argparse
import hashlib
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
from typing import Optional
import queue

# Konfigurasi logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
logger = logging.getLogger(__name__)


class TLSChatClient:
    def __init__(self, host: str, port: int, cert_path: str, key_path: str, gui_queue: queue.Queue):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.gui_queue = gui_queue
        self.client_id = os.path.basename(cert_path).split('.')[0]
        self.ssl_socket: Optional[ssl.SSLSocket] = None
        self.stop_event = threading.Event()

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
            self.ssl_socket.settimeout(1.0) # Timeout untuk recv

            self._update_gui('connection_status', {'connected': True, 'client_id': self.client_id})

            while not self.stop_event.is_set():
                try:
                    data = self.ssl_socket.recv(4096)
                    if not data:
                        break
                    messages = data.decode('utf-8').strip().split('\n')
                    for message in messages:
                        if message: self._update_gui('message', message)
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
                self.ssl_socket.sendall(message.encode('utf-8'))
            except Exception as e:
                self._update_gui('log', f"ERROR saat mengirim: {e}")
                self.stop()

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


class ChatGUI(tk.Frame):
    def __init__(self, master: tk.Tk, client: TLSChatClient):
        super().__init__(master)
        self.master = master
        self.client = client
        self.pack(fill="both", expand=True, padx=10, pady=10)
        self.create_widgets()
        self.process_gui_queue()

    def create_widgets(self):
        # Configure grid weights
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=3)
        self.rowconfigure(3, weight=1)

        # Status Label with better styling
        self.status_label = ttk.Label(self, text="Status: Menghubungkan...", font=('Helvetica', 10, 'bold'))
        self.status_label.grid(row=0, column=0, sticky="ew", pady=(0,5))
        
        # Chat Display with better styling
        self.chat_display = scrolledtext.ScrolledText(
            self, 
            state='disabled', 
            wrap=tk.WORD,
            font=('Helvetica', 10),
            background='#f0f0f0',
            foreground='#000000'
        )
        self.chat_display.grid(row=1, column=0, sticky="nsew", pady=(0,5))
        
        # Input Frame with better styling
        input_frame = ttk.Frame(self)
        input_frame.grid(row=2, column=0, sticky="ew", pady=(0,5))
        input_frame.columnconfigure(0, weight=1)
        
        self.message_input = ttk.Entry(
            input_frame,
            font=('Helvetica', 10)
        )
        self.message_input.grid(row=0, column=0, sticky="ew", padx=(0,5))
        self.message_input.bind("<Return>", self.send_message_from_gui)
        
        self.send_button = ttk.Button(
            input_frame, 
            text="Kirim",
            command=self.send_message_from_gui,
            style='Accent.TButton'
        )
        self.send_button.grid(row=0, column=1)
        
        # Log Display with better styling
        self.log_display = scrolledtext.ScrolledText(
            self, 
            state='disabled', 
            wrap=tk.WORD, 
            height=8,
            font=('Helvetica', 9),
            background='#f8f8f8',
            foreground='#333333'
        )
        self.log_display.grid(row=3, column=0, sticky="nsew")
        
        # Configure custom styles
        style = ttk.Style()
        style.configure('Accent.TButton', font=('Helvetica', 10))
        
        self.update_ui(False)  # Awalnya disabled

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

    def update_ui(self, connected: bool):
        state = 'normal' if connected else 'disabled'
        self.message_input.config(state=state)
        self.send_button.config(state=state)
        status_text = f"Status: Terhubung sebagai {self.client.client_id}" if connected else "Status: Terputus"
        self.status_label.config(text=status_text)
        
        # Update colors based on connection status
        if connected:
            self.status_label.config(foreground='green')
        else:
            self.status_label.config(foreground='red')

    def send_message_from_gui(self, event=None):
        message = self.message_input.get().strip()
        if message and self.client.is_running():
            self.add_to_display(self.chat_display, f"[You] {message}")
            self.client.send_message(message)
            self.message_input.delete(0, tk.END)

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

    # --- INI ADALAH PERUBAHAN UTAMA ---
    gui_queue = queue.Queue()
    client = TLSChatClient(
        host='localhost', port=8443,
        cert_path=cert_path, key_path=key_path,
        gui_queue=gui_queue,
    )

    # Jalankan client di thread terpisah
    client_thread = threading.Thread(target=client.run, daemon=True)
    client_thread.start()

    # Jalankan GUI di thread utama
    root = tk.Tk()
    root.title(f"Chat Client - {os.path.basename(cert_path).split('.')[0]}")
    root.geometry("800x600")  # Set ukuran window default
    
    # Konfigurasi style
    style = ttk.Style()
    style.configure("TLabel", padding=5)
    style.configure("TButton", padding=5)
    style.configure("TEntry", padding=5)
    
    app = ChatGUI(root, client)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)  # Handle window closing
    
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