import json
import os
import getpass
import socket
import subprocess
import platform
import threading
import csv
from datetime import datetime
from cryptography.fernet import Fernet
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
    SSHException
)
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
import pandas as pd

LOG_FILE = "sensor_check.log"

# Language settings
CURRENT_LANGUAGE = "en"  # Default to English

# Language strings
MESSAGES = {
    "en": {
        "app_title": "Sensor Management Tool",
        "language_select": "Select Language",
        "language_english": "English",
        "language_japanese": "日本語 (Japanese)",
        "tab_encrypt": "Encryption",
        "tab_health": "Health Check",
        "tab_results": "Results",
        "encrypt_title": "Encrypt Credentials File",
        "source_file_label": "Source Credentials File:",
        "browse_button": "Browse",
        "output_file_label": "Output Encrypted File:",
        "encrypt_button": "Encrypt File",
        "health_title": "Sensor Health Check",
        "creds_file_label": "Encrypted Credentials File:",
        "decrypt_key_label": "Decryption Key:",
        "start_check_button": "Start Health Check",
        "export_csv_button": "Export Results to CSV",
        "clear_results_button": "Clear Results",
        "results_title": "Health Check Results",
        "log_title": "Activity Log",
        "sensor_name": "Sensor Name",
        "ip_address": "IP Address",
        "ping_status": "Ping Status",
        "ssh_connectivity": "SSH Connectivity",
        "system_sanity": "System Sanity",
        "uptime_result": "Uptime Result",
        "status_ok": "OK",
        "status_fail": "FAIL",
        "status_pass": "PASS",
        "status_warn": "WARN",
        "status_error": "ERROR",
        "status_pending": "PENDING",
        "file_encrypted": "File encrypted successfully!",
        "encryption_key": "Encryption Key (SAVE THIS SECURELY):",
        "health_check_complete": "Health check completed!",
        "no_file_selected": "No file selected",
        "invalid_key": "Invalid decryption key",
        "file_not_found": "File not found",
        "export_success": "Results exported successfully!",
        "results_cleared": "Results cleared!",
        "health_check_running": "Health check is running...",
        "health_check_stopped": "Health check stopped"
    },
    "ja": {
        "app_title": "センサー管理ツール",
        "language_select": "言語選択",
        "language_english": "English",
        "language_japanese": "日本語 (Japanese)",
        "tab_encrypt": "暗号化",
        "tab_health": "ヘルスチェック",
        "tab_results": "結果",
        "encrypt_title": "認証情報ファイルの暗号化",
        "source_file_label": "ソース認証情報ファイル:",
        "browse_button": "参照",
        "output_file_label": "出力暗号化ファイル:",
        "encrypt_button": "ファイルを暗号化",
        "health_title": "センサーヘルスチェック",
        "creds_file_label": "暗号化認証情報ファイル:",
        "decrypt_key_label": "復号化キー:",
        "start_check_button": "ヘルスチェック開始",
        "export_csv_button": "結果をCSVにエクスポート",
        "clear_results_button": "結果をクリア",
        "results_title": "ヘルスチェック結果",
        "log_title": "活動ログ",
        "sensor_name": "センサー名",
        "ip_address": "IPアドレス",
        "ping_status": "Ping状態",
        "ssh_connectivity": "SSH接続性",
        "system_sanity": "システムサニティ",
        "uptime_result": "アップタイム結果",
        "status_ok": "OK",
        "status_fail": "失敗",
        "status_pass": "合格",
        "status_warn": "警告",
        "status_error": "エラー",
        "status_pending": "保留中",
        "file_encrypted": "ファイルが正常に暗号化されました！",
        "encryption_key": "暗号化キー（安全に保存してください）:",
        "health_check_complete": "ヘルスチェックが完了しました！",
        "no_file_selected": "ファイルが選択されていません",
        "invalid_key": "無効な復号化キー",
        "file_not_found": "ファイルが見つかりません",
        "export_success": "結果が正常にエクスポートされました！",
        "results_cleared": "結果がクリアされました！",
        "health_check_running": "ヘルスチェックが実行中です...",
        "health_check_stopped": "ヘルスチェックが停止されました"
    }
}

def get_message(key, *args):
    """Get message in current language with optional formatting"""
    message = MESSAGES[CURRENT_LANGUAGE].get(key, MESSAGES["en"].get(key, key))
    if args:
        return message.format(*args)
    return message

class SensorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(get_message("app_title"))
        self.root.geometry("1000x700")
        
        # Initialize variables
        self.source_file_var = tk.StringVar(value="flag.json")
        self.output_file_var = tk.StringVar(value="sensor_credentials.enc")
        self.creds_file_var = tk.StringVar(value="sensor_credentials.enc")
        self.decrypt_key_var = tk.StringVar()
        
        # Results storage
        self.results_data = []
        self.is_checking = False
        
        # Create GUI elements
        self.create_language_selection()
        self.create_notebook()
        self.create_encryption_tab()
        self.create_health_check_tab()
        self.create_results_tab()
        
    def create_language_selection(self):
        """Create language selection frame"""
        lang_frame = ttk.Frame(self.root)
        lang_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(lang_frame, text=get_message("language_select")).pack(side=tk.LEFT)
        
        self.language_var = tk.StringVar(value="en")
        ttk.Radiobutton(lang_frame, text=get_message("language_english"), 
                       variable=self.language_var, value="en", 
                       command=self.change_language).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(lang_frame, text=get_message("language_japanese"), 
                       variable=self.language_var, value="ja", 
                       command=self.change_language).pack(side=tk.LEFT, padx=10)
        
    def change_language(self):
        """Change the application language"""
        global CURRENT_LANGUAGE
        CURRENT_LANGUAGE = self.language_var.get()
        # Update GUI text
        self.update_gui_text()
        
    def update_gui_text(self):
        """Update all GUI text based on current language"""
        self.root.title(get_message("app_title"))
        # Update tab texts
        self.notebook.tab(0, text=get_message("tab_encrypt"))
        self.notebook.tab(1, text=get_message("tab_health"))
        self.notebook.tab(2, text=get_message("tab_results"))
        
    def create_notebook(self):
        """Create main notebook with tabs"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.health_frame = ttk.Frame(self.notebook)
        self.results_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.encrypt_frame, text=get_message("tab_encrypt"))
        self.notebook.add(self.health_frame, text=get_message("tab_health"))
        self.notebook.add(self.results_frame, text=get_message("tab_results"))
        
    def create_encryption_tab(self):
        """Create encryption tab"""
        # Title
        title_label = ttk.Label(self.encrypt_frame, text=get_message("encrypt_title"), 
                               font=("Arial", 12, "bold"))
        title_label.pack(pady=10)
        
        # Source file selection
        source_frame = ttk.Frame(self.encrypt_frame)
        source_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(source_frame, text=get_message("source_file_label")).pack(side=tk.LEFT)
        ttk.Entry(source_frame, textvariable=self.source_file_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(source_frame, text=get_message("browse_button"), 
                  command=self.browse_source_file).pack(side=tk.LEFT, padx=5)
        
        # Output file selection
        output_frame = ttk.Frame(self.encrypt_frame)
        output_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(output_frame, text=get_message("output_file_label")).pack(side=tk.LEFT)
        ttk.Entry(output_frame, textvariable=self.output_file_var, width=50).pack(side=tk.LEFT, padx=5)
        
        # Encrypt button
        encrypt_btn = ttk.Button(self.encrypt_frame, text=get_message("encrypt_button"), 
                               command=self.encrypt_file)
        encrypt_btn.pack(pady=20)
        
        # Results area
        self.encrypt_results = ScrolledText(self.encrypt_frame, height=15, width=80)
        self.encrypt_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_health_check_tab(self):
        """Create health check tab"""
        # Title
        title_label = ttk.Label(self.health_frame, text=get_message("health_title"), 
                               font=("Arial", 12, "bold"))
        title_label.pack(pady=10)
        
        # Credentials file selection
        creds_frame = ttk.Frame(self.health_frame)
        creds_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(creds_frame, text=get_message("creds_file_label")).pack(side=tk.LEFT)
        ttk.Entry(creds_frame, textvariable=self.creds_file_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(creds_frame, text=get_message("browse_button"), 
                  command=self.browse_creds_file).pack(side=tk.LEFT, padx=5)
        
        # Decryption key
        key_frame = ttk.Frame(self.health_frame)
        key_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(key_frame, text=get_message("decrypt_key_label")).pack(side=tk.LEFT)
        ttk.Entry(key_frame, textvariable=self.decrypt_key_var, width=50, show="*").pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(self.health_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text=get_message("start_check_button"), 
                                   command=self.start_health_check)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Check", 
                                  command=self.stop_health_check, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.health_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=20, pady=5)
        
        # Log area
        ttk.Label(self.health_frame, text=get_message("log_title")).pack(anchor=tk.W, padx=20)
        self.log_text = ScrolledText(self.health_frame, height=15, width=80)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_results_tab(self):
        """Create results tab with CSV-like table"""
        # Title
        title_label = ttk.Label(self.results_frame, text=get_message("results_title"), 
                               font=("Arial", 12, "bold"))
        title_label.pack(pady=10)
        
        # Control buttons
        button_frame = ttk.Frame(self.results_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Button(button_frame, text=get_message("export_csv_button"), 
                  command=self.export_to_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text=get_message("clear_results_button"), 
                  command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
        # Results table
        columns = (
            get_message("sensor_name"),
            get_message("ip_address"),
            get_message("ping_status"),
            get_message("ssh_connectivity"),
            get_message("system_sanity"),
            get_message("uptime_result")
        )
        
        self.results_tree = ttk.Treeview(self.results_frame, columns=columns, show="headings", height=20)
        
        # Define column headings
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=120)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack everything
        self.results_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def browse_source_file(self):
        """Browse for source credentials file"""
        filename = filedialog.askopenfilename(
            title="Select Source Credentials File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.source_file_var.set(filename)
            
    def browse_creds_file(self):
        """Browse for encrypted credentials file"""
        filename = filedialog.askopenfilename(
            title="Select Encrypted Credentials File",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if filename:
            self.creds_file_var.set(filename)
            
    def encrypt_file(self):
        """Encrypt the credentials file"""
        source_file = self.source_file_var.get()
        output_file = self.output_file_var.get()
        
        if not source_file or not os.path.exists(source_file):
            messagebox.showerror("Error", get_message("file_not_found"))
            return
            
        try:
            # Generate encryption key
            key = Fernet.generate_key()
            
            # Read and encrypt file
            with open(source_file, "rb") as f:
                data = f.read()
                
            cipher = Fernet(key)
            encrypted_data = cipher.encrypt(data)
            
            # Save encrypted file
            with open(output_file, "wb") as f:
                f.write(encrypted_data)
                
            # Display results
            self.encrypt_results.delete(1.0, tk.END)
            self.encrypt_results.insert(tk.END, f"{get_message('file_encrypted')}\n\n")
            self.encrypt_results.insert(tk.END, f"{get_message('encryption_key')}\n")
            self.encrypt_results.insert(tk.END, f"{key.decode()}\n\n")
            self.encrypt_results.insert(tk.END, "IMPORTANT: Save this key securely! You will need it to decrypt the credentials.\n")
            
            messagebox.showinfo("Success", get_message("file_encrypted"))
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            
    def start_health_check(self):
        """Start health check in a separate thread"""
        if self.is_checking:
            return
            
        creds_file = self.creds_file_var.get()
        decrypt_key = self.decrypt_key_var.get()
        
        if not creds_file or not os.path.exists(creds_file):
            messagebox.showerror("Error", get_message("file_not_found"))
            return
            
        if not decrypt_key:
            messagebox.showerror("Error", "Please enter decryption key")
            return
            
        self.is_checking = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        
        # Clear previous results
        self.clear_results()
        
        # Start health check thread
        self.health_thread = threading.Thread(target=self.run_health_check, 
                                            args=(creds_file, decrypt_key))
        self.health_thread.daemon = True
        self.health_thread.start()
        
    def stop_health_check(self):
        """Stop health check"""
        self.is_checking = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.log_message(get_message("health_check_stopped"))
        
    def run_health_check(self, creds_file, decrypt_key):
        """Run health check process"""
        try:
            # Load credentials
            key = decrypt_key.encode()
            credentials = self.load_credentials(creds_file, key)
            
            if not credentials:
                self.log_message("Failed to load credentials")
                return
                
            self.log_message(f"Loaded credentials for {len(credentials)} sensors")
            
            # Check each sensor
            for ip, creds in credentials.items():
                if not self.is_checking:
                    break
                    
                sensor_name = creds.get("name", ip)
                result = self.check_sensor(ip, creds, sensor_name)
                
                # Add result to table
                self.root.after(0, self.add_result_to_table, result)
                
        except Exception as e:
            self.log_message(f"Health check error: {str(e)}")
        finally:
            self.root.after(0, self.health_check_finished)
            
    def health_check_finished(self):
        """Called when health check is finished"""
        self.is_checking = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.log_message(get_message("health_check_complete"))
        
    def load_credentials(self, encrypted_path, key):
        """Load and decrypt credentials"""
        try:
            cipher = Fernet(key)
            with open(encrypted_path, "rb") as f:
                encrypted_data = f.read()
            decrypted = cipher.decrypt(encrypted_data)
            credentials = json.loads(decrypted.decode())
            return credentials
        except Exception as e:
            self.log_message(f"Failed to load credentials: {str(e)}")
            return {}
            
    def check_sensor(self, ip, creds, sensor_name):
        """Check a single sensor and return results"""
        result = {
            "sensor_name": sensor_name,
            "ip_address": ip,
            "ping_status": get_message("status_pending"),
            "ssh_connectivity": get_message("status_pending"),
            "system_sanity": get_message("status_pending"),
            "uptime_result": get_message("status_pending")
        }
        
        self.log_message(f"Checking sensor: {sensor_name} ({ip})")
        
        # Step 1: Ping test
        if self.ping_sensor(ip):
            result["ping_status"] = get_message("status_ok")
            self.log_message(f"[OK] Sensor {ip} is reachable via ping")
        else:
            result["ping_status"] = get_message("status_fail")
            self.log_message(f"[FAIL] Sensor {ip} is not reachable via ping")
            return result
            
        # Step 2: SSH Test User 1 (System Sanity)
        user1 = creds.get("username")
        pass1 = creds.get("password")
        
        if user1 and pass1:
            success, output, error = self.run_ssh_command(ip, user1, pass1, "system sanity")
            if success:
                result["ssh_connectivity"] = get_message("status_ok")
                if output and "System is UP!" in output:
                    result["system_sanity"] = get_message("status_pass")
                    self.log_message(f"[PASS] {ip} - System sanity passed")
                else:
                    result["system_sanity"] = get_message("status_fail")
                    self.log_message(f"[FAIL] {ip} - System sanity failed")
            else:
                result["ssh_connectivity"] = get_message("status_fail")
                result["system_sanity"] = get_message("status_error")
                self.log_message(f"[ERROR] {ip} - SSH failed: {error}")
        else:
            result["ssh_connectivity"] = get_message("status_error")
            result["system_sanity"] = get_message("status_error")
            self.log_message(f"[ERROR] Missing User1 credentials for {ip}")
            
        # Step 3: SSH Test User 2 (Uptime)
        user2 = creds.get("username2")
        pass2 = creds.get("password2")
        
        if user2 and pass2:
            success, output, error = self.run_ssh_command(ip, user2, pass2, "uptime")
            if success:
                if output:
                    result["uptime_result"] = get_message("status_pass")
                    self.log_message(f"[PASS] {ip} - Uptime: {output.strip()}")
                else:
                    result["uptime_result"] = get_message("status_warn")
                    self.log_message(f"[WARN] {ip} - No uptime output")
            else:
                result["uptime_result"] = get_message("status_error")
                self.log_message(f"[ERROR] {ip} - Uptime SSH failed: {error}")
        else:
            result["uptime_result"] = get_message("status_error")
            self.log_message(f"[ERROR] Missing User2 credentials for {ip}")
            
        return result
        
    def ping_sensor(self, ip, timeout=2):
        """Ping a sensor"""
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except Exception:
            return False
            
    def run_ssh_command(self, ip, username, password, command, timeout=15):
        """Run SSH command on sensor"""
        connection = None
        try:
            device = {
                'device_type': 'terminal_server',
                'host': ip,
                'username': username,
                'password': password,
                'timeout': timeout,
                'banner_timeout': 30,
                'conn_timeout': timeout,
                'auth_timeout': timeout,
                'session_log': None,
                'keepalive': 0,
                'default_enter': '\r\n',
                'response_return': '\n',
                'serial_settings': None,
                'fast_cli': False,
                'session_timeout': 60,
                'read_timeout_override': None,
                'encoding': 'utf-8',
                'sock': None,
                'auto_connect': True
            }
            
            connection = ConnectHandler(**device)
            
            if "system sanity" in command:
                output = connection.send_command_timing(
                    command, 
                    delay_factor=3,
                    max_loops=20,
                    strip_prompt=True,
                    strip_command=True
                )
            else:
                output = connection.send_command_timing(
                    command, 
                    delay_factor=1,
                    max_loops=10,
                    strip_prompt=True,
                    strip_command=True
                )
            
            return True, output, ""
            
        except Exception as e:
            return False, "", str(e)
        finally:
            if connection:
                try:
                    connection.disconnect()
                except:
                    pass
                    
    def add_result_to_table(self, result):
        """Add result to the results table"""
        self.results_data.append(result)
        self.results_tree.insert("", tk.END, values=(
            result["sensor_name"],
            result["ip_address"],
            result["ping_status"],
            result["ssh_connectivity"],
            result["system_sanity"],
            result["uptime_result"]
        ))
        
    def export_to_csv(self):
        """Export results to CSV file"""
        if not self.results_data:
            messagebox.showwarning("Warning", "No results to export")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save Results as CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                df = pd.DataFrame(self.results_data)
                df.to_csv(filename, index=False)
                messagebox.showinfo("Success", get_message("export_success"))
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
                
    def clear_results(self):
        """Clear all results"""
        self.results_data.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.log_text.delete(1.0, tk.END)
        
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_entry = f"{timestamp} {message}\n"
        
        # Add to GUI log
        self.root.after(0, self._update_log, log_entry)
        
        # Add to file log
        with open(LOG_FILE, "a") as f:
            f.write(log_entry)
            
    def _update_log(self, message):
        """Update GUI log (called from main thread)"""
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)

def main():
    root = tk.Tk()
    app = SensorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
