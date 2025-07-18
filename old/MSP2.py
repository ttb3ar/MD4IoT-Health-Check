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
MESSAGES = {}

def load_translations():
    """Load translation files"""
    global MESSAGES
    translation_files = {
        "en": "translations/en.json",
        "ja": "translations/jp.json"
    }
    
    for lang_code, file_path in translation_files.items():
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    MESSAGES[lang_code] = data.get(lang_code, {})
            else:
                print(f"Warning: Translation file {file_path} not found")
                # Fallback to basic English if files don't exist
                if lang_code == "en":
                    MESSAGES[lang_code] = {
                        "app_title": "Sensor Management Tool",
                        "language_select": "Select Language",
                        "language_english": "English",
                        "language_japanese": "日本語 (Japanese)",
                        "tab_encrypt": "Encryption",
                        "tab_health": "Health Check",
                        "tab_results": "Results",
                        "error_title": "Error",
                        "success_title": "Success",
                        "warning_title": "Warning"
                    }
        except Exception as e:
            print(f"Error loading translation file {file_path}: {e}")
            
def get_message(key, *args):
    """Get message in current language with optional formatting"""
    if not MESSAGES:
        load_translations()
    
    message = MESSAGES.get(CURRENT_LANGUAGE, {}).get(key)
    if not message:
        message = MESSAGES.get("en", {}).get(key, key)
    
    if args:
        try:
            return message.format(*args)
        except (IndexError, KeyError):
            return message
    return message

class SensorGUI:
    def __init__(self, root):
        # Load translations first
        load_translations()
        
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
        
        # Update labels and buttons
        self.encrypt_title_label.config(text=get_message("encrypt_title"))
        self.source_file_label.config(text=get_message("source_file_label"))
        self.browse_source_btn.config(text=get_message("browse_button"))
        self.output_file_label.config(text=get_message("output_file_label"))
        self.encrypt_btn.config(text=get_message("encrypt_button"))
        
        self.health_title_label.config(text=get_message("health_title"))
        self.creds_file_label.config(text=get_message("creds_file_label"))
        self.browse_creds_btn.config(text=get_message("browse_button"))
        self.decrypt_key_label.config(text=get_message("decrypt_key_label"))
        self.start_btn.config(text=get_message("start_check_button"))
        self.stop_btn.config(text=get_message("stop_check_button"))
        self.log_label.config(text=get_message("log_title"))
        
        self.results_title_label.config(text=get_message("results_title"))
        self.export_btn.config(text=get_message("export_csv_button"))
        self.clear_btn.config(text=get_message("clear_results_button"))
        
        # Update column headings
        columns = [
            get_message("sensor_name"),
            get_message("ip_address"),
            get_message("ping_status"),
            get_message("ssh_connectivity"),
            get_message("system_sanity"),
            get_message("uptime_result")
        ]
        
        for i, col in enumerate(columns):
            self.results_tree.heading(f"#{i+1}", text=col)
        
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
        self.encrypt_title_label = ttk.Label(self.encrypt_frame, text=get_message("encrypt_title"), 
                                           font=("Arial", 12, "bold"))
        self.encrypt_title_label.pack(pady=10)
        
        # Source file selection
        source_frame = ttk.Frame(self.encrypt_frame)
        source_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.source_file_label = ttk.Label(source_frame, text=get_message("source_file_label"))
        self.source_file_label.pack(side=tk.LEFT)
        ttk.Entry(source_frame, textvariable=self.source_file_var, width=50).pack(side=tk.LEFT, padx=5)
        self.browse_source_btn = ttk.Button(source_frame, text=get_message("browse_button"), 
                                          command=self.browse_source_file)
        self.browse_source_btn.pack(side=tk.LEFT, padx=5)
        
        # Output file selection
        output_frame = ttk.Frame(self.encrypt_frame)
        output_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.output_file_label = ttk.Label(output_frame, text=get_message("output_file_label"))
        self.output_file_label.pack(side=tk.LEFT)
        ttk.Entry(output_frame, textvariable=self.output_file_var, width=50).pack(side=tk.LEFT, padx=5)
        
        # Encrypt button
        self.encrypt_btn = ttk.Button(self.encrypt_frame, text=get_message("encrypt_button"), 
                                    command=self.encrypt_file)
        self.encrypt_btn.pack(pady=20)
        
        # Results area
        self.encrypt_results = ScrolledText(self.encrypt_frame, height=15, width=80)
        self.encrypt_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_health_check_tab(self):
        """Create health check tab"""
        # Title
        self.health_title_label = ttk.Label(self.health_frame, text=get_message("health_title"), 
                                          font=("Arial", 12, "bold"))
        self.health_title_label.pack(pady=10)
        
        # Credentials file selection
        creds_frame = ttk.Frame(self.health_frame)
        creds_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.creds_file_label = ttk.Label(creds_frame, text=get_message("creds_file_label"))
        self.creds_file_label.pack(side=tk.LEFT)
        ttk.Entry(creds_frame, textvariable=self.creds_file_var, width=50).pack(side=tk.LEFT, padx=5)
        self.browse_creds_btn = ttk.Button(creds_frame, text=get_message("browse_button"), 
                                         command=self.browse_creds_file)
        self.browse_creds_btn.pack(side=tk.LEFT, padx=5)
        
        # Decryption key
        key_frame = ttk.Frame(self.health_frame)
        key_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.decrypt_key_label = ttk.Label(key_frame, text=get_message("decrypt_key_label"))
        self.decrypt_key_label.pack(side=tk.LEFT)
        ttk.Entry(key_frame, textvariable=self.decrypt_key_var, width=50, show="*").pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(self.health_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text=get_message("start_check_button"), 
                                   command=self.start_health_check)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text=get_message("stop_check_button"), 
                                  command=self.stop_health_check, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.health_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=20, pady=5)
        
        # Log area
        self.log_label = ttk.Label(self.health_frame, text=get_message("log_title"))
        self.log_label.pack(anchor=tk.W, padx=20)
        self.log_text = ScrolledText(self.health_frame, height=15, width=80)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_results_tab(self):
        """Create results tab with CSV-like table"""
        # Title
        self.results_title_label = ttk.Label(self.results_frame, text=get_message("results_title"), 
                                           font=("Arial", 12, "bold"))
        self.results_title_label.pack(pady=10)
        
        # Control buttons
        button_frame = ttk.Frame(self.results_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.export_btn = ttk.Button(button_frame, text=get_message("export_csv_button"), 
                                   command=self.export_to_csv)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text=get_message("clear_results_button"), 
                                  command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
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
            title=get_message("select_source_file"),
            filetypes=[(get_message("json_files"), "*.json"), (get_message("all_files"), "*.*")]
        )
        if filename:
            self.source_file_var.set(filename)
            
    def browse_creds_file(self):
        """Browse for encrypted credentials file"""
        filename = filedialog.askopenfilename(
            title=get_message("select_encrypted_file"),
            filetypes=[(get_message("encrypted_files"), "*.enc"), (get_message("all_files"), "*.*")]
        )
        if filename:
            self.creds_file_var.set(filename)
            
    def encrypt_file(self):
        """Encrypt the credentials file"""
        source_file = self.source_file_var.get()
        output_file = self.output_file_var.get()
        
        if not source_file or not os.path.exists(source_file):
            messagebox.showerror(get_message("error_title"), get_message("file_not_found"))
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
            self.encrypt_results.insert(tk.END, f"{get_message('encryption_key_warning')}\n")
            
            messagebox.showinfo(get_message("success_title"), get_message("file_encrypted"))
            
        except Exception as e:
            messagebox.showerror(get_message("error_title"), get_message("encryption_failed", str(e)))
            
    def start_health_check(self):
        """Start health check in a separate thread"""
        if self.is_checking:
            return
            
        creds_file = self.creds_file_var.get()
        decrypt_key = self.decrypt_key_var.get()
        
        if not creds_file or not os.path.exists(creds_file):
            messagebox.showerror(get_message("error_title"), get_message("file_not_found"))
            return
            
        if not decrypt_key:
            messagebox.showerror(get_message("error_title"), get_message("please_enter_key"))
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
                self.log_message(get_message("failed_to_load_credentials", "Invalid key or file"))
                return
                
            self.log_message(get_message("loaded_credentials", len(credentials)))
            
            # Check each sensor
            for ip, creds in credentials.items():
                if not self.is_checking:
                    break
                    
                sensor_name = creds.get("name", ip)
                result = self.check_sensor(ip, creds, sensor_name)
                
                # Add result to table
                self.root.after(0, self.add_result_to_table, result)
                
        except Exception as e:
            self.log_message(get_message("health_check_error", str(e)))
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
            self.log_message(get_message("failed_to_load_credentials", str(e)))
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
        
        self.log_message(get_message("checking_sensor", sensor_name, ip))
        
        # Step 1: Ping test
        if self.ping_sensor(ip):
            result["ping_status"] = get_message("status_ok")
            self.log_message(get_message("sensor_reachable", ip))
        else:
            result["ping_status"] = get_message("status_fail")
            self.log_message(get_message("sensor_unreachable", ip))
            return result
            
        # Step 2: SSH Test User 1 (System Sanity)
        user1 = creds.get("username")
        pass1 = creds.get("password")
        
        if user1 and pass1:
            success, output, error = self.run_ssh_command(ip, user1, pass1, "system sanity")
            if success:
                result["ssh_connectivity"] = get_message("status_ok")
                if output and "system is up" in output.lower():
                    result["system_sanity"] = get_message("status_pass")
                    self.log_message(get_message("system_sanity_passed", ip))
                else:
                    result["system_sanity"] = get_message("status_fail")
                    self.log_message(get_message("system_sanity_failed", ip))
            else:
                result["ssh_connectivity"] = get_message("status_fail")
                result["system_sanity"] = get_message("status_error")
                self.log_message(get_message("ssh_failed", ip, error))
        else:
            result["ssh_connectivity"] = get_message("status_error")
            result["system_sanity"] = get_message("status_error")
            self.log_message(get_message("missing_user1_credentials", ip))
            
        # Step 3: SSH Test User 2 (Uptime)
        user2 = creds.get("username2")
        pass2 = creds.get("password2")
        
        if user2 and pass2:
            success, output, error = self.run_ssh_command(ip, user2, pass2, "uptime")
            if success:
                if output:
                    result["uptime_result"] = get_message("status_pass")
                    self.log_message(get_message("uptime_result", ip, output.strip()))
                else:
                    result["uptime_result"] = get_message("status_warn")
                    self.log_message(get_message("no_uptime_output", ip))
            else:
                result["uptime_result"] = get_message("status_error")
                self.log_message(get_message("uptime_ssh_failed", ip, error))
        else:
            result["uptime_result"] = get_message("status_error")
            self.log_message(get_message("missing_user2_credentials", ip))
            
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
                    delay_factor=10,
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
            messagebox.showwarning(get_message("warning_title"), get_message("no_results_to_export"))
            return
            
        filename = filedialog.asksaveasfilename(
            title=get_message("save_results_csv"),
            defaultextension=".csv",
            filetypes=[(get_message("csv_files"), "*.csv"), (get_message("all_files"), "*.*")]
        )
        
        if filename:
            try:
                df = pd.DataFrame(self.results_data)
                df.to_csv(filename, index=False)
                messagebox.showinfo(get_message("success_title"), get_message("export_success"))
            except Exception as e:
                messagebox.showerror(get_message("error_title"), get_message("export_failed", str(e)))
                
    def clear_results(self):
        """Clear all results"""
        self.results_data.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.log_text.delete(1.0, tk.END)
        
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime(get_message("timestamp_format"))
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
