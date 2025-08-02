import json
import os
import getpass
import socket
import subprocess
import platform
import threading
import csv
import glob
from datetime import datetime
from functools import lru_cache
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

# Lazy imports - only import when needed
_netmiko_imported = False
_crypto_imported = False
_pandas_imported = False

def _import_netmiko():
    """Lazy import netmiko when needed"""
    global _netmiko_imported, ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException, SSHException
    if not _netmiko_imported:
        from netmiko import ConnectHandler
        from netmiko.exceptions import (
            NetmikoTimeoutException,
            NetmikoAuthenticationException,
            SSHException
        )
        _netmiko_imported = True

def _import_crypto():
    """Lazy import cryptography when needed"""
    global _crypto_imported, Fernet
    if not _crypto_imported:
        from cryptography.fernet import Fernet
        _crypto_imported = True

def _import_pandas():
    """Lazy import pandas when needed"""
    global _pandas_imported, pd
    if not _pandas_imported:
        import pandas as pd
        _pandas_imported = True

LOG_FILE = "sensor_check.log"

# Language settings - use class to avoid global variables
class LanguageManager:
    def __init__(self):
        self.current_language = "en"
        self.messages = {}
        self.available_languages = {}
        self._translations_loaded = False
        
    @lru_cache(maxsize=10)
    def discover_languages(self):
        """Discover available language files (cached)"""
        available = {}
        
        # Look for translation files in the translations directory
        if os.path.exists("translations"):
            for file_path in glob.glob("translations/*.json"):
                try:
                    # Just get the language code from filename for discovery
                    lang_code = os.path.splitext(os.path.basename(file_path))[0]
                    # We'll load the display name when we actually load the file
                    available[lang_code] = lang_code.title()
                except Exception as e:
                    print(f"Error discovering language file {file_path}: {e}")
        
        # Ensure we have at least English as fallback
        if not available:
            available = {"en": "English"}
            
        self.available_languages = available
        return available

    def load_translations(self):
        """Load translation files only when needed"""
        if self._translations_loaded:
            return
            
        self.messages = {}
        
        # Discover available languages first
        self.discover_languages()
        
        for lang_code in self.available_languages.keys():
            file_path = f"translations/{lang_code}.json"
            try:
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        self.messages[lang_code] = data.get(lang_code, {})
                        # Update display name from file if available
                        if lang_code in data and "language_display_name" in data[lang_code]:
                            self.available_languages[lang_code] = data[lang_code]["language_display_name"]
                else:
                    # Fallback to basic English if files don't exist
                    if lang_code == "en":
                        self.messages[lang_code] = self._get_default_english_messages()
            except Exception as e:
                print(f"Error loading translation file {file_path}: {e}")
                
        self._translations_loaded = True
    
    def _get_default_english_messages(self):
        """Get default English messages"""
        return {
            "app_title": "Sensor Management Tool",
            "language_select": "Select Language",
            "language_display_name": "English",
            "tab_encrypt": "Encryption",
            "tab_health": "Health Check",
            "tab_results": "Results",
            "error_title": "Error",
            "success_title": "Success",
            "warning_title": "Warning",
            "encrypt_title": "Encrypt Credentials File",
            "source_file_label": "Source File:",
            "browse_button": "Browse",
            "output_file_label": "Output File:",
            "encrypt_button": "Encrypt File",
            "health_title": "Sensor Health Check",
            "creds_file_label": "Credentials File:",
            "decrypt_key_label": "Decryption Key:",
            "start_check_button": "Start Check",
            "stop_check_button": "Stop Check",
            "log_title": "Log:",
            "results_title": "Health Check Results",
            "export_csv_button": "Export to CSV",
            "clear_results_button": "Clear Results",
            "sensor_name": "Sensor Name",
            "ip_address": "IP Address",
            "ping_status": "Ping Status",
            "ssh_connectivity": "SSH Connectivity",
            "system_sanity": "System Sanity",
            "uptime_result": "Uptime Result",
            "status_pending": "Pending",
            "status_ok": "OK",
            "status_fail": "FAIL",
            "status_pass": "PASS",
            "status_warn": "WARN",
            "status_error": "ERROR",
            "timestamp_format": "%Y-%m-%d %H:%M:%S",
            "file_not_found": "File not found or does not exist.",
            "please_enter_key": "Please enter the decryption key.",
            "health_check_stopped": "Health check stopped by user.",
            "health_check_complete": "Health check completed.",
            "file_encrypted": "File encrypted successfully!",
            "encryption_key": "Encryption Key (SAVE THIS KEY!):",
            "encryption_key_warning": "WARNING: Save this key securely! You will need it to decrypt the file.",
            "encryption_failed": "Encryption failed: {}",
            "select_source_file": "Select Source File",
            "select_encrypted_file": "Select Encrypted File",
            "json_files": "JSON files",
            "encrypted_files": "Encrypted files",
            "all_files": "All files",
            "csv_files": "CSV files",
            "save_results_csv": "Save Results as CSV",
            "no_results_to_export": "No results to export.",
            "export_success": "Results exported successfully!",
            "export_failed": "Export failed: {}",
            "loaded_credentials": "Loaded {} sensor credentials.",
            "failed_to_load_credentials": "Failed to load credentials: {}",
            "health_check_error": "Health check error: {}",
            "checking_sensor": "Checking sensor {} ({})",
            "sensor_reachable": "Sensor {} is reachable.",
            "sensor_unreachable": "Sensor {} is unreachable.",
            "system_sanity_passed": "System sanity check passed for {}",
            "system_sanity_failed": "System sanity check failed for {}",
            "ssh_failed": "SSH connection failed for {}: {}",
            "missing_user1_credentials": "Missing user1 credentials for {}",
            "uptime_result": "Uptime for {}: {}",
            "no_uptime_output": "No uptime output for {}",
            "uptime_ssh_failed": "Uptime SSH failed for {}: {}",
            "missing_user2_credentials": "Missing user2 credentials for {}"
        }
            
    def get_message(self, key, *args):
        """Get message in current language with optional formatting"""
        if not self._translations_loaded:
            self.load_translations()
        
        message = self.messages.get(self.current_language, {}).get(key)
        if not message:
            message = self.messages.get("en", {}).get(key, key)
        
        if args:
            try:
                return message.format(*args)
            except (IndexError, KeyError):
                return message
        return message

# Global language manager instance
lang_manager = LanguageManager()

class SensorGUI:
    def __init__(self, root):
        self.root = root
        
        # Initialize variables early
        self.source_file_var = tk.StringVar(value="flag.json")
        self.output_file_var = tk.StringVar(value="sensor_credentials.enc")
        self.creds_file_var = tk.StringVar(value="sensor_credentials.enc")
        self.decrypt_key_var = tk.StringVar()
        
        # Results storage
        self.results_data = []
        self.is_checking = False
        
        # Set up basic window properties first
        self.root.title(lang_manager.get_message("app_title"))
        self.root.geometry("1000x700")
        
        # Try to set icon, but don't fail if it doesn't exist
        try:
            self.root.iconbitmap("favicon.ico")
        except tk.TclError:
            pass  # Icon file doesn't exist, continue without it
        
        # Create GUI elements
        self.create_language_selection()
        self.create_notebook()
        self.create_encryption_tab()
        self.create_health_check_tab()
        self.create_results_tab()
        
    def create_language_selection(self):
        """Create language selection frame with dropdown"""
        lang_frame = ttk.Frame(self.root)
        lang_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(lang_frame, text=lang_manager.get_message("language_select")).pack(side=tk.LEFT)
        
        # Create dropdown with available languages
        self.language_var = tk.StringVar(value=lang_manager.current_language)
        self.language_dropdown = ttk.Combobox(lang_frame, textvariable=self.language_var, 
                                            state="readonly", width=20)
        
        # Get available languages (this will load them if needed)
        available_languages = lang_manager.discover_languages()
        
        # Populate dropdown with available languages
        language_options = []
        language_values = []
        for lang_code, display_name in available_languages.items():
            language_options.append(display_name)
            language_values.append(lang_code)
        
        self.language_dropdown['values'] = language_options
        self.language_values = language_values
        
        # Set current selection
        try:
            current_index = language_values.index(lang_manager.current_language)
            self.language_dropdown.current(current_index)
        except ValueError:
            self.language_dropdown.current(0)
        
        self.language_dropdown.bind('<<ComboboxSelected>>', self.on_language_change)
        self.language_dropdown.pack(side=tk.LEFT, padx=10)
        
    def on_language_change(self, event=None):
        """Handle language change from dropdown"""
        selected_index = self.language_dropdown.current()
        if 0 <= selected_index < len(self.language_values):
            lang_manager.current_language = self.language_values[selected_index]
            # Update GUI text
            self.update_gui_text()
        
    def update_gui_text(self):
        """Update all GUI text based on current language"""
        self.root.title(lang_manager.get_message("app_title"))
        
        # Update tab texts
        self.notebook.tab(0, text=lang_manager.get_message("tab_encrypt"))
        self.notebook.tab(1, text=lang_manager.get_message("tab_health"))
        self.notebook.tab(2, text=lang_manager.get_message("tab_results"))
        
        # Update labels and buttons
        self.encrypt_title_label.config(text=lang_manager.get_message("encrypt_title"))
        self.source_file_label.config(text=lang_manager.get_message("source_file_label"))
        self.browse_source_btn.config(text=lang_manager.get_message("browse_button"))
        self.output_file_label.config(text=lang_manager.get_message("output_file_label"))
        self.encrypt_btn.config(text=lang_manager.get_message("encrypt_button"))
        
        self.health_title_label.config(text=lang_manager.get_message("health_title"))
        self.creds_file_label.config(text=lang_manager.get_message("creds_file_label"))
        self.browse_creds_btn.config(text=lang_manager.get_message("browse_button"))
        self.decrypt_key_label.config(text=lang_manager.get_message("decrypt_key_label"))
        self.start_btn.config(text=lang_manager.get_message("start_check_button"))
        self.stop_btn.config(text=lang_manager.get_message("stop_check_button"))
        self.log_label.config(text=lang_manager.get_message("log_title"))
        
        self.results_title_label.config(text=lang_manager.get_message("results_title"))
        self.export_btn.config(text=lang_manager.get_message("export_csv_button"))
        self.clear_btn.config(text=lang_manager.get_message("clear_results_button"))
        
        # Update column headings
        columns = [
            lang_manager.get_message("sensor_name"),
            lang_manager.get_message("ip_address"),
            lang_manager.get_message("ping_status"),
            lang_manager.get_message("ssh_connectivity"),
            lang_manager.get_message("system_sanity"),
            lang_manager.get_message("uptime_result")
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
        
        self.notebook.add(self.encrypt_frame, text=lang_manager.get_message("tab_encrypt"))
        self.notebook.add(self.health_frame, text=lang_manager.get_message("tab_health"))
        self.notebook.add(self.results_frame, text=lang_manager.get_message("tab_results"))
        
    def create_encryption_tab(self):
        """Create encryption tab"""
        # Title
        self.encrypt_title_label = ttk.Label(self.encrypt_frame, text=lang_manager.get_message("encrypt_title"), 
                                           font=("Arial", 12, "bold"))
        self.encrypt_title_label.pack(pady=10)
        
        # Source file selection
        source_frame = ttk.Frame(self.encrypt_frame)
        source_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.source_file_label = ttk.Label(source_frame, text=lang_manager.get_message("source_file_label"))
        self.source_file_label.pack(side=tk.LEFT)
        ttk.Entry(source_frame, textvariable=self.source_file_var, width=50).pack(side=tk.LEFT, padx=5)
        self.browse_source_btn = ttk.Button(source_frame, text=lang_manager.get_message("browse_button"), 
                                          command=self.browse_source_file)
        self.browse_source_btn.pack(side=tk.LEFT, padx=5)
        
        # Output file selection
        output_frame = ttk.Frame(self.encrypt_frame)
        output_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.output_file_label = ttk.Label(output_frame, text=lang_manager.get_message("output_file_label"))
        self.output_file_label.pack(side=tk.LEFT)
        ttk.Entry(output_frame, textvariable=self.output_file_var, width=50).pack(side=tk.LEFT, padx=5)
        
        # Encrypt button
        self.encrypt_btn = ttk.Button(self.encrypt_frame, text=lang_manager.get_message("encrypt_button"), 
                                    command=self.encrypt_file)
        self.encrypt_btn.pack(pady=20)
        
        # Results area
        self.encrypt_results = ScrolledText(self.encrypt_frame, height=15, width=80)
        self.encrypt_results.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_health_check_tab(self):
        """Create health check tab"""
        # Title
        self.health_title_label = ttk.Label(self.health_frame, text=lang_manager.get_message("health_title"), 
                                          font=("Arial", 12, "bold"))
        self.health_title_label.pack(pady=10)
        
        # Credentials file selection
        creds_frame = ttk.Frame(self.health_frame)
        creds_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.creds_file_label = ttk.Label(creds_frame, text=lang_manager.get_message("creds_file_label"))
        self.creds_file_label.pack(side=tk.LEFT)
        ttk.Entry(creds_frame, textvariable=self.creds_file_var, width=50).pack(side=tk.LEFT, padx=5)
        self.browse_creds_btn = ttk.Button(creds_frame, text=lang_manager.get_message("browse_button"), 
                                         command=self.browse_creds_file)
        self.browse_creds_btn.pack(side=tk.LEFT, padx=5)
        
        # Decryption key
        key_frame = ttk.Frame(self.health_frame)
        key_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.decrypt_key_label = ttk.Label(key_frame, text=lang_manager.get_message("decrypt_key_label"))
        self.decrypt_key_label.pack(side=tk.LEFT)
        ttk.Entry(key_frame, textvariable=self.decrypt_key_var, width=50, show="*").pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(self.health_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text=lang_manager.get_message("start_check_button"), 
                                   command=self.start_health_check)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text=lang_manager.get_message("stop_check_button"), 
                                  command=self.stop_health_check, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.health_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=20, pady=5)
        
        # Log area
        self.log_label = ttk.Label(self.health_frame, text=lang_manager.get_message("log_title"))
        self.log_label.pack(anchor=tk.W, padx=20)
        self.log_text = ScrolledText(self.health_frame, height=15, width=80)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_results_tab(self):
        """Create results tab with CSV-like table"""
        # Title
        self.results_title_label = ttk.Label(self.results_frame, text=lang_manager.get_message("results_title"), 
                                           font=("Arial", 12, "bold"))
        self.results_title_label.pack(pady=10)
        
        # Control buttons
        button_frame = ttk.Frame(self.results_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.export_btn = ttk.Button(button_frame, text=lang_manager.get_message("export_csv_button"), 
                                   command=self.export_to_csv)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text=lang_manager.get_message("clear_results_button"), 
                                  command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Results table
        columns = (
            lang_manager.get_message("sensor_name"),
            lang_manager.get_message("ip_address"),
            lang_manager.get_message("ping_status"),
            lang_manager.get_message("ssh_connectivity"),
            lang_manager.get_message("system_sanity"),
            lang_manager.get_message("uptime_result")
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
            title=lang_manager.get_message("select_source_file"),
            filetypes=[(lang_manager.get_message("json_files"), "*.json"), (lang_manager.get_message("all_files"), "*.*")]
        )
        if filename:
            self.source_file_var.set(filename)
            
    def browse_creds_file(self):
        """Browse for encrypted credentials file"""
        filename = filedialog.askopenfilename(
            title=lang_manager.get_message("select_encrypted_file"),
            filetypes=[(lang_manager.get_message("encrypted_files"), "*.enc"), (lang_manager.get_message("all_files"), "*.*")]
        )
        if filename:
            self.creds_file_var.set(filename)
            
    def encrypt_file(self):
        """Encrypt the credentials file"""
        _import_crypto()  # Import crypto only when needed
        
        source_file = self.source_file_var.get()
        output_file = self.output_file_var.get()
        
        if not source_file or not os.path.exists(source_file):
            messagebox.showerror(lang_manager.get_message("error_title"), lang_manager.get_message("file_not_found"))
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
            self.encrypt_results.insert(tk.END, f"{lang_manager.get_message('file_encrypted')}\n\n")
            self.encrypt_results.insert(tk.END, f"{lang_manager.get_message('encryption_key')}\n")
            self.encrypt_results.insert(tk.END, f"{key.decode()}\n\n")
            self.encrypt_results.insert(tk.END, f"{lang_manager.get_message('encryption_key_warning')}\n")
            
            messagebox.showinfo(lang_manager.get_message("success_title"), lang_manager.get_message("file_encrypted"))
            
        except Exception as e:
            messagebox.showerror(lang_manager.get_message("error_title"), lang_manager.get_message("encryption_failed", str(e)))
            
    def start_health_check(self):
        """Start health check in a separate thread"""
        if self.is_checking:
            return
            
        creds_file = self.creds_file_var.get()
        decrypt_key = self.decrypt_key_var.get()
        
        if not creds_file or not os.path.exists(creds_file):
            messagebox.showerror(lang_manager.get_message("error_title"), lang_manager.get_message("file_not_found"))
            return
            
        if not decrypt_key:
            messagebox.showerror(lang_manager.get_message("error_title"), lang_manager.get_message("please_enter_key"))
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
        self.log_message(lang_manager.get_message("health_check_stopped"))
        
    def run_health_check(self, creds_file, decrypt_key):
        """Run health check process"""
        try:
            # Load credentials
            key = decrypt_key.encode()
            credentials = self.load_credentials(creds_file, key)
            
            if not credentials:
                self.log_message(lang_manager.get_message("failed_to_load_credentials", "Invalid key or file"))
                return
                
            self.log_message(lang_manager.get_message("loaded_credentials", len(credentials)))
            
            # Check each sensor
            for ip, creds in credentials.items():
                if not self.is_checking:
                    break
                    
                sensor_name = creds.get("name", ip)
                result = self.check_sensor(ip, creds, sensor_name)
                
                # Add result to table
                self.root.after(0, self.add_result_to_table, result)
                
        except Exception as e:
            self.log_message(lang_manager.get_message("health_check_error", str(e)))
        finally:
            self.root.after(0, self.health_check_finished)
            
    def health_check_finished(self):
        """Called when health check is finished"""
        self.is_checking = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.log_message(lang_manager.get_message("health_check_complete"))
        
    def load_credentials(self, encrypted_path, key):
        """Load and decrypt credentials"""
        _import_crypto()  # Import crypto only when needed
        
        try:
            cipher = Fernet(key)
            with open(encrypted_path, "rb") as f:
                encrypted_data = f.read()
            decrypted = cipher.decrypt(encrypted_data)
            credentials = json.loads(decrypted.decode())
            return credentials
        except Exception as e:
            self.log_message(lang_manager.get_message("failed_to_load_credentials", str(e)))
            return {}
            
    def check_sensor(self, ip, creds, sensor_name):
        """Check a single sensor and return results"""
        result = {
            "sensor_name": sensor_name,
            "ip_address": ip,
            "ping_status": lang_manager.get_message("status_pending"),
            "ssh_connectivity": lang_manager.get_message("status_pending"),
            "system_sanity": lang_manager.get_message("status_pending"),
            "uptime_result": lang_manager.get_message("status_pending")
        }
        
        self.log_message(lang_manager.get_message("checking_sensor", sensor_name, ip))
        
        # Step 1: Ping test
        if self.ping_sensor(ip):
            result["ping_status"] = lang_manager.get_message("status_ok")
            self.log_message(lang_manager.get_message("sensor_reachable", ip))
        else:
            result["ping_status"] = lang_manager.get_message("status_fail")
            self.log_message(lang_manager.get_message("sensor_unreachable", ip))
            return result
            
        # Step 2: SSH Test User 1 (System Sanity)
        user1 = creds.get("username")
        pass1 = creds.get("password")
        
        if user1 and pass1:
            success, output, error = self.run_ssh_command(ip, user1, pass1, "system sanity")
            if success:
                result["ssh_connectivity"] = lang_manager.get_message("status_ok")
                if output and "system is up" in output.lower():
                    result["system_sanity"] = lang_manager.get_message("status_pass")
                    self.log_message(lang_manager.get_message("system_sanity_passed", ip))
                else:
                    result["system_sanity"] = lang_manager.get_message("status_fail")
                    self.log_message(lang_manager.get_message("system_sanity_failed", ip)
            else:
                result["ssh_connectivity"] = lang_manager.get_message("status_fail")
                result["system_sanity"] = lang_manager.get_message("status_error")
                self.log_message(lang_manager.get_message("ssh_failed", ip, error))
        else:
            result["ssh_connectivity"] = lang_manager.get_message("status_error")
            result["system_sanity"] = lang_manager.get_message("status_error")
            self.log_message(lang_manager.get_message("missing_user1_credentials", ip))
            
        # Step 3: SSH Test User 2 (Uptime)
        user2 = creds.get("username2")
        pass2 = creds.get("password2")
        
        if user2 and pass2:
            success, output, error = self.run_ssh_command(ip, user2, pass2, "uptime")
            if success:
                if output:
                    result["uptime_result"] = lang_manager.get_message("status_pass")
                    self.log_message(lang_manager.get_message("uptime_result", ip, output.strip()))
                else:
                    result["uptime_result"] = lang_manager.get_message("status_warn")
                    self.log_message(lang_manager.get_message("no_uptime_output", ip))
            else:
                result["uptime_result"] = lang_manager.get_message("status_error")
                self.log_message(lang_manager.get_message("uptime_ssh_failed", ip, error))
        else:
            result["uptime_result"] = lang_manager.get_message("status_error")
            self.log_message(lang_manager.get_message("missing_user2_credentials", ip))
            
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
        _import_netmiko()  # Import netmiko only when needed
        
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
                    delay_factor=10,
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
            messagebox.showwarning(lang_manager.get_message("warning_title"), lang_manager.get_message("no_results_to_export"))
            return
            
        filename = filedialog.asksaveasfilename(
            title=lang_manager.get_message("save_results_csv"),
            defaultextension=".csv",
            filetypes=[(lang_manager.get_message("csv_files"), "*.csv"), (lang_manager.get_message("all_files"), "*.*")]
        )
        
        if filename:
            try:
                _import_pandas()  # Import pandas only when needed
                df = pd.DataFrame(self.results_data)
                df.to_csv(filename, index=False)
                messagebox.showinfo(lang_manager.get_message("success_title"), lang_manager.get_message("export_success"))
            except Exception as e:
                messagebox.showerror(lang_manager.get_message("error_title"), lang_manager.get_message("export_failed", str(e)))
                
    def clear_results(self):
        """Clear all results"""
        self.results_data.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.log_text.delete(1.0, tk.END)
        
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime(lang_manager.get_message("timestamp_format"))
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
    main()message("system_sanity_passed", ip))
