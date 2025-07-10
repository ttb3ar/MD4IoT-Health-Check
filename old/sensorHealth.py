import json
import os
import socket
import subprocess
import platform
import paramiko
import threading
import time
from datetime import datetime
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.simpledialog import askstring

class SensorHealthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sensor Health Check Tool")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.credentials = {}
        self.encryption_key = None
        self.is_checking = False
        self.check_thread = None
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('Title.TLabel', font=('Arial', 14, 'bold'))
        self.style.configure('Header.TLabel', font=('Arial', 10, 'bold'))
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Sensor Health Check Tool", style='Title.TLabel')
        title_label.grid(row=0, column=0, pady=(0, 20))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Create tabs
        self.create_credentials_tab()
        self.create_health_check_tab()
        self.create_log_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
    def create_credentials_tab(self):
        # Credentials management tab
        cred_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(cred_frame, text="Credentials")
        
        # Configure grid
        cred_frame.columnconfigure(0, weight=1)
        cred_frame.rowconfigure(2, weight=1)
        
        # Load/Create credentials section
        load_frame = ttk.LabelFrame(cred_frame, text="Load/Create Credentials", padding="10")
        load_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        load_frame.columnconfigure(1, weight=1)
        
        ttk.Button(load_frame, text="Load JSON File", command=self.load_json_file).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(load_frame, text="Load Encrypted File", command=self.load_encrypted_file).grid(row=0, column=1, padx=(0, 10))
        ttk.Button(load_frame, text="Create New", command=self.create_new_credentials).grid(row=0, column=2)
        
        # Encryption section
        encrypt_frame = ttk.LabelFrame(cred_frame, text="Encryption", padding="10")
        encrypt_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        encrypt_frame.columnconfigure(1, weight=1)
        
        ttk.Button(encrypt_frame, text="Generate New Key", command=self.generate_key).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(encrypt_frame, text="Enter Key", command=self.enter_key).grid(row=0, column=1, padx=(0, 10))
        ttk.Button(encrypt_frame, text="Save Encrypted", command=self.save_encrypted).grid(row=0, column=2)
        
        # Current key status
        self.key_status = ttk.Label(encrypt_frame, text="No encryption key set", foreground="red")
        self.key_status.grid(row=1, column=0, columnspan=3, pady=(10, 0))
        
        # Credentials display/edit
        cred_display_frame = ttk.LabelFrame(cred_frame, text="Credentials", padding="10")
        cred_display_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        cred_display_frame.columnconfigure(0, weight=1)
        cred_display_frame.rowconfigure(0, weight=1)
        
        # Treeview for credentials
        self.cred_tree = ttk.Treeview(cred_display_frame, columns=('username', 'username2'), show='tree headings', height=10)
        self.cred_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar for treeview
        cred_scrollbar = ttk.Scrollbar(cred_display_frame, orient=tk.VERTICAL, command=self.cred_tree.yview)
        cred_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.cred_tree.configure(yscrollcommand=cred_scrollbar.set)
        
        # Configure treeview columns
        self.cred_tree.heading('#0', text='IP Address')
        self.cred_tree.heading('username', text='User 1')
        self.cred_tree.heading('username2', text='User 2')
        self.cred_tree.column('#0', width=150)
        self.cred_tree.column('username', width=100)
        self.cred_tree.column('username2', width=100)
        
        # Buttons for credential management
        cred_button_frame = ttk.Frame(cred_display_frame)
        cred_button_frame.grid(row=1, column=0, columnspan=2, pady=(10, 0))
        
        ttk.Button(cred_button_frame, text="Add Sensor", command=self.add_sensor).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(cred_button_frame, text="Edit Sensor", command=self.edit_sensor).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(cred_button_frame, text="Remove Sensor", command=self.remove_sensor).pack(side=tk.LEFT)
        
    def create_health_check_tab(self):
        # Health check tab
        health_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(health_frame, text="Health Check")
        
        # Configure grid
        health_frame.columnconfigure(0, weight=1)
        health_frame.rowconfigure(1, weight=1)
        
        # Control buttons
        control_frame = ttk.Frame(health_frame)
        control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.start_button = ttk.Button(control_frame, text="Start Health Check", command=self.start_health_check)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_health_check, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(control_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT)
        
        # Progress bar
        self.progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.progress.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Results display
        results_frame = ttk.LabelFrame(health_frame, text="Results", padding="10")
        results_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=20)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure text tags for colored output
        self.results_text.tag_configure("ERROR", foreground="red")
        self.results_text.tag_configure("FAIL", foreground="red")
        self.results_text.tag_configure("PASS", foreground="green")
        self.results_text.tag_configure("OK", foreground="green")
        self.results_text.tag_configure("WARN", foreground="orange")
        self.results_text.tag_configure("INFO", foreground="blue")
        
    def create_log_tab(self):
        # Log tab
        log_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(log_frame, text="Log")
        
        # Configure grid
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)
        
        # Log controls
        log_control_frame = ttk.Frame(log_frame)
        log_control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(log_control_frame, text="Refresh Log", command=self.refresh_log).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(log_control_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(log_control_frame, text="Save Log", command=self.save_log).pack(side=tk.LEFT)
        
        # Log display
        log_display_frame = ttk.LabelFrame(log_frame, text="Log Content", padding="10")
        log_display_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_display_frame.columnconfigure(0, weight=1)
        log_display_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_display_frame, wrap=tk.WORD, height=20, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def log_message(self, message, tag=None):
        """Log message to both results and log file"""
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        full_message = f"{timestamp} {message}\n"
        
        # Write to log file
        with open("sensor_check.log", "a") as f:
            f.write(full_message)
        
        # Update GUI
        self.results_text.insert(tk.END, full_message, tag)
        self.results_text.see(tk.END)
        self.root.update_idletasks()
        
    def load_json_file(self):
        """Load credentials from JSON file"""
        filename = filedialog.askopenfilename(
            title="Select JSON credentials file",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    self.credentials = json.load(f)
                self.update_credentials_display()
                self.status_var.set(f"Loaded {len(self.credentials)} sensors from {filename}")
                messagebox.showinfo("Success", f"Loaded {len(self.credentials)} sensors")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load JSON file: {str(e)}")
                
    def load_encrypted_file(self):
        """Load credentials from encrypted file"""
        if not self.encryption_key:
            messagebox.showerror("Error", "Please enter encryption key first")
            return
            
        filename = filedialog.askopenfilename(
            title="Select encrypted credentials file",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                cipher = Fernet(self.encryption_key)
                with open(filename, "rb") as f:
                    encrypted_data = f.read()
                decrypted = cipher.decrypt(encrypted_data)
                self.credentials = json.loads(decrypted.decode())
                self.update_credentials_display()
                self.status_var.set(f"Loaded {len(self.credentials)} sensors from encrypted file")
                messagebox.showinfo("Success", f"Loaded {len(self.credentials)} sensors from encrypted file")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load encrypted file: {str(e)}")
                
    def create_new_credentials(self):
        """Create new empty credentials"""
        self.credentials = {}
        self.update_credentials_display()
        self.status_var.set("Created new credentials")
        
    def generate_key(self):
        """Generate new encryption key"""
        key = Fernet.generate_key()
        self.encryption_key = key
        self.update_key_status()
        
        # Show key to user
        key_str = key.decode()
        messagebox.showinfo("Encryption Key Generated", 
                          f"Save this key securely:\n\n{key_str}\n\nThis key is now active for encryption/decryption.")
        
    def enter_key(self):
        """Enter existing encryption key"""
        key_str = askstring("Enter Encryption Key", "Enter the encryption key:", show='*')
        if key_str:
            try:
                self.encryption_key = key_str.encode()
                # Test the key
                Fernet(self.encryption_key)
                self.update_key_status()
                messagebox.showinfo("Success", "Encryption key accepted")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid encryption key: {str(e)}")
                self.encryption_key = None
                self.update_key_status()
                
    def update_key_status(self):
        """Update key status display"""
        if self.encryption_key:
            self.key_status.config(text="Encryption key is set", foreground="green")
        else:
            self.key_status.config(text="No encryption key set", foreground="red")
            
    def save_encrypted(self):
        """Save credentials to encrypted file"""
        if not self.encryption_key:
            messagebox.showerror("Error", "Please generate or enter encryption key first")
            return
            
        if not self.credentials:
            messagebox.showerror("Error", "No credentials to save")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save encrypted credentials",
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                cipher = Fernet(self.encryption_key)
                data = json.dumps(self.credentials).encode()
                encrypted_data = cipher.encrypt(data)
                
                with open(filename, "wb") as f:
                    f.write(encrypted_data)
                    
                messagebox.showinfo("Success", f"Credentials encrypted and saved to {filename}")
                self.status_var.set(f"Saved encrypted credentials to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save encrypted file: {str(e)}")
                
    def update_credentials_display(self):
        """Update the credentials treeview"""
        # Clear existing items
        for item in self.cred_tree.get_children():
            self.cred_tree.delete(item)
            
        # Add credentials
        for ip, creds in self.credentials.items():
            self.cred_tree.insert('', 'end', text=ip, values=(
                creds.get('username', ''),
                creds.get('username2', '')
            ))
            
    def add_sensor(self):
        """Add new sensor dialog"""
        dialog = SensorDialog(self.root, "Add Sensor")
        if dialog.result:
            ip, username, password, username2, password2 = dialog.result
            self.credentials[ip] = {
                'username': username,
                'password': password,
                'username2': username2,
                'password2': password2
            }
            self.update_credentials_display()
            self.status_var.set(f"Added sensor {ip}")
            
    def edit_sensor(self):
        """Edit selected sensor"""
        selected = self.cred_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a sensor to edit")
            return
            
        item = selected[0]
        ip = self.cred_tree.item(item, 'text')
        current_creds = self.credentials.get(ip, {})
        
        dialog = SensorDialog(self.root, "Edit Sensor", ip, current_creds)
        if dialog.result:
            new_ip, username, password, username2, password2 = dialog.result
            
            # Remove old entry if IP changed
            if new_ip != ip:
                del self.credentials[ip]
                
            self.credentials[new_ip] = {
                'username': username,
                'password': password,
                'username2': username2,
                'password2': password2
            }
            self.update_credentials_display()
            self.status_var.set(f"Updated sensor {new_ip}")
            
    def remove_sensor(self):
        """Remove selected sensor"""
        selected = self.cred_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a sensor to remove")
            return
            
        item = selected[0]
        ip = self.cred_tree.item(item, 'text')
        
        if messagebox.askyesno("Confirm", f"Remove sensor {ip}?"):
            del self.credentials[ip]
            self.update_credentials_display()
            self.status_var.set(f"Removed sensor {ip}")
            
    def start_health_check(self):
        """Start health check in separate thread"""
        if not self.credentials:
            messagebox.showerror("Error", "No credentials loaded")
            return
            
        if self.is_checking:
            return
            
        self.is_checking = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start()
        
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        
        # Start check in separate thread
        self.check_thread = threading.Thread(target=self.run_health_check)
        self.check_thread.daemon = True
        self.check_thread.start()
        
    def stop_health_check(self):
        """Stop health check"""
        self.is_checking = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
        self.status_var.set("Health check stopped")
        
    def run_health_check(self):
        """Run health check for all sensors"""
        try:
            self.log_message("=== Sensor Health Check Started ===", "INFO")
            
            for ip, creds in self.credentials.items():
                if not self.is_checking:
                    break
                    
                self.check_sensor(ip, creds)
                time.sleep(1)  # Small delay between sensors
                
            self.log_message("=== Sensor Health Check Completed ===", "INFO")
            
        except Exception as e:
            self.log_message(f"[ERROR] Fatal error in health check: {e}", "ERROR")
        finally:
            self.root.after(0, self.stop_health_check)
            
    def check_sensor(self, ip, creds):
        """Check individual sensor health"""
        self.log_message(f"--- Checking sensor at {ip} ---", "INFO")
        
        # Step 1: Ping test
        if self.ping_sensor(ip):
            self.log_message(f"[OK] Sensor {ip} is reachable via ping.", "OK")
        else:
            self.log_message(f"[FAIL] Sensor {ip} is not reachable via ping.", "FAIL")
            return
            
        # Step 2: Test User 1
        user1, pass1 = creds.get("username"), creds.get("password")
        if not user1 or not pass1:
            self.log_message(f"[ERROR] Missing credentials for user1 on {ip}", "ERROR")
            return
            
        success1, output1, err1 = self.run_ssh_command(ip, user1, pass1, "system sanity")
        
        if success1:
            if output1:
                lines = output1.strip().splitlines()
                if len(lines) >= 2 and lines[-2] == "System is UP! (L100)":
                    self.log_message(f"[PASS] {ip} - User1 ({user1}): system sanity passed.", "PASS")
                else:
                    self.log_message(f"[FAIL] {ip} - User1 ({user1}): Unexpected output format", "FAIL")
            else:
                self.log_message(f"[FAIL] {ip} - User1 ({user1}): No output received", "FAIL")
        else:
            self.log_message(f"[ERROR] {ip} - User1 ({user1}) failed: {err1}", "ERROR")
            
        # Step 3: Test User 2
        user2, pass2 = creds.get("username2"), creds.get("password2")
        if not user2 or not pass2:
            self.log_message(f"[ERROR] Missing credentials for user2 on {ip}", "ERROR")
            return
            
        success2, output2, err2 = self.run_ssh_command(ip, user2, pass2, "uptime")
        
        if success2:
            if output2:
                self.log_message(f"[PASS] {ip} - User2 ({user2}): uptime output: {output2}", "PASS")
            else:
                self.log_message(f"[WARN] {ip} - User2 ({user2}): SSH successful but no uptime output", "WARN")
        else:
            self.log_message(f"[ERROR] {ip} - User2 ({user2}) failed: {err2}", "ERROR")
            
    def ping_sensor(self, ip, timeout=2):
        """Ping sensor to check connectivity"""
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except Exception as e:
            self.log_message(f"[ERROR] Ping failed for {ip}: {e}", "ERROR")
            return False
            
    def run_ssh_command(self, ip, username, password, command, timeout=15):
        """Execute SSH command on sensor"""
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                ip, 
                username=username, 
                password=password, 
                timeout=timeout,
                look_for_keys=False, 
                allow_agent=False,
                banner_timeout=30
            )
            
            stdin, stdout, stderr = client.exec_command(command, timeout=30)
            
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            
            return True, output, error
            
        except Exception as e:
            return False, "", str(e)
        finally:
            if client:
                try:
                    client.close()
                except:
                    pass
                    
    def clear_results(self):
        """Clear results display"""
        self.results_text.delete(1.0, tk.END)
        
    def refresh_log(self):
        """Refresh log display"""
        try:
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            
            if os.path.exists("sensor_check.log"):
                with open("sensor_check.log", "r") as f:
                    content = f.read()
                self.log_text.insert(1.0, content)
                
            self.log_text.config(state=tk.DISABLED)
            self.log_text.see(tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh log: {str(e)}")
            
    def clear_log(self):
        """Clear log file and display"""
        if messagebox.askyesno("Confirm", "Clear log file?"):
            try:
                if os.path.exists("sensor_check.log"):
                    os.remove("sensor_check.log")
                self.log_text.config(state=tk.NORMAL)
                self.log_text.delete(1.0, tk.END)
                self.log_text.config(state=tk.DISABLED)
                self.status_var.set("Log cleared")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear log: {str(e)}")
                
    def save_log(self):
        """Save log to file"""
        filename = filedialog.asksaveasfilename(
            title="Save log file",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                content = self.log_text.get(1.0, tk.END)
                with open(filename, "w") as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Log saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {str(e)}")


class SensorDialog:
    def __init__(self, parent, title, ip="", creds=None):
        self.result = None
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (300 // 2)
        self.dialog.geometry(f"400x300+{x}+{y}")
        
        # Create form
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # IP Address
        ttk.Label(main_frame, text="IP Address:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip_var = tk.StringVar(value=ip)
        ttk.Entry(main_frame, textvariable=self.ip_var, width=30).grid(row=0, column=1, pady=5, sticky=(tk.W, tk.E))
        
        # User 1
        ttk.Label(main_frame, text="Username 1:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.user1_var = tk.StringVar(value=creds.get('username', '') if creds else '')
        ttk.Entry(main_frame, textvariable=self.user1_var, width=30).grid(row=1, column=1, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Label(main_frame, text="Password 1:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.pass1_var = tk.StringVar(value=creds.get('password', '') if creds else '')
        ttk.Entry(main_frame, textvariable=self.pass1_var, width=30, show="*").grid(row=2, column=1, pady=5, sticky=(tk.W, tk.E))
        
        # User 2
        ttk.Label(main_frame, text="Username 2:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.user2_var = tk.StringVar(value=creds.get('username2', '') if creds else '')
        ttk.Entry(main_frame, textvariable=self.user2_var, width=30).grid(row=3, column=1, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Label(main_frame, text="Password 2:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.pass2_var = tk.StringVar(value=creds.get('password2', '') if creds else '')
        ttk.Entry(main_frame, textvariable=self.pass2_var, width=30, show="*").grid(row=4, column=1, pady=5, sticky=(tk.W, tk.E))
        
        # Configure column weight
        main_frame.columnconfigure(1, weight=1)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="OK", command=self.ok_clicked).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=self.cancel_clicked).pack(side=tk.LEFT)
        
        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self.ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self.cancel_clicked())
        
        # Wait for dialog to close
        self.dialog.wait_window()
        
    def ok_clicked(self):
        """Handle OK button click"""
        ip = self.ip_var.get().strip()
        user1 = self.user1_var.get().strip()
        pass1 = self.pass1_var.get()
        user2 = self.user2_var.get().strip()
        pass2 = self.pass2_var.get()
        
        if not ip:
            messagebox.showerror("Error", "IP Address is required")
            return
            
        if not user1 or not pass1:
            messagebox.showerror("Error", "Username 1 and Password 1 are required")
            return
            
        if not user2 or not pass2:
            messagebox.showerror("Error", "Username 2 and Password 2 are required")
            return
            
        self.result = (ip, user1, pass1, user2, pass2)
        self.dialog.destroy()
        
    def cancel_clicked(self):
        """Handle Cancel button click"""
        self.dialog.destroy()


def main():
    """Main function to run the GUI application"""
    root = tk.Tk()
    app = SensorHealthGUI(root)
    
    # Handle window close event
    def on_closing():
        if app.is_checking:
            if messagebox.askokcancel("Quit", "Health check is running. Do you want to quit?"):
                app.stop_health_check()
                root.destroy()
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("Application interrupted by user")
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Application Error", f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
