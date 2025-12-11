"""
GUI layer for Sensor Management Tool
Uses separated business logic classes for clean architecture
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
from typing import Optional
from datetime import datetime
from core_classes import *

# Import the separated business logic classes
from core_classes import (
    Config,
    CredentialManager,
    SensorHealthChecker,
    Logger,
    ResultsManager,
    SensorResult
)


class TranslationManager:
    """Handles translations and language switching"""
    
    def __init__(self):
        self.current_language = "en"
        self.messages = {}
        self.available_languages = {}
        self.callbacks = []
        self.translations_path = None
        self.load_translations()
    
    def load_translations(self, custom_path: Optional[str] = None):
        """Load all translation files"""
        import json
        import os
        import glob

        # Determine translations directory
        if custom_path and os.path.exists(custom_path):
            translations_dir = custom_path
        else:
            # Get the absolute path of the directory where this script is located
            script_dir = os.path.dirname(os.path.abspath(__file__))
            translations_dir = os.path.join(script_dir, "translations")

        self.translations_path = translations_dir

        # Clear existing translations
        self.messages.clear()
        self.available_languages.clear()
        
        # Discover and load translations
        if os.path.exists(translations_dir):
            for file_path in glob.glob(os.path.join("translations", "*.json")):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        lang_code = os.path.splitext(os.path.basename(file_path))[0]
                        if lang_code in data:
                            self.messages[lang_code] = data[lang_code]
                            display_name = data[lang_code].get("language_display_name", lang_code)
                            self.available_languages[lang_code] = display_name
                except Exception as e:
                    print(f"Error loading translation: {e}")
        
        # Fallback to English
        if not self.available_languages:
            self.available_languages = {"en": "English"}
            self.messages["en"] = {"language_display_name": "English"}
    
    def get_message(self, key: str, *args) -> str:
        """Get translated message"""
        message = self.messages.get(self.current_language, {}).get(key)
        if not message:
            message = self.messages.get("en", {}).get(key, key)
        
        if args:
            try:
                return message.format(*args)
            except (IndexError, KeyError):
                return message
        return message
    
    def set_language(self, lang_code: str):
        """Change current language"""
        if lang_code in self.available_languages:
            self.current_language = lang_code
            for callback in self.callbacks:
                callback()
    
    def add_language_change_callback(self, callback):
        """Register callback for language changes"""
        self.callbacks.append(callback)


class EncryptionTabView:
    """Handles the encryption tab UI"""
    
    def __init__(self, parent, translation_manager: TranslationManager):
        self.parent = parent
        self.tm = translation_manager
        self.credential_manager = CredentialManager()
        
        # Variables
        self.source_file_var = tk.StringVar(value="flag.json")
        self.output_file_var = tk.StringVar(value="sensor_credentials.enc")
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create all widgets for encryption tab"""
        # Title
        self.title_label = ttk.Label(
            self.parent, 
            text=self.tm.get_message("encrypt_title"),
            font=("Arial", 12, "bold")
        )
        self.title_label.pack(pady=10)
        
        # Source file selection
        source_frame = ttk.Frame(self.parent)
        source_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.source_label = ttk.Label(source_frame, text=self.tm.get_message("source_file_label"))
        self.source_label.pack(side=tk.LEFT)
        
        ttk.Entry(source_frame, textvariable=self.source_file_var, width=50).pack(side=tk.LEFT, padx=5)
        
        self.browse_source_btn = ttk.Button(
            source_frame,
            text=self.tm.get_message("browse_button"),
            command=self.browse_source_file
        )
        self.browse_source_btn.pack(side=tk.LEFT, padx=5)
        
        # Output file selection
        output_frame = ttk.Frame(self.parent)
        output_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.output_label = ttk.Label(output_frame, text=self.tm.get_message("output_file_label"))
        self.output_label.pack(side=tk.LEFT)
        
        ttk.Entry(output_frame, textvariable=self.output_file_var, width=50).pack(side=tk.LEFT, padx=5)
        
        # Encrypt button
        self.encrypt_btn = ttk.Button(
            self.parent,
            text=self.tm.get_message("encrypt_button"),
            command=self.encrypt_file
        )
        self.encrypt_btn.pack(pady=20)
        
        # Results area
        self.results_text = ScrolledText(self.parent, height=15, width=80)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def browse_source_file(self):
        """Browse for source file"""
        filename = filedialog.askopenfilename(
            title=self.tm.get_message("select_source_file"),
            filetypes=[
                (self.tm.get_message("json_files"), "*.json"),
                (self.tm.get_message("all_files"), "*.*")
            ]
        )
        if filename:
            self.source_file_var.set(filename)
    
    def encrypt_file(self):
        """Perform file encryption"""
        source_file = self.source_file_var.get()
        output_file = self.output_file_var.get()
        
        try:
            # Generate key and encrypt
            key = self.credential_manager.generate_key()
            self.credential_manager.encrypt_file(source_file, output_file, key)
            
            # Display results
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"{self.tm.get_message('file_encrypted')}\n\n")
            self.results_text.insert(tk.END, f"{self.tm.get_message('encryption_key')}\n")
            self.results_text.insert(tk.END, f"{key.decode()}\n\n")
            self.results_text.insert(tk.END, f"{self.tm.get_message('encryption_key_warning')}\n")
            
            messagebox.showinfo(
                self.tm.get_message("success_title"),
                self.tm.get_message("file_encrypted")
            )
            
        except FileNotFoundError:
            messagebox.showerror(
                self.tm.get_message("error_title"),
                self.tm.get_message("file_not_found")
            )
        except Exception as e:
            messagebox.showerror(
                self.tm.get_message("error_title"),
                self.tm.get_message("encryption_failed", str(e))
            )
    
    def update_text(self):
        """Update all text elements (called on language change)"""
        self.title_label.config(text=self.tm.get_message("encrypt_title"))
        self.source_label.config(text=self.tm.get_message("source_file_label"))
        self.browse_source_btn.config(text=self.tm.get_message("browse_button"))
        self.output_label.config(text=self.tm.get_message("output_file_label"))
        self.encrypt_btn.config(text=self.tm.get_message("encrypt_button"))


class HealthCheckTabView:
    """Handles the health check tab UI"""
    
    def __init__(self, parent, translation_manager: TranslationManager, results_manager: ResultsManager):
        self.parent = parent
        self.tm = translation_manager
        self.results_manager = results_manager
        
        self.credential_manager = CredentialManager()
        self.logger = Logger()
        self.health_checker = SensorHealthChecker(self.logger)
        
        # Variables
        self.creds_file_var = tk.StringVar(value="sensor_credentials.enc")
        self.decrypt_key_var = tk.StringVar()
        self.is_checking = False
        self.check_thread: Optional[threading.Thread] = None
        
        # Setup logger callback
        self.logger.add_callback(self.on_log_message)
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create all widgets for health check tab"""
        # Title
        self.title_label = ttk.Label(
            self.parent,
            text=self.tm.get_message("health_title"),
            font=("Arial", 12, "bold")
        )
        self.title_label.pack(pady=10)
        
        # Credentials file selection
        creds_frame = ttk.Frame(self.parent)
        creds_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.creds_label = ttk.Label(creds_frame, text=self.tm.get_message("creds_file_label"))
        self.creds_label.pack(side=tk.LEFT)
        
        ttk.Entry(creds_frame, textvariable=self.creds_file_var, width=50).pack(side=tk.LEFT, padx=5)
        
        self.browse_creds_btn = ttk.Button(
            creds_frame,
            text=self.tm.get_message("browse_button"),
            command=self.browse_creds_file
        )
        self.browse_creds_btn.pack(side=tk.LEFT, padx=5)
        
        # Decryption key
        key_frame = ttk.Frame(self.parent)
        key_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.key_label = ttk.Label(key_frame, text=self.tm.get_message("decrypt_key_label"))
        self.key_label.pack(side=tk.LEFT)
        
        ttk.Entry(key_frame, textvariable=self.decrypt_key_var, width=50, show="*").pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(self.parent)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.start_btn = ttk.Button(
            button_frame,
            text=self.tm.get_message("start_check_button"),
            command=self.start_health_check
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(
            button_frame,
            text=self.tm.get_message("stop_check_button"),
            command=self.stop_health_check,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.parent, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=20, pady=5)
        
        # Log area
        self.log_label = ttk.Label(self.parent, text=self.tm.get_message("log_title"))
        self.log_label.pack(anchor=tk.W, padx=20)
        
        self.log_text = ScrolledText(self.parent, height=15, width=80)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    def browse_creds_file(self):
        """Browse for credentials file"""
        filename = filedialog.askopenfilename(
            title=self.tm.get_message("select_encrypted_file"),
            filetypes=[
                (self.tm.get_message("encrypted_files"), "*.enc"),
                (self.tm.get_message("all_files"), "*.*")
            ]
        )
        if filename:
            self.creds_file_var.set(filename)
    
    def start_health_check(self):
        """Start the health check process"""
        if self.is_checking:
            return
        
        creds_file = self.creds_file_var.get()
        decrypt_key = self.decrypt_key_var.get()
        
        # Validation
        if not creds_file:
            messagebox.showerror(
                self.tm.get_message("error_title"),
                self.tm.get_message("file_not_found")
            )
            return
        
        if not decrypt_key:
            messagebox.showerror(
                self.tm.get_message("error_title"),
                self.tm.get_message("please_enter_key")
            )
            return
        
        # Update UI state
        self.is_checking = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        
        # Clear previous results
        self.log_text.delete(1.0, tk.END)
        
        # Start health check in separate thread
        self.check_thread = threading.Thread(
            target=self.run_health_check,
            args=(creds_file, decrypt_key),
            daemon=True
        )
        self.check_thread.start()
    
    def stop_health_check(self):
        """Stop the health check process"""
        self.health_checker.stop()
        self.logger.log(self.tm.get_message("health_check_stopped"))
    
    def run_health_check(self, creds_file: str, decrypt_key: str):
        """Run health check in background thread"""
        try:
            # Load credentials
            key = decrypt_key.encode()
            credentials = self.credential_manager.decrypt_file(creds_file, key)
            
            self.logger.log(self.tm.get_message("loaded_credentials", len(credentials)))
            
            # Check each sensor
            for ip, creds in credentials.items():
                if not self.is_checking:
                    break
                
                result = self.health_checker.check_sensor(ip, creds)
                
                # Add result to results manager
                self.results_manager.add_result(result)
            
        except FileNotFoundError:
            self.logger.log(self.tm.get_message("file_not_found"))
        except ValueError as e:
            self.logger.log(self.tm.get_message("failed_to_load_credentials", str(e)))
        except Exception as e:
            self.logger.log(self.tm.get_message("health_check_error", str(e)))
        finally:
            # Update UI state from main thread
            self.parent.after(0, self.health_check_finished)
    
    def health_check_finished(self):
        """Called when health check completes"""
        self.is_checking = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.logger.log(self.tm.get_message("health_check_complete"))
    
    def on_log_message(self, message: str):
        """Callback for log messages (called from logger)"""
        # Update log text from main thread
        self.parent.after(0, self._update_log_text, message)
    
    def _update_log_text(self, message: str):
        """Update log text widget (must be called from main thread)"""
        # Check if user is at bottom before inserting
        at_bottom = self.log_text.yview()[1] == 1.0
        
        self.log_text.insert(tk.END, message + "\n")

        if at_bottom:
            self.log_text.see(tk.END)
    
    def update_text(self):
        """Update all text elements (called on language change)"""
        self.title_label.config(text=self.tm.get_message("health_title"))
        self.creds_label.config(text=self.tm.get_message("creds_file_label"))
        self.browse_creds_btn.config(text=self.tm.get_message("browse_button"))
        self.key_label.config(text=self.tm.get_message("decrypt_key_label"))
        self.start_btn.config(text=self.tm.get_message("start_check_button"))
        self.stop_btn.config(text=self.tm.get_message("stop_check_button"))
        self.log_label.config(text=self.tm.get_message("log_title"))


class ResultsTabView:
    """Handles the results tab UI"""
    
    def __init__(self, parent, translation_manager: TranslationManager, results_manager: ResultsManager):
        self.parent = parent
        self.tm = translation_manager
        self.results_manager = results_manager
        
        self.create_widgets()
        
        # Auto-refresh results every second
        self.refresh_results()
    
    def create_widgets(self):
        """Create all widgets for results tab"""
        # Title
        self.title_label = ttk.Label(
            self.parent,
            text=self.tm.get_message("results_title"),
            font=("Arial", 12, "bold")
        )
        self.title_label.pack(pady=10)
        
        # Control buttons
        button_frame = ttk.Frame(self.parent)
        button_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.export_btn = ttk.Button(
            button_frame,
            text=self.tm.get_message("export_csv_button"),
            command=self.export_to_csv
        )
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(
            button_frame,
            text=self.tm.get_message("clear_results_button"),
            command=self.clear_results
        )
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Summary label
        self.summary_label = ttk.Label(button_frame, text="")
        self.summary_label.pack(side=tk.LEFT, padx=20)
        
        # Results table frame
        table_frame = ttk.Frame(self.parent)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Define columns
        columns = (
            #self.tm.get_message("sensor_name"),
            self.tm.get_message("ip_address"),
            self.tm.get_message("ping_status"),
            self.tm.get_message("ssh_connectivity"),
            self.tm.get_message("system_sanity"),
            self.tm.get_message("uptime_column")
        )
        
        self.results_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        
        # Define column headings
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=120)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack table and scrollbars
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
    
    def refresh_results(self):
        """Refresh the results table periodically"""
        # Get current results
        results = self.results_manager.get_all_results()
        
        # Get current item count
        current_count = len(self.results_tree.get_children())
        
        # If new results, update table
        if len(results) > current_count:
            for result in results[current_count:]:
                # Format sanity display
                sanity_display = self.tm.get_message(result.system_sanity)
                if result.sanity_output:
                    sanity_display = f"{sanity_display} : {result.sanity_output}"
                
                # Format uptime display
                uptime_display = self.tm.get_message(result.uptime_result)
                if result.uptime_output:
                    uptime_display = f"{uptime_display} : {result.uptime_output}"

                translated_values = (
                    #result.sensor_name,
                    result.ip_address,
                    self.tm.get_message(result.ping_status),  # Translate here
                    self.tm.get_message(result.ssh_connectivity),
                    sanity_display,
                    uptime_display
                )
                self.results_tree.insert("", tk.END, values=translated_values)
        
        # Update summary
        self.update_summary()
        
        # Schedule next refresh
        self.parent.after(1000, self.refresh_results)
    
    def update_summary(self):
        """Update the summary statistics"""
        summary = self.results_manager.get_summary()
        summary_text = (
            f"Total: {summary['total']} | "
            f"Ping OK: {summary['ping_ok']} | "
            f"SSH OK: {summary['ssh_ok']} | "
            f"Sanity Pass: {summary['sanity_pass']} | "
            f"Uptime Pass: {summary['uptime_pass']}"
        )
        self.summary_label.config(text=summary_text)
    
    def export_to_csv(self):
        """Export results to CSV file"""
        if not self.results_manager.get_all_results():
            messagebox.showwarning(
                self.tm.get_message("warning_title"),
                self.tm.get_message("no_results_to_export")
            )
            return
        
        filename = filedialog.asksaveasfilename(
            title=self.tm.get_message("save_results_csv"),
            defaultextension=".csv",
            filetypes=[
                (self.tm.get_message("csv_files"), "*.csv"),
                (self.tm.get_message("all_files"), "*.*")
            ]
        )
        
        if filename:
            try:
                self.results_manager.export_to_csv(filename)
                messagebox.showinfo(
                    self.tm.get_message("success_title"),
                    self.tm.get_message("export_success")
                )
            except Exception as e:
                messagebox.showerror(
                    self.tm.get_message("error_title"),
                    self.tm.get_message("export_failed", str(e))
                )
    
    def clear_results(self):
        """Clear all results"""
        self.results_manager.clear_results()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.update_summary()
    
    def update_text(self):
        """Update all text elements (called on language change)"""
        self.title_label.config(text=self.tm.get_message("results_title"))
        self.export_btn.config(text=self.tm.get_message("export_csv_button"))
        self.clear_btn.config(text=self.tm.get_message("clear_results_button"))
        
        # Update column headings
        columns = [
            #self.tm.get_message("sensor_name"),
            self.tm.get_message("ip_address"),
            self.tm.get_message("ping_status"),
            self.tm.get_message("ssh_connectivity"),
            self.tm.get_message("system_sanity"),
            self.tm.get_message("uptime_column")
        ]
        
        for i, col in enumerate(columns):
            self.results_tree.heading(f"#{i+1}", text=col)
        
        self.update_summary()

        for item in self.results_tree.get_children():
            # Get the result index
            idx = self.results_tree.index(item)
            result = self.results_manager.get_all_results()[idx]

            # Format sanity display
            sanity_display = self.tm.get_message(result.system_sanity)
            if result.sanity_output:
                sanity_display = f"{sanity_display} : {result.sanity_output}"

            # Format uptime display
            uptime_display = self.tm.get_message(result.uptime_result)
            if result.uptime_output:
                uptime_display = f"{uptime_display} : {result.uptime_output}"
            
            # Update with translated values
            translated_values = (
                #result.sensor_name,
                result.ip_address,
                self.tm.get_message(result.ping_status),
                self.tm.get_message(result.ssh_connectivity),
                sanity_display,
                uptime_display
            )
            self.results_tree.item(item, values=translated_values)


class SettingsDialogView:
    """Handles the settings dialog UI"""
    
    def __init__(self, dialog_window, translation_manager: TranslationManager):
        self.dialog = dialog_window
        self.tm = translation_manager
        self.config = Config()
        
        # Variables to hold setting values
        self.setting_vars = {}
        
        self.create_widgets()
        self.load_current_settings()
    
    def create_widgets(self):
        """Create all widgets for settings dialog"""
        # Title
        title_label = ttk.Label(
            self.dialog,
            text="Settings",
            font=("Arial", 12, "bold")
        )
        title_label.pack(pady=10)
        
        # Main frame with scrollbar
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Create input fields for each setting
        for key in Config.DEFAULT_VALUES.keys():
            frame = ttk.Frame(scrollable_frame)
            frame.pack(fill=tk.X, pady=5)
            
            # Label
            label_text = key.replace('_', ' ').title()
            ttk.Label(frame, text=label_text, width=30).pack(side=tk.LEFT)
            
            # Input field
            var = tk.StringVar()
            self.setting_vars[key] = var
            ttk.Entry(frame, textvariable=var, width=20).pack(side=tk.LEFT, padx=5)
            
            # Default value label
            default_val = Config.DEFAULT_VALUES[key]
            ttk.Label(frame, text=f"(default: {default_val})", 
                     foreground="gray").pack(side=tk.LEFT)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Buttons at bottom
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Button(
            button_frame,
            text="Save",
            command=self.save_settings
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Reset to Defaults",
            command=self.reset_to_defaults
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Cancel",
            command=self.dialog.destroy
        ).pack(side=tk.RIGHT, padx=5)
    
    def load_current_settings(self):
        """Load current settings into the form"""
        current_settings = self.config.get_all_settings()
        for key, value in current_settings.items():
            if key in self.setting_vars:
                self.setting_vars[key].set(str(value))
    
    def save_settings(self):
        """Save settings from form"""
        try:
            # Validate and update each setting
            for key, var in self.setting_vars.items():
                value_str = var.get()
                default_type = type(Config.DEFAULT_VALUES[key])
                
                # Convert to appropriate type
                if default_type == int:
                    value = int(value_str)
                elif default_type == float:
                    value = float(value_str)
                else:
                    value = value_str
                
                self.config.update_setting(key, value)
            
            # Save to file
            if self.config.save_config():
                messagebox.showinfo(
                    "Success",
                    "Settings saved successfully! Changes will take effect on next check."
                )
                self.dialog.destroy()
            else:
                messagebox.showerror(
                    "Error",
                    "Failed to save settings"
                )
                
        except ValueError as e:
            messagebox.showerror(
                "Error",
                f"Invalid value: {str(e)}"
            )
    
    def reset_to_defaults(self):
        """Reset all settings to defaults"""
        if messagebox.askyesno(
            "Confirm Reset",
            "Reset all settings to defaults?"
        ):
            self.config.reset_to_defaults()
            self.load_current_settings()


class SensorGUI:
    """Main GUI application - orchestrates all views"""
    
    def __init__(self, root):
        self.root = root
        
        # Initialize managers
        self.translation_manager = TranslationManager()
        self.results_manager = ResultsManager()
        
        # Setup window
        self.root.title(self.translation_manager.get_message("app_title"))
        self.root.geometry("1000x700")
        
        # Register for language change notifications
        self.translation_manager.add_language_change_callback(self.on_language_changed)
        
        # Create UI
        self.create_language_selection()
        self.create_notebook()
    
    def create_language_selection(self):
        """Create language selection dropdown and settings button"""
        lang_frame = ttk.Frame(self.root)
        lang_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.lang_label = ttk.Label(
            lang_frame,
            text=self.translation_manager.get_message("language_select")
        )
        self.lang_label.pack(side=tk.LEFT)
        
        # Create dropdown
        self.language_var = tk.StringVar(value=self.translation_manager.current_language)
        self.language_dropdown = ttk.Combobox(
            lang_frame,
            textvariable=self.language_var,
            state="readonly",
            width=20
        )
        
        # Populate dropdown
        self.language_options = []
        self.language_codes = []
        
        for code, name in self.translation_manager.available_languages.items():
            self.language_options.append(name)
            self.language_codes.append(code)
        
        self.language_dropdown['values'] = self.language_options
        
        # Set current selection
        try:
            current_index = self.language_codes.index(self.translation_manager.current_language)
            self.language_dropdown.current(current_index)
        except ValueError:
            self.language_dropdown.current(0)
        
        self.language_dropdown.bind('<<ComboboxSelected>>', self.on_language_dropdown_changed)
        self.language_dropdown.pack(side=tk.LEFT, padx=10)

        # Settings button
        self.settings_btn = ttk.Button(
            lang_frame,
            text="⚙ Settings",  # Or use an icon
            command=self.open_settings_dialog
        )
        self.settings_btn.pack(side=tk.RIGHT, padx=10)
    
    def on_language_dropdown_changed(self, event=None):
        """Handle language dropdown selection"""
        selected_index = self.language_dropdown.current()
        if 0 <= selected_index < len(self.language_codes):
            new_language = self.language_codes[selected_index]
            self.translation_manager.set_language(new_language)
    
    def on_language_changed(self):
        """Called when language changes - update all UI text"""
        self.root.title(self.translation_manager.get_message("app_title"))
        self.lang_label.config(text=self.translation_manager.get_message("language_select"))
        
        # Update notebook tabs
        self.notebook.tab(0, text=self.translation_manager.get_message("tab_encrypt"))
        self.notebook.tab(1, text=self.translation_manager.get_message("tab_health"))
        self.notebook.tab(2, text=self.translation_manager.get_message("tab_results"))
        self.notebook.tab(3, text="Settings")
        
        # Update each tab view
        self.encryption_view.update_text()
        self.health_check_view.update_text()
        self.results_view.update_text()
        self.settings_view.update_text()

    def open_settings_dialog(self):
        """Open settings in a popup dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Settings")
        dialog.geometry("600x500")
        dialog.transient(self.root)  # Make it a child of main window
        dialog.grab_set()  # Make it modal
        
        # Create the settings view in the dialog
        SettingsDialogView(dialog, self.translation_manager)
    
    def create_notebook(self):
        """Create main notebook with tabs"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create frames for each tab
        encrypt_frame = ttk.Frame(self.notebook)
        health_frame = ttk.Frame(self.notebook)
        results_frame = ttk.Frame(self.notebook)
        
        # Create view objects for each tab
        self.encryption_view = EncryptionTabView(encrypt_frame, self.translation_manager)
        self.health_check_view = HealthCheckTabView(
            health_frame,
            self.translation_manager,
            self.results_manager
        )
        self.results_view = ResultsTabView(
            results_frame,
            self.translation_manager,
            self.results_manager
        )
        
        # Add tabs to notebook
        self.notebook.add(encrypt_frame, text=self.translation_manager.get_message("tab_encrypt"))
        self.notebook.add(health_frame, text=self.translation_manager.get_message("tab_health"))
        self.notebook.add(results_frame, text=self.translation_manager.get_message("tab_results"))


def main():
    """Application entry point"""
    root = tk.Tk()
    app = SensorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
