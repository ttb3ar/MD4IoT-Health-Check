"""
Core business logic classes for Sensor Management Tool
Separated from GUI concerns for better maintainability and testability
"""

import json
import os
import subprocess
import platform
from datetime import datetime
from typing import Dict, Tuple, Optional, Any, List
from cryptography.fernet import Fernet
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
    SSHException
)


class Config:
    """Configuration constants and settings"""
    LOG_FILE = "sensor_check.log"
    DEFAULT_SSH_TIMEOUT = 75
    DEFAULT_PING_TIMEOUT = 75
    SSH_BANNER_TIMEOUT = 75
    SSH_SESSION_TIMEOUT = 75
    SYSTEM_SANITY_DELAY_FACTOR = 10
    SYSTEM_SANITY_MAX_LOOPS = 20
    UPTIME_DELAY_FACTOR = 10
    UPTIME_MAX_LOOPS = 10
    SHELL_COMMAND_DELAY = 2  # Delay for shell transitions


class CredentialManager:
    """Handles encryption and decryption of credential files"""
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    @staticmethod
    def encrypt_file(source_path: str, output_path: str, key: bytes) -> None:
        """
        Encrypt a file with the given key
        
        Args:
            source_path: Path to source file
            output_path: Path to save encrypted file
            key: Encryption key
            
        Raises:
            FileNotFoundError: If source file doesn't exist
            ValueError: If encryption fails
        """
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source file not found: {source_path}")
        
        try:
            with open(source_path, "rb") as f:
                data = f.read()
            
            cipher = Fernet(key)
            encrypted_data = cipher.encrypt(data)
            
            with open(output_path, "wb") as f:
                f.write(encrypted_data)
                
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_file(encrypted_path: str, key: bytes) -> Dict[str, Any]:
        """
        Decrypt and load credentials from file
        
        Args:
            encrypted_path: Path to encrypted file
            key: Decryption key
            
        Returns:
            Dictionary containing credentials
            
        Raises:
            FileNotFoundError: If encrypted file doesn't exist
            ValueError: If decryption or JSON parsing fails
        """
        if not os.path.exists(encrypted_path):
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")
        
        try:
            cipher = Fernet(key)
            with open(encrypted_path, "rb") as f:
                encrypted_data = f.read()
            
            decrypted = cipher.decrypt(encrypted_data)
            credentials = json.loads(decrypted.decode())
            return credentials
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")


class NetworkTester:
    """Handles network connectivity tests"""
    
    @staticmethod
    def ping(ip: str, timeout: int = Config.DEFAULT_PING_TIMEOUT) -> bool:
        """
        Ping a host to check basic connectivity
        
        Args:
            ip: IP address to ping
            timeout: Timeout in seconds
            
        Returns:
            True if ping successful, False otherwise
        """
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
            
            result = subprocess.run(
                cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1
            )
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, Exception):
            return False


class SSHCommandRunner:
    """Handles SSH command execution"""
    
    def __init__(self, timeout: int = Config.DEFAULT_SSH_TIMEOUT):
        self.timeout = timeout
    
    def execute_commands_single_session(
        self,
        ip: str,
        username: str,
        password: str
    ) -> Tuple[bool, str, str, str, str]:
        """
        Execute both system sanity and uptime checks in a single SSH session
        
        Args:
            ip: Host IP address
            username: SSH username (initial login)
            password: SSH password (initial login)
            cyberx_password: Password for 'cyberx' user (su command)
            
        Returns:
            Tuple of (success, sanity_output, uptime_output, error_stage, error_message)
            error_stage can be: "connection", "system_sanity", "shell", "su", "uptime"
        """
        connection = None
        try:
            device = {
                'device_type': 'terminal_server',
                'host': ip,
                'username': username,
                'password': password,
                'timeout': self.timeout,
                'banner_timeout': Config.SSH_BANNER_TIMEOUT,
                'conn_timeout': self.timeout,
                'auth_timeout': self.timeout,
                'session_log': None,
                'keepalive': 0,
                'default_enter': '\r\n',
                'response_return': '\n',
                'fast_cli': False,
                'session_timeout': Config.SSH_SESSION_TIMEOUT,
                'encoding': 'utf-8',
                'auto_connect': True
            }
            
            connection = ConnectHandler(**device)
            
            # Step 1: Run system sanity as initial user
            sanity_output = connection.send_command_timing(
                "system sanity",
                delay_factor=Config.SYSTEM_SANITY_DELAY_FACTOR,
                max_loops=Config.SYSTEM_SANITY_MAX_LOOPS,
                strip_prompt=True,
                strip_command=True
            )
            
            # Step 2: Enter system shell
            connection.send_command_timing(
                "system shell",
                delay_factor=2,
                max_loops=5,
                strip_prompt=False,
                strip_command=False
            )
            
            # Step 3: Switch to cyberx user with su
            # Send su command
            connection.write_channel("su - cyberx\n")
            import time
            time.sleep(1)  # Wait for password prompt
            
            # Clear any welcome messages
            output = connection.read_channel()
            
            # Step 4: Run uptime as cyberx user
            uptime_output = connection.send_command_timing(
                "uptime",
                delay_factor=Config.UPTIME_DELAY_FACTOR,
                max_loops=Config.UPTIME_MAX_LOOPS,
                strip_prompt=True,
                strip_command=True
            )
            
            return True, sanity_output, uptime_output, "", ""
            
        except NetmikoTimeoutException as e:
            return False, "", "", "connection", f"Connection timeout: {str(e)}"
        except NetmikoAuthenticationException as e:
            return False, "", "", "connection", f"Authentication failed: {str(e)}"
        except SSHException as e:
            return False, "", "", "connection", f"SSH error: {str(e)}"
        except Exception as e:
            return False, "", "", "unknown", f"Unexpected error: {str(e)}"
        finally:
            if connection:
                try:
                    connection.disconnect()
                except Exception:
                    pass


class SensorResult:
    """Data class for sensor check results"""
    
    def __init__(self, sensor_name: str, ip_address: str):
        self.sensor_name = sensor_name
        self.ip_address = ip_address
        self.ping_status = "status_pending"
        self.ssh_connectivity = "status_pending"
        self.system_sanity = "status_pending"
        self.uptime_result = "status_pending"
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, str]:
        """Convert result to dictionary"""
        return {
            "sensor_name": self.sensor_name,
            "ip_address": self.ip_address,
            "ping_status": self.ping_status,
            "ssh_connectivity": self.ssh_connectivity,
            "system_sanity": self.system_sanity,
            "uptime_result": self.uptime_result,
            "timestamp": self.timestamp.isoformat()
        }
    
    def to_tuple(self) -> Tuple[str, ...]:
        """Convert result to tuple (for GUI display)"""
        return (
            self.sensor_name,
            self.ip_address,
            self.ping_status,
            self.ssh_connectivity,
            self.system_sanity,
            self.uptime_result
        )


class SensorHealthChecker:
    """Performs health checks on sensors"""
    
    def __init__(self, logger: Optional['Logger'] = None):
        self.network_tester = NetworkTester()
        self.ssh_runner = SSHCommandRunner()
        self.logger = logger or Logger()
        self._should_stop = False
    
    def stop(self):
        """Signal to stop checking"""
        self._should_stop = True
    
    def check_sensor(
        self, 
        ip: str, 
        credentials: Dict[str, str]
    ) -> SensorResult:
        """
        Perform complete health check on a sensor using single login
        
        Args:
            ip: Sensor IP address
            credentials: Dictionary with username, password, cyberx_password
            sensor_name: Human-readable sensor name
            
        Returns:
            SensorResult object with check results
        """
        result = SensorResult(ip, ip)
        
        if self._should_stop:
            return result
        
        self.logger.log(f"Checking sensor: {ip}")
        
        # Step 1: Ping test
        if self.network_tester.ping(ip):
            result.ping_status = "status_ok"
            self.logger.log(f"✓ Sensor {ip} is reachable")
        else:
            result.ping_status = "status_fail"
            self.logger.log(f"✗ Sensor {ip} is unreachable")
            return result
        
        if self._should_stop:
            return result
        
        # Step 2: Single SSH session for all checks
        username = credentials.get("username")
        password = credentials.get("password")
        
        if not username or not password:
            result.ssh_connectivity = "status_error"
            result.system_sanity = "status_error"
            result.uptime_result = "status_error"
            self.logger.log(f"⚠ Missing primary credentials for {ip}")
            return result
        
        # Execute all commands in single session
        success, sanity_output, uptime_output, error_stage, error_msg = \
            self.ssh_runner.execute_commands_single_session(
                ip, username, password or ""
            )
        
        if not success:
            result.ssh_connectivity = "status_fail"
            result.system_sanity = "status_error"
            result.uptime_result = "status_error"
            self.logger.log(f"✗ SSH session failed for {ip} at stage '{error_stage}': {error_msg}")
            return result
        
        # SSH connected successfully
        result.ssh_connectivity = "status_ok"
        
        # Check system sanity output
        if sanity_output and "system is up" in sanity_output.lower():
            result.system_sanity = "status_pass"
            self.logger.log(f"✓ System sanity passed for {ip}")
        else:
            result.system_sanity = "status_fail"
            self.logger.log(f"✗ System sanity failed for {ip}")
        
        # Check uptime output
        if uptime_output:
            result.uptime_result = "status_pass"
            self.logger.log(f"✓ Uptime for {ip}: {uptime_output.strip()}")
        else:
            result.uptime_result = "status_warn"
            self.logger.log(f"⚠ No uptime output for {ip}")
        return result
    
    def check_all_sensors(
        self, 
        credentials: Dict[str, Dict[str, str]]
    ) -> List[SensorResult]:
        """
        Check all sensors in the credentials dictionary
        
        Args:
            credentials: Dictionary mapping IP to credentials
            
        Returns:
            List of SensorResult objects
        """
        results = []
        self._should_stop = False
        
        for ip, creds in credentials.items():
            if self._should_stop:
                break
            
            result = self.check_sensor(ip, creds)
            results.append(result)
        
        return results


class Logger:
    """Handles logging to file and provides callback mechanism for GUI"""
    
    def __init__(self, log_file: str = Config.LOG_FILE):
        self.log_file = log_file
        self.callbacks = []
    
    def add_callback(self, callback):
        """Add a callback function to be called when logging"""
        self.callbacks.append(callback)
    
    def log(self, message: str):
        """Log a message to file and notify callbacks"""
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_entry = f"{timestamp} {message}"
        
        # Write to file
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"Failed to write to log file: {e}")
        
        # Notify callbacks (for GUI updates)
        for callback in self.callbacks:
            try:
                callback(log_entry)
            except Exception as e:
                print(f"Callback error: {e}")


class ResultsManager:
    """Manages sensor check results"""
    
    def __init__(self):
        self.results: List[SensorResult] = []
    
    def add_result(self, result: SensorResult):
        """Add a result to the collection"""
        self.results.append(result)
    
    def clear_results(self):
        """Clear all results"""
        self.results.clear()
    
    def get_all_results(self) -> List[SensorResult]:
        """Get all results"""
        return self.results.copy()
    
    def export_to_csv(self, filename: str):
        """
        Export results to CSV file
        
        Args:
            filename: Output CSV filename
            
        Raises:
            ValueError: If export fails
        """
        if not self.results:
            raise ValueError("No results to export")
        
        try:
            import pandas as pd
            data = [result.to_dict() for result in self.results]
            df = pd.DataFrame(data)
            df.to_csv(filename, index=False)
        except Exception as e:
            raise ValueError(f"Export failed: {str(e)}")
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary statistics of results"""
        summary = {
            "total": len(self.results),
            "ping_ok": 0,
            "ssh_ok": 0,
            "sanity_pass": 0,
            "uptime_pass": 0
        }
        
        for result in self.results:
            if result.ping_status == "status_ok":
                summary["ping_ok"] += 1
            if result.ssh_connectivity == "status_ok":
                summary["ssh_ok"] += 1
            if result.system_sanity == "status_pass":
                summary["sanity_pass"] += 1
            if result.uptime_result == "status_pass":
                summary["uptime_pass"] += 1
        
        return summary
