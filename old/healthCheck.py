import json
import os
import getpass
import socket
import subprocess
import platform
import paramiko
from datetime import datetime
from cryptography.fernet import Fernet

LOG_FILE = "sensor_check.log"

def log(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {message}\n")
    print(f"{timestamp} {message}")

def get_decryption_key():
    return getpass.getpass("Enter decryption key: ").encode()

def load_credentials(encrypted_path, key):
    try:
        cipher = Fernet(key)
        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()
        decrypted = cipher.decrypt(encrypted_data)
        credentials = json.loads(decrypted.decode())
        return credentials
    except Exception as e:
        log(f"[ERROR] Failed to load credentials: {e}")
        return {}

def ping_sensor(ip, timeout=2):
    try:
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        log(f"[ERROR] Ping failed for {ip}: {e}")
        return False

def run_ssh_command(ip, username, password, command, timeout=15):
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Increased connection timeout and added more specific error handling
        client.connect(
            ip, 
            username=username, 
            password=password, 
            timeout=timeout,
            look_for_keys=False, 
            allow_agent=False,
            banner_timeout=30  # Added banner timeout
        )
        
        # Execute command with longer timeout
        stdin, stdout, stderr = client.exec_command(command, timeout=30)
        
        # Read output with better error handling
        output = stdout.read().decode('utf-8', errors='ignore').strip()
        error = stderr.read().decode('utf-8', errors='ignore').strip()
        
        # Log the raw output for debugging
        log(f"[DEBUG] Raw command output: '{output}'")
        if error:
            log(f"[DEBUG] Command stderr: '{error}'")
            
        return True, output, error
        
    except paramiko.AuthenticationException as e:
        return False, "", f"Authentication failed: {str(e)}"
    except paramiko.SSHException as e:
        return False, "", f"SSH protocol error: {str(e)}"
    except socket.timeout as e:
        return False, "", f"Connection timeout: {str(e)}"
    except socket.error as e:
        return False, "", f"Network error: {str(e)}"
    except Exception as e:
        return False, "", f"Unexpected error: {str(e)}"
    finally:
        if client:
            try:
                client.close()
            except:
                pass

def check_sensor(ip, creds):
    log(f"--- Checking sensor at {ip} ---")
    
    # Step 1: Ping the sensor
    if ping_sensor(ip):
        log(f"[OK] Sensor {ip} is reachable via ping.")
    else:
        log(f"[FAIL] Sensor {ip} is not reachable via ping.")
        return  # Stop here if ping fails
    
    # Step 2: Test User 1
    user1, pass1 = creds.get("username"), creds.get("password")
    if not user1 or not pass1:
        log(f"[ERROR] Missing credentials for user1 on {ip}")
        return
        
    log(f"[DEBUG] Attempting SSH as {user1} to run 'system sanity' on {ip}...")
    success1, output1, err1 = run_ssh_command(ip, user1, pass1, "system sanity")
    log(f"[DEBUG] SSH command complete for {user1} on {ip}.")
    
    if success1:
        if output1:  # Check if output exists
            lines = output1.strip().splitlines()
            if len(lines) >= 2 and lines[-2] == "System is UP! (L100)":
                log(f"[PASS] {ip} - User1 ({user1}): system sanity passed.")
            else:
                log(f"[FAIL] {ip} - User1 ({user1}): Unexpected output format")
                log(f"[DEBUG] Expected 'System is UP! (L100)' in second-to-last line, got: {lines}")
        else:
            log(f"[FAIL] {ip} - User1 ({user1}): No output received from 'system sanity' command")
    else:
        log(f"[ERROR] {ip} - User1 ({user1}) failed: {err1}")
    
    # Step 3: Test User 2
    user2, pass2 = creds.get("username2"), creds.get("password2")
    if not user2 or not pass2:
        log(f"[ERROR] Missing credentials for user2 on {ip}")
        return
        
    log(f"[DEBUG] Attempting SSH as {user2} to run 'uptime' on {ip}...")
    success2, output2, err2 = run_ssh_command(ip, user2, pass2, "uptime")
    
    if success2:
        if output2:
            log(f"[PASS] {ip} - User2 ({user2}): uptime output: {output2}")
        else:
            log(f"[WARN] {ip} - User2 ({user2}): SSH successful but no uptime output received")
    else:
        log(f"[ERROR] {ip} - User2 ({user2}) failed: {err2}")

def main():
    log("=== Sensor Health Check Started ===")
    
    try:
        key = get_decryption_key()
        credentials = load_credentials("sensor_credentials.enc", key)
        
        if not credentials:
            log("[ERROR] No credentials loaded. Exiting.")
            return
            
        log(f"[INFO] Loaded credentials for {len(credentials)} sensors")
        
        for ip, creds in credentials.items():
            try:
                check_sensor(ip, creds)
            except Exception as e:
                log(f"[ERROR] Unexpected error checking sensor {ip}: {e}")
            
            # Add a small delay between sensors
            import time
            time.sleep(1)
            
    except KeyboardInterrupt:
        log("[INFO] Health check interrupted by user")
    except Exception as e:
        log(f"[ERROR] Fatal error in main: {e}")
    finally:
        log("=== Sensor Health Check Completed ===")

if __name__ == "__main__":
    main()
