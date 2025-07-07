from cryptography.fernet import Fernet

# Generate a key (run once and save it somewhere secure, like an environment variable)
key = Fernet.generate_key()
print(f"Save this key securely: {key.decode()}")

# Encrypt the file
with open("flag.json", "rb") as f:
    data = f.read()

cipher = Fernet(key)
encrypted_data = cipher.encrypt(data)

with open("sensor_credentials.enc", "wb") as f:
    f.write(encrypted_data)

print("Credentials encrypted and saved to 'sensor_credentials.enc'.")
