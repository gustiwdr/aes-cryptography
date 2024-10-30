from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import time

def pad(text):
    padding_len = AES.block_size - len(text) % AES.block_size
    padding = chr(padding_len) * padding_len
    return text + padding

def unpad(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

def encrypt_aes(key, plaintext):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plaintext)
    ciphertext = cipher.encrypt(padded_text.encode())
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_aes(key, encoded_ciphertext):
    raw_data = base64.b64decode(encoded_ciphertext)
    iv = raw_data[:AES.block_size]
    ciphertext = raw_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext).decode()
    return unpad(decrypted_text)

def measure_encryption_decryption(key, plaintext):
    start_time = time.time()
    ciphertext = encrypt_aes(key, plaintext)
    encryption_time = time.time() - start_time
    ciphertext_size = len(base64.b64decode(ciphertext))

    start_time = time.time()
    decrypted_text = decrypt_aes(key, ciphertext)
    decryption_time = time.time() - start_time
    decrypted_size = len(decrypted_text.encode())

    return ciphertext, decrypted_text, encryption_time, decryption_time, ciphertext_size, decrypted_size

# User inputs
plaintext = input("Enter the message you want to encrypt: ")
print("\nChoose AES encryption type:")
print("1. AES-128")
print("2. AES-192")
print("3. AES-256")
aes_choice = input("Enter the number corresponding to your AES choice: ")

print("\nChoose a key option:")
print("1. Kelompok 1")
print("2. Kelompok 2")
print("3. Kelompok 3")
print("4. Kelompok 4")
key_option = input("Enter the number corresponding to your key choice: ")

# Define keys for each kelompok and AES type
keys = {
    "1": {
        "1": b'kelompok 1'.ljust(16),  # AES-128
        "2": b'kelompok 1'.ljust(24),  # AES-192
        "3": b'kelompok 1'.ljust(32)   # AES-256
    },
    "2": {
        "1": b'kelompok 2'.ljust(16),  # AES-128
        "2": b'kelompok 2'.ljust(24),  # AES-192
        "3": b'kelompok 2'.ljust(32)   # AES-256
    },
    "3": {
        "1": b'kelompok 3'.ljust(16),  # AES-128
        "2": b'kelompok 3'.ljust(24),  # AES-192
        "3": b'kelompok 3'.ljust(32)   # AES-256
    },
    "4": {
        "1": b'kelompok 4'.ljust(16),  # AES-128
        "2": b'kelompok 4'.ljust(24),  # AES-192
        "3": b'kelompok 4'.ljust(32)   # AES-256
    }
}

# Validate user input and choose the correct key
key = keys.get(key_option, {}).get(aes_choice)
if not key:
    print("Invalid option selected.")
else:
    # Perform encryption and decryption
    plaintext_size = len(plaintext.encode())
    ciphertext, decrypted_text, encryption_time, decryption_time, ciphertext_size, decrypted_size = measure_encryption_decryption(key, plaintext)

    # Display results
    print(f"\nAES-{len(key) * 8} Encryption:")
    print("Plaintext:", plaintext)
    print("Encrypted:", ciphertext)
    print("Decrypted:", decrypted_text)
    print(f"Original plaintext size: {plaintext_size} bytes")
    print(f"Ciphertext size: {ciphertext_size} bytes")
    print(f"Decrypted text size: {decrypted_size} bytes")
    print(f"Encryption time: {encryption_time:.6f} seconds")
    print(f"Decryption time: {decryption_time:.6f} seconds")
