from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import time
import io

app = Flask(__name__)

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

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        aes_choice = request.form['aes_choice']
        key_option = request.form['key_option']

        # Menghitung ukuran plaintext
        plaintext_size = len(plaintext.encode())  # Menghitung ukuran dalam byte

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

        key = keys.get(key_option, {}).get(aes_choice)
        if not key:
            return render_template('index.html', error="Invalid option selected.")

        # Perform encryption and decryption
        start_time = time.time()
        ciphertext = encrypt_aes(key, plaintext)
        encryption_time = time.time() - start_time
        ciphertext_size = len(base64.b64decode(ciphertext))

        start_time = time.time()
        decrypted_text = decrypt_aes(key, ciphertext)
        decryption_time = time.time() - start_time
        decrypted_size = len(decrypted_text.encode())

        # Save results to a file
        filename = f"{key_option}_AES_{aes_choice}_result.txt"
        with open(filename, "w") as file:
            file.write(f"Plaintext: {plaintext}\n")
            file.write(f"Plaintext Size: {plaintext_size} bytes\n")
            file.write(f"Ciphertext: {ciphertext}\n")
            file.write(f"Decrypted Text: {decrypted_text}\n")
            file.write(f"Encryption Time: {encryption_time} seconds\n")
            file.write(f"Decryption Time: {decryption_time} seconds\n")
            file.write(f"Ciphertext Size: {ciphertext_size} bytes\n")
            file.write(f"Decrypted Text Size: {decrypted_size} bytes\n")

        return render_template('index.html', 
                               plaintext=plaintext,
                               plaintext_size=plaintext_size,
                               ciphertext=ciphertext,
                               decrypted_text=decrypted_text,
                               encryption_time=encryption_time,
                               decryption_time=decryption_time,
                               ciphertext_size=ciphertext_size,
                               decrypted_size=decrypted_size,
                               aes_choice=aes_choice,
                               key_option=key_option,
                               download_link=filename)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
