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
        plaintext_size = len(plaintext.encode())

        # Define keys for each kelompok and AES type
        keys = {
            "1": {
                "1": b'kelompok 1'.ljust(16),  
                "2": b'kelompok 1'.ljust(24),  
                "3": b'kelompok 1'.ljust(32)   
            },
            "2": {
                "1": b'kelompok 2'.ljust(16),  
                "2": b'kelompok 2'.ljust(24),  
                "3": b'kelompok 2'.ljust(32)   
            },
            "3": {
                "1": b'kelompok 3'.ljust(16),  
                "2": b'kelompok 3'.ljust(24),  
                "3": b'kelompok 3'.ljust(32)   
            },
            "4": {
                "1": b'kelompok 4'.ljust(16),  
                "2": b'kelompok 4'.ljust(24),  
                "3": b'kelompok 4'.ljust(32)   
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

        # Save results for download
        content = (
            f"Plaintext: {plaintext}\n"
            f"Plaintext Size: {plaintext_size} bytes\n"
            f"Ciphertext: {ciphertext}\n"
            f"Decrypted Text: {decrypted_text}\n"
            f"Encryption Time: {encryption_time} seconds\n"
            f"Decryption Time: {decryption_time} seconds\n"
            f"Ciphertext Size: {ciphertext_size} bytes\n"
            f"Decrypted Text Size: {decrypted_size} bytes\n"
        )

        # Simpan file ke memori untuk diunduh
        download_file = io.BytesIO(content.encode('utf-8'))
        download_file.seek(0)

        return render_template(
            'index.html', 
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
            download_link=True  # Indikator untuk download link
        )
    return render_template('index.html')

@app.route('/download', methods=['POST'])
def download():
    # Ambil data dari form di halaman
    plaintext = request.form.get('plaintext')
    ciphertext = request.form.get('ciphertext')
    decrypted_text = request.form.get('decrypted_text')

    # Isi file hasil
    content = (
        f"Plaintext: {plaintext}\n"
        f"Ciphertext: {ciphertext}\n"
        f"Decrypted Text: {decrypted_text}\n"
    )
    file = io.BytesIO(content.encode('utf-8'))
    file.seek(0)

    # Kirim file ke pengguna dengan nama `hasil_enkripsi.txt`
    return send_file(
        file,
        as_attachment=True,
        download_name="hasil_enkripsi.txt",
        mimetype='text/plain'
    )

if __name__ == '__main__':
    app.run(debug=True)
