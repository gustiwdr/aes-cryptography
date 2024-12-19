from flask import Flask, request, render_template, jsonify, send_file
import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time

app = Flask(__name__)

# Folder untuk menyimpan file
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Fungsi untuk mendapatkan ukuran file
def get_file_size(file_path):
    return os.path.getsize(file_path)

# Fungsi untuk mengenkripsi file
def encrypt_file(key, input_file_path, output_file_path):
    with open(input_file_path, 'rb') as file:
        data = file.read()

    nonce = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    start_time = time.time()
    ciphertext = cipher.encrypt(data)
    encryption_time = time.time() - start_time

    # Menyimpan nonce dan ciphertext dalam satu file
    with open(output_file_path, 'wb') as file:
        file.write(nonce + ciphertext)

    print(f"[ENCRYPTION] Nonce: {nonce}, Ciphertext Length: {len(ciphertext)}")  # Debug log
    return encryption_time

# Fungsi untuk mendekripsi file
def decrypt_file(key, input_file_path, output_file_path):
    with open(input_file_path, 'rb') as file:
        data = file.read()

    nonce = data[:8]
    ciphertext = data[8:]

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    start_time = time.time()
    plaintext = cipher.decrypt(ciphertext)
    decryption_time = time.time() - start_time

    # Menulis kembali plaintext ke file
    with open(output_file_path, 'wb') as file:
        file.write(plaintext)

    print(f"[DECRYPTION] Nonce: {nonce}, Plaintext Length: {len(plaintext)}")  # Debug log
    return decryption_time

# Route untuk halaman utama
@app.route('/')
def home():
    return render_template('aes_encryptor.html')

# Route untuk memproses enkripsi/dekripsi
@app.route('/process', methods=['POST'])
def process():
    aes_type = request.form.get('aes_type')
    key = request.form.get('key')
    operation = request.form.get('operation')
    input_file = request.files['input_file']
    output_file_name = request.form.get('output_file')

    key_lengths = {"AES-128": 16, "AES-192": 24, "AES-256": 32}
    key_length = key_lengths.get(aes_type)

    if len(key) != key_length:
        return jsonify({"error": f"Key harus {key_length} karakter."}), 400

    input_file_path = os.path.join(UPLOAD_FOLDER, input_file.filename)
    output_file_path = os.path.join(UPLOAD_FOLDER, output_file_name)
    input_file.save(input_file_path)

    key_bytes = key.encode('utf-8')

    try:
        if operation == "encrypt":
            process_time = encrypt_file(key_bytes, input_file_path, output_file_path)
        elif operation == "decrypt":
            process_time = decrypt_file(key_bytes, input_file_path, output_file_path)
        else:
            return jsonify({"error": "Operasi tidak valid."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    input_file_size = get_file_size(input_file_path)
    output_file_size = get_file_size(output_file_path)

    result_message = f"File berhasil {'terenkripsi' if operation == 'encrypt' else 'terdekripsi'}."

    return jsonify({
        "message": result_message,
        "process_time": f"{process_time:.6f} detik",
        "input_file_size": input_file_size,
        "output_file_size": output_file_size,
        "output_file": output_file_name,
        "download_link": f"/download/{output_file_name}"
    })

# Route untuk mengunduh file
@app.route('/download/<filename>', methods=['GET'])
def download(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        return "File tidak ditemukan.", 404
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
