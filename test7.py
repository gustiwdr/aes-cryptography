import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Folder untuk menyimpan hasil
RESULT_FOLDER = "hasil"
os.makedirs(RESULT_FOLDER, exist_ok=True)

# Fungsi untuk enkripsi data
def encrypt_data(key, plaintext):
    iv = os.urandom(16)  # IV untuk mode CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding untuk memastikan blok 16-byte
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

# Fungsi untuk dekripsi data
def decrypt_data(key, ciphertext):
    iv = ciphertext[:16]  # Ambil IV dari awal file terenkripsi
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    # Hapus padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

# Fungsi untuk membaca file dan mengenkripsi isinya
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Sisipkan nama file asli di awal data
    file_name = os.path.basename(file_path).encode()
    file_name_length = len(file_name)
    data_with_name = file_name_length.to_bytes(2, 'big') + file_name + file_data

    start_time = time.time()
    encrypted_data = encrypt_data(key, data_with_name)
    encryption_time = time.time() - start_time

    enc_file_path = os.path.join(RESULT_FOLDER, os.path.basename(file_path) + '.enc')
    with open(enc_file_path, 'wb') as f:
        f.write(encrypted_data)

    # Ringkasan ciphertext (64 karakter pertama)
    ciphertext_summary = encrypted_data.hex()[:64] + "..."
    print(f"\nUkuran file asli: {os.path.getsize(file_path)} bytes")
    print(f"Waktu enkripsi: {encryption_time:.4f} detik")
    print(f"Ukuran file terenkripsi: {os.path.getsize(enc_file_path)} bytes")
    print(f"Ciphertext (ringkasan): {ciphertext_summary}\n")
    return enc_file_path

# Fungsi untuk membaca file dan mendekripsinya
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    start_time = time.time()
    decrypted_data = decrypt_data(key, encrypted_data)
    decryption_time = time.time() - start_time

    # Ambil nama file asli dari data yang didekripsi
    file_name_length = int.from_bytes(decrypted_data[:2], 'big')
    original_file_name = decrypted_data[2:2 + file_name_length].decode()
    file_content = decrypted_data[2 + file_name_length:]

    dec_file_path = os.path.join(RESULT_FOLDER, original_file_name)
    with open(dec_file_path, 'wb') as f:
        f.write(file_content)

    print(f"\nUkuran file terenkripsi: {os.path.getsize(file_path)} bytes")
    print(f"Waktu dekripsi: {decryption_time:.4f} detik")
    print(f"File didekripsi disimpan sebagai: {dec_file_path}\n")
    return dec_file_path

# Fungsi utama
def main():
    print("Pilih aksi:")
    print("1. Enkripsi file")
    print("2. Dekripsi file")
    action = input("Masukkan pilihan (1/2): ")

    print("\nPilih metode enkripsi:")
    print("1. AES-128")
    print("2. AES-192")
    print("3. AES-256")
    method_choice = input("Masukkan pilihan (1/2/3): ")

    if method_choice == '1':
        key_length = 16
    elif method_choice == '2':
        key_length = 24
    elif method_choice == '3':
        key_length = 32
    else:
        print("Pilihan tidak valid.")
        return

    print("\nPilih kunci enkripsi:")
    print("1. Masukkan kunci secara manual")
    print("2. Generate kunci secara acak")
    key_choice = input("Masukkan pilihan (1/2): ")

    if key_choice == '1':
        key_hex = input("Masukkan kunci dalam format hex: ")
        key = bytes.fromhex(key_hex)
        if len(key) != key_length:
            print(f"Kunci harus memiliki panjang {key_length * 8} bit.")
            return
    elif key_choice == '2':
        key = os.urandom(key_length)
        print(f"Kunci enkripsi (hex): {key.hex()}")
    else:
        print("Pilihan tidak valid.")
        return

    if action == '1':
        file_path = input("Masukkan path file: ")
        if os.path.exists(file_path):
            encrypt_file(file_path, key)
        else:
            print("File tidak ditemukan.")
    elif action == '2':
        file_path = input("Masukkan path file terenkripsi: ")
        if os.path.exists(file_path):
            decrypt_file(file_path, key)
        else:
            print("File tidak ditemukan.")
    else:
        print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()
