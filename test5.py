from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

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
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    # Unpad data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

# Fungsi untuk enkripsi file
def encrypt_file(file_path, key):
    file_name = os.path.basename(file_path).encode()  # Nama file asli
    file_name_length = len(file_name)
    if file_name_length > 255:
        raise ValueError("Nama file terlalu panjang!")

    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Gabungkan metadata nama file dengan data
    metadata = file_name_length.to_bytes(1, 'big') + file_name
    encrypted_data = encrypt_data(key, metadata + file_data)

    enc_file_path = file_path + '.enc'
    with open(enc_file_path, 'wb') as f:
        f.write(encrypted_data)

    print(f"File terenkripsi disimpan sebagai: {enc_file_path}")

# Fungsi untuk dekripsi file
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    try:
        decrypted_data = decrypt_data(key, encrypted_data)

        # Ekstrak metadata nama file asli
        file_name_length = decrypted_data[0]
        file_name = decrypted_data[1:1 + file_name_length].decode()
        file_content = decrypted_data[1 + file_name_length:]

        dec_file_path = file_name
        with open(dec_file_path, 'wb') as f:
            f.write(file_content)

        print(f"File didekripsi disimpan sebagai: {dec_file_path}")
    except Exception as e:
        print(f"Kesalahan dekripsi: {e}")

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
    method = input("Masukkan pilihan (1/2/3): ")
    if method == '1':
        key_length = 16
    elif method == '2':
        key_length = 24
    elif method == '3':
        key_length = 32
    else:
        print("Pilihan metode tidak valid.")
        return

    print("\nPilih kunci enkripsi:")
    print("1. Masukkan kunci secara manual")
    print("2. Generate kunci secara acak")
    key_option = input("Masukkan pilihan (1/2): ")

    if key_option == '1':
        key_hex = input("Masukkan kunci dalam format hex: ")
        key = bytes.fromhex(key_hex)
        if len(key) != key_length:
            print(f"Kunci harus sepanjang {key_length * 8} bit ({key_length} byte).")
            return
    elif key_option == '2':
        key = os.urandom(key_length)
        print(f"Kunci yang di-generate (hex): {key.hex()}")
    else:
        print("Pilihan kunci tidak valid.")
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
        print("Pilihan aksi tidak valid.")

if __name__ == "__main__":
    main()
