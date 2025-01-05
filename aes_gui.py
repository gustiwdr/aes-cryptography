import os
import time
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

RESULT_FOLDER = "hasil"
os.makedirs(RESULT_FOLDER, exist_ok=True)

# Enkripsi dan Dekripsi Fungsi
def encrypt_data(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_data(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

def encrypt_file():
    filepath = file_entry.get()
    if not os.path.isfile(filepath):
        messagebox.showerror("Error", "File tidak ditemukan!")
        return

    method = method_var.get()
    key_length = 16 if method == "AES-128" else 24 if method == "AES-192" else 32
    key_choice = key_choice_var.get()
    key = None

    if key_choice == "Masukkan kunci manual":
        key_hex = key_entry.get()
        try:
            key = bytes.fromhex(key_hex)
            if len(key) != key_length:
                raise ValueError
        except:
            messagebox.showerror("Error", f"Kunci harus {key_length * 8} bit dalam format hex.")
            return
    else:
        key = os.urandom(key_length)

    with open(filepath, 'rb') as f:
        file_data = f.read()

    file_name = os.path.basename(filepath).encode()
    file_name_length = len(file_name)
    data_with_name = file_name_length.to_bytes(2, 'big') + file_name + file_data

    start_time = time.time()
    encrypted_data = encrypt_data(key, data_with_name)
    encryption_time = time.time() - start_time

    enc_file_path = os.path.join(RESULT_FOLDER, os.path.basename(filepath) + '.enc')
    with open(enc_file_path, 'wb') as f:
        f.write(encrypted_data)

    messagebox.showinfo("Sukses", f"File terenkripsi disimpan di {enc_file_path}.\nWaktu: {encryption_time:.4f} detik\nKunci: {key.hex()}")

def decrypt_file():
    filepath = file_entry.get()
    if not os.path.isfile(filepath):
        messagebox.showerror("Error", "File tidak ditemukan!")
        return

    try:
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()

        method = method_var.get()
        key_length = 16 if method == "AES-128" else 24 if method == "AES-192" else 32
        key_hex = key_entry.get()
        key = bytes.fromhex(key_hex)

        if len(key) != key_length:
            raise ValueError

        start_time = time.time()
        decrypted_data = decrypt_data(key, encrypted_data)
        decryption_time = time.time() - start_time

        file_name_length = int.from_bytes(decrypted_data[:2], 'big')
        original_file_name = decrypted_data[2:2 + file_name_length].decode()
        file_content = decrypted_data[2 + file_name_length:]

        dec_file_path = os.path.join(RESULT_FOLDER, original_file_name)
        with open(dec_file_path, 'wb') as f:
            f.write(file_content)

        messagebox.showinfo("Sukses", f"File didekripsi disimpan di {dec_file_path}.\nWaktu: {decryption_time:.4f} detik")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mendekripsi file: {e}")

def select_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        file_entry.delete(0, END)
        file_entry.insert(0, filepath)

# GUI
app = ttk.Window(themename="darkly")
app.title("AES Encryption/Decryption")
app.geometry("600x400")

# Frame untuk file
frame_file = ttk.Frame(app, padding=10)
frame_file.pack(fill=X)
ttk.Label(frame_file, text="Pilih File:").pack(side=LEFT, padx=5)
file_entry = ttk.Entry(frame_file)
file_entry.pack(side=LEFT, fill=X, expand=YES, padx=5)
ttk.Button(frame_file, text="Browse", command=select_file).pack(side=LEFT, padx=5)

# Frame untuk metode
frame_method = ttk.Frame(app, padding=10)
frame_method.pack(fill=X)
ttk.Label(frame_method, text="Metode Enkripsi:").pack(side=LEFT, padx=5)
method_var = ttk.StringVar(value="AES-128")
ttk.Combobox(frame_method, textvariable=method_var, values=["AES-128", "AES-192", "AES-256"]).pack(side=LEFT, padx=5)

# Frame untuk kunci
frame_key = ttk.Frame(app, padding=10)
frame_key.pack(fill=X)
key_choice_var = ttk.StringVar(value="Generate kunci acak")
ttk.Radiobutton(frame_key, text="Masukkan kunci manual", variable=key_choice_var, value="Masukkan kunci manual").pack(side=LEFT, padx=5)
ttk.Radiobutton(frame_key, text="Generate kunci acak", variable=key_choice_var, value="Generate kunci acak").pack(side=LEFT, padx=5)
key_entry = ttk.Entry(frame_key)
key_entry.pack(fill=X, padx=5, pady=5)

# Frame untuk tombol aksi
frame_action = ttk.Frame(app, padding=10)
frame_action.pack(fill=X)
ttk.Button(frame_action, text="Enkripsi File", command=encrypt_file).pack(side=LEFT, padx=5)
ttk.Button(frame_action, text="Dekripsi File", command=decrypt_file).pack(side=LEFT, padx=5)

app.mainloop()
