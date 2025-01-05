import os
import time
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Folder untuk menyimpan hasil
RESULT_FOLDER = "hasil"
os.makedirs(RESULT_FOLDER, exist_ok=True)

# Variabel global untuk menyimpan kunci yang dihasilkan
generated_key = None


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
    return unpadder.update(padded_data) + unpadder.finalize()


def encrypt_file():
    global generated_key  # Referensi variabel global untuk menyimpan kunci

    filepath = file_entry.get()
    if not os.path.isfile(filepath):
        messagebox.showerror("Error", "File tidak ditemukan!")
        return

    method = method_var.get()
    key_length = 16 if method == "AES-128" else 24 if method == "AES-192" else 32
    if manual_key_var.get():
        try:
            key = bytes.fromhex(key_entry.get())
            if len(key) != key_length:
                raise ValueError
        except:
            messagebox.showerror("Error", f"Kunci harus {key_length * 8} bit dalam format hex.")
            return
    else:
        key = os.urandom(key_length)
        generated_key = key  # Simpan kunci ke variabel global
        key_entry.config(state=NORMAL)
        key_entry.delete(0, END)
        key_entry.insert(0, key.hex())
        key_entry.config(state="readonly")

    with open(filepath, 'rb') as f:
        file_data = f.read()

    file_name = os.path.basename(filepath).encode()
    file_name_length = len(file_name)
    data_with_name = file_name_length.to_bytes(2, 'big') + file_name + file_data

    try:
        start_time = time.time()
        encrypted_data = encrypt_data(key, data_with_name)
        encryption_time = time.time() - start_time

        enc_file_path = os.path.join(RESULT_FOLDER, os.path.basename(filepath) + '.enc')
        with open(enc_file_path, 'wb') as f:
            f.write(encrypted_data)

        messagebox.showinfo("Sukses", f"File berhasil dienkripsi!\nFile disimpan di: {enc_file_path}\nWaktu: {encryption_time:.4f} detik")
        file_entry.delete(0, END)  # Reset hanya bagian file
    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan saat enkripsi: {str(e)}")


def decrypt_file():
    filepath = file_entry.get()
    if not os.path.isfile(filepath):
        messagebox.showerror("Error", "File tidak ditemukan!")
        return

    method = method_var.get()
    key_length = 16 if method == "AES-128" else 24 if method == "AES-192" else 32
    try:
        key = bytes.fromhex(key_entry.get())
        if len(key) != key_length:
            raise ValueError
    except:
        messagebox.showerror("Error", f"Kunci harus {key_length * 8} bit dalam format hex.")
        return

    with open(filepath, 'rb') as f:
        encrypted_data = f.read()

    try:
        start_time = time.time()
        decrypted_data = decrypt_data(key, encrypted_data)
        decryption_time = time.time() - start_time

        file_name_length = int.from_bytes(decrypted_data[:2], 'big')
        original_file_name = decrypted_data[2:2 + file_name_length].decode()
        file_content = decrypted_data[2 + file_name_length:]

        dec_file_path = os.path.join(RESULT_FOLDER, original_file_name)
        with open(dec_file_path, 'wb') as f:
            f.write(file_content)

        messagebox.showinfo("Sukses", f"File berhasil didekripsi!\nFile disimpan di: {dec_file_path}\nWaktu: {decryption_time:.4f} detik")
        reset_form()
    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan saat dekripsi: {str(e)}")


def toggle_key_input():
    if manual_key_var.get():
        key_entry.config(state=NORMAL)
    else:
        key_entry.delete(0, END)
        key_entry.config(state="readonly")


def reset_form():
    global generated_key  # Tambahkan referensi ke variabel global
    file_entry.delete(0, END)
    if manual_key_var.get():
        key_entry.config(state=NORMAL)
        key_entry.delete(0, END)
        key_entry.config(state="readonly")
        generated_key = None  # Reset kunci hanya jika mode manual
    else:
        key_entry.delete(0, END)
        if generated_key:  # Tetap tampilkan kunci otomatis jika ada
            key_entry.config(state=NORMAL)
            key_entry.insert(0, generated_key.hex())
            key_entry.config(state="readonly")


def copy_key():
    key = key_entry.get()
    if key:
        app.clipboard_clear()
        app.clipboard_append(key)
        app.update()
        messagebox.showinfo("Info", "Kunci berhasil disalin ke clipboard.")


# GUI setup
app = Tk()
app.title("AES Encryption/Decryption")
app.geometry("500x400")

# Frame untuk file input
frame_file = ttk.Frame(app, padding=10)
frame_file.pack(fill=X)
ttk.Label(frame_file, text="File:").pack(side=LEFT, padx=5)
file_entry = ttk.Entry(frame_file, width=40)
file_entry.pack(side=LEFT, fill=X, expand=True, padx=5)
ttk.Button(frame_file, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename())).pack(side=LEFT, padx=5)

# Frame untuk metode
frame_method = ttk.Frame(app, padding=10)
frame_method.pack(fill=X)
ttk.Label(frame_method, text="Metode:").pack(side=LEFT, padx=5)
method_var = StringVar(value="AES-256")
ttk.OptionMenu(frame_method, method_var, "AES-128", "AES-128", "AES-192", "AES-256").pack(side=LEFT, padx=5)

# Frame untuk kunci
frame_key = ttk.Frame(app, padding=10)
frame_key.pack(fill=X)
manual_key_var = IntVar()
ttk.Checkbutton(frame_key, text="Masukkan kunci manual", variable=manual_key_var, command=toggle_key_input).pack(anchor=W)
key_entry = ttk.Entry(frame_key, state="readonly")
key_entry.pack(fill=X, padx=5, pady=5)
ttk.Button(frame_key, text="Salin Kunci", command=copy_key).pack(anchor=E, padx=5)

# Frame untuk tombol aksi
frame_action = ttk.Frame(app, padding=10)
frame_action.pack(fill=X)
ttk.Button(frame_action, text="Enkripsi File", command=encrypt_file).pack(side=LEFT, padx=5)
ttk.Button(frame_action, text="Dekripsi File", command=decrypt_file).pack(side=LEFT, padx=5)
ttk.Button(frame_action, text="Reset Form", command=reset_form).pack(side=LEFT, padx=5)

app.mainloop()
