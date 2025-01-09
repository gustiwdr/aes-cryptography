import os
import time
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Variabel global untuk menyimpan kunci dan hasil dekripsi
generated_key = None
decrypted_text = None

def convert_input_to_key(input_text, key_type, required_length):
    if key_type == "hex":
        try:
            key = bytes.fromhex(input_text)
        except:
            raise ValueError("Invalid hex format")
    elif key_type == "string":
        # Convert string to bytes and pad/truncate to required length
        key = input_text.encode('utf-8')
        if len(key) < required_length:
            # Pad with zeros if too short
            key = key + b'\0' * (required_length - len(key))
        else:
            # Truncate if too long
            key = key[:required_length]
    elif key_type == "char":
        # Repeat single character to fill key length
        if len(input_text) != 1:
            raise ValueError("Please enter exactly one character")
        key = input_text.encode('utf-8') * required_length
        key = key[:required_length]
    
    if len(key) != required_length:
        raise ValueError(f"Key must be exactly {required_length * 8} bits")
    
    return key

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
    global generated_key

    filepath = file_entry.get()
    plaintext = plaintext_entry.get()

    if not filepath and not plaintext:
        messagebox.showerror("Error", "Masukkan file atau teks biasa untuk dienkripsi!")
        return

    method = method_var.get()
    key_length = 16 if method == "AES-128" else 24 if method == "AES-192" else 32
    
    if manual_key_var.get():
        try:
            key = convert_input_to_key(
                key_entry.get(),
                key_type_var.get(),
                key_length
            )
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return
    else:
        key = os.urandom(key_length)
        generated_key = key
        key_entry.config(state=NORMAL)
        key_entry.delete(0, END)
        key_entry.insert(0, key.hex())
        key_entry.config(state="readonly")

    # Enkripsi
    try:
        start_time = time.time()

        if filepath:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            file_size = len(file_data)

            file_name = os.path.basename(filepath).encode()
            file_name_length = len(file_name)
            data_with_name = file_name_length.to_bytes(2, 'big') + file_name + file_data

            encrypted_data = encrypt_data(key, data_with_name)
            enc_file_path = filepath + '.enc'

            with open(enc_file_path, 'wb') as f:
                f.write(encrypted_data)
            encrypted_size = len(encrypted_data)

            duration = time.time() - start_time
            messagebox.showinfo(
                "Sukses",
                f"File berhasil dienkripsi!\n"
                f"File asli: {file_size} bytes\n"
                f"File terenkripsi: {encrypted_size} bytes\n"
                f"Waktu: {duration:.4f} detik\n"
                f"Disimpan di: {enc_file_path}"
            )
        else:
            plaintext_bytes = plaintext.encode()
            plaintext_size = len(plaintext_bytes)

            encrypted_data = encrypt_data(key, plaintext_bytes)
            enc_file_path = "plaintext.enc"

            with open(enc_file_path, 'wb') as f:
                f.write(encrypted_data)
            encrypted_size = len(encrypted_data)

            duration = time.time() - start_time
            messagebox.showinfo(
                "Sukses",
                f"Teks berhasil dienkripsi!\n"
                f"Teks asli: {plaintext_size} bytes\n"
                f"Teks terenkripsi: {encrypted_size} bytes\n"
                f"Waktu: {duration:.4f} detik\n"
                f"Disimpan di: {enc_file_path}"
            )
        reset_form()
    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan saat enkripsi: {str(e)}")


def decrypt_file():
    global decrypted_text

    filepath = file_entry.get()

    if not filepath:
        messagebox.showerror("Error", "Masukkan file untuk didekripsi!")
        return

    method = method_var.get()
    key_length = 16 if method == "AES-128" else 24 if method == "AES-192" else 32
    
    try:
        key = convert_input_to_key(
            key_entry.get(),
            key_type_var.get(),
            key_length
        )
    except ValueError as e:
        messagebox.showerror("Error", str(e))
        return

    try:
        start_time = time.time()

        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        encrypted_size = len(encrypted_data)

        decrypted_data = decrypt_data(key, encrypted_data)
        try:
            # Jika teks biasa
            decrypted_text = decrypted_data.decode()
            plaintext_entry.delete(0, END)
            plaintext_entry.insert(0, decrypted_text)

            duration = time.time() - start_time
            messagebox.showinfo(
                "Sukses",
                f"Teks berhasil didekripsi!\n"
                f"Waktu: {duration:.4f} detik"
            )
        except UnicodeDecodeError:
            # Jika file
            file_name_length = int.from_bytes(decrypted_data[:2], 'big')
            original_file_name = decrypted_data[2:2 + file_name_length].decode()
            file_content = decrypted_data[2 + file_name_length:]
            original_size = len(file_content)

            dec_file_path = os.path.join("hasil", original_file_name)
            os.makedirs("hasil", exist_ok=True)
            with open(dec_file_path, 'wb') as f:
                f.write(file_content)

            duration = time.time() - start_time
            messagebox.showinfo(
                "Sukses",
                f"File berhasil didekripsi!\n"
                f"File terenkripsi: {encrypted_size} bytes\n"
                f"File asli: {original_size} bytes\n"
                f"Waktu: {duration:.4f} detik\n"
                f"Disimpan di: {dec_file_path}"
            )
    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan saat dekripsi: {str(e)}")


def save_decrypted_text():
    global decrypted_text
    if decrypted_text:
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if save_path:
            with open(save_path, 'w') as f:
                f.write(decrypted_text)
            messagebox.showinfo("Sukses", f"Teks berhasil disimpan di: {save_path}")


def toggle_key_input():
    if manual_key_var.get():
        key_entry.config(state=NORMAL)
        key_type_var.set("hex")  # Default to hex
    else:
        key_entry.delete(0, END)
        key_entry.config(state="readonly")


def reset_form():
    global generated_key, decrypted_text
    file_entry.delete(0, END)
    plaintext_entry.delete(0, END)
    if manual_key_var.get():
        key_entry.config(state=NORMAL)
        key_entry.delete(0, END)
        key_entry.config(state="readonly")
    else:
        key_entry.delete(0, END)
    generated_key = None
    decrypted_text = None


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
app.geometry("500x600")

# Frame untuk file input
frame_file = ttk.Frame(app, padding=10)
frame_file.pack(fill=X)
ttk.Label(frame_file, text="File:").pack(side=LEFT, padx=5)
file_entry = ttk.Entry(frame_file, width=40)
file_entry.pack(side=LEFT, fill=X, expand=True, padx=5)
ttk.Button(frame_file, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename())).pack(side=LEFT, padx=5)

# Frame untuk plaintext input
frame_plaintext = ttk.Frame(app, padding=10)
frame_plaintext.pack(fill=X)
ttk.Label(frame_plaintext, text="Teks Biasa:").pack(anchor=W, padx=5)
plaintext_entry = ttk.Entry(frame_plaintext)
plaintext_entry.pack(fill=X, padx=5)

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

# Add key type selection
key_type_frame = ttk.Frame(frame_key)
key_type_frame.pack(fill=X, pady=5)
key_type_var = StringVar(value="hex")
ttk.Label(key_type_frame, text="Tipe Kunci:").pack(side=LEFT, padx=5)
ttk.Radiobutton(key_type_frame, text="Hex", variable=key_type_var, value="hex").pack(side=LEFT, padx=5)
ttk.Radiobutton(key_type_frame, text="String", variable=key_type_var, value="string").pack(side=LEFT, padx=5)
ttk.Radiobutton(key_type_frame, text="Char", variable=key_type_var, value="char").pack(side=LEFT, padx=5)

key_entry = ttk.Entry(frame_key, state="readonly")
key_entry.pack(fill=X, padx=5, pady=5)
ttk.Button(frame_key, text="Salin Kunci", command=copy_key).pack(anchor=E, padx=5)

# Frame untuk tombol aksi
frame_action = ttk.Frame(app, padding=10)
frame_action.pack(fill=X)
ttk.Button(frame_action, text="Enkripsi File/Teks", command=encrypt_file).pack(side=LEFT, padx=5)
ttk.Button(frame_action, text="Dekripsi File/Teks", command=decrypt_file).pack(side=LEFT, padx=5)
ttk.Button(frame_action, text="Reset Form", command=reset_form).pack(side=LEFT, padx=5)

# Tombol untuk menyimpan hasil dekripsi teks
ttk.Button(app, text="Simpan Teks Didekripsi", command=save_decrypted_text).pack(pady=10)

app.mainloop()
