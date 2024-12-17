import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

print("Pilih tipe AES:")
print("1. AES-128 (16 karakter key)")
print("2. AES-192 (24 karakter key)")
print("3. AES-256 (32 karakter key)")


aes_type = input("Masukkan pilihan (1/2/3): ")
key_length = None

# Validasi panjang key berdasarkan pilihan
if aes_type == "1":
    key_length = 16
elif aes_type == "2":
    key_length = 24
elif aes_type == "3":
    key_length = 32
else:
    print("Pilihan tidak valid.")
    exit()


data = input("Masukkan data yang akan dienkripsi: ").encode('utf-8')

# Input key dan validasi panjangnya
key_input = input(f"Masukkan key ({key_length} karakter): ")
while len(key_input) != key_length:
    print(f"Key harus memiliki panjang {key_length} karakter.")
    key_input = input(f"Masukkan key ({key_length} karakter): ")

key = key_input.encode('utf-8')  # Konversi key ke byte

# Membuat cipher AES dengan mode CTR
cipher = AES.new(key, AES.MODE_CTR)

# Enkripsi data
ct_bytes = cipher.encrypt(data)

# Encode nonce dan ciphertext ke Base64
nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')

# Output hasil dalam format JSON
result = json.dumps({'nonce': nonce, 'ciphertext': ct})
print("\nHasil Enkripsi:")
print(result)