import json
from base64 import b64decode
from Crypto.Cipher import AES

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

# Input key dan validasi panjangnya
key_input = input(f"Masukkan key ({key_length} karakter): ")
while len(key_input) != key_length:
    print(f"Key harus memiliki panjang {key_length} karakter.")
    key_input = input(f"Masukkan key ({key_length} karakter): ")

key = key_input.encode('utf-8')  # Konversi key ke byte

# Input JSON ciphertext
json_input = input("Masukkan ciphertext dalam format JSON: ")

try:
    # Decode JSON input
    b64 = json.loads(json_input)
    nonce = b64decode(b64['nonce'])         # Decode nonce dari Base64
    ct = b64decode(b64['ciphertext'])       # Decode ciphertext dari Base64

    # Buat cipher AES dengan mode CTR
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    # Dekripsi ciphertext
    pt = cipher.decrypt(ct)

    # Output plaintext
    print("\nPesan asli adalah: ", pt.decode('utf-8'))
except (ValueError, KeyError) as e:
    print("\nDekripsi gagal:", e)