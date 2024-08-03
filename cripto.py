from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    # Use PBKDF2 to generate a key from the password and salt
    return PBKDF2(password, salt, dkLen=32)  # 32 bytes key length for AES-256

def encrypt_file(file_name: str, password: str):
    salt = get_random_bytes(16)  # Generate a random salt
    key = generate_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    
    with open(file_name, 'rb') as file:
        plaintext = file.read()
    
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    with open(file_name + '.enc', 'wb') as file:
        file.write(salt)  # Save the salt for key derivation later
        file.write(cipher.iv)
        file.write(ciphertext)

def decrypt_file(encrypted_file_name: str, password: str):
    with open(encrypted_file_name, 'rb') as file:
        salt = file.read(16)  # Read the salt
        iv = file.read(16)    # Read the IV
        ciphertext = file.read()
    
    key = generate_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open(encrypted_file_name[:-4], 'wb') as file:
        file.write(plaintext)


password = os.environ.get('PASSWORD')  
file_name = os.environ.get('FILE_NAME') 

if os.environ.get('ENCRIPTY').upper().startswith('Y'):
    encrypt_file(file_name, password)
    print(f'Arquivo {file_name} criptografado com sucesso.')
    
if os.environ.get('DECRYPT').upper().startswith('Y'):
    encrypted_file_name = file_name + '.enc'
    decrypt_file(encrypted_file_name, password)
    print(f'Arquivo {encrypted_file_name} descriptografado com sucesso.')
