import base64
import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from cryptography.hazmat.backends import default_backend

GLOBAL_SALT = b'some_global_salt_for_kdf_'

def derive_key(password: str, salt=GLOBAL_SALT, length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# AES Encryption/Decryption (CBC mode)
def aes_encrypt(plaintext: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ct_bytes).decode()

def aes_decrypt(enc_b64: str, key: bytes) -> str:
    raw = base64.b64decode(enc_b64)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# Fernet Encryption/Decryption
def fernet_key_from_password(password: str, salt=GLOBAL_SALT) -> bytes:
    key = derive_key(password, salt)
    return base64.urlsafe_b64encode(key)

def fernet_encrypt(plaintext: str, key: bytes) -> str:
    f = Fernet(key)
    return f.encrypt(plaintext.encode()).decode()

def fernet_decrypt(token: str, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()

# RSA Keypair Generation, Encrypt, Decrypt
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes, pub_bytes

def rsa_encrypt(plaintext: str, pub_key_pem: bytes) -> str:
    public_key = serialization.load_pem_public_key(pub_key_pem)
    encrypted = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    )
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(cipher_b64: str, priv_key_pem: bytes) -> str:
    private_key = serialization.load_pem_private_key(priv_key_pem, password=None)
    ciphertext = base64.b64decode(cipher_b64)
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    )
    return decrypted.decode()

# XOR cipher (simple)
def xor_encrypt(plaintext: str, key: str) -> str:
    key_len = len(key)
    encrypted = ''.join(chr(ord(c) ^ ord(key[i % key_len])) for i, c in enumerate(plaintext))
    return base64.b64encode(encrypted.encode()).decode()

def xor_decrypt(cipher_b64: str, key: str) -> str:
    ciphertext = base64.b64decode(cipher_b64).decode()
    key_len = len(key)
    decrypted = ''.join(chr(ord(c) ^ ord(key[i % key_len])) for i, c in enumerate(ciphertext))
    return decrypted

# Caesar cipher (simple)
def caesar_encrypt(plaintext: str, shift: int=3) -> str:
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def caesar_decrypt(ciphertext: str, shift: int=3) -> str:
    return caesar_encrypt(ciphertext, -shift)



def decrypt_entry_password(ciphertext, master_password, enc_type, post_data=None):
    post_data = post_data or {}
    try:
        if enc_type == 'AES':
            key = derive_key(master_password)
            return aes_decrypt(ciphertext, key)
        elif enc_type == 'FERNET':
            key = fernet_key_from_password(master_password)
            return fernet_decrypt(ciphertext, key)
        elif enc_type == 'RSA':
            private_key = post_data.get('private_key')
            if not private_key:
                raise ValueError("Private key required for RSA decryption")
            return rsa_decrypt(ciphertext, private_key)
        elif enc_type == 'XOR':
            key = master_password[:8] or 'defaultkey'
            return xor_decrypt(ciphertext, key)
        elif enc_type == 'CAESAR':
            shift = int(post_data.get('caesar_shift', 3))
            return caesar_decrypt(ciphertext, shift)
        else:
            raise ValueError(f"Unsupported encryption type: {enc_type}")
    except Exception as e:
        # Add more specific error handling if needed
        raise ValueError(f"Decryption failed: {str(e)}")