import os
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

MAGIC = b'CTAE'
VERSION = 1

class CryptoError(Exception):
    pass

def derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or password == "":
        raise CryptoError("Password required.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    aad = MAGIC + bytes([VERSION])

    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(bytes([VERSION]))
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    min_len = 4 + 1 + SALT_SIZE + NONCE_SIZE + 16
    if len(data) < min_len:
        raise CryptoError("File too short or corrupted.")

    magic = data[:4]
    version = data[4]
    if magic != MAGIC or version != VERSION:
        raise CryptoError("Unrecognized file format.")

    offset = 5
    salt = data[offset:offset + SALT_SIZE]; offset += SALT_SIZE
    nonce = data[offset:offset + NONCE_SIZE]; offset += NONCE_SIZE
    ciphertext = data[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    aad = MAGIC + bytes([VERSION])

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        raise CryptoError("Decryption failed. Wrong password or file corrupted.")

    with open(output_path, "wb") as f:
        f.write(plaintext)

