
import hashlib
import bcrypt
import secrets
import base64
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


PEPPER = "5"
ph = PasswordHasher(time_cost=1, memory_cost=64 * 1024, parallelism=1)

def sha256_hash(password: str):
    salt = secrets.token_bytes(16)
    h = hashlib.sha256((PEPPER + password).encode() + salt).hexdigest()
    return h, base64.b64encode(salt).decode()

# sha256
def encrypt_sha256 (password: str):
    sha_hash, sha_salt = sha256_hash(password)
    return sha_hash, sha_salt

# bcrypt
def encrypt_bcrypt(password: str):
    bcrypt_hash = bcrypt.hashpw(
    (PEPPER + password).encode(),
    bcrypt.gensalt(rounds=12)
    ).decode()
    return bcrypt_hash

# argon2
def encrypt_aragon2(password: str):
    argon2_hash = ph.hash(PEPPER + password)
    return argon2_hash

# SHA-256 + salt: recompute and compare
def verify_sha256(password: str, stored_hash: str, stored_salt_b64: str):
    salt = base64.b64decode(stored_salt_b64.encode())
    calc = hashlib.sha256((PEPPER + password).encode() + salt).hexdigest()
    return calc == stored_hash

# bcrypt: library verify
def verify_bcrypt(password: str, stored_bcrypt_hash: str):
    return bcrypt.checkpw((PEPPER + password).encode(), stored_bcrypt_hash.encode())

# Argon2id: library verify
def verify_argon2(password: str, stored_argon2_hash: str):
    try:
        return ph.verify(stored_argon2_hash, PEPPER + password)
    except VerifyMismatchError:
        return False