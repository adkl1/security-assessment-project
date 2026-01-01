
import json
import sqlite3
import hashlib
import bcrypt
import secrets
import base64
import os
from argon2 import PasswordHasher

DB_PATH = "server.db"
USERS_JSON = "users.json"

PEPPER = os.environ.get("AUTH_PEPPER", "")
ph = PasswordHasher(time_cost=1, memory_cost=64 * 1024, parallelism=1)

def sha256_hash(password: str):
    salt = secrets.token_bytes(16)
    h = hashlib.sha256((PEPPER + password).encode() + salt).hexdigest()
    return h, base64.b64encode(salt).decode()

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  sha256_hash TEXT,
  sha256_salt TEXT,
  bcrypt_hash TEXT,
  argon2_hash TEXT,
  totp_enabled INTEGER
)
""")

with open(USERS_JSON, "r") as f:
    data = json.load(f)

for u in data["users"]:
    username = u["username"]
    password = u["password"]
    totp_enabled = 1 if u.get("totp_secret") else 0

    # sha256
    sha_hash, sha_salt = sha256_hash(password)

    # bcrypt
    bcrypt_hash = bcrypt.hashpw(
        (PEPPER + password).encode(),
        bcrypt.gensalt(rounds=12)
    ).decode()

    # argon2
    argon2_hash = ph.hash(PEPPER + password)

    cur.execute("""
    INSERT OR REPLACE INTO users
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        username,
        sha_hash,
        sha_salt,
        bcrypt_hash,
        argon2_hash,
        totp_enabled
    ))

conn.commit()
conn.close()

print("users.db created with 3 hashes per user")