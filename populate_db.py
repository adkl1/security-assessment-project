
import json
import sqlite3
from encryptions import encrypt_bcrypt, encrypt_sha256,encrypt_aragon2


DB_PATH = "server.db"
USERS_JSON = "users.json"


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

sha_hash , sha_salt = encrypt_sha256(password)

bcrypt_hash = encrypt_bcrypt(password)

argon2_hash = encrypt_aragon2(password)

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

print("server.db created with 3 hashes per user")