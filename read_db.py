import sqlite3

conn = sqlite3.connect("users.db")
cur = conn.cursor()

rows = cur.execute("SELECT * FROM users").fetchall()

for row in rows:
    print(row)

conn.close()