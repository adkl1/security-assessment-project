from flask import Flask, request, redirect, url_for, session, render_template_string, render_template, abort
import sqlite3
from encryptions import verify_sha256, verify_bcrypt, verify_argon2

app = Flask(__name__)
GROUP_SEED = "506512019"
app.secret_key = GROUP_SEED
FAILED_ATTEMPTS = {}   # { username: count }
MAX_TRIES = 5
DB_NAME = "server.db"


# functions for db so that each client thread has a direct access
def get_db():
    return sqlite3.connect(DB_NAME)

LOGIN_HTML = ""
REGISTER_HTML = ""

with open("login.html", "r") as file:
    LOGIN_HTML = file.read()
with open("register.html", "r") as file:
    REGISTER_HTML = file.read()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        encryption = request.form["hash_mode"]

        FAILED_ATTEMPTS.setdefault(username, 0)

        # Don't print passwords
        print(username, password, encryption)

        if FAILED_ATTEMPTS[username] >= MAX_TRIES:
            return render_template_string(
                LOGIN_HTML,
                error="Account locked after too many attempts"
            )

        with get_db() as db:
            cur = db.execute("SELECT * FROM USERS WHERE username = ?", (username,))
            row = cur.fetchone()

        if row is None:
            # count as a failed attempt too (optional but consistent)
            FAILED_ATTEMPTS[username] += 1
            return render_template_string(LOGIN_HTML, error="Invalid credentials")

        user = row[0]
        sha = row[1]
        salt = row[2]
        bcrypt_hash = row[3]
        argon_hash = row[4]

        ok = False
        if encryption == "sha256":
            ok = verify_sha256(password, sha, salt)
        elif encryption == "bcrypt":
            ok = verify_bcrypt(password, bcrypt_hash)
        elif encryption == "argon2id":
            ok = verify_argon2(password, argon_hash)
        else:
            return render_template_string(LOGIN_HTML, error="Invalid hash")

        if ok:
            session["user"] = username
            session["encryption"] = encryption
            FAILED_ATTEMPTS[username] = 0
            return redirect(url_for("test"))

        FAILED_ATTEMPTS[username] += 1
        left = MAX_TRIES - FAILED_ATTEMPTS[username]

        if left <= 0:
            return render_template_string(LOGIN_HTML, error="Account locked after too many attempts")

        return render_template_string(LOGIN_HTML, error=f"Invalid credentials ({left} attempts left)")

    return render_template_string(LOGIN_HTML)



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")

        try:
            with get_db() as db:
                db.execute("INSERT INTO USERS (username, password) VALUES (?, ?)", (username, password))
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template_string(REGISTER_HTML, error="Username already exists")

    return render_template_string(REGISTER_HTML)


@app.route("/test")
def test():
    if "user" not in session:
        return redirect(url_for("login"))

    return f"Welcome, {session['user']}! with encrypted password {session['encryption']}"

@app.route("/reset_lockout", methods=["POST"])
def reset_lockout():
    token = request.form.get("token", "")
    if token != GROUP_SEED:
        abort(403)
    FAILED_ATTEMPTS.clear()
    return "OK", 200
if __name__ == "__main__":
    app.run(threaded=True)
