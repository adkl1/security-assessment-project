from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3
from encryptions import verify_sha256, verify_bcrypt, verify_argon2
import pyotp

app = Flask(__name__)
GROUP_SEED = "506512019"
app.secret_key = GROUP_SEED

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

        print(username,password,encryption)

        with get_db() as db:
            cur = db.execute("SELECT * FROM USERS WHERE username = ?", (username,))
            row = cur.fetchone()
            if row is None:
                return render_template_string(LOGIN_HTML, error="Invalid credentials")
            user = row[0]
            sha = row[1]
            salt = row[2]
            bcrypt = row[3]
            argon = row[4]

            if encryption == "sha256":
                if verify_sha256(password, sha, salt):
                    session['user'] = username
                    session['encryption'] = encryption
                    session["password_ok"] = True
                    session["totp_ok"] = False
                    return redirect(url_for("login_totp"))
            elif encryption == "bcrypt":
                if verify_bcrypt(password, bcrypt):
                    session['user'] = username
                    session['encryption'] = encryption
                    session["password_ok"] = True
                    session["totp_ok"] = False
                    return redirect(url_for("login_totp"))
            elif encryption == "argon2id":
                if verify_argon2(password, argon):
                    session['user'] = username
                    session['encryption'] = encryption
                    session["password_ok"] = True
                    session["totp_ok"] = False
                    return redirect(url_for("login_totp"))
            else:
                return render_template_string(LOGIN_HTML, error="Invalid hash")

        return render_template_string(LOGIN_HTML, error="Invalid credentials")

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

@app.route("/login_totp", methods=["GET", "POST"])
def login_totp():
    if not session.get("password_ok"):
        return redirect("/login")

    if request.method == "GET":
        return "TOTP required"

    code = request.form.get("code")

    user_list = []
    user_totp = ""
    with open(USERS_JSON, "r") as f:
        data = json.load(f)
    for user in data['users']:
        if user['username'] == session["user"]:
            user_totp = user["totp_secret"]

    totp = pyotp.TOTP(user_totp)

    # Use server time explicitly
    now = time.time()

    if not totp.verify(code, for_time=now, valid_window=1):
        return "Invalid TOTP code", 401

    # Fully authenticated
    session["totp_ok"] = True

    return redirect("/test")

@app.route("/test")
def test():
    if "user" not in session or not session.get("password_ok") or not session.get("totp_ok"):
        return redirect(url_for("login"))

    return f"Welcome, {session['user']}! with encrypted password {session['encryption']}"



if __name__ == "__main__":
    app.run(threaded=True)
