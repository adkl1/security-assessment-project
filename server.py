from flask import Flask, request, redirect, url_for, session, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import json
from encryptions import verify_sha256, verify_bcrypt, verify_argon2

app = Flask(__name__)



#defaults
data = {"DB_NAME":"server.db","GROUPS_SEED":"123456"}
with open("server.config", "r") as f:
    data = json.load(f)

DB_NAME = data["DB_NAME"]
GROUP_SEED = data["GROUP_SEED"]

# enable rate limiter with username as key
def username_key():
    # Use username as the rate-limit key
    return request.form.get("username", "anonymous")

limiter = Limiter(
    key_func=username_key,
    app=app
)
app.secret_key = GROUP_SEED



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
@limiter.limit("100 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        encryption = request.form["hash_mode"]
        print(username, password, encryption)

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
                    return redirect(url_for("test"))
            elif encryption == "bcrypt":
                if verify_bcrypt(password, bcrypt):
                    session['user'] = username
                    session['encryption'] = encryption
                    return redirect(url_for("test"))
            elif encryption == "argon2id":
                if verify_argon2(password, argon):
                    session['user'] = username
                    session['encryption'] = encryption
                    return redirect(url_for("test"))
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
                db.execute("INSERT INTO USERS VALUES (?, ?, ?, ?, ?, ?)", (username, password,password,password,password,0))
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template_string(REGISTER_HTML, error="Username already exists")

    return render_template_string(REGISTER_HTML)


@app.route("/test")
def test():
    if "user" not in session:
        return redirect(url_for("login"))

    return f"Welcome, {session['user']}! with encrypted password {session['encryption']}"


if __name__ == "__main__":
    app.run(threaded=True)
