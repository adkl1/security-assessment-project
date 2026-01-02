from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3

app = Flask(__name__)
GROUP_SEED = "506512019"
app.secret_key = GROUP_SEED

DB_NAME = "server.db"


# functions for db so that each client thread has a direct access
def get_db():
    return sqlite3.connect(DB_NAME)

USERNAME = "test"
PASSWORD = "test123"

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
        password = request.form["password"].encode('utf-8')

        with get_db() as db:
            cur = db.execute("SELECT password FROM USERS WHERE username = ?", (username,))
            row = cur.fetchone()
        if row and row[0] == password:
            session['user'] = username
            return redirect(url_for("test"))

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


@app.route("/test")
def test():
    if "user" not in session:
        return redirect(url_for("login"))

    return f"Welcome, {session['user']}!"

if __name__ == "__main__":
    app.run()
