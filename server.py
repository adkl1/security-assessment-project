from flask import Flask, request, redirect, url_for, session, render_template_string

app = Flask(__name__)
GROUP_SEED = "506512019"
app.secret_key = GROUP_SEED

USERNAME = "test"
PASSWORD = "test123"

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    {% if error %}
        <p style="color:red;">{{ error }}</p>
    {% endif %}
    <form method="post">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == USERNAME and password == PASSWORD:
            session["user"] = username
            return redirect(url_for("test"))

        return render_template_string(LOGIN_HTML, error="Invalid credentials")

    return render_template_string(LOGIN_HTML)


@app.route("/test")
def test():
    if "user" not in session:
        return redirect(url_for("login"))

    return f"Welcome, {session['user']}!"

if __name__ == "__main__":
    app.run()
