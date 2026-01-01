import requests

LOGIN_URL = "http://127.0.0.1:5000/login"
USERNAME = "user"
PASSWORD = "test"

def try_login():
    session = requests.Session()

    response = session.post(
        LOGIN_URL,
        data={
            "username": USERNAME,
            "password": PASSWORD
        },
        allow_redirects=True
    )

    if "Logged in as" in response.text or "test" in response.url:
        print("Login successful")
    else:
        print("Login failed")

if __name__ == "__main__":
    try_login()