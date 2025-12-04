# import requests
# import json
# import time

# url = "http://192.168.137.91:5000/predict"
# body = {
#     "IP": "45.146.165.137",
#     "Endpoint": "/.env",
#     "User-Agent": "curl/7.68.0",
#     "Country": "DE",
#     "Date": "2024-10-01 05:00:00"
# }

# while True:
#     try:
#         response = requests.post(url, json=body)
#         print(f"Status code: {response.status_code}")
#         print("Response:", response.json())
#     except Exception as e:
#         print("Request failed:", e)

#     # Wait for 1 second before sending the next request (adjust as needed)
#     time.sleep(1)

import requests
import random
import time
from datetime import datetime, timedelta

URL = "http://127.0.0.1:5050/predict"   # target endpoint (your local test server)
INTERVAL_SECONDS = 1                   # wait between requests (real seconds)
SIMULATED_STEP_SECONDS = 300                 # how much to advance the simulated timestamp per request (makes it feel "not real-time")
SEED = 42                                    # reproducible randomness (set to None for non-deterministic)
MAX_REQUESTS = None                          # set to an int to limit total requests for safety, or None for indefinite

random.seed(SEED)

# lists of suspicious/interesting-looking endpoints, UAs, countries
ENDPOINTS = ["/.env", "/admin", "/phpmyadmin", "/wp-login.php", "/api/v1/login", "/.git/config", "/cgi-bin/", "/backup.zip"]
UAS = [
    "curl/7.68.0",
    "python-requests/2.28.1",
    "Masscan/1.0",
    "Nmap Scripting Engine",
    "Mozilla/5.0 (compatible; UnknownBot/1.0; +http://example.com/bot)",
    "Scanner/0.1",
]
COUNTRIES = ["RU", "CN", "UA", "DE", "BR", "IR", "US", "NL"]

def gen_repeated_octet():
    octet = str(random.randint(1, 254))
    return ".".join([octet]*4)

def gen_sequential_pattern():
    start = random.randint(1, 250)
    return ".".join(str((start + i) % 255 or 1) for i in range(4))

def gen_same_prefix(prefix_length=3):
    prefix = ".".join(str(random.randint(1,254)) for _ in range(prefix_length))
    while prefix.count(".") < prefix_length-1:
        prefix += ".0"
    remaining = ".".join(str(random.randint(1,254)) for _ in range(4-prefix_length))
    if remaining:
        return prefix + "." + remaining
    return prefix + ".1"

def gen_random_publicish():
    # generate a "public-looking" address avoiding simple low values
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def gen_malformed_like():
    # create something that looks suspicious but still parsable by some logs
    patterns = [
        "999.999.999.999",
        "1234::5678",   # IPv6-looking string
        "0.0.0.0",
        "255.255.255.255",
    ]
    return random.choice(patterns)

# choose from the generators with weighted probabilities (favor malicious-looking patterns)
IP_GENERATORS = [
    (gen_repeated_octet, 0.20),
    (gen_sequential_pattern, 0.20),
    (gen_same_prefix, 0.20),
    (gen_random_publicish, 0.30),
    (gen_malformed_like, 0.10),
]

def pick_ip():
    r = random.random()
    cum = 0.0
    for fn, weight in IP_GENERATORS:
        cum += weight
        if r <= cum:
            # some generators accept args: if gen_same_prefix randomly choose prefix length
            if fn == gen_same_prefix:
                return fn(prefix_length=random.choice([2,3]))
            return fn()

    return gen_random_publicish()

def pick_endpoint():
    # pick suspicious endpoints with some chance of dynamic paths / query strings
    base = random.choice(ENDPOINTS)
    if random.random() < 0.25:
        base += "?q=" + "".join(random.choices("abcdef0123456789", k=8))
    return base

def pick_ua():
    return random.choice(UAS)

def pick_country():
    # slight chance of uncommon two-letter codes
    return random.choice(COUNTRIES)

def build_payload(sim_timestamp):
    payload = {
        "IP": pick_ip(),
        "Endpoint": pick_endpoint(),
        "User-Agent": pick_ua(),
        "Country": pick_country(),
        "Date": sim_timestamp.strftime("%Y-%m-%d %H:%M:%S")
    }
    return payload

def main():
    sim_time = datetime.strptime("2024-10-01 05:00:00", "%Y-%m-%d %H:%M:%S")  # seed simulated time
    sent = 0
    try:
        while True:
            payload = build_payload(sim_time)
            try:
                r = requests.post(URL, json=payload, timeout=5)
                status = r.status_code
                try:
                    j = r.json()
                except Exception:
                    j = r.text[:500]
                print(f"[{datetime.now().isoformat()}] Sent simulated {payload['IP']:15} -> {payload['Endpoint']:20} | status {status} | resp: {j}")
            except Exception as e:
                print(f"[{datetime.now().isoformat()}] Request failed: {e} | payload={payload}")

            # advance simulated time by a larger step so logs *feel* non-real-time/simulated
            sim_time += timedelta(seconds=SIMULATED_STEP_SECONDS + random.randint(-60, 120))

            sent += 1
            if MAX_REQUESTS and sent >= MAX_REQUESTS:
                print("Reached MAX_REQUESTS, exiting.")
                break

            time.sleep(INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("Stopped by user.")

if __name__ == "__main__":
    main()

# import requests
# import random
# import time
# from datetime import datetime, timedelta

# URL = "http://192.168.137.113:5000/predict"   # target endpoint (your local test server)
# INTERVAL_SECONDS = 1                         # wait between requests (real seconds)
# SIMULATED_STEP_SECONDS = 300                 # how much to advance the simulated timestamp per request (makes it feel "not real-time")
# SEED = 42                                    # reproducible randomness (set to None for non-deterministic)
# MAX_REQUESTS = None                          # set to an int to limit total requests for safety, or None for indefinite

# random.seed(SEED)

# # lists of suspicious/interesting-looking endpoints, UAs, countries
# ENDPOINTS = ["/.env", "/admin", "/phpmyadmin", "/wp-login.php", "/api/v1/login", "/.git/config", "/cgi-bin/", "/backup.zip"]
# UAS = [
#     "curl/7.68.0",
#     "python-requests/2.28.1",
#     "Masscan/1.0",
#     "Nmap Scripting Engine",
#     "Mozilla/5.0 (compatible; UnknownBot/1.0; +http://example.com/bot)",
#     "Scanner/0.1",
# ]
# COUNTRIES = ["RU", "CN", "UA", "DE", "BR", "IR", "US", "NL"]

# def gen_repeated_octet():
#     octet = str(random.randint(1, 254))
#     return ".".join([octet]*4)

# def gen_sequential_pattern():
#     start = random.randint(1, 250)
#     return ".".join(str((start + i) % 255 or 1) for i in range(4))

# def gen_same_prefix(prefix_length=3):
#     prefix = ".".join(str(random.randint(1,254)) for _ in range(prefix_length))
#     while prefix.count(".") < prefix_length-1:
#         prefix += ".0"
#     remaining = ".".join(str(random.randint(1,254)) for _ in range(4-prefix_length))
#     if remaining:
#         return prefix + "." + remaining
#     return prefix + ".1"

# def gen_random_publicish():
#     # generate a "public-looking" address avoiding simple low values
#     return ".".join(str(random.randint(1, 254)) for _ in range(4))

# def gen_malformed_like():
#     # create something that looks suspicious but still parsable by some logs
#     patterns = [
#         "999.999.999.999",
#         "1234::5678",   # IPv6-looking string
#         "0.0.0.0",
#         "255.255.255.255",
#     ]
#     return random.choice(patterns)
# # choose from the generators with weighted probabilities (favor malicious-looking patterns)
# IP_GENERATORS = [
#     (gen_repeated_octet, 0.20),
#     (gen_sequential_pattern, 0.20),
#     (gen_same_prefix, 0.20),
#     (gen_random_publicish, 0.30),
#     (gen_malformed_like, 0.10),
# ]

# def pick_ip():
#     r = random.random()
#     cum = 0.0
#     for fn, weight in IP_GENERATORS:
#         cum += weight
#         if r <= cum:
#             # some generators accept args: if gen_same_prefix randomly choose prefix length
#             if fn == gen_same_prefix:
#                 return fn(prefix_length=random.choice([2,3]))
#             return fn()

#     return gen_random_publicish()

# def pick_endpoint():
#     # pick suspicious endpoints with some chance of dynamic paths / query strings
#     base = random.choice(ENDPOINTS)
#     if random.random() < 0.25:
#         base += "?q=" + "".join(random.choices("abcdef0123456789", k=8))
#     return base

# def pick_ua():
#     return random.choice(UAS)

# def pick_country():
#     # slight chance of uncommon two-letter codes
#     return random.choice(COUNTRIES)

# def build_payload(sim_timestamp):
#     payload = {
#         "IP": pick_ip(),
#         "Endpoint": pick_endpoint(),
#         "User-Agent": pick_ua(),
#         "Country": pick_country(),
#         "Date": sim_timestamp.strftime("%Y-%m-%d %H:%M:%S")
#     }
#     return payload

# def main():
#     sim_time = datetime.strptime("2024-10-01 05:00:00", "%Y-%m-%d %H:%M:%S")  # seed simulated time
#     sent = 0
#     try:
#         while True:
#             payload = build_payload(sim_time)
#             try:
#                 r = requests.post(URL, json=payload, timeout=5)
#                 status = r.status_code
#                 try:
#                     j = r.json()
#                 except Exception:
#                     j = r.text[:500]
#                 print(f"[{datetime.now().isoformat()}] Sent simulated {payload['IP']:15} -> {payload['Endpoint']:20} | status {status} | resp: {j}")
#             except Exception as e:
#                 print(f"[{datetime.now().isoformat()}] Request failed: {e} | payload={payload}")

#             # advance simulated time by a larger step so logs *feel* non-real-time/simulated
#             sim_time += timedelta(seconds=SIMULATED_STEP_SECONDS + random.randint(-60, 120))

#             sent += 1
#             if MAX_REQUESTS and sent >= MAX_REQUESTS:
#                 print("Reached MAX_REQUESTS, exiting.")
#                 break

#             time.sleep(INTERVAL_SECONDS)
#     except KeyboardInterrupt:
#         print("Stopped user.")

# if __name__ == "__main__":
#     main()

