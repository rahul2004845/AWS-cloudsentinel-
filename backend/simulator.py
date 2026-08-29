import time
import random
import requests
from faker import Faker
from datetime import datetime

fake = Faker()

API_URL = "http://localhost:8000/api/logs"

def generate_normal_log():
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": fake.ipv4(),
        "user_id": fake.user_name(),
        "event_type": random.choice(["login", "api_call", "file_access", "logout", "api_call", "api_call"]),
        "status": random.choices(["success", "failed"], weights=[90, 10])[0],
        "resource": fake.uri_path(),
        "bytes_transferred": random.randint(100, 5000),
        "user_agent": fake.user_agent()
    }

def simulate_brute_force(ip):
    print(f"--- Simulating Brute Force from {ip} ---")
    for _ in range(12): # Trigger rule if > 10 in 60s
        log = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_ip": ip,
            "user_id": "admin",
            "event_type": "login",
            "status": "failed",
            "resource": "/auth/login",
            "bytes_transferred": 120,
            "user_agent": "python-requests/2.25.1"
        }
        requests.post(API_URL, json=log)
        time.sleep(0.1)

def simulate_exfiltration(ip):
    print(f"--- Simulating Data Exfiltration from {ip} ---")
    log = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": ip,
        "user_id": fake.user_name(),
        "event_type": "file_access",
        "status": "success",
        "resource": "/restricted/database_dump.sql",
        "bytes_transferred": random.randint(6000000, 15000000), # > 5 MB
        "user_agent": fake.user_agent()
    }
    requests.post(API_URL, json=log)

if __name__ == "__main__":
    print("Starting Log Simulator...")
    counter = 0
    while True:
        try:
            # Randomly inject attacks roughly every 15-20 cycles
            if counter > 0 and counter % 15 == 0:
                attack_type = random.choice(["brute_force", "exfiltration"])
                malicious_ip = fake.ipv4()
                if attack_type == "brute_force":
                    simulate_brute_force(malicious_ip)
                else:
                    simulate_exfiltration(malicious_ip)
            else:
                log = generate_normal_log()
                requests.post(API_URL, json=log)
            
            counter += 1
            time.sleep(random.uniform(0.5, 2.0))
        except requests.exceptions.ConnectionError:
            print("Failed to connect to backend. Is the FastAPI server running?")
            time.sleep(5)
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(1)
