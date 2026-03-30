from collections import defaultdict
import re

log_file = "logs/auth.log"

failed_attempts = defaultdict(int)
successful_logins = defaultdict(int)

with open(log_file, "r") as file:
    for line in file:
        if "Failed password" in line:
            match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
            if match:
                ip = match.group()
                failed_attempts[ip] += 1

        if "Accepted password" in line:
            match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
            if match:
                ip = match.group()
                successful_logins[ip] += 1

print("\n🚨 Suspicious Activity Report:\n")

for ip, count in failed_attempts.items():
    if count >= 3:
        print(f"🔴 HIGH ALERT: Brute force attack from {ip} ({count} failed attempts)")

for ip, count in successful_logins.items():
    print(f"🟢 Successful login from {ip}")
