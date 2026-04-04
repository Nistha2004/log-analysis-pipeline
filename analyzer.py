from collections import defaultdict
import re
from datetime import datetime

log_file = "logs/auth.log"

failed_attempts = defaultdict(list)
successful_logins = defaultdict(int)

alerts = []

with open(log_file, "r") as file:
    for line in file:
        time_match = re.search(r'(\w+ \d+ \d+:\d+:\d+)', line)
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)

        if time_match and ip_match:
            time_str = "2026 " + time_match.group()
            ip = ip_match.group()

            log_time = datetime.strptime(time_str, "%Y %b %d %H:%M:%S")

            if "Failed password" in line:
                failed_attempts[ip].append(log_time)

            if "Accepted password" in line:
                successful_logins[ip] += 1

# 🔍 Detection Logic
for ip, times in failed_attempts.items():
    times.sort()
    
    if len(times) >= 3:
        rapid_attack = False
        
        for i in range(len(times) - 2):
            diff = (times[i+2] - times[i]).seconds
            
            if diff <= 10:
                alerts.append(f"🔴 HIGH ALERT: Rapid brute-force attack from {ip}")
                rapid_attack = True
                break
        
        if not rapid_attack:
            alerts.append(f"🟡 MEDIUM ALERT: Multiple failed attempts from {ip}")
    
    elif len(times) > 0:
        alerts.append(f"🟢 LOW ALERT: Few failed attempts from {ip}")

# 🟢 Successful logins
for ip in successful_logins:
    alerts.append(f"🟢 Successful login from {ip}")

# 🖥️ Print output
print("\n🚨 Suspicious Activity Report:\n")
for alert in alerts:
    print(alert)

# 📄 Save report
with open("report.txt", "w") as report:
    report.write("🚨 Suspicious Activity Report\n\n")
    for alert in alerts:
        report.write(alert + "\n")
