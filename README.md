# Log Analysis Pipeline – Brute Force Detection

## 📌 Overview
This project analyzes system authentication logs to detect suspicious activity such as brute-force login attempts and unusual access patterns.

It simulates real-world SOC (Security Operations Center) analysis by identifying failed login attempts and tracking successful logins.

---

## 📂 Project Structure

log-analysis-pipeline/
├── logs/
│   └── auth.log
├── analyzer.py
└── README.md

---

## 🔍 Features

- Detects repeated failed login attempts  
- Identifies potential brute-force attacks  
- Tracks successful login events  
- Generates alert-based output  

---

##  Detection Logic

- If an IP performs **3 or more failed login attempts**, it is flagged as a **HIGH ALERT (possible brute-force attack)**  
- Successful login attempts are also tracked for visibility  

---

##  Sample Output
🚨 Suspicious Activity Report:

🔴 HIGH ALERT: Brute force attack from 192.168.1.10 (3 failed attempts)
🟢 Successful login from 192.168.1.20 


---

## 🛠️ Tools & Technologies

- Python  
- Log Analysis Techniques  
- Regex (for IP extraction)  

---

##  SOC Analyst Perspective

From a SOC perspective, this activity indicates a potential brute-force attack where an attacker repeatedly attempts to gain unauthorized access.

Such behavior would trigger alerts and require further investigation.


---
## 💻 Core Detection Logic

```python
if count >= 3:
    print(f"🔴 HIGH ALERT: Brute force attack from {ip} ({count} failed attempts)")

---

##  Future Improvements

- Add time-based attack detection  
- Export results to a report file  
- Integrate with real-time log monitoring  
- Visualize data using graphs  

---

## ✅ Conclusion

This project demonstrates how log analysis can detect suspicious activity and identify potential security threats, reflecting real-world SOC responsibilities.
