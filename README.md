# Log Analysis Pipeline – Brute Force Detection
# Log Analysis Pipeline – Advanced SSH Auth Analyzer

## 📌 Overview
This project analyzes system authentication logs to detect suspicious activity such as brute-force login attempts and unusual access patterns.
`analyzer.py` parses SSH authentication logs and detects suspicious activity patterns such as brute-force attacks, rapid attack bursts, credential stuffing behavior, and successful logins after failures.

It simulates real-world SOC (Security Operations Center) analysis by identifying failed login attempts and tracking successful logins.
The analyzer reads syslog-style lines (for example from `logs/auth.log`) and produces:
- console output
- a persisted report file (default: `report.txt`)

---

## 📂 Project Structure
## ⚙️ What `analyzer.py` Detects

log-analysis-pipeline/
├── logs/
│   └── auth.log
├── analyzer.py
└── README.md
### 1) Failed login patterns by IP
- **🔴 HIGH ALERT (rapid brute-force):** at least `--fail-threshold` failures within `--rapid-window-seconds`.
- **🟠 HIGH ALERT (persistent brute-force):** at least `--fail-threshold` failures, but not in a rapid burst.
- **🟡 MEDIUM ALERT:** more than one but fewer than `--fail-threshold` failures.
- **🟢 LOW ALERT:** exactly one failed attempt.

---
### 2) Credential stuffing signal
- **🟠 HIGH ALERT:** an IP targets at least `--stuffing-user-threshold` distinct usernames.

## 🔍 Features
### 3) Successful logins
- **🔵 INFO:** successful login from an IP that had previous failures.
- **🟢 Successful login:** successful login from an IP with no prior failures.

- Detects repeated failed login attempts  
- Identifies potential brute-force attacks  
- Tracks successful login events  
- Generates alert-based output  
### 4) Summary stats
The report includes:
- `total_events`
- `failed_events`
- `successful_events`
- `ips_with_failures`
- `ips_with_successes`

---

##  Detection Logic

- If an IP performs **3 or more failed login attempts**, it is flagged as a **HIGH ALERT (possible brute-force attack)**  
- Successful login attempts are also tracked for visibility  
## 🧠 Parser Behavior
The script parses these SSH auth patterns:
- `Failed password for ... from <ip>`
- `Accepted password for ... from <ip>`

---
## 📄 Report Generation
It applies a provided year (`--year`) to syslog timestamps that do not include one.

The tool generates a `report.txt` file containing all detected alerts for further analysis and documentation.
---
##  Sample Output
🚨 Suspicious Activity Report:

🔴 HIGH ALERT: Brute force attack from 192.168.1.10 (3 failed attempts)
🟢 Successful login from 192.168.1.20 
## 🚀 Usage

### Default run
```bash
python3 analyzer.py
```


### Tuned run (recommended for explicit reproducibility)
```bash
python3 analyzer.py \
  --log-file logs/auth.log \
  --report-file report.txt \
  --year 2026 \
  --fail-threshold 3 \
  --rapid-window-seconds 10 \
  --stuffing-user-threshold 3
```

---

## 🛠️ Tools & Technologies
## 🛠️ CLI Arguments

- Python  
- Log Analysis Techniques  
- Regex (for IP extraction)  
| Argument | Default | Description |
|---|---:|---|
| `--log-file` | `logs/auth.log` | Path to SSH authentication log file |
| `--report-file` | `report.txt` | Path to write the generated report |
| `--year` | current UTC year | Year applied to syslog timestamps |
| `--fail-threshold` | `3` | Failed-attempt threshold for high-risk brute-force |
| `--rapid-window-seconds` | `10` | Time window for rapid brute-force detection |
| `--stuffing-user-threshold` | `3` | Distinct usernames per IP to flag credential stuffing |

---

##  SOC Analyst Perspective

From a SOC perspective, this activity indicates a potential brute-force attack where an attacker repeatedly attempts to gain unauthorized access.
## 📄 Output Format

Such behavior would trigger alerts and require further investigation.
`report.txt` structure:
1. `🚨 Suspicious Activity Report`
2. `📊 Summary` section with counters
3. `🔎 Alerts` section with one alert per line

Example alert lines:
- `🔴 HIGH ALERT: Rapid brute-force from 192.168.1.10 (3 failures in 8s)`
- `🟠 HIGH ALERT: Possible credential stuffing from 203.0.113.5 (5 usernames targeted)`
- `🔵 INFO: Successful login after failures from 198.51.100.7 (1 successful logins)`

---
## Future Improvements
Add time-based attack detection
Export results to a report file
Integrate real-time log monitoring
Visualize data using graphs

## ✅ Conclusion

This project demonstrates how log analysis can be used to detect suspicious activity and identify potential threats, reflecting real-world SOC analyst responsibilities.
---
## 💻 Core Detection Logic

```python
if count >= 3:
    print(f"🔴 HIGH ALERT: Brute force attack from {ip} ({count} failed attempts)")


## 📂 Project Structure

```text
log-analysis-pipeline/
├── analyzer.py
├── logs/
│   └── auth.log
├── report.txt
└── README.md
```
