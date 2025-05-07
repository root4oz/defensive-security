# ❗ Failed Login Attempts Detection

**Objective:** Identify multiple failed login attempts from the same source IP. Ex: Brute Force Attack:

### 🔍 SPL Query:
```spl

index=windows EventCode=4625 (or EventID=4625)
| stats count by src_ip, user
| where count > 5


📌 Notes:

EventCode 4625 indicates failed logon in Windows systems.

Modify the threshold based on your environment.




# 👤 2. Multiple Failed Login Attempts for the Same User

index=windows  eventCode=4625
| stats count by user
| where count > 10



# 📆 3. Failed Login Attempts Over Time

index=windows EventCode=4625
| timechart span=5m count by src_ip


Purpose: Monitor failed login attempts over time by source IP.


# 🧠 4. Failed Login Attempts by User, Workstation, and IP

index=windows EventCode=4625
| stats count by user, WorkstationName, src_ip
| where count > 5

Purpose: Track failed login attempts per user, workstation, and IP address.



# 🧪 5. Failed Logins Followed by Successful Logins (Possible Brute Force Success)


(index=windiws Eventcode=4625 or Eventcode=4624)
| transaction user startswith=(EventCode=4625) endswith=(EventCode=4624)
| where eventcount > 3


Purpose: Detect a pattern where several failed attempts are followed by a successful login (indicating a possible brute force attack).




