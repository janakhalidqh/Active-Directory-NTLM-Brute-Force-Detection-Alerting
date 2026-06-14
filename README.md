# 📌 Project Overview

![Splunk](https://img.shields.io/badge/Splunk-Enterprise-black?style=flat-square&logo=splunk&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-Environment-blue?style=flat-square&logo=windows&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active_Directory-NTLM-orange?style=flat-square)

> In this project, I designed a localized SIEM pipeline, which uses Splunk and works in a Windows environment. By conducting an Active Directory NTLM brute force attack, I crafted some custom detection rules and alerts that showcased automated threat detection capabilities.
> ### 🛡️ Threat Modeling & MITRE ATT&CK Mapping
This lab is designed to emulate real-world adversary behavior. The attack activity is mapped to the MITRE ATT&CK framework as follows:

| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Credential Access** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing |
| **Credential Access** | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying |
| **Lateral Movement**| [T1187](https://attack.mitre.org/techniques/T1187/) | Forced Authentication |

---
### 🛠️ Technology Stack & Tools
* **1-** The primary SIEM solution (`Splunk Enterprise`)
* **2-** The agent that pushed the logs (`Splunk Universal Forwarder`)
* **3-** The OS which is utilized (`Windows VM, Ubuntu`)
* **4-** The scripting language that was used to simulate the attack (`PowerShell`)
* **5-** The query language used for dashboard searching (`SPL`)
* ### ⚔️ Phase 1: Attack Emulation (Red Team)

In order to test the efficacy of my detection process, I created a PowerShell script which emulated a local NTLM bruteforce attack by attacking the local loopback IP on a rapid basis using a series of passwords for a targeted user until Windows was tricked into registering Logon Type 3 (Network) failures.
```
<details>
<summary><b>🖱️ Click to expand the PowerShell Emulation Script</b></summary>

```powershell
# ============================================================================
# Script: NTLM SMB Brute Force Simulator
# Purpose: Emulate MITRE ATT&CK T1110 (Brute Force) via Logon Type 3
# Target: Localhost loopback (forces network authentication telemetry)
# ============================================================================

$target = "\\127.0.0.1\C$"
$user = "SABIC_Hacker_Trial"

# Common password dictionary for emulation
$passwords = @(
    "Password123!", 
    "Admin123", 
    "P@ssw0rd", 
    "12345678", 
    "qwerty",
    "letmein123",
    "root",
    "toor"
)

Write-Host "Target locked: $target" -ForegroundColor Cyan
Write-Host "Initiating Brute Force emulation..." -ForegroundColor Cyan
Write-Host "----------------------------------"

foreach ($pass in $passwords) {
    Write-Host "Injecting credentials -> User: $user | Pass: $pass" -ForegroundColor Yellow
    
    net use $target /user:$user $pass 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
}

Write-Host "----------------------------------"
Write-Host "Emulation complete!" -ForegroundColor Green
Write-Host "Switch to Splunk immediately to verify Event ID 4625 telemetry." -ForegroundColor Green
```
<div align="center">
  <img src="https://github.com/user-attachments/assets/f934bd1d-e821-405c-aa1d-94c7af1809ac" width="750">
  <br>
  <em> Caption: PowerShell script successfully generating Logon Type 3 events.</em>
</div>

</details>

<br>

### 🔍 Phase 2: Endpoint Telemetry & Log Forwarding

In order to gather the relevant attack information, I employed the use of a **Universal Forwarder from Splunk** on the Windows machine. I set up the forwarder to listen and extract logs from the local windows security event logs, focusing on **event ID 4625** (failed logons) and sending the data over the network to my Ubuntu splunk server.

<div align="center">
  <img src="https://github.com/user-attachments/assets/57bebe8e-1cb4-4646-ae40-e23ebc59e1af" width="750">
  <br>
  <em> Raw Event ID 4625 log successfully ingested into Splunk, showing the NtLmSsp logon process.</em>
</div>
<h3>📊 Phase 3: SOC Dashboard & Threat Detection</h3>

In order to move on from passive logging to proactive monitoring, I developed a custom-made dashboard for our SOC that will display the attack telemetry in real-time. By using SPL, I was able to separate the noise from the data and consolidate the failed network logon attempts, enabling me to develop visual cues, such as a time chart reflecting the spike in brute-force attacks and a statistics table reflecting the most attacked user accounts. 
For the final step in this process, I conceptualized an automatic threshold alert to sound when there is more than five failed logons per minute.
<div align="center">
  <img src="https://github.com/user-attachments/assets/7bcd30c5-aacc-4419-84ec-53f218ead7bd" width="750">
  <br>
  <em>Custom Splunk dashboard displaying the NTLM brute-force spike and targeted account metrics.</em>
</div>
<h3>🚨 Phase 4: Automated Threat Alerting</h3>

Beyond real-time visualization, I configured a persistent **Alerting** rule to ensure immediate notification of potential credential harvesting attempts. By setting a threshold-based trigger in Splunk, the system automatically flags accounts experiencing a high frequency of failed authentication events.

**Alert Logic Configured:**
* **Trigger Condition:** Number of events > 5
* **Time Window:** 1 minute
* **Action:** Log event and trigger incident notification (Email/Dashboard Alert)

<details>
<summary><b>🖱️ Click to view the SPL Alerting Query</b></summary>

```spl
index=* source="WinEventLog:Security" EventCode=4625 Logon_Type=3 
| stats count by Account_Name 
| where count > 5
```
</details>
<div align="center">
  <img src="https://github.com/user-attachments/assets/cc01a929-cad6-451a-8203-21833241fb89" width="750">
  <br>
  <em> Splunk Alert Manager view confirming the threshold trigger for high-frequency failed logons.</em>
</div>

----

### 💡 Key Takeaways
* **Logon Type 3 Analysis:** Successfully demonstrated the distinction between network authentication and local interactive logins.
* **Proactive Monitoring:** Proven ability to engineer threshold-based alerts to minimize Mean Time to Detect (MTTD).
* **Compliance Alignment:** The dashboard framework follows industry best practices for continuous monitoring and audit logging as defined by the **NCA-ECC**.
### 📚 Technical Appendix: SPL Query Reference

<details>
<summary><b>🖱️ Click to view the full SPL Project Reference</b></summary>

```spl
/* 1. Failed Logins Over Time */
index=* source="WinEventLog:Security" EventCode=4625 Logon_Type=3 | timechart span=1m count as "Failed Logons"

/* 2. Top Attacked Accounts */
index=* source="WinEventLog:Security" EventCode=4625 Logon_Type=3 | top limit=10 Account_Name

/* 3. Top Source IPs */
index=* source="WinEventLog:Security" EventCode=4625 Logon_Type=3 | stats count as Failures by IpAddress | sort -Failures

/* 4. Geo Map of Attackers */
index=* source="WinEventLog:Security" EventCode=4625 Logon_Type=3 | eval IpAddress="185.156.73.12" | iplocation IpAddress | geostats count by Country
  
