# 🛡️ System Audit Investigation: Operation Paranoid

**Platform:** Blue Team Labs Online (BTLO)  
**Investigator:** Roshan Kumar  
**Tools Used:** `aureport`, `ausearch`, Linux Audit Framework (auditd)  
**Category:** Host-Based Forensics / Linux Security / Incident Response

---

## 📄 Scenario Overview
The objective was to investigate a potential compromise on a Linux-based system. Instead of traditional log file scrolling, I utilized the **Linux Audit CLI tool (`aureport`)** to generate summary reports of system activities, focusing on process execution, failed authentication, and suspicious modifications to system files.

## 🛠️ Investigation Steps & Findings using `aureport`

### 1. Identifying Suspicious Process Executions
I ran `aureport -p` to view a summary of all processes executed during the timeframe of the alert.
* **Findings:** Identified an unusual execution of a binary from a temporary directory (`/tmp` or `/dev/shm`).
* **Evidence:** Process ID [829992] was spawned by an unknown parent process, indicating a possible web-shell or remote execution.

### 2. Monitoring Failed Authentication Attempts
Using `aureport -au`, I generated a summary of authentication attempts to check for lateral movement or brute force.
* **Findings:** Multiple failed `su` attempts followed by a single successful login from a non-standard account.

### 3. File Integrity & System Changes
I utilized `aureport -f` to track modifications to critical configuration files.
* **Key Discovery:** Unauthorized modifications were detected in `/etc/crontab`, suggesting the attacker established **Persistence** via a scheduled task.

### 4. Detailed Event Analysis
After finding the summary in `aureport`, I pivoted to `ausearch` to find the exact timestamp and user associated with the malicious event.
* **Command:** `ausearch -p 829992 -if audit.log`
* **Result:** Traced the origin of the malicious process back to an initial exploitation of a vulnerable web service.

---

## 🛡️ Remediation Recommendations
1. **Auditd Tuning:** Enhance the audit rules to specifically monitor egress network connections triggered by system binaries.
2. **Eradication:** Remove the unauthorized cron jobs identified in the analysis.
3. **Hardening:** Mount `/tmp` with `noexec` permissions to prevent the execution of malicious payloads from temporary directories.

---

## 📈 Conclusion
Using `aureport` allowed for a rapid, high-level overview of the system's state during the attack. This methodology proved much faster than manual log analysis, enabling a quicker transition from detection to containment.
