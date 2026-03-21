🛡️ Digital Forensics Investigation: Windows Bruteforce Attack

Platform: Blue Team Labs Online (BTLO)

Investigator: Roshan Kumar

Date: March 21, 2026

Category: Log Analysis / Windows Security

📄 Scenario

A Windows server flagged multiple failed login attempts within a very short timeframe. My objective was to analyze the Windows Event Logs to identify the attacker's IP address, the account they targeted, and the technical scope of the attack (Source Ports used).

🛠️ Investigation Steps & Findings

1. Identifying the Attack Vector

By filtering for Event ID 4625 (An account failed to log on) in the provided logs, I identified a massive spike in failed authentication attempts.

Attacker IP Address: 113.161.192.227

Targeted Username: Administrator

2. Technical Scope: Source Port Analysis

To determine the range of source ports used by the attacker, I exported the logs to CSV and utilized Excel string manipulation.

I used the following formula to extract the buried source port data from the description field:
=IFERROR(MID(F1,FIND("Source Port:",F1)+12,5),"")

Lowest Port Used: 49162

Highest Port Used: 65534

Port Range: 49162-65534

3. MITRE ATT&CK Mapping

Technique: T1110 (Brute Force)

Sub-technique: T1110.001 (Password Guessing)

4. Remediation Recommendations

Implement an Account Lockout Policy after 5 failed attempts.

Enable Multi-Factor Authentication (MFA) for all remote logins.

Restrict RDP/Login access to specific authorized IP ranges via firewall rules.

📈 Conclusion

This investigation demonstrated the pattern of an automated brute-force attack. By extracting source port data, I was able to confirm the use of an automated tool (like Hydra or Burp Suite) which increments ephemeral ports rapidly for each attempt.
