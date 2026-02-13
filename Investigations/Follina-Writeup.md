🔍 BTLO Investigation: Follina (CVE-2022-30190)

Date: February 13, 2026

Category: Incident Response / Digital Forensics

Level: Easy

📄 Scenario Overview

On a Friday evening, the team was alerted to a new Remote Code Execution (RCE) vulnerability being exploited in the wild. I was tasked with analyzing a suspicious sample to extract indicators of compromise (IOCs) and understand the attack vector.

🛠️ Investigation Details

During the analysis, I performed the following steps:

File Identification: * SHA1 Hash: 06727ffda60359236a8029e0b3e8a0fd11c23313

File Type: Office Open XML Document (.docx)

Technical Deep-Dive:

Infection Vector: The sample uses a malicious URL hidden within document.xml.rels.

Malicious URL: https://www.xmlformats.com:443/office/word/2022/wordprocessingDrawing/RDF842l.html

Trigger Mechanism: The vulnerability executes a payload via the Microsoft Support Diagnostic Tool (msdt.exe) if the file contains more than 4096 bytes.

Detection & Mapping:

Process Detection: Created a detection rule using Windows Event ID 4688 focusing on msdt.exe with winword.exe as the parent process.

MITRE ATT&CK Mapping: T1559 - Inter-Process Communication.

Vulnerability ID: CVE-2022-30190.

💡 Key Learnings

Understanding how "Living off the Land" binaries (like msdt.exe) can be weaponized.

Learned how to pivot from a file hash to VirusTotal for rapid identification.

Developed process-based detection rules to identify future exploitation attempts.!

![3ss](https://github.com/user-attachments/assets/fe67e62a-1f29-4085-bccf-304baf63ee6d)
[1ss](https://github.com/user-attachments/assets/b4120b9b-3508-4a9c-b1ec-b7d813898d79)
![2ss](https://github.com/user-attachments/assets/8a295e69-0aab-4ede-a0cd-a0fbbba434a9)
