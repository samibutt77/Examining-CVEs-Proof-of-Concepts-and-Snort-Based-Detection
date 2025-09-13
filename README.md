# CVE Analysis & Detection — PoCs, Snort Detection, and Mitigations
# Overview

This repository documents hands-on vulnerability analysis and proof-of-concept (PoC) exploitation carried out in a controlled lab. It includes PoCs for multiple high-impact CVEs, packet captures (Wireshark), IDS detection using Snort, and recommended mitigation strategies. All activities were performed in isolated VMs (attacker/target) and are intended for defensive research, learning, and testing only. 

# CVE list (covered in this work)

- BlueKeep — CVE-2019-0708: RDP RCE (wormable) affecting older Windows versions; exploited via Metasploit in lab. 


- Log4Shell — CVE-2021-44228: Log4j JNDI lookup RCE — demonstrated with vulnerable Docker app and LDAP/RMI exploit chain.
  

- Apache Path Traversal / RCE — CVE-2021-41773: Path normalization issue in Apache 2.4.49 leading to file disclosure and possible RCE when CGI enabled.
  

- 7-Zip MotW Bypass — CVE-2025-0411: Mark-of-the-Web flag bypass in 7-Zip (pre-24.09) causing extracted files to lose MotW protection; used to deploy payloads silently.
  

- Windows OLE Zero-Click — CVE-2025-21298: Use-after-free in OLE parsing allowing zero-click RCE via malicious RTF.
  

- Sysinternals DLL loading / DLL hijack (0-day style): Demonstrated DLL injection/hijacking by supplying a malicious DLL alongside Sysinternals tools (e.g., Process Explorer) to achieve DoS or a Meterpreter reverse shell. (Note: zero-day/unassigned in doc.) 


- Older TCP/IP DoS CVEs (historical): SYN flooding and TCP/IP stack DoS CVEs used as background for traffic analysis.

- Bonus: Syn Flooding DOS POC Converted to Port Scanning. 


# Proofs-of-Concept & detection summary

# Environment

- Attacker: Kali Linux (Metasploit, msfvenom, custom scripts)

- Target: Windows VMs (various versions), Docker containers running vulnerable apps

- File hosting: Python http.server for delivering payloads during tests

- Monitoring: Wireshark captures on victim, Snort IDS for signature detection and logging. 


# Key PoCs performed (high level)

- BlueKeep: Used Metasploit module to check and exploit legacy Windows RDP; confirmed via RDP traffic in Wireshark and Snort alerts. 


- Log4Shell: Deployed a vulnerable Java app in Docker, hosted malicious LDAP/RMI payload, injected ${jndi:ldap://…} in headers to trigger remote code execution (demonstrated by touch /tmp/pwned). Snort captured exploit traffic after rule deployment. 


- CVE-2021-41773 (Apache): Ran vulnerable Apache container and issued path traversal requests to read /etc/passwd, validating via packet captures and Snort alerts. 


- Sysinternals DLL Hijack: Built malicious DLL (DoS or Meterpreter payload), bundled with Sysinternals binary, served via Python HTTP server; when executed on target, the binary loaded the malicious DLL producing DoS or reverse shell behavior. Detection via Wireshark and process activity logs was shown. 


- 7-Zip MotW Bypass (CVE-2025-0411): Created nested 7z archives to strip MotW on extraction, delivered loader.exe; upon extraction, loader executed without MotW warnings leading to reverse shell or DoS. 


- OLE Zero-Click (CVE-2025-21298): Crafted malicious RTF, opened/previewed in Word to trigger crash and prove exploitability; also demonstrated potential for Meterpreter reverse shell. 


# IDS (Snort) detection

- Custom/standard Snort signatures were deployed to detect: BlueKeep exploit patterns, JNDI/LDAP indicators used by Log4Shell PoCs, directory traversal attempts on Apache, and suspicious downloads/HTTP headers used in PoCs. Snort logged alerts for each exploited case in tests; Wireshark traces corroborated network indicators. 


# Detection & mitigation recommendations (summary)

# Immediate actions

- Patch vulnerable software immediately (apply vendor fixes and recommended versions). 


- Disable or restrict remote services (e.g., RDP), block external access to risky ports. 


# Hardening & policy

- Enforce application control (AppLocker/WDAC) and DLL signature validation to mitigate DLL hijacking. 


- Preserve Mark-of-the-Web behavior and update extraction tools (7-Zip) to fixed versions to prevent MotW bypass exploitation. 


- Disable insecure Java features (JNDI lookups) or patch Log4j to safe versions; use WAF rules to drop suspicious payloads. 


# Detection

- Deploy and tune Snort/IDS signatures for observed exploit indicators (JNDI strings, odd LDAP/RMI flows, RDP exploit patterns, unusual file access via HTTP). Use EDR to monitor process creation and DLL loads. 


- Monitor for missing MotW flags on extracted files and unusual outbound connections from Office apps (winword.exe) to detect OLE/RCE exploitation. 


# Longer term

- Adopt least privilege, network segmentation, zero trust, and software supply-chain verification for tools used in enterprise (e.g., download Sysinternals from official sources only). 

