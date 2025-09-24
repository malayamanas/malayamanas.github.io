---
title: "Bashed HTB - Easy Linux Box Walkthrough"
date: 2025-09-22T13:00:00Z
tags: ["easy-linux", "nmap", "gobuster", "webshell", "php-bash", "privilege-escalation", "sudo-misconfiguration", "cron-job", "file-upload", "ubuntu-xenial", "apache", "TJ_Null OSCP Prep", "directory-enumeration", "reverse-shell"]
difficulty: ["easy"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Bashed HTB machine featuring PHP web shell exploitation, sudo privilege escalation, and cron job manipulation for root access"
---

# Bashed HTB - Easy Linux Box Walkthrough

{{< youtube 2DqdPcbYcy8 >}}

## Key Exploitation Steps and Techniques

### Exploitation Chain (Chronological Order)

1. **Initial Enumeration with Nmap**: Perform an Nmap scan (`nmap -sC -sV -oA initial [TARGET-IP]`) to identify open ports, discovering port 80 running Apache 2.4.18 on Ubuntu.

2. **Determine OS Version**: Search for Ubuntu versions associated with Apache 2.4.18, concluding it's Ubuntu Xenial 16.04.

3. **Web Server Exploration**: Access the web server at `http://[TARGET-IP]`, finding a page for "Arrexel's Development" with a link to PHP Bash, identified as a web shell.

4. **Directory Enumeration with Gobuster**: Run Gobuster (`gobuster -u http://[TARGET-IP] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`) to discover hidden directories: /uploads, /php (with send_mail.php), /dev (with phpbash.php and phpbash.min.php), /css, /js.

5. **Test Uploads Directory**: Confirm /uploads is writable by creating a test file via the web shell.

6. **Access Web Shell**: Execute commands in /dev/phpbash.php (e.g., `id`, `ifconfig`) to confirm remote code execution as www-data.

7. **Privilege Escalation Enumeration**: Download and run LinEnum.sh via wget to /dev/shm, analyzing output to find no kernel exploits but sudo rights for www-data to run commands as scriptmanager without a password.

8. **Test Sudo Rights**: Use `sudo -u scriptmanager whoami` in the web shell, noting the shell is non-persistent, resetting user after each command.

9. **Attempt Direct Reverse Shells**: Try bash, netcat, and PHP reverse shells directly in the web shell, but they fail due to potential redirects in the web shell code.

10. **Upload PHP Reverse Shell**: Host a PHP reverse shell on the attacker machine, download it to /uploads via wget in the web shell, then execute it to establish a persistent reverse shell as www-data.

11. **Switch to Scriptmanager User**: In the persistent reverse shell, run `sudo -u scriptmanager bash` to switch users persistently.

12. **Explore Scripts Directory**: Navigate to /scripts, finding test.py (writes to test.txt) and test.txt (modified every minute, owned by root), indicating a cron job.

13. **Confirm Cron Job**: Use `crontab -l` to verify a root-owned cron job executes *.py in /scripts every minute.

14. **Exploit Cron Job for Root**: Replace test.py with Python reverse shell code, wait for the next cron execution, receiving a root reverse shell.

15. **Capture Root Flag**: Access /root/root.txt to obtain the flag.

## Security Gaps and Remediation

### Web Server (Apache 2.4.18 on Ubuntu 16.04)

- **Outdated Apache Version**: Running Apache 2.4.18, which may have known vulnerabilities (though not directly exploited here).
  **Fix**: Configuration fix - Update the system and Apache package to the latest stable version via `apt update && apt upgrade apache2` to patch potential security issues.

- **Exposed Development Directories**: Directories like /dev, /php, /css, /js are publicly accessible via directory enumeration tools like Gobuster, revealing sensitive files.
  **Fix**: Configuration fix - Add Apache configuration directives in the virtual host file (e.g., /etc/apache2/sites-enabled/000-default.conf) to deny access to these directories, such as `<Directory /var/www/html/dev> Options -Indexes </Directory>` or remove unnecessary directories from the web root.

### PHP Bash Web Shell (/dev/phpbash.php)

- **Publicly Accessible Web Shell**: The PHP Bash script is exposed on the web server, allowing unauthenticated remote command execution as the www-data user.
  **Fix**: Source code fix - Implement authentication in the PHP code, such as adding session-based login checks or HTTP Basic Auth before executing commands. Alternatively, configuration fix - Remove the file from the web root or set file permissions to 000 (unreadable/unexecutable) via `chmod 000 /var/www/html/dev/phpbash.php`.

- **Command Execution Without Sanitization**: The web shell executes arbitrary commands via system calls, with no input validation, enabling code injection.
  **Fix**: Source code fix - Modify the PHP code to sanitize inputs using functions like `escapeshellarg()` or `escapeshellcmd()` before passing to `shell_exec()` or similar.

- **Appended Redirects Breaking Reverse Shells**: The web shell code appends redirects (e.g., `2>&1`) that interfere with establishing persistent reverse shells.
  **Fix**: Source code fix - Refactor the command execution logic in the PHP script to avoid unnecessary redirects or allow optional raw execution modes.

- **Lack of Tab Completion and History**: The web shell lacks features like tab completion, making it less user-friendly but also indicating incomplete implementation that could lead to misuse.
  **Fix**: Source code fix - Enhance the PHP code to support better input handling, though this is more of a usability gap; for security, focus on restricting access as above.

- **Non-Persistent Shell Sessions**: Each command spawns a new shell, preventing stateful operations like user switching without re-authentication.
  **Fix**: Source code fix - Implement session management in PHP to maintain shell state across requests, using serialized session data or a backend process.

### Uploads Directory (/uploads)

- **Writable by Web User Without Restrictions**: The /uploads directory is writable by www-data, allowing file uploads and execution of malicious scripts (e.g., PHP reverse shells).
  **Fix**: Configuration fix - Change directory permissions to restrict write access, e.g., `chown root:root /var/www/html/uploads && chmod 755 /var/www/html/uploads`, or disable PHP execution in the directory via Apache config with `<Directory /var/www/html/uploads> php_flag engine off </Directory>`.

- **No File Type Validation or Scanning**: Uploaded files are not checked for malicious content, enabling execution of webshells.
  **Fix**: Source code fix - If there's an upload handler script (e.g., send_mail.php or implied), add server-side validation in PHP to restrict file types (e.g., using `mime_content_type()`) and scan for malware.

### Sudo Configuration

- **Passwordless Sudo for www-data as scriptmanager**: The www-data user can run any command as scriptmanager without a password, facilitating privilege escalation.
  **Fix**: Configuration fix - Edit /etc/sudoers to remove or restrict this entry, e.g., delete the line `www-data ALL=(scriptmanager) NOPASSWD: ALL` or limit it to specific commands like `www-data ALL=(scriptmanager) NOPASSWD: /usr/bin/ls`.

### Scripts Directory (/scripts)

- **Writable by Non-Root User**: The /scripts directory is owned by scriptmanager, allowing modification of files executed by root.
  **Fix**: Configuration fix - Change ownership and permissions to root-only, e.g., `chown -R root:root /scripts && chmod -R 755 /scripts`, preventing non-root users from writing files.

### Cron Jobs

- **Root Cron Job Executing User-Writable Scripts**: A root-owned cron job runs all *.py files in /scripts every minute, without validation, leading to root code execution if modified.
  **Fix**: Configuration fix - Edit the root crontab (`crontab -e` as root) to specify exact scripts instead of wildcards (e.g., `/usr/bin/python /scripts/specific_script.py`), or move the directory to a root-only writable location.

- **Overwriting Files in Write Mode**: The test.py script overwrites test.txt (owned by root) without append, but this exposes a pattern for exploitation.
  **Fix**: Source code fix - Modify test.py to use append mode ('a') instead of write ('w') if needed, but primarily secure the cron job as above to prevent unauthorized modifications.

### General System-Level Gaps

- **Outdated Ubuntu Version (Xenial 16.04)**: The OS is end-of-life (EOL since April 2021), lacking security updates and potentially vulnerable to unpatched exploits.
  **Fix**: Configuration fix - Upgrade the OS to a supported LTS version, e.g., Ubuntu 22.04, via `do-release-upgrade`.

- **No Kernel Privilege Escalation Protections Checked**: While LinEnum.sh showed no immediate kernel exploits, the system lacks modern mitigations (e.g., AppArmor, SELinux).
  **Fix**: Configuration fix - Enable and configure AppArmor or SELinux profiles for services like Apache, e.g., `aa-enforce /etc/apparmor.d/usr.sbin.apache2`.

- **Missing Firewall or Network Restrictions**: Port 80 is open without apparent restrictions, allowing unrestricted access.
  **Fix**: Configuration fix - Implement UFW or iptables rules to restrict access, e.g., `ufw allow from <trusted_IP> to any port 80` or block unnecessary ports.

## Conclusion

Bashed is an excellent beginner-friendly machine that demonstrates fundamental web application security issues and basic Linux privilege escalation techniques. It requires understanding of:

- Web enumeration and directory discovery techniques
- PHP web shell identification and exploitation
- Linux privilege escalation through sudo misconfigurations
- Cron job exploitation for root access
- File permission analysis and manipulation
- Basic reverse shell techniques and persistence

This machine serves as an ideal introduction to HTB and OSCP preparation, covering essential penetration testing skills in a straightforward exploitation chain.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*