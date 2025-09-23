---
title: "Laser HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T07:45:00Z
tags: ["insane-linux", "printer-exploitation", "grpc", "ssrf", "solr", "protocol-smuggling", "docker", "privilege-escalation", "aes-decryption", "gopher"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Laser HTB machine featuring printer exploitation via PRET toolkit, gRPC SSRF vulnerability, protocol smuggling with Gopher, Apache Solr exploitation, and Docker container privilege escalation"
---

# Laser HTB - Insane Linux Box Walkthrough

{{< youtube vD3jSJlc0ro >}}

## Exploitation Steps

1. **Initial Reconnaissance with Nmap**: Perform an Nmap scan to identify open ports: 22 (SSH), 9000 (unknown service, possibly HTTP/2-based), and 9100 (JetDirect printer port). Technique: Port scanning and service enumeration.

2. **Printer Interaction with PRET Toolkit**: Use the Printer Exploitation Toolkit (PRET) to connect to port 9100 via PJL mode. List directories and dump a queued print job from /pjl/jobs, resulting in Base64-encoded encrypted data. Technique: Printer protocol exploitation for data dumping.

3. **NVRAM Dump for Encryption Key**: Use PRET to dump the printer's NVRAM (non-volatile memory) and extract an AES key (16 bytes after trimming). Identify encryption mode as AES-CBC from printer info. Technique: Memory dumping to retrieve cryptographic keys.

4. **Decrypt Print Job**: Trim the dumped job file to remove size header and IV (initialization vector), then decrypt using AES-CBC with the extracted key and IV in CyberChef. The decrypted file is a PDF describing the gRPC API on port 9000. Technique: Cryptographic decryption of captured data.

5. **gRPC API Analysis and Client Setup**: Based on the PDF, define a Protocol Buffer (protobuf) schema for the "Print" service with RPC method "Feed". Generate Python stubs using grpcio-tools. Create a Python script to connect to port 9000 and send payloads. Technique: Reverse engineering API from documentation and building a custom client.

6. **Attempt Deserialization Attacks**: Try sending pickled payloads for RCE (remote code execution), but fail due to restrictions on unpickling built-ins. Switch to JSON payloads. Technique: Deserialization vulnerability testing (e.g., Python pickle exploits).

7. **Discover SSRF Vulnerability**: Modify the "feed_url" in the JSON payload to point to external or internal resources (e.g., attacker's IP, localhost ports). Confirm SSRF by observing requests to the attacker's server. Technique: Server-Side Request Forgery (SSRF) via URL parameter manipulation.

8. **Internal Port Scanning via SSRF**: Use SSRF to scan localhost ports by crafting "feed_url" as "http://localhost:`<port>`". Identify open port 8983 (Apache Solr). Technique: Blind internal port scanning through SSRF.

9. **Protocol Smuggling with Gopher for POST Requests**: Since SSRF only allows GET requests, use Gopher protocol in "feed_url" (e.g., "gopher://localhost:8983/`<raw HTTP POST>`") to smuggle POST requests to Solr on localhost:8983. Technique: Protocol smuggling (Gopher) to bypass HTTP method restrictions in SSRF.

10. **Exploit Apache Solr**: Smuggle a POST to configure Solr's "staging" core for vulnerability (update config). Then smuggle another request to execute a command (e.g., curl to attacker's server). Gain initial shell as "solr" user. Technique: CVE or misconfiguration exploit in Solr via smuggled requests (arbitrary command execution).

11. **Privilege Escalation Enumeration**: As "solr" user, observe processes with "ps aux". Identify a root-run script (/opt/updates/run.sh) using "sshpass" to SSH to 172.18.0.2 every 10 seconds with a password. Technique: Process monitoring for privilege escalation vectors.

12. **Capture SSH Password with pspy**: Use pspy64s (process snooper) to capture the password in memory before sshpass overwrites it with zeros (timing race condition). Password revealed as used in "sshpass -p `<password>` ...". Technique: Race condition exploitation in process argument hiding.

13. **SSH to Internal Container**: Use the captured password to SSH as root to 172.18.0.2 (a Docker container). Technique: Credential reuse for lateral movement.

14. **SSH Redirection with Socat**: In the container, download and run Socat to redirect port 22 traffic back to the main host's port 22 (tcp-listen:22,fork,reuseaddr tcp:172.18.0.1:22). Poison the update script by replacing the transferred file with a reverse shell payload. Technique: Port redirection and script hijacking for command injection.

15. **Gain Root Shell**: The poisoned script executes on the main host, providing a root reverse shell. Stabilize with SSH key for persistent access. Technique: Reverse shell deployment via hijacked update mechanism.

## Security Gaps and Remediation

Below is a list of identified gaps in the services and systems exploited in the "Laser" machine from Hack The Box, as described in the provided data, along with recommended fixes categorized by proper source code or configuration changes. Each gap corresponds to a vulnerability or misconfiguration that allowed the exploitation to progress, and the fixes aim to mitigate these issues.

### 1. Printer Service (Port 9100, JetDirect)
**Gap**: The printer exposes sensitive data (queued print jobs and NVRAM) via the PJL protocol, allowing attackers to dump encrypted print jobs and extract AES keys from NVRAM.

- **Fix Type**: Configuration Fix
  - **Solution**:
    - Disable or restrict access to the PJL (Printer Job Language) interface on port 9100 unless explicitly required. Configure the printer to only allow trusted IP addresses or networks via firewall rules or printer access control lists (ACLs).
    - Disable NVRAM dumping functionality or limit it to authenticated administrative users. Ensure sensitive data like AES keys are not stored in easily accessible memory.
    - Use strong, unique encryption keys and rotate them regularly. Store keys securely (e.g., in a hardware security module) rather than in NVRAM.
  - **Impact**: Prevents unauthorized access to print jobs and cryptographic keys, blocking the initial data extraction step.

- **Fix Type**: Source Code Fix
  - **Solution**:
    - Modify the printer firmware to encrypt or obfuscate sensitive NVRAM data, ensuring AES keys are not stored in plaintext or easily extractable formats.
    - Implement authentication checks in the PJL protocol handler to restrict access to sensitive commands like job dumping or NVRAM access.
  - **Impact**: Adds a layer of security to the printer's firmware, making it harder for attackers to extract sensitive data even if they gain network access to port 9100.

### 2. gRPC API Service (Port 9000)
**Gap**: The gRPC API is vulnerable to Server-Side Request Forgery (SSRF), allowing attackers to manipulate the `feed_url` parameter to make requests to internal or external resources, including localhost services.

- **Fix Type**: Source Code Fix
  - **Solution**:
    - Implement strict input validation for the `feed_url` parameter in the gRPC service code. Use an allowlist of permitted domains or IPs, explicitly excluding localhost (127.0.0.1, ::1) and internal network ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    - Sanitize and validate URLs to prevent protocol smuggling (e.g., `gopher://`, `file://`). Restrict supported protocols to HTTP/HTTPS only.
    - Use a secure URL parsing library to handle `feed_url` and reject malformed or unexpected inputs.
  - **Impact**: Eliminates SSRF by ensuring the API cannot make requests to unauthorized or internal endpoints.

- **Fix Type**: Configuration Fix
  - **Solution**:
    - Configure a Web Application Firewall (WAF) or network firewall to block outgoing requests from the gRPC service to localhost or internal IPs.
    - Disable unnecessary outbound network access from the server hosting the gRPC service, limiting it to only required external services.
  - **Impact**: Reduces the attack surface by preventing the service from accessing internal resources, even if SSRF is attempted.

**Gap**: The gRPC service accepts arbitrary JSON payloads without sufficient validation, allowing protocol smuggling via Gopher to craft POST requests.

- **Fix Type**: Source Code Fix
  - **Solution**:
    - Add strict JSON schema validation for payloads, ensuring only expected fields (e.g., `feed_url`) and data types are accepted.
    - Reject payloads containing unexpected or malicious protocols (e.g., `gopher://`) by validating the protocol scheme in `feed_url`.
    - Implement rate limiting or payload size restrictions to prevent abuse of the API for smuggling large or complex requests.
  - **Impact**: Prevents protocol smuggling and ensures only legitimate payloads are processed, blocking the ability to craft malicious POST requests.

### 3. Apache Solr Service (Port 8983, Localhost)
**Gap**: Apache Solr on localhost:8983 is accessible via SSRF and has a misconfiguration or vulnerability allowing remote configuration changes and command execution (likely CVE-2017-12629 or similar).

- **Fix Type**: Configuration Fix
  - **Solution**:
    - Bind Solr to a specific interface (e.g., 127.0.0.1) and ensure it is not exposed externally. Verify that firewall rules (e.g., iptables, ufw) block external access to port 8983.
    - Disable or restrict Solr's admin endpoints (`/solr/admin/cores`, `/solr/staging/config`) to require authentication. Configure Solr to use strong authentication (e.g., Basic Auth or OAuth) and role-based access control.
    - Update Solr to the latest version to patch known vulnerabilities (e.g., CVE-2017-12629, which allows RCE via RUNNABLE listeners in older versions).
    - Disable unnecessary Solr cores (e.g., `staging`) or ensure they are not writable without authentication.
  - **Impact**: Prevents unauthorized access to Solr via SSRF and mitigates known vulnerabilities, blocking configuration changes and RCE.

- **Fix Type**: Source Code Fix
  - **Solution**:
    - If custom Solr plugins or configurations are used, audit and secure the code to prevent unauthorized modifications (e.g., reject unauthenticated config updates).
    - Implement input validation in Solr's request handlers to reject malformed or unexpected POST requests, especially those targeting sensitive endpoints like `/config` or `/select`.
  - **Impact**: Hardens Solr against exploits by ensuring only authorized and validated requests are processed.

### 4. SSH Service and Update Script (Port 22, /opt/updates/run.sh)
**Gap**: The update script (`/opt/updates/run.sh`) runs as root, uses `sshpass` to SSH to an internal container (172.18.0.2) with a hardcoded password, and executes transferred files without validation.

- **Fix Type**: Source Code Fix
  - **Solution**:
    - Rewrite the update script to avoid hardcoded credentials. Use SSH key-based authentication with a dedicated, low-privilege service account instead of `sshpass`.
    - Implement file validation (e.g., checksums or digital signatures) to ensure only trusted files are executed. Reject unsigned or unverified files.
    - Limit the script's execution scope by running commands in a restricted environment (e.g., using `restrict` in SSH or a sandboxed interpreter).
  - **Impact**: Prevents credential leakage and ensures only authorized files are executed, blocking RCE via file replacement.

- **Fix Type**: Configuration Fix
  - **Solution**:
    - Configure SSH to disable password authentication (`PasswordAuthentication no` in `/etc/ssh/sshd_config`) and enforce key-based authentication.
    - Run the update script as a low-privilege user instead of root, using `sudo` with minimal permissions if root access is required.
    - Set up a cron job or systemd timer with proper permissions and environment isolation to run the script, reducing the attack surface.
    - Configure the Docker container (172.18.0.2) to reject unauthorized SSH connections and limit inbound traffic to trusted sources.
  - **Impact**: Reduces the risk of credential compromise and unauthorized command execution by securing SSH and script privileges.

**Gap**: The `sshpass` command exposes the password in process memory, vulnerable to a race condition exploit with tools like `pspy`.

- **Fix Type**: Source Code Fix
  - **Solution**:
    - Replace `sshpass` with a more secure method, such as SSH key-based authentication or a secrets management system (e.g., HashiCorp Vault) to handle credentials dynamically.
    - If `sshpass` is unavoidable, use environment variables or secure memory handling to avoid exposing credentials in the process's command-line arguments.
  - **Impact**: Eliminates password exposure in memory, preventing race condition attacks.

- **Fix Type**: Configuration Fix
  - **Solution**:
    - Use Linux kernel features like `hidepid` on `/proc` (e.g., mount `/proc` with `hidepid=2`) to restrict non-privileged users from viewing other processes' command-line arguments.
    - Configure the system to limit process visibility (e.g., via AppArmor or SELinux) to prevent tools like `pspy` from accessing sensitive process data.
  - **Impact**: Blocks unauthorized access to process memory, mitigating tools like `pspy` from capturing credentials.

### 5. Docker Container (172.18.0.2)
**Gap**: The internal Docker container allows root SSH access with a weak password and executes unverified files transferred via SCP.

- **Fix Type**: Configuration Fix
  - **Solution**:
    - Disable root SSH login in the container's SSH configuration (`PermitRootLogin no` in `/etc/ssh/sshd_config`) and use a non-root service account with key-based authentication.
    - Restrict SCP to specific directories with read-only access using SSH's `ChrootDirectory` or `ForceCommand` options.
    - Apply Docker security best practices: run containers with minimal privileges (e.g., `--user` for non-root), use read-only filesystems (`--read-only`), and isolate network access with strict Docker network policies.
  - **Impact**: Prevents unauthorized root access and ensures only trusted files are processed, blocking RCE via SCP.

- **Fix Type**: Source Code Fix
  - **Solution**:
    - If the container runs a custom application, validate all incoming files before execution (e.g., verify signatures or checksums).
    - Implement logging and monitoring to detect and alert on unauthorized SSH logins or file transfers.
  - **Impact**: Adds runtime checks to prevent malicious file execution and improves auditability.

### 6. General System Security
**Gap**: The system allows port redirection (via Socat) and SSH key installation by the `solr` user, indicating overly permissive user privileges or Docker configuration.

- **Fix Type**: Configuration Fix
  - **Solution**:
    - Restrict the `solr` user's permissions to prevent network socket operations (e.g., block `socat` execution via AppArmor/SELinux or file permissions).
    - Harden Docker container configurations to prevent privilege escalation (e.g., use `--cap-drop=ALL --cap-add=<minimal_caps>` to limit capabilities).
    - Remove write access to sensitive directories like `~/.ssh` for non-privileged users, and enforce strict file permissions (e.g., `chmod 600 ~/.ssh/authorized_keys`).
    - Implement network segmentation to prevent containers from accessing the host or other containers unnecessarily.
  - **Impact**: Limits the `solr` user's ability to manipulate network traffic or install persistent access mechanisms, reducing lateral movement risks.

### Summary of Fixes by Service/System
- **Printer (Port 9100)**: Secure PJL interface, encrypt NVRAM data, and restrict access.
- **gRPC API (Port 9000)**: Validate `feed_url`, restrict protocols, and limit outbound requests.
- **Apache Solr (Port 8983)**: Secure admin endpoints, update software, and restrict localhost access.
- **SSH and Update Script**: Remove hardcoded credentials, validate executed files, and secure process memory.
- **Docker Container**: Disable root SSH, restrict SCP, and harden container privileges.
- **General System**: Restrict user permissions, harden Docker, and enforce network segmentation.

These fixes address the vulnerabilities exploited in the attack chain, ensuring the system is more resilient to similar attacks. Each fix is tailored to either patch the application logic (source code) or adjust deployment settings (configuration) to close the identified gaps.

## Conclusion

Laser is an excellent machine that demonstrates the complexity of modern IoT and enterprise environments involving printers, APIs, and containerized services. It requires expertise in:
- Printer exploitation and protocol analysis (PRET toolkit)
- Cryptographic analysis and AES decryption techniques
- gRPC API reverse engineering and client development
- Server-Side Request Forgery (SSRF) and protocol smuggling
- Apache Solr exploitation and configuration vulnerabilities
- Docker container security and privilege escalation
- Process monitoring and race condition exploitation

The machine emphasizes the importance of securing IoT devices, implementing proper input validation in APIs, and maintaining strong isolation between containerized services.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*