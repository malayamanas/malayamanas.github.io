---
title: "Brainfuck HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T12:00:00Z
tags: ["insane-linux", "nmap", "ssl-certificate", "wordpress", "wpscan", "plugin-exploit", "smtp", "imap", "vigenere-cipher", "rsa-cryptography", "ssh-keys", "john-the-ripper", "cryptanalysis", "privilege-escalation", "mail-enumeration"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Brainfuck HTB machine featuring WordPress plugin exploitation, SMTP credential extraction, Vigenère cipher cryptanalysis, RSA key cracking, and advanced cryptographic attacks"
---

# Brainfuck HTB - Insane Linux Box Walkthrough

{{< youtube o5x1yg3JnYI >}}

## Key Exploitation Steps and Techniques

Below is a chronological extraction of the key exploitation steps and techniques used in the provided data for the "Brainfuck" machine from Hack The Box, as described in the transcript. The steps are organized in the order they were performed, focusing on the critical actions and techniques that led to the successful compromise of the system.

### Key Exploitation Steps and Techniques (Chronological Order)

### 1. Initial Reconnaissance with Nmap
- **Technique**: Network scanning and service enumeration
- **Step**: Performed an Nmap scan with safe scripts and version enumeration (`nmap -sC -sV -oA nmap [TARGET-IP]`) to identify open ports and services.
- **Findings**: Identified open ports for SSH (22), SMTP (25), POP3 (110), IMAP (143), and HTTPS (443). Notably, no HTTP (port 80) was present, which is unusual for Hack The Box machines.
- **Purpose**: Established the attack surface, noting mail-related protocols (SMTP, POP3, IMAP) and HTTPS as potential entry points.

### 2. SSL Certificate Analysis
- **Technique**: SSL certificate enumeration
- **Step**: Inspected the SSL certificate for the HTTPS service to gather additional information.
- **Findings**: Discovered the common name `brainfuck.htb`, alternative names `www.brainfuck.htb` and `supersecret.brainfuck.htb`, and an issuer email `orestis@brainfuck.htb`.
- **Purpose**: Identified potential virtual hosts and a valid email address for further exploitation (e.g., brute-forcing or mail-related attacks). Added these domains to the `/etc/hosts` file for resolution.

### 3. Web Enumeration and WordPress Discovery
- **Technique**: Web enumeration and application identification
- **Step**: Accessed `https://brainfuck.htb`, which displayed a blank Nginx page, and checked for `robots.txt` (not found). Navigated to `supersecret.brainfuck.htb` and identified a WordPress site with a custom form and an "open ticket" feature.
- **Purpose**: Confirmed the presence of a WordPress installation, a common target for vulnerabilities, and noted the ticketing system as a potential attack vector.

### 4. WordPress Enumeration with WPScan
- **Technique**: Automated WordPress vulnerability scanning
- **Step**: Ran WPScan (`wpscan --url https://brainfuck.htb --disable-tls-checks -e u`) to enumerate WordPress users and vulnerabilities.
- **Findings**: Identified two users (`admin` and `administrator`) and a plugin vulnerability in the "Support Plus Responsive Ticketing System" (authenticated SQL injection, but required credentials).
- **Purpose**: Gathered user accounts for potential exploitation and identified a plugin vulnerability, though it was initially unusable due to lack of credentials.

### 5. Exploitation of WordPress Plugin Vulnerability
- **Technique**: Unauthenticated privilege escalation via plugin exploit
- **Step**: Researched the "Support Plus Responsive Ticketing System" plugin using `searchsploit` and found an unauthenticated privilege escalation vulnerability (Exploit-DB ID: 40939). The exploit involved crafting an HTML form to manipulate `admin-ajax.php` to set admin cookies without authentication.
- **Execution**: Modified the exploit HTML to target `https://brainfuck.htb/wp-admin/admin-ajax.php`, set the username to `admin`, and hosted it locally using `python -m http.server`. Accessed the exploit via a browser, which set valid admin cookies, granting access to the WordPress admin panel.
- **Purpose**: Gained unauthorized administrative access to the WordPress site.

### 6. Attempted Code Execution via WordPress Theme Editor
- **Technique**: Attempted PHP code injection
- **Step**: Navigated to the WordPress theme editor to modify PHP files for code execution but found that files were not writable by the WordPress user.
- **Purpose**: Explored direct shell access through file modification, but this approach failed due to permissions.

### 7. SMTP Credential Extraction from WordPress
- **Technique**: Credential harvesting from configuration
- **Step**: In the WordPress admin panel, accessed the "Easy WP SMTP" settings, found the username `orestis`, and extracted the SMTP password by inspecting the HTML input field using browser developer tools (F12).
- **Purpose**: Obtained SMTP credentials (`orestis` and password) for further mail-related exploitation.

### 8. Email Client Configuration and Credential Discovery
- **Technique**: Email access via IMAP
- **Step**: Configured an email client (Evolution) with the SMTP credentials (`orestis@brainfuck.htb`, IMAP port 143) to access the mailbox. Found an email containing credentials for the "supersecret" form.
- **Findings**: Retrieved credentials (`orestis` and a new password) for the supersecret form.
- **Purpose**: Gained access to additional system components by leveraging email credentials.

### 9. Accessing the Supersecret Form
- **Technique**: Credential-based authentication
- **Step**: Logged into `supersecret.brainfuck.htb` using the credentials from the email (`orestis` and password).
- **Findings**: Accessed a forum with posts, including one indicating SSH access was upgraded to key-based authentication (password logins disabled) and another with encrypted content.
- **Purpose**: Gained access to a restricted area of the application, revealing new attack vectors.

### 10. Cryptographic Analysis of Forum Post
- **Technique**: Known plaintext attack on a Vigenère cipher
- **Step**: Analyzed an encrypted forum post signed with `orestis hacking for fun and profit`. Recognized the signature as a known plaintext, suggesting a Vigenère cipher (mistakenly referred to as a one-time pad). Used the known plaintext to derive the cipher key.
- **Execution**: Manually calculated character shifts (e.g., `o` to `p` as a shift of 1) and used an online tool (Rumkin's Vigenère cipher tool) with the key `mybrain` to decrypt the post, revealing a URL to an encrypted RSA key file (`id_rsa`).
- **Purpose**: Decrypted sensitive content to obtain an SSH private key.

### 11. Downloading and Decrypting the RSA Key
- **Technique**: Password cracking with John the Ripper
- **Step**: Downloaded the encrypted `id_rsa` file and used `ssh2john` to convert it into a format compatible with John the Ripper. Ran John with a wordlist (`rockyou.txt`) to crack the passphrase, revealing `3poulakia`.
- **Purpose**: Obtained the passphrase to decrypt the SSH private key for user `orestis`.

### 12. SSH Access as User
- **Technique**: SSH authentication with private key
- **Step**: Used the decrypted `id_rsa` file (`chmod 600 id_rsa`) and passphrase `3poulakia` to log into the server via SSH as `orestis@brainfuck.htb`.
- **Findings**: Accessed user-level files, including `user.txt`, `debug.txt`, `encrypt.sage`, and `output.txt`.
- **Purpose**: Gained user-level access to the system, allowing further enumeration.

### 13. Analysis of Encryption Script
- **Technique**: Code analysis and RSA key reconstruction
- **Step**: Examined `encrypt.sage`, a SageMath script that encrypted `root.txt` into `output.txt` using RSA. Found `debug.txt` containing RSA parameters `p`, `q`, and `e`.
- **Purpose**: Identified the components needed for an RSA decryption attack.

### 14. RSA Decryption with Known Parameters
- **Technique**: RSA decryption using known `p`, `q`, and `e`
- **Step**: Used a Python script from a Stack Exchange post to compute the private key `d` from `p`, `q`, and `e`, and decrypted the ciphertext from `output.txt`. Converted the resulting plaintext (a large integer) to hex, then to ASCII, to reveal the contents of `root.txt`.
- **Purpose**: Successfully decrypted the root flag, achieving full system compromise.

### Summary of Techniques
- **Enumeration**: Nmap scanning, SSL certificate analysis, WPScan for WordPress, and email client enumeration.
- **Exploitation**: Unauthenticated WordPress plugin exploit for admin access, credential harvesting from SMTP settings and email.
- **Cryptography**: Known plaintext attack on a Vigenère cipher, RSA key cracking with John the Ripper, and RSA decryption using known parameters.
- **Access**: SSH login with a decrypted private key.

This sequence reflects the logical progression of reconnaissance, exploitation, and privilege escalation, leveraging vulnerabilities in web applications, mail services, and cryptographic implementations to achieve full system access.

## Security Gaps and Remediation

Based on the provided transcript of the "Brainfuck" machine exploitation, several vulnerabilities and misconfigurations in services and systems were exploited to gain unauthorized access. Below is a list of the identified gaps in each service or system, along with recommended fixes, categorized by whether they require a source code fix or a configuration fix. The fixes aim to address the vulnerabilities and prevent similar attacks.

### 1. Service: HTTPS (Web Server with WordPress)
**Gap**: Unauthenticated Privilege Escalation in WordPress Plugin
- **Description**: The "Support Plus Responsive Ticketing System" plugin had a vulnerability (Exploit-DB ID: 40939) allowing unauthenticated access to `admin-ajax.php`, enabling attackers to set admin cookies and gain administrative access to the WordPress site.
- **Fix Type**: Source Code Fix
  - **Recommended Fix**: Update the plugin to a patched version where the authentication logic for `admin-ajax.php` is corrected to prevent unauthorized cookie setting. Ensure the plugin properly validates user authentication before processing requests. If no patch is available, remove the vulnerable plugin and replace it with a secure alternative.
  - **Additional Notes**: Regularly update all WordPress plugins and core to mitigate known vulnerabilities. Implement a Web Application Firewall (WAF) to filter malicious requests to `admin-ajax.php`.

**Gap**: Insecure File Permissions in WordPress Theme Editor
- **Description**: The WordPress theme editor was accessible to admins, but file permissions prevented direct code execution. However, the presence of the editor still poses a risk if permissions are misconfigured in the future.
- **Fix Type**: Configuration Fix
  - **Recommended Fix**: Disable the WordPress theme and plugin editor by adding `define('DISALLOW_FILE_EDIT', true);` to the `wp-config.php` file. Additionally, ensure the web server user (e.g., `www-data`) has read-only access to WordPress files and directories (`chmod -R 644 /path/to/wordpress` for files, `755` for directories).
  - **Additional Notes**: Use the principle of least privilege for file permissions to prevent unauthorized modifications.

**Gap**: Exposure of Sensitive Information in SSL Certificate
- **Description**: The SSL certificate exposed the email address `orestis@brainfuck.htb` and alternative domain names (`www.brainfuck.htb`, `supersecret.brainfuck.htb`), which aided in enumeration and targeting.
- **Fix Type**: Configuration Fix
  - **Recommended Fix**: Minimize information in SSL certificates by using generic or non-sensitive values for fields like email and common name. For example, use a generic email like `admin@domain.com` instead of a specific user's email. Ensure Subject Alternative Names (SANs) only include necessary domains to reduce exposure.
  - **Additional Notes**: Use tools like `openssl` to review certificate details before deployment and avoid including sensitive data.

### 2. Service: SMTP (Easy WP SMTP Plugin)
**Gap**: Exposure of SMTP Credentials in WordPress Admin Panel
- **Description**: The Easy WP SMTP plugin stored credentials in plain text, viewable in the WordPress admin panel via HTML inspection, allowing attackers to extract the username `orestis` and password.
- **Fix Type**: Source Code Fix
  - **Recommended Fix**: Modify the plugin to securely handle credentials, such as encrypting them in the database and only decrypting them when needed. Avoid rendering sensitive fields like passwords in plain text in the admin interface. Use secure input fields (e.g., `type="password"`) that do not expose values via HTML inspection.
  - **Additional Notes**: Consider using a secrets management solution (e.g., environment variables or a vault) to store sensitive credentials outside the application.

**Gap**: Weak SMTP Authentication
- **Description**: The SMTP service allowed access to the `orestis@brainfuck.htb` mailbox using credentials exposed in the WordPress admin panel, indicating weak authentication or lack of additional security measures.
- **Fix Type**: Configuration Fix
  - **Recommended Fix**: Enforce strong, unique passwords for SMTP accounts and implement multi-factor authentication (MFA) if supported by the mail server (e.g., Postfix or Dovecot). Restrict SMTP access to trusted IP ranges using firewall rules or server configuration (e.g., `smtpd_client_restrictions` in Postfix).
  - **Additional Notes**: Regularly rotate SMTP credentials and audit mail server logs for unauthorized access attempts.

### 3. Service: IMAP
**Gap**: Exposure of Sensitive Data in Emails
- **Description**: The IMAP service allowed access to an email containing credentials for the supersecret form, indicating poor data handling practices (e.g., sending sensitive information via email).
- **Fix Type**: Configuration Fix
  - **Recommended Fix**: Avoid sending sensitive information like credentials in plain text emails. Instead, use secure methods like encrypted file transfers or temporary, expiring links for credential distribution. Configure the application to avoid storing sensitive data in emails accessible via IMAP.
  - **Additional Notes**: Implement email encryption (e.g., S/MIME or PGP) for sensitive communications and enforce strict access controls on mailboxes.

**Gap**: Weak IMAP Authentication
- **Description**: The IMAP service allowed access with the SMTP credentials, suggesting shared or weak credentials across services.
- **Fix Type**: Configuration Fix
  - **Recommended Fix**: Use separate credentials for IMAP and SMTP services to prevent credential reuse vulnerabilities. Enforce strong passwords and consider implementing MFA for IMAP access. Restrict IMAP access to specific IP ranges using firewall rules or server settings (e.g., `dovecot.conf` access controls).
  - **Additional Notes**: Monitor IMAP authentication logs for suspicious activity and ensure the mail server is hardened against brute-force attacks.

### 4. Service: Supersecret Forum (Web Application)
**Gap**: Weak Authentication in Supersecret Forum
- **Description**: The supersecret forum relied on a simple username/password combination, with credentials exposed in an email, making it vulnerable to unauthorized access once credentials were obtained.
- **Fix Type**: Source Code Fix
  - **Recommended Fix**: Implement robust authentication mechanisms, such as MFA or OAuth-based login, for the supersecret forum. Ensure credentials are not stored or transmitted in plain text (e.g., via email). Use secure session management with strong, unique session tokens.
  - **Additional Notes**: Regularly audit user accounts and implement account lockout mechanisms to prevent brute-force attacks.

**Gap**: Insecure Storage of Encrypted Data
- **Description**: The forum contained an encrypted post using a Vigenère cipher with a weak key (`mybrain`), which was vulnerable to a known plaintext attack due to the predictable signature `orestis hacking for fun and profit`.
- **Fix Type**: Source Code Fix
  - **Recommended Fix**: Replace the Vigenère cipher with a modern, secure encryption algorithm (e.g., AES-256) with a randomly generated, strong key. Avoid using predictable or static keys. If encryption is needed, use a cryptographically secure library and ensure keys are managed securely (e.g., using a key management system).
  - **Additional Notes**: Avoid embedding predictable patterns (e.g., signatures) in encrypted data, as they enable known plaintext attacks. Conduct regular security reviews of cryptographic implementations.

**Gap**: Exposure of SSH Private Key in Forum
- **Description**: The forum provided a URL to download an encrypted SSH private key (`id_rsa`), which was a critical security risk, even if encrypted.
- **Fix Type**: Configuration Fix
  - **Recommended Fix**: Do not store or provide access to SSH private keys via a web application. Instead, distribute keys securely through out-of-band channels (e.g., secure file transfer protocols or hardware tokens). If keys must be shared, ensure they are strongly encrypted and access is restricted to authorized users only.
  - **Additional Notes**: Implement strict access controls on sensitive resources and audit web application content for unintended exposure of critical assets.

### 5. Service: SSH
**Gap**: Weak Passphrase for Encrypted SSH Private Key
- **Description**: The SSH private key (`id_rsa`) was encrypted with a weak passphrase (`3poulakia`), which was quickly cracked using John the Ripper with the `rockyou.txt` wordlist.
- **Fix Type**: Configuration Fix
  - **Recommended Fix**: Enforce strong, complex passphrases for SSH private keys (e.g., minimum 20 characters with mixed case, numbers, and symbols). Educate users on secure passphrase practices and consider using key management tools to generate and store keys securely.
  - **Additional Notes**: Use SSH key management solutions (e.g., HashiCorp Vault) to securely distribute and manage keys, reducing the risk of weak passphrases.

**Gap**: Lack of SSH Hardening
- **Description**: The SSH service allowed key-based authentication without additional restrictions, making it vulnerable once the private key was compromised.
- **Fix Type**: Configuration Fix
  - **Recommended Fix**: Harden the SSH configuration by editing `/etc/ssh/sshd_config`:
    - Disable password-based authentication (`PasswordAuthentication no`).
    - Restrict SSH access to specific users (`AllowUsers orestis`).
    - Use strong ciphers and algorithms (e.g., `Ciphers aes256-ctr`).
    - Implement rate-limiting or IP whitelisting using tools like `fail2ban` or firewall rules.
  - **Additional Notes**: Regularly rotate SSH keys and monitor SSH logs for unauthorized access attempts.

### 6. System: Encryption Script (SageMath)
**Gap**: Weak RSA Implementation
- **Description**: The `encrypt.sage` script used RSA with a small private key (`d`) due to a large public exponent (`e`), making it vulnerable to attacks like Wiener's attack. The script also output sensitive RSA parameters (`p`, `q`, `e`) to `debug.txt`, enabling easy decryption.
- **Fix Type**: Source Code Fix
  - **Recommended Fix**: Use a standard RSA library (e.g., OpenSSL or PyCryptodome) with secure parameters:
    - Use a standard public exponent (e.g., `e=65537`).
    - Ensure the private key `d` is sufficiently large by using appropriately sized prime numbers (`p` and `q`).
    - Avoid outputting sensitive cryptographic parameters to files. If debugging is needed, use secure logging mechanisms with restricted access.
  - **Additional Notes**: Follow cryptographic best practices, such as using established libraries and undergoing security audits for custom cryptographic implementations.

**Gap**: Exposure of Sensitive Cryptographic Parameters
- **Description**: The `debug.txt` file contained RSA parameters (`p`, `q`, `e`), which allowed attackers to reconstruct the private key and decrypt the ciphertext.
- **Fix Type**: Configuration Fix
  - **Recommended Fix**: Remove or secure debug output files. Ensure sensitive files like `debug.txt` are not readable by the web server user or other low-privilege accounts (`chmod 600 debug.txt`, `chown root:root debug.txt`). Ideally, disable debug output in production environments.
  - **Additional Notes**: Implement file system monitoring to detect and alert on unauthorized access to sensitive files.

### Summary of Fixes by Service/System
| **Service/System** | **Gap** | **Fix Type** | **Summary of Fix** |
|---------------------|---------|--------------|--------------------|
| HTTPS (WordPress)  | Unauthenticated plugin vulnerability | Source Code | Update plugin to patch `admin-ajax.php` vulnerability. |
| HTTPS (WordPress)  | Insecure theme editor access | Configuration | Disable file editing in `wp-config.php` and restrict file permissions. |
| HTTPS (SSL)        | Sensitive info in SSL certificate | Configuration | Use generic values in certificate fields, minimize SANs. |
| SMTP               | Plain text credential exposure | Source Code | Encrypt credentials, avoid plain text in HTML. |
| SMTP               | Weak authentication | Configuration | Enforce strong passwords, MFA, and IP restrictions. |
| IMAP               | Sensitive data in emails | Configuration | Avoid sending credentials in emails, use encryption. |
| IMAP               | Weak authentication | Configuration | Use separate credentials, enforce MFA, restrict IPs. |
| Supersecret Forum  | Weak authentication | Source Code | Implement MFA, secure session management. |
| Supersecret Forum  | Weak Vigenère cipher | Source Code | Use modern encryption (e.g., AES-256) with strong keys. |
| Supersecret Forum  | SSH key exposure | Configuration | Avoid storing keys in web apps, use secure distribution. |
| SSH                | Weak key passphrase | Configuration | Enforce strong passphrases, use key management tools. |
| SSH                | Unhardened SSH service | Configuration | Disable password auth, restrict users, use strong ciphers. |
| Encryption Script  | Weak RSA implementation | Source Code | Use standard RSA libraries with secure parameters. |
| Encryption Script  | Exposed RSA parameters | Configuration | Secure or remove debug files, restrict access. |

### General Recommendations
- **Patch Management**: Regularly update all software (WordPress, plugins, mail servers, SSH) to address known vulnerabilities.
- **Least Privilege**: Apply strict permissions for files, directories, and services to minimize the impact of compromised credentials.
- **Monitoring and Logging**: Enable logging for all services (web, mail, SSH) and monitor for suspicious activity.
- **Security Awareness**: Train administrators to avoid weak passwords, predictable keys, and insecure practices like sending credentials via email.
- **Penetration Testing**: Conduct regular security assessments to identify and fix vulnerabilities before they are exploited.

These fixes address the specific gaps exploited in the "Brainfuck" machine and align with best practices to secure similar systems against common attack vectors.

## Conclusion

Brainfuck is an excellent machine that demonstrates the complexity of cryptographic attacks and multi-service exploitation. It requires expertise in:
- WordPress security assessment and plugin vulnerability exploitation
- Mail server enumeration and credential extraction techniques
- Classical cryptography and cryptanalysis (Vigenère cipher attacks)
- RSA cryptographic implementation weaknesses and mathematical attacks
- SSH key management and password cracking methodologies
- Multi-layered privilege escalation through interconnected services
- Advanced penetration testing across web, mail, and cryptographic systems

The machine emphasizes the importance of secure cryptographic implementations, proper credential management, and comprehensive security across interconnected services in preventing sophisticated attack chains.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*