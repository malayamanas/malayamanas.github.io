---
title: "Response HTB - Insane Linux Box Walkthrough"
date: 2024-03-15T10:00:00Z
tags: ["insane-linux", "web", "ldap", "proxy", "protocol-smuggling", "memory-forensics", "meterpreter", "ssh-reconstruction"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Response HTB machine featuring custom proxy exploitation, protocol smuggling, LDAP manipulation, memory forensics, and SSH key reconstruction"
---

# Response HTB - Insane Linux Box Walkthrough

{{< youtube -t1UAvTxB94 >}}

Response is an Insane difficulty Linux machine from Hack The Box that truly lives up to its rating. This box requires standing up multiple services (web, DNS, SMTP, LDAP) on your attack machine and involves complex multi-stage exploitation including custom proxy development, cross-protocol forgery attacks, memory forensics, and SSH key reconstruction.

## Key Exploitation Steps and Techniques (Chronological Order)

### Phase 1: Initial Recon and Web Proxy Bypass

#### 1. Port Scanning and Host Discovery
- Run Nmap to identify open ports: SSH (22) and HTTP (80) on Nginx
- Access the web page, identify redirects, and add virtual hosts to `/etc/hosts` (e.g., `response.htb`, `www.response.htb`, `proxy.response.htb`, `api.response.htb`, `chat.response.htb`)
- **Technique**: Basic reconnaissance with Nmap (`-sC -sV`); virtual host enumeration via source code and network inspection (Burp Suite/Developer Tools). Gobuster for directory enumeration confirms static site

#### 2. Bypass Proxy URL Digest Validation
- Analyze proxy requests to `proxy.response.htb/fetch`; discover URL digest is a SHA-256 HMAC signed using a secret derived from PHPSESSID cookie
- Manipulate PHPSESSID to include target URL (e.g., `http://chat.response.htb`), request a signed digest from the server, and reuse it to proxy arbitrary requests
- **Technique**: Session manipulation and signature oracle abuse; reverse-engineering JavaScript/PHP responses via Burp Repeater and base64 decoding

#### 3. Build Custom Proxy for Chat Access
- Develop a Python script using `requests` and `http.server` to act as a man-in-the-middle proxy, forwarding requests to `chat.response.htb` while replacing domains to bypass restrictions. Handle MIME types, string replacements, and GET/POST methods
- Download and analyze chat source code (`chat_source.zip`) to identify guest/guest creds and LDAP auth
- **Technique**: Custom scripting for proxying; content modification to evade CORS/JavaScript restrictions

### Phase 2: Phishing and Initial User Access (Bob)

#### 4. Spoof LDAP for Admin Access to Chat
- Intercept LDAP auth requests; spoof responses using Netcat (`nc`) with hardcoded successful bind hex bytes (e.g., `300c02010161070a010004000400`) to login as admin/admin
- Replace LDAP server in proxy script with attacker's IP
- **Technique**: Protocol spoofing/mitm on LDAP (port 389); inconsistent AI-generated responses required trial-and-error

#### 5. Phish Internal FTP Info via Chat
- As admin in chat, message user "Bob" and convince him to share internal FTP details ([INTERNAL-FTP-IP]:2121, ftpuser:secret12345)
- **Technique**: Social engineering/phishing in real-time chat application

#### 6. Cross-Protocol Forgery to Exfiltrate Creds
- Send Bob a link to malicious JavaScript (using XMLHttpRequest) that performs HTTP smuggling of FTP commands: logs in to internal FTP, uses PORT command to redirect data to attacker's IP/port, and retrieves `creds.txt`
- Monitor with Wireshark/Netcat for exfil
- **Technique**: Cross-protocol request forgery (HTTP to FTP smuggling); active mode FTP exploitation with packed port encoding; browser-based side-channel attack

#### 7. SSH as Bob
- Use exfiltrated creds from `creds.txt` (bob's SSH password) to SSH into the box
- **Technique**: Credential reuse from exfil

### Phase 3: Privilege Escalation to scryh

#### 8. Analyze and Manipulate scan.sh Script
- Examine `/home/scryh/scan/scan.sh`: script queries LDAP for IPs/emails, scans with Nmap (TLS-focused NSE scripts), generates PDF reports, and emails via SMTP (resolved via DNS MX)
- Add LDAP entry (using `ldapadd` with LDIFF file) to register attacker's IP as a "server" to scan
- **Technique**: Script analysis for misconfigurations; LDAP injection/modification using bind creds from script

#### 9. Stand Up Fake Infrastructure for Callback
- Create self-signed cert with OpenSSL; run HTTPS server (Python `http.server` with SSL)
- Run DNSMasq with custom config for MX records pointing to attacker's SMTP; use iptables for port redirection (53 -> 8053)
- Run SMTP debug server (Python `smtpd`)
- **Technique**: Infrastructure spoofing (web/DNS/SMTP) to receive callbacks; port redirection for compatibility

#### 10. Exploit LFI in Custom NSE Script
- Identify modified `ssl-cert.nse` script allows reading files via `stateOrProvinceName` in cert (concatenated to `/data/profits_name`)
- Set malicious state in cert (e.g., `../../../../home/scryh/.ssh/id_rsa`); server scans attacker's HTTPS, includes LFI output in emailed PDF report
- Extract leaked id_rsa from PDF
- **Technique**: Local File Inclusion (LFI) via custom Nmap NSE script abuse; path traversal in certificate fields

#### 11. SSH as scryh
- Use extracted id_rsa to SSH as scryh
- **Technique**: Key-based authentication with stolen private key

### Phase 4: Privilege Escalation to Root

#### 12. Analyze Incident Files
- Access `/home/scryh/incident/`; download pcap, core dump, and IR PDF
- Review PDF: describes meterpreter payload, encrypted stream, possible zip leak
- **Technique**: File exfiltration via Python HTTP server and wget

#### 13. Extract and Decrypt Meterpreter Stream
- Use Scapy to extract TCP stream (port 4444) from pcap into binary file
- Parse TLV packets: XOR key, session GUID, flags, length/type; decrypt AES-CBC portions using key from memory
- Use bulk_extractor on core dump to find AES keys via key expansion/entropy analysis
- Decrypt to extract leaked `docsbackup.zip`
- **Technique**: Packet parsing/decryption (custom Python script for Meterpreter TLV/AES); memory forensics with bulk_extractor

#### 14. Reconstruct Root SSH Key from Screenshot
- Unzip `docsbackup.zip`; find screenshot with partial base64 SSH key (bottom chunk containing prime q)
- Base64-decode partial key, align bytes, extract q (193 bits)
- Use public key from `/root/.ssh/authorized_keys`; reconstruct private key with RSA CTF Tool (`--q`, `--e`, `--private`)
- **Technique**: RSA key reconstruction from partial prime (using math/tools); OCR/manual transcription of image leak; padding/alignment for base64 decoding

#### 15. SSH as Root
- Use reconstructed key to SSH as root
- **Technique**: Key-based authentication with rebuilt private key

## Security Gaps and Remediation

This machine demonstrates multiple critical security vulnerabilities across different services:

### Web Proxy Service (proxy.response.htb)
- **Gap**: URL digest validation can be bypassed by setting PHPSESSID to include the target URL, allowing the server to sign arbitrary requests due to shared secret derivation from user-controlled session data
- **Fix**: Source code fix - Generate HMAC secrets server-side without relying on user input; implement proper validation to ensure sessions cannot control signing content

### Chat Application (chat.response.htb)
- **Gap**: Allows guest/guest login and uses LDAP authentication that can be spoofed by intercepting and responding with forged successful bind responses
- **Fix**: Configuration fix - Restrict LDAP connections to internal IPs only via firewall rules; Source code fix - Enhance authentication with multi-factor or certificate-based verification beyond alphanumeric checks
- **Gap**: JavaScript and resource loading lacks restrictions, enabling domain replacements and proxying
- **Fix**: Source code fix - Hardcode internal domains in JavaScript; Configuration fix - Implement Content-Security-Policy (CSP) headers to prevent unauthorized resource loading

### LDAP Service
- **Gap**: Plaintext credentials hardcoded in scripts (e.g., scan.sh), allowing unauthorized queries and additions via ldapadd
- **Fix**: Configuration fix - Store credentials in secure vaults or environment variables; Source code fix - Implement role-based access control (RBAC) to limit query/modification scopes
- **Gap**: No validation on added entries, enabling injection of malicious IPs or data
- **Fix**: Source code fix - Add input sanitization and schema enforcement for attributes like IPHostNumber

### Internal FTP Server
- **Gap**: Exposed to browser-based attacks via cross-protocol forgery, where HTTP requests smuggle FTP commands, bypassing network restrictions
- **Fix**: Configuration fix - Isolate FTP to internal network segments with firewall rules; Source code fix - (If custom client) Validate protocols in client-side scripts to prevent smuggling

### Scan Script/System (scan.sh and Nmap NSE Scripts)
- **Gap**: Trusts unvalidated LDAP data for scanning IPs, leading to external callbacks and report exfiltration
- **Fix**: Source code fix - Validate IPs against allowlists before scanning; Configuration fix - Run script in isolated environment with outbound restrictions
- **Gap**: Custom ssl-cert.nse script concatenates untrusted certificate fields (e.g., stateOrProvinceName) to file paths, enabling LFI/path traversal
- **Fix**: Source code fix - Sanitize and escape certificate fields before file operations
- **Gap**: Race condition in script (mentioned in initial summary) allows access to another user
- **Fix**: Source code fix - Implement file locks or atomic operations to prevent races

### DNS and SMTP Resolution
- **Gap**: Resolves external DNS for SMTP servers based on untrusted domains, allowing attacker-controlled mail servers
- **Fix**: Configuration fix - Use internal DNS resolvers or static SMTP configurations; enforce egress filtering for DNS queries
- **Gap**: No authentication or encryption checks in SMTP sending, enabling interception of reports
- **Fix**: Configuration fix - Enable TLS and authentication for SMTP

### Incident Response/Forensic Files (pcap, memory dumps)
- **Gap**: Memory dumps contain extractable AES keys due to lack of memory protections
- **Fix**: Configuration fix - Enable Address Space Layout Randomization (ASLR) and disable core dumps in production; Source code fix - Use secure key generation/wiping in payloads
- **Gap**: Encrypted Meterpreter streams in pcap can be decrypted with dumped keys
- **Fix**: Source code fix - Implement forward secrecy or ephemeral keys in custom payloads

### SSH System
- **Gap**: Partial private key exposure in screenshots allows reconstruction using public key components
- **Fix**: Configuration fix - Enforce key rotation post-incident and use passphrases; Source code fix - N/A (procedural, but integrate key checks in auth modules if custom)

## Conclusion

Response is an excellent machine that demonstrates the complexity of modern attack chains. It requires expertise in:
- Custom proxy development and web application security
- Protocol manipulation and cross-protocol attacks
- Infrastructure setup and service spoofing
- Memory forensics and cryptographic analysis
- SSH key mathematics and reconstruction

The machine emphasizes that security is only as strong as the weakest link, and even sophisticated systems can be compromised through creative attack chaining and persistence.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*