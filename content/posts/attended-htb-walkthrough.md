---
title: "Attended HTB - Insane OpenBSD Box Walkthrough"
date: 2025-09-22T07:00:00Z
tags: ["insane-openbsd", "smtp", "phishing", "vim-rce", "cve-2019-12735", "buffer-overflow", "rop-chain", "privilege-escalation", "c2", "ssh"]
difficulty: ["insane"]
categories: ["HTB", "OpenBSD"]
draft: false
description: "Complete walkthrough of Attended HTB machine featuring SMTP phishing, Vim RCE exploitation, custom HTTP C2 development, buffer overflow analysis, and ROP chain construction for privilege escalation"
---

# Attended HTB - Insane OpenBSD Box Walkthrough

{{< youtube ABVR8EgXsQU >}}

## Exploitation Steps

1. **Initial Reconnaissance (Nmap Scan)**: Perform an Nmap scan on the target IP ([TARGET-IP]) to identify open ports: SSH on 22 and SMTP on 25. Discover hostname attended.htb, potential user "gully", OS OpenBSD, and SMTP server OpenSMTPD.

2. **Hosts File Modification**: Add "[TARGET-IP] attended.htb" to the local /etc/hosts file for name resolution.

3. **IPTables Logging Setup**: Configure iptables to log new incoming TCP connections on the tun0 interface for monitoring reverse connections or detections.

4. **Phishing via SMTP (Initial Email)**: Use swaks to send an email to gully@attended.htb with a pretext link to a local HTTP server. Observe no click, but receive a response email indicating the target initiates SMTP connections back.

5. **SMTP Server Setup for Responses**: Run a Python SMTP debug server to capture response emails from gully, confirming automated replies and hints about user "freshness".

6. **Email Spoofing**: Spoof emails from freshness@attended.htb to gully, eliciting responses that reveal preferences (Vim user, against proprietary attachments) and Python 2 availability.

7. **Attachment Testing**: Send a .docx attachment; rejected due to proprietary format. Switch to .txt for Vim compatibility.

8. **Vim RCE Exploitation (CVE-2019-12735)**: Craft a malicious .txt file with embedded code to execute a ping back to attacker IP, confirming RCE as gully when opened in Vim. Firewall blocks non-RFC compliant connections (e.g., reverse shells).

9. **Custom HTTP C2 Implant Development**: Build a Python 2-compatible HTTP-based command-and-control (C2) client (web cradle) using requests.get for tasking and output, with server-side handling to keep connections open for low-latency, low-volume communication. Base64-encode the client for delivery via Vim exploit.

10. **Initial Foothold as Gully**: Deliver the C2 implant via malicious .txt attachment, gaining command execution as gully. Enumerate files, find ~/.ssh/config.swap with SSH config hints.

11. **Privilege Escalation to Freshness via Cron Job**: Identify cron-run fchecker.py script processing /home/shared configs. Inject a malicious SSH config with ProxyCommand executing the C2 implant, pivoting to freshness user. Drop SSH key for persistent access.

12. **Binary Discovery and Transfer**: As freshness, locate authkeys binary in ~/.ssh/auth_keys. Transfer to local machine for analysis; note it's an OpenBSD binary with buffer overflow vulnerability.

13. **Binary Reverse Engineering**: Use IDA Pro and GDB (with GEF) on an OpenBSD VM to analyze authkeys. Identify buffer overflow in base64 decoding (copies >0x300 bytes), leading to RIP overwrite.

14. **ROP Chain Construction**: Build ROP chain using gadgets (not al, shr eax, pop rdx, movss, cvttss2si, mov rdi,rsi) to set registers for sys_execve (syscall 59): RAX=59, RDI=pathname (/usr/local/bin/python2), RSI=argv array, RDX=0. Use stack for strings/pointers, convert addresses to floats for SSE instructions.

15. **Exploit Formatting as SSH Public Key**: Prefix ROP payload with SSH-RSA public key header (length fields, exponents) to trigger via AuthorizedKeysCommand in sshd_config on attended-gw (port 2222).

16. **Root Access on Attended-GW**: Attempt SSH with exploit.pub to root@attended-gw:2222, triggering buffer overflow and executing Python 2 reverse shell as root. Retrieve root.txt.

## Security Gaps and Remediation

### 1. **SMTP Service (OpenSMTPD)**:
   - **Gap**: Automated email responses reveal internal information such as potential usernames (e.g., "freshness") and system details (e.g., Python 2 environment, Vim usage, outbound traffic restrictions).
     - **Fix**: Configuration fix - Modify OpenSMTPD configuration (/etc/mail/smtpd.conf) to disable or limit verbose error messages and automated replies to untrusted senders, using rules to filter or anonymize responses.
   - **Gap**: Allows email spoofing from internal users (e.g., spoofing from "freshness" to bypass dodging emails from others).
     - **Fix**: Configuration fix - Enable SPF, DKIM, or DMARC in OpenSMTPD configuration to verify sender domains and prevent spoofing; add milter plugins for additional validation.
   - **Gap**: Automated opening of email attachments in Vim, leading to RCE exploitation.
     - **Fix**: Source code fix - If automated attachment processing is custom-scripted, refactor the script to sandbox attachments or use secure viewers; alternatively, configuration fix by disabling attachment auto-opening in email client configs or using antivirus scanning.

### 2. **Vim Editor**:
   - **Gap**: Vulnerable to RCE (CVE-2019-12735) due to outdated version (2019 vulnerability).
     - **Fix**: Configuration fix - Update Vim to a patched version (e.g., via pkg_add on OpenBSD) to include security fixes; disable modelines or unsafe features in /etc/vimrc.

### 3. **Firewall System**:
   - **Gap**: Permits HTTP outbound traffic but blocks non-RFC compliant connections, allowing custom HTTP C2 but restricting standard reverse shells.
     - **Fix**: Configuration fix - Tighten firewall rules (e.g., pf.conf on OpenBSD) to whitelist specific outbound protocols/ports and inspect HTTP traffic for anomalies using tools like pf or additional IDS.

### 4. **Cron Job System (fchecker.py Script)**:
   - **Gap**: Processes untrusted files in /home/shared without input sanitization, leading to command injection via malicious filenames (e.g., filenames with semicolons executing arbitrary commands).
     - **Fix**: Source code fix - In fchecker.py, sanitize filenames using shlex.quote or validate against allowed characters; use subprocess.Popen with shell=False and list arguments to prevent injection.
   - **Gap**: Deletes configs after short delay (0.2 seconds) but still allows execution of embedded commands (e.g., ProxyCommand).
     - **Fix**: Source code fix - Add validation to parse and restrict SSH config options (e.g., disallow ProxyCommand) before execution; run in a restricted environment.

### 5. **SSH Service (OpenSSH)**:
   - **Gap**: SSH config allows arbitrary ProxyCommand execution from untrusted sources, enabling code execution pivot.
     - **Fix**: Configuration fix - In sshd_config, set Match blocks to restrict ProxyCommand usage or disable it via "PermitProxyCommand no"; ensure configs are loaded from trusted paths only.
   - **Gap**: Writable .ssh directory as freshness allows unauthorized key drops.
     - **Fix**: Configuration fix - Set stricter permissions on .ssh directories (chmod 700) and use umask; implement SELinux/AppArmor policies if available.
   - **Gap**: AuthorizedKeysCommand in sshd_config runs vulnerable binary (authkeys) for key evaluation.
     - **Fix**: Configuration fix - Disable AuthorizedKeysCommand in sshd_config or replace with a secure alternative like sshd's built-in key handling; restrict to run as non-root (e.g., nobody).

### 6. **Custom Binary (authkeys)**:
   - **Gap**: Buffer overflow in base64 decoding due to unsafe copying (copies >0x300 bytes without bounds checking).
     - **Fix**: Source code fix - Replace unsafe string operations (e.g., strcpy) with bounded alternatives like strncpy or strlcpy; implement input length validation before decoding.
   - **Gap**: Runs with elevated privileges (as root on attended-gw), allowing full system compromise via overflow.
     - **Fix**: Configuration fix - Run the binary as a low-privilege user (e.g., nobody) via sudo or setuid; drop privileges early in code if source is available.
   - **Gap**: Processes SSH public keys without validation, enabling ROP chain exploitation.
     - **Fix**: Source code fix - Add key format validation (e.g., check lengths, reject oversized keys); use secure parsing libraries for SSH keys.

### 7. **Overall System (OpenBSD VMs - attended.htb and attended-gw)**:
   - **Gap**: Information disclosure via SMTP banner and help messages (e.g., revealing OpenBSD version and contact).
     - **Fix**: Configuration fix - Customize SMTP banners in smtpd.conf to remove version/OS details; disable unnecessary HELP responses.
   - **Gap**: Old user.txt and timestamps indicate potential VM snapshot issues or lack of flag rotation, hinting at misconfiguration in HTB setup (meta, but implies insecure VM management).
     - **Fix**: Configuration fix - Ensure VM boot scripts rotate flags properly; use secure VM isolation (e.g., via bhyve or vmm on OpenBSD).
   - **Gap**: Python 2 environment exposed and used for exploits, lacking modules like requests in some contexts.
     - **Fix**: Configuration fix - Upgrade to Python 3 and remove Python 2; install necessary modules securely if needed.

## Conclusion

Attended is an excellent machine that demonstrates the complexity of modern attack chains involving social engineering, legacy software vulnerabilities, and advanced exploitation techniques on OpenBSD. It requires expertise in:
- SMTP enumeration and phishing campaign development
- Legacy vulnerability exploitation (CVE-2019-12735)
- Custom command-and-control development and deployment
- Buffer overflow analysis and ROP chain construction
- OpenBSD-specific binary exploitation and system insaneening
- Multi-stage privilege escalation through cron job abuse

The machine emphasizes the importance of keeping software updated, implementing proper input validation, and securing custom binaries with appropriate privilege separation and bounds checking.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*