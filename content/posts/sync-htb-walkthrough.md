---
title: "Sync HTB - Hard Linux Box Walkthrough"
date: 2025-09-22T06:30:00Z
tags: ["hard-linux", "web", "gitea", "http-smuggling", "gunicorn", "haproxy", "aws-localstack", "kms", "secrets-manager", "privilege-escalation"]
difficulty: ["hard"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Sync HTB machine featuring HTTP request smuggling in Gunicorn/HAProxy, Gitea exploitation, AWS LocalStack enumeration, KMS decryption, and multi-container stabilization"
---

# Sync HTB - Hard Linux Box Walkthrough

{{< youtube 8gf5YvvY1yc >}}

Below is a chronological extraction of the key exploitation steps and techniques used in the provided data, based on the narrative of the "Sync" box from Hack The Box, as described in the YouTube video transcript. The steps are organized in the order they were performed, focusing on the critical actions and techniques used to progress through the exploitation process.

---

## Key Exploitation Steps and Techniques (Chronological Order)

1. **Initial Reconnaissance with Nmap**
   - **Technique**: Network scanning using Nmap with default scripts (`-sC`), version enumeration (`-sV`), and output in all formats (`-oA`).
   - **Details**:
     - Scanned the target IP `[TARGET-IP]` to identify open ports and services.
     - Identified SSH on port 22 (Ubuntu Bionic 18.04), an HTTP server on port 3000 (Gitea application), and another HTTP server on port 5000 (Gunicorn 20.0.0).
     - Noted the Gunicorn version was outdated (released October 30, 2019), hinting at potential vulnerabilities like HTTP request smuggling due to a changelog mentioning fixed chunk encoding issues in later versions.

2. **Enumeration of HTTP Service on Port 3000 (Gitea)**
   - **Technique**: Manual HTTP request crafting and source code analysis.
   - **Details**:
     - Sent manual HTTP requests to port 3000 to identify the service as Gitea (version 1.12.6).
     - Enumerated the Gitea version by accessing `/js/jquery` and using VirusTotal to correlate the jQuery file's MD5 hash with a submission date (October 24, 2020), aligning with Gitea's release timeline.
     - Identified the application's title ("Gitea: Git with a cup of tea") and noted a CSRF token and cookie.

3. **Enumeration of HTTP Service on Port 5000 (Gunicorn and HAProxy)**
   - **Technique**: Web application enumeration and version analysis.
   - **Details**:
     - Confirmed Gunicorn 20.0.0 running behind HAProxy, with a "Via: haproxy" header indicating a proxy setup.
     - Attempted basic interactions (e.g., login with `admin:password`, signup with `ipsec:root@ipsec.rocks:password`) to understand functionality.
     - Identified a potential IDOR (Insecure Direct Object Reference) vulnerability by fuzzing note IDs (`/notes/9001` caused a 500 error, while lower IDs redirected, indicating note existence validation).

4. **HTTP Request Smuggling Attack**
   - **Technique**: HTTP request smuggling exploiting chunked transfer encoding mismatch between HAProxy and Gunicorn.
   - **Details**:
     - Researched Gunicorn 20.0.0's vulnerability to HTTP smuggling due to improper chunked encoding handling (fixed in later versions).
     - Crafted a malicious HTTP request using Burp Suite, adding `Transfer-Encoding: chunked` and a vertical tab (`\x0b`, base64-encoded as `cw==`) to exploit the mismatch.
     - Set a specific `Content-Length` header (e.g., 280 or 290) to smuggle a second request, capturing another user's session cookie by appending their request data to a note.
     - Repeated the request multiple times to win the race condition, capturing a session cookie ending in `ey`, which granted admin access to `sync.htb`.

5. **Privilege Escalation via Stolen Admin Credentials**
   - **Technique**: Session hijacking and credential reuse.
   - **Details**:
     - Used the stolen admin session cookie to access the admin panel on port 5000.
     - Discovered credentials for `nagiosadmin`, `dev`, and `chef` in admin notes but noted admin could not view low-privilege user notes directly.
     - Logged into Gitea on port 3000 with `dev` credentials (reused password), revealing four Git repositories: `elasticsearch`, `serverless`, `key-management`, and `log-management`.

6. **Enumeration of Git Repositories**
   - **Technique**: Git repository analysis and commit history review.
   - **Details**:
     - Explored the `key-management` repository, finding an SSH private key (`marcus.pem`) in a commit for EC2 key management.
     - Downloaded the key, fixed formatting issues (removed extra spaces), and used it to SSH into the target as user `marcus` (`ssh -i marcus.pem marcus@[TARGET-IP]`).

7. **AWS Local Stack Enumeration**
   - **Technique**: Interaction with AWS Local Stack CLI to enumerate cloud services.
   - **Details**:
     - On the `marcus` account, confirmed no Elasticsearch or Kibana services (ports 9200 and 5601 not listening).
     - Used `aws_local` CLI to interact with Local Stack, listing CloudTrail log streams (`aws_local logs describe-log-streams --log-group-name cloudtrail`).
     - Retrieved log events (`aws_local logs get-log-events`) showing `RotateSecret` actions, indicating AWS Secrets Manager usage.
     - Listed secrets (`aws_local secretsmanager list-secrets`), identifying `jira_support` (user: `david`, password), `sync_panel` (user: `albert`), and `jenkins_login` (no user `john` found in `/etc/passwd`).
     - Used `david`'s password to switch user (`su david`) on the box.

8. **Decryption of Encrypted File**
   - **Technique**: AWS KMS decryption of an encrypted file.
   - **Details**:
     - As `david`, found an encrypted file `servers.enc` in `~/projects/prod-deployment`.
     - Confirmed high entropy (7.6 bits/byte) using the `ent` command, indicating encryption.
     - Listed KMS keys (`aws_local kms list-keys`), identified an enabled key for encryption/decryption, and described its properties (`aws_local kms describe-key --key-id <key_id>`).
     - Decrypted `servers.enc` using `aws_local kms decrypt --key-id <key_id> --ciphertext-blob fileb://servers.enc --encryption-algorithm RSAES_OAEP_SHA_256 --output text`, yielding a base64-encoded blob.
     - Decoded the blob, identified it as a gzip-compressed tar archive (`file` command), and extracted it (`tar xzvf unknown.tar.gz`), revealing `servers.yaml` with `admin` credentials.

9. **Root Access**
   - **Technique**: Credential reuse for privilege escalation.
   - **Details**:
     - Used the `admin` password from `servers.yaml` to switch user (`su -`) and gain root access.
     - Retrieved the root flag from `root.txt`.

10. **Stabilizing the Box (Post-Exploitation)**
    - **Technique**: IPTables-based IP modulo routing for container isolation.
    - **Details**:
      - Noted the box's instability due to HTTP smuggling race conditions in a multi-user environment.
      - Implemented IPTables rules on the pre-routing chain (`iptables -t nat -L`) to route traffic based on the last octet of the source IP (e.g., `[ATTACKER-NET]/28`, 16 IPs) to one of 16 Docker containers (ports 6000–6015 mapped to 8080).
      - Used rules like `-s [ATTACKER-NET]/28 -p tcp --dport 5000 -j DNAT --to-destination [INTERNAL-IP]:8080` to minimize interference between users' HTTP smuggling attempts.
      - Chose IPTables over a kernel module or other load balancers (e.g., Pound) to avoid breaking the smuggling exploit and reduce custom code vulnerabilities.

---

## Summary of Techniques
- **Reconnaissance**: Nmap scanning, version enumeration.
- **Web Enumeration**: Manual HTTP requests, source code analysis, VirusTotal for file dating.
- **HTTP Request Smuggling**: Exploited chunked encoding mismatch between HAProxy and Gunicorn to steal session cookies.
- **Session Hijacking**: Used stolen admin cookies to access restricted areas.
- **Credential Reuse**: Leveraged credentials from Git repositories and AWS secrets.
- **AWS Local Stack**: Interacted with Secrets Manager and KMS to retrieve and decrypt sensitive data.
- **File Decryption**: Used KMS to decrypt a tar.gz archive containing credentials.
- **IPTables Routing**: Configured IP modulo routing to stabilize multi-user exploitation.

This sequence reflects the logical progression from reconnaissance to root access, with each step building on the previous findings to escalate privileges and achieve the objective.

## Security Gaps and Remediation

Based on the provided data from the "Sync" Hack The Box exploitation, several vulnerabilities and misconfigurations in services and systems were exploited to gain unauthorized access. Below is a list of the identified gaps in each service or system, along with recommended fixes categorized as either source code fixes or configuration fixes. The gaps are derived from the exploitation steps and techniques described, focusing on the vulnerabilities that enabled the attack.

---

### Identified Gaps and Recommended Fixes

#### 1. Gunicorn (Port 5000) - HTTP Request Smuggling Vulnerability
   - **Gap**: The Gunicorn version 20.0.0 (released October 30, 2019) was vulnerable to HTTP request smuggling due to improper handling of chunked transfer encoding, allowing an attacker to append another user's request data to steal session cookies. This was exacerbated by a mismatch in how HAProxy and Gunicorn processed the `Transfer-Encoding: chunked` header with a vertical tab (`\x0b`).
   - **Impact**: Enabled session cookie theft, leading to unauthorized admin access.
   - **Fixes**:
     - **Source Code Fix**: Update Gunicorn to a version post-November 2019 (e.g., 20.0.1 or later), where the changelog indicates fixed chunk encoding support to prevent request smuggling.
     - **Configuration Fix**:
       - Configure HAProxy to strictly validate `Transfer-Encoding` headers and reject requests with invalid or ambiguous headers (e.g., those containing vertical tabs).
       - Enable strict HTTP parsing in HAProxy by setting `option http-use-htx` and `http-request deny` for malformed requests.
       - Disable chunked transfer encoding in HAProxy if not required, using `no option http-use-chunked`.

#### 2. HAProxy (Fronting Gunicorn on Port 5000) - Improper Header Validation
   - **Gap**: HAProxy failed to properly validate or sanitize the `Transfer-Encoding: chunked` header, ignoring the vertical tab (`\x0b`) and forwarding the request to Gunicorn, which treated it as a valid chunked request. This allowed the smuggling attack to succeed.
   - **Impact**: Facilitated HTTP request smuggling, enabling session cookie theft.
   - **Fixes**:
     - **Configuration Fix**:
       - Update HAProxy to the latest version to ensure robust header parsing.
       - Add a configuration rule to reject requests with unexpected or malformed `Transfer-Encoding` headers, e.g., `http-request deny if { hdr(Transfer-Encoding) -m reg chunked.*[\x0b] }`.
       - Implement stricter HTTP request validation by enabling `option httpchk` and ensuring HAProxy enforces consistent header handling with backend servers like Gunicorn.

#### 3. Gitea (Port 3000) - Exposure of Version Information
   - **Gap**: The Gitea application exposed its version (1.12.6) via the `/js/jquery` file, which was correlated with a VirusTotal MD5 hash submission date. Additionally, the application revealed implementation details (e.g., Go version 1.14.12) in its source code, aiding attackers in identifying potential vulnerabilities.
   - **Impact**: Allowed attackers to pinpoint the exact software version and research associated vulnerabilities.
   - **Fixes**:
     - **Source Code Fix**:
       - Remove or obfuscate version information from publicly accessible files (e.g., remove version strings from JavaScript files or HTML metadata).
       - Implement a generic error page that does not leak software details like Go version.
     - **Configuration Fix**:
       - Configure Gitea to disable directory listing for `/js/` or other static directories using a web server rule (e.g., in Nginx: `autoindex off;`).
       - Use a reverse proxy (e.g., Nginx or HAProxy) to strip sensitive headers or metadata from responses, such as `Server` or `X-Powered-By`.

#### 4. Gitea (Port 3000) - Insecure Direct Object Reference (IDOR) in Note Access
   - **Gap**: The Gitea application exhibited an IDOR vulnerability in the `/notes` endpoint. Requesting a non-existent note ID (e.g., `/notes/9001`) triggered a 500 Internal Server Error, while valid low-numbered IDs caused a redirect, allowing attackers to confirm the existence of notes they did not have permission to access.
   - **Impact**: Enabled enumeration of valid note IDs, potentially leading to unauthorized access if combined with other vulnerabilities.
   - **Fixes**:
     - **Source Code Fix**:
       - Implement consistent error handling to return a generic 403 Forbidden or 404 Not Found response for both existent and non-existent note IDs, preventing enumeration.
       - Validate user permissions before processing note ID requests, ensuring users can only access their own notes.
     - **Configuration Fix**:
       - Configure the web server or application firewall to rate-limit requests to `/notes` endpoints to deter ID fuzzing.
       - Use a Web Application Firewall (WAF) to detect and block patterns of sequential ID requests.

#### 5. Gitea (Port 3000) - Exposed Git Repositories with Sensitive Data
   - **Gap**: The `key-management` repository contained an SSH private key (`marcus.pem`) in a commit, which was accessible to authenticated users. This key allowed SSH access to the target as the `marcus` user.
   - **Impact**: Enabled unauthorized SSH access to the system as a low-privilege user.
   - **Fixes**:
     - **Source Code Fix**:
       - Implement a pre-commit hook in Gitea to scan for sensitive data (e.g., SSH keys, passwords) using tools like `gitleaks` or `truffleHog` and block commits containing such data.
       - Enforce code review policies to prevent sensitive data from being committed.
     - **Configuration Fix**:
       - Restrict repository access to only authorized users by configuring Gitea's access controls (e.g., set repositories to private and limit access to specific teams).
       - Regularly audit repository commit histories and remove sensitive data using `git filter-repo` or BFG Repo-Cleaner.
       - Disable raw file access for unauthenticated users in Gitea's configuration (`[repository] DISABLE_HTTP_GIT = true`).

#### 6. AWS Local Stack - Exposed AWS Secrets in Secrets Manager
   - **Gap**: The AWS Local Stack instance exposed sensitive credentials (`jira_support`, `sync_panel`, `jenkins_login`) via the Secrets Manager (`aws_local secretsmanager list-secrets` and `get-secret-value`), accessible to the `marcus` user. These credentials included usernames and passwords for other system users (e.g., `david`).
   - **Impact**: Allowed privilege escalation by retrieving credentials for higher-privilege users.
   - **Fixes**:
     - **Source Code Fix**:
       - Implement least privilege access controls in the application using Local Stack, ensuring users like `marcus` cannot access Secrets Manager.
       - Encrypt sensitive data in Secrets Manager with stricter access policies, requiring specific IAM roles for retrieval.
     - **Configuration Fix**:
       - Configure Local Stack to restrict Secrets Manager access by setting IAM policies that limit `secretsmanager:ListSecrets` and `secretsmanager:GetSecretValue` to specific roles or users.
       - Rotate secrets regularly using AWS Secrets Manager's rotation feature and remove outdated or unused secrets.
       - Disable unauthenticated access to Local Stack services by securing the endpoint (port 4566) with authentication or network restrictions.

#### 7. AWS Local Stack - Weak KMS Key Access Controls
   - **Gap**: The `marcus` user could list and describe KMS keys (`aws_local kms list-keys`, `describe-key`) and decrypt the `servers.enc` file using an enabled KMS key, revealing sensitive `admin` credentials.
   - **Impact**: Enabled decryption of sensitive data, leading to root access.
   - **Fixes**:
     - **Source Code Fix**:
       - Modify the application to enforce stricter KMS key policies, ensuring only authorized roles can perform `kms:Decrypt` or `kms:DescribeKey` actions.
       - Implement key rotation and auditing to track key usage and detect unauthorized access attempts.
     - **Configuration Fix**:
       - Update KMS key policies to restrict access to specific IAM roles or users, e.g., `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::account-id:role/admin"},"Action":"kms:Decrypt","Resource":"*"}`.
       - Disable unused or unnecessary KMS keys to reduce the attack surface (`aws_local kms disable-key --key-id <key_id>`).
       - Monitor KMS key usage logs via CloudTrail to detect unauthorized access attempts.

#### 8. System - Weak Password Reuse Across Accounts
   - **Gap**: Password reuse was prevalent across accounts (e.g., `dev` credentials worked on Gitea, `david` credentials from Secrets Manager worked for `su`, and `admin` credentials from decrypted files granted root access). The system did not enforce strong password policies or account separation.
   - **Impact**: Facilitated privilege escalation by reusing credentials across services and accounts.
   - **Fixes**:
     - **Source Code Fix**:
       - Implement a password policy enforcement module in the application to require strong, unique passwords (e.g., minimum length, complexity requirements).
       - Integrate a password manager or SSO solution to prevent credential reuse across services.
     - **Configuration Fix**:
       - Enforce strong password policies at the system level using PAM (Pluggable Authentication Module) configurations, e.g., `/etc/security/pwquality.conf` with settings like `minlen=12`, `dcredit=-1`, `ucredit=-1`.
       - Implement account lockout mechanisms after failed login attempts to deter brute-forcing (`pam_tally2` or `pam_faildelay`).
       - Use separate credentials for each service and user account, enforced via configuration management tools like Chef or Ansible.

#### 9. System - Unprotected SSH Private Key
   - **Gap**: The SSH private key (`marcus.pem`) was stored in a Git repository and was accessible without proper permissions (world-readable, requiring a `chmod 600` fix during exploitation). No key passphrase was set.
   - **Impact**: Allowed unauthorized SSH access as the `marcus` user.
   - **Fixes**:
     - **Source Code Fix**:
       - Integrate a key management system in the application to securely store and distribute SSH keys, avoiding plaintext storage in repositories.
       - Require passphrases for SSH keys during generation and enforce their use in the application.
     - **Configuration Fix**:
       - Set proper file permissions for SSH keys (`chmod 600 ~/.ssh/*`) and ensure the `.ssh` directory is restricted (`chmod 700 ~/.ssh`).
       - Configure SSH server (`/etc/ssh/sshd_config`) to reject connections using keys without passphrases by setting `PermitEmptyPasswords no` and `PasswordAuthentication no`.
       - Regularly audit SSH key storage locations and remove unauthorized keys from `/home/*/ssh/authorized_keys`.

#### 10. System - Insecure File Permissions for Encrypted Data
   - **Gap**: The `servers.enc` file was accessible to the `david` user, who could decrypt it using KMS, revealing sensitive `admin` credentials. File permissions did not restrict access to authorized users only.
   - **Impact**: Enabled unauthorized access to encrypted data, leading to root escalation.
   - **Fixes**:
     - **Source Code Fix**:
       - Implement access control checks in the application to ensure only authorized users can access encrypted files or initiate KMS decryption.
       - Use a secure file storage mechanism (e.g., AWS S3 with bucket policies) instead of local file storage for sensitive data.
     - **Configuration Fix**:
       - Set strict file permissions for sensitive files (`chmod 600 servers.enc`, `chown root:root servers.enc`) to prevent unauthorized access.
       - Use filesystem ACLs (Access Control Lists) to further restrict access to specific users or groups (`setfacl -m u:root:r servers.enc`).
       - Store encrypted files in a dedicated, restricted directory (e.g., `/var/secure/`) with `chmod 700` and `chown root:root`.

#### 11. IPTables Configuration - Lack of Logging for Routing Rules
   - **Gap**: The IPTables rules used for IP modulo routing to Docker containers lacked logging, making it difficult to detect or audit unauthorized access attempts or misrouted traffic. The pre-routing chain rules were critical but not monitored.
   - **Impact**: Reduced visibility into potential exploitation attempts targeting the routing mechanism.
   - **Fixes**:
     - **Configuration Fix**:
       - Add logging to IPTables rules to track traffic routing, e.g., `iptables -t nat -A PREROUTING -s [ATTACKER-NET]/28 -p tcp --dport 5000 -j LOG --log-prefix "SYNC_ROUTING: "`.
       - Implement a logging solution (e.g., `rsyslog` or `auditd`) to monitor IPTables activity and store logs securely.
       - Regularly review IPTables rules (`iptables-save`) to ensure only authorized routing configurations are present.

#### 12. Docker Containers - Insufficient Isolation
   - **Gap**: The use of 16 Docker containers to handle multi-user traffic relied on IPTables routing, but there was no mention of container isolation measures (e.g., namespaces, seccomp, or AppArmor) to prevent container breakouts or inter-container communication.
   - **Impact**: Potential for container escape or interference if an attacker gained access to one container.
   - **Fixes**:
     - **Configuration Fix**:
       - Enable Docker security features like user namespaces (`--userns-remap`) to isolate container users from the host.
       - Apply AppArmor or SELinux profiles to Docker containers to restrict system calls and file access.
       - Restrict inter-container networking by setting `--network none` or using a custom network with strict firewall rules.
       - Limit container privileges by running with `--cap-drop all` and adding only necessary capabilities (e.g., `--cap-add NET_BIND_SERVICE`).

---

### Summary of Gaps and Fix Types
| **Service/System** | **Gap** | **Fix Type** |
|--------------------|---------|--------------|
| Gunicorn (Port 5000) | HTTP Request Smuggling | Source Code (Update Gunicorn), Configuration (HAProxy header validation) |
| HAProxy | Improper Header Validation | Configuration (Stricter header parsing, reject malformed requests) |
| Gitea (Port 3000) | Version Information Exposure | Source Code (Remove version strings), Configuration (Disable directory listing) |
| Gitea (Port 3000) | IDOR in Note Access | Source Code (Consistent error handling), Configuration (Rate-limiting, WAF) |
| Gitea (Port 3000) | Exposed Git Repositories with SSH Key | Source Code (Pre-commit hooks), Configuration (Access controls, audit commits) |
| AWS Local Stack | Exposed AWS Secrets | Source Code (Least privilege), Configuration (IAM policies, secret rotation) |
| AWS Local Stack | Weak KMS Key Access | Source Code (Stricter key policies), Configuration (Restrict access, disable unused keys) |
| System | Password Reuse | Source Code (Password policy enforcement), Configuration (PAM settings, SSO) |
| System | Unprotected SSH Key | Source Code (Secure key management), Configuration (File permissions, SSHD config) |
| System | Insecure File Permissions | Source Code (Access control checks), Configuration (File permissions, ACLs) |
| IPTables | Lack of Logging | Configuration (Add logging rules, monitor logs) |
| Docker Containers | Insufficient Isolation | Configuration (User namespaces, AppArmor, network restrictions) |

---

### Additional Recommendations
- **Patch Management**: Implement a regular patch management process to update all software (Gunicorn, HAProxy, Gitea, etc.) to the latest stable versions.
- **Monitoring and Auditing**: Deploy a centralized logging and monitoring solution (e.g., ELK Stack or Splunk) to detect and respond to suspicious activities, such as repeated IDOR attempts or HTTP smuggling.
- **Security Training**: Educate developers and administrators on secure coding practices, such as avoiding sensitive data in Git commits and implementing proper input validation.
- **Network Segmentation**: Isolate services (e.g., Gitea, Gunicorn, Local Stack) on separate network segments or VLANs to limit lateral movement if one service is compromised.

These fixes address the specific vulnerabilities exploited in the "Sync" box, ensuring a more secure configuration and reducing the attack surface.

## Conclusion

Sync is an excellent machine that demonstrates the complexity of modern web application security and cloud service integration. It requires expertise in:
- HTTP request smuggling and protocol manipulation
- Git repository analysis and version enumeration
- AWS LocalStack service interaction and enumeration
- Cloud encryption and key management systems
- Multi-container deployment and networking

The machine emphasizes the importance of proper version management, secure configuration of proxy servers, and the risks of exposing development cloud services in production environments.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*