---
title: "Scanned HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T05:50:00Z
tags: ["insane-linux", "web", "chroot-escape", "sandbox-escape", "file-descriptor-abuse", "ptrace", "path-hijacking", "privilege-escalation", "django"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Scanned HTB machine featuring chroot jail escape via file descriptor abuse, data exfiltration through syscall logging, and privilege escalation via path hijacking"
---

# Scanned HTB - Insane Linux Box Walkthrough

{{< youtube FoQuNsCyQz0>}}

Scanned is a Insane difficulty Linux machine from Hack The Box that demonstrates advanced sandbox escape techniques. This machine requires expertise in Linux internals, particularly chroot jail escapes, file descriptor manipulation, and privilege escalation via path hijacking. The exploitation chain involves escaping a malware sandbox application, exfiltrating data through ptrace syscall logging, and escalating privileges through library hijacking.

## Key Exploitation Steps and Techniques (Chronological Order)

### Phase 1: Reconnaissance and Initial Discovery

#### 1. Reconnaissance and Initial Discovery
- Perform an Nmap scan (`nmap -sC -sV -oA`) to identify open ports: SSH (22) and HTTP (80) running Nginx
- Access the HTTP site at port 80, revealing a "Malware Scanner" web app (Django-based) that allows uploading executables for syscall analysis in a sandbox
- **Technique**: Basic port scanning and web enumeration to identify the entry point

#### 2. Testing the Sandbox Functionality
- Upload a sample binary (e.g., MSFVenom reverse shell ELF) via the web form and observe the syscall output (e.g., socket/connect failures)
- Download and extract the source code (`malscanner.tar.gz`), focusing on `sandbox.c` and `tracing.c`
- Analyze the code: The sandbox creates a chroot jail, copies libraries, sets namespaces/capabilities, drops privileges to UID/GID 1001, and uses ptrace to log syscalls to `/log`
- **Technique**: Functional testing of the app and static source code review to understand the sandbox mechanics (e.g., chroot, ptrace for syscall tracing)

### Phase 2: Chroot Jail Escape and Data Exfiltration

#### 3. Identifying Chroot Jail Escape Vulnerability
- Note that the parent process (PID 1 in the jail) leaves an open file descriptor (FD 3) to the `/jails` directory outside the chroot
- This FD is accessible via `/proc/1/fd/3` and can be abused for directory traversal (e.g., `../etc/passwd`) since chroot only isolates the filesystem view without proper FD closure in the parent
- **Technique**: Code analysis reveals improper FD handling (`close(jails_fd)` only in child processes), allowing LFI-like access outside the jail via procfs

#### 4. Data Exfiltration via Syscall Log Overwrite
- Create a C program (e.g., `please_subscribe.c`) that writes to `/out`, then renames it to `/log` (which is world-writable, mode 777)
- Use fwrite to craft 64-byte syscall entries (syscall in first 8 bytes, junk in next 48, data in last 8 as return value)
- Upload the compiled binary; the web app displays the overwritten `/log` contents, allowing exfiltration of arbitrary data as hex-encoded syscall returns
- Automate uploads with a Python script using `requests` to post files and extract/decode output via regex and `struct.unpack`
- **Technique**: Abuse ptrace syscall logging and file overwrite to exfiltrate data from the sandboxed environment

#### 5. Implementing Directory Listing (LS) Inside the Jail
- Create `ls.c` using `opendir/readdir` to list directories, writing output to `/dir`, then reading and encoding it into syscall format for exfil via `/log`
- Enhance to `ls_sym.c` with `readlink` to follow symlinks (e.g., list FDs in `/proc/1/fd`)
- Use this to explore the jail filesystem (e.g., `/proc`, confirming processes: PID 1 sandbox, PID 2 child, PID 3 killer)
- **Technique**: Custom directory enumeration to map the jailed environment and confirm the open FD vulnerability

#### 6. Escaping Chroot and Reading Sensitive Files
- Create `read_file.c` to open `/proc/1/fd/3/../etc/passwd` (or similar traversals) and exfil the contents via the syscall log method
- Read `/etc/passwd` to identify users (e.g., 'clearance', 'sandbox')
- Traverse to read the Django database (`/var/www/malscanner/malscanner.db`), exfil it as binary, and extract strings (including an MD5 hash for 'clearance')
- **Technique**: Procfs-based chroot escape via open FD, combined with directory traversal for arbitrary file read

### Phase 3: Credential Cracking and User Access

#### 7. Cracking Credentials and Gaining User Access
- Extract MD5 hash from the database (`clearance:$md5$salt$hash`)
- Format for Hashcat (mode 20: md5($salt.$pass)) and crack using rockyou.txt, revealing password "onedayillfeellikecrying"
- SSH as 'clearance' using the cracked password
- **Technique**: Offline password cracking with Hashcat after file exfiltration

### Phase 4: Privilege Escalation via Path Hijacking

#### 8. Privilege Escalation to Root via Path Hijacking
- As 'clearance', access `/var/www/malscanner/sandbox/sandbox` (setuid binary running as root)
- Run the binary with a program (e.g., `/bin/su`) and a jail name (e.g., 'ipsec'), creating a new chroot jail in `/jails/<name>`
- Use `ldd /bin/su` to list required libraries; copy them to a temp dir (`/tmp/lib`)
- Hijack a library (e.g., `libpam_misc.so.0`) by compiling a malicious version (`libpam_misc.c`) with a constructor function (runs before main)
- In the constructor: Set UID/GID to 0, create a setuid bash copy at `/proc/1/fd/3/../../tmp/please_subscribe`, chown/chmod it to root-owned 4755
- Upload a sleeper binary (`exec_file.c`) that sleeps 2 seconds then execs `/bin/su`
- Run the sandbox with the sleeper, quickly copy the libraries (including hijacked one) into the jail before execution
- Execute the created setuid shell with `-p` flag to gain root (e.g., `./please_subscribe -p`)
- **Technique**: Race condition abuse to inject libraries into the jail, library constructor for pre-main code execution, path hijacking on setuid binary to elevate privileges and escape chroot again

## Security Gaps and Remediation

This machine demonstrates multiple critical security vulnerabilities across different services:

### Web Application (Django-based Malware Scanner)
- **Gap**: Lack of input validation or restrictions on uploaded binaries leading to sandbox execution of arbitrary code, where users can upload any ELF binary, which is executed in the sandbox, potentially allowing malicious payloads if the sandbox is escapable
- **Fix**: Source code fix - Implement file type checks, size limits, or static analysis in the Django view handling uploads (e.g., in `views.py`, add validation using `magic` library to ensure only benign executables are processed)

- **Gap**: Exposure of source code download link where the website provides a direct link to download the full source code, aiding attackers in vulnerability discovery
- **Fix**: Configuration fix - Remove or password-protect the source code download endpoint in the Nginx configuration (e.g., add `auth_basic` in the server block for the `/source` location)

- **Gap**: No CSRF protection or session management issues (inferred from easy automation of uploads) where uploads can be automated via simple POST requests without tokens, potentially allowing CSRF attacks
- **Fix**: Source code fix - Enable CSRF middleware in Django settings (`settings.py`) and add `@csrf_protect` decorators to upload views

### Sandbox Binary (sandbox.c and related)
- **Gap**: Open file descriptor to /jails directory not closed in parent process where FD 3 remains open in PID 1, accessible via /proc/1/fd/3, allowing chroot escape and arbitrary file reads via directory traversal
- **Fix**: Source code fix - Close the jails_fd in the parent process after forking, e.g., add `close(jails_fd);` immediately after the chroot setup in `make_jail()` function

- **Gap**: World-writable /log file allowing overwrite where /log is set to 0777, enabling uploaded binaries to clobber it and exfiltrate data via syscall logs displayed on the web
- **Fix**: Source code fix - Change permissions to 0644 or 0600 in `do_trace()` before writing, e.g., `chmod("/log", 0644);` after creation

- **Gap**: Insufficient privilege dropping and capability management where binary runs as root initially, drops to UID/GID 1001, but open FDs and procfs allow re-escalation
- **Fix**: Source code fix - Use `prctl(PR_SET_NO_NEW_PRIVS, 1)` to prevent privilege regain, and drop all capabilities with `cap_set_proc()` after chroot

- **Gap**: Race condition in jail creation and execution where time window between jail creation and binary execution allows external processes to inject files (e.g., libraries) into the jail
- **Fix**: Source code fix - Use atomic operations or locking (e.g., flock on jail directory) in `make_jail()` to prevent modifications during setup

- **Gap**: Library copying into jail without verification where copies system libraries into jail, but allows hijacking if attacker controls the jail contents
- **Fix**: Source code fix - Verify library integrity (e.g., via checksums) before copying in `copy_libraries()`, or use static linking to avoid dynamic libraries

- **Gap**: Ptrace-based syscall logging exposes sensitive register data where logs full registers (64 bytes) including potentially sensitive data, aiding exfiltration
- **Fix**: Source code fix - Sanitize or filter logged data in `log_syscall()`, e.g., mask non-essential registers before writing to /log

### Database (SQLite - malscanner.db)
- **Gap**: Database file stored in web-readable directory with sensitive data where file at /var/www/malscanner/malscanner.db contains hashed credentials, readable via chroot escape
- **Fix**: Configuration fix - Move database to a non-web directory (e.g., /var/lib/malscanner/) and set ownership to a dedicated user with 0600 permissions via `chown` and `chmod`

- **Gap**: Weak password hashing (MD5 with salt) which uses MD5, which is crackable offline (e.g., via Hashcat)
- **Fix**: Source code fix - Upgrade to bcrypt or Argon2 in Django's auth backend (e.g., in `settings.py`, set `PASSWORD_HASHERS` to prefer `'django.contrib.auth.hashers.Argon2PasswordHasher'`)

### SSH Service
- **Gap**: Weak or exposed user credentials where user 'clearance' password stored in database and crackable, allowing SSH login
- **Fix**: Configuration fix - Enforce key-based authentication only by setting `PasswordAuthentication no` in /etc/ssh/sshd_config and restarting SSH

### Overall System Configuration
- **Gap**: Setuid binary (sandbox) accessible to non-root users where /var/www/malscanner/sandbox/sandbox is executable by 'clearance', allowing privesc via jail manipulation
- **Fix**: Configuration fix - Restrict execution to root only via `chmod 700 /path/to/sandbox` and use sudoers for controlled access

- **Gap**: Insufficient filesystem permissions on /jails where jails directory allows reading/modification by web user, aiding injection attacks
- **Fix**: Configuration fix - Set restrictive permissions (e.g., `chown root:root /jails; chmod 700 /jails`) to prevent non-root access

- **Gap**: No seccomp or AppArmor/SELinux profiles where sandbox lacks kernel-level restrictions, allowing syscalls that aid escapes
- **Fix**: Configuration fix - Enable AppArmor profile for the sandbox binary (e.g., create /etc/apparmor.d/sandbox and enforce with `aa-enforce`), restricting syscalls and file access

## Conclusion

Scanned is an excellent machine that demonstrates the complexity of sandbox security and Linux internals exploitation. It requires expertise in:
- Advanced chroot jail escape techniques and file descriptor manipulation
- Custom C payload development for data exfiltration
- Ptrace syscall tracing and log manipulation
- Linux privilege escalation via library hijacking and race conditions
- Django web application security and database exploitation

The machine emphasizes the importance of proper sandbox implementation, secure file descriptor handling, and the principle of least privilege in system security.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*
