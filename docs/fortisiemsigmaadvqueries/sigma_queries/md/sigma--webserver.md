# Sigma → FortiSIEM:  Webserver

> 13 rules · Generated 2026-03-17

## Table of Contents

- [F5 BIG-IP iControl Rest API Command Execution - Webserver](#f5-big-ip-icontrol-rest-api-command-execution-webserver)
- [Successful IIS Shortname Fuzzing Scan](#successful-iis-shortname-fuzzing-scan)
- [Java Payload Strings](#java-payload-strings)
- [JNDIExploit Pattern](#jndiexploit-pattern)
- [Path Traversal Exploitation Attempts](#path-traversal-exploitation-attempts)
- [Source Code Enumeration Detection by Keyword](#source-code-enumeration-detection-by-keyword)
- [SQL Injection Strings In URI](#sql-injection-strings-in-uri)
- [Server Side Template Injection Strings](#server-side-template-injection-strings)
- [Suspicious User-Agents Related To Recon Tools](#suspicious-user-agents-related-to-recon-tools)
- [Suspicious Windows Strings In URI](#suspicious-windows-strings-in-uri)
- [Webshell ReGeorg Detection Via Web Logs](#webshell-regeorg-detection-via-web-logs)
- [Windows Webshell Strings](#windows-webshell-strings)
- [Cross Site Scripting Strings](#cross-site-scripting-strings)

## F5 BIG-IP iControl Rest API Command Execution - Webserver

| Field | Value |
|---|---|
| **Sigma ID** | `85254a62-22be-4239-b79c-2ec17e566c37` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1190 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Thurein Oo |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_f5_tm_utility_bash_api_request.yml)**

> Detects POST requests to the F5 BIG-IP iControl Rest API "bash" endpoint, which allows the execution of commands on the BIG-IP

```sql
-- ============================================================
-- Title:        F5 BIG-IP iControl Rest API Command Execution - Webserver
-- Sigma ID:     85254a62-22be-4239-b79c-2ec17e566c37
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1190
-- Author:       Nasreddine Bencherchali (Nextron Systems), Thurein Oo
-- Date:         2023-11-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_f5_tm_utility_bash_api_request.yml
-- Unmapped:     cs-method, cs-uri-query
-- False Pos:    Legitimate usage of the BIG IP REST API to execute command for administration purposes
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver
-- UNMAPPED_FIELD: cs-method
-- UNMAPPED_FIELD: cs-uri-query

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'POST'
    AND rawEventMsg LIKE '%/mgmt/tm/util/bash')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of the BIG IP REST API to execute command for administration purposes

**References:**
- https://f5-sdk.readthedocs.io/en/latest/apidoc/f5.bigip.tm.util.html#module-f5.bigip.tm.util.bash
- https://community.f5.com/t5/technical-forum/icontrolrest-11-5-execute-bash-command/td-p/203029
- https://community.f5.com/t5/technical-forum/running-bash-commands-via-rest-api/td-p/272516

---

## Successful IIS Shortname Fuzzing Scan

| Field | Value |
|---|---|
| **Sigma ID** | `7cb02516-6d95-4ffc-8eee-162075e111ac` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_iis_tilt_shortname_scan.yml)**

> When IIS uses an old .Net Framework it's possible to enumerate folders with the symbol "~"

```sql
-- ============================================================
-- Title:        Successful IIS Shortname Fuzzing Scan
-- Sigma ID:     7cb02516-6d95-4ffc-8eee-162075e111ac
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1190
-- Author:       frack113
-- Date:         2021-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_iis_tilt_shortname_scan.yml
-- Unmapped:     cs-uri-query, cs-method, sc-status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver
-- UNMAPPED_FIELD: cs-uri-query
-- UNMAPPED_FIELD: cs-method
-- UNMAPPED_FIELD: sc-status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%~1%'
    AND rawEventMsg LIKE '%a.aspx'
    AND rawEventMsg IN ('GET', 'OPTIONS')
    AND rawEventMsg IN ('200', '301'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/projectdiscovery/nuclei-templates/blob/9d2889356eebba661c8407038e430759dfd4ec31/fuzzing/iis-shortname.yaml
- https://www.exploit-db.com/exploits/19525
- https://github.com/lijiejie/IIS_shortname_Scanner

---

## Java Payload Strings

| Field | Value |
|---|---|
| **Sigma ID** | `583aa0a2-30b1-4d62-8bf3-ab73689efe6c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | frack113, Harjot Singh, "@cyb3rjy0t" (update) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_java_payload_in_access_logs.yml)**

> Detects possible Java payloads in web access logs

```sql
-- ============================================================
-- Title:        Java Payload Strings
-- Sigma ID:     583aa0a2-30b1-4d62-8bf3-ab73689efe6c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       frack113, Harjot Singh, "@cyb3rjy0t" (update)
-- Date:         2022-06-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_java_payload_in_access_logs.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate apps
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%\%24\%7B\%28\%23a\%3D\%40%' OR rawEventMsg LIKE '%${(#a=@%' OR rawEventMsg LIKE '%\%24\%7B\%40java%' OR rawEventMsg LIKE '%${@java%' OR rawEventMsg LIKE '%u0022java%' OR rawEventMsg LIKE '%\%2F\%24\%7B\%23%' OR rawEventMsg LIKE '%/${#%' OR rawEventMsg LIKE '%new+java.%' OR rawEventMsg LIKE '%getRuntime().exec(%' OR rawEventMsg LIKE '%getRuntime\%28\%29.exec\%28%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate apps

**References:**
- https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/
- https://www.rapid7.com/blog/post/2021/09/02/active-exploitation-of-confluence-server-cve-2021-26084/
- https://github.com/httpvoid/writeups/blob/62d3751945289d088ccfdf4d0ffbf61598a2cd7d/Confluence-RCE.md
- https://twitter.com/httpvoid0x2f/status/1532924261035384832
- https://medium.com/geekculture/text4shell-exploit-walkthrough-ebc02a01f035

---

## JNDIExploit Pattern

| Field | Value |
|---|---|
| **Sigma ID** | `412d55bc-7737-4d25-9542-5b396867ce55` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_jndi_exploit.yml)**

> Detects exploitation attempt using the JNDI-Exploit-Kit

```sql
-- ============================================================
-- Title:        JNDIExploit Pattern
-- Sigma ID:     412d55bc-7737-4d25-9542-5b396867ce55
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-12-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_jndi_exploit.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate apps the use these paths
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%/Basic/Command/Base64/%' OR rawEventMsg LIKE '%/Basic/ReverseShell/%' OR rawEventMsg LIKE '%/Basic/TomcatMemshell%' OR rawEventMsg LIKE '%/Basic/JettyMemshell%' OR rawEventMsg LIKE '%/Basic/WeblogicMemshell%' OR rawEventMsg LIKE '%/Basic/JBossMemshell%' OR rawEventMsg LIKE '%/Basic/WebsphereMemshell%' OR rawEventMsg LIKE '%/Basic/SpringMemshell%' OR rawEventMsg LIKE '%/Deserialization/URLDNS/%' OR rawEventMsg LIKE '%/Deserialization/CommonsCollections1/Dnslog/%' OR rawEventMsg LIKE '%/Deserialization/CommonsCollections2/Command/Base64/%' OR rawEventMsg LIKE '%/Deserialization/CommonsBeanutils1/ReverseShell/%' OR rawEventMsg LIKE '%/Deserialization/Jre8u20/TomcatMemshell%' OR rawEventMsg LIKE '%/TomcatBypass/Dnslog/%' OR rawEventMsg LIKE '%/TomcatBypass/Command/%' OR rawEventMsg LIKE '%/TomcatBypass/ReverseShell/%' OR rawEventMsg LIKE '%/TomcatBypass/TomcatMemshell%' OR rawEventMsg LIKE '%/TomcatBypass/SpringMemshell%' OR rawEventMsg LIKE '%/GroovyBypass/Command/%' OR rawEventMsg LIKE '%/WebsphereBypass/Upload/%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate apps the use these paths

**References:**
- https://github.com/pimps/JNDI-Exploit-Kit
- https://web.archive.org/web/20231015205935/https://githubmemory.com/repo/FunctFan/JNDIExploit

---

## Path Traversal Exploitation Attempts

| Field | Value |
|---|---|
| **Sigma ID** | `7745c2ea-24a5-4290-b680-04359cb84b35` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | Subhash Popuri (@pbssubhash), Florian Roth (Nextron Systems), Thurein Oo, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_path_traversal_exploitation_attempt.yml)**

> Detects path traversal exploitation attempts

```sql
-- ============================================================
-- Title:        Path Traversal Exploitation Attempts
-- Sigma ID:     7745c2ea-24a5-4290-b680-04359cb84b35
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1190
-- Author:       Subhash Popuri (@pbssubhash), Florian Roth (Nextron Systems), Thurein Oo, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-09-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_path_traversal_exploitation_attempt.yml
-- Unmapped:     cs-uri-query
-- False Pos:    Expected to be continuously seen on systems exposed to the Internet; Internal vulnerability scanners
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver
-- UNMAPPED_FIELD: cs-uri-query

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%../../../../../lib/password%' OR rawEventMsg LIKE '%../../../../windows/%' OR rawEventMsg LIKE '%../../../etc/%' OR rawEventMsg LIKE '%..\%252f..\%252f..\%252fetc\%252f%' OR rawEventMsg LIKE '%..\%c0\%af..\%c0\%af..\%c0\%afetc\%c0\%af%' OR rawEventMsg LIKE '%\%252e\%252e\%252fetc\%252f%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Expected to be continuously seen on systems exposed to the Internet; Internal vulnerability scanners

**References:**
- https://github.com/projectdiscovery/nuclei-templates
- https://book.hacktricks.xyz/pentesting-web/file-inclusion

---

## Source Code Enumeration Detection by Keyword

| Field | Value |
|---|---|
| **Sigma ID** | `953d460b-f810-420a-97a2-cfca4c98e602` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | James Ahearn |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_source_code_enumeration.yml)**

> Detects source code enumeration that use GET requests by keyword searches in URL strings

```sql
-- ============================================================
-- Title:        Source Code Enumeration Detection by Keyword
-- Sigma ID:     953d460b-f810-420a-97a2-cfca4c98e602
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       James Ahearn
-- Date:         2019-06-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_source_code_enumeration.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%.git/%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://pentester.land/tutorials/2018/10/25/source-code-disclosure-via-exposed-git-folder.html
- https://medium.com/@logicbomb_1/bugbounty-how-i-was-able-to-download-the-source-code-of-indias-largest-telecom-service-52cf5c5640a1

---

## SQL Injection Strings In URI

| Field | Value |
|---|---|
| **Sigma ID** | `5513deaf-f49a-46c2-a6c8-3f111b5cb453` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Saw Win Naung, Nasreddine Bencherchali (Nextron Systems), Thurein Oo (Yoma Bank) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_sql_injection_in_access_logs.yml)**

> Detects potential SQL injection attempts via GET requests in access logs.

```sql
-- ============================================================
-- Title:        SQL Injection Strings In URI
-- Sigma ID:     5513deaf-f49a-46c2-a6c8-3f111b5cb453
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Saw Win Naung, Nasreddine Bencherchali (Nextron Systems), Thurein Oo (Yoma Bank)
-- Date:         2020-02-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_sql_injection_in_access_logs.yml
-- Unmapped:     cs-method
-- False Pos:    Java scripts and CSS Files; User searches in search boxes of the respective website; Internal vulnerability scanners can cause some serious FPs when used, if you experience a lot of FPs due to this think of adding more filters such as "User Agent" strings and more response codes
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver
-- UNMAPPED_FIELD: cs-method

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'GET'
  AND rawEventMsg LIKE '%@@version%' OR rawEventMsg LIKE '%\%271\%27\%3D\%271%' OR rawEventMsg LIKE '%=select %' OR rawEventMsg LIKE '%=select(%' OR rawEventMsg LIKE '%=select\%20%' OR rawEventMsg LIKE '%concat\_ws(%' OR rawEventMsg LIKE '%CONCAT(0x%' OR rawEventMsg LIKE '%from mysql.innodb\_table\_stats%' OR rawEventMsg LIKE '%from\%20mysql.innodb\_table\_stats%' OR rawEventMsg LIKE '%group\_concat(%' OR rawEventMsg LIKE '%information\_schema.tables%' OR rawEventMsg LIKE '%json\_arrayagg(%' OR rawEventMsg LIKE '%or 1=1#%' OR rawEventMsg LIKE '%or\%201=1#%' OR rawEventMsg LIKE '%order by %' OR rawEventMsg LIKE '%order\%20by\%20%' OR rawEventMsg LIKE '%select * %' OR rawEventMsg LIKE '%select database()%' OR rawEventMsg LIKE '%select version()%' OR rawEventMsg LIKE '%select\%20*\%20%' OR rawEventMsg LIKE '%select\%20database()%' OR rawEventMsg LIKE '%select\%20version()%' OR rawEventMsg LIKE '%select\%28sleep\%2810\%29%' OR rawEventMsg LIKE '%SELECTCHAR(%' OR rawEventMsg LIKE '%table\_schema%' OR rawEventMsg LIKE '%UNION ALL SELECT%' OR rawEventMsg LIKE '%UNION SELECT%' OR rawEventMsg LIKE '%UNION\%20ALL\%20SELECT%' OR rawEventMsg LIKE '%UNION\%20SELECT%' OR rawEventMsg LIKE '%'1'='1%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Java scripts and CSS Files; User searches in search boxes of the respective website; Internal vulnerability scanners can cause some serious FPs when used, if you experience a lot of FPs due to this think of adding more filters such as "User Agent" strings and more response codes

**References:**
- https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/
- https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/
- https://brightsec.com/blog/sql-injection-payloads/
- https://github.com/payloadbox/sql-injection-payload-list
- https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection

---

## Server Side Template Injection Strings

| Field | Value |
|---|---|
| **Sigma ID** | `ada3bc4f-f0fd-42b9-ba91-e105e8af7342` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1221 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_ssti_in_access_logs.yml)**

> Detects SSTI attempts sent via GET requests in access logs

```sql
-- ============================================================
-- Title:        Server Side Template Injection Strings
-- Sigma ID:     ada3bc4f-f0fd-42b9-ba91-e105e8af7342
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1221
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_ssti_in_access_logs.yml
-- Unmapped:     cs-method, sc-status
-- False Pos:    User searches in search boxes of the respective website; Internal vulnerability scanners can cause some serious FPs when used, if you experience a lot of FPs due to this think of adding more filters such as "User Agent" strings and more response codes
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver
-- UNMAPPED_FIELD: cs-method
-- UNMAPPED_FIELD: sc-status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'GET'
  AND rawEventMsg LIKE '%={{%' OR rawEventMsg LIKE '%=\%7B\%7B%' OR rawEventMsg LIKE '%=${%' OR rawEventMsg LIKE '%=$\%7B%' OR rawEventMsg LIKE '%=<\%=%' OR rawEventMsg LIKE '%=\%3C\%25=%' OR rawEventMsg LIKE '%=@(%' OR rawEventMsg LIKE '%freemarker.template.utility.Execute%' OR rawEventMsg LIKE '%.getClass().forName('javax.script.ScriptEngineManager')%' OR rawEventMsg LIKE '%T(org.apache.commons.io.IOUtils)%'
  AND NOT (rawEventMsg = '404'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User searches in search boxes of the respective website; Internal vulnerability scanners can cause some serious FPs when used, if you experience a lot of FPs due to this think of adding more filters such as "User Agent" strings and more response codes

**References:**
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
- https://github.com/payloadbox/ssti-payloads

---

## Suspicious User-Agents Related To Recon Tools

| Field | Value |
|---|---|
| **Sigma ID** | `19aa4f58-94ca-45ff-bc34-92e533c0994a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_susp_useragents.yml)**

> Detects known suspicious (default) user-agents related to scanning/recon tools

```sql
-- ============================================================
-- Title:        Suspicious User-Agents Related To Recon Tools
-- Sigma ID:     19aa4f58-94ca-45ff-bc34-92e533c0994a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1190
-- Author:       Nasreddine Bencherchali (Nextron Systems), Tim Shelton
-- Date:         2022-07-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_susp_useragents.yml
-- Unmapped:     cs-user-agent
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver
-- UNMAPPED_FIELD: cs-user-agent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%Wfuzz/%' OR rawEventMsg LIKE '%WPScan v%' OR rawEventMsg LIKE '%Recon-ng/v%' OR rawEventMsg LIKE '%GIS - AppSec Team - Project Vision%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/wpscanteam/wpscan/blob/196fbab5b1ce3870a43515153d4f07878a89d410/lib/wpscan/browser.rb
- https://github.com/xmendez/wfuzz/blob/1b695ee9a87d66a7d7bf6cae70d60a33fae51541/docs/user/basicusage.rst
- https://github.com/lanmaster53/recon-ng/blob/9e907dfe09fce2997f0301d746796408e01a60b7/recon/core/base.py#L92

---

## Suspicious Windows Strings In URI

| Field | Value |
|---|---|
| **Sigma ID** | `9f6a34b4-2688-4eb7-a7f5-e39fef573d0e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence, exfiltration |
| **MITRE Techniques** | T1505.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_susp_windows_path_uri.yml)**

> Detects suspicious Windows strings in URI which could indicate possible exfiltration or webshell communication

```sql
-- ============================================================
-- Title:        Suspicious Windows Strings In URI
-- Sigma ID:     9f6a34b4-2688-4eb7-a7f5-e39fef573d0e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence, exfiltration | T1505.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_susp_windows_path_uri.yml
-- Unmapped:     cs-uri-query
-- False Pos:    Legitimate application and websites that use windows paths in their URL
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver
-- UNMAPPED_FIELD: cs-uri-query

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%=C:/Users%' OR rawEventMsg LIKE '%=C:/Program\%20Files%' OR rawEventMsg LIKE '%=C:/Windows%' OR rawEventMsg LIKE '%=C\%3A\%5CUsers%' OR rawEventMsg LIKE '%=C\%3A\%5CProgram\%20Files%' OR rawEventMsg LIKE '%=C\%3A\%5CWindows%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate application and websites that use windows paths in their URL

**References:**
- https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/

---

## Webshell ReGeorg Detection Via Web Logs

| Field | Value |
|---|---|
| **Sigma ID** | `2ea44a60-cfda-11ea-87d0-0242ac130003` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Cian Heasley |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_webshell_regeorg.yml)**

> Certain strings in the uri_query field when combined with null referer and null user agent can indicate activity associated with the webshell ReGeorg.

```sql
-- ============================================================
-- Title:        Webshell ReGeorg Detection Via Web Logs
-- Sigma ID:     2ea44a60-cfda-11ea-87d0-0242ac130003
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Cian Heasley
-- Date:         2020-08-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_webshell_regeorg.yml
-- Unmapped:     cs-uri-query, cs-referer, cs-user-agent, cs-method
-- False Pos:    Web applications that use the same URL parameters as ReGeorg
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver
-- UNMAPPED_FIELD: cs-uri-query
-- UNMAPPED_FIELD: cs-referer
-- UNMAPPED_FIELD: cs-user-agent
-- UNMAPPED_FIELD: cs-method

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%cmd=read%' OR rawEventMsg LIKE '%connect&target%' OR rawEventMsg LIKE '%cmd=connect%' OR rawEventMsg LIKE '%cmd=disconnect%' OR rawEventMsg LIKE '%cmd=forward%')
  AND (rawEventMsg = 'None'
    AND rawEventMsg = 'None'
    AND rawEventMsg = 'POST'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Web applications that use the same URL parameters as ReGeorg

**References:**
- https://community.rsa.com/community/products/netwitness/blog/2019/02/19/web-shells-and-netwitness-part-3
- https://github.com/sensepost/reGeorg

---

## Windows Webshell Strings

| Field | Value |
|---|---|
| **Sigma ID** | `7ff9db12-1b94-4a79-ba68-a2402c5d6729` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_win_webshells_in_access_logs.yml)**

> Detects common commands used in Windows webshells

```sql
-- ============================================================
-- Title:        Windows Webshell Strings
-- Sigma ID:     7ff9db12-1b94-4a79-ba68-a2402c5d6729
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2017-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_win_webshells_in_access_logs.yml
-- Unmapped:     cs-method
-- False Pos:    Web sites like wikis with articles on os commands and pages that include the os commands in the URLs; User searches in search boxes of the respective website
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver
-- UNMAPPED_FIELD: cs-method

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%=whoami%' OR rawEventMsg LIKE '%=net\%20user%' OR rawEventMsg LIKE '%=net+user%' OR rawEventMsg LIKE '%=net\%2Buser%' OR rawEventMsg LIKE '%=cmd\%20/c\%%' OR rawEventMsg LIKE '%=cmd+/c+%' OR rawEventMsg LIKE '%=cmd\%2B/c\%%' OR rawEventMsg LIKE '%=cmd\%20/r\%%' OR rawEventMsg LIKE '%=cmd+/r+%' OR rawEventMsg LIKE '%=cmd\%2B/r\%%' OR rawEventMsg LIKE '%=cmd\%20/k\%%' OR rawEventMsg LIKE '%=cmd+/k+%' OR rawEventMsg LIKE '%=cmd\%2B/k\%%' OR rawEventMsg LIKE '%=powershell\%%' OR rawEventMsg LIKE '%=powershell+%' OR rawEventMsg LIKE '%=tasklist\%%' OR rawEventMsg LIKE '%=tasklist+%' OR rawEventMsg LIKE '%=wmic\%%' OR rawEventMsg LIKE '%=wmic+%' OR rawEventMsg LIKE '%=ssh\%%' OR rawEventMsg LIKE '%=ssh+%' OR rawEventMsg LIKE '%=python\%%' OR rawEventMsg LIKE '%=python+%' OR rawEventMsg LIKE '%=python3\%%' OR rawEventMsg LIKE '%=python3+%' OR rawEventMsg LIKE '%=ipconfig%' OR rawEventMsg LIKE '%=wget\%%' OR rawEventMsg LIKE '%=wget+%' OR rawEventMsg LIKE '%=curl\%%' OR rawEventMsg LIKE '%=curl+%' OR rawEventMsg LIKE '%=certutil%' OR rawEventMsg LIKE '%=copy\%20\%5C\%5C%' OR rawEventMsg LIKE '%=dsquery\%%' OR rawEventMsg LIKE '%=dsquery+%' OR rawEventMsg LIKE '%=nltest\%%' OR rawEventMsg LIKE '%=nltest+%'
  AND rawEventMsg = 'GET')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Web sites like wikis with articles on os commands and pages that include the os commands in the URLs; User searches in search boxes of the respective website

**References:**
- https://bad-jubies.github.io/RCE-NOW-WHAT/
- https://m365internals.com/2022/10/07/hunting-in-on-premises-exchange-server-logs/

---

## Cross Site Scripting Strings

| Field | Value |
|---|---|
| **Sigma ID** | `65354b83-a2ea-4ea6-8414-3ab38be0d409` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1189 |
| **Author** | Saw Win Naung, Nasreddine Bencherchali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_xss_in_access_logs.yml)**

> Detects XSS attempts injected via GET requests in access logs

```sql
-- ============================================================
-- Title:        Cross Site Scripting Strings
-- Sigma ID:     65354b83-a2ea-4ea6-8414-3ab38be0d409
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1189
-- Author:       Saw Win Naung, Nasreddine Bencherchali
-- Date:         2021-08-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_xss_in_access_logs.yml
-- Unmapped:     cs-method, sc-status
-- False Pos:    JavaScripts,CSS Files and PNG files; User searches in search boxes of the respective website; Internal vulnerability scanners can cause some serious FPs when used, if you experience a lot of FPs due to this think of adding more filters such as "User Agent" strings and more response codes
-- ============================================================
-- UNMAPPED_LOGSOURCE: webserver
-- UNMAPPED_FIELD: cs-method
-- UNMAPPED_FIELD: sc-status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'GET'
  AND rawEventMsg LIKE '%=<script>%' OR rawEventMsg LIKE '%=\%3Cscript\%3E%' OR rawEventMsg LIKE '%=\%253Cscript\%253E%' OR rawEventMsg LIKE '%<iframe %' OR rawEventMsg LIKE '%\%3Ciframe %' OR rawEventMsg LIKE '%<svg %' OR rawEventMsg LIKE '%\%3Csvg %' OR rawEventMsg LIKE '%document.cookie%' OR rawEventMsg LIKE '%document.domain%' OR rawEventMsg LIKE '% onerror=%' OR rawEventMsg LIKE '% onresize=%' OR rawEventMsg LIKE '% onload="%' OR rawEventMsg LIKE '%onmouseover=%' OR rawEventMsg LIKE '%${alert%' OR rawEventMsg LIKE '%javascript:alert%' OR rawEventMsg LIKE '%javascript\%3Aalert%'
  AND NOT (rawEventMsg = '404'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** JavaScripts,CSS Files and PNG files; User searches in search boxes of the respective website; Internal vulnerability scanners can cause some serious FPs when used, if you experience a lot of FPs due to this think of adding more filters such as "User Agent" strings and more response codes

**References:**
- https://github.com/payloadbox/xss-payload-list
- https://portswigger.net/web-security/cross-site-scripting/contexts

---
