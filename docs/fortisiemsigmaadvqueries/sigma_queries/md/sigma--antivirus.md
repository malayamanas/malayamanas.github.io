# Sigma → FortiSIEM:  Antivirus

> 6 rules · Generated 2026-03-17

## Table of Contents

- [Antivirus Exploitation Framework Detection](#antivirus-exploitation-framework-detection)
- [Antivirus Hacktool Detection](#antivirus-hacktool-detection)
- [Antivirus Password Dumper Detection](#antivirus-password-dumper-detection)
- [Antivirus Ransomware Detection](#antivirus-ransomware-detection)
- [Antivirus Relevant File Paths Alerts](#antivirus-relevant-file-paths-alerts)
- [Antivirus Web Shell Detection](#antivirus-web-shell-detection)

## Antivirus Exploitation Framework Detection

| Field | Value |
|---|---|
| **Sigma ID** | `238527ad-3c2c-4e4f-a1f6-92fd63adb864` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1203, T1219.002 |
| **Author** | Florian Roth (Nextron Systems), Arnim Rupp |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_exploiting.yml)**

> Detects a highly relevant Antivirus alert that reports an exploitation framework.
This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.


```sql
-- ============================================================
-- Title:        Antivirus Exploitation Framework Detection
-- Sigma ID:     238527ad-3c2c-4e4f-a1f6-92fd63adb864
-- Level:        critical  |  FSM Severity: 9
-- Status:       stable
-- MITRE:        execution | T1203, T1219.002
-- Author:       Florian Roth (Nextron Systems), Arnim Rupp
-- Date:         2018-09-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_exploiting.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: antivirus

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'signature')] AS signature,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'signature') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor.Cobalt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Brutel%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%BruteR%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%CobaltStr%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%CobaltStrike%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%COBEACON%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Cometer%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Exploit.Script.CVE%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%IISExchgSpawnCMD%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Metasploit%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Meterpreter%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%MeteTool%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Mpreter%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%MsfShell%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PowerSploit%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Razy%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Rozena%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Sbelt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Seatbelt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Sliver%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Swrort%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.nextron-systems.com/?s=antivirus
- https://www.virustotal.com/gui/file/925b0b28472d4d79b4bf92050e38cc2b8f722691c713fc28743ac38551bc3797
- https://www.virustotal.com/gui/file/8f8daabe1c8ceb5710949283818e16c4aa8059bf2ce345e2f2c90b8692978424
- https://www.virustotal.com/gui/file/d9669f7e3eb3a9cdf6a750eeb2ba303b5ae148a43e36546896f1d1801e912466

---

## Antivirus Hacktool Detection

| Field | Value |
|---|---|
| **Sigma ID** | `fa0c05b6-8ad3-468d-8231-c1cbccb64fba` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204 |
| **Author** | Florian Roth (Nextron Systems), Arnim Rupp |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_hacktool.yml)**

> Detects a highly relevant Antivirus alert that reports a hack tool or other attack tool.
This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.


```sql
-- ============================================================
-- Title:        Antivirus Hacktool Detection
-- Sigma ID:     fa0c05b6-8ad3-468d-8231-c1cbccb64fba
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        execution | T1204
-- Author:       Florian Roth (Nextron Systems), Arnim Rupp
-- Date:         2021-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_hacktool.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: antivirus

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'signature')] AS signature,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'signature') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'ATK/%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'Exploit.Script.CVE%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'HKTL%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'HTOOL%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'PWS.%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'PWSX%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'SecurityTool%')))
  OR ((indexOf(metrics_string.name, 'signature') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Adfind%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Brutel%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%BruteR%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Cobalt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%COBEACON%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Cometer%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%DumpCreds%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%FastReverseProxy%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Hacktool%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Havoc%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Impacket%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Keylogger%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Koadic%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Mimikatz%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Nighthawk%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PentestPowerShell%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Potato%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PowerSploit%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PowerSSH%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PshlSpy%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PSWTool%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PWCrack%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PWDump%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Rozena%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Rusthound%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Sbelt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Seatbelt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SecurityTool%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SharpDump%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SharpHound%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Shellcode%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Sliver%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Snaffler%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SOAPHound%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Splinter%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Swrort%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%TurtleLoader%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.nextron-systems.com/2021/08/16/antivirus-event-analysis-cheat-sheet-v1-8-2/
- https://www.nextron-systems.com/?s=antivirus

---

## Antivirus Password Dumper Detection

| Field | Value |
|---|---|
| **Sigma ID** | `78cc2dd2-7d20-4d32-93ff-057084c38b93` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1003, T1558, T1003.001, T1003.002 |
| **Author** | Florian Roth (Nextron Systems), Arnim Rupp |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_password_dumper.yml)**

> Detects a highly relevant Antivirus alert that reports a password dumper.
This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.


```sql
-- ============================================================
-- Title:        Antivirus Password Dumper Detection
-- Sigma ID:     78cc2dd2-7d20-4d32-93ff-057084c38b93
-- Level:        critical  |  FSM Severity: 9
-- Status:       stable
-- MITRE:        T1003, T1558, T1003.001, T1003.002
-- Author:       Florian Roth (Nextron Systems), Arnim Rupp
-- Date:         2018-09-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_password_dumper.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: antivirus

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'signature')] AS signature,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'signature') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'PWS%'))
  OR ((indexOf(metrics_string.name, 'signature') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Certify%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%DCSync%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%DumpCreds%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%DumpLsass%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%DumpPert%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%HTool/WCE%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Kekeo%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Lazagne%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%LsassDump%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Mimikatz%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%MultiDump%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Nanodump%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%NativeDump%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Outflank%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PShlSpy%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PSWTool%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PWCrack%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PWDump%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PWS.%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PWSX%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%pypykatz%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Rubeus%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SafetyKatz%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SecurityTool%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SharpChrome%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SharpDPAPI%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SharpDump%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SharpKatz%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SharpS.%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%ShpKatz%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%TrickDump%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.nextron-systems.com/?s=antivirus
- https://www.virustotal.com/gui/file/5fcda49ee7f202559a6cbbb34edb65c33c9a1e0bde9fa2af06a6f11b55ded619
- https://www.virustotal.com/gui/file/a4edfbd42595d5bddb442c82a02cf0aaa10893c1bf79ea08b9ce576f82749448

---

## Antivirus Ransomware Detection

| Field | Value |
|---|---|
| **Sigma ID** | `4c6ca276-d4d0-4a8c-9e4c-d69832f8671f` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1486 |
| **Author** | Florian Roth (Nextron Systems), Arnim Rupp |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_ransomware.yml)**

> Detects a highly relevant Antivirus alert that reports ransomware.
This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.


```sql
-- ============================================================
-- Title:        Antivirus Ransomware Detection
-- Sigma ID:     4c6ca276-d4d0-4a8c-9e4c-d69832f8671f
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        impact | T1486
-- Author:       Florian Roth (Nextron Systems), Arnim Rupp
-- Date:         2022-05-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_ransomware.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: antivirus

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'signature')] AS signature,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'signature') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%BlackWorm%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Chaos%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Cobra%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%ContiCrypt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Crypter%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%CRYPTES%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Cryptor%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%CylanCrypt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%DelShad%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Destructor%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Filecoder%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%GandCrab%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%GrandCrab%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Haperlock%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Hiddentear%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%HydraCrypt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Krypt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Lockbit%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Locker%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Mallox%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Phobos%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Ransom%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Ryuk%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Ryzerlo%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Stopcrypt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Tescrypt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%TeslaCrypt%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%WannaCry%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Xorist%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.nextron-systems.com/?s=antivirus
- https://www.virustotal.com/gui/file/43b0f7872900bd234975a0877744554f4f355dc57505517abd1ef611e1ce6916
- https://www.virustotal.com/gui/file/c312c05ddbd227cbb08958876df2b69d0f7c1b09e5689eb9d93c5b357f63eff7
- https://www.virustotal.com/gui/file/20179093c59bca3acc6ce9a4281e8462f577ffd29fd7bf51cf2a70d106062045
- https://www.virustotal.com/gui/file/554db97ea82f17eba516e6a6fdb9dc04b1d25580a1eb8cb755eeb260ad0bd61d
- https://www.virustotal.com/gui/file/69fe77dd558e281621418980040e2af89a2547d377d0f2875502005ce22bc95c
- https://www.virustotal.com/gui/file/6f0f20da34396166df352bf301b3c59ef42b0bc67f52af3d541b0161c47ede05

---

## Antivirus Relevant File Paths Alerts

| Field | Value |
|---|---|
| **Sigma ID** | `c9a88268-0047-4824-ba6e-4d81ce0b907c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1588 |
| **Author** | Florian Roth (Nextron Systems), Arnim Rupp |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_relevant_files.yml)**

> Detects an Antivirus alert in a highly relevant file path or with a relevant file name.
This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.


```sql
-- ============================================================
-- Title:        Antivirus Relevant File Paths Alerts
-- Sigma ID:     c9a88268-0047-4824-ba6e-4d81ce0b907c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1588
-- Author:       Florian Roth (Nextron Systems), Arnim Rupp
-- Date:         2018-09-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_relevant_files.yml
-- Unmapped:     Filename
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: antivirus
-- UNMAPPED_FIELD: Filename

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%.asax' OR rawEventMsg LIKE '%.ashx' OR rawEventMsg LIKE '%.asmx' OR rawEventMsg LIKE '%.asp' OR rawEventMsg LIKE '%.aspx' OR rawEventMsg LIKE '%.bat' OR rawEventMsg LIKE '%.cfm' OR rawEventMsg LIKE '%.cgi' OR rawEventMsg LIKE '%.chm' OR rawEventMsg LIKE '%.cmd' OR rawEventMsg LIKE '%.dat' OR rawEventMsg LIKE '%.ear' OR rawEventMsg LIKE '%.gif' OR rawEventMsg LIKE '%.hta' OR rawEventMsg LIKE '%.jpeg' OR rawEventMsg LIKE '%.jpg' OR rawEventMsg LIKE '%.jsp' OR rawEventMsg LIKE '%.jspx' OR rawEventMsg LIKE '%.lnk' OR rawEventMsg LIKE '%.msc' OR rawEventMsg LIKE '%.php' OR rawEventMsg LIKE '%.pl' OR rawEventMsg LIKE '%.png' OR rawEventMsg LIKE '%.ps1' OR rawEventMsg LIKE '%.psm1' OR rawEventMsg LIKE '%.py' OR rawEventMsg LIKE '%.pyc' OR rawEventMsg LIKE '%.rb' OR rawEventMsg LIKE '%.scf' OR rawEventMsg LIKE '%.sct' OR rawEventMsg LIKE '%.sh' OR rawEventMsg LIKE '%.svg' OR rawEventMsg LIKE '%.txt' OR rawEventMsg LIKE '%.vbe' OR rawEventMsg LIKE '%.vbs' OR rawEventMsg LIKE '%.war' OR rawEventMsg LIKE '%.wll' OR rawEventMsg LIKE '%.wsf' OR rawEventMsg LIKE '%.wsh' OR rawEventMsg LIKE '%.xll' OR rawEventMsg LIKE '%.xml')
  OR (rawEventMsg LIKE '%:\\PerfLogs\\%' OR rawEventMsg LIKE '%:\\Temp\\%' OR rawEventMsg LIKE '%:\\Users\\Default\\%' OR rawEventMsg LIKE '%:\\Users\\Public\\%' OR rawEventMsg LIKE '%:\\Windows\\%' OR rawEventMsg LIKE '%/www/%' OR rawEventMsg LIKE '%\\inetpub\\%' OR rawEventMsg LIKE '%\\tsclient\\%' OR rawEventMsg LIKE '%apache%' OR rawEventMsg LIKE '%nginx%' OR rawEventMsg LIKE '%tomcat%' OR rawEventMsg LIKE '%weblogic%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.nextron-systems.com/?s=antivirus

---

## Antivirus Web Shell Detection

| Field | Value |
|---|---|
| **Sigma ID** | `fdf135a2-9241-4f96-a114-bb404948f736` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Florian Roth (Nextron Systems), Arnim Rupp |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_webshell.yml)**

> Detects a highly relevant Antivirus alert that reports a web shell.
It's highly recommended to tune this rule to the specific strings used by your anti virus solution by downloading a big WebShell repository from e.g. github and checking the matches.
This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.


```sql
-- ============================================================
-- Title:        Antivirus Web Shell Detection
-- Sigma ID:     fdf135a2-9241-4f96-a114-bb404948f736
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Florian Roth (Nextron Systems), Arnim Rupp
-- Date:         2018-09-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/category/antivirus/av_webshell.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: antivirus

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'signature')] AS signature,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'signature') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'ASP.%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'IIS/BackDoor%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'JAVA/Backdoor%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'JSP.%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'Perl.%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'PHP.%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'Troj/ASP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'Troj/JSP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'Troj/PHP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE 'VBS/Uxor%')))
  OR ((indexOf(metrics_string.name, 'signature') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%ASP\_%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%ASP:%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%ASP.Agent%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%ASP/%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Aspdoor%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%ASPXSpy%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor.ASP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor.Java%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor.JSP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor.PHP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor.VBS%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor/ASP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor/Java%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor/JSP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor/PHP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Backdoor/VBS%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%C99shell%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Chopper%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%filebrowser%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%JSP\_%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%JSP:%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%JSP.Agent%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%JSP/%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Perl:%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Perl/%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PHP\_%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PHP:%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PHP.Agent%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PHP/%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PHPShell%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%PShlSpy%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%SinoChoper%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Trojan.ASP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Trojan.JSP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Trojan.PHP%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Trojan.VBS%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%VBS.Agent%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%VBS/Agent%' OR metrics_string.value[indexOf(metrics_string.name,'signature')] LIKE '%Webshell%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.nextron-systems.com/?s=antivirus
- https://github.com/tennc/webshell
- https://www.virustotal.com/gui/file/bd1d52289203866645e556e2766a21d2275877fbafa056a76fe0cf884b7f8819/detection
- https://www.virustotal.com/gui/file/308487ed28a3d9abc1fec7ebc812d4b5c07ab025037535421f64c60d3887a3e8/detection
- https://www.virustotal.com/gui/file/7d3cb8a8ff28f82b07f382789247329ad2d7782a72dde9867941f13266310c80/detection
- https://www.virustotal.com/gui/file/e841675a4b82250c75273ebf0861245f80c6a1c3d5803c2d995d9d3b18d5c4b5/detection
- https://www.virustotal.com/gui/file/a80042c61a0372eaa0c2c1e831adf0d13ef09feaf71d1d20b216156269045801/detection
- https://www.virustotal.com/gui/file/b219f7d3c26f8bad7e175934cd5eda4ddb5e3983503e94ff07d39c0666821b7e/detection
- https://www.virustotal.com/gui/file/b8702acf32fd651af9f809ed42d15135f842788cd98d81a8e1b154ee2a2b76a2/detection
- https://www.virustotal.com/gui/file/13ae8bfbc02254b389ab052aba5e1ba169b16a399d9bc4cb7414c4a73cd7dc78/detection

---
