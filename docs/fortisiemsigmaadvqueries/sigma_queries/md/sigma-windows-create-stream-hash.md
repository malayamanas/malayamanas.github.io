# Sigma → FortiSIEM: Windows Create Stream Hash

> 9 rules · Generated 2026-03-17

## Table of Contents

- [Hidden Executable In NTFS Alternate Data Stream](#hidden-executable-in-ntfs-alternate-data-stream)
- [Creation Of a Suspicious ADS File Outside a Browser Download](#creation-of-a-suspicious-ads-file-outside-a-browser-download)
- [Suspicious File Download From File Sharing Websites -  File Stream](#suspicious-file-download-from-file-sharing-websites-file-stream)
- [Unusual File Download From File Sharing Websites - File Stream](#unusual-file-download-from-file-sharing-websites-file-stream)
- [HackTool Named File Stream Created](#hacktool-named-file-stream-created)
- [Exports Registry Key To an Alternate Data Stream](#exports-registry-key-to-an-alternate-data-stream)
- [Unusual File Download from Direct IP Address](#unusual-file-download-from-direct-ip-address)
- [Potential Suspicious Winget Package Installation](#potential-suspicious-winget-package-installation)
- [Potentially Suspicious File Download From ZIP TLD](#potentially-suspicious-file-download-from-zip-tld)

## Hidden Executable In NTFS Alternate Data Stream

| Field | Value |
|---|---|
| **Sigma ID** | `b69888d4-380c-45ce-9cf9-d9ce46e67821` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1564.004 |
| **Author** | Florian Roth (Nextron Systems), @0xrawsec |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_ads_executable.yml)**

> Detects the creation of an ADS (Alternate Data Stream) that contains an executable by looking at a non-empty Imphash

```sql
-- ============================================================
-- Title:        Hidden Executable In NTFS Alternate Data Stream
-- Sigma ID:     b69888d4-380c-45ce-9cf9-d9ce46e67821
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1564.004
-- Author:       Florian Roth (Nextron Systems), @0xrawsec
-- Date:         2018-06-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_ads_executable.yml
-- Unmapped:     Hash
-- False Pos:    This rule isn't looking for any particular binary characteristics. As legitimate installers and programs were seen embedding hidden binaries in their ADS. Some false positives are expected from browser processes and similar.
-- ============================================================
-- UNMAPPED_FIELD: Hash

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-15-FileCreateStreamHash')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%IMPHASH=%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This rule isn't looking for any particular binary characteristics. As legitimate installers and programs were seen embedding hidden binaries in their ADS. Some false positives are expected from browser processes and similar.

**References:**
- https://twitter.com/0xrawsec/status/1002478725605273600?s=21

---

## Creation Of a Suspicious ADS File Outside a Browser Download

| Field | Value |
|---|---|
| **Sigma ID** | `573df571-a223-43bc-846e-3f98da481eca` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_creation_internet_file.yml)**

> Detects the creation of a suspicious ADS (Alternate Data Stream) file by software other than browsers

```sql
-- ============================================================
-- Title:        Creation Of a Suspicious ADS File Outside a Browser Download
-- Sigma ID:     573df571-a223-43bc-846e-3f98da481eca
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       frack113
-- Date:         2022-10-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_creation_internet_file.yml
-- Unmapped:     Contents
-- False Pos:    Other legitimate browsers not currently included in the filter (please add them); Legitimate downloads via scripting or command-line tools (Investigate to determine if it's legitimate)
-- ============================================================
-- UNMAPPED_FIELD: Contents

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-15-FileCreateStreamHash')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '[ZoneTransfer]  ZoneId=3%'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:Zone.Identifier')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.scr%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmd%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docx%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jse%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.lnk%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pptx%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.reg%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sct%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vb%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wsc%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wsf%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsx%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other legitimate browsers not currently included in the filter (please add them); Legitimate downloads via scripting or command-line tools (Investigate to determine if it's legitimate)

**References:**
- https://www.bleepingcomputer.com/news/security/exploited-windows-zero-day-lets-javascript-files-bypass-security-warnings/

---

## Suspicious File Download From File Sharing Websites -  File Stream

| Field | Value |
|---|---|
| **Sigma ID** | `52182dfb-afb7-41db-b4bc-5336cb29b464` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1564.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_file_sharing_domains_download_susp_extension.yml)**

> Detects the download of suspicious file type from a well-known file and paste sharing domain

```sql
-- ============================================================
-- Title:        Suspicious File Download From File Sharing Websites -  File Stream
-- Sigma ID:     52182dfb-afb7-41db-b4bc-5336cb29b464
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1564.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_file_sharing_domains_download_susp_extension.yml
-- Unmapped:     Contents
-- False Pos:    Some false positives might occur with binaries download via Github
-- ============================================================
-- UNMAPPED_FIELD: Contents

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-15-FileCreateStreamHash')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%.githubusercontent.com%' OR rawEventMsg LIKE '%anonfiles.com%' OR rawEventMsg LIKE '%cdn.discordapp.com%' OR rawEventMsg LIKE '%ddns.net%' OR rawEventMsg LIKE '%dl.dropboxusercontent.com%' OR rawEventMsg LIKE '%ghostbin.co%' OR rawEventMsg LIKE '%github.com%' OR rawEventMsg LIKE '%glitch.me%' OR rawEventMsg LIKE '%gofile.io%' OR rawEventMsg LIKE '%hastebin.com%' OR rawEventMsg LIKE '%mediafire.com%' OR rawEventMsg LIKE '%mega.nz%' OR rawEventMsg LIKE '%onrender.com%' OR rawEventMsg LIKE '%pages.dev%' OR rawEventMsg LIKE '%paste.ee%' OR rawEventMsg LIKE '%pastebin.com%' OR rawEventMsg LIKE '%pastebin.pl%' OR rawEventMsg LIKE '%pastetext.net%' OR rawEventMsg LIKE '%pixeldrain.com%' OR rawEventMsg LIKE '%privatlab.com%' OR rawEventMsg LIKE '%privatlab.net%' OR rawEventMsg LIKE '%send.exploit.in%' OR rawEventMsg LIKE '%sendspace.com%' OR rawEventMsg LIKE '%storage.googleapis.com%' OR rawEventMsg LIKE '%storjshare.io%' OR rawEventMsg LIKE '%supabase.co%' OR rawEventMsg LIKE '%temp.sh%' OR rawEventMsg LIKE '%transfer.sh%' OR rawEventMsg LIKE '%trycloudflare.com%' OR rawEventMsg LIKE '%ufile.io%' OR rawEventMsg LIKE '%w3spaces.com%' OR rawEventMsg LIKE '%workers.dev%')
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cpl:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.lnk:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.one:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xll:Zone%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some false positives might occur with binaries download via Github

**References:**
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015
- https://www.cisa.gov/uscert/ncas/alerts/aa22-321a
- https://fabian-voith.de/2020/06/25/sysmon-v11-1-reads-alternate-data-streams/
- https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/

---

## Unusual File Download From File Sharing Websites - File Stream

| Field | Value |
|---|---|
| **Sigma ID** | `ae02ed70-11aa-4a22-b397-c0d0e8f6ea99` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1564.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_file_sharing_domains_download_unusual_extension.yml)**

> Detects the download of suspicious file type from a well-known file and paste sharing domain

```sql
-- ============================================================
-- Title:        Unusual File Download From File Sharing Websites - File Stream
-- Sigma ID:     ae02ed70-11aa-4a22-b397-c0d0e8f6ea99
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1564.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_file_sharing_domains_download_unusual_extension.yml
-- Unmapped:     Contents
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Contents

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-15-FileCreateStreamHash')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%.githubusercontent.com%' OR rawEventMsg LIKE '%anonfiles.com%' OR rawEventMsg LIKE '%cdn.discordapp.com%' OR rawEventMsg LIKE '%ddns.net%' OR rawEventMsg LIKE '%dl.dropboxusercontent.com%' OR rawEventMsg LIKE '%ghostbin.co%' OR rawEventMsg LIKE '%github.com%' OR rawEventMsg LIKE '%glitch.me%' OR rawEventMsg LIKE '%gofile.io%' OR rawEventMsg LIKE '%hastebin.com%' OR rawEventMsg LIKE '%mediafire.com%' OR rawEventMsg LIKE '%mega.nz%' OR rawEventMsg LIKE '%onrender.com%' OR rawEventMsg LIKE '%pages.dev%' OR rawEventMsg LIKE '%paste.ee%' OR rawEventMsg LIKE '%pastebin.com%' OR rawEventMsg LIKE '%pastebin.pl%' OR rawEventMsg LIKE '%pastetext.net%' OR rawEventMsg LIKE '%pixeldrain.com%' OR rawEventMsg LIKE '%privatlab.com%' OR rawEventMsg LIKE '%privatlab.net%' OR rawEventMsg LIKE '%send.exploit.in%' OR rawEventMsg LIKE '%sendspace.com%' OR rawEventMsg LIKE '%storage.googleapis.com%' OR rawEventMsg LIKE '%storjshare.io%' OR rawEventMsg LIKE '%supabase.co%' OR rawEventMsg LIKE '%temp.sh%' OR rawEventMsg LIKE '%transfer.sh%' OR rawEventMsg LIKE '%trycloudflare.com%' OR rawEventMsg LIKE '%ufile.io%' OR rawEventMsg LIKE '%w3spaces.com%' OR rawEventMsg LIKE '%workers.dev%')
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmd:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1:Zone%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015
- https://www.cisa.gov/uscert/ncas/alerts/aa22-321a
- https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/

---

## HackTool Named File Stream Created

| Field | Value |
|---|---|
| **Sigma ID** | `19b041f6-e583-40dc-b842-d6fa8011493f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1564.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_hktl_generic_download.yml)**

> Detects the creation of a named file stream with the imphash of a well-known hack tool

```sql
-- ============================================================
-- Title:        HackTool Named File Stream Created
-- Sigma ID:     19b041f6-e583-40dc-b842-d6fa8011493f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1564.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_hktl_generic_download.yml
-- Unmapped:     Hash
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Hash

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-15-FileCreateStreamHash')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%IMPHASH=BCCA3C247B619DCD13C8CDFF5F123932%' OR rawEventMsg LIKE '%IMPHASH=3A19059BD7688CB88E70005F18EFC439%' OR rawEventMsg LIKE '%IMPHASH=bf6223a49e45d99094406777eb6004ba%' OR rawEventMsg LIKE '%IMPHASH=0C106686A31BFE2BA931AE1CF6E9DBC6%' OR rawEventMsg LIKE '%IMPHASH=0D1447D4B3259B3C2A1D4CFB7ECE13C3%' OR rawEventMsg LIKE '%IMPHASH=1B0369A1E06271833F78FFA70FFB4EAF%' OR rawEventMsg LIKE '%IMPHASH=4C1B52A19748428E51B14C278D0F58E3%' OR rawEventMsg LIKE '%IMPHASH=4D927A711F77D62CEBD4F322CB57EC6F%' OR rawEventMsg LIKE '%IMPHASH=66EE036DF5FC1004D9ED5E9A94A1086A%' OR rawEventMsg LIKE '%IMPHASH=672B13F4A0B6F27D29065123FE882DFC%' OR rawEventMsg LIKE '%IMPHASH=6BBD59CEA665C4AFCC2814C1327EC91F%' OR rawEventMsg LIKE '%IMPHASH=725BB81DC24214F6ECACC0CFB36AD30D%' OR rawEventMsg LIKE '%IMPHASH=9528A0E91E28FBB88AD433FEABCA2456%' OR rawEventMsg LIKE '%IMPHASH=9DA6D5D77BE11712527DCAB86DF449A3%' OR rawEventMsg LIKE '%IMPHASH=A6E01BC1AB89F8D91D9EAB72032AAE88%' OR rawEventMsg LIKE '%IMPHASH=B24C5EDDAEA4FE50C6A96A2A133521E4%' OR rawEventMsg LIKE '%IMPHASH=D21BBC50DCC169D7B4D0F01962793154%' OR rawEventMsg LIKE '%IMPHASH=FCC251CCEAE90D22C392215CC9A2D5D6%' OR rawEventMsg LIKE '%IMPHASH=23867A89C2B8FC733BE6CF5EF902F2D1%' OR rawEventMsg LIKE '%IMPHASH=A37FF327F8D48E8A4D2F757E1B6E70BC%' OR rawEventMsg LIKE '%IMPHASH=F9A28C458284584A93B14216308D31BD%' OR rawEventMsg LIKE '%IMPHASH=6118619783FC175BC7EBECFF0769B46E%' OR rawEventMsg LIKE '%IMPHASH=959A83047E80AB68B368FDB3F4C6E4EA%' OR rawEventMsg LIKE '%IMPHASH=563233BFA169ACC7892451F71AD5850A%' OR rawEventMsg LIKE '%IMPHASH=87575CB7A0E0700EB37F2E3668671A08%' OR rawEventMsg LIKE '%IMPHASH=13F08707F759AF6003837A150A371BA1%' OR rawEventMsg LIKE '%IMPHASH=1781F06048A7E58B323F0B9259BE798B%' OR rawEventMsg LIKE '%IMPHASH=233F85F2D4BC9D6521A6CAAE11A1E7F5%' OR rawEventMsg LIKE '%IMPHASH=24AF2584CBF4D60BBE5C6D1B31B3BE6D%' OR rawEventMsg LIKE '%IMPHASH=632969DDF6DBF4E0F53424B75E4B91F2%' OR rawEventMsg LIKE '%IMPHASH=713C29B396B907ED71A72482759ED757%' OR rawEventMsg LIKE '%IMPHASH=749A7BB1F0B4C4455949C0B2BF7F9E9F%' OR rawEventMsg LIKE '%IMPHASH=8628B2608957A6B0C6330AC3DE28CE2E%' OR rawEventMsg LIKE '%IMPHASH=8B114550386E31895DFAB371E741123D%' OR rawEventMsg LIKE '%IMPHASH=94CB940A1A6B65BED4D5A8F849CE9793%' OR rawEventMsg LIKE '%IMPHASH=9D68781980370E00E0BD939EE5E6C141%' OR rawEventMsg LIKE '%IMPHASH=B18A1401FF8F444056D29450FBC0A6CE%' OR rawEventMsg LIKE '%IMPHASH=CB567F9498452721D77A451374955F5F%' OR rawEventMsg LIKE '%IMPHASH=730073214094CD328547BF1F72289752%' OR rawEventMsg LIKE '%IMPHASH=17B461A082950FC6332228572138B80C%' OR rawEventMsg LIKE '%IMPHASH=DC25EE78E2EF4D36FAA0BADF1E7461C9%' OR rawEventMsg LIKE '%IMPHASH=819B19D53CA6736448F9325A85736792%' OR rawEventMsg LIKE '%IMPHASH=829DA329CE140D873B4A8BDE2CBFAA7E%' OR rawEventMsg LIKE '%IMPHASH=C547F2E66061A8DFFB6F5A3FF63C0A74%' OR rawEventMsg LIKE '%IMPHASH=0588081AB0E63BA785938467E1B10CCA%' OR rawEventMsg LIKE '%IMPHASH=0D9EC08BAC6C07D9987DFD0F1506587C%' OR rawEventMsg LIKE '%IMPHASH=BC129092B71C89B4D4C8CDF8EA590B29%' OR rawEventMsg LIKE '%IMPHASH=4DA924CF622D039D58BCE71CDF05D242%' OR rawEventMsg LIKE '%IMPHASH=E7A3A5C377E2D29324093377D7DB1C66%' OR rawEventMsg LIKE '%IMPHASH=9A9DBEC5C62F0380B4FA5FD31DEFFEDF%' OR rawEventMsg LIKE '%IMPHASH=AF8A3976AD71E5D5FDFB67DDB8DADFCE%' OR rawEventMsg LIKE '%IMPHASH=0C477898BBF137BBD6F2A54E3B805FF4%' OR rawEventMsg LIKE '%IMPHASH=0CA9F02B537BCEA20D4EA5EB1A9FE338%' OR rawEventMsg LIKE '%IMPHASH=3AB3655E5A14D4EEFC547F4781BF7F9E%' OR rawEventMsg LIKE '%IMPHASH=E6F9D5152DA699934B30DAAB206471F6%' OR rawEventMsg LIKE '%IMPHASH=3AD59991CCF1D67339B319B15A41B35D%' OR rawEventMsg LIKE '%IMPHASH=FFDD59E0318B85A3E480874D9796D872%' OR rawEventMsg LIKE '%IMPHASH=0CF479628D7CC1EA25EC7998A92F5051%' OR rawEventMsg LIKE '%IMPHASH=07A2D4DCBD6CB2C6A45E6B101F0B6D51%' OR rawEventMsg LIKE '%IMPHASH=D6D0F80386E1380D05CB78E871BC72B1%' OR rawEventMsg LIKE '%IMPHASH=38D9E015591BBFD4929E0D0F47FA0055%' OR rawEventMsg LIKE '%IMPHASH=0E2216679CA6E1094D63322E3412D650%' OR rawEventMsg LIKE '%IMPHASH=ADA161BF41B8E5E9132858CB54CAB5FB%' OR rawEventMsg LIKE '%IMPHASH=2A1BC4913CD5ECB0434DF07CB675B798%' OR rawEventMsg LIKE '%IMPHASH=11083E75553BAAE21DC89CE8F9A195E4%' OR rawEventMsg LIKE '%IMPHASH=A23D29C9E566F2FA8FFBB79267F5DF80%' OR rawEventMsg LIKE '%IMPHASH=4A07F944A83E8A7C2525EFA35DD30E2F%' OR rawEventMsg LIKE '%IMPHASH=767637C23BB42CD5D7397CF58B0BE688%' OR rawEventMsg LIKE '%IMPHASH=14C4E4C72BA075E9069EE67F39188AD8%' OR rawEventMsg LIKE '%IMPHASH=3C782813D4AFCE07BBFC5A9772ACDBDC%' OR rawEventMsg LIKE '%IMPHASH=7D010C6BB6A3726F327F7E239166D127%' OR rawEventMsg LIKE '%IMPHASH=89159BA4DD04E4CE5559F132A9964EB3%' OR rawEventMsg LIKE '%IMPHASH=6F33F4A5FC42B8CEC7314947BD13F30F%' OR rawEventMsg LIKE '%IMPHASH=5834ED4291BDEB928270428EBBAF7604%' OR rawEventMsg LIKE '%IMPHASH=5A8A8A43F25485E7EE1B201EDCBC7A38%' OR rawEventMsg LIKE '%IMPHASH=DC7D30B90B2D8ABF664FBED2B1B59894%' OR rawEventMsg LIKE '%IMPHASH=41923EA1F824FE63EA5BEB84DB7A3E74%' OR rawEventMsg LIKE '%IMPHASH=3DE09703C8E79ED2CA3F01074719906B%' OR rawEventMsg LIKE '%IMPHASH=A53A02B997935FD8EEDCB5F7ABAB9B9F%' OR rawEventMsg LIKE '%IMPHASH=E96A73C7BF33A464C510EDE582318BF2%' OR rawEventMsg LIKE '%IMPHASH=32089B8851BBF8BC2D014E9F37288C83%' OR rawEventMsg LIKE '%IMPHASH=09D278F9DE118EF09163C6140255C690%' OR rawEventMsg LIKE '%IMPHASH=03866661686829d806989e2fc5a72606%' OR rawEventMsg LIKE '%IMPHASH=e57401fbdadcd4571ff385ab82bd5d6d%' OR rawEventMsg LIKE '%IMPHASH=84B763C45C0E4A3E7CA5548C710DB4EE%' OR rawEventMsg LIKE '%IMPHASH=19584675D94829987952432E018D5056%' OR rawEventMsg LIKE '%IMPHASH=330768A4F172E10ACB6287B87289D83B%' OR rawEventMsg LIKE '%IMPHASH=885C99CCFBE77D1CBFCB9C4E7C1A3313%' OR rawEventMsg LIKE '%IMPHASH=22A22BC9E4E0D2F189F1EA01748816AC%' OR rawEventMsg LIKE '%IMPHASH=7FA30E6BB7E8E8A69155636E50BF1B28%' OR rawEventMsg LIKE '%IMPHASH=96DF3A3731912449521F6F8D183279B1%' OR rawEventMsg LIKE '%IMPHASH=7E6CF3FF4576581271AC8A313B2AAB46%' OR rawEventMsg LIKE '%IMPHASH=51791678F351C03A0EB4E2A7B05C6E17%' OR rawEventMsg LIKE '%IMPHASH=25CE42B079282632708FC846129E98A5%' OR rawEventMsg LIKE '%IMPHASH=021BCCA20BA3381B11BDDE26B4E62F20%' OR rawEventMsg LIKE '%IMPHASH=59223B5F52D8799D38E0754855CBDF42%' OR rawEventMsg LIKE '%IMPHASH=81E75D8F1D276C156653D3D8813E4A43%' OR rawEventMsg LIKE '%IMPHASH=17244E8B6B8227E57FE709CCAD421420%' OR rawEventMsg LIKE '%IMPHASH=5B76DA3ACDEDC8A5CDF23A798B5936B4%' OR rawEventMsg LIKE '%IMPHASH=CB2B65BB77D995CC1C0E5DF1C860133C%' OR rawEventMsg LIKE '%IMPHASH=40445337761D80CF465136FAFB1F63E6%' OR rawEventMsg LIKE '%IMPHASH=8A790F401B29FA87BC1E56F7272B3AA6%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/gentilkiwi/mimikatz
- https://github.com/topotam/PetitPotam
- https://github.com/ohpe/juicy-potato
- https://github.com/antonioCoco/RoguePotato
- https://www.tarasco.org/security/pwdump_7/
- https://github.com/fortra/nanodump
- https://github.com/codewhitesec/HandleKatz
- https://github.com/xuanxuan0/DripLoader
- https://github.com/hfiref0x/UACME
- https://github.com/outflanknl/Dumpert
- https://github.com/wavestone-cdt/EDRSandblast

---

## Exports Registry Key To an Alternate Data Stream

| Field | Value |
|---|---|
| **Sigma ID** | `0d7a9363-af70-4e7b-a3b7-1a176b7fbe84` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1564.004 |
| **Author** | Oddvar Moe, Sander Wiebing, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_regedit_export_to_ads.yml)**

> Exports the target Registry key and hides it in the specified alternate data stream.

```sql
-- ============================================================
-- Title:        Exports Registry Key To an Alternate Data Stream
-- Sigma ID:     0d7a9363-af70-4e7b-a3b7-1a176b7fbe84
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1564.004
-- Author:       Oddvar Moe, Sander Wiebing, oscd.community
-- Date:         2020-10-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_regedit_export_to_ads.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-15-FileCreateStreamHash')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\regedit.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://lolbas-project.github.io/lolbas/Binaries/Regedit/
- https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f

---

## Unusual File Download from Direct IP Address

| Field | Value |
|---|---|
| **Sigma ID** | `025bd229-fd1f-4fdb-97ab-20006e1a5368` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1564.004 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_susp_ip_domains.yml)**

> Detects the download of suspicious file type from URLs with IP

```sql
-- ============================================================
-- Title:        Unusual File Download from Direct IP Address
-- Sigma ID:     025bd229-fd1f-4fdb-97ab-20006e1a5368
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1564.004
-- Author:       Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
-- Date:         2022-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_susp_ip_domains.yml
-- Unmapped:     Contents
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Contents

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-15-FileCreateStreamHash')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (match(rawEventMsg, 'http[s]?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.one:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmd:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xll:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.lnk:Zone%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/trustedsec/SysmonCommunityGuide/blob/adcdfee20999f422b974c8d4149bf4c361237db7/chapters/file-stream-creation-hash.md
- https://labs.withsecure.com/publications/detecting-onenote-abuse

---

## Potential Suspicious Winget Package Installation

| Field | Value |
|---|---|
| **Sigma ID** | `a3f5c081-e75b-43a0-9f5b-51f26fe5dba2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_winget_susp_package_source.yml)**

> Detects potential suspicious winget package installation from a suspicious source.

```sql
-- ============================================================
-- Title:        Potential Suspicious Winget Package Installation
-- Sigma ID:     a3f5c081-e75b-43a0-9f5b-51f26fe5dba2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_winget_susp_package_source.yml
-- Unmapped:     Contents
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Contents

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-15-FileCreateStreamHash')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '[ZoneTransfer]  ZoneId=3%'
    AND (rawEventMsg LIKE '%://1%' OR rawEventMsg LIKE '%://2%' OR rawEventMsg LIKE '%://3%' OR rawEventMsg LIKE '%://4%' OR rawEventMsg LIKE '%://5%' OR rawEventMsg LIKE '%://6%' OR rawEventMsg LIKE '%://7%' OR rawEventMsg LIKE '%://8%' OR rawEventMsg LIKE '%://9%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:Zone.Identifier')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\WinGet\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget

---

## Potentially Suspicious File Download From ZIP TLD

| Field | Value |
|---|---|
| **Sigma ID** | `0bb4bbeb-fe52-4044-b40c-430a04577ebe` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_zip_tld_download.yml)**

> Detects the download of a file with a potentially suspicious extension from a .zip top level domain.

```sql
-- ============================================================
-- Title:        Potentially Suspicious File Download From ZIP TLD
-- Sigma ID:     0bb4bbeb-fe52-4044-b40c-430a04577ebe
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2023-05-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_zip_tld_download.yml
-- Unmapped:     Contents
-- False Pos:    Legitimate file downloads from a websites and web services that uses the ".zip" top level domain.
-- ============================================================
-- UNMAPPED_FIELD: Contents

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-15-FileCreateStreamHash')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%.zip/%'
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dat:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.doc:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docm:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pptm:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.rar:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.rtf:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sct:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ws:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wsf:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xll:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xls:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsm:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.zip:Zone%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate file downloads from a websites and web services that uses the ".zip" top level domain.

**References:**
- https://twitter.com/cyb3rops/status/1659175181695287297
- https://fabian-voith.de/2020/06/25/sysmon-v11-1-reads-alternate-data-streams/

---
