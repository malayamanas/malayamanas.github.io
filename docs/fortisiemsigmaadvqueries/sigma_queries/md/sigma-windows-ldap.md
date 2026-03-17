# Sigma → FortiSIEM: Windows Ldap

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Potential Active Directory Reconnaissance/Enumeration Via LDAP](#potential-active-directory-reconnaissanceenumeration-via-ldap)

## Potential Active Directory Reconnaissance/Enumeration Via LDAP

| Field | Value |
|---|---|
| **Sigma ID** | `31d68132-4038-47c7-8f8e-635a39a7c174` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.002, T1087.002, T1482 |
| **Author** | Adeem Mawani |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/ldap/win_ldap_recon.yml)**

> Detects potential Active Directory enumeration via LDAP

```sql
-- ============================================================
-- Title:        Potential Active Directory Reconnaissance/Enumeration Via LDAP
-- Sigma ID:     31d68132-4038-47c7-8f8e-635a39a7c174
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1069.002, T1087.002, T1482
-- Author:       Adeem Mawani
-- Date:         2021-06-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/ldap/win_ldap_recon.yml
-- Unmapped:     SearchFilter, DistinguishedName
-- False Pos:    (none)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ldap
-- UNMAPPED_FIELD: SearchFilter
-- UNMAPPED_FIELD: DistinguishedName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '30'
    AND (rawEventMsg LIKE '%(groupType:1.2.840.113556.1.4.803:=2147483648)%' OR rawEventMsg LIKE '%(groupType:1.2.840.113556.1.4.803:=2147483656)%' OR rawEventMsg LIKE '%(groupType:1.2.840.113556.1.4.803:=2147483652)%' OR rawEventMsg LIKE '%(groupType:1.2.840.113556.1.4.803:=2147483650)%' OR rawEventMsg LIKE '%(sAMAccountType=805306369)%' OR rawEventMsg LIKE '%(sAMAccountType=805306368)%' OR rawEventMsg LIKE '%(sAMAccountType=536870913)%' OR rawEventMsg LIKE '%(sAMAccountType=536870912)%' OR rawEventMsg LIKE '%(sAMAccountType=268435457)%' OR rawEventMsg LIKE '%(sAMAccountType=268435456)%' OR rawEventMsg LIKE '%(objectCategory=groupPolicyContainer)%' OR rawEventMsg LIKE '%(objectCategory=organizationalUnit)%' OR rawEventMsg LIKE '%(objectCategory=nTDSDSA)%' OR rawEventMsg LIKE '%(objectCategory=server)%' OR rawEventMsg LIKE '%(objectCategory=domain)%' OR rawEventMsg LIKE '%(objectCategory=person)%' OR rawEventMsg LIKE '%(objectCategory=group)%' OR rawEventMsg LIKE '%(objectCategory=user)%' OR rawEventMsg LIKE '%(objectClass=trustedDomain)%' OR rawEventMsg LIKE '%(objectClass=computer)%' OR rawEventMsg LIKE '%(objectClass=server)%' OR rawEventMsg LIKE '%(objectClass=group)%' OR rawEventMsg LIKE '%(objectClass=user)%' OR rawEventMsg LIKE '%(primaryGroupID=521)%' OR rawEventMsg LIKE '%(primaryGroupID=516)%' OR rawEventMsg LIKE '%(primaryGroupID=515)%' OR rawEventMsg LIKE '%(primaryGroupID=512)%' OR rawEventMsg LIKE '%Domain Admins%' OR rawEventMsg LIKE '%objectGUID=\\*%' OR rawEventMsg LIKE '%(schemaIDGUID=\\*)%' OR rawEventMsg LIKE '%admincount=1%'))
  AND NOT ((winEventId = '30'
    AND (rawEventMsg LIKE '%(domainSid=*)%' OR rawEventMsg LIKE '%(objectSid=*)%'))))
  OR (winEventId = '30'
    AND (rawEventMsg LIKE '%(userAccountControl:1.2.840.113556.1.4.803:=4194304)%' OR rawEventMsg LIKE '%(userAccountControl:1.2.840.113556.1.4.803:=2097152)%' OR rawEventMsg LIKE '%!(userAccountControl:1.2.840.113556.1.4.803:=1048574)%' OR rawEventMsg LIKE '%(userAccountControl:1.2.840.113556.1.4.803:=524288)%' OR rawEventMsg LIKE '%(userAccountControl:1.2.840.113556.1.4.803:=65536)%' OR rawEventMsg LIKE '%(userAccountControl:1.2.840.113556.1.4.803:=8192)%' OR rawEventMsg LIKE '%(userAccountControl:1.2.840.113556.1.4.803:=544)%' OR rawEventMsg LIKE '%!(UserAccountControl:1.2.840.113556.1.4.803:=2)%' OR rawEventMsg LIKE '%msDS-AllowedToActOnBehalfOfOtherIdentity%' OR rawEventMsg LIKE '%msDS-AllowedToDelegateTo%' OR rawEventMsg LIKE '%msDS-GroupManagedServiceAccount%' OR rawEventMsg LIKE '%(accountExpires=9223372036854775807)%' OR rawEventMsg LIKE '%(accountExpires=0)%' OR rawEventMsg LIKE '%(adminCount=1)%' OR rawEventMsg LIKE '%ms-MCS-AdmPwd%'))
  OR (winEventId = '30'
    AND rawEventMsg = '(objectclass=\*)'
    AND (rawEventMsg LIKE '%CN=Domain Admins%' OR rawEventMsg LIKE '%CN=Enterprise Admins%' OR rawEventMsg LIKE '%CN=Group Policy Creator Owners%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-reconnaissance-activities-using-ldap-search-filters/ba-p/824726
- https://github.com/PowerShellMafia/PowerSploit/blob/d943001a7defb5e0d1657085a77a0e78609be58f/Recon/PowerView.ps1
- https://github.com/BloodHoundAD/SharpHound3/blob/7d96b991b1887ff50349ce59c80980bc0d95c86a/SharpHound3/LdapBuilder.cs
- https://medium.com/falconforce/falconfriday-detecting-active-directory-data-collection-0xff21-c22d1a57494c
- https://github.com/fox-it/BloodHound.py/blob/d65eb614831cd30f26028ccb072f5e77ca287e0b/bloodhound/ad/domain.py#L427
- https://ipurple.team/2024/07/15/sharphound-detection/

---
