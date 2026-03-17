# Sigma → FortiSIEM: M365 Exchange

> 1 rule · Generated 2026-03-17

## Table of Contents

- [New Federated Domain Added - Exchange](#new-federated-domain-added-exchange)

## New Federated Domain Added - Exchange

| Field | Value |
|---|---|
| **Sigma ID** | `42127bdd-9133-474f-a6f1-97b6c08a4339` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.003 |
| **Author** | Splunk Threat Research Team (original rule), '@ionsor (rule)' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/exchange/microsoft365_new_federated_domain_added_exchange.yml)**

> Detects the addition of a new Federated Domain.

```sql
-- ============================================================
-- Title:        New Federated Domain Added - Exchange
-- Sigma ID:     42127bdd-9133-474f-a6f1-97b6c08a4339
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1136.003
-- Author:       Splunk Threat Research Team (original rule), '@ionsor (rule)'
-- Date:         2022-02-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/exchange/microsoft365_new_federated_domain_added_exchange.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    The creation of a new Federated domain is not necessarily malicious, however these events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities at a similar or different cloud provider.
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/exchange
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Exchange'
    AND rawEventMsg = 'Add-FederatedDomain'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** The creation of a new Federated domain is not necessarily malicious, however these events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities at a similar or different cloud provider.

**References:**
- https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf
- https://us-cert.cisa.gov/ncas/alerts/aa21-008a
- https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html
- https://www.sygnia.co/golden-saml-advisory
- https://o365blog.com/post/aadbackdoor/

---
