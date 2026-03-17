# Sigma → FortiSIEM: Github Audit

> 15 rules · Generated 2026-03-17

## Table of Contents

- [Github Delete Action Invoked](#github-delete-action-invoked)
- [Github High Risk Configuration Disabled](#github-high-risk-configuration-disabled)
- [Outdated Dependency Or Vulnerability Alert Disabled](#outdated-dependency-or-vulnerability-alert-disabled)
- [Github Fork Private Repositories Setting Enabled/Cleared](#github-fork-private-repositories-setting-enabledcleared)
- [New Github Organization Member Added](#new-github-organization-member-added)
- [Github New Secret Created](#github-new-secret-created)
- [Github Outside Collaborator Detected](#github-outside-collaborator-detected)
- [GitHub Repository Pages Site Changed to Public](#github-repository-pages-site-changed-to-public)
- [Github Push Protection Bypass Detected](#github-push-protection-bypass-detected)
- [Github Push Protection Disabled](#github-push-protection-disabled)
- [Github Repository/Organization Transferred](#github-repositoryorganization-transferred)
- [GitHub Repository Archive Status Changed](#github-repository-archive-status-changed)
- [Github Secret Scanning Feature Disabled](#github-secret-scanning-feature-disabled)
- [Github Self Hosted Runner Changes Detected](#github-self-hosted-runner-changes-detected)
- [Github SSH Certificate Configuration Changed](#github-ssh-certificate-configuration-changed)

## Github Delete Action Invoked

| Field | Value |
|---|---|
| **Sigma ID** | `16a71777-0b2e-4db7-9888-9d59cb75200b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact, collection |
| **MITRE Techniques** | T1213.003 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_delete_action_invoked.yml)**

> Detects delete action in the Github audit logs for codespaces, environment, project and repo.

```sql
-- ============================================================
-- Title:        Github Delete Action Invoked
-- Sigma ID:     16a71777-0b2e-4db7-9888-9d59cb75200b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact, collection | T1213.003
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2023-01-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_delete_action_invoked.yml
-- Unmapped:     action
-- False Pos:    Validate the deletion activity is permitted. The "actor" field need to be validated.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('codespaces.delete', 'environment.delete', 'project.delete', 'repo.destroy')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Validate the deletion activity is permitted. The "actor" field need to be validated.

**References:**
- https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#audit-log-actions

---

## Github High Risk Configuration Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `8622c92d-c00e-463c-b09d-fd06166f6794` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_disable_high_risk_configuration.yml)**

> Detects when a user disables a critical security feature for an organization.

```sql
-- ============================================================
-- Title:        Github High Risk Configuration Disabled
-- Sigma ID:     8622c92d-c00e-463c-b09d-fd06166f6794
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1556
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2023-01-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_disable_high_risk_configuration.yml
-- Unmapped:     action
-- False Pos:    Approved administrator/owner activities.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('business_advanced_security.disabled_for_new_repos', 'business_advanced_security.disabled_for_new_user_namespace_repos', 'business_advanced_security.disabled', 'business_advanced_security.user_namespace_repos_disabled', 'org.advanced_security_disabled_for_new_repos', 'org.advanced_security_disabled_on_all_repos', 'org.advanced_security_policy_selected_member_disabled', 'org.disable_oauth_app_restrictions', 'org.disable_two_factor_requirement', 'repo.advanced_security_disabled')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Approved administrator/owner activities.

**References:**
- https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/disabling-oauth-app-access-restrictions-for-your-organization
- https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#dependabot_alerts-category-actions
- https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-security-and-analysis-settings-for-your-repository
- https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise

---

## Outdated Dependency Or Vulnerability Alert Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `34e1c7d4-0cd5-419d-9f1b-1dad3f61018d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1195.001 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_disabled_outdated_dependency_or_vulnerability.yml)**

> Dependabot performs a scan to detect insecure dependencies, and sends Dependabot alerts.
This rule detects when an organization owner disables Dependabot alerts private repositories or Dependabot security updates for all repositories.


```sql
-- ============================================================
-- Title:        Outdated Dependency Or Vulnerability Alert Disabled
-- Sigma ID:     34e1c7d4-0cd5-419d-9f1b-1dad3f61018d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1195.001
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2023-01-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_disabled_outdated_dependency_or_vulnerability.yml
-- Unmapped:     action
-- False Pos:    Approved changes by the Organization owner. Please validate the 'actor' if authorized to make the changes.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('dependabot_alerts_new_repos.disable', 'dependabot_alerts.disable', 'dependabot_security_updates_new_repos.disable', 'dependabot_security_updates.disable', 'repository_vulnerability_alerts.disable')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Approved changes by the Organization owner. Please validate the 'actor' if authorized to make the changes.

**References:**
- https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts
- https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/managing-security-and-analysis-settings-for-your-organization

---

## Github Fork Private Repositories Setting Enabled/Cleared

| Field | Value |
|---|---|
| **Sigma ID** | `69b3bd1e-b38a-462f-9a23-fbdbf63d2294` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, exfiltration |
| **MITRE Techniques** | T1020, T1537 |
| **Author** | Romain Gaillard (@romain-gaillard) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_fork_private_repos_enabled_or_cleared.yml)**

> Detects when the policy allowing forks of private and internal repositories is changed (enabled or cleared).


```sql
-- ============================================================
-- Title:        Github Fork Private Repositories Setting Enabled/Cleared
-- Sigma ID:     69b3bd1e-b38a-462f-9a23-fbdbf63d2294
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, exfiltration | T1020, T1537
-- Author:       Romain Gaillard (@romain-gaillard)
-- Date:         2024-07-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_fork_private_repos_enabled_or_cleared.yml
-- Unmapped:     action
-- False Pos:    Allowed administrative activities.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('private_repository_forking.clear', 'private_repository_forking.enable')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Allowed administrative activities.

**References:**
- https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise#private_repository_forking

---

## New Github Organization Member Added

| Field | Value |
|---|---|
| **Sigma ID** | `3908d64a-3c06-4091-b503-b3a94424533b` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.003 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_new_org_member.yml)**

> Detects when a new member is added or invited to a github organization.

```sql
-- ============================================================
-- Title:        New Github Organization Member Added
-- Sigma ID:     3908d64a-3c06-4091-b503-b3a94424533b
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1136.003
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2023-01-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_new_org_member.yml
-- Unmapped:     action
-- False Pos:    Organization approved new members
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('org.add_member', 'org.invite_member')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Organization approved new members

**References:**
- https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#dependabot_alerts-category-actions

---

## Github New Secret Created

| Field | Value |
|---|---|
| **Sigma ID** | `f9405037-bc97-4eb7-baba-167dad399b83` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_new_secret_created.yml)**

> Detects when a user creates action secret for the organization, environment, codespaces or repository.

```sql
-- ============================================================
-- Title:        Github New Secret Created
-- Sigma ID:     f9405037-bc97-4eb7-baba-167dad399b83
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2023-01-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_new_secret_created.yml
-- Unmapped:     action
-- False Pos:    This detection cloud be noisy depending on the environment. It is recommended to keep a check on the new secrets when created and validate the "actor".
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('codespaces.create_an_org_secret', 'environment.create_actions_secret', 'org.create_actions_secret', 'repo.create_actions_secret')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This detection cloud be noisy depending on the environment. It is recommended to keep a check on the new secrets when created and validate the "actor".

**References:**
- https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#audit-log-actions

---

## Github Outside Collaborator Detected

| Field | Value |
|---|---|
| **Sigma ID** | `eaa9ac35-1730-441f-9587-25767bde99d7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, collection |
| **MITRE Techniques** | T1098.001, T1098.003, T1213.003 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_outside_collaborator_detected.yml)**

> Detects when an organization member or an outside collaborator is added to or removed from a project board or has their permission level changed or when an owner removes an outside collaborator from an organization or when two-factor authentication is required in an organization and an outside collaborator does not use 2FA or disables 2FA.


```sql
-- ============================================================
-- Title:        Github Outside Collaborator Detected
-- Sigma ID:     eaa9ac35-1730-441f-9587-25767bde99d7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, collection | T1098.001, T1098.003, T1213.003
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2023-01-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_outside_collaborator_detected.yml
-- Unmapped:     action
-- False Pos:    Validate the actor if permitted to access the repo.; Validate the Multifactor Authentication changes.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('org.remove_outside_collaborator', 'project.update_user_permission')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Validate the actor if permitted to access the repo.; Validate the Multifactor Authentication changes.

**References:**
- https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#audit-log-actions
- https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization

---

## GitHub Repository Pages Site Changed to Public

| Field | Value |
|---|---|
| **Sigma ID** | `0c46d4f4-a2bf-4104-9597-8d653fc2bb55` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection, exfiltration |
| **MITRE Techniques** | T1567.001 |
| **Author** | Ivan Saakov |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_pages_site_changed_to_public.yml)**

> Detects when a GitHub Pages site of a repository is made public. This usually is part of a publishing process but could indicate or lead to potential unauthorized exposure of sensitive information or code.


```sql
-- ============================================================
-- Title:        GitHub Repository Pages Site Changed to Public
-- Sigma ID:     0c46d4f4-a2bf-4104-9597-8d653fc2bb55
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        collection, exfiltration | T1567.001
-- Author:       Ivan Saakov
-- Date:         2025-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_pages_site_changed_to_public.yml
-- Unmapped:     action
-- False Pos:    Legitimate publishing of repository pages by authorized users
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'repo.pages_public'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate publishing of repository pages by authorized users

**References:**
- https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site
- https://www.sentinelone.com/blog/exploiting-repos-6-ways-threat-actors-abuse-github-other-devops-platforms
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events

---

## Github Push Protection Bypass Detected

| Field | Value |
|---|---|
| **Sigma ID** | `02cf536a-cf21-4876-8842-4159c8aee3cc` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_push_protection_bypass_detected.yml)**

> Detects when a user bypasses the push protection on a secret detected by secret scanning.

```sql
-- ============================================================
-- Title:        Github Push Protection Bypass Detected
-- Sigma ID:     02cf536a-cf21-4876-8842-4159c8aee3cc
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-03-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_push_protection_bypass_detected.yml
-- Unmapped:     action
-- False Pos:    Allowed administrative activities.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%secret\_scanning\_push\_protection.bypass%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Allowed administrative activities.

**References:**
- https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/push-protection-for-repositories-and-organizations
- https://thehackernews.com/2024/03/github-rolls-out-default-secret.html

---

## Github Push Protection Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `ccd55945-badd-4bae-936b-823a735d37dd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_push_protection_disabled.yml)**

> Detects if the push protection feature is disabled for an organization, enterprise, repositories or custom pattern rules.

```sql
-- ============================================================
-- Title:        Github Push Protection Disabled
-- Sigma ID:     ccd55945-badd-4bae-936b-823a735d37dd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-03-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_push_protection_disabled.yml
-- Unmapped:     action
-- False Pos:    Allowed administrative activities.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('business_secret_scanning_custom_pattern_push_protection.disabled', 'business_secret_scanning_push_protection.disable', 'business_secret_scanning_push_protection.disabled_for_new_repos', 'org.secret_scanning_custom_pattern_push_protection_disabled', 'org.secret_scanning_push_protection_disable', 'org.secret_scanning_push_protection_new_repos_disable', 'repository_secret_scanning_custom_pattern_push_protection.disabled')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Allowed administrative activities.

**References:**
- https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/push-protection-for-repositories-and-organizations
- https://thehackernews.com/2024/03/github-rolls-out-default-secret.html

---

## Github Repository/Organization Transferred

| Field | Value |
|---|---|
| **Sigma ID** | `04ad83ef-1a37-4c10-b57a-81092164bf33` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, exfiltration |
| **MITRE Techniques** | T1020, T1537 |
| **Author** | Romain Gaillard (@romain-gaillard) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_repo_or_org_transferred.yml)**

> Detects when a repository or an organization is being transferred to another location.

```sql
-- ============================================================
-- Title:        Github Repository/Organization Transferred
-- Sigma ID:     04ad83ef-1a37-4c10-b57a-81092164bf33
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, exfiltration | T1020, T1537
-- Author:       Romain Gaillard (@romain-gaillard)
-- Date:         2024-07-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_repo_or_org_transferred.yml
-- Unmapped:     action
-- False Pos:    Allowed administrative activities.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('migration.create', 'org.transfer_outgoing', 'org.transfer', 'repo.transfer_outgoing')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Allowed administrative activities.

**References:**
- https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository
- https://docs.github.com/en/organizations/managing-organization-settings/transferring-organization-ownership
- https://docs.github.com/en/migrations
- https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise#migration

---

## GitHub Repository Archive Status Changed

| Field | Value |
|---|---|
| **Sigma ID** | `dca8991c-cb16-4128-abf8-6b11e5cd156f` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence, impact |
| **Author** | Ivan Saakov |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_repository_archive_status_changed.yml)**

> Detects when a GitHub repository is archived or unarchived, which may indicate unauthorized changes to repository status.


```sql
-- ============================================================
-- Title:        GitHub Repository Archive Status Changed
-- Sigma ID:     dca8991c-cb16-4128-abf8-6b11e5cd156f
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        persistence, impact
-- Author:       Ivan Saakov
-- Date:         2025-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_repository_archive_status_changed.yml
-- Unmapped:     action
-- False Pos:    Archiving or unarchiving a repository is often legitimate. Investigate this action to determine if it was authorized.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('repo.archived', 'repo.unarchived')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Archiving or unarchiving a repository is often legitimate. Investigate this action to determine if it was authorized.

**References:**
- https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories
- https://www.sentinelone.com/blog/exploiting-repos-6-ways-threat-actors-abuse-github-other-devops-platforms
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events

---

## Github Secret Scanning Feature Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `3883d9a0-fd0f-440f-afbb-445a2a799bb8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_secret_scanning_feature_disabled.yml)**

> Detects if the secret scanning feature is disabled for an enterprise or repository.

```sql
-- ============================================================
-- Title:        Github Secret Scanning Feature Disabled
-- Sigma ID:     3883d9a0-fd0f-440f-afbb-445a2a799bb8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-03-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_secret_scanning_feature_disabled.yml
-- Unmapped:     action
-- False Pos:    Allowed administrative activities.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('business_secret_scanning.disable', 'business_secret_scanning.disabled_for_new_repos', 'repository_secret_scanning.disable', 'secret_scanning_new_repos.disable', 'secret_scanning.disable')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Allowed administrative activities.

**References:**
- https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/about-secret-scanning

---

## Github Self Hosted Runner Changes Detected

| Field | Value |
|---|---|
| **Sigma ID** | `f8ed0e8f-7438-4b79-85eb-f358ef2fbebd` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact, discovery, collection, persistence |
| **MITRE Techniques** | T1526, T1213.003, T1078.004 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_self_hosted_runner_changes_detected.yml)**

> A self-hosted runner is a system that you deploy and manage to execute jobs from GitHub Actions on GitHub.com.
This rule detects changes to self-hosted runners configurations in the environment. The self-hosted runner configuration changes once detected,
it should be validated from GitHub UI because the log entry may not provide full context.


```sql
-- ============================================================
-- Title:        Github Self Hosted Runner Changes Detected
-- Sigma ID:     f8ed0e8f-7438-4b79-85eb-f358ef2fbebd
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact, discovery, collection, persistence | T1526, T1213.003, T1078.004
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2023-01-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_self_hosted_runner_changes_detected.yml
-- Unmapped:     action
-- False Pos:    Allowed self-hosted runners changes in the environment.; A self-hosted runner is automatically removed from GitHub if it has not connected to GitHub Actions for more than 14 days.; An ephemeral self-hosted runner is automatically removed from GitHub if it has not connected to GitHub Actions for more than 1 day.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('org.remove_self_hosted_runner', 'org.runner_group_created', 'org.runner_group_removed', 'org.runner_group_runner_removed', 'org.runner_group_runners_added', 'org.runner_group_runners_updated', 'org.runner_group_updated', 'repo.register_self_hosted_runner', 'repo.remove_self_hosted_runner')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Allowed self-hosted runners changes in the environment.; A self-hosted runner is automatically removed from GitHub if it has not connected to GitHub Actions for more than 14 days.; An ephemeral self-hosted runner is automatically removed from GitHub if it has not connected to GitHub Actions for more than 1 day.

**References:**
- https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners#about-self-hosted-runners
- https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#search-based-on-operation

---

## Github SSH Certificate Configuration Changed

| Field | Value |
|---|---|
| **Sigma ID** | `2f575940-d85e-4ddc-af13-17dad6f1a0ef` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Romain Gaillard (@romain-gaillard) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_ssh_certificate_config_changed.yml)**

> Detects when changes are made to the SSH certificate configuration of the organization.

```sql
-- ============================================================
-- Title:        Github SSH Certificate Configuration Changed
-- Sigma ID:     2f575940-d85e-4ddc-af13-17dad6f1a0ef
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Romain Gaillard (@romain-gaillard)
-- Date:         2024-07-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_ssh_certificate_config_changed.yml
-- Unmapped:     action
-- False Pos:    Allowed administrative activities.
-- ============================================================
-- UNMAPPED_LOGSOURCE: github/audit
-- UNMAPPED_FIELD: action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('ssh_certificate_authority.create', 'ssh_certificate_requirement.disable')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Allowed administrative activities.

**References:**
- https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-git-access-to-your-organizations-repositories/about-ssh-certificate-authorities
- https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise#ssh_certificate_authority

---
