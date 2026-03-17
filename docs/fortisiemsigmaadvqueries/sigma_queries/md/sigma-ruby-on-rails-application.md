# Sigma → FortiSIEM: Ruby_On_Rails Application

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Ruby on Rails Framework Exceptions](#ruby-on-rails-framework-exceptions)

## Ruby on Rails Framework Exceptions

| Field | Value |
|---|---|
| **Sigma ID** | `0d2c3d4c-4b48-4ac3-8f23-ea845746bb1a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | Thomas Patzke |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/ruby/appframework_ruby_on_rails_exceptions.yml)**

> Detects suspicious Ruby on Rails exceptions that could indicate exploitation attempts

```sql
-- ============================================================
-- Title:        Ruby on Rails Framework Exceptions
-- Sigma ID:     0d2c3d4c-4b48-4ac3-8f23-ea845746bb1a
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1190
-- Author:       Thomas Patzke
-- Date:         2017-08-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/ruby/appframework_ruby_on_rails_exceptions.yml
-- Unmapped:     (none)
-- False Pos:    Application bugs
-- ============================================================
-- UNMAPPED_LOGSOURCE: ruby_on_rails/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%ActionController::InvalidAuthenticityToken%' OR rawEventMsg LIKE '%ActionController::InvalidCrossOriginRequest%' OR rawEventMsg LIKE '%ActionController::MethodNotAllowed%' OR rawEventMsg LIKE '%ActionController::BadRequest%' OR rawEventMsg LIKE '%ActionController::ParameterMissing%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application bugs

**References:**
- http://edgeguides.rubyonrails.org/security.html
- http://guides.rubyonrails.org/action_controller_overview.html
- https://stackoverflow.com/questions/25892194/does-rails-come-with-a-not-authorized-exception
- https://github.com/rails/rails/blob/cd08e6bcc4cd8948fe01e0be1ea0c7ca60373a25/actionpack/lib/action_dispatch/middleware/exception_wrapper.rb

---
