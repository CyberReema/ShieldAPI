# ShieldAPI Security Scanner Report

Generated at: 2026-07-08 03:30:32

Target: `http://127.0.0.1:8000`

## Executive Summary

Total vulnerability findings: **3**

Secure endpoint controls tested: **6**

Secure endpoint controls passed: **6/6**

## Severity Summary

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 0 |
| Low | 0 |

## Findings

### Finding 1: Broken Access Control

**Severity:** High

**Endpoint:** `/admin/users`

**OWASP Mapping:** API5:2023 Broken Function Level Authorization

**Description:** Admin user data is accessible without authentication.

**Evidence:** HTTP 200 returned a users list without an Authorization header.

**Recommended Remediation:** Require authentication and verify that the requester has the admin role.

### Finding 2: IDOR / BOLA

**Severity:** High

**Endpoint:** `/orders/{order_id}`

**OWASP Mapping:** API1:2023 Broken Object Level Authorization

**Description:** Different users' order records can be accessed by changing the order ID.

**Evidence:** /orders/1001 returned owner 'reema' and /orders/1002 returned owner 'admin' without proving ownership.

**Recommended Remediation:** Check that the authenticated user owns the requested object or has an authorized admin role.

### Finding 3: Sensitive Data Exposure

**Severity:** Critical

**Endpoint:** `/debug/config`

**OWASP Mapping:** API8:2023 Security Misconfiguration

**Description:** Sensitive configuration keys are exposed in the API response.

**Evidence:** Exposed keys: database_url, api_key, jwt_secret

**Recommended Remediation:** Remove public debug/config endpoints and never return secrets in API responses.

## Secure Endpoint Validation

| Control | Endpoint | Expected | Observed | Result |
|---|---|---|---|---|
| Secure admin endpoint blocks unauthenticated access | `/secure/admin/users` | 401 or 403 | HTTP 401 | PASS |
| Secure admin endpoint blocks normal users | `/secure/admin/users` | 403 | HTTP 403 | PASS |
| Secure admin endpoint allows admin users | `/secure/admin/users` | 200 | HTTP 200 | PASS |
| Secure order endpoint allows object owner | `/secure/orders/1001` | 200 | HTTP 200 | PASS |
| Secure order endpoint blocks IDOR/BOLA | `/secure/orders/1002` | 403 | HTTP 403 | PASS |
| Secure config endpoint does not expose secrets | `/secure/debug/config` | No database_url, api_key, or jwt_secret in response | Exposed keys: none | PASS |

## Methodology

The scanner sends HTTP requests to intentionally vulnerable endpoints and checks whether sensitive data or unauthorized resources are returned.

The scanner also sends requests to secure endpoints to validate whether authentication, role-based authorization, object ownership checks, and secret protection are working as expected.

## Disclaimer

This project is for educational and defensive cybersecurity learning only. All vulnerabilities are intentionally created inside a local lab environment.