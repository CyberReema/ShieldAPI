# ShieldAPI Security Scanner Report

Generated at: 2026-07-08 02:59:15

## Summary

Total findings: 3

## Finding 1: Broken Access Control

**Severity:** High

**Endpoint:** `/admin/users`

**Description:** Admin user data is accessible without authentication.

## Finding 2: IDOR / BOLA

**Severity:** High

**Endpoint:** `/orders/{order_id}`

**Description:** Different order records can be accessed by changing the order ID without proving ownership.

## Finding 3: Sensitive Data Exposure

**Severity:** Critical

**Endpoint:** `/debug/config`

**Description:** Sensitive keys exposed in API response: database_url, api_key, jwt_secret
