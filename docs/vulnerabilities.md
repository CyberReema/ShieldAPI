# ShieldAPI Vulnerability Notes

This file documents the intentional vulnerabilities inside the ShieldAPI lab.

---

## Vulnerability 1: Broken Access Control

### Endpoint

```http
GET /admin/users
```

### Description

The `/admin/users` endpoint exposes user data without requiring authentication or admin authorization.

Any visitor can access the endpoint directly through the browser:

```text
http://127.0.0.1:8000/admin/users
```

### Why This Is Dangerous

Admin endpoints should only be accessible to authenticated admin users.

In this vulnerable version, the API does not check:

- Whether the user is logged in
- Whether the user has a valid token
- Whether the user has the `admin` role

Because of this, sensitive user data can be exposed.

### Example Response

```json
{
  "warning": "This endpoint is intentionally vulnerable.",
  "issue": "Admin data is exposed without authentication.",
  "users": [
    {
      "username": "admin",
      "role": "admin"
    },
    {
      "username": "reema",
      "role": "user"
    }
  ]
}
```

### Security Category

Broken Access Control

### Future Fix

Later, this endpoint should require:

- Login authentication
- A valid access token
- Admin role authorization