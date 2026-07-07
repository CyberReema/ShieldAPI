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




---

## Vulnerability 2: IDOR / BOLA

### Endpoint

```http
GET /orders/{order_id}
```

### Description

The `/orders/{order_id}` endpoint exposes order data based only on the order ID in the URL.

A user can change the order ID and access another user's order.

Example:

```text
http://127.0.0.1:8000/orders/1001
http://127.0.0.1:8000/orders/1002
```

### Why This Is Dangerous

The API does not check:

- Whether the user is logged in
- Whether the user owns the requested order
- Whether the user is allowed to access that order

Because of this, an attacker can guess or change order IDs and view data that does not belong to them.

### Example Response

```json
{
  "warning": "This endpoint is intentionally vulnerable.",
  "issue": "Order data is exposed without checking ownership.",
  "order_id": 1002,
  "order": {
    "owner": "admin",
    "item": "Security Server",
    "price": 12000,
    "status": "processing"
  }
}
```

### Security Category

IDOR / BOLA  
Broken Object Level Authorization

### Future Fix

Later, this endpoint should check:

- The logged-in user's identity
- The owner of the order
- Whether the user has permission to view that order