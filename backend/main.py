from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="ShieldAPI",
    description="A vulnerable API lab and security scanner project.",
    version="2.0.0"
)


class LoginRequest(BaseModel):
    username: str
    password: str


fake_users = {
    "admin": {
        "password": "admin123",
        "role": "admin",
        "token": "admin-token-123"
    },
    "reema": {
        "password": "student123",
        "role": "user",
        "token": "reema-token-123"
    }
}

fake_tokens = {
    "admin-token-123": "admin",
    "reema-token-123": "reema"
}

fake_orders = {
    1001: {
        "owner": "reema",
        "item": "Laptop",
        "price": 4500,
        "status": "shipped"
    },
    1002: {
        "owner": "admin",
        "item": "Security Server",
        "price": 12000,
        "status": "processing"
    },
    1003: {
        "owner": "guest",
        "item": "USB Drive",
        "price": 80,
        "status": "delivered"
    }
}


def get_current_user(authorization: str = Header(default="")):
    """
    Simple educational token check.

    This is not production authentication.
    It is used only to demonstrate how authorization checks fix
    the vulnerable endpoints in this lab.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header"
        )

    token = authorization.replace("Bearer ", "", 1).strip()
    username = fake_tokens.get(token)

    if not username:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    user = fake_users[username]

    return {
        "username": username,
        "role": user["role"]
    }


@app.get("/")
def home():
    return {
        "message": "ShieldAPI backend is running",
        "project": "API Security Scanner + Vulnerable API Lab",
        "version": "2.0.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok"
    }


@app.post("/login")
def login(request: LoginRequest):
    user = fake_users.get(request.username)

    if not user:
        return {
            "success": False,
            "message": "Invalid username or password"
        }

    if request.password != user["password"]:
        return {
            "success": False,
            "message": "Invalid username or password"
        }

    return {
        "success": True,
        "message": "Login successful",
        "username": request.username,
        "role": user["role"],
        "token": user["token"]
    }


# -------------------------------------------------------------------
# Vulnerable endpoints
# These endpoints are intentionally insecure for security testing.
# -------------------------------------------------------------------

@app.get("/admin/users")
def get_all_users():
    return {
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


@app.get("/orders/{order_id}")
def get_order(order_id: int):
    order = fake_orders.get(order_id)

    if not order:
        return {
            "success": False,
            "message": "Order not found"
        }

    return {
        "warning": "This endpoint is intentionally vulnerable.",
        "issue": "Order data is exposed without checking ownership.",
        "order_id": order_id,
        "order": order
    }


@app.get("/debug/config")
def debug_config():
    return {
        "warning": "This endpoint is intentionally vulnerable.",
        "issue": "Sensitive configuration data is exposed.",
        "environment": "development",
        "database_url": "FAKE_DATABASE_URL_FOR_LAB_ONLY",
        "api_key": "FAKE_API_KEY_FOR_LAB_ONLY",
        "jwt_secret": "FAKE_JWT_SECRET_FOR_LAB_ONLY",
        "admin_email": "admin@shieldapi.local"
    }


# -------------------------------------------------------------------
# Secure endpoints
# These endpoints demonstrate how the vulnerable behavior can be fixed.
# -------------------------------------------------------------------

@app.get("/secure/admin/users")
def secure_get_all_users(authorization: str = Header(default="")):
    current_user = get_current_user(authorization)

    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin role required"
        )

    return {
        "message": "Authorized admin access granted.",
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


@app.get("/secure/orders/{order_id}")
def secure_get_order(order_id: int, authorization: str = Header(default="")):
    current_user = get_current_user(authorization)
    order = fake_orders.get(order_id)

    if not order:
        raise HTTPException(
            status_code=404,
            detail="Order not found"
        )

    is_admin = current_user["role"] == "admin"
    is_owner = order["owner"] == current_user["username"]

    if not is_admin and not is_owner:
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to access this order"
        )

    return {
        "message": "Authorized order access granted.",
        "order_id": order_id,
        "order": order
    }


@app.get("/secure/debug/config")
def secure_debug_config(authorization: str = Header(default="")):
    current_user = get_current_user(authorization)

    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin role required"
        )

    return {
        "message": "Sensitive configuration values are protected.",
        "environment": "development",
        "debug_mode": False,
        "secrets_exposed": False
    }