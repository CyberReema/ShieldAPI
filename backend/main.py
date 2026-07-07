from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="ShieldAPI",
    description="A vulnerable API lab and security scanner project.",
    version="1.0.0"
)


class LoginRequest(BaseModel):
    username: str
    password: str


fake_users = {
    "admin": {
        "password": "admin123",
        "role": "admin"
    },
    "reema": {
        "password": "student123",
        "role": "user"
    }
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


@app.get("/")
def home():
    return {
        "message": "ShieldAPI backend is running",
        "project": "API Security Scanner + Vulnerable API Lab"
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
        "role": user["role"]
    }





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