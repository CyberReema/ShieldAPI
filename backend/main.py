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