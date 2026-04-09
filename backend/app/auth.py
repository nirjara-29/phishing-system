from fastapi import APIRouter

router = APIRouter()

# ✅ Register endpoint
@router.post("/register")
def register():
    return {"message": "User registered successfully"}

# ✅ Login endpoint
@router.post("/login")
def login():
    return {"token": "demo-token"}