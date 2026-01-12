from fastapi import FastAPI, Depends, HTTPException
from sqlmodel import Session, select
from database import create_db_and_tables, get_session
from models import User
from auth import create_access_token, get_current_user
import hashlib

app = FastAPI()

# ---------- STARTUP ----------
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# ---------- HOME ----------
@app.get("/")
def home():
    return {"message": "Backend is running successfully"}

# ---------- SIGNUP ----------
@app.post("/signup")
def signup(user: User, session: Session = Depends(get_session)):
    existing_user = session.exec(
        select(User).where(User.email == user.email)
    ).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    user.password = hashlib.sha256(user.password.encode()).hexdigest()

    session.add(user)
    session.commit()
    session.refresh(user)

    return {"message": "User registered successfully"}

# ---------- LOGIN ----------
@app.post("/login")
def login(email: str, password: str, session: Session = Depends(get_session)):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    user = session.exec(
        select(User).where(User.email == email)
    ).first()

    if not user or user.password != hashed_password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"user_id": user.id})

    return {"accessToken": token}

# ---------- PROFILE (PROTECTED) ----------
@app.post("/profile")
def profile(
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    user_id = current_user.get("user_id")
    user = session.get(User, user_id)

    return {
        "id": user.id,
        "name": user.name,
        "email": user.email
    }
