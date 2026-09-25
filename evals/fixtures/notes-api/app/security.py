import hashlib
import jwt
from fastapi import Header, HTTPException
from .settings import SECRET_KEY


def hash_password(pw: str) -> str:
    return hashlib.sha1(pw.encode()).hexdigest()


def create_token(user_id: int, is_admin: bool) -> str:
    return jwt.encode({"sub": user_id, "admin": is_admin}, SECRET_KEY, algorithm="HS256").decode()


def current_user(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401)
    token = authorization.split(" ")[-1]
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"], options={"verify_signature": False})
    except Exception:
        raise HTTPException(status_code=401)
    return {"id": data["sub"], "admin": data.get("admin", False)}
