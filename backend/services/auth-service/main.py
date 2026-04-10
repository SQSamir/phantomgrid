import os
import uuid
import hmac
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, Header
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.db import get_db
from backend.shared.models.user import User
from backend.shared.redis_client import get_redis
from backend.shared.schemas.auth import RegisterRequest, LoginRequest, TokenResponse

app = FastAPI(title="auth-service")
pwd = CryptContext(schemes=["argon2"], deprecated="auto")

PRIVATE_KEY_PATH = os.getenv("JWT_PRIVATE_KEY_PATH", "/run/secrets/jwt_private.pem")
PUBLIC_KEY_PATH = os.getenv("JWT_PUBLIC_KEY_PATH", "/run/secrets/jwt_public.pem")
FALLBACK_SECRET = os.getenv("JWT_SECRET", "dev-secret")


def _jwt_material():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
            priv = f.read()
        with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
            pub = f.read()
        return "RS256", priv, pub
    return "HS256", FALLBACK_SECRET, FALLBACK_SECRET


def _now():
    return datetime.now(timezone.utc)


def _access_claims(user: User):
    now = _now()
    return {
        "sub": str(user.id),
        "tid": str(user.tenant_id),
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
        "jti": str(uuid.uuid4()),
    }


def _refresh_claims(user: User):
    now = _now()
    return {
        "sub": str(user.id),
        "tid": str(user.tenant_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=7)).timestamp()),
        "jti": str(uuid.uuid4()),
        "typ": "refresh",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/auth/register")
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    exists = await db.scalar(select(User).where(User.email == req.email))
    if exists:
        raise HTTPException(409, "email exists")
    u = User(
        tenant_id=uuid.uuid4(),
        email=req.email,
        password_hash=pwd.hash(req.password),
        role="tenant_admin",
        display_name=req.display_name,
    )
    db.add(u)
    await db.commit()
    return {"id": str(u.id), "email": u.email}


@app.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    u = await db.scalar(select(User).where(User.email == req.email))
    fail = "invalid credentials"
    if not u:
        raise HTTPException(401, fail)

    if u.locked_until and u.locked_until > _now():
        raise HTTPException(423, "account locked")

    ok = hmac.compare_digest(str(pwd.verify(req.password, u.password_hash)), "True")
    if not ok:
        u.failed_login_attempts = (u.failed_login_attempts or 0) + 1
        if u.failed_login_attempts >= 5:
            u.locked_until = _now() + timedelta(minutes=15)
        await db.commit()
        raise HTTPException(401, fail)

    u.failed_login_attempts = 0
    u.locked_until = None
    u.last_login_at = _now()
    await db.commit()

    algo, sign_key, _ = _jwt_material()
    access_claims = _access_claims(u)
    refresh_claims = _refresh_claims(u)
    access = jwt.encode(access_claims, sign_key, algorithm=algo)
    refresh = jwt.encode(refresh_claims, sign_key, algorithm=algo)

    r = get_redis()
    await r.setex(f"refresh:{refresh_claims['jti']}", 7 * 24 * 3600, str(u.id))
    return TokenResponse(access_token=access, refresh_token=refresh)


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(payload: dict):
    refresh = payload.get("refresh_token")
    if not refresh:
        raise HTTPException(400, "missing refresh_token")

    algo, _, verify_key = _jwt_material()
    try:
        claims = jwt.decode(refresh, verify_key, algorithms=[algo])
    except JWTError:
        raise HTTPException(401, "invalid refresh token")

    if claims.get("typ") != "refresh":
        raise HTTPException(401, "invalid token type")

    jti = claims.get("jti")
    r = get_redis()
    exists = await r.get(f"refresh:{jti}")
    if not exists:
        raise HTTPException(401, "refresh token already used or revoked")

    await r.delete(f"refresh:{jti}")

    uid = claims.get("sub")
    tid = claims.get("tid")
    role = "tenant_admin"
    now = _now()
    new_access_claims = {
        "sub": uid,
        "tid": tid,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    new_refresh_claims = {
        "sub": uid,
        "tid": tid,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=7)).timestamp()),
        "jti": str(uuid.uuid4()),
        "typ": "refresh",
    }
    algo, sign_key, _ = _jwt_material()
    access = jwt.encode(new_access_claims, sign_key, algorithm=algo)
    new_refresh = jwt.encode(new_refresh_claims, sign_key, algorithm=algo)
    await r.setex(f"refresh:{new_refresh_claims['jti']}", 7 * 24 * 3600, uid)
    return TokenResponse(access_token=access, refresh_token=new_refresh)


@app.post("/auth/logout")
async def logout(payload: dict):
    refresh = payload.get("refresh_token")
    if refresh:
        algo, _, verify_key = _jwt_material()
        try:
            claims = jwt.decode(refresh, verify_key, algorithms=[algo])
            jti = claims.get("jti")
            if jti:
                await get_redis().delete(f"refresh:{jti}")
        except Exception:
            pass
    return {"ok": True}


@app.get("/auth/me")
async def me(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.replace("Bearer ", "", 1)
    algo, _, verify_key = _jwt_material()
    try:
        claims = jwt.decode(token, verify_key, algorithms=[algo])
    except JWTError:
        raise HTTPException(401, "invalid token")
    return {
        "sub": claims.get("sub"),
        "tenant_id": claims.get("tid"),
        "role": claims.get("role"),
        "exp": claims.get("exp"),
    }
