import os
import uuid
import hmac
from datetime import datetime, timedelta, timezone

import pyotp
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
REQUIRE_RS256 = os.getenv("REQUIRE_RS256", "false").lower() == "true"
FALLBACK_SECRET = os.getenv("JWT_SECRET", "dev-secret")


class TotpRequest(dict):
    pass


def _jwt_material():
    has_rs = os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)
    if has_rs:
        with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
            priv = f.read()
        with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
            pub = f.read()
        return "RS256", priv, pub

    if REQUIRE_RS256:
        raise RuntimeError("RS256 required but key files not present")

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


def _verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


async def _token_from_authz(authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    return authorization.replace("Bearer ", "", 1)


async def _decode_access(token: str):
    algo, _, verify_key = _jwt_material()
    try:
        return jwt.decode(token, verify_key, algorithms=[algo])
    except JWTError:
        raise HTTPException(401, "invalid token")


@app.get("/health")
async def health():
    # fail fast if RS256 required but not mounted
    if REQUIRE_RS256 and (not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH)):
        raise HTTPException(500, "RS256 key files missing")
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

    # MFA gate
    if u.mfa_enabled:
        if not req.otp:
            raise HTTPException(401, "mfa required")
        # replay prevention per user+TOTP time-step
        timestep = int(_now().timestamp() // 30)
        replay_key = f"mfa:replay:{u.id}:{timestep}:{req.otp}"
        r = get_redis()
        if await r.get(replay_key):
            raise HTTPException(401, "otp replay detected")
        if not _verify_totp(u.mfa_secret or "", req.otp):
            raise HTTPException(401, "invalid otp")
        await r.setex(replay_key, 120, "1")

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
    token = await _token_from_authz(authorization)
    claims = await _decode_access(token)
    return {
        "sub": claims.get("sub"),
        "tenant_id": claims.get("tid"),
        "role": claims.get("role"),
        "exp": claims.get("exp"),
    }


@app.post("/auth/mfa/setup")
async def mfa_setup(authorization: str = Header(default=""), db: AsyncSession = Depends(get_db)):
    token = await _token_from_authz(authorization)
    claims = await _decode_access(token)
    uid = claims.get("sub")
    u = await db.scalar(select(User).where(User.id == uid))
    if not u:
        raise HTTPException(404, "user not found")

    secret = pyotp.random_base32()
    r = get_redis()
    await r.setex(f"mfa:pending:{u.id}", 600, secret)
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=u.email, issuer_name="PHANTOMGRID")
    return {"secret": secret, "otpauth_url": uri}


@app.post("/auth/mfa/confirm")
async def mfa_confirm(payload: dict, authorization: str = Header(default=""), db: AsyncSession = Depends(get_db)):
    token = await _token_from_authz(authorization)
    claims = await _decode_access(token)
    uid = claims.get("sub")
    code = payload.get("otp")

    u = await db.scalar(select(User).where(User.id == uid))
    if not u:
        raise HTTPException(404, "user not found")

    r = get_redis()
    secret = await r.get(f"mfa:pending:{u.id}")
    if not secret:
        raise HTTPException(400, "mfa setup not initiated or expired")

    if not _verify_totp(secret, code):
        raise HTTPException(401, "invalid otp")

    u.mfa_secret = secret
    u.mfa_enabled = True
    await db.commit()
    await r.delete(f"mfa:pending:{u.id}")
    return {"ok": True, "mfa_enabled": True}


@app.post("/auth/mfa/verify")
async def mfa_verify(payload: dict, db: AsyncSession = Depends(get_db)):
    # step-up endpoint for clients that separate password and otp phases
    email = payload.get("email")
    code = payload.get("otp")
    if not email or not code:
        raise HTTPException(400, "email and otp required")

    u = await db.scalar(select(User).where(User.email == email))
    if not u or not u.mfa_enabled:
        raise HTTPException(404, "mfa not enabled")

    timestep = int(_now().timestamp() // 30)
    replay_key = f"mfa:replay:{u.id}:{timestep}:{code}"
    r = get_redis()
    if await r.get(replay_key):
        raise HTTPException(401, "otp replay detected")

    if not _verify_totp(u.mfa_secret or "", code):
        raise HTTPException(401, "invalid otp")

    await r.setex(replay_key, 120, "1")
    return {"ok": True}
