import asyncio
import os
import secrets
import uuid
import hmac
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, Depends, HTTPException, Header
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.db import get_db
from backend.shared.models.tenant import Tenant
from backend.shared.models.user import User
from backend.shared.redis_client import get_redis
from backend.shared.schemas.auth import RegisterRequest, LoginRequest, TokenResponse

app = FastAPI(title="auth-service")
pwd = CryptContext(schemes=["argon2"], deprecated="auto")

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)

# ---------------------------------------------------------------------------
# JWT signing material — validated once at startup, cached in memory
# ---------------------------------------------------------------------------
PRIVATE_KEY_PATH = os.getenv("JWT_PRIVATE_KEY_PATH", "/run/secrets/jwt_private.pem")
PUBLIC_KEY_PATH = os.getenv("JWT_PUBLIC_KEY_PATH", "/run/secrets/jwt_public.pem")
REQUIRE_RS256 = os.getenv("REQUIRE_RS256", "false").lower() == "true"
_JWT_SECRET_ENV = os.getenv("JWT_SECRET", "")

_has_rs256_keys = os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)
if not _has_rs256_keys:
    if not _JWT_SECRET_ENV:
        raise RuntimeError(
            "No JWT signing material found. "
            "Mount RS256 key files or set JWT_SECRET (minimum 32 characters)."
        )
    if len(_JWT_SECRET_ENV) < 32:
        raise RuntimeError(f"JWT_SECRET is too short ({len(_JWT_SECRET_ENV)} chars). Minimum 32.")

FALLBACK_SECRET = _JWT_SECRET_ENV


@lru_cache(maxsize=1)
def _jwt_material():
    """Load JWT keys once; cached for the process lifetime."""
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
            priv = f.read()
        with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
            pub = f.read()
        return "RS256", priv, pub
    if REQUIRE_RS256:
        raise RuntimeError("RS256 required but key files not present")
    return "HS256", FALLBACK_SECRET, FALLBACK_SECRET


# ---------------------------------------------------------------------------
# MFA secret encryption
# ---------------------------------------------------------------------------
_MFA_ENC_KEY = os.getenv("MFA_ENCRYPTION_KEY", "")
if not _MFA_ENC_KEY:
    raise RuntimeError(
        "MFA_ENCRYPTION_KEY not set. "
        "Generate: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )
try:
    _fernet = Fernet(_MFA_ENC_KEY.encode() if isinstance(_MFA_ENC_KEY, str) else _MFA_ENC_KEY)
except Exception as exc:
    raise RuntimeError(f"MFA_ENCRYPTION_KEY is not a valid Fernet key: {exc}") from exc

_BACKUP_CODE_COUNT = 8
_BACKUP_CODE_LEN = 10


def _encrypt_mfa_secret(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode()).decode()


def _decrypt_mfa_secret(ciphertext: str) -> str:
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("failed to decrypt MFA secret") from exc


def _generate_backup_codes() -> tuple[list[str], list[str]]:
    plain = [secrets.token_hex(_BACKUP_CODE_LEN // 2) for _ in range(_BACKUP_CODE_COUNT)]
    hashed = [pwd.hash(code) for code in plain]
    return plain, hashed


def _verify_backup_code(code: str, hashed_codes: list[str]) -> int | None:
    for i, h in enumerate(hashed_codes):
        try:
            if pwd.verify(code, h):
                return i
        except Exception:
            continue
    return None


def _verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


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


async def _hash_password(password: str) -> str:
    """Run argon2 hashing in a thread pool so it doesn't block the event loop."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, pwd.hash, password)


async def _verify_password(password: str, hashed: str) -> bool:
    """Run argon2 verification in a thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, pwd.verify, password, hashed)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    if REQUIRE_RS256 and (not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH)):
        raise HTTPException(500, "RS256 key files missing")
    return {"status": "ok"}


def _registration_enabled(tenant_config: dict) -> bool:
    """Return True unless admin has explicitly disabled registration."""
    return tenant_config.get("registration_enabled", True)


@app.post("/auth/register")
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Self-registration check: if ANY tenant has disabled registration we refuse.
    # (For a fresh install with no tenants yet the check passes.)
    # We check a global Redis flag set by the first tenant's admin.
    r = get_redis()
    reg_disabled = await r.get("global:registration_disabled")
    if reg_disabled == "1":
        raise HTTPException(403, "registration is disabled — contact your administrator")

    exists = await db.scalar(select(User).where(User.email == req.email))
    if exists:
        raise HTTPException(409, "email exists")

    # Create a new tenant for this registration
    tenant = Tenant(name=req.display_name or req.email.split("@")[0])
    db.add(tenant)
    await db.flush()

    hashed = await _hash_password(req.password)
    u = User(
        tenant_id=tenant.id,
        email=req.email,
        password_hash=hashed,
        role="tenant_admin",
        display_name=req.display_name,
    )
    db.add(u)
    await db.commit()
    return {"id": str(u.id), "tenant_id": str(tenant.id), "email": u.email}


@app.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    u = await db.scalar(select(User).where(User.email == req.email))
    fail = "invalid credentials"
    if not u:
        raise HTTPException(401, fail)

    if u.locked_until and u.locked_until > _now():
        raise HTTPException(423, "account locked")

    ok = await _verify_password(req.password, u.password_hash)
    if not ok:
        u.failed_login_attempts = (u.failed_login_attempts or 0) + 1
        if u.failed_login_attempts >= 5:
            u.locked_until = _now() + timedelta(minutes=15)
        await db.commit()
        raise HTTPException(401, fail)

    # Tenant-level MFA enforcement
    tenant = await db.scalar(select(Tenant).where(Tenant.id == u.tenant_id))
    if tenant and tenant.mfa_required and not u.mfa_enabled:
        raise HTTPException(403, "mfa enrollment required — contact your administrator")

    if u.mfa_enabled:
        if not req.otp:
            raise HTTPException(401, "mfa required")
        r = get_redis()
        otp_value = req.otp.strip()
        backup_codes = u.mfa_backup_codes or []
        if backup_codes and len(otp_value) == _BACKUP_CODE_LEN:
            match_idx = _verify_backup_code(otp_value, backup_codes)
            if match_idx is None:
                raise HTTPException(401, "invalid backup code")
            backup_codes.pop(match_idx)
            u.mfa_backup_codes = backup_codes
        else:
            timestep = int(_now().timestamp() // 30)
            replay_key = f"mfa:replay:{u.id}:{timestep}:{otp_value}"
            if await r.get(replay_key):
                raise HTTPException(401, "otp replay detected")
            totp_secret = _decrypt_mfa_secret(u.mfa_secret) if u.mfa_secret else ""
            if not _verify_totp(totp_secret, otp_value):
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


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    algo, _, verify_key = _jwt_material()
    try:
        claims = jwt.decode(req.refresh_token, verify_key, algorithms=[algo])
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
    # Re-read user from DB to pick up current role (not stale from token)
    u = await db.scalar(select(User).where(User.id == uid))
    if not u or u.deactivated_at:
        raise HTTPException(401, "user not found or deactivated")

    algo, sign_key, _ = _jwt_material()
    new_access_claims = _access_claims(u)
    new_refresh_claims = _refresh_claims(u)
    access = jwt.encode(new_access_claims, sign_key, algorithm=algo)
    new_refresh = jwt.encode(new_refresh_claims, sign_key, algorithm=algo)
    await r.setex(f"refresh:{new_refresh_claims['jti']}", 7 * 24 * 3600, str(u.id))
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
        except JWTError:
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

    plain_codes, hashed_codes = _generate_backup_codes()
    u.mfa_secret = _encrypt_mfa_secret(secret)
    u.mfa_enabled = True
    u.mfa_backup_codes = hashed_codes
    await db.commit()
    await r.delete(f"mfa:pending:{u.id}")
    return {"ok": True, "mfa_enabled": True, "backup_codes": plain_codes}


@app.post("/auth/mfa/verify")
async def mfa_verify(payload: dict, db: AsyncSession = Depends(get_db)):
    email = payload.get("email")
    code = payload.get("otp")
    if not email or not code:
        raise HTTPException(400, "email and otp required")

    u = await db.scalar(select(User).where(User.email == email))
    if not u or not u.mfa_enabled:
        raise HTTPException(404, "mfa not enabled")

    # Enforce account lockout on this endpoint too
    if u.locked_until and u.locked_until > _now():
        raise HTTPException(423, "account locked")

    timestep = int(_now().timestamp() // 30)
    replay_key = f"mfa:replay:{u.id}:{timestep}:{code}"
    r = get_redis()
    if await r.get(replay_key):
        raise HTTPException(401, "otp replay detected")

    totp_secret = _decrypt_mfa_secret(u.mfa_secret) if u.mfa_secret else ""
    if not _verify_totp(totp_secret, code):
        u.failed_login_attempts = (u.failed_login_attempts or 0) + 1
        if u.failed_login_attempts >= 5:
            u.locked_until = _now() + timedelta(minutes=15)
        await db.commit()
        raise HTTPException(401, "invalid otp")

    u.failed_login_attempts = 0
    u.locked_until = None
    await db.commit()
    await r.setex(replay_key, 120, "1")
    return {"ok": True}


# ===========================================================================
# Admin — User Management
# All endpoints require a valid JWT with role == "tenant_admin".
# Users can only manage others within their own tenant.
# ===========================================================================

from sqlalchemy import func as sqlfunc


def _user_out(u: User) -> dict:
    return {
        "id":                    str(u.id),
        "tenant_id":             str(u.tenant_id),
        "email":                 u.email,
        "display_name":          u.display_name,
        "role":                  u.role,
        "mfa_enabled":           u.mfa_enabled,
        "failed_login_attempts": u.failed_login_attempts or 0,
        "locked":                bool(u.locked_until and u.locked_until > _now()),
        "locked_until":          u.locked_until.isoformat() if u.locked_until else None,
        "last_login_at":         u.last_login_at.isoformat() if u.last_login_at else None,
        "created_at":            u.created_at.isoformat() if u.created_at else None,
        "active":                u.deactivated_at is None,
    }


async def _require_admin(authorization: str = Header(default=""), db: AsyncSession = Depends(get_db)):
    """Dependency: decode JWT, ensure caller is tenant_admin, return (claims, user)."""
    token = await _token_from_authz(authorization)
    claims = await _decode_access(token)
    if claims.get("role") != "tenant_admin":
        raise HTTPException(403, "admin role required")
    u = await db.scalar(select(User).where(User.id == claims["sub"]))
    if not u or u.deactivated_at:
        raise HTTPException(401, "user not found")
    return claims, u


@app.get("/auth/admin/users")
async def admin_list_users(
    offset: int = 0,
    limit:  int = 50,
    auth=Depends(_require_admin),
    db: AsyncSession = Depends(get_db),
):
    claims, caller = auth
    tid = caller.tenant_id
    rows = await db.execute(
        select(User)
        .where(User.tenant_id == tid)
        .order_by(User.created_at.desc())
        .offset(offset).limit(min(limit, 200))
    )
    users = rows.scalars().all()
    total = await db.scalar(
        select(sqlfunc.count(User.id)).where(User.tenant_id == tid)
    )
    return {"total": total, "items": [_user_out(u) for u in users]}


@app.get("/auth/admin/users/{user_id}")
async def admin_get_user(
    user_id: str,
    auth=Depends(_require_admin),
    db: AsyncSession = Depends(get_db),
):
    claims, caller = auth
    u = await db.scalar(
        select(User).where(User.id == user_id, User.tenant_id == caller.tenant_id)
    )
    if not u:
        raise HTTPException(404, "user not found")
    return _user_out(u)


class AdminCreateUser(BaseModel):
    email: str
    password: str
    display_name: str | None = None
    role: str = "viewer"


@app.post("/auth/admin/users", status_code=201)
async def admin_create_user(
    body: AdminCreateUser,
    auth=Depends(_require_admin),
    db: AsyncSession = Depends(get_db),
):
    claims, caller = auth
    if body.role not in ("tenant_admin", "analyst", "viewer"):
        raise HTTPException(400, "role must be tenant_admin, analyst, or viewer")
    exists = await db.scalar(select(User).where(User.email == body.email))
    if exists:
        raise HTTPException(409, "email already registered")
    hashed = await _hash_password(body.password)
    u = User(
        tenant_id=caller.tenant_id,
        email=body.email,
        password_hash=hashed,
        role=body.role,
        display_name=body.display_name,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return _user_out(u)


class AdminUpdateUser(BaseModel):
    display_name: str | None = None
    role:         str | None = None
    active:       bool | None = None   # False = deactivate, True = reactivate
    unlock:       bool | None = None   # True = clear lockout


@app.patch("/auth/admin/users/{user_id}")
async def admin_update_user(
    user_id: str,
    body: AdminUpdateUser,
    auth=Depends(_require_admin),
    db: AsyncSession = Depends(get_db),
):
    claims, caller = auth
    u = await db.scalar(
        select(User).where(User.id == user_id, User.tenant_id == caller.tenant_id)
    )
    if not u:
        raise HTTPException(404, "user not found")
    if str(u.id) == str(caller.id) and body.role is not None and body.role != "tenant_admin":
        raise HTTPException(400, "cannot demote yourself")
    if body.display_name is not None:
        u.display_name = body.display_name
    if body.role is not None:
        if body.role not in ("tenant_admin", "analyst", "viewer"):
            raise HTTPException(400, "invalid role")
        u.role = body.role
    if body.active is False:
        if str(u.id) == str(caller.id):
            raise HTTPException(400, "cannot deactivate yourself")
        u.deactivated_at = _now()
    elif body.active is True:
        u.deactivated_at = None
    if body.unlock:
        u.failed_login_attempts = 0
        u.locked_until = None
    await db.commit()
    await db.refresh(u)
    return _user_out(u)


class AdminResetPassword(BaseModel):
    new_password: str


@app.post("/auth/admin/users/{user_id}/reset-password")
async def admin_reset_password(
    user_id: str,
    body: AdminResetPassword,
    auth=Depends(_require_admin),
    db: AsyncSession = Depends(get_db),
):
    claims, caller = auth
    u = await db.scalar(
        select(User).where(User.id == user_id, User.tenant_id == caller.tenant_id)
    )
    if not u:
        raise HTTPException(404, "user not found")
    if len(body.new_password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    u.password_hash = await _hash_password(body.new_password)
    u.failed_login_attempts = 0
    u.locked_until = None
    await db.commit()
    return {"ok": True}


@app.delete("/auth/admin/users/{user_id}", status_code=204)
async def admin_delete_user(
    user_id: str,
    auth=Depends(_require_admin),
    db: AsyncSession = Depends(get_db),
):
    claims, caller = auth
    if user_id == str(caller.id):
        raise HTTPException(400, "cannot delete yourself")
    u = await db.scalar(
        select(User).where(User.id == user_id, User.tenant_id == caller.tenant_id)
    )
    if not u:
        raise HTTPException(404, "user not found")
    await db.delete(u)
    await db.commit()


# ===========================================================================
# Admin — Registration toggle
# ===========================================================================

@app.get("/auth/admin/settings")
async def admin_get_settings(
    auth=Depends(_require_admin),
    db: AsyncSession = Depends(get_db),
):
    r = get_redis()
    disabled = await r.get("global:registration_disabled")
    return {"registration_enabled": disabled != "1"}


@app.patch("/auth/admin/settings")
async def admin_update_settings(
    body: dict,
    auth=Depends(_require_admin),
    db: AsyncSession = Depends(get_db),
):
    r = get_redis()
    if "registration_enabled" in body:
        if body["registration_enabled"]:
            await r.delete("global:registration_disabled")
        else:
            await r.set("global:registration_disabled", "1")
    disabled = await r.get("global:registration_disabled")
    return {"registration_enabled": disabled != "1"}
