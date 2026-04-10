import os, uuid, hmac
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException
from jose import jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.db import get_db
from backend.shared.models.user import User
from backend.shared.schemas.auth import RegisterRequest, LoginRequest, TokenResponse

app = FastAPI(title="auth-service")
pwd = CryptContext(schemes=["argon2"], deprecated="auto")
ALGO = "HS256"
SECRET = os.getenv("JWT_SECRET", "dev-secret")

@app.get('/health')
async def health(): return {'status':'ok'}

@app.post('/auth/register')
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    exists = await db.scalar(select(User).where(User.email == req.email))
    if exists: raise HTTPException(409, 'email exists')
    u = User(tenant_id=uuid.uuid4(), email=req.email, password_hash=pwd.hash(req.password), role='tenant_admin', display_name=req.display_name)
    db.add(u); await db.commit()
    return {'id': str(u.id), 'email': u.email}

@app.post('/auth/login', response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    u = await db.scalar(select(User).where(User.email == req.email))
    fail = "invalid credentials"
    if not u or not hmac.compare_digest(str(pwd.verify(req.password, u.password_hash)), "True"):
        raise HTTPException(401, fail)
    now = datetime.now(timezone.utc)
    claims = {'sub': str(u.id), 'tid': str(u.tenant_id), 'role': u.role, 'iat': int(now.timestamp()), 'exp': int((now+timedelta(minutes=15)).timestamp()), 'jti': str(uuid.uuid4())}
    access = jwt.encode(claims, SECRET, algorithm=ALGO)
    refresh = jwt.encode({'sub': str(u.id), 'exp': int((now+timedelta(days=7)).timestamp()), 'jti': str(uuid.uuid4())}, SECRET, algorithm=ALGO)
    return TokenResponse(access_token=access, refresh_token=refresh)
