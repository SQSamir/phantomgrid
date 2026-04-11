import os
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

DATABASE_URL = os.getenv("POSTGRES_DSN", "postgresql+asyncpg://phantomgrid:change_me@postgres:5432/phantomgrid")
engine = create_async_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with SessionLocal() as session:
        yield session


@asynccontextmanager
async def tenant_db(tenant_id: str):
    """Session with RLS tenant context set — use for all tenant-scoped queries."""
    async with SessionLocal() as session:
        await session.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": str(tenant_id)},
        )
        yield session
