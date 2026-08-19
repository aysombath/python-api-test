from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession as SQLModelAsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker

from python_api.config import settings

engine = create_async_engine(settings.database_url, echo=False)

async_session_maker = sessionmaker(
    engine, class_=SQLModelAsyncSession, expire_on_commit=False
)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
        # Lightweight column migration for tables created before the "role"
        # column existed. Replace with Alembic once schema changes get frequent.
        await conn.exec_driver_sql(
            "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS role VARCHAR NOT NULL DEFAULT 'user'"
        )


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session
