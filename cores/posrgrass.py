from sqlalchemy import DateTime, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
POSTGRES_USER=os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD=os.getenv('POSTGRES_PASSWORD')
POSTGRES_DB=os.getenv('POSTGRES_DB')

DATABASE_URL = f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@localhost:5433/{POSTGRES_DB}"

engine = create_async_engine(DATABASE_URL, echo=False) # Flase เพื่อปิด log
SessionLocal = async_sessionmaker(engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    uid: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str] = mapped_column()
    role: Mapped[str] = mapped_column()
    status: Mapped[str] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

class Files(Base):
    __tablename__ = "files"

    fid: Mapped[int] = mapped_column(primary_key=True)
    file_hash: Mapped[str] = mapped_column(unique=True)
    file_path: Mapped[str] = mapped_column()
    file_type: Mapped[str] = mapped_column()
    file_size: Mapped[int] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )
