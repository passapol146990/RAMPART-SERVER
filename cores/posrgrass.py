from sqlalchemy import Boolean, DateTime, ForeignKey, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from datetime import datetime
from dotenv import load_dotenv
import os

# ======================
# ENV + DB
# ======================
load_dotenv()

POSTGRES_USER = os.getenv("POSTGRES_USER")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_DB = os.getenv("POSTGRES_DB")

DATABASE_URL = (
    f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@localhost:5433/{POSTGRES_DB}"
)

engine = create_async_engine(DATABASE_URL, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

# ======================
# Base
# ======================
class Base(DeclarativeBase):
    pass

# ======================
# Users
# ======================
class User(Base):
    __tablename__ = "users"

    uid: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True, nullable=False)
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    password: Mapped[str] = mapped_column(nullable=False)
    role: Mapped[str] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )

    uploads = relationship(
        "Uploads",
        back_populates="user",
        cascade="all, delete-orphan"
    )

# ======================
# Files (ไฟล์กลาง)
# ======================
class Files(Base):
    __tablename__ = "files"

    fid: Mapped[int] = mapped_column(primary_key=True)
    file_hash: Mapped[str] = mapped_column(unique=True, nullable=False)
    file_path: Mapped[str] = mapped_column(nullable=False)
    file_type: Mapped[str] = mapped_column(nullable=True)
    file_size: Mapped[int] = mapped_column(nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )

    uploads = relationship(
        "Uploads",
        back_populates="file"
    )

# ======================
# Uploads (user ↔ file)
# ======================
class Uploads(Base):
    __tablename__ = "uploads"

    up_id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str] = mapped_column()

    uid: Mapped[int] = mapped_column(
        ForeignKey("users.uid", ondelete="CASCADE"),
        nullable=False
    )

    fid: Mapped[int] = mapped_column(
        ForeignKey("files.fid", ondelete="RESTRICT"),
        nullable=False
    )

    privacy: Mapped[bool] = mapped_column(
        Boolean,
        server_default=text("TRUE"),
        nullable=False
    )

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )

    user = relationship("User", back_populates="uploads")
    file = relationship("Files", back_populates="uploads")
