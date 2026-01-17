from pydantic import BaseModel
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import select
from passlib.context import CryptContext
import uvicorn, os
from dotenv import load_dotenv
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

ph = PasswordHasher()

load_dotenv()
POSTGRES_USER=os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD=os.getenv('POSTGRES_PASSWORD')
POSTGRES_DB=os.getenv('POSTGRES_DB')

DATABASE_URL = "postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@localhost:5433/{POSTGRES_DB}"

engine = create_async_engine(DATABASE_URL, echo=True)
SessionLocal = async_sessionmaker(engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str] = mapped_column()

def verify_password(plain_password, hashed_password):
    try:
        return ph.verify(plain_password, hashed_password)
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        print("Error: The hash in database is not a valid Argon2 hash.")
        return False

def get_password_hash(password):
    return ph.hash(password)

username = "rampart"
password = "123456"

# print(get_password_hash(password=password))
x = "$argon2id$v=19$m=65536,t=3,p=4$ZMhOrFP79RSWUGf5Kuo6CA$D76jG/0WLAxvVJQ2yr07CUKQodUh5ES1pjqbVIP2zDc"
print(verify_password(x,password))
