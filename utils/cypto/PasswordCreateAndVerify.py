from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

ph = PasswordHasher()

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
