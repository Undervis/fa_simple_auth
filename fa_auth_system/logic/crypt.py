from datetime import datetime, timezone, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.exceptions import HTTPException

from passlib.context import CryptContext
from jose import jwt, JWTError

from config import settings
from fa_auth_system.database.dao import TokensDAO, ObjectNotFound


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Encode value
def get_password_hash(password: str) -> str:
    """
    Hash a plain text value.
    It's a secure method to save user value to the database.
    :param password:
    :return: Hashed value
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Encode plain text value to hash and equal with hashed value
    :param plain_password,
    :param hashed_password,
    :return: True if value matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


async def create_access_token(data: dict, db: AsyncSession) -> str:
    """
    Create access token with any data you want
    :param data: Any data to encode in a dict() format like {'sub': 'username' }
    :param db: AsyncSession
    :return: encoded token
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=data['exp'] | 43200)
    to_encode.update({"exp": expire})
    auth_data = settings.get_auth_data
    encode_jwt = jwt.encode(to_encode, auth_data['secret_key'], algorithm=auth_data['algorithm'])
    await TokensDAO.create(db, token=encode_jwt, user_id=data['user_id'])
    return encode_jwt


async def check_token(token: str, db: AsyncSession) -> dict:
    """
    Check access token on valid and expire. Return decoded token data.
    :param token:
    :param db:
    :return: decoded token data
    """
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is missing")
    try:
        await TokensDAO.is_token_active(token, db)
        auth_data = settings.get_auth_data
        payload = jwt.decode(token, auth_data['secret_key'], algorithms=[auth_data['algorithm']])
    except ObjectNotFound:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not found")
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f'Token is invalid, {e}')

    return payload
