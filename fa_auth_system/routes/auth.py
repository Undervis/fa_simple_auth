import requests
from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated, Union, Type

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.requests import Request

from fa_auth_system.database.models import *
from pydantic import BaseModel as PydanticBaseModel
from fa_auth_system.database.dao import UserDAO, TokensDAO
from fa_auth_system.logic.crypt import get_password_hash, verify_password, create_access_token, check_token
from fa_auth_system.schemas.rbac import UserRegister, Token, UserResponse, UserChangePassword, Session
from fa_auth_system.logic.misc import get_current_user, create_audit_log
from fa_auth_system.system import auth_system

auth_router = APIRouter(prefix="/sys", tags=["🚪 Auth"])


class SimpleResponse(PydanticBaseModel):
    message: str = "Success"

    def __init__(self, message: str):
        super().__init__()
        self.message = message


async def create_token(request: Request, db: AsyncSession, token: str):
    response = requests.get(f"http://ip-api.com/json/{request.client.host}")
    data = response.json()
    try:
        location = {
            'country-code': data['countryCode'],
            'country': data['country'],
            'region': data['regionName'],
            'city': data['city'],
            'zip': data['zip'],
            'timeZone': data['timezone'],
            'isp': data['isp']
        }
    except KeyError:
        location = None
    client_data = {
        "ip_address": request.client.host if request else None,
        "platform": request.headers.get("sec-ch-ua-platform"),
        "user_agent": request.headers.get("User-Agent"),
        "location": location,
        "timestamp": datetime.now(tz=timezone.utc).isoformat()
    }

    q = update(AccessToken).filter_by(token=token).values(client_data=client_data)
    await db.execute(q)
    await db.commit()


@auth_router.post(
    "/register",
    summary="Register a new user",
    response_model=Union[UserResponse, dict[str, str]],
    status_code=status.HTTP_201_CREATED
)
async def register_user(
        user_data: UserRegister,
        request: Request,
        background_tasks: BackgroundTasks,
        login: bool = Query(
            default=False,
            description="Create and return an access token instead of returning user data"
        ),
        db: AsyncSession = Depends(auth_system.get_async_session)
) -> Union[dict[str, str], Type[User]]:
    user = await UserDAO.find_or_none(db, username=user_data.username)
    if user:
        await create_audit_log(None, action=ActionTypes.create, resource_type=ResourceTypes.auth_users,
                               details={"error": "This user already registered", "action": "Register"},
                               ip_address=request.client.host if request else None)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This user already registered")
    user_dict = user_data.model_dump()
    user_dict["hashed_password"] = get_password_hash(user_data.password)
    user_dict.pop("password")

    new_user = await UserDAO.create(db, **user_dict)
    if login:
        access_token = await create_access_token({
            "user_id": user.id,
            "sub": user.username,
            "email": user.email,
            "exp": None
        }, db=db)
        background_tasks.add_task(create_token, request, db, access_token)

        background_tasks.add_task(
            create_audit_log,
            user_id=user.id,
            action=ActionTypes.create,
            resource_type=ResourceTypes.auth_users,
            details={"success": True, "action": "Register user"},
            ip_address=request.client.host if request else None
        )

        return {"access_token": access_token}
    return new_user


@auth_router.post(
    "/login",
    summary="Login a user",
    status_code=status.HTTP_200_OK,
    response_model=Token,
    responses={status.HTTP_401_UNAUTHORIZED: {"description": "Username and/or value incorrect"}}
)
async def login_user(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()], request: Request,
        background_tasks: BackgroundTasks, db: AsyncSession = Depends(auth_system.get_async_session),
        expires: int = Query(default=43200, description="Expiration time in minutes (by default it's 30 days)")
) -> Token:
    user: User = await UserDAO.find_or_none(db, username=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        await create_audit_log(None, action=ActionTypes.create, resource_type=ResourceTypes.auth_users,
                               details={"error": "Username and/or value incorrect", "action": "login"},
                               ip_address=request.client.host if request else None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Username and/or value incorrect")
    else:
        access_token = await create_access_token({
            "user_id": user.id,
            "sub": user.username,
            "email": user.email,
            "exp": expires
        }, db=db)
        background_tasks.add_task(create_token, request, db, access_token)

        background_tasks.add_task(
            create_audit_log,
            user_id=user.id,
            action=ActionTypes.create,
            resource_type=ResourceTypes.auth_users,
            details={"success": True, "action": "login, create token"},
            ip_address=request.client.host if request else None
        )

        return Token(access_token=access_token)


@auth_router.get("/sessions", summary="Get all user sessions", response_model=List[Session])
async def get_all_sessions(
        background_tasks: BackgroundTasks, request: Request, user: User = Depends(get_current_user)
) -> List[Session]:
    sessions = [Session(**at.__dict__) for at in user.access_tokens]

    background_tasks.add_task(
        create_audit_log,
        user_id=user.id,
        action=ActionTypes.read,
        resource_type=ResourceTypes.auth_system,
        details={"action": "Get all sessions"},
        ip_address=request.client.host if request else None
    )
    return sessions


@auth_router.delete('/close_sessions', summary="Close all sessions of user", status_code=status.HTTP_200_OK)
async def close_sessions(
        background_tasks: BackgroundTasks, request: Request,
        db: AsyncSession = Depends(auth_system.get_async_session), user: User = Depends(get_current_user),
        save_current_session: bool = Query(default=True, description="Save current session for stay logged in")
) -> SimpleResponse:
    await UserDAO.delete_all_tokens(db, user.id, request.headers.get("Authorization")[7:] if save_current_session else "")
    background_tasks.add_task(
        create_audit_log,
        user_id=user.id,
        action=ActionTypes.delete,
        resource_type=ResourceTypes.auth_system,
        details={"action": "Close all sessions"},
        ip_address=request.client.host if request else None
    )
    return SimpleResponse("All sessions are closed")


@auth_router.delete("/close_session/{session_id}", summary="Close a specific session", status_code=status.HTTP_200_OK)
async def close_session(
        session_id: int, background_tasks: BackgroundTasks, request: Request,
        db: AsyncSession = Depends(auth_system.get_async_session), user: User = Depends(get_current_user),
) -> SimpleResponse:
    await UserDAO.close_session(db, user.id, session_id)
    background_tasks.add_task(
        create_audit_log,
        user_id=user.id,
        action=ActionTypes.delete,
        resource_type=ResourceTypes.auth_system,
        details={"action": f"Session with token id={session_id} was deleted"},
        ip_address=request.client.host if request else None
    )
    return SimpleResponse("All sessions are closed")


@auth_router.post(
    "/logout", summary="Logout a user, close current session",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_current_user)],
    responses={status.HTTP_401_UNAUTHORIZED: {"description": "Unauthorized user"}}
)
async def logout_user(request: Request, db: AsyncSession = Depends(auth_system.get_async_session)):
    token = request.headers.get('Authorization')[7:]
    payload = await check_token(token, db)
    await TokensDAO.delete_by(token, db)
    await create_audit_log(payload['user_id'], action=ActionTypes.delete, resource_type=ResourceTypes.auth_users,
                           details={"action": "Logout, delete token", "success": True},
                           ip_address=request.client.host if request else None)
    return {"msg": "Logout successful"}


@auth_router.get(
    '/current_user',
    response_model=UserResponse,
    summary="Get current user",
    responses={status.HTTP_401_UNAUTHORIZED: {"description": "Unauthorized user"}}
)
async def get_user(background_tasks: BackgroundTasks, request: Request, user_data: User = Depends(get_current_user)):
    background_tasks.add_task(
        create_audit_log,
        user_id=user_data.id,
        action=ActionTypes.read,
        resource_type=ResourceTypes.auth_users,
        details={"action": "Read user data"},
        ip_address=request.client.host if request else None
    )
    return user_data


@auth_router.patch(
    "/change_password",
    summary="Change value of a user",
    responses={status.HTTP_401_UNAUTHORIZED: {"description": "Unauthorized user"}}
)
async def change_password(
        password_data: UserChangePassword, background_tasks: BackgroundTasks, request: Request,
        user_data: User = Depends(get_current_user), db: AsyncSession = Depends(auth_system.get_async_session)
) -> SimpleResponse:
    user: User = await UserDAO.find_or_none(db, id=user_data.id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not verify_password(password_data.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current Password is incorrect")
    new_password = get_password_hash(password_data.new_password)
    await UserDAO.change_password(user_data.id, new_password, db)
    background_tasks.add_task(
        create_audit_log,
        user_id=user_data.id,
        action=ActionTypes.update,
        resource_type=ResourceTypes.auth_users,
        details={"action": "change_password"},
        ip_address=request.client.host if request else None
    )
    return SimpleResponse("Password change successfully!")
