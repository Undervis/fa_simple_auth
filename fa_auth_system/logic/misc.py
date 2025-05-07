from typing import Optional, Dict, Any

from fastapi import Depends, HTTPException, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from fa_auth_system.database.dao import UserDAO
from fa_auth_system.database.models import User, AuditLog, ActionTypes, ResourceTypes
from fa_auth_system.logic.crypt import check_token

from fa_auth_system.system import auth_system

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/sys/login")


async def create_audit_log(
        user_id: Optional[int],
        action: ActionTypes,
        resource_type: ResourceTypes,
        resource_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
) -> AuditLog:
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address
    )
    async with auth_system.get_session() as db:
        db.add(audit_log)
        await db.commit()
        await db.refresh(audit_log)
        return audit_log


async def get_current_user(background_tasks: BackgroundTasks, request: Request,
                           token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(auth_system.get_async_session)) -> User:
    payload = await check_token(token, db)
    username = payload.get('sub')
    if not username:
        background_tasks.add_task(
            create_audit_log,
            user_id=None,
            action=ActionTypes.read,
            resource_type=ResourceTypes.auth_system,
            details={"error": "User ID not found in token"},
            ip_address=request.client.host if request else None
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User ID not found in token')

    user = await UserDAO.find_or_none(db, username=username)
    if not user:
        background_tasks.add_task(
            create_audit_log,
            user_id=None,
            action=ActionTypes.read,
            resource_type=ResourceTypes.auth_system,
            details={"error": "User not found by token"},
            ip_address=request.client.host if request else None
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User not found')

    background_tasks.add_task(
        create_audit_log,
        user_id=user.id,
        action=ActionTypes.read,
        resource_type=ResourceTypes.auth_system,
        details={"success": True},
        ip_address=request.client.host if request else None
    )
    return user
