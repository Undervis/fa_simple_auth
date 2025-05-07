from datetime import datetime

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette import status
from starlette.exceptions import HTTPException
from starlette.requests import Request

from fa_auth_system.database.models import User, ResourceTypes, ActionTypes, Role, Group
from typing import Optional, Dict, Any

from fa_auth_system.logic.misc import get_current_user
from fa_auth_system.system import auth_system


async def has_permission(
        user: User,
        resource: ResourceTypes,
        action: ActionTypes,
        context: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Check if a user has permission to perform an action on a resource.
    Implements Attribute-Based Access Control (ABAC) by considering:
    - Direct user permissions
    - Role-based permissions
    - Group-based permissions
    - Contextual conditions
    """
    context = context or {}

    # Helper function to check conditions
    def evaluate_conditions(conditions: Optional[Dict[str, Any]], context: Dict[str, Any]) -> bool:
        if not conditions:
            return True

        # Example condition: {"time_between": ["09:00", "17:00"]}
        for condition_key, condition_value in conditions.items():
            if condition_key == "time_between":
                current_time = context.get("current_time", datetime.now().time())
                start_time = datetime.strptime(condition_value[0], "%H:%M").time()
                end_time = datetime.strptime(condition_value[1], "%H:%M").time()
                if not (start_time <= current_time <= end_time):
                    return False
            elif condition_key == "ip_range":
                ip = context.get("ip_address")
                if not ip or ip not in condition_value:
                    return False
            elif condition_key == "role_grade":
                role = context.get("role_grade")

            # Add more condition types as needed

        return True

    async with auth_system.get_session() as db:
        query = select(User).where(User.id == user.id).options(
            selectinload(User.permissions), selectinload(User.roles).selectinload(Role.permissions),
            selectinload(User.groups).selectinload(Group.roles).selectinload(Role.permissions)
        )
        result = await db.execute(query)
        user = result.scalars().one_or_none()

    # If user is superman, he can do anything)
    if user.is_superuser:
        return True

    # Check direct user permissions

    for permission in user.permissions:
        if (permission.resource == resource and
                permission.action == action and
                evaluate_conditions(permission.conditions, context)):
            return True

    # Check role-based permissions
    for role in user.roles:
        for permission in role.permissions:
            if (permission.resource == resource and
                    permission.action == action and
                    evaluate_conditions(permission.conditions, context)):
                return True

    # Check group-based permissions (through roles)
    for group in user.groups:
        for role in group.roles:
            for permission in role.permissions:
                if (permission.resource == resource and
                        permission.action == action and
                        evaluate_conditions(permission.conditions, context)):
                    return True

    return False


# Permission dependency for FastAPI routes
def require_permission(resource: ResourceTypes, action: ActionTypes):
    async def permission_dependency(
            current_user: User = Depends(get_current_user),
            request: Request = None
    ):
        context = {
            "current_time": datetime.now().time(),
            "ip_address": request.client.host if request else None
        }

        if not await has_permission(current_user, resource, action, context=context):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {action.value} on {resource.value}"
            )
        return current_user

    return permission_dependency
