from typing import Type

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.requests import Request

from fa_auth_system.database.dao import RoleDAO, GroupDAO, PermissionDAO, UserDAO
from fa_auth_system.database.models import User, AssignableResource
from fa_auth_system.logic.crypt import verify_password, get_password_hash
from fa_auth_system.logic.rbac import require_permission
from fa_auth_system.logic.assign_service import AssignService
from fa_auth_system.routes.auth import SimpleResponse
from fa_auth_system.routes.crud import RouteCRUD
from fa_auth_system.logic.misc import get_current_user, create_audit_log
from fa_auth_system.schemas.rbac import *
from fa_auth_system.system import auth_system

"""
All routers inherit from RouteCRUD, they have basic CRUD operations. With inheritance you can add your unique routes
"""

err_responses = {
    status.HTTP_401_UNAUTHORIZED: {"description": "Unauthorized"},
    status.HTTP_403_FORBIDDEN: {"description": "Forbidden"},
    status.HTTP_404_NOT_FOUND: {"description": "Not found"},
    status.HTTP_409_CONFLICT: {"model": AssignConflictResponse, "description": "Conflict with assignable items"}
}


class RoleCRUD(RouteCRUD[RoleCreate, RoleResponse]):
    def __init__(self, dao, router: APIRouter, verbose_name: str, plural_name: str, resource_type: ResourceTypes,
                 presentation_schema: Type[BaseModel], create_schema: Type[BaseModel]):
        super().__init__(dao, router, verbose_name, plural_name, resource_type, presentation_schema, create_schema)
        router.add_api_route(
            "/assign_remove", endpoint=self.assign_remove, methods=["POST"],
            summary="Assign or/and remove permissions to/from group",
            description="Send list of permissions id that need to be assigned or/and remove to/from group.",
            responses=err_responses,
            response_model=AssignResponse,
            dependencies=[Depends(require_permission(ResourceTypes.auth_permissions, ActionTypes.assign))]
        )

    @staticmethod
    async def assign_remove(
            background_tasks: BackgroundTasks, request: Request,
            roles_id: AssignInput, target_id: int, target_type: AssignableResource = Query(description='Type of target to assign'),
            current_user: User = Depends(get_current_user),
            strict_mode: bool = Query(
                default=False,
                description='If the objects for assignment are not found or have already assigned/removed, you will get exception.'
            ),
            db: AsyncSession = Depends(auth_system.get_async_session)
    ) -> AssignResponse:
        result = await AssignService.assign_remove(
            dao=RoleDAO, assign_data=roles_id, target_id=target_id, target_type=target_type, strict_mode=strict_mode,
            target_dao=UserDAO if target_type == AssignableResource.auth_users else GroupDAO, attr_name='roles', db=db
        )
        # Write log about it
        background_tasks.add_task(
            create_audit_log,
            user_id=current_user.id,
            action=ActionTypes.assign,
            resource_type=ResourceTypes.auth_permissions,
            details=result.model_dump(),
            ip_address=request.client.host if request else None
        )
        return result


class GroupsCRUD(RouteCRUD[GroupCreate, GroupResponse]):
    def __init__(self, dao, router: APIRouter, verbose_name: str, plural_name: str, resource_type: ResourceTypes,
                 presentation_schema: Type[BaseModel], create_schema: Type[BaseModel]):
        super().__init__(dao, router, verbose_name, plural_name, resource_type, presentation_schema, create_schema)
        router.add_api_route(
            "/assign_remove_to_user", endpoint=self.assign_remove, methods=["POST"],
            summary="Assign or/and remove groups to/from user",
            description="Send list of user id's that need to be assigned or/and remove to/from group.",
            responses=err_responses,
            response_model=AssignResponse,
            dependencies=[Depends(require_permission(ResourceTypes.auth_groups, ActionTypes.assign))]
        )

    @staticmethod
    async def assign_remove(
            background_tasks: BackgroundTasks, request: Request,
            users_id: AssignInput, group_id: int, current_user: User = Depends(get_current_user),
            strict_mode: bool = Query(
                default=False,
                description='If the objects for assignment are not found or have already assigned/removed, you will get exception.'
            ),
            db: AsyncSession = Depends(auth_system.get_async_session)
    ) -> AssignResponse:
        result = await AssignService.assign_remove(
            dao=UserDAO, assign_data=users_id, target_id=group_id, target_type=AssignableResource.auth_users, strict_mode=strict_mode,
            target_dao=GroupDAO, attr_name='users', db=db, target_title_attr="username"
        )
        # Write log about it
        background_tasks.add_task(
            create_audit_log,
            user_id=current_user.id,
            action=ActionTypes.assign,
            resource_type=ResourceTypes.auth_groups,
            details=result.model_dump(),
            ip_address=request.client.host if request else None
        )
        return result


# Permissions router
class PermissionsCRUD(RouteCRUD[PermissionCreate, PermissionResponse]):
    def __init__(self, dao, router: APIRouter, verbose_name: str, plural_name: str, resource_type: ResourceTypes,
                 presentation_schema: Type[BaseModel], create_schema: Type[BaseModel]):
        super().__init__(dao, router, verbose_name, plural_name, resource_type, presentation_schema, create_schema)
        router.add_api_route(
            "/assign_remove", endpoint=self.assign_remove, methods=["POST"],
            summary="Assign or/and remove permissions to/from some target",
            description="Send list of permissions id that need to be assigned or/and remove to/from some target.",
            responses=err_responses,
            response_model=AssignResponse,
            dependencies=[Depends(require_permission(ResourceTypes.auth_permissions, ActionTypes.assign))]
        )

    @staticmethod
    async def assign_remove(
            background_tasks: BackgroundTasks, request: Request,
            permissions_id: AssignInput, target_id: int, target_type: AssignableResource = Query(description='Type of target to assign'),
            current_user: User = Depends(get_current_user),
            strict_mode: bool = Query(
                default=False,
                description='If the objects for assignment are not found or have already assigned/removed, you will get exception.'
            ),
            db: AsyncSession = Depends(auth_system.get_async_session)
    ) -> AssignResponse:
        result = await AssignService.assign_remove(
            dao=PermissionDAO, assign_data=permissions_id, target_id=target_id, target_type=target_type, strict_mode=strict_mode,
            target_dao=UserDAO if target_type == AssignableResource.auth_users else RoleDAO, attr_name='permissions', db=db
        )
        # Write log about it
        background_tasks.add_task(
            create_audit_log,
            user_id=current_user.id,
            action=ActionTypes.assign,
            resource_type=ResourceTypes.auth_permissions,
            details=result.model_dump(),
            ip_address=request.client.host if request else None
        )
        return result


# User router
class UserCRUD(RouteCRUD[UserRegister, UserResponse]):
    def __init__(self, dao, router: APIRouter, verbose_name: str, plural_name: str, resource_type: ResourceTypes,
                 presentation_schema: Type[BaseModel], create_schema: Type[BaseModel]):
        super().__init__(dao, router, verbose_name, plural_name, resource_type, presentation_schema, create_schema)
        router.add_api_route(
            "/change_password/{user_id}", endpoint=self.change_password, methods=["PATCH"],
            summary="Change user value", response_model=SimpleResponse,
            responses={
                status.HTTP_401_UNAUTHORIZED: {"description": "Unauthorized"},
                status.HTTP_403_FORBIDDEN: {"description": "Forbidden"},
                status.HTTP_404_NOT_FOUND: {"description": "User not found"}
            }
        )

    async def change_password(self, user_id: int, user_data: UserChangePassword, db: AsyncSession = Depends(auth_system.get_async_session)) -> SimpleResponse:
        user: User = await self._dao.find_or_none(id=user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not verify_password(user_data.current_password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current Password is incorrect")

        new_password = get_password_hash(user_data.new_password)
        await UserDAO.change_password(user_id, new_password, db)
        return SimpleResponse("Password changed successfully")


# Create routers
role_router = APIRouter(prefix="/roles", tags=["🎭 Roles"])
role_crud = RoleCRUD(
    dao=RoleDAO, router=role_router, verbose_name="Role", plural_name="roles",
    resource_type=ResourceTypes.auth_roles, presentation_schema=RoleResponse, create_schema=RoleCreate
)

groups_router = APIRouter(prefix="/groups", tags=["👯 Groups"])
groups_crud = GroupsCRUD(
    dao=GroupDAO, router=groups_router, verbose_name="Group", plural_name="groups",
    resource_type=ResourceTypes.auth_groups, presentation_schema=GroupResponse, create_schema=GroupCreate
)

permissions_router = APIRouter(prefix="/permissions", tags=["🔒 Permissions"])
permissions_crud = PermissionsCRUD(
    dao=PermissionDAO, router=permissions_router, verbose_name="Permission", plural_name="permissions",
    resource_type=ResourceTypes.auth_permissions, presentation_schema=PermissionResponse, create_schema=PermissionCreate
)

users_router = APIRouter(prefix="/users", tags=["🤡 Users"])
users_crud = UserCRUD(
    dao=UserDAO, router=users_router, verbose_name="User", plural_name="users",
    resource_type=ResourceTypes.auth_users, presentation_schema=UserResponse, create_schema=UserSchema
)
