from fastapi import HTTPException, BackgroundTasks
from typing import List, Type, Generic, TypeVar

from fastapi import APIRouter
from fastapi.params import Depends
from pydantic import BaseModel as PyBaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.requests import Request

from fa_auth_system.database.models import User, ActionTypes, ResourceTypes

from fa_auth_system.database.dao import ObjectNotFound
from fa_auth_system.logic.rbac import require_permission
from fa_auth_system.logic.misc import create_audit_log, get_current_user
from fa_auth_system.system import auth_system

CreateSchema = TypeVar("CreateSchema", bound=PyBaseModel)
PresentationSchema = TypeVar("PresentationSchema", bound=PyBaseModel)



class RouteCRUD(Generic[CreateSchema, PresentationSchema]):
    def __init__(self, dao, router: APIRouter, verbose_name: str, plural_name: str, resource_type: ResourceTypes,
                 presentation_schema: Type[PresentationSchema], create_schema: Type[CreateSchema]):
        self._dao = dao
        self._verbose_name = verbose_name
        self._plural_name = plural_name
        self._resource_type = resource_type

        self._router = router

        # Get all objects of model
        # TODO: Create filter system
        async def get_all(db: AsyncSession = Depends(auth_system.get_async_session)) -> List[presentation_schema]:
            objects = await self._dao.get_all(db)
            objects_list = []
            for obj in objects:
                obj = obj.__dict__
                obj.pop("_sa_instance_state")
                objects_list.append(presentation_schema(**obj))

            return objects_list

        # Get objects by id
        async def get_by_id(object_id: int, db: AsyncSession = Depends(auth_system.get_async_session)) -> presentation_schema:
            obj = await self._dao.get_by_id(object_id, db)
            if not obj:
                raise HTTPException(status_code=404, detail=f"{self._verbose_name} with ID({object_id}) not found")
            return presentation_schema(**obj.__dict__)

        # Create a new object
        # TODO: Create exception for unique items
        async def create(
                obj_data: create_schema, request: Request, background_tasks: BackgroundTasks,
                current_user: User = Depends(get_current_user), db: AsyncSession = Depends(auth_system.get_async_session)
        ) -> presentation_schema:
            try:
                obj = await self._dao.create(db, **obj_data.model_dump())
                background_tasks.add_task(
                    create_audit_log,
                    user_id=current_user.id,
                    action=ActionTypes.create,
                    resource_type=self._resource_type,
                    resource_id=obj.id,
                    details={"success": True},
                    ip_address=request.client.host if request else None,
                )
                obj = obj.__dict__
                obj.pop("_sa_instance_state")
                return presentation_schema(**obj)
            except IntegrityError as e:
                raise e
                # raise HTTPException(status_code=409, detail=f"This {cls._verbose_name} already exists")

        # Update object
        # TODO: Create exception for unique fields
        async def update_obj(
                object_id: int, obj_data: create_schema, request: Request, background_tasks: BackgroundTasks,
                current_user: User = Depends(get_current_user), db: AsyncSession = Depends(auth_system.get_async_session)
        ) -> presentation_schema:
            try:
                before = await self._dao.get_by_id(object_id, db)
                before = before.__dict__
                before.pop("_sa_instance_state")
                for key in before.keys():
                    if type(before[key]) is ActionTypes or type(before[key]) is ResourceTypes:
                        before[key] = before[key].value

                obj = await self._dao.update_by_id(object_id, db, **obj_data.model_dump())
                background_tasks.add_task(
                    create_audit_log,
                    user_id=current_user.id,
                    action=ActionTypes.update,
                    resource_type=self._resource_type,
                    resource_id=obj.id,
                    details={"updated_data": {**before}},
                    ip_address=request.client.host if request else None,
                )
                return presentation_schema(**obj)
            except ObjectNotFound:
                raise HTTPException(status_code=404, detail=f"{self._verbose_name} with id={object_id} not found")
            except IntegrityError:
                raise HTTPException(status_code=409, detail=f"{self._verbose_name} with this data already exists")

        # Delete object
        async def delete(
                object_id: int, request: Request, background_tasks: BackgroundTasks,
                current_user: User = Depends(get_current_user), db: AsyncSession = Depends(auth_system.get_async_session)
        ) -> None:
            try:
                before = await self._dao.get_by_id(object_id, db)
                before = before.__dict__
                before.pop("_sa_instance_state")
                for key in before.keys():
                    if type(before[key]) is ActionTypes or type(before[key]) is ResourceTypes:
                        before[key] = before[key].value

                await self._dao.delete_by_id(object_id, db)
                background_tasks.add_task(
                    create_audit_log,
                    user_id=current_user.id,
                    action=ActionTypes.delete,
                    resource_type=self._resource_type,
                    details={"deleted_data": {**before}},
                    ip_address=request.client.host if request else None,
                )
            except ObjectNotFound:
                raise HTTPException(status_code=404, detail=f"{self._verbose_name} with id={object_id} not found")

        responses = {
            status.HTTP_401_UNAUTHORIZED: {"description": "Unauthorized user"},
            status.HTTP_403_FORBIDDEN: {"description": "Forbidden"},
            status.HTTP_404_NOT_FOUND: {"description": f"{verbose_name} not found"},
            status.HTTP_409_CONFLICT: {"description": f"This {verbose_name} already exists"},
        }

        self._router.add_api_route(
            "/", endpoint=get_all, response_model=List[presentation_schema],
            methods=["GET"], status_code=status.HTTP_200_OK, summary=f"Get all {plural_name}",
            responses=responses, dependencies=[Depends(require_permission(self._resource_type, ActionTypes.read))],
        )
        self._router.add_api_route(
            "/{object_id}", endpoint=get_by_id, methods=["GET"], status_code=status.HTTP_200_OK,
            response_model=presentation_schema, summary=f"Get {verbose_name} by ID",
            responses=responses, dependencies=[Depends(require_permission(self._resource_type, ActionTypes.read))]
        )
        self._router.add_api_route(
            "/", endpoint=create, methods=["POST"], status_code=status.HTTP_201_CREATED,
            response_model=presentation_schema, summary=f"Create {verbose_name} object",
            responses=responses, dependencies=[Depends(require_permission(self._resource_type, ActionTypes.create))]
        )
        self._router.add_api_route(
            "/{object_id}", endpoint=update_obj, methods=["PUT"], status_code=status.HTTP_200_OK,
            response_model=presentation_schema, summary=f"Update {verbose_name} object",
            responses=responses, dependencies=[Depends(require_permission(self._resource_type, ActionTypes.update))]
        )
        self._router.add_api_route(
            "/{object_id}", endpoint=delete, methods=["DELETE"], status_code=status.HTTP_204_NO_CONTENT,
            summary=f"Delete {verbose_name} object", responses=responses,
            dependencies=[Depends(require_permission(self._resource_type, ActionTypes.delete))]
        )
