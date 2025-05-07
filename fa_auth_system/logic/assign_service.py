from typing import Type

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from fa_auth_system.database.models import AssignableResource
from fa_auth_system.schemas.rbac import AssignInput, AssignResponse
from fa_auth_system.database.dao import BaseDAO, ObjectNotFound


class AssignService:
    @classmethod
    async def assign_remove(
            cls, dao: Type[BaseDAO], assign_data: AssignInput, target_id: int, target_dao: Type[BaseDAO], db: AsyncSession,
            target_type: AssignableResource, attr_name: str, strict_mode: bool = False, target_title_attr: str = "title"
    ) -> AssignResponse:

        assign_items, remove_items = (
            await dao.filter(db, dao.model.id.in_(assign_data.assign)),
            await dao.filter(db, dao.model.id.in_(assign_data.remove))
        )
        assign_difference, remove_difference = (
            set(assign_data.assign) - set([a.id for a in assign_items]),
            set(assign_data.remove) - set([a.id for a in remove_items])
        )

        # Check the difference between given data and exist data
        if (assign_difference or remove_difference) and strict_mode:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail=f"Roles with ID's {list(assign_difference) + list(remove_difference)} not found")

        # Try to assign roles to group
        target = await target_dao.get_by_id(target_id, db)
        try:
            accepted_and_skipped = await dao.assign_or_remove(
                assign_list=assign_items, remove_list=remove_items,
                target=target, attr_name=attr_name, db=db, target_title_attr=target_title_attr
            )
        except ObjectNotFound:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{target_dao.model.__name__} with id={target_id} not found")

        if accepted_and_skipped['skipped'] and strict_mode:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={'msg': 'This objects was skipped', 'skipped': accepted_and_skipped['skipped']})

        result = {
            "accepted": [role for role in accepted_and_skipped['accepted']],
            "skipped": [role for role in accepted_and_skipped['skipped']],
            "target_id": target_id,
            "target_type": target_type.value,
            "not_found_ids": list(assign_difference) + list(remove_difference)
        }
        return AssignResponse(**result)
