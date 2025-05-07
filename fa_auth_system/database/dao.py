from typing import List, Generic, TypeVar

from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fa_auth_system.database.models import User, AccessToken, Role, Group, Permission
from fa_auth_system.database.models import BaseModel


class ObjectNotFound(Exception):
    pass


class BaseDAO:
    model: BaseModel = BaseModel

    @classmethod
    async def get_all(cls, db: AsyncSession) -> List[type(model)]:
        query = select(cls.model).options(selectinload("*"))
        result = await db.execute(query)
        return result.scalars().all()

    @classmethod
    async def find_or_none(cls, db: AsyncSession, **kwargs) -> type(model) | None:
        query = select(cls.model).filter_by(**kwargs).options(selectinload("*"))
        objects = await db.execute(query)
        return objects.scalars().one_or_none()

    @classmethod
    async def get_by_id(cls, id: int, db: AsyncSession) -> type(model):
        query = select(cls.model).filter_by(id=id).options(selectinload("*"))
        result = await db.execute(query)
        obj = result.scalars().one_or_none()
        if obj:
            return obj
        else:
            raise ObjectNotFound()

    @classmethod
    async def filter(cls, db: AsyncSession, criteria) -> List[type(model)]:
        query = select(cls.model).filter(criteria).options(selectinload("*"))
        result = await db.execute(query)
        return result.scalars().all()

    @classmethod
    async def create(cls, db: AsyncSession, commit: bool = True, **kwargs) -> type(model):
        new_object = cls.model(**kwargs)
        db.add(new_object)
        if commit:
            await db.commit()
            await db.refresh(new_object)
            q = await db.execute(select(cls.model).filter_by(id=new_object.id).options(selectinload("*")))
            new_object = q.scalars().first()
        else:
            await db.flush()
            await db.refresh(new_object)
        return new_object

    @classmethod
    async def update_by_id(cls, id: int | str, db: AsyncSession, **kwargs) -> type(model):
        stmt = await db.execute(
            update(cls.model).filter_by(id=id).values(**kwargs).returning(cls.model).options(selectinload("*")))
        obj = stmt.scalars().first()
        if obj:
            await db.commit()
            await db.refresh(obj)
            return obj
        else:
            raise ObjectNotFound()

    @classmethod
    async def delete_by_id(cls, id: int | str, db: AsyncSession):
        result = await db.execute(select(cls.model).filter_by(id=id))
        obj = result.scalars().first()
        if obj:
            await db.delete(obj)
            await db.commit()
        else:
            raise ObjectNotFound()

    @classmethod
    async def delete_by(cls, criteria, db: AsyncSession):
        result = await db.execute(select(cls.model).filter(criteria))
        objects = result.scalars().all()
        for obj in objects:
            if obj:
                await db.delete(obj)
                await db.commit()
            else:
                raise ObjectNotFound()


AssignType = TypeVar('AssignType')
TargetType = TypeVar('TargetType')


class AssignDAO(Generic[AssignType, TargetType]):
    @classmethod
    async def assign_or_remove(
            cls, assign_list: List[AssignType], remove_list: List[TargetType],
            target: TargetType, attr_name: str, db: AsyncSession, target_title_attr: str = "title"
    ) -> dict:
        """
        DAO function to assign/remove items like Permission, Role to/from a target object like User, Role, Group
        :param target_title_attr: Target title attribute for response
        :param assign_list: list of AssignType items, like a list of Permissions
        :param remove_list: list of TargetType items, like a list of Roles/Users
        :param target: Object like User, Role, Group
        :param attr_name: Attribute name of assignable object, like 'permissions' or 'roles', in final it's looks like TargetModel.permissions
        :param db: Async session
        :return: dict with data who assigned/removed or skipped
        """
        accepted_and_skipped = {"accepted": [], "skipped": []}
        # Assign resources
        if assign_list:
            if not target:
                raise ObjectNotFound()
            for assign_res in assign_list:
                if assign_res not in getattr(target, attr_name):
                    getattr(target, attr_name).append(assign_res)
                    accepted_and_skipped['accepted'].append({"action": "assign", "id": assign_res.id, "title": getattr(assign_res, target_title_attr)})
                else:
                    accepted_and_skipped['skipped'].append({"action": "assign", "id": assign_res.id, "title": getattr(assign_res, target_title_attr), 'reason': "Already assigned"})

        # Remove resources
        if remove_list:
            original_assigns = list(getattr(target, attr_name))
            remove_ids = [i.id for i in remove_list]
            setattr(target, attr_name, [i for i in getattr(target, attr_name) if i.id not in remove_ids])

            q = await db.execute(select(type(remove_list[0])))
            all_items_of_target = q.scalars().all()
            for remove_id in remove_ids:
                obj = list(filter(lambda x: x.id == remove_id, all_items_of_target))[0]
                if any(i.id == remove_id for i in original_assigns):
                    accepted_and_skipped['accepted'].append(
                        {"action": "remove", "id": obj.id, "title": obj.title}
                    )
                else:
                    accepted_and_skipped['skipped'].append(
                        {"action": "remove", "id": obj.id, "title": obj.title, 'reason': "Object did not belong to this target"}
                    )

        db.add(target)
        await db.commit()
        return accepted_and_skipped


class UserDAO(BaseDAO, AssignDAO[User, Group]):
    model = User

    @classmethod
    async def change_password(cls, user_id: int, new_hashed_password: str, db: AsyncSession):
        stmt = await db.execute(
            update(cls.model).filter_by(id=user_id).values(hashed_password=new_hashed_password).returning(cls.model)
        )
        obj = stmt.scalars().first()
        if obj:
            await db.commit()
        else:
            raise ObjectNotFound()

    @classmethod
    async def close_session(cls, db: AsyncSession, user_id: int, token_id: int):
        await db.execute(delete(AccessToken).filter_by(id=token_id, user_id=user_id))

    @classmethod
    async def delete_all_tokens(cls, db: AsyncSession, user_id: int, current_token: str):
        await db.execute(delete(AccessToken).filter(AccessToken.user_id == user_id, AccessToken.token != current_token))
        await db.commit()


class TokensDAO(BaseDAO):
    model = AccessToken

    @classmethod
    async def is_token_active(cls, token: str, db: AsyncSession) -> bool:
        query = select(cls.model).filter_by(token=token)
        objects = await db.execute(query)
        token = objects.scalars().one_or_none()
        if token:
            return True
        else:
            raise ObjectNotFound()


class GroupDAO(BaseDAO):
    model = Group


class RoleDAO(BaseDAO, AssignDAO[Role, Group | User]):
    model = Role


class PermissionDAO(BaseDAO, AssignDAO[Permission, Role | User]):
    model = Permission
