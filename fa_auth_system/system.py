import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from fa_auth_system.database.models import ActionTypes, ResourceTypes, AssignableResource, Permission, BaseModel

class AuthSystem:
    def __init__(self):
        self._app = None
        self._async_session = None
        self._async_engine = None


    async def init_engine(self):
        async with self._async_engine.connect() as conn:
            await conn.run_sync(BaseModel.metadata.create_all)
            await conn.commit()

    async def get_async_session(self) -> AsyncGenerator:
        async with self._async_session() as session:
            yield session
            
    def set_conf(self, db_url: str, echo: bool):
        from fa_auth_system.routes.auth import auth_router
        from fa_auth_system.routes.main import role_router, groups_router, permissions_router, users_router
        self._async_engine = create_async_engine(db_url, echo=echo)
        self._async_session = async_sessionmaker(self._async_engine, expire_on_commit=False)

        @asynccontextmanager
        async def lifespan():
            await self.init_engine()
            yield

        self._app: FastAPI = FastAPI(lifespan=lifespan)

        self._app.include_router(auth_router)
        self._app.include_router(role_router)
        self._app.include_router(groups_router)
        self._app.include_router(permissions_router)
        self._app.include_router(users_router)

    @property
    def get_app(self) -> FastAPI:
        return self._app

    def get_session(self) -> AsyncSession:
        return self._async_session()

    async def generate_perms(self):
        with self._async_session() as db:
            resources = [r for r in ResourceTypes]
            actions = [a for a in ActionTypes]
            actions.remove(ActionTypes.assign)
            assignables = [r.value for r in AssignableResource]

            q = await db.execute(select(Permission))
            permissions = q.scalars().all()

            for resource in resources:
                for action in actions:
                    if list(filter(lambda p: p.title == f'{action.value}.{resource.value}', permissions)):
                        continue
                    try:
                        new_perm = Permission(resource=resource, action=action)
                        db.add(new_perm)
                        await db.commit()
                    except IntegrityError:
                        await db.rollback()
                        continue
            for assignable in assignables:
                if list(filter(lambda p: p.title == f'assign.{assignable.value}', permissions)):
                    continue
                try:
                    new_perm = Permission(resource=assignable, action=ActionTypes.assign)
                    db.add(new_perm)
                    await db.commit()
                except IntegrityError:
                    await db.rollback()
                    continue


auth_system = AuthSystem()