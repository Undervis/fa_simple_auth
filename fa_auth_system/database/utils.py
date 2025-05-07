'''from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from auth_system.database.models import BaseModel

async_engine = create_async_engine("")
async_session = async_sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)


async def init_db(db_url: str, echo: bool = False):
    global async_session, async_engine
    async_engine = create_async_engine(url=db_url, echo=echo)
    async_session = async_sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)
    async with async_engine.connect() as conn:
        await conn.run_sync(BaseModel.metadata.create_all)
        await conn.commit()


async def get_async_session():
    async with async_session() as session:
        yield session'''