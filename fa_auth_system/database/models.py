import enum
from typing import List, TypeVar, Any
from datetime import datetime, timezone
from sqlalchemy import String, ForeignKey, JSON, TEXT, Table, Column, Integer, text, Enum, Text, MetaData
from sqlalchemy.orm import Mapped, mapped_column, relationship, DeclarativeBase

ORM_Model = TypeVar("ORM_Model")

class BaseModel(DeclarativeBase):
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_`%(constraint_name)s`",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )

    def __repr__(self):
        cols = []
        for column in self.__table__.columns.keys():
            cols.append(f'{column}={getattr(self, column)}')

        return f"<{self.__class__.__name__}> ({', '.join(cols)})"

def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ActionTypes(enum.Enum):
    assign = "assign"
    create = "create"
    update = "update"
    delete = "delete"
    read = "read"


class ResourceTypes(str, enum.Enum):
    auth_system = "auth_system"
    auth_users = "auth_users"
    auth_permissions = "auth_permissions"
    auth_roles = "auth_roles"
    auth_groups = "auth_groups"


class AssignableResource(enum.Enum):
    auth_users = ResourceTypes.auth_users
    auth_roles = ResourceTypes.auth_roles
    auth_groups = ResourceTypes.auth_groups


user_roles = Table(
    'auth_user_roles',
    BaseModel.metadata,
    Column('user_id', Integer, ForeignKey('auth_users.id', ondelete='CASCADE')),
    Column('group_id', Integer, ForeignKey('auth_roles.id', ondelete='CASCADE'))
)

role_permissions = Table(
    'auth_role_permissions',
    BaseModel.metadata,
    Column('permission_id', Integer, ForeignKey('auth_permissions.id', ondelete='CASCADE')),
    Column('role_id', Integer, ForeignKey('auth_roles.id', ondelete='CASCADE'))
)

user_permissions = Table(
    'auth_user_permissions',
    BaseModel.metadata,
    Column('user_id', Integer, ForeignKey('auth_users.id', ondelete='CASCADE')),
    Column('permission_id', Integer, ForeignKey('auth_permissions.id', ondelete='CASCADE'))
)

user_groups = Table(
    'auth_user_groups',
    BaseModel.metadata,
    Column('user_id', Integer, ForeignKey('auth_users.id', ondelete='CASCADE')),
    Column('group_id', Integer, ForeignKey('auth_groups.id', ondelete='CASCADE'))
)

group_roles = Table(
    'auth_group_roles',
    BaseModel.metadata,
    Column('group_id', Integer, ForeignKey('auth_groups.id', ondelete='CASCADE')),
    Column('role_id', Integer, ForeignKey('auth_roles.id', ondelete='CASCADE'))
)


class Permission(BaseModel):
    __tablename__ = 'auth_permissions'
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(64), unique=True)
    resource: Mapped[str] = mapped_column(Enum(ResourceTypes))
    action: Mapped[str] = mapped_column(Enum(ActionTypes))
    conditions: Mapped[JSON | None] = mapped_column(type_=JSON)
    description: Mapped[str | None] = mapped_column(TEXT)

    roles: Mapped[List['Role']] = relationship(secondary=role_permissions, back_populates='permissions')
    users: Mapped[List['User']] = relationship(secondary=user_permissions, back_populates='permissions')

    def __init__(self, **kw: Any):
        super().__init__(**kw)
        self.title = f"{kw.get('action').value}.{kw.get('resource').value}__{self.title}"


class Role(BaseModel):
    __tablename__ = 'auth_roles'
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(32), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    grade: Mapped[int]

    users: Mapped[list['User']] = relationship(secondary=user_roles, back_populates='roles')
    permissions: Mapped[list['Permission']] = relationship(secondary=role_permissions, back_populates='roles')
    groups: Mapped[list['Group']] = relationship(secondary=group_roles, back_populates='roles')



class Group(BaseModel):
    __tablename__ = 'auth_groups'
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str | None] = mapped_column(Text)

    users: Mapped[List['User']] = relationship(secondary=user_groups, back_populates='groups')
    roles: Mapped[List['Role']] = relationship(secondary=group_roles, back_populates='groups')


class User(BaseModel):
    __tablename__ = "auth_users"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(unique=True, index=True)
    email: Mapped[str | None] = mapped_column(unique=True, index=True)
    first_name: Mapped[str | None] = mapped_column(String(32))
    last_name: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', now())"))

    is_active: Mapped[bool] = mapped_column(default=True)
    is_staff: Mapped[bool] = mapped_column(default=False)
    is_superuser: Mapped[bool] = mapped_column(default=False)
    is_verified: Mapped[bool] = mapped_column(default=False)

    hashed_password: Mapped[str]

    roles: Mapped[list['Role']] = relationship(secondary=user_roles, back_populates="users")
    permissions: Mapped[list['Permission']] = relationship(secondary=user_permissions, back_populates="users")
    groups: Mapped[list['Group']] = relationship(secondary=user_groups, back_populates="users")
    audit_logs: Mapped[list['AuditLog']] = relationship(back_populates="user")
    access_tokens: Mapped[list['AccessToken']] = relationship(back_populates="user")


class AuditLog(BaseModel):
    __tablename__ = "auth_audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey('auth_users.id', ondelete='SET NULL'))
    action: Mapped[enum.Enum] = mapped_column(Enum(ActionTypes))
    resource_type: Mapped[enum.Enum] = mapped_column(Enum(ResourceTypes))
    resource_id: Mapped[int | None]
    details: Mapped[JSON | None] = mapped_column(type_=JSON)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    timestamp: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', now())"))

    user: Mapped[User | None] = relationship(back_populates="audit_logs")


class AccessToken(BaseModel):
    __tablename__ = "auth_access_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[User] = mapped_column(ForeignKey('auth_users.id', ondelete='CASCADE'), nullable=True)
    token: Mapped[str] = mapped_column(unique=True, index=True)
    client_data: Mapped[JSON] = mapped_column(type_=JSON)

    user: Mapped[User] = relationship(back_populates="access_tokens")