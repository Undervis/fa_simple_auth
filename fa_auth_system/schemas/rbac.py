from pydantic import ConfigDict, AfterValidator
from typing import Optional, List, Dict, Any, Annotated
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr
from fa_auth_system.database.models import ResourceTypes, ActionTypes


def password_validator(value: str) -> str:
    def is_digit_line():
        digit_line = []
        line_digits_count = 0
        for (char, index) in zip(value, range(len(value))):
            if char.isdigit():
                digit_line.append(char)
            if len(digit_line) > 0 and char.isdigit():
                if int(digit_line[index - 1]) == (int(char) - 1):
                    line_digits_count += 1
                else:
                    line_digits_count = 0
        return line_digits_count >= 4

    if len(value) < 8:
        raise ValueError("Password must be at least 8 characters long")
    elif not any(v.isdigit() for v in value):
        raise ValueError("Password must contain at least one digit")
    elif not any(v.isalpha() for v in value):
        raise ValueError("Password must contain at least one letter")
    elif is_digit_line():
        raise ValueError("Don't use a linear digits sequence")
    else:
        return value


Password = Annotated[str, AfterValidator(password_validator)]

# User schemas
class UserSchema(BaseModel):
    username: str = Field(examples=["username"])
    email: EmailStr | None = Field(description="The email address of the user", examples=["example@example.com"])
    first_name: str | None = Field(max_length=32, description="The first name of the user", examples=["John"])
    last_name: str | None = Field(max_length=32, description="The last name of the user", examples=["Doe"])

    is_active: bool = True
    is_superuser: bool = False

    class Config:
        from_attributes = True


class UserResponse(UserSchema):
    id: int = Field(..., alias="id")
    created_at: datetime

    roles: 'list[RoleSimpleResponse]'
    permissions: 'list[PermissionSimpleResponse]'
    groups: 'list[GroupSimpleResponse]'

    class Config:
        from_attributes = True


class UserRegister(BaseModel):
    username: str = Field(description="The username of the user", min_length=3, examples=["username"])
    password: Password = Field(description="Password of the user", examples=["Very strong password"])
    first_name: str | None = Field(max_length=32, description="First name of the user", default=None, examples=["John"])
    last_name: str | None = Field(max_length=32, description="Last name of the user", default=None, examples=["Doe"])

    model_config = ConfigDict(extra='forbid')


class UserChangePassword(BaseModel):
    current_password: str = Field(description="Current password of the user", examples=["Very strong password"])
    new_password: Password = Field(description="New password of the user", examples=["Very strong password"])

    model_config = ConfigDict(extra='forbid')


# Roles
class RoleBase(BaseModel):
    title: str
    description: str | None
    grade: int


class RoleCreate(RoleBase):
    pass


class RoleResponse(RoleBase):
    id: int
    permissions: List["PermissionResponse"] = []

    model_config = ConfigDict(from_attributes=True)


class RoleSimpleResponse(RoleBase):
    id: int
    title: str

    permissions: List["PermissionSimpleResponse"]
    model_config = ConfigDict(from_attributes=True)


# Permission models
class PermissionBase(BaseModel):
    title: str
    resource: ResourceTypes
    action: ActionTypes
    description: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class PermissionCreate(PermissionBase):
    pass


class PermissionResponse(PermissionBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class PermissionSimpleResponse(BaseModel):
    id: int
    title: str

    model_config = ConfigDict(from_attributes=True)


# Group models
class GroupBase(BaseModel):
    title: str
    description: Optional[str] = None


class GroupCreate(GroupBase):
    pass


class GroupResponse(GroupBase):
    id: int
    users: 'List[UserResponse]' = []
    roles: 'List[RoleResponse]' = []

    model_config = ConfigDict(from_attributes=True)


class GroupSimpleResponse(BaseModel):
    id: int
    title: str

    model_config = ConfigDict(from_attributes=True)


# Return token
class Token(BaseModel):
    access_token: str
    token_type: str = 'Bearer'


class Session(BaseModel):
    id: int
    client_data: dict | None = Field(examples=[{
        "ip_address": '127.0.0.1',
        "platform": "Windows",
        "user_agent": "Mozilla/5.0",
    }])

    model_config = ConfigDict(from_attributes=True)


# For assign somthing to target
class AssignInput(BaseModel):
    assign: List[int]
    remove: List[int]


class AssignResponse(BaseModel):
    accepted: List = Field(examples=[{'id': 123, "title": "read.auth_users"}])
    skipped: List = Field(examples=[{'id': 999, "title": "create.auth_users"}])
    target_id: int = Field(examples=[123, 999])
    target_type: str = Field(examples=["auth_users", "auth_roles"])
    not_found_ids: List[int] = Field(examples=[[123, 999]])


class AssignConflictResponse(BaseModel):
    msg: str = Field(examples=["This objects was skipped."])
    skipped: List = Field(examples=[
        [
            {'action': 'assign', 'id': 123, "title": "create.auth_users", 'reason': "Already assigned"},
            {'action': 'remove', 'id': 123, "title": "read.auth_users", 'reason': "Object did not belong to this target"},
        ]
    ])
