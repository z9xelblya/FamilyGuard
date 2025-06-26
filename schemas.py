from datetime import datetime
from typing import List

from pydantic import BaseModel, EmailStr, root_validator, model_validator, Field, ConfigDict


class UserBase(BaseModel):
    email: EmailStr
    firstName: str
    lastName: str
    timezone: str
    phone: str


class UserCreate(UserBase):
    password: str
    confirmPassword: str

    @model_validator(mode='after')
    def check_password(cls, values):
        if values.password != values.confirmPassword:
            raise ValueError('Passwords do not match')
        return values

class UserResponse(BaseModel):
    userId: str
    email: str
    firstName: str
    lastName: str
    createdAt: str

    model_config = ConfigDict(from_attributes=True)


class DeviceInfo(BaseModel):
    deviceId: str
    platform: str
    appVersion: str

    model_config = ConfigDict(from_attributes=True)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    deviceInfo: DeviceInfo

class LoginData(BaseModel):
    token: str
    userId: str
    email: EmailStr
    firstName: str
    lastName: str
    expiresAt: str

    model_config = ConfigDict(from_attributes=True)



class ScreenshotBase(BaseModel):
    category: str
    transaction_id: str
    device_id: str

class ScreenshotCreate(ScreenshotBase):
    pass


class ScreenshotResponse(ScreenshotBase):
    id: str
    image: str
    model_config = ConfigDict(from_attributes=True)

class DeviceBase(BaseModel):
    name: str
    model: str
    osVersion: str


class DeviceCreate(DeviceBase):
    tetheringCode: str


class DeviceResponse(BaseModel):
    deviceId: str
    name: str
    model: str
    osVersion: str
    tetheringAt: str

    model_config = ConfigDict(from_attributes=True)

class TetherResponse(BaseModel):
    code: str
    expiredAt: str
    validitySeconds: int

    model_config = ConfigDict(from_attributes=True)

class CategoryBase(BaseModel):
    name: str
    label: str
    description: str
    restricted: bool


class CategoryCreate(CategoryBase):
    pass

class CategoryResponse(BaseModel):
    categoryId: str
    name: str
    label: str
    description: str
    restricted: bool

    model_config = ConfigDict(from_attributes=True)

class ErrorItem(BaseModel):
    field: str
    message: str

    model_config = ConfigDict(from_attributes=True)


class ErrorResponse(BaseModel):

    status: str = Field("error")
    code: int
    message: str
    errors: List[ErrorItem]

    model_config = ConfigDict(from_attributes=True)

class SuccessResponse(BaseModel):
    status: str = Field("success")
    data: object

    model_config = ConfigDict(from_attributes=True)