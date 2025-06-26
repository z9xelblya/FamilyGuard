import uuid

from pydantic.v1 import root_validator
from sqlalchemy import Column, Integer, ForeignKey, String, DateTime, func, Boolean
from database import Base

class User(Base):
    __tablename__ = 'users'

    user_id = Column(String, primary_key=True)
    firstName = Column(String)
    lastName = Column(String)
    email = Column(String)
    password = Column(String)
    phone = Column(String)
    timezone = Column(String)
    createdAt = Column(DateTime(timezone=True), server_default=func.now())

class Device(Base):
    __tablename__ = 'devices'

    device_id = Column(String, primary_key=True)
    name = Column(String)
    model = Column(String)
    osVersion = Column(String)
    isBlocked = Column(Boolean)
    user_id = Column(String, ForeignKey('users.user_id'))
    tetheredAt = Column(DateTime(timezone=True), server_default=func.now())

class TetheringCode(Base):
    __tablename__ = 'tethering_code'

    id = Column(Integer, primary_key=True,autoincrement=True)
    code = Column(String, unique=True)
    user_id = Column(String, ForeignKey('users.user_id'))
    createdAt = Column(DateTime(timezone=True), server_default=func.now())
    expiredAt = Column(DateTime(timezone=True))
    used = Column(Boolean)

# class Screenshot(Base):
#     __tablename__ = 'screenshots'
#
#     id = Column(Integer, primary_key=True)
#     user_id = Column(Integer, ForeignKey('user.user_id'), nullable=False, index=True)
#     device_id = Column(String)
#     category = Column(String)
#     app_name = Column(String)
#     screen_time = Column(Integer)
#     image_path = Column(String)