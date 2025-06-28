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

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String, unique=True)
    user_id = Column(String, ForeignKey('users.user_id'))
    createdAt = Column(DateTime(timezone=True), server_default=func.now())
    expiredAt = Column(DateTime(timezone=True))
    used = Column(Boolean)

class Category(Base):
    __tablename__ = 'categories'
    id = Column(String, primary_key=True)
    name = Column(String)
    label = Column(String)
    description = Column(String)
    restricted = Column(Boolean)


class Screenshot(Base):
    __tablename__ = 'screenshots'

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey('users.user_id'))
    image = Column(String)
    category = Column(String)
    transaction_id = Column(String)
    device_id = Column(String, ForeignKey('devices.device_id'))
    createdAt = Column(DateTime(timezone=True), server_default=func.now())

class Screentime(Base):
    __tablename__ = 'screentime'
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey('users.user_id'))
    deviceId = Column(String, ForeignKey('devices.device_id'))
    limit = Column(Integer)
    scheduleStart = Column(String)
    scheduleEnd = Column(String)

class LogScreentime(Base):
    __tablename__ = 'log_screentime'
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey('users.user_id'))
    screenTime = Column(Integer)
    timestamp = Column(String)
    device_id = Column(String, ForeignKey('devices.device_id'))
    screentime_id = Column(String, ForeignKey('screentime.id'))
    activityType = Column(String)
