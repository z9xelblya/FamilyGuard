import os
import uuid
import string
import random
import logging
from datetime import datetime, timedelta, date
from contextlib import asynccontextmanager
from typing import Optional, List
from pathlib import Path

import jwt
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Date, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from dotenv import load_dotenv
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles

# Загрузка переменных окружения
load_dotenv()

# Настройка логгирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Определяем пути
current_dir = Path(__file__).resolve().parent
static_dir = current_dir / "static"

# Создаем базовый класс для моделей
Base = declarative_base()


# Модели базы данных
class User(Base):
    __tablename__ = "users"
    user_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    firstName = Column(String, nullable=False)
    lastName = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    timezone = Column(String, nullable=False)
    phone = Column(String)
    createdAt = Column(DateTime, default=datetime.utcnow)
    devices = relationship("Device", back_populates="user")
    notifications = relationship("Notification", back_populates="user")
    statistics = relationship("Statistic", back_populates="user")
    schedules = relationship("Schedule", back_populates="user")


class Device(Base):
    __tablename__ = "devices"
    device_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    name = Column(String, nullable=False)
    model = Column(String)
    osVersion = Column(String)
    isBlocked = Column(Boolean, default=False)
    tetheredAt = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="devices")
    schedules = relationship("Schedule", back_populates="device")
    statistics = relationship("Statistic", back_populates="device")


class TetheringCode(Base):
    __tablename__ = "tethering_codes"
    code = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    expiredAt = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)


class Schedule(Base):
    __tablename__ = "schedules"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    device_id = Column(String, ForeignKey('devices.device_id'), nullable=False)
    name = Column(String, nullable=False)
    days = Column(JSON, nullable=False)  # List of days: ["mon", "tue", ...]
    start_time = Column(String, nullable=False)  # "08:00"
    end_time = Column(String, nullable=False)  # "16:00"
    type = Column(String, default="full")  # "full", "app", "web"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="schedules")
    device = relationship("Device", back_populates="schedules")


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    title = Column(String, nullable=False)
    message = Column(String, nullable=False)
    type = Column(String, default="info")  # "info", "alert", "success"
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="notifications")


class Statistic(Base):
    __tablename__ = "statistics"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    device_id = Column(String, ForeignKey('devices.device_id'))
    date = Column(Date, default=date.today)
    total_usage = Column(Integer, default=0)  # in minutes
    app_usage = Column(JSON)  # {"app1": 30, "app2": 45}
    blocked_time = Column(Integer, default=0)  # in minutes
    user = relationship("User", back_populates="statistics")
    device = relationship("Device", back_populates="statistics")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Контекст жизненного цикла приложения"""
    await init_db()
    yield


# Создаем экземпляр FastAPI
app = FastAPI(lifespan=lifespan)


# Middleware для логирования запросов
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Request: {request.method} {request.url}")
    response = await call_next(request)
    return response


# Настраиваем CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Конфигурация безопасности
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 10

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()


# Модели данных Pydantic
class UserCreate(BaseModel):
    firstName: str
    lastName: str
    email: str
    password: str
    timezone: str
    phone: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str


class DeviceTetherRequest(BaseModel):
    code: str
    deviceName: str
    deviceModel: Optional[str] = None
    osVersion: Optional[str] = None


class DeviceResponse(BaseModel):
    deviceId: str
    name: str
    model: Optional[str] = None
    osVersion: Optional[str] = None
    tetheringAt: str
    isBlocked: bool


class TetheringCodeResponse(BaseModel):
    code: str
    expiresAt: str
    validitySeconds: int


class ErrorItem(BaseModel):
    field: str
    message: str


class ErrorResponse(BaseModel):
    status: str
    code: int
    message: str
    errors: Optional[List[ErrorItem]] = None


class UserResponse(BaseModel):
    userId: str
    email: str
    firstName: str
    lastName: str
    createdAt: str


class LoginData(BaseModel):
    token: str
    userId: str
    email: str
    firstName: str
    lastName: str
    expiresAt: str


class SuccessResponse(BaseModel):
    status: str = "success"
    data: dict


class ScheduleCreate(BaseModel):
    device_id: str
    name: str
    days: List[str]
    start_time: str
    end_time: str
    type: str = "full"


class ScheduleResponse(BaseModel):
    id: str
    device_id: str
    device_name: str
    name: str
    days: List[str]
    start_time: str
    end_time: str
    type: str
    is_active: bool
    created_at: str


class NotificationResponse(BaseModel):
    id: str
    title: str
    message: str
    type: str
    is_read: bool
    created_at: str


class StatisticResponse(BaseModel):
    date: str
    total_usage: int
    app_usage: dict
    blocked_time: int


class ProfileUpdate(BaseModel):
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    phone: Optional[str] = None
    timezone: Optional[str] = None


class PasswordChange(BaseModel):
    currentPassword: str
    newPassword: str


# Новые модели для статистики
class UsageData(BaseModel):
    labels: List[str]
    data: List[int]


class AppUsageItem(BaseModel):
    name: str
    minutes: int
    category: Optional[str] = None


class CategoryUsageItem(BaseModel):
    name: str
    minutes: int


class ComparisonData(BaseModel):
    labels: List[str]
    currentWeek: List[int]
    previousWeek: List[int]
    currentWeekTotal: int
    previousWeekTotal: int
    trendPercentage: float


class StatsData(BaseModel):
    totalUsage: str
    mostUsedDevice: str
    avgDailyUsage: str
    blockedTime: str
    usageData: UsageData
    appUsage: List[AppUsageItem]
    categoryData: List[CategoryUsageItem]
    comparisonData: ComparisonData


class StatsResponse(BaseModel):
    status: str = "success"
    data: StatsData


# Модель для добавления устройства через веб
class WebDeviceCreate(BaseModel):
    name: str
    model: Optional[str] = None
    osVersion: Optional[str] = None
    tetheringCode: str


# Функция для проверки токена
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    """Верификация JWT токена"""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or missing token: {str(e)}"
        )


# Инициализация базы данных
async def init_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./familyguard.db")
    engine = create_engine(DATABASE_URL)

    # Создаем таблицы
    Base.metadata.create_all(bind=engine)

    # Создаем сессию
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    app.state.db = SessionLocal()
    logger.info("Database initialized")


# Получение сессии базы данных
def get_db():
    return app.state.db


# Обработчики ошибок
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Обработка ошибок валидации"""
    logger.error(f"Validation error: {exc}")
    errors = []
    for err in exc.errors():
        loc = err.get("loc", [])
        field = loc[-1] if loc else "body"
        errors.append({"field": field, "message": err.get("msg")})
    return JSONResponse(
        status_code=400,
        content={
            "status": "error",
            "code": 400,
            "message": "Invalid input",
            "errors": errors
        }
    )


@app.exception_handler(404)
async def spa_handler(request: Request, exc: HTTPException):
    """Обработчик для SPA - перенаправляет все запросы на index.html"""
    # Для API-путей возвращаем JSON-ошибку
    if request.url.path.startswith("/api"):
        return JSONResponse(
            status_code=404,
            content={
                "status": "error",
                "code": 404,
                "message": "Not Found"
            }
        )

    # Для всех остальных путей возвращаем index.html
    return FileResponse(static_dir / "index.html")


# Регистрация пользователя
@app.post("/api/v1/register")
async def register(payload: UserCreate, db: Session = Depends(get_db)):
    """Регистрация нового пользователя"""
    logger.info(f"Register request: {payload.dict()}")
    try:
        existing = db.query(User).filter(User.email == payload.email).first()
        if existing:
            logger.warning(f"Email already exists: {payload.email}")
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "code": 400,
                    "message": "Invalid input",
                    "errors": [
                        {
                            "field": "email",
                            "message": "Email already exists"
                        }
                    ]
                }
            )

        pwd = pwd_context.hash(payload.password)
        user = User(
            firstName=payload.firstName,
            lastName=payload.lastName,
            email=payload.email,
            password=pwd,
            timezone=payload.timezone,
            phone=payload.phone,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"User created: {user.user_id}")

        resp = UserResponse(
            userId=user.user_id,
            email=user.email,
            firstName=user.firstName,
            lastName=user.lastName,
            createdAt=user.createdAt.isoformat()
        )
        return JSONResponse(
            status_code=201,
            content={
                "status": "success",
                "data": resp.dict()
            }
        )
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Авторизация пользователя
@app.post("/api/v1/login")
async def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Авторизация пользователя"""
    logger.info(f"Login attempt for: {payload.email}")
    try:
        user = db.query(User).filter(User.email == payload.email).first()
        if not user or not pwd_context.verify(payload.password, user.password):
            logger.warning(f"Invalid credentials for: {payload.email}")
            return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "code": 401,
                    "message": "Invalid credentials"
                }
            )

        now = datetime.now()
        expire = now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)

        token = jwt.encode({
            "sub": user.user_id,
            "email": user.email,
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp())
        }, SECRET_KEY, algorithm=ALGORITHM)

        data = LoginData(
            token=token,
            userId=user.user_id,
            email=user.email,
            firstName=user.firstName,
            lastName=user.lastName,
            expiresAt=expire.isoformat()
        )
        logger.info(f"Login successful for: {user.user_id}")
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "data": data.dict()
            }
        )
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Helper function for generating tethering codes
def generate_code() -> str:
    """Генерация случайного кода привязки"""
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(5))


@app.post("/api/v1/tethering-code", status_code=201)
async def create_tethering_code(
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Создание кода для привязки устройства"""
    logger.info(f"Generating tethering code for user: {user_id}")
    try:
        now = datetime.utcnow()
        code = None
        expires_at = None

        for _ in range(5):
            c = generate_code()
            exp = now + timedelta(seconds=600)
            entry = TetheringCode(code=c, user_id=user_id, expiredAt=exp, used=False)
            db.add(entry)
            try:
                db.commit()
                code = c
                expires_at = exp
                break
            except IntegrityError:
                db.rollback()
                logger.warning(f"Code collision: {c}, retrying...")

        if not code:
            logger.error("Could not generate unique tethering code")
            raise HTTPException(
                status_code=500,
                detail="Could not generate unique tethering code"
            )

        logger.info(f"Generated code: {code} for user: {user_id}")
        return {
            "status": "success",
            "data": {
                "code": code,
                "expiresAt": expires_at.isoformat(),
                "validitySeconds": 600
            }
        }
    except Exception as e:
        logger.error(f"Tethering code error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Новый эндпоинт для привязки устройства с мобильного приложения
@app.post("/api/v1/devices/tether", status_code=201)
async def tether_device(
        payload: DeviceTetherRequest,
        db: Session = Depends(get_db)
):
    """Привязка нового устройства через мобильное приложение"""
    logger.info(f"Tethering device with code: {payload.code}")
    try:
        now = datetime.utcnow()
        code_entry = db.query(TetheringCode).filter(
            TetheringCode.code == payload.code,
            TetheringCode.used == False,
            TetheringCode.expiredAt > now
        ).first()

        if not code_entry:
            logger.warning(f"Invalid or expired tethering code: {payload.code}")
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "code": 400,
                    "message": "Invalid or expired tethering code"
                }
            )

        # Создаем новое устройство
        device = Device(
            user_id=code_entry.user_id,
            name=payload.deviceName,
            model=payload.deviceModel,
            osVersion=payload.osVersion,
            isBlocked=False
        )
        db.add(device)

        # Помечаем код как использованный
        code_entry.used = True
        db.add(code_entry)

        # Создаем уведомление
        notification = Notification(
            user_id=code_entry.user_id,
            title="New Device Added",
            message=f"Device '{payload.deviceName}' has been tethered to your account",
            type="success"
        )
        db.add(notification)

        db.commit()
        db.refresh(device)
        logger.info(f"Device tethered: {device.device_id} for user: {code_entry.user_id}")

        return JSONResponse(
            status_code=201,
            content={
                "status": "success",
                "message": "Device tethered successfully",
                "data": {
                    "deviceId": device.device_id
                }
            }
        )
    except Exception as e:
        logger.error(f"Tether device error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Эндпоинт для добавления устройства через веб-интерфейс
@app.post("/api/v1/devices", status_code=201)
async def add_device_via_web(
        payload: WebDeviceCreate,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Добавление устройства через веб-интерфейс с использованием кода привязки"""
    logger.info(f"Adding device via web with code: {payload.tetheringCode}")
    try:
        now = datetime.utcnow()
        code_entry = db.query(TetheringCode).filter(
            TetheringCode.code == payload.tetheringCode,
            TetheringCode.used == False,
            TetheringCode.expiredAt > now,
            TetheringCode.user_id == user_id
        ).first()

        if not code_entry:
            logger.warning(f"Invalid or expired tethering code: {payload.tetheringCode}")
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "code": 400,
                    "message": "Invalid or expired tethering code"
                }
            )

        # Создаем новое устройство
        device = Device(
            user_id=user_id,
            name=payload.name,
            model=payload.model,
            osVersion=payload.osVersion,
            isBlocked=False
        )
        db.add(device)

        # Помечаем код как использованный
        code_entry.used = True
        db.add(code_entry)

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="New Device Added",
            message=f"Device '{payload.name}' has been tethered to your account",
            type="success"
        )
        db.add(notification)

        db.commit()
        db.refresh(device)
        logger.info(f"Device added via web: {device.device_id}")

        return JSONResponse(
            status_code=201,
            content={
                "status": "success",
                "message": "Device added successfully",
                "data": {
                    "deviceId": device.device_id
                }
            }
        )
    except Exception as e:
        logger.error(f"Add device via web error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Получение списка устройств
@app.get("/api/v1/devices")
async def get_devices(
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Получение списка привязанных устройств"""
    logger.info(f"Getting devices for user: {user_id}")
    try:
        devices = db.query(Device).filter(Device.user_id == user_id).all()
        device_list = []
        for device in devices:
            device_list.append(DeviceResponse(
                deviceId=device.device_id,
                name=device.name,
                model=device.model,
                osVersion=device.osVersion,
                tetheringAt=device.tetheredAt.isoformat(),
                isBlocked=device.isBlocked
            ).dict())

        logger.info(f"Found {len(device_list)} devices for user: {user_id}")
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "data": device_list
            }
        )
    except Exception as e:
        logger.error(f"Get devices error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Блокировка устройства
@app.post("/api/v1/devices/{device_id}/block")
async def block_device(
        device_id: str,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Блокировка устройства"""
    logger.info(f"Blocking device: {device_id} for user: {user_id}")
    try:
        device = db.query(Device).filter(
            Device.device_id == device_id,
            Device.user_id == user_id
        ).first()

        if not device:
            logger.warning(f"Device not found: {device_id}")
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Device not found"
                }
            )

        device.isBlocked = True
        db.add(device)

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="Device Blocked",
            message=f"Device '{device.name}' has been blocked",
            type="alert"
        )
        db.add(notification)

        db.commit()
        logger.info(f"Device blocked: {device_id}")
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Device blocked"
            }
        )
    except Exception as e:
        logger.error(f"Block device error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Разблокировка устройства
@app.post("/api/v1/devices/{device_id}/unblock")
async def unblock_device(
        device_id: str,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Разблокировка устройства"""
    logger.info(f"Unblocking device: {device_id} for user: {user_id}")
    try:
        device = db.query(Device).filter(
            Device.device_id == device_id,
            Device.user_id == user_id
        ).first()

        if not device:
            logger.warning(f"Device not found: {device_id}")
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Device not found"
                }
            )

        device.isBlocked = False
        db.add(device)

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="Device Unblocked",
            message=f"Device '{device.name}' has been unblocked",
            type="success"
        )
        db.add(notification)

        db.commit()
        logger.info(f"Device unblocked: {device_id}")
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Device unblocked"
            }
        )
    except Exception as e:
        logger.error(f"Unblock device error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# ========== РАСШИРЕННЫЙ ФУНКЦИОНАЛ ==========

# Получение расписаний блокировки
@app.get("/api/v1/schedules", response_model=List[ScheduleResponse])
async def get_schedules(
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Получение расписаний блокировки"""
    try:
        schedules = db.query(Schedule).join(Device).filter(Device.user_id == user_id).all()
        response = [
            ScheduleResponse(
                id=s.id,
                device_id=s.device_id,
                device_name=s.device.name,
                name=s.name,
                days=s.days,
                start_time=s.start_time,
                end_time=s.end_time,
                type=s.type,
                is_active=s.is_active,
                created_at=s.created_at.isoformat()
            ) for s in schedules
        ]
        return response
    except Exception as e:
        logger.error(f"Get schedules error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )


# Создание расписания блокировки
@app.post("/api/v1/schedules", status_code=201)
async def create_schedule(
        schedule: ScheduleCreate,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Создание нового расписания блокировки"""
    try:
        # Проверка принадлежности устройства пользователю
        device = db.query(Device).filter(
            Device.device_id == schedule.device_id,
            Device.user_id == user_id
        ).first()

        if not device:
            logger.warning(f"Device not found: {schedule.device_id}")
            raise HTTPException(status_code=404, detail="Device not found")

        new_schedule = Schedule(
            user_id=user_id,
            device_id=schedule.device_id,
            name=schedule.name,
            days=schedule.days,
            start_time=schedule.start_time,
            end_time=schedule.end_time,
            type=schedule.type
        )

        db.add(new_schedule)

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="New Blocking Schedule",
            message=f"You created a new schedule '{schedule.name}' for {device.name}",
            type="info"
        )
        db.add(notification)

        db.commit()
        return {"status": "success", "message": "Schedule created"}
    except Exception as e:
        logger.error(f"Create schedule error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )


# Получение уведомлений
@app.get("/api/v1/notifications", response_model=List[NotificationResponse])
async def get_notifications(
        user_id: str = Depends(verify_token),
        limit: int = Query(10, gt=0),
        db: Session = Depends(get_db)
):
    """Получение уведомлений"""
    try:
        notifications = db.query(Notification).filter(
            Notification.user_id == user_id
        ).order_by(Notification.created_at.desc()).limit(limit).all()

        return [
            NotificationResponse(
                id=n.id,
                title=n.title,
                message=n.message,
                type=n.type,
                is_read=n.is_read,
                created_at=n.created_at.isoformat()
            ) for n in notifications
        ]
    except Exception as e:
        logger.error(f"Get notifications error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )


# Очистка всех уведомлений
@app.delete("/api/v1/notifications")
async def clear_notifications(
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Очистка всех уведомлений"""
    try:
        db.query(Notification).filter(Notification.user_id == user_id).delete()
        db.commit()
        return {"status": "success", "message": "All notifications cleared"}
    except Exception as e:
        logger.error(f"Clear notifications error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )


# Получение статистики использования
@app.get("/api/v1/stats")
async def get_statistics(
        user_id: str = Depends(verify_token),
        device: str = Query("all"),
        period: str = Query("week"),
        db: Session = Depends(get_db)
):
    """Получение статистики использования с фиктивными данными"""
    logger.info(f"Getting stats for user: {user_id}, device: {device}, period: {period}")
    try:
        # Фиктивные данные для графика использования
        usage_data = UsageData(
            labels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            data=[120, 90, 150, 100, 180, 240, 200]
        )

        # Фиктивные данные для использования приложений
        app_usage = [
            AppUsageItem(name="TikTok", minutes=120, category="Social"),
            AppUsageItem(name="YouTube", minutes=90, category="Entertainment"),
            AppUsageItem(name="Instagram", minutes=60, category="Social"),
            AppUsageItem(name="Chrome", minutes=45, category="Browsing"),
            AppUsageItem(name="Minecraft", minutes=30, category="Games")
        ]

        # Фиктивные данные по категориям
        category_data = [
            CategoryUsageItem(name="Social", minutes=180),
            CategoryUsageItem(name="Entertainment", minutes=90),
            CategoryUsageItem(name="Browsing", minutes=45),
            CategoryUsageItem(name="Games", minutes=30)
        ]

        # Фиктивные данные для сравнения
        comparison_data = ComparisonData(
            labels=["Social", "Entertainment", "Games", "Browsing", "Education"],
            currentWeek=[120, 90, 30, 45, 15],
            previousWeek=[100, 120, 45, 30, 20],
            currentWeekTotal=300,
            previousWeekTotal=315,
            trendPercentage=-4.76
        )

        # Формируем полный ответ
        stats_data = StatsData(
            totalUsage="12h 30m",
            mostUsedDevice="Tom's iPad",
            avgDailyUsage="2h 15m",
            blockedTime="8h 45m",
            usageData=usage_data.dict(),
            appUsage=[item.dict() for item in app_usage],
            categoryData=[item.dict() for item in category_data],
            comparisonData=comparison_data.dict()
        )

        return JSONResponse(
            status_code=200,
            content=StatsResponse(data=stats_data).dict()
        )
    except Exception as e:
        logger.error(f"Get statistics error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Получение профиля пользователя
@app.get("/api/v1/profile")
async def get_profile(
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Получение профиля пользователя"""
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return {
            "status": "success",
            "data": {
                "firstName": user.firstName,
                "lastName": user.lastName,
                "email": user.email,
                "phone": user.phone,
                "timezone": user.timezone
            }
        }
    except Exception as e:
        logger.error(f"Get profile error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )


# Обновление профиля пользователя
@app.put("/api/v1/profile")
async def update_profile(
        profile: ProfileUpdate,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Обновление профиля пользователя"""
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if profile.firstName is not None:
            user.firstName = profile.firstName
        if profile.lastName is not None:
            user.lastName = profile.lastName
        if profile.phone is not None:
            user.phone = profile.phone
        if profile.timezone is not None:
            user.timezone = profile.timezone

        db.commit()
        return {"status": "success", "message": "Profile updated"}
    except Exception as e:
        logger.error(f"Update profile error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )


# Смена пароля
@app.post("/api/v1/change-password")
async def change_password(
        passwords: PasswordChange,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Смена пароля пользователя"""
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Проверка текущего пароля
        if not pwd_context.verify(passwords.currentPassword, user.password):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        # Хеширование нового пароля
        new_password_hash = pwd_context.hash(passwords.newPassword)
        user.password = new_password_hash
        db.commit()

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="Password Changed",
            message="Your password was successfully changed",
            type="info"
        )
        db.add(notification)
        db.commit()

        return {"status": "success", "message": "Password updated"}
    except Exception as e:
        logger.error(f"Change password error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )


# Проверка здоровья сервера
@app.get("/api/v1/health")
async def health_check():
    """Проверка работоспособности сервера"""
    return {"status": "ok", "message": "Server is running"}


# Ping endpoint
@app.get("/api/v1/ping")
async def ping():
    """Проверка соединения"""
    return {"status": "success", "message": "pong"}


# Монтирование статики
app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

# Запуск сервера
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
