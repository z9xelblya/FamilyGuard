import os
import uuid
import string
import random
import logging
from datetime import datetime, timedelta, date
from contextlib import asynccontextmanager
from typing import Optional, List, Dict
from pathlib import Path
import shutil

from collections import defaultdict
from typing import Tuple

import jwt
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request, Query, UploadFile, File, Form
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
uploads_dir = current_dir / "uploads"
os.makedirs(uploads_dir, exist_ok=True)  # Создаем директорию для загрузок

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
    categories = relationship("Category", back_populates="user")
    screenshots = relationship("Screenshot", back_populates="user")
    screen_times = relationship("ScreenTime", back_populates="user")
    screen_time_logs = relationship("ScreenTimeLog", back_populates="user")


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
    screenshots = relationship("Screenshot", back_populates="device")
    screen_times = relationship("ScreenTime", back_populates="device")
    screen_time_logs = relationship("ScreenTimeLog", back_populates="device")


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


class Category(Base):
    __tablename__ = "categories"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    name = Column(String, nullable=False)
    label = Column(String)
    description = Column(String)
    restricted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="categories")


class Screenshot(Base):
    __tablename__ = "screenshots"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    device_id = Column(String, ForeignKey('devices.device_id'), nullable=False)
    image = Column(String, nullable=False)  # Путь к файлу
    category = Column(String)
    transaction_id = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="screenshots")
    device = relationship("Device", back_populates="screenshots")


class ScreenTime(Base):
    __tablename__ = "screen_times"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    device_id = Column(String, ForeignKey('devices.device_id'), nullable=False)
    limit = Column(Integer, nullable=False)  # in minutes
    schedule_start = Column(String)  # "08:00"
    schedule_end = Column(String)  # "22:00"
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="screen_times")
    device = relationship("Device", back_populates="screen_times")


class ScreenTimeLog(Base):
    __tablename__ = "screen_time_logs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    device_id = Column(String, ForeignKey('devices.device_id'), nullable=False)
    screen_time_id = Column(String, ForeignKey('screen_times.id'), nullable=False)
    screen_time = Column(Integer, nullable=False)  # in minutes
    timestamp = Column(DateTime, nullable=False)
    activity_type = Column(String)  # "app", "web", "total"
    user = relationship("User", back_populates="screen_time_logs")
    device = relationship("Device", back_populates="screen_time_logs")
    screen_time_obj = relationship("ScreenTime")


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


##классы для аппы
class LoginViaTokenRequest(BaseModel):
    """Модель запроса для входа по коду привязки"""
    tetheringCode: str


class LoginViaTokenData(BaseModel):
    """Модель ответа с данными пользователя при входе по коду"""
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

class StatisticReport(BaseModel):
    device_id: str
    date: date
    total_usage: int  # в минутах
    app_usage: Dict[str, int]  # {название_приложения: минуты}
    blocked_time: int  # в минутах

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

class CategoryCreate(BaseModel):
    name: str
    label: str
    description: str
    restricted: bool


class CategoryResponse(BaseModel):
    id: str
    name: str
    label: str
    description: str
    restricted: bool
    created_at: str


class ScreenshotCreate(BaseModel):
    category: str
    transaction_id: str
    device_id: str


class ScreenshotResponse(BaseModel):
    id: str
    image: str
    category: str
    transaction_id: str
    device_id: str
    created_at: str


class ScreenTimeCreate(BaseModel):
    device_id: str
    limit: int  # in minutes
    schedule_start: str  # "08:00"
    schedule_end: str  # "22:00"


class ScreenTimeResponse(BaseModel):
    id: str
    device_id: str
    limit: int
    schedule_start: str
    schedule_end: str
    created_at: str


class ScreenTimeLogCreate(BaseModel):
    device_id: str
    screen_time_id: str
    screen_time: int  # in minutes
    timestamp: str
    activity_type: str


class ScreenTimeLogResponse(BaseModel):
    used_time: int
    remaining: int
    limit: int
    schedule_start: str
    schedule_end: str
    last_update: str


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

    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database.db")
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
    """Обратчик для SPA - перенаправляет все запросы на index.html"""
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


##Для Гоши
@app.post("/api/v1/login-via-token", response_model=SuccessResponse)
async def login_via_token(
        payload: LoginViaTokenRequest,
        db: Session = Depends(get_db)
):
    """
    Аутентификация по коду привязки устройства
    Возвращает те же данные, что и обычный login, но с другим способом аутентификации
    """
    logger.info(f"Attempt to login via tethering code: {payload.tetheringCode}")

    try:
        now = datetime.utcnow()
        # Проверяем код на валидность
        code_entry = db.query(TetheringCode).filter(
            TetheringCode.code == payload.tetheringCode,
            TetheringCode.used == False,
            TetheringCode.expiredAt > now
        ).first()

        if not code_entry:
            logger.warning(f"Invalid tethering code: {payload.tetheringCode}")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "status": "error",
                    "code": 400,
                    "message": "Invalid or expired tethering code",
                    "errors": [{
                        "field": "tetheringCode",
                        "message": "The provided code is invalid or has expired"
                    }]
                }
            )

        # Получаем пользователя
        user = db.query(User).filter(User.user_id == code_entry.user_id).first()
        if not user:
            logger.error(f"User not found for code {code_entry.user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Помечаем код как использованный
        #code_entry.used = True
        #db.add(code_entry)

        # Создаем уведомление (в стиле первого кода)
        notification = Notification(
            user_id=user.user_id,
            title="New Device Login",
            message=f"Logged in via tethering code",
            type="info"
        )
        db.add(notification)
        db.commit()

        # Генерируем JWT токена
        expire = now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
        token = jwt.encode({
            "sub": user.user_id,
            "email": user.email,
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp())
        }, SECRET_KEY, algorithm=ALGORITHM)

        # Формируем ответ
        response_data = LoginViaTokenData(
            token=token,
            userId=user.user_id,
            email=user.email,
            firstName=user.firstName,
            lastName=user.lastName,
            expiresAt=expire.isoformat()
        )

        logger.info(f"Successful login via token for user {user.user_id}")
        return {
            "status": "success",
            "data": response_data.dict()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login via token failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
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

######### СТАТИСТИКА ПЕРВАЯ РУЧКА ДЛЯ АППЫ ВТОРАЯ ДЛЯ САЙТА #####################
@app.post("/api/v1/stats/report")
async def report_statistics(
        payload: StatisticReport,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Прием статистики использования от мобильного приложения"""
    logger.info(f"Receiving stats report for device: {payload.device_id}")

    try:
        # Проверка принадлежности устройства пользователю
        device = db.query(Device).filter(
            Device.device_id == payload.device_id,
            Device.user_id == user_id
        ).first()

        if not device:
            logger.warning(f"Device not found: {payload.device_id}")
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Device not found"
                }
            )

        # Поиск существующей записи за эту дату
        statistic = db.query(Statistic).filter(
            Statistic.user_id == user_id,
            Statistic.device_id == payload.device_id,
            Statistic.date == payload.date
        ).first()

        if statistic:
            # Обновление существующей записи
            statistic.total_usage = payload.total_usage
            statistic.app_usage = payload.app_usage
            statistic.blocked_time = payload.blocked_time
        else:
            # Создание новой записи
            statistic = Statistic(
                user_id=user_id,
                device_id=payload.device_id,
                date=payload.date,
                total_usage=payload.total_usage,
                app_usage=payload.app_usage,
                blocked_time=payload.blocked_time
            )
            db.add(statistic)

        db.commit()
        logger.info(f"Stats saved for device: {payload.device_id}, date: {payload.date}")

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Statistics saved"
            }
        )
    except Exception as e:
        logger.error(f"Save statistics error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


def minutes_to_hh_mm(minutes: int) -> str:
    """Конвертирует минуты в формат 'Xh Ym'"""
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins}m" if hours > 0 else f"{mins}m"


def get_week_dates(period: str) -> Tuple[date, date]:
    """Возвращает даты начала и конца периода"""
    today = date.today()

    if period == "week":
        start = today - timedelta(days=today.weekday())
        end = start + timedelta(days=6)
    elif period == "month":
        start = date(today.year, today.month, 1)
        # Исправление для декабря
        if today.month == 12:
            end = date(today.year + 1, 1, 1) - timedelta(days=1)
        else:
            end = date(today.year, today.month + 1, 1) - timedelta(days=1)
    else:  # day
        start = today
        end = today

    return start, end


@app.get("/api/v1/stats")
async def get_statistics(
        user_id: str = Depends(verify_token),
        device_id: str = Query("all"),
        period: str = Query("week"),
        db: Session = Depends(get_db)
):
    """Получение статистики использования (реальные данные)"""
    logger.info(f"Getting stats for user: {user_id}, device: {device_id}, period: {period}")

    try:
        # Определяем временной период
        start_date, end_date = get_week_dates(period)

        # Получаем данные из базы
        query = db.query(Statistic).filter(
            Statistic.user_id == user_id,
            Statistic.date.between(start_date, end_date)
        )

        if device_id != "all":
            query = query.filter(Statistic.device_id == device_id)

        stats = query.all()

        # Если данных нет, возвращаем пустой ответ
        if not stats:
            return JSONResponse(
                status_code=200,
                content=StatsResponse(data=StatsData(
                    totalUsage="0m",
                    mostUsedDevice="No data",
                    avgDailyUsage="0m",
                    blockedTime="0m",
                    usageData=UsageData(labels=[], data=[]).dict(),
                    appUsage=[],
                    categoryData=[],
                    comparisonData=ComparisonData(
                        labels=[],
                        currentWeek=[],
                        previousWeek=[],
                        currentWeekTotal=0,
                        previousWeekTotal=0,
                        trendPercentage=0.0
                    ).dict()
                )).dict()
            )

        # Анализ данных
        total_usage = sum(s.total_usage for s in stats)
        blocked_time = sum(s.blocked_time for s in stats)

        # Находим самое используемое устройство
        device_usage = defaultdict(int)
        for s in stats:
            device_usage[s.device_id] += s.total_usage

        if device_usage:
            most_used_device_id = max(device_usage, key=device_usage.get)
            device = db.query(Device).filter(Device.device_id == most_used_device_id).first()
            most_used_device = device.name if device else "Unknown device"
        else:
            most_used_device = "No devices"

        # Рассчитываем среднее дневное использование
        days_count = (end_date - start_date).days + 1
        avg_daily = total_usage // days_count

        # Данные для графика (по дням)
        usage_by_day = defaultdict(int)
        current_date = start_date
        while current_date <= end_date:
            usage_by_day[current_date] = 0
            current_date += timedelta(days=1)

        for s in stats:
            usage_by_day[s.date] += s.total_usage

        # Форматируем даты для меток
        day_labels = [d.strftime("%a") for d in sorted(usage_by_day.keys())]
        day_data = [usage_by_day[d] for d in sorted(usage_by_day.keys())]

        # Топ приложений
        app_usage = defaultdict(int)
        for s in stats:
            if s.app_usage:
                for app, minutes in s.app_usage.items():
                    app_usage[app] += minutes

        top_apps = sorted(app_usage.items(), key=lambda x: x[1], reverse=True)[:5]
        app_usage_data = [
            AppUsageItem(name=app, minutes=minutes, category="")
            for app, minutes in top_apps
        ]

        # Данные для сравнения (текущая и предыдущая неделя)
        prev_start = start_date - timedelta(days=7)
        prev_end = end_date - timedelta(days=7)

        prev_stats = db.query(Statistic).filter(
            Statistic.user_id == user_id,
            Statistic.date.between(prev_start, prev_end)
        ).all()

        prev_total = sum(s.total_usage for s in prev_stats) if prev_stats else 0

        # Расчет изменения в процентах
        trend_percentage = 0.0
        if prev_total > 0:
            trend_percentage = ((total_usage - prev_total) / prev_total) * 100

        # Формируем ответ
        stats_data = StatsData(
            totalUsage=minutes_to_hh_mm(total_usage),
            mostUsedDevice=most_used_device,
            avgDailyUsage=minutes_to_hh_mm(avg_daily),
            blockedTime=minutes_to_hh_mm(blocked_time),
            usageData=UsageData(
                labels=day_labels,
                data=day_data
            ).dict(),
            appUsage=[item.dict() for item in app_usage_data],
            categoryData=[],
            comparisonData=ComparisonData(
                labels=["Total Usage"],
                currentWeek=[total_usage],
                previousWeek=[prev_total],
                currentWeekTotal=total_usage,
                previousWeekTotal=prev_total,
                trendPercentage=trend_percentage
            ).dict()
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

# Получение статистики использования
#@app.get("/api/v1/stats")
#async def get_statistics(
#        user_id: str = Depends(verify_token),
#        device: str = Query("all"),
#        period: str = Query("week"),
#        db: Session = Depends(get_db)
#):
#    """Получение статистики использования с фиктивными данными"""
#    logger.info(f"Getting stats for user: {user_id}, device: {device}, period: {period}")
#    try:
#        # Фиктивные данные для графика использования
#        usage_data = UsageData(
#            labels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
#            data=[120, 90, 150, 100, 180, 240, 200]
#        )
#
#        # Фиктивные данные для использования приложений
#        app_usage = [
#            AppUsageItem(name="TikTok", minutes=120, category="Social"),
#            AppUsageItem(name="YouTube", minutes=90, category="Entertainment"),
#            AppUsageItem(name="Instagram", minutes=60, category="Social"),
#            AppUsageItem(name="Chrome", minutes=45, category="Browsing"),
#           AppUsageItem(name="Minecraft", minutes=30, category="Games")
#        ]
#
#        # Фиктивные данные по категориям
#        category_data = [
#            CategoryUsageItem(name="Social", minutes=180),
#            CategoryUsageItem(name="Entertainment", minutes=90),
#            CategoryUsageItem(name="Browsing", minutes=45),
#            CategoryUsageItem(name="Games", minutes=30)
#        ]
#
#        # Фиктивные данные для сравнения
#        comparison_data = ComparisonData(
#            labels=["Social", "Entertainment", "Games", "Browsing", "Education"],
#            currentWeek=[120, 90, 30, 45, 15],
#            previousWeek=[100, 120, 45, 30, 20],
#            currentWeekTotal=300,
#            previousWeekTotal=315,
#            trendPercentage=-4.76
#        )
#
#        # Формируем полный ответ
#        stats_data = StatsData(
#            totalUsage="12h 30m",
#            mostUsedDevice="Tom's iPad",
#            avgDailyUsage="2h 15m",
#            blockedTime="8h 45m",
#            usageData=usage_data.dict(),
#            appUsage=[item.dict() for item in app_usage],
#            categoryData=[item.dict() for item in category_data],
#            comparisonData=comparison_data.dict()
#        )
#
#        return JSONResponse(
#            status_code=200,
#            content=StatsResponse(data=stats_data).dict()
#        )
#    except Exception as e:
#        logger.error(f"Get statistics error: {str(e)}")
#       return JSONResponse(
#            status_code=500,
#           content={
#                "status": "error",
#               "message": "Internal server error"
#            }
#     )


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


# ========== НОВЫЕ ФУНКЦИИ ИЗ КОДА Степы==========

# Категории приложений
@app.post("/api/v1/categories", status_code=status.HTTP_201_CREATED)
async def create_category(
        payload: CategoryCreate,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Создание новой категории приложений"""
    logger.info(f"Creating category: {payload.name}")
    try:
        category = Category(
            user_id=user_id,
            name=payload.name,
            label=payload.label,
            description=payload.description,
            restricted=payload.restricted
        )
        db.add(category)
        db.commit()
        db.refresh(category)

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="New Category Created",
            message=f"Category '{payload.name}' was created",
            type="info"
        )
        db.add(notification)
        db.commit()

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "status": "success",
                "message": "Category created",
                "data": {
                    "id": category.id,
                    "name": category.name,
                    "label": category.label,
                    "description": category.description,
                    "restricted": category.restricted,
                    "created_at": category.created_at.isoformat()
                }
            }
        )
    except Exception as e:
        logger.error(f"Create category error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


@app.get("/api/v1/categories", response_model=List[CategoryResponse])
async def get_categories(
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Получение списка категорий"""
    try:
        categories = db.query(Category).filter(Category.user_id == user_id).all()
        return [
            CategoryResponse(
                id=cat.id,
                name=cat.name,
                label=cat.label,
                description=cat.description,
                restricted=cat.restricted,
                created_at=cat.created_at.isoformat()
            ) for cat in categories
        ]
    except Exception as e:
        logger.error(f"Get categories error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.delete("/api/v1/categories/{category_id}")
async def delete_category(
        category_id: str,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Удаление категории"""
    logger.info(f"Deleting category: {category_id}")
    try:
        category = db.query(Category).filter(
            Category.id == category_id,
            Category.user_id == user_id
        ).first()
        if not category:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Category not found"
                }
            )

        db.delete(category)

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="Category Deleted",
            message=f"Category '{category.name}' was deleted",
            type="warning"
        )
        db.add(notification)
        db.commit()

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "success",
                "message": "Category deleted"
            }
        )
    except Exception as e:
        logger.error(f"Delete category error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Скриншоты
@app.post("/api/v1/screenshots", status_code=status.HTTP_201_CREATED)
async def upload_screenshot(
        category: str = Form(...),
        transaction_id: str = Form(...),
        device_id: str = Form(...),
        file: UploadFile = File(...),
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Загрузка скриншота"""
    logger.info(f"Uploading screenshot for device: {device_id}")
    try:
        # Проверяем существование устройства
        device = db.query(Device).filter(
            Device.device_id == device_id,
            Device.user_id == user_id
        ).first()
        if not device:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Device not found"
                }
            )

        # Сохраняем файл
        file_ext = os.path.splitext(file.filename)[1] if file.filename else ".jpg"
        filename = f"{uuid.uuid4().hex}{file_ext}"
        file_path = os.path.join(uploads_dir, filename)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Создаем запись в БД
        screenshot = Screenshot(
            user_id=user_id,
            device_id=device_id,
            image=filename,  # Сохраняем только имя файла
            category=category,
            transaction_id=transaction_id
        )
        db.add(screenshot)

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="New Screenshot",
            message=f"Screenshot uploaded from {device.name}",
            type="info"
        )
        db.add(notification)
        db.commit()
        db.refresh(screenshot)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "status": "success",
                "message": "Screenshot uploaded",
                "data": {
                    "id": screenshot.id,
                    "image": f"/uploads/{filename}",
                    "category": screenshot.category,
                    "transaction_id": screenshot.transaction_id,
                    "device_id": screenshot.device_id,
                    "created_at": screenshot.created_at.isoformat()
                }
            }
        )
    except Exception as e:
        logger.error(f"Upload screenshot error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Управление экранным временем
@app.post("/api/v1/screen-time", status_code=status.HTTP_201_CREATED)
async def create_screen_time(
        payload: ScreenTimeCreate,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Создание ограничения экранного времени"""
    logger.info(f"Creating screen time limit for device: {payload.device_id}")
    try:
        # Проверяем существование устройства
        device = db.query(Device).filter(
            Device.device_id == payload.device_id,
            Device.user_id == user_id
        ).first()
        if not device:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Device not found"
                }
            )

        screen_time = ScreenTime(
            user_id=user_id,
            device_id=payload.device_id,
            limit=payload.limit,
            schedule_start=payload.schedule_start,
            schedule_end=payload.schedule_end
        )
        db.add(screen_time)

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="Screen Time Limit Set",
            message=f"Screen time limit set for {device.name}",
            type="info"
        )
        db.add(notification)
        db.commit()
        db.refresh(screen_time)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "status": "success",
                "message": "Screen time limit created",
                "data": {
                    "id": screen_time.id,
                    "device_id": screen_time.device_id,
                    "limit": screen_time.limit,
                    "schedule_start": screen_time.schedule_start,
                    "schedule_end": screen_time.schedule_end,
                    "created_at": screen_time.created_at.isoformat()
                }
            }
        )
    except Exception as e:
        logger.error(f"Create screen time error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


@app.get("/api/v1/screen-time", response_model=List[ScreenTimeResponse])
async def get_screen_times(
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Получение списка ограничений экранного времени"""
    try:
        screen_times = db.query(ScreenTime).filter(
            ScreenTime.user_id == user_id
        ).all()

        return [
            ScreenTimeResponse(
                id=st.id,
                device_id=st.device_id,
                limit=st.limit,
                schedule_start=st.schedule_start,
                schedule_end=st.schedule_end,
                created_at=st.created_at.isoformat()
            ) for st in screen_times
        ]
    except Exception as e:
        logger.error(f"Get screen times error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.put("/api/v1/screen-time/{screen_time_id}")
async def update_screen_time(
        screen_time_id: str,
        payload: ScreenTimeCreate,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Обновление ограничения экранного времени"""
    logger.info(f"Updating screen time limit: {screen_time_id}")
    try:
        screen_time = db.query(ScreenTime).filter(
            ScreenTime.id == screen_time_id,
            ScreenTime.user_id == user_id
        ).first()
        if not screen_time:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Screen time limit not found"
                }
            )

        # Проверяем существование устройства
        device = db.query(Device).filter(
            Device.device_id == payload.device_id,
            Device.user_id == user_id
        ).first()
        if not device:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Device not found"
                }
            )

        screen_time.device_id = payload.device_id
        screen_time.limit = payload.limit
        screen_time.schedule_start = payload.schedule_start
        screen_time.schedule_end = payload.schedule_end

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="Screen Time Limit Updated",
            message=f"Screen time limit updated for {device.name}",
            type="info"
        )
        db.add(notification)
        db.commit()
        db.refresh(screen_time)

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "success",
                "message": "Screen time limit updated",
                "data": {
                    "id": screen_time.id,
                    "device_id": screen_time.device_id,
                    "limit": screen_time.limit,
                    "schedule_start": screen_time.schedule_start,
                    "schedule_end": screen_time.schedule_end,
                    "created_at": screen_time.created_at.isoformat()
                }
            }
        )
    except Exception as e:
        logger.error(f"Update screen time error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


@app.delete("/api/v1/screen-time/{screen_time_id}")
async def delete_screen_time(
        screen_time_id: str,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Удаление ограничения экранного времени"""
    logger.info(f"Deleting screen time limit: {screen_time_id}")
    try:
        screen_time = db.query(ScreenTime).filter(
            ScreenTime.id == screen_time_id,
            ScreenTime.user_id == user_id
        ).first()
        if not screen_time:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Screen time limit not found"
                }
            )

        device_name = screen_time.device.name if screen_time.device else "Unknown device"

        db.delete(screen_time)

        # Создаем уведомление
        notification = Notification(
            user_id=user_id,
            title="Screen Time Limit Removed",
            message=f"Screen time limit removed for {device_name}",
            type="warning"
        )
        db.add(notification)
        db.commit()

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "success",
                "message": "Screen time limit deleted"
            }
        )
    except Exception as e:
        logger.error(f"Delete screen time error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


@app.post("/api/v1/screen-time/log", status_code=status.HTTP_201_CREATED)
async def log_screen_time(
        payload: ScreenTimeLogCreate,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    """Логирование экранного времени"""
    logger.info(f"Logging screen time for device: {payload.device_id}")
    try:
        # Проверяем существование устройства
        device = db.query(Device).filter(
            Device.device_id == payload.device_id,
            Device.user_id == user_id
        ).first()
        if not device:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Device not found"
                }
            )

        # Проверяем существование ограничения
        screen_time = db.query(ScreenTime).filter(
            ScreenTime.id == payload.screen_time_id,
            ScreenTime.user_id == user_id
        ).first()
        if not screen_time:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "status": "error",
                    "code": 404,
                    "message": "Screen time limit not found"
                }
            )

        # Создаем запись лога
        log = ScreenTimeLog(
            user_id=user_id,
            device_id=payload.device_id,
            screen_time_id=payload.screen_time_id,
            screen_time=payload.screen_time,
            timestamp=datetime.fromisoformat(payload.timestamp),
            activity_type=payload.activity_type
        )
        db.add(log)
        db.commit()

        # Вычисляем использованное и оставшееся время
        logs = db.query(ScreenTimeLog).filter(
            ScreenTimeLog.screen_time_id == payload.screen_time_id
        ).all()

        used_time = sum(log.screen_time for log in logs)
        remaining = max(0, screen_time.limit - used_time)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "status": "success",
                "message": "Screen time logged",
                "data": {
                    "used_time": used_time,
                    "remaining": remaining,
                    "limit": screen_time.limit,
                    "schedule_start": screen_time.schedule_start,
                    "schedule_end": screen_time.schedule_end,
                    "last_update": datetime.utcnow().isoformat()
                }
            }
        )
    except Exception as e:
        logger.error(f"Log screen time error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


# Монтирование статики
app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
app.mount("/uploads", StaticFiles(directory=uploads_dir), name="uploads")

# Запуск сервера
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
