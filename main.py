import base64
import os
import string
import uuid
from contextlib import asynccontextmanager
from datetime import timedelta, timezone
import random

from typing import Optional

import jwt  # PyJWT

import uvicorn
from fastapi import FastAPI, Form, UploadFile, File, Depends, HTTPException, Request, Header
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext
from sqlalchemy.exc import IntegrityError
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR, HTTP_201_CREATED

from database import init_db, get_db, Session
from models import *
from schemas import *

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
app = FastAPI(prefix="/api/v1", lifespan=lifespan)

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-very-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 1  # token valid for 1 hour

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

uploads_directory = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(uploads_directory):
    os.makedirs(uploads_directory)

app.mount('/uploads', StaticFiles(directory=uploads_directory))

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        loc = err.get("loc", [])
        field = loc[-1] if loc else "body"
        msg = err.get("msg")
        errors.append({"field": field, "message": msg})
    content = {
        "status": "error",
        "code": 400,
        "message": "Invalid input",
        "errors": errors,
    }
    return JSONResponse(status_code=400, content=content)

@app.post("/register")
async def register(payload: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        err = ErrorResponse(status="error", code=400, message="Invalid input", errors=[ErrorItem(field="email", message="Email already exists")])
        return JSONResponse(status_code=400, content=err.model_dump())
    password = pwd_context.hash(payload.password)
    new_user = User(user_id=str(uuid.uuid4()), firstName=payload.firstName, lastName=payload.lastName, email=str(payload.email), password=password, timezone=payload.timezone, phone=str(payload.phone))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    user_response = UserResponse(userId=new_user.user_id, email=new_user.email, firstName=new_user.firstName, lastName=new_user.lastName, createdAt=new_user.createdAt.isoformat())
    resp = SuccessResponse(data=user_response.dict())
    return JSONResponse(status_code=201, content=resp.model_dump())


@app.post("/login")
async def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    # 1. Verify user exists
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        # invalid credentials
        content = {
            "status": "error",
            "code": 401,
            "message": "Invalid credentials"
        }
        return JSONResponse(status_code=401, content=content)

    # 2. Verify password
    if not pwd_context.verify(payload.password, user.password):
        content = {
            "status": "error",
            "code": 401,
            "message": "Invalid credentials"
        }
        return JSONResponse(status_code=401, content=content)

    # 3. (Optional) Log or store deviceInfo somewhere.
    # For example, you might have a Device model/table. If not, you can at least log:
    # print(f"User {user.user_id} logged in from device: {payload.deviceInfo.json()}")

    # 4. Create JWT token
    now = datetime.utcnow()
    expire = now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode = {
        "sub": user.user_id,
        "email": user.email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        # you can include deviceInfo if desired:
        # "device": {"id": payload.deviceInfo.deviceId, "platform": payload.deviceInfo.platform}
    }
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    # 5. Prepare response
    login_data = LoginData(
        token=token,
        userId=user.user_id,
        email=user.email,
        firstName=user.firstName,
        lastName=user.lastName,
        expiresAt=expire.isoformat()  # datetime; will be serialized as ISO format
    )
    resp = SuccessResponse(data=login_data.dict())
    return JSONResponse(status_code=200, content=resp.model_dump())

def verify_jwt_and_get_user_id(authorization: Optional[str]) -> Optional[str]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return None
    user_id = payload.get("user_id") or payload.get("sub")
    if not user_id:
        return None
    return str(user_id)

def codeGenerator() -> str:
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(5))

@app.post("/devices")
async def addDevice(payload: DeviceCreate, authorization: Optional[str] = Header(None, alias="Authorization"), db: Session = Depends(get_db)):
    user_id = verify_jwt_and_get_user_id(authorization)
    if user_id is None:
        return JSONResponse(status_code=401, content={"status": "error", "code": 401, "message": "Invalid or missing token"})


@app.post("/tethering-code")
async def tetheringCode(authorization: Optional[str] = Header(None, alias="Authorization"), db: Session = Depends(get_db)):
    user_id = verify_jwt_and_get_user_id(authorization)
    if user_id is None:
        return JSONResponse(status_code=401, content={"status": "error", "code": 401, "message": "Invalid or missing token"})
    max_tries = 5
    code = None
    now = datetime.utcnow()
    for _ in range(max_tries):
        candidate = codeGenerator()
        expires_at = now + timedelta(seconds=600)
        # Пробуем вставить
        new_entry = TetheringCode(
            code=candidate,
            user_id=user_id,
            expiredAt=expires_at,
            used=False
        )
        db.add(new_entry)
        try:
            db.commit()
            code = candidate
            break
        except IntegrityError:
            db.rollback()
            # Код уже существует, пробуем снова
            continue
    if code is None:
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "error", "message": "Could not generate unique tethering code, try again"}
        )
    # Форматируем expiresAt в ISO UTC с Z
    expires_at_str = (expires_at.replace(tzinfo=timezone.utc)
                      .isoformat().replace("+00:00", "Z"))
    return JSONResponse(
        status_code=HTTP_201_CREATED,
        content={
            "status": "success",
            "data": {
                "code": code,
                "expiresAt": expires_at_str,
                "validitySeconds": 600
            }
        }
    )


# @app.post("/settings", response_model=ScreenshotResponse)
# async def upload_screenshot(
#     user_id: int = Form(...),
#     device_id: str = Form(...),
#     category: str = Form(...),
#     app_name: str = Form(...),
#     screen_time: int = Form(...),
#     file: UploadFile = File(...),
#     db: Session = Depends(get_db),
# ):
#     ext = ".jpg"
#     filename = f"{uuid.uuid4().hex}{ext}"
#     file_path = os.path.join(uploads_directory, filename)
#     # Сохранение файла
#     try:
#         content = await file.read()
#         with open(file_path, "wb") as f:
#             f.write(content)
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")
#     # Сохранение в БД
#     screenshot = Screenshot(
#         user_id=user_id,
#         device_id=device_id,
#         category=category,
#         app_name=app_name,
#         screen_time=screen_time,
#         image_path=file_path,
#     )
#     db.add(screenshot)
#     db.commit()
#     db.refresh(screenshot)
#     image_url = f"/uploads/{filename}"
#     # screenshot.user = user
#     return ScreenshotResponse(
#         id=screenshot.id,
#         device_id=screenshot.device_id,
#         category=screenshot.category,
#         app_name=screenshot.app_name,
#         screen_time=screenshot.screen_time,
#         image_path=image_url
#     )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="debug")