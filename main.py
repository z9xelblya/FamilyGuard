import base64
import os
import string
import uuid
import random

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
import uvicorn
from fastapi import FastAPI, Form, UploadFile, File, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt import ExpiredSignatureError
from passlib.context import CryptContext
from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR, HTTP_201_CREATED
from dotenv import load_dotenv

from ai_worker import moderate_screenshot
from database import init_db, get_db, Session
from models import *
from schemas import *

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield




app = FastAPI(lifespan=lifespan)

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 10

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

uploads_directory = os.path.join(os.getcwd(), "uploads")
os.makedirs(uploads_directory, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=uploads_directory))

bearer_scheme = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid or missing token: " + str(e))
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return user_id

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        loc = err.get("loc", [])
        field = loc[-1] if loc else "body"
        errors.append({"field": field, "message": err.get("msg")})
    return JSONResponse(status_code=400, content={
        "status": "error",
        "code": 400,
        "message": "Invalid input",
        "errors": errors,
    })


@app.post("/api/v1/register")
async def register(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        return JSONResponse(status_code=400, content=ErrorResponse(
            status="error", code=400, message="Invalid input",
            errors=[ErrorItem(field="email", message="Email already exists")]
        ).model_dump())
    pwd = pwd_context.hash(payload.password)
    user = User(
        user_id=str(uuid.uuid4()),
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
    resp = UserResponse(
        userId=user.user_id,
        email=user.email,
        firstName=user.firstName,
        lastName=user.lastName,
        createdAt=user.createdAt.isoformat()
    )
    return JSONResponse(status_code=201, content=SuccessResponse(data=resp.dict()).model_dump())


@app.post("/api/v1/login")
async def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not pwd_context.verify(payload.password, user.password):
        return JSONResponse(status_code=401, content={
            "status": "error",
            "code": 401,
            "message": "Invalid credentials"
        })
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
    return JSONResponse(status_code=200, content=SuccessResponse(data=data.dict()).model_dump())





# qweqq

def code_generator() -> str:
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(5))


@app.post("/api/v1/devices", status_code=201)
async def add_device(payload: DeviceCreate, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    obj = db.query(TetheringCode).filter(
        and_(
            TetheringCode.code == payload.tetheringCode,
            TetheringCode.used == False,
            TetheringCode.expiredAt > now
        )
    ).first()
    if (obj is None) or (obj.user_id != user_id):
        raise HTTPException(status_code=400, detail="Invalid tethering code")
    obj.used = True
    db.add(obj)

    device = Device(
        device_id=str(uuid.uuid4()),
        user_id=user_id,
        name=payload.name,
        model=payload.model,
        osVersion=payload.osVersion,
        isBlocked=False,
        heartbeat=now
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    data = DeviceResponse(
        deviceId=device.device_id,
        name=device.name,
        model=device.model,
        osVersion=device.osVersion,
        tetheringAt=device.tetheredAt.isoformat()
    )
    return JSONResponse(status_code=200, content=SuccessResponse(data=data.dict()).model_dump())


@app.post("/api/v1/tethering-code", status_code=201)
async def tethering_code(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    now = datetime.utcnow()
    code = None
    for _ in range(5):
        c = code_generator()
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
    if not code:
        raise HTTPException(status_code=500, detail="Could not generate unique tethering code")
    expires_str = expires_at.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    return {"status": "success", "data": {"code": code, "expiresAt": expires_str, "validitySeconds": 600}}


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }
    for path, ops in schema["paths"].items():
        if path in ("/api/v1/devices", "/api/v1/tethering-code", "/api/v1/devices/{device_id}/block",
                    "/api/v1/devices/{device_id}/unblock", "/api/v1/categories", "/api/v1/categories/{category_id}",
                    "/api/v1/settings/screenshots", "/api/v1/settings/screen-time", "/api/v1/settings/screen-time/{screentimeId}", "/api/v1/settings/screen-time/log", "/api/v1/ai", "/api/v1/heartbeat"):
            for op in ops.values():
                op.setdefault("security", []).append({"BearerAuth": []})
    app.openapi_schema = schema
    return schema
# awdw
#
@app.get("/api/v1/devices", status_code=201)
async def devices(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    all_devices = db.query(Device).filter(Device.user_id == user_id).all()
    list_devices = []
    for device in all_devices:
        data = DeviceResponse(
            deviceId=device.device_id,
            name=device.name,
            model=device.model,
            osVersion=device.osVersion,
            tetheringAt=device.tetheredAt.isoformat()
        )
        list_devices.append(data.dict())
    return JSONResponse(status_code=200, content=SuccessResponse(data=list_devices).model_dump())


@app.post("/api/v1/devices/{device_id}/block", status_code=201)
async def block_device(device_id: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.user_id == user_id).filter(Device.device_id == device_id).first()
    device.isBlocked = True
    db.add(device)
    db.commit()
    db.refresh(device)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return JSONResponse(status_code=200,
                        content=SuccessResponse(data={"status": "success", "msg": "Device blocked"}).model_dump())


@app.post("/api/v1/devices/{device_id}/unblock", status_code=201)
async def unblock_device(device_id: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.user_id == user_id).filter(Device.device_id == device_id).first()
    device.isBlocked = False
    db.add(device)
    db.commit()
    db.refresh(device)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return JSONResponse(status_code=200,
                        content=SuccessResponse(data={"status": "success", "msg": "Device unblocked"}).model_dump())


@app.post("/api/v1/categories", status_code=201)
async def category_add(payload: CategoryCreate, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    category = Category(
        id=str(uuid.uuid4()),
        name=payload.name,
        label=payload.label,
        description=payload.description,
        restricted=payload.restricted
    )
    db.add(category)
    db.commit()
    db.refresh(category)
    data = CategoryResponse(
        categoryId=category.id,
        name=category.name,
        label=category.label,
        description=category.description,
        restricted=category.restricted
    )
    return JSONResponse(status_code=200, content=SuccessResponse(data=data.dict()).model_dump())


@app.get("/api/v1/categories", status_code=201)
async def categories(db: Session = Depends(get_db)):
    all_categories = db.query(Category).all()
    list_categories = []
    for category in all_categories:
        data = CategoryResponse(
            categoryId=category.id,
            name=category.name,
            label=category.label,
            description=category.description,
            restricted=category.restricted
        )
        list_categories.append(data.dict())
    return JSONResponse(status_code=200, content=SuccessResponse(data=list_categories).model_dump())


@app.delete("/api/v1/categories/{category_id}", status_code=201)
async def delete_category(categoryId: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    category = db.query(Category).filter(Category.id == categoryId).first()
    if category is None:
        raise HTTPException(status_code=404, detail="Category not found")
    db.delete(category)
    db.commit()
    db.refresh(category)
    return JSONResponse(status_code=200,
                        content=SuccessResponse(data={"status": "success", "msg": "Category deleted"}).model_dump())


@app.post("/api/v1/settings/screenshots", status_code=201)
async def screenshots(category: str = Form(...),
                      transaction_id: str = Form(...),
                      device_id: str = Form(...), file: UploadFile = File(...), user_id: str = Depends(verify_token),
                      db: Session = Depends(get_db)):
    ext = ".jpg"
    filename = f"{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(uploads_directory, filename)

    try:
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")

    screenshot = Screenshot(
        id=str(uuid.uuid4()),
        user_id=user_id,
        image=file_path,
        category=category,
        transaction_id=transaction_id,
        device_id=device_id,
    )
    db.add(screenshot)
    db.commit()
    db.refresh(screenshot)

    data = ScreenshotResponse(
        id=screenshot.id,
        image=file_path,
        category=screenshot.category,
        transaction_id=screenshot.transaction_id,
        device_id=screenshot.device_id
    )
    return JSONResponse(status_code=200, content=SuccessResponse(data=data.dict()).model_dump())

@app.post("/api/v1/settings/screen-time", status_code=201)
async def screen_time(payload: ScreentimeCreate, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    check = db.query(Device).filter(Device.user_id == user_id, Device.device_id == payload.deviceId).first()
    if check is None:
        raise HTTPException(status_code=400, detail="Device not found")

    screentime = Screentime(
        id = str(uuid.uuid4()),
        user_id=user_id,
        deviceId = payload.deviceId,
        limit = payload.limit,
        scheduleStart=payload.schedule.start,
        scheduleEnd=payload.schedule.end,
        appName = payload.appName
    )
    db.add(screentime)
    db.commit()
    db.refresh(screentime)
    data = ScreentimeResponse(
        screentimeId=screentime.id,
        limit=screentime.limit,
        appName=screentime.appName,
        schedule=ScheduleItem(start=screentime.scheduleStart, end=screentime.scheduleEnd)
    )
    return JSONResponse(status_code=200, content=SuccessResponse(data=data.dict()).model_dump())

@app.put("/api/v1/settings/screen-time/{screentimeId}", status_code=201)
async def screem_time_update(payload: ScreentimeUpdate, screentime_id: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    screentime = db.query(Screentime).filter(Screentime.id == screentime_id, Screentime.user_id == user_id).first()
    if screentime is None:
        raise HTTPException(status_code=400, detail="Screentime not found")
    if payload.limit is not None:
        screentime.limit = payload.limit
    if payload.schedule.start is not None:
        screentime.scheduleStart = payload.schedule.start
    if payload.schedule.end is not None:
        screentime.scheduleEnd = payload.schedule.end
    db.add(screentime)
    db.commit()
    db.refresh(screentime)
    return JSONResponse(status_code=200, content=SuccessResponseMsg(msg="Settings updated").model_dump())

@app.get("/api/v1/settings/screen-time", status_code=201)
async def get_screen_time(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    all_screentimes = db.query(Screentime).filter(Screentime.user_id == user_id).all()
    list_screentimes = []
    for screen_time in all_screentimes:
        data = ScreentimeResponse(
            screentimeId=screen_time.id,
            limit=screen_time.limit,
            schedule=ScheduleItem(start=screen_time.scheduleStart, end=screen_time.scheduleEnd),
        )
        list_screentimes.append(data.dict())
    return JSONResponse(status_code=200, content=SuccessResponse(data=list_screentimes).model_dump())

@app.delete("/api/v1/settings/screen-time/{screentimeId}", status_code=204)
async def del_screen_time(screentimeId: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    screentime = db.query(Screentime).filter(Screentime.id == screentimeId, Screentime.user_id == user_id).first()
    if screentime is None:
        raise HTTPException(status_code=400, detail="Screentime not found")
    db.delete(screentime)
    db.commit()
    return JSONResponse(status_code=200,
                        content=SuccessResponse(data={"status": "success", "msg": "Screentime deleted"}).model_dump())

@app.post("/api/v1/settings/screen-time/log", status_code=204)
async def post_screen_time_log(payload: LogScreentimeCreate, user_id: str = Depends(verify_token), db=Depends(get_db)):
    device = db.query(Device).filter(Device.user_id == user_id, Device.device_id == payload.device_id).first()
    if device is None:
        raise HTTPException(status_code=400, detail="Device not found")
    screentime = db.query(Screentime).filter(Screentime.id == payload.screentime_id, Screentime.user_id == user_id).first()
    if screentime is None:
        raise HTTPException(status_code=400, detail="Screentime not found")
    logScreentime = db.query(LogScreentime).filter(LogScreentime.screentime_id == payload.screentime_id, LogScreentime.user_id == user_id).all()
    usedTime = sum([logSt.screenTime for logSt in logScreentime]) + payload.screenTime
    remainingTime = screentime.limit - usedTime
    if remainingTime <= 0:
        raise HTTPException(status_code=400, detail="Remaining time exceeds limit")

    logStDb = LogScreentime(
        id = str(uuid.uuid4()),
        user_id = user_id,
        screenTime = payload.screenTime,
        timestamp = payload.timestamp,
        device_id = device.device_id,
        screentime_id = screentime.id,
        activityType = payload.activityType,
    )

    db.add(logStDb)
    db.commit()
    db.refresh(logStDb)

    logScreentimeResponse = LogScreentimeResponse(
        usedTime=usedTime,
        remaining=remainingTime,
        limit=screentime.limit,
        schedule=ScheduleItem(start=screentime.scheduleStart, end=screentime.scheduleEnd),
        lastUpdate=logScreentime[-1].timestamp
    )

    return JSONResponse(status_code=200, content=SuccessResponse(data=logScreentimeResponse).model_dump())

@app.post("/api/v1/ai")
async def moderate(
        payload: AI,
        user_id: str = Depends(verify_token),
        db: Session = Depends(get_db)
):
    categories = db.query(Category).all()
    categories_names = [i.name for i in categories]
    print(categories_names)
    image = payload.content
    report = moderate_screenshot(image, categories)
    print(report)
    if "category" in report:
        category = db.query(Category).filter(Category.name == report["category"]).first()
        if category is None:
            category = Category(
                id=str(uuid.uuid4()),
                name=report["category"],
                label="",
                description="",
                restricted=False
            )
            db.add(category)
            db.commit()
            db.refresh(category)

        success = SuccessResponseStatusMsg(
            data=CategoryAi(categoryId=category.id, categoryName=report["category"], confidence=report["confidence"]),
            msg="Content analyzed"
        )
        return JSONResponse(status_code=200, content=success.model_dump())
    else:
        return JSONResponse(status_code=400, content=StatusError(error="Invalid content type").model_dump())


@app.post("/api/v1/heartbeat")
async def heartbeat(device_id: str, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    # обновляем устройство в БД
    device = db.query(Device).filter(Device.device_id == device_id).first()
    device.heartbeat = now
    db.add(device)
    db.commit()
    db.refresh(device)
    return JSONResponse(status_code=200, content=SuccessResponse(data="The last ping was updated successfuly!").model_dump())

app.openapi = custom_openapi

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
