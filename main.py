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

app = FastAPI(lifespan=lifespan)

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-very-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 1

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

uploads_directory = os.path.join(os.getcwd(), "uploads")
os.makedirs(uploads_directory, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=uploads_directory))

bearer_scheme = HTTPBearer()

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
    now = datetime.utcnow()
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

def verify_token(creds: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return user_id

def code_generator() -> str:
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(5))

@app.post("/api/v1/devices", status_code=201)
async def add_device(payload: DeviceCreate, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    device = Device(user_id=user_id, **payload.dict())
    db.add(device)
    db.commit()
    db.refresh(device)
    return {"status": "success", "data": DeviceResponse.from_orm(device).dict()}

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
        if path in ("/api/v1/devices", "/api/v1/tethering-code"):
            for op in ops.values():
                op.setdefault("security", []).append({"BearerAuth": []})
    app.openapi_schema = schema
    return schema

app.openapi = custom_openapi

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7999)
