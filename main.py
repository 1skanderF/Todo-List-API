from fastapi import FastAPI, Response, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from authx import AuthX, AuthXConfig
from datetime import datetime, timedelta, timezone
import json
import os
import hashlib
import secrets

app = FastAPI()

config = AuthXConfig()
config.JWT_SECRET_KEY = os.environ.get(
    "JWT_SECRET_KEY", "your-secret-key-minimum-32-characters-long!!!"
)
config.JWT_ACCESS_COOKIE_NAME = "my_access_token"
config.JWT_TOKEN_LOCATION = ["cookies"]
config.JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
config.JWT_COOKIE_CSRF_PROTECT = False  # чтобы не требовался отдельный CSRF-токен

security = AuthX(config)


class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserInDB(BaseModel):
    id: str
    name: str
    email: EmailStr
    password_hash: str
    created_at: str


class UserResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    created_at: str


class Task(BaseModel):
    id_u: str
    id_t: int
    title: str
    description: str


class TaskCreate(BaseModel):
    title: str
    description: str

class TaskResponse(BaseModel):
    id: int
    title: str
    description: str

data_file = "users.json"
task_file = "tasks.json"


def load_users() -> list[UserInDB]:
    if os.path.exists(data_file):
        with open(data_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [UserInDB(**item) for item in data]
    return []


def save_users(users: list[UserInDB]):
    with open(data_file, "w", encoding="utf-8") as f:
        json.dump([user.dict() for user in users], f, indent=2, ensure_ascii=False)


def load_tasks() -> list[Task]:
    if os.path.exists(task_file):
        with open(task_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [Task(**item) for item in data]
    return []


def save_tasks(tasks: list[Task]):
    with open(task_file, "w", encoding="utf-8") as f:
        json.dump([task.dict() for task in tasks], f, indent=2, ensure_ascii=False)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256()
    hash_obj.update((salt + password).encode("utf-8"))
    return f"{salt}:{hash_obj.hexdigest()}"


def verify_password(password: str, password_hash: str) -> bool:
    salt, hash_value = password_hash.split(":")
    hash_obj = hashlib.sha256()
    hash_obj.update((salt + password).encode("utf-8"))
    return hash_obj.hexdigest() == hash_value


def create_task_id(user_id: str) -> int:
    for user in user_db:
        if user.id == user_id:
            user_tasks = [task for task in task_db if task.id_u == user_id]
            if user_tasks:
                return max(task.id_t for task in user_tasks) + 1
            else:
                return 1
    raise HTTPException(status_code=404, detail="User not found")


user_db = load_users()
task_db = load_tasks()


# ВАЖНО: этот колбэк обязателен для authx — он говорит библиотеке,
# как по uid из токена достать пользователя.
@security.set_subject_getter
def get_user_from_uid(uid: str, *args, **kwargs):
    for user in user_db:
        if user.id == uid:
            return user
    return None


def get_current_user_id(
    user: UserInDB = Depends(security.get_current_subject),
) -> str:
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    return user.id


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserRegister, response: Response):
    global user_db

    for existing_user in user_db:
        if existing_user.email == user.email:
            raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = hash_password(user.password)

    new_user = UserInDB(
        id=secrets.token_hex(16),
        name=user.name,
        email=user.email,
        password_hash=password_hash,
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    user_db.append(new_user)
    save_users(user_db)

    token = security.create_access_token(uid=new_user.id)
    response.set_cookie(
        key=config.JWT_ACCESS_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        # secure=True,  # включите, когда будет HTTPS
    )

    return {
        "token": token,
        "user": UserResponse(
            id=new_user.id,
            name=new_user.name,
            email=new_user.email,
            created_at=new_user.created_at,
        ),
    }


@app.post("/login")
def login_user(user: UserLogin, response: Response):
    user_in_db = None

    for u in user_db:
        if u.email == user.email:
            user_in_db = u
            break

    if not user_in_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not verify_password(user.password, user_in_db.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = security.create_access_token(uid=user_in_db.id)
    response.set_cookie(
        key=config.JWT_ACCESS_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        # secure=True,  # включите, когда будет HTTPS
    )

    return {
        "token": token,
        "user": UserResponse(
            id=user_in_db.id,
            name=user_in_db.name,
            email=user_in_db.email,
            created_at=user_in_db.created_at,
        ),
    }


@app.post("/todos")
def create_task(new_task: TaskCreate, user_id: str = Depends(get_current_user_id)):
    global task_db

    task_id = create_task_id(user_id)

    task = Task(
        id_u=user_id,
        id_t=task_id,
        title=new_task.title,
        description=new_task.description,
    )

    task_db.append(task)
    save_tasks(task_db)

    return {
        "id": task.id_t,
        "title": task.title,
        "description": task.description,
    }
    
@app.put("/todos/{task_id}")
def update_task(task_id: int, updated_task: TaskCreate, user_id: str = Depends(get_current_user_id)):
    
    global task_db
    task_found = None
    task_index = -1
    for task in task_db:
        if task.id_t == task_id and task.id_u == user_id:
            task_found = task
            task_index = task_db.index(task)
            break
    
    if task_found is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You don't have permission to update this task or task not found")

    
    
    updated_task_obj = Task(
        id_u=user_id,
        id_t=task_id,
        title=updated_task.title,
        description=updated_task.description,
    )
    
    task_db[task_index] = updated_task_obj
    save_tasks(task_db)
    
    return {
        "id": task.id_t,
        "title": task.title,
        "description": task.description,
    }
    
@app.delete("/todos/{task_id}")
def delete_task(task_id: int, user_id: str = Depends(get_current_user_id)):
    
    global task_db
    
    task_found = None
    
    for task in task_db:
        if task.id_t == task_id and task.id_u == user_id:
            task_found = task
            break
        
    if task_found is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You don't have permission to delete this task or task not found")
    
    del task_db[task_db.index(task_found)]
    save_tasks(task_db)
    
    return {
        "status_code" : status.HTTP_204_NO_CONTENT,
        "detail": "Task deleted successfully",
    }
    

@app.get("/todos")
def get_tasks(page: int, limit: int, user_id: str = Depends(get_current_user_id)):
    
    if page < 1 and limit < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Page and limit must be greater than 0",
        )
    
    user_tasks = [task for task in task_db if task.id_u == user_id]
    
    start_index = (page - 1) * limit
    end_index = start_index + limit 
    user_tasks_paginated = user_tasks[start_index:end_index]
    
    return {
        "data": [TaskResponse(
            id=task.id_t,
            title=task.title,
            description=task.description
        ) for task in user_tasks_paginated],
        "page": page,
        "limit" : limit,
        "total": len(user_tasks)
    }
    
    
    
    