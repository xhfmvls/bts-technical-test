from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
import os
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer
import json
import base64
import hmac
import hashlib
import uuid
# import bcrypt

# CONFIGURATION
load_dotenv()
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
ALGORITHM = "HS256"
JWT_SECRET_KEY = os.getenv('SECRET')

app = FastAPI()

class User(BaseModel):
    username: str
    password: str
    email: str = None

class Checklist(BaseModel):
    checklist_id: str = None
    title: str = None

class Todo(BaseModel):
    title: str
    checklist_id: str = None
    is_checked: bool = False 

# Simulated databases (in-memory)
users_db: Dict[str, Dict] = {}        # Stores user data as user_id -> (email, password hash)
checklists_db: Dict[str, Dict] = {}   # Stores checklist data as checklist_id -> (user_id, title)
todos_db: Dict[str, Dict] = {}        # Stores todo data as todo_id -> (checklist_id, title, is_checked)


@app.get("/")
async def root():
    return {"message": "Hello World"}

def verify_access_token(token: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        
        # Decode the header and payload
        payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode()
        payload = json.loads(payload_json)

        # Verify expiration
        exp = datetime.fromisoformat(payload.get("exp"))
        if datetime.now(timezone.utc) > exp:
            raise HTTPException(status_code=401, detail="Token has expired")

        # Recreate the signature
        expected_signature = hmac.new(
            JWT_SECRET_KEY.encode(),
            f"{header_b64}.{payload_b64}".encode(),
            hashlib.sha256
        ).digest()

        # Verify the signature
        expected_signature_b64 = base64.urlsafe_b64encode(expected_signature).decode().strip("=")
        
        if not hmac.compare_digest(signature_b64, expected_signature_b64):
            raise HTTPException(status_code=401, detail="Invalid token")

        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def create_access_token(data: dict, expires_delta):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire.isoformat()})

    # Encode the header and payload to base64
    header = json.dumps({"alg": ALGORITHM, "typ": "JWT"}).encode()
    payload = json.dumps(to_encode).encode()
    header_b64 = base64.urlsafe_b64encode(header).decode().strip("=")
    payload_b64 = base64.urlsafe_b64encode(payload).decode().strip("=")

    # Create the signature
    signature = hmac.new(
        JWT_SECRET_KEY.encode(),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256
    ).digest()

    # Encode the signature to base64
    signature_b64 = base64.urlsafe_b64encode(signature).decode().strip("=")
    # Concatenate the parts to form the JWT
    jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"

    return jwt_token

def decode_access_token(token: str) -> dict:
    try:
        base64_header, base64_payload, _ = token.split('.')
        json_data = base64.urlsafe_b64decode(base64_payload + '==')
        payload = json.loads(json_data)
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/login/")
async def login(user: User):
    hashed_password = hashlib.sha256(user.password.encode()).hexdigest()
    print(users_db.items())

    for user_id, user_data in users_db.items():
        if user_data['username'] == user.username:
            if user_data['password_hash'] == hashed_password:
                access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
                access_token = create_access_token(data={"sub": user.username, "pass": hashed_password}, expires_delta=access_token_expires)
                return {"access_token": access_token, "token_type": "bearer"}

    raise HTTPException(status_code=400, detail="Invalid credentials")

@app.post("/register/")
async def register(user: User):
    # Check if the username already exists
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Hash the password
    hashed_password = hashlib.sha256(user.password.encode()).hexdigest()
    
    # Create a unique user ID
    user_id = str(len(users_db) + 1)  # Simple ID generation
    users_db[user_id] = {
        "username": user.username,
        "email": user.email,
        "password_hash": hashed_password
    }

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "pass": hashed_password}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/checklist/")
async def create_checklist(checklist: Checklist, authorization: str = Header(...)):
    token = authorization.split(" ")[1] 
    payload = decode_access_token(token)

    checklist_id = str(uuid.uuid4())  # Simple ID generation
    checklists_db[checklist_id] = {
        "checklist_id": checklist_id,
        "title": checklist.title
    }
    
    return {"msg": "Checklist created successfully", "checklist_id": checklist_id}

@app.get("/checklist/")
async def get_checklists(authorization: str = Header(...)):
    token = authorization.split(" ")[1] 
    payload = decode_access_token(token)

    return {"checklists": [{**checklist, "checklist_id": checklist_id} for checklist_id, checklist in checklists_db.items()]}

@app.post("/checklist/{checklist_id}/item/")
async def create_todo(checklist_id: str, todo: Todo, authorization: str = Header(...)):
    token = authorization.split(" ")[1]  # Get the token part
    payload = decode_access_token(token)  # Validate the token

    username = payload["sub"]  # Get the username from the token

    # Check if the checklist exists
    if checklist_id not in checklists_db:
        raise HTTPException(status_code=404, detail="Checklist not found")

    todo_id = str(uuid.uuid4())  # Generate a new UUID for the todo ID
    # Add the new to-do to the checklist
    if 'todos' not in checklists_db[checklist_id]:
        checklists_db[checklist_id]['todos'] = []  # Initialize todos list if it doesn't exist

    checklists_db[checklist_id]['todos'].append({
        "id": todo_id,
        "title": todo.title,
        "is_checked": todo.is_checked
    })

    return {"msg": "To-do created successfully", "todo_id": todo_id}

@app.delete("/checklist/")
async def delete_checklist(checklist: Checklist, authorization: str = Header(...)):
    checklist_id = checklist.checklist_id
    token = authorization.split(" ")[1]  # Get the token part
    payload = decode_access_token(token)  # Validate the token

    # Check if the checklist exists
    if checklist_id not in checklists_db:
        raise HTTPException(status_code=404, detail="Checklist not found")

    # Delete the checklist
    del checklists_db[checklist_id]

    return {"msg": "Checklist deleted successfully"}

@app.get("/checklist/{checklist_id}")
async def get_todos(checklist_id: str, authorization: str = Header(...)):
    token = authorization.split(" ")[1]  # Get the token part
    payload = decode_access_token(token)  # Validate the token

    # Check if the checklist exists
    if checklist_id not in checklists_db:
        raise HTTPException(status_code=404, detail="Checklist not found")

    # Get the to-dos for the specified checklist
    todos = checklists_db[checklist_id].get('todos', [])

    return {"checklist_id": checklist_id, "todos": todos}


# uvicorn app.main:app --port 8000