import asyncio
import json
import hashlib
import os
from datetime import datetime
from typing import Dict, Set, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import databases
import sqlalchemy
import jwt

# ─── Config ────────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./messenger.db")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-please")

# ─── Database ───────────────────────────────────────────────────────────────────
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table("users", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String(50), unique=True, nullable=False),
    sqlalchemy.Column("password_hash", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

messages = sqlalchemy.Table("messages", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("from_user", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("to_user", sqlalchemy.Integer, nullable=True),   # None = group
    sqlalchemy.Column("group_id", sqlalchemy.Integer, nullable=True),
    sqlalchemy.Column("text", sqlalchemy.Text, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

groups = sqlalchemy.Table("groups", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String(100), nullable=False),
    sqlalchemy.Column("owner_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

group_members = sqlalchemy.Table("group_members", metadata,
    sqlalchemy.Column("group_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("groups.id")),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
)

engine = sqlalchemy.create_engine(DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://") if "postgresql" in DATABASE_URL else DATABASE_URL)
metadata.create_all(engine)

# ─── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="ICQ Messenger API")

app.add_middleware(CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Connection Manager ─────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        # user_id -> set of websockets (multiple tabs)
        self.connections: Dict[int, Set[WebSocket]] = {}

    async def connect(self, user_id: int, ws: WebSocket):
        await ws.accept()
        self.connections.setdefault(user_id, set()).add(ws)
        await self.broadcast_status(user_id, "online")

    def disconnect(self, user_id: int, ws: WebSocket):
        if user_id in self.connections:
            self.connections[user_id].discard(ws)
            if not self.connections[user_id]:
                del self.connections[user_id]

    def is_online(self, user_id: int) -> bool:
        return user_id in self.connections and len(self.connections[user_id]) > 0

    def online_users(self) -> list:
        return list(self.connections.keys())

    async def send_to_user(self, user_id: int, data: dict):
        if user_id in self.connections:
            dead = set()
            for ws in self.connections[user_id]:
                try:
                    await ws.send_json(data)
                except:
                    dead.add(ws)
            for ws in dead:
                self.connections[user_id].discard(ws)

    async def broadcast_status(self, user_id: int, status: str):
        """Notify all connected users about status change"""
        msg = {"type": "status", "user_id": user_id, "status": status}
        for uid, sockets in self.connections.items():
            for ws in list(sockets):
                try:
                    await ws.send_json(msg)
                except:
                    pass

manager = ConnectionManager()

# ─── Auth helpers ───────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(user_id: int, username: str) -> str:
    return jwt.encode({"user_id": user_id, "username": username}, SECRET_KEY, algorithm="HS256")

def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

security = HTTPBearer()

async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return decode_token(creds.credentials)
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# ─── Schemas ─────────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class SendMessageRequest(BaseModel):
    to_user_id: Optional[int] = None
    group_id: Optional[int] = None
    text: str

class CreateGroupRequest(BaseModel):
    name: str
    member_ids: list[int] = []

# ─── Routes ─────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.post("/register")
async def register(req: RegisterRequest):
    existing = await database.fetch_one(users.select().where(users.c.username == req.username))
    if existing:
        raise HTTPException(400, "Username already taken")
    user_id = await database.execute(users.insert().values(
        username=req.username,
        password_hash=hash_password(req.password),
        created_at=datetime.utcnow()
    ))
    token = create_token(user_id, req.username)
    return {"token": token, "user_id": user_id, "username": req.username}

@app.post("/login")
async def login(req: LoginRequest):
    user = await database.fetch_one(
        users.select().where(users.c.username == req.username)
    )
    if not user or user["password_hash"] != hash_password(req.password):
        raise HTTPException(401, "Invalid credentials")
    token = create_token(user["id"], user["username"])
    return {"token": token, "user_id": user["id"], "username": user["username"]}

@app.get("/users")
async def get_users(current=Depends(get_current_user)):
    rows = await database.fetch_all(users.select())
    return [
        {"id": r["id"], "username": r["username"], "online": manager.is_online(r["id"])}
        for r in rows if r["id"] != current["user_id"]
    ]

@app.get("/history/{target_id}")
async def get_history(target_id: int, is_group: bool = False, current=Depends(get_current_user)):
    me = current["user_id"]
    if is_group:
        query = messages.select().where(messages.c.group_id == target_id).order_by(messages.c.created_at)
    else:
        query = messages.select().where(
            ((messages.c.from_user == me) & (messages.c.to_user == target_id)) |
            ((messages.c.from_user == target_id) & (messages.c.to_user == me))
        ).order_by(messages.c.created_at)
    
    rows = await database.fetch_all(query)
    result = []
    for r in rows:
        sender = await database.fetch_one(users.select().where(users.c.id == r["from_user"]))
        result.append({
            "id": r["id"],
            "text": r["text"],
            "from_user": r["from_user"],
            "from_username": sender["username"] if sender else "?",
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        })
    return result

@app.post("/groups")
async def create_group(req: CreateGroupRequest, current=Depends(get_current_user)):
    me = current["user_id"]
    group_id = await database.execute(groups.insert().values(
        name=req.name, owner_id=me, created_at=datetime.utcnow()
    ))
    # Add owner + members
    all_members = list(set([me] + req.member_ids))
    for uid in all_members:
        await database.execute(group_members.insert().values(group_id=group_id, user_id=uid))
    return {"id": group_id, "name": req.name}

@app.get("/groups")
async def get_groups(current=Depends(get_current_user)):
    me = current["user_id"]
    rows = await database.fetch_all(
        sqlalchemy.select(groups).join(group_members, groups.c.id == group_members.c.group_id)
        .where(group_members.c.user_id == me)
    )
    return [{"id": r["id"], "name": r["name"]} for r in rows]

@app.get("/groups/{group_id}/members")
async def get_group_members(group_id: int, current=Depends(get_current_user)):
    rows = await database.fetch_all(
        sqlalchemy.select(users).join(group_members, users.c.id == group_members.c.user_id)
        .where(group_members.c.group_id == group_id)
    )
    return [{"id": r["id"], "username": r["username"], "online": manager.is_online(r["id"])} for r in rows]


@app.delete("/history/{target_id}")
async def delete_history(target_id: int, is_group: bool = False, current=Depends(get_current_user)):
    me = current["user_id"]
    if is_group:
        # Удалить группу + все сообщения + участников (только если owner)
        group = await database.fetch_one(groups.select().where(groups.c.id == target_id))
        if not group:
            raise HTTPException(404, "Group not found")
        if group["owner_id"] != me:
            raise HTTPException(403, "Only the owner can delete a group")
        await database.execute(messages.delete().where(messages.c.group_id == target_id))
        await database.execute(group_members.delete().where(group_members.c.group_id == target_id))
        await database.execute(groups.delete().where(groups.c.id == target_id))
        return {"ok": True}
    else:
        # Удалить переписку с пользователем (только у себя — удаляет все сообщения между двумя)
        await database.execute(messages.delete().where(
            ((messages.c.from_user == me) & (messages.c.to_user == target_id)) |
            ((messages.c.from_user == target_id) & (messages.c.to_user == me))
        ))
        return {"ok": True}

# ─── WebSocket ──────────────────────────────────────────────────────────────────
@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        payload = decode_token(token)
    except:
        await websocket.close(code=1008)
        return

    user_id = payload["user_id"]
    username = payload["username"]

    await manager.connect(user_id, websocket)
    # Send current online list to the newly connected user
    await websocket.send_json({
        "type": "online_list",
        "users": manager.online_users()
    })

    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("type")

            if action == "message":
                to_user = data.get("to_user_id")
                group_id = data.get("group_id")
                text = data.get("text", "").strip()
                if not text:
                    continue

                msg_id = await database.execute(messages.insert().values(
                    from_user=user_id,
                    to_user=to_user,
                    group_id=group_id,
                    text=text,
                    created_at=datetime.utcnow()
                ))

                payload_out = {
                    "type": "message",
                    "id": msg_id,
                    "from_user": user_id,
                    "from_username": username,
                    "text": text,
                    "to_user_id": to_user,
                    "group_id": group_id,
                    "created_at": datetime.utcnow().isoformat(),
                }

                if to_user:
                    # Private message — send to both parties
                    await manager.send_to_user(to_user, payload_out)
                    await manager.send_to_user(user_id, payload_out)
                elif group_id:
                    # Group message — send to all members
                    members = await database.fetch_all(
                        group_members.select().where(group_members.c.group_id == group_id)
                    )
                    for m in members:
                        await manager.send_to_user(m["user_id"], payload_out)

    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)
        await manager.broadcast_status(user_id, "offline")
