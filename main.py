# main.py
# Purpose: FastAPI AI-agent application with deliberately seeded security vulnerabilities.
#          Used as a static analysis target for the aisec repository scan.
#          DO NOT deploy — this file is intentionally insecure for testing only.
# Author: Thamizhmani
# Date: 2026-09-16

import sqlite3
from fastapi import FastAPI, Request
from pydantic import BaseModel
from agent import get_ai_response

app = FastAPI(title="AI Agent Test App — INSECURE")


# ── VULNERABILITY R-04: PII fields exposed in data model ─────────────────────
# SAST / PII detector should flag ssn, credit_card, dob, passport.
class UserProfile(BaseModel):
    id: int
    name: str
    email: str
    phone: str
    ssn: str           # PII — Social Security Number
    credit_card: str   # PII — payment card number
    dob: str           # PII — date of birth
    passport: str      # PII — passport number
    address: str


class ChatMessage(BaseModel):
    content: str
    session_id: str = ""


DB_PATH = "users.db"


# ── VULNERABILITY R-03: SQL injection via string concatenation ────────────────
# SAST should flag this as HIGH — user_id is embedded directly in the query.
@app.get("/users/{user_id}")
def get_user(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    query = f"SELECT * FROM users WHERE id = {user_id}"  # nosec (intentional for test)
    cursor = conn.execute(query)
    row = cursor.fetchone()
    conn.close()
    return {"user": row}


@app.post("/users")
def create_user(profile: UserProfile):
    conn = sqlite3.connect(DB_PATH)
    # Also vulnerable — inserts PII without encryption
    conn.execute(
        f"INSERT INTO users VALUES ({profile.id}, '{profile.name}', '{profile.ssn}')"  # nosec
    )
    conn.commit()
    conn.close()
    return {"created": profile.id}


# ── VULNERABILITY: No rate limiting on AI chat endpoint ──────────────────────
@app.post("/chat")
async def chat(message: ChatMessage):
    response = get_ai_response(message.content)
    return {"response": response}


# ── VULNERABILITY R-08: Deprecated v1 API still active ───────────────────────
# Deprecated version detector: /v1/ returns 200 while /v2/ exists.
@app.get("/v1/users")
def list_users_v1():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name FROM users").fetchall()
    conn.close()
    return {"users": rows, "version": "v1"}


@app.get("/v2/users")
def list_users_v2():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name FROM users").fetchall()
    conn.close()
    return {"users": rows, "version": "v2"}


@app.get("/v1/chat")
def chat_v1():
    return {"model": "gpt-3.5-turbo", "deprecated": False}  # deprecated but active


@app.get("/v2/chat")
def chat_v2():
    return {"model": "gpt-4", "version": "v2"}


@app.get("/health")
def health():
    return {"status": "ok"}
