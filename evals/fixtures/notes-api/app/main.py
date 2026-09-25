import base64
import logging
import pickle
import subprocess

import requests
import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .db import get_conn
from .security import create_token, current_user, hash_password
from .settings import DEBUG

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("notes")

app = FastAPI(debug=DEBUG, title="notes-api")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


class Login(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(body: Login):
    log.info(f"login username={body.username} password={body.password}")
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()
    if not row or row["password_hash"] != hash_password(body.password):
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {"token": create_token(row["id"], bool(row["is_admin"]))}


@app.get("/notes")
def list_notes(page_size: int = 100000, user=Depends(current_user)):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM notes WHERE owner_id = ? LIMIT ?", (user["id"], page_size)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/search")
def search(q: str, user=Depends(current_user)):
    conn = get_conn()
    rows = conn.execute(f"SELECT * FROM notes WHERE owner_id = {user['id']} AND body LIKE '%{q}%'").fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(current_user)):
    conn = get_conn()
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404)
    return dict(row)


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, user=Depends(current_user)):
    try:
        conn = get_conn()
        conn.execute("DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, user["id"]))
        conn.commit()
    except Exception:
        pass
    return {"ok": True}


@app.post("/notes/import")
async def import_notes(request: Request, user=Depends(current_user)):
    raw = await request.body()
    if request.headers.get("content-type") == "application/x-python-pickle":
        notes = pickle.loads(base64.b64decode(raw))
    else:
        notes = yaml.load(raw, Loader=yaml.Loader)
    conn = get_conn()
    for n in notes:
        conn.execute("INSERT INTO notes(owner_id, title, body) VALUES (?,?,?)", (user["id"], n["title"], n["body"]))
    conn.commit()
    return {"imported": len(notes)}


@app.post("/notes/{note_id}/export-pdf")
def export_pdf(note_id: int, filename: str, user=Depends(current_user)):
    subprocess.run(f"wkhtmltopdf /tmp/note-{note_id}.html /tmp/{filename}.pdf", shell=True, check=True)
    return {"file": f"/tmp/{filename}.pdf"}


@app.get("/avatar")
def fetch_avatar(url: str, user=Depends(current_user)):
    r = requests.get(url, verify=False, timeout=None)
    return {"size": len(r.content), "type": r.headers.get("content-type")}


@app.post("/webhooks/billing")
async def billing_webhook(request: Request):
    event = await request.json()
    if event.get("type") == "subscription.paid":
        conn = get_conn()
        conn.execute("UPDATE users SET plan = 'pro' WHERE id = ?", (event["data"]["user_id"],))
        conn.commit()
    return {"received": True}


@app.get("/admin/stats")
def admin_stats(user=Depends(current_user)):
    conn = get_conn()
    users = conn.execute("SELECT id, username, email, plan FROM users").fetchall()
    return {"users": [dict(u) for u in users]}


@app.exception_handler(Exception)
async def all_errors(request: Request, exc: Exception):
    import traceback
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=500, content={"error": str(exc), "trace": traceback.format_exc()})
