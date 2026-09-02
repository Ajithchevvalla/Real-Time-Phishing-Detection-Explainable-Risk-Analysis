from datetime import datetime, timezone
from pathlib import Path
from typing import List

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .analyzer import analyze_message

from .database import init_db, save_scan, recent_scans, clear_scans

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="PhishGuard AI",
    version="1.0.0",
    description="Real-time AI-assisted phishing detection and explainable risk analysis."
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


class ScanRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    message: str = Field(..., min_length=1, max_length=50000)
    sender: str = Field(default="", max_length=500)


class ConnectionManager:
    def __init__(self):
        self.connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, payload):
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@app.on_event("startup")
def startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={})


@app.get("/health")
def health():
    return {"status": "ok", "service": "PhishGuard AI"}


@app.get("/api/history")
def history():
    return {"items": recent_scans(50)}


@app.delete("/api/history")
def delete_history():
    clear_scans()
    return {"cleared": True}


@app.post("/api/scan")
async def scan(payload: ScanRequest):
    result = await analyze_message(payload.subject, payload.message, payload.sender)
    item = {
        **result,
        "subject": payload.subject,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    save_scan(item)
    await manager.broadcast({"type": "scan", "data": item})
    return item


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception:
        manager.disconnect(ws)


