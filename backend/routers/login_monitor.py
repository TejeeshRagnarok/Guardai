# backend/routers/login_monitor.py
from fastapi import APIRouter
from pydantic import BaseModel
import random
from typing import Optional
import datetime

router = APIRouter()

class LoginEvent(BaseModel):
    user_email: str
    ip: str
    device: Optional[str] = None
    country: Optional[str] = None
    success: Optional[bool] = True
    ts: Optional[str] = None

@router.post("/login/ingest")
def ingest_login(event: LoginEvent):
    # Mock anomaly scoring using simple heuristics
    now = datetime.datetime.utcnow().isoformat()
    score = random.randint(5, 95)
    status = "Normal" if score < 40 else ("Suspicious" if score < 70 else "High Risk")
    alert = {
        "user_email": event.user_email,
        "ip": event.ip,
        "device": event.device,
        "country": event.country,
        "ts": event.ts or now,
        "anomaly_score": int(score),
        "status": status,
        "message": "Simulated anomaly detection (use IsolationForest later)"
    }
    return alert
