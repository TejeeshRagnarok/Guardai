# backend/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routers import url_analyzer, email_analyzer, login_monitor

app = FastAPI(title="GuardAI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(url_analyzer.router, prefix="/api/analyze")
app.include_router(email_analyzer.router, prefix="/api/analyze")
app.include_router(login_monitor.router, prefix="/api")

@app.get("/")
def root():
    return {"status": "ok", "service": "GuardAI backend"}
