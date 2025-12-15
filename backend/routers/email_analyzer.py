# backend/routers/email_analyzer.py
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
import random
from .url_analyzer import compute_simple_url_score

router = APIRouter()

class EmailRequest(BaseModel):
    raw_email: str
    user_id: Optional[int] = None

def quick_email_parse_and_score(text: str) -> dict:
    # very basic parsing: find http(s) urls; you can replace with real parser later
    urls = []
    parts = text.split()
    for p in parts:
        if p.startswith("http://") or p.startswith("https://"):
            urls.append(p.strip())
    aggregated_score = 0
    reasons = []
    url_details = []
    for u in urls:
        ud = compute_simple_url_score(u)
        url_details.append(ud)
        aggregated_score = max(aggregated_score, ud["threat_score"])
    # some simple heuristics
    if any(word in text.lower() for word in ["verify", "immediately", "urgent", "click here", "bank"]):
        reasons.append("Contains urgent/verification language")
        aggregated_score = max(aggregated_score, aggregated_score + 10)
    if "@" in text and "reply-to" in text.lower():
        reasons.append("Reply-To header mismatch possibly present")
        aggregated_score = min(100, aggregated_score)
    verdict = "Safe" if aggregated_score < 35 else ("Suspicious" if aggregated_score < 65 else "Malicious")
    return {
        "threat_score": int(aggregated_score),
        "verdict": verdict,
        "reasons": reasons or ["Heuristic email checks"],
        "extracted_urls": url_details,
        "highlights": [{"text": "Sample suspicious phrase", "reason": "Urgency"}] if reasons else []
    }

@router.post("/email")
def analyze_email(req: EmailRequest):
    """
    POST /api/analyze/email
    body: {"raw_email": "..."}
    """
    return quick_email_parse_and_score(req.raw_email or "")
