# backend/routers/url_analyzer.py
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
import tldextract
import random
from rapidfuzz import fuzz

router = APIRouter()

class URLRequest(BaseModel):
    url: str
    user_id: Optional[int] = None

def compute_simple_url_score(url: str) -> dict:
    # simple heuristic scoring - replace with real checks later
    ext = tldextract.extract(url)
    domain = ".".join(part for part in (ext.domain, ext.suffix) if part)
    score = random.randint(10, 90)
    reasons = []
    if "-" in domain or "secure" in url.lower():
        reasons.append("Brand-like token or hyphen in domain")
    if len(domain.split(".")) > 2:
        reasons.append("Multi-level domain (possible typosquatting)")
    # cheap fuzzy check vs sample brand
    if fuzz.partial_ratio(domain.lower(), "paytm") > 70:
        reasons.append("Domain similar to known brand (paytm) using fuzzy match")
        score = max(score, 60)
    return {"url": url, "domain": domain, "threat_score": score,
            "verdict": "Safe" if score < 35 else ("Suspicious" if score < 65 else "Malicious"),
            "reasons": reasons or ["Heuristic checks"]}

@router.post("/url")
def analyze_url(req: URLRequest):
    """
    POST /api/analyze/url
    body: {"url": "http://example.com"}
    """
    return compute_simple_url_score(req.url)
