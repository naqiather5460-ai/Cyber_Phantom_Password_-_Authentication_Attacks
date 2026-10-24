"""
AuthGuard AI - Telemetry, audit & external evaluation router.
Every endpoint here is an INTERNAL/back-office API and requires the service API key (X-API-Key).
Never ship that key to a browser: call these from your server or SOC console backend.
"""

import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status

from src.agent.authguard_agent import get_agent
from src.api.schemas import RiskEvaluationRequest, RiskEvaluationResponse, SOCOverviewResponse
from src.core.database import db
from src.core.security import security


def require_api_key(x_api_key: Optional[str] = Header(None)) -> None:
    if not security.is_service_key(x_api_key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "A valid X-API-Key header is required.")


router = APIRouter(prefix="/telemetry", tags=["SOC Telemetry & Risk Diagnosis"],
                   dependencies=[Depends(require_api_key)])
agent = get_agent()


@router.post("/evaluate", response_model=RiskEvaluationResponse)
def evaluate_external_session(req: RiskEvaluationRequest, request: Request):
    """Standalone risk assessment for API gateways (Envoy, Kong, ...). Does not touch user tables."""
    request_id = getattr(request.state, "request_id", "ext_eval")
    now = time.localtime()
    session_ctx = {
        "user_id": req.user_id, "asn": req.asn, "country": req.country, "city": req.city,
        "device_type": req.device_type, "browser": req.browser, "os": req.os, "rtt_ms": req.rtt_ms,
        "hour": now.tm_hour, "login_successful": req.login_successful,
        "is_weekend": 1 if now.tm_wday in (5, 6) else 0,
    }
    baseline = db.get_baseline(req.user_id)
    if baseline:
        agent.rba_engine.user_profiles[req.user_id] = baseline
    agent.deception_engine.hydrate(req.user_id, db.get_honeywords(req.user_id))

    result = agent.evaluate_login_request(
        user_id=req.user_id, password_candidate=req.password_candidate,
        session_context=session_ctx, network_flow=req.network_flow)

    db.log_event({"request_id": request_id, "user_id": req.user_id, "ip_address": req.ip_address,
                  "asn": req.asn, "country": req.country, "city": req.city, "browser": req.browser,
                  "os": req.os, "decision": result["decision"], "risk_score": result["risk_score"],
                  "threat_type": result["threat_type"], "latency_ms": result["latency_ms"]})

    return RiskEvaluationResponse(
        user_id=req.user_id, decision=result["decision"], risk_score=result["risk_score"],
        threat_type=result["threat_type"], mitigation=result["mitigation"],
        latency_ms=result["latency_ms"], risk_breakdown=result["risk_breakdown"])


@router.get("/soc-overview", response_model=SOCOverviewResponse)
def get_soc_overview():
    return SOCOverviewResponse(**db.get_soc_metrics())


@router.get("/audit-logs")
def get_audit_trail(limit: int = Query(50, ge=1, le=500)):
    logs = db.get_recent_audit_logs(limit=limit)
    return {"count": len(logs), "audit_logs": logs}


@router.get("/user-risk-profile/{user_id}")
def get_user_risk_profile(user_id: str):
    """Baseline familiarity profile (known ASNs, devices, countries) for a user."""
    profile = db.get_baseline(user_id) or agent.rba_engine.user_profiles.get(user_id)
    if not profile:
        return {"user_id": user_id, "status": "cold_start",
                "message": "No historical login baseline established yet."}
    return {
        "user_id": user_id, "status": "profiled",
        "known_asns": sorted(map(str, profile.get("asns", []))),
        "known_countries": sorted(map(str, profile.get("countries", []))),
        "known_devices": sorted(map(str, profile.get("devices", []))),
        "known_browsers": sorted(map(str, profile.get("browsers", []))),
        "historical_rtt_samples": len(profile.get("rtts", [])),
    }
