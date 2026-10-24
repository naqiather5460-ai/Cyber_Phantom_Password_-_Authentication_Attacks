"""
AuthGuard AI - Autonomous Authentication Attack Diagnosis & Prevention Agent
Fuses multi-modal telemetry (Network flow + Application session context + Deception canary)
and executes autonomous real-time mitigation actions.
"""

import time
from typing import Dict, Any
from src.models.network_threat_engine import NetworkThreatEngine
from src.models.behavioral_rba_engine import BehavioralRBAEngine
from src.agent.deceptive_engine import DeceptiveDefenseEngine
from src.core.config import settings

class AuthGuardAgent:
    def __init__(self):
        self.network_engine = NetworkThreatEngine()
        self.rba_engine = BehavioralRBAEngine()
        self.deception_engine = DeceptiveDefenseEngine()
        
        # Load pre-trained models
        self.network_loaded = self.network_engine.load()
        self.rba_loaded = self.rba_engine.load()
        
        if settings.SEED_DEMO_USER:
            self._seed_demo_user()

        # Pre-warm inference pipelines and C-extension threading pools
        self._warmup()

    def _seed_demo_user(self) -> None:
        """Development-only demo baseline (enabled with AUTHGUARD_SEED_DEMO_USER=true)."""
        if 'sarah_connor' not in self.rba_engine.user_profiles:
            self.rba_engine.user_profiles['sarah_connor'] = {
                'asns': {29695}, 'countries': {'NO'}, 'cities': {'Oslo'},
                'devices': {'desktop'}, 'browsers': {'Chrome'}, 'oss': {'Windows'}, 'rtts': [38.0, 42.0]}
        if 'sarah_connor' not in self.deception_engine.honeychecker_store:
            self.deception_engine.register_user_credentials("sarah_connor", "SkynetKiller2024!")

    def _warmup(self):
        """Pre-heats model inference pipelines to eliminate first-call cold-start JIT overhead."""
        try:
            dummy_ctx = {
                'user_id': 'sarah_connor',
                'asn': '29695',
                'country': 'NO',
                'city': 'Oslo',
                'device_type': 'Desktop',
                'browser': 'Chrome',
                'os': 'Windows',
                'rtt_ms': 38.0,
                'login_successful': 1
            }
            if self.rba_loaded:
                self.rba_engine.predict_session_risk(dummy_ctx)
            if self.network_loaded:
                self.network_engine.predict_risk({col: 0.0 for col in self.network_engine.feature_names})
        except Exception:
            pass

    def evaluate_login_request(self, 
                               user_id: str,
                               password_candidate: str,
                               session_context: Dict[str, Any],
                               network_flow: Dict[str, Any] = None,
                               check_honeywords: bool = True) -> Dict[str, Any]:
        """
        Diagnoses authentication intent and decides mitigation action in real-time (<50ms).
        """
        start_time = time.perf_counter()
        
        # 1. Check Deceptive Canary / Honeyword status
        honey_check = (self.deception_engine.verify_attempt(user_id, password_candidate)
                       if check_honeywords else {})
        if honey_check.get('is_honeyword'):
            latency_ms = (time.perf_counter() - start_time) * 1000
            return {
                'decision': 'DECEPTIVE_QUARANTINE',
                'risk_score': 0.999,
                'threat_type': 'HONEYWORD_DATABASE_LEAK_EXPLOITATION',
                'mitigation': {
                    'action': 'Silent Quarantine & Fake Success Simulation',
                    'detail': 'Threat actor submitted decoy honeyword. Alarm raised; session sandboxed in honeypot.',
                    'http_status': 200, # Fake 200 to fool automated scraping tools
                    'delay_seconds': 2.0
                },
                'latency_ms': round(latency_ms, 2),
                'risk_breakdown': {
                    'deception_trigger': 1.0,
                    'network_risk': 1.0,
                    'behavioral_risk': 1.0
                }
            }
            
        # 2. Network Flow Risk (NTE)
        net_risk = 0.05
        has_network = bool(network_flow and self.network_loaded)
        if has_network:
            net_risk = self.network_engine.predict_risk(network_flow)
            
        # 3. Behavioral Application Risk (RBA)
        rba_risk = 0.05
        rba_features: Dict[str, Any] = {}
        if self.rba_loaded:
            rba_risk, rba_features = self.rba_engine.predict_session_risk(session_context, return_features=True)
            
        # 4. Bayesian Calibrated Risk Fusion
        # If no network flow provided, application identity/session context drives risk directly.
        if not has_network:
            combined_risk = rba_risk
        elif net_risk > 0.70:
            combined_risk = 0.65 * net_risk + 0.35 * rba_risk
        else:
            combined_risk = 0.30 * net_risk + 0.70 * rba_risk
            
        combined_risk = float(min(max(combined_risk, 0.0), 1.0))
        
        # 5. Zero-trust floor. The ML score alone is not enough: with every familiarity feature at 0 the
        # RBA model still scores ~0.23 (< ALLOW threshold), because most dataset attacks come from known-bad
        # ASNs rather than merely 'new' contexts. Frictionless ALLOW therefore also requires that the
        # location (ASN or country) AND at least two of device/browser/OS are known for this user.
        is_login_success = session_context.get('login_successful', 1) == 1
        needs_step_up_floor = False
        if self.rba_loaded and is_login_success:
            loc_known = rba_features.get('asn_familiarity', 0) or rba_features.get('country_familiarity', 0)
            dev_known = (rba_features.get('device_familiarity', 0) + rba_features.get('browser_familiarity', 0)
                         + rba_features.get('os_familiarity', 0)) >= 2
            needs_step_up_floor = not (loc_known and dev_known)

        # 5b. Determine Threat Classification
        threat_type = "BENIGN_NORMAL_USER"
        if net_risk > 0.75:
            threat_type = "NETWORK_BRUTE_FORCE_PATATOR"
        elif not is_login_success and (rba_risk > 0.65 or combined_risk > 0.65):
            threat_type = "CREDENTIAL_STUFFING_ATTEMPT"
        elif not is_login_success:
            threat_type = "INVALID_CREDENTIALS"
        elif rba_risk > 0.75 and is_login_success:
            threat_type = "ACCOUNT_TAKEOVER_IN_PROGRESS"
        elif combined_risk > 0.30 or needs_step_up_floor:
            threat_type = "SUSPICIOUS_UNFAMILIAR_CONTEXT"
            
        # 6. Graduated Mitigation Matrix (Google/Zero-Trust Tiering)
        if not is_login_success:
            # Under NO circumstance is a failed password attempt granted ALLOW
            if net_risk > 0.70 or combined_risk > 0.60:
                decision = 'TARPIT_THROTTLE'
                mitigation = {
                    'action': 'Adaptive Tarpit & Proof-of-Work Challenge',
                    'detail': 'High-velocity suspicious anomaly or repeated failure. Rate throttled with PoW requirement.',
                    'http_status': 429,
                    'delay_seconds': settings.TARPIT_DELAY_SECONDS
                }
            else:
                decision = 'DENIED'
                mitigation = {
                    'action': 'Authentication Rejected',
                    'detail': 'Invalid credentials candidate.',
                    'http_status': 401,
                    'delay_seconds': 0.0
                }
        elif combined_risk < 0.25 and not needs_step_up_floor:
            decision = 'ALLOW'
            mitigation = {
                'action': 'Frictionless Login Approved',
                'detail': 'Known trusted device & network flow. Single-factor access granted.',
                'http_status': 200,
                'delay_seconds': 0.0
            }
        elif combined_risk < 0.65:
            decision = 'STEP_UP_CHALLENGE'
            mitigation = {
                'action': 'Multi-Factor Authentication (FIDO2 / TOTP)',
                'detail': 'Unfamiliar browser, ASN or location detected. Requiring cryptographically bound step-up.',
                'http_status': 401,
                'delay_seconds': 0.0
            }
        elif combined_risk < 0.85:
            decision = 'TARPIT_THROTTLE'
            # Exponential backoff tarpit to exhaust botnet concurrency
            tarpit_delay = settings.TARPIT_DELAY_SECONDS
            mitigation = {
                'action': 'Adaptive Tarpit & Proof-of-Work Challenge',
                'detail': f'High-velocity suspicious anomaly. Rate throttled by {tarpit_delay}s with Wasm PoW requirement.',
                'http_status': 429,
                'delay_seconds': tarpit_delay
            }
        else:
            decision = 'BLOCK_AND_QUARANTINE'
            mitigation = {
                'action': 'Automated Defense Blackhole',
                'detail': 'High-confidence automated password attack or account takeover. Traffic isolated.',
                'http_status': 403,
                'delay_seconds': 5.0
            }
            
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        return {
            'user_id': user_id,
            'decision': decision,
            'risk_score': round(combined_risk, 4),
            'threat_type': threat_type,
            'mitigation': mitigation,
            'latency_ms': round(latency_ms, 2),
            'risk_breakdown': {
                'network_risk': round(net_risk, 4),
                'behavioral_rba_risk': round(rba_risk, 4),
                'device_familiarity': rba_features.get('device_familiarity', 0),
                'asn_familiarity': rba_features.get('asn_familiarity', 0),
                'country_familiarity': rba_features.get('country_familiarity', 0)
            }
        }


_agent = None


def get_agent() -> AuthGuardAgent:
    """Process-wide singleton. (v1.0 built two agents - one per router - each loading the 12 MB model
    and holding its own honeyword/profile state, so the two could disagree.)"""
    global _agent
    if _agent is None:
        _agent = AuthGuardAgent()
    return _agent
