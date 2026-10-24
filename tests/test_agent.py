"""
Unit & Integration Test Suite for AuthGuard AI
Verifies model accuracy, agent decision policies, deceptive honeywords, and latency constraints.
"""

import unittest
import time
from src.agent.authguard_agent import AuthGuardAgent

class TestAuthGuardAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = AuthGuardAgent()
        # Arm a test user with a real password and realistic decoys
        reg = cls.agent.deception_engine.register_user_credentials("john_doe", "Secur3P@ss2024!")
        cls.decoys = reg['decoys']
        cls.agent.rba_engine.user_profiles['john_doe'] = {
            'asns': {15169, '15169', 'AS15169'},
            'countries': {'US'},
            'cities': {'New York'},
            'devices': {'desktop'},
            'browsers': {'Chrome'},
            'oss': {'Windows'},
            'rtts': [35.0, 36.0]
        }
        cls.agent._warmup()
        print(f"[+] Armed user john_doe with decoys: {cls.decoys}")

    def test_model_loading(self):
        """Ensure both production models loaded successfully"""
        self.assertTrue(self.agent.network_loaded, "Network Threat Engine must be loaded")
        self.assertTrue(self.agent.rba_loaded, "Behavioral RBA Engine must be loaded")

    def test_benign_user_frictionless_allow(self):
        """Scenario 1: Benign user on home network with low RTT should be ALLOW or low risk"""
        session_ctx = {
            'user_id': 'john_doe',
            'asn': 'AS15169',
            'country': 'US',
            'city': 'New York',
            'device_type': 'desktop',
            'browser': 'Chrome 122',
            'os': 'Windows 11',
            'rtt_ms': 35.0,
            'hour': 14,
            'login_successful': 1,
            'is_weekend': 0
        }
        res = self.agent.evaluate_login_request(
            user_id="john_doe",
            password_candidate="Secur3P@ss2024!",
            session_context=session_ctx
        )
        print(f"\n[+] Benign Test: Decision={res['decision']}, Risk={res['risk_score']}, Latency={res['latency_ms']}ms")
        self.assertIn(res['decision'], ['ALLOW', 'STEP_UP_CHALLENGE'])
        self.assertLess(res['latency_ms'], 50.0, "Latency must be under 50ms SLA")

    def test_23andme_credential_stuffing(self):
        """Scenario 2: Credential stuffing from high-threat ASN (393398) with unfamiliar context"""
        session_ctx = {
            'user_id': 'john_doe',
            'asn': 393398, # High-risk attack ASN identified in dataset
            'country': 'US',
            'city': 'Unknown',
            'device_type': 'mobile',
            'browser': 'HeadlessChrome',
            'os': 'Linux',
            'rtt_ms': 350.0,
            'hour': 3,
            'login_successful': 0,
            'is_weekend': 0
        }
        res = self.agent.evaluate_login_request(
            user_id="john_doe",
            password_candidate="Secur3P@ss2024!",
            session_context=session_ctx
        )
        print(f"[+] 23andMe Stuffing Test: Decision={res['decision']}, Risk={res['risk_score']}, Threat={res['threat_type']}")
        self.assertIn(res['decision'], ['STEP_UP_CHALLENGE', 'TARPIT_THROTTLE', 'BLOCK_AND_QUARANTINE'])

    def test_network_brute_force_patator(self):
        """Scenario 3: Fast automated SSH-Patator brute force burst from CICIDS-2017 dataset"""
        flow = {
            'Destination Port': 22.0,
            'Flow Duration': 404.0,
            'Total Fwd Packets': 2.0,
            'Total Backward Packets': 0.0,
            'Total Length of Fwd Packets': 0.0,
            'Total Length of Bwd Packets': 0.0,
            'Fwd Packet Length Max': 0.0,
            'Fwd Packet Length Mean': 0.0,
            'Fwd Packet Length Std': 0.0,
            'Flow Bytes/s': 0.0,
            'Flow Packets/s': 4950.495,
            'Flow IAT Mean': 404.0,
            'Flow IAT Std': 0.0,
            'Flow IAT Max': 404.0,
            'Fwd IAT Total': 404.0,
            'Fwd IAT Mean': 404.0,
            'Bwd IAT Total': 0.0,
            'Bwd IAT Mean': 0.0,
            'Bwd Packets/s': 0.0,
            'Packet Length Mean': 0.0,
            'Packet Length Std': 0.0,
            'Average Packet Size': 0.0
        }
        res = self.agent.evaluate_login_request(
            user_id="victim_server",
            password_candidate="password123",
            session_context={'user_id': 'victim_server', 'login_successful': 0, 'browser': 'None', 'os': 'Linux'},
            network_flow=flow
        )
        print(f"[+] Network Brute Force Test: Decision={res['decision']}, Risk={res['risk_score']}, Threat={res['threat_type']}")
        self.assertGreater(res['risk_score'], 0.65)
        self.assertEqual(res['threat_type'], 'NETWORK_BRUTE_FORCE_PATATOR')
        self.assertIn(res['decision'], ['TARPIT_THROTTLE', 'BLOCK_AND_QUARANTINE'])

    def test_honeyword_canary_tripped(self):
        """Scenario 4: Threat actor tests a decoy password from a dumped database"""
        decoy_password = self.decoys[0]
        res = self.agent.evaluate_login_request(
            user_id="john_doe",
            password_candidate=decoy_password,
            session_context={'user_id': 'john_doe', 'browser': 'TorBrowser', 'os': 'Linux'}
        )
        print(f"[+] Honeyword Trip Test: Decision={res['decision']}, Threat={res['threat_type']}")
        self.assertEqual(res['decision'], 'DECEPTIVE_QUARANTINE')
        self.assertEqual(res['risk_score'], 0.999)

if __name__ == '__main__':
    unittest.main()
