"""
Behavioral Risk-Based Authentication (RBA) Engine
Inspired by Google's RBA architecture (Freeman et al., Wiefling et al.).
Evaluates login session telemetry: device fingerprinting, ASN reputation,
geo-velocity, and round-trip time anomalies.
Calibrated with Bayesian smoothed priors and balanced class weighting
to prevent underfitting and identity memorization.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    average_precision_score,
    confusion_matrix
)

RBA_FEATURES = [
    'asn_familiarity',       # 1 if ASN seen in user history, 0 otherwise
    'country_familiarity',   # 1 if Country seen in user history, 0 otherwise
    'city_familiarity',      # 1 if City seen in user history, 0 otherwise
    'device_familiarity',    # 1 if Device Type seen in user history, 0 otherwise
    'browser_familiarity',   # 1 if Browser Name seen in user history, 0 otherwise
    'os_familiarity',        # 1 if OS Name seen in user history, 0 otherwise
    'asn_risk_prior',        # Empirical Bayes smoothed threat rate for the ASN
    'country_risk_prior',    # Empirical Bayes smoothed threat rate for the Country
    'rtt_zscore',            # Standardized deviation from user baseline RTT
    'rtt_raw',               # Raw round trip time in ms
    'login_successful'       # 1 if credentials matched, 0 if failed
]

class BehavioralRBAEngine:
    def __init__(self, model_path="models/behavioral_rba_engine.joblib"):
        self.model_path = model_path
        self.scaler = None
        self.model = None
        self.feature_names = RBA_FEATURES
        self.user_profiles = {}
        self.asn_risk_map = {}
        self.country_risk_map = {}
        self.global_prior = 0.10
        
    def load(self):
        if os.path.exists(self.model_path):
            data = joblib.load(self.model_path)
            self.model = data['model']
            self.scaler = data['scaler']
            self.feature_names = data['feature_names']
            self.user_profiles = data.get('user_profiles', {})
            self.asn_risk_map = data.get('asn_risk_map', {})
            self.country_risk_map = data.get('country_risk_map', {})
            self.global_prior = data.get('global_prior', 0.10)
            print(f"[+] Loaded BehavioralRBAEngine from {self.model_path}")
            return True
        return False

    def build_priors(self, df: pd.DataFrame, m: int = 15):
        """
        Calculates Empirical Bayes smoothed priors:
        smoothed_rate = (attacks + m * prior) / (count + m)
        Prevents overfitting on rare ASNs while capturing malicious hosting ranges.
        """
        self.global_prior = float(df['target'].mean())
        
        # ASN priors
        asn_stats = df.groupby('ASN')['target'].agg(['count', 'sum'])
        for asn, row in asn_stats.iterrows():
            smoothed = (row['sum'] + m * self.global_prior) / (row['count'] + m)
            self.asn_risk_map[asn] = float(smoothed)
            
        # Country priors
        ctry_stats = df.groupby('Country')['target'].agg(['count', 'sum'])
        for ctry, row in ctry_stats.iterrows():
            smoothed = (row['sum'] + m * self.global_prior) / (row['count'] + m)
            self.country_risk_map[ctry] = float(smoothed)

    def engineer_features(self, df: pd.DataFrame, is_training: bool = True) -> pd.DataFrame:
        df = df.copy()
        
        # Parse timestamp
        df['dt'] = pd.to_datetime(df['Login Timestamp'])
        df['login_hour'] = df['dt'].dt.hour
        df['is_weekend'] = df['dt'].dt.dayofweek.isin([5, 6]).astype(int)
        df['login_successful'] = df['Login Successful'].astype(int)
        df['rtt_raw'] = pd.to_numeric(df['Round-Trip Time [ms]'], errors='coerce').fillna(100.0)
        
        # Priors
        df['asn_risk_prior'] = df['ASN'].map(self.asn_risk_map).fillna(self.global_prior)
        df['country_risk_prior'] = df['Country'].map(self.country_risk_map).fillna(self.global_prior)
        
        # User familiarity
        asn_fam = []
        country_fam = []
        city_fam = []
        device_fam = []
        browser_fam = []
        os_fam = []
        rtt_zscores = []
        
        for _, row in df.iterrows():
            uid = row['User ID']
            profile = self.user_profiles.get(uid, {
                'asns': set(), 'countries': set(), 'cities': set(),
                'devices': set(), 'browsers': set(), 'oss': set(), 'rtts': []
            })
            
            asn_fam.append(1 if row['ASN'] in profile['asns'] else 0)
            country_fam.append(1 if row['Country'] in profile['countries'] else 0)
            city_fam.append(1 if row['City'] in profile['cities'] else 0)
            device_fam.append(1 if row['Device Type'] in profile['devices'] else 0)
            browser_fam.append(1 if str(row['Browser Name and Version']).split()[0] in profile['browsers'] else 0)
            os_fam.append(1 if str(row['OS Name and Version']).split()[0] in profile['oss'] else 0)
            
            curr_rtt = float(row['rtt_raw'])
            if len(profile['rtts']) >= 2:
                mean_rtt = np.mean(profile['rtts'])
                std_rtt = np.std(profile['rtts']) + 1e-5
                zscore = (curr_rtt - mean_rtt) / std_rtt
            else:
                zscore = 0.0
            rtt_zscores.append(float(np.clip(zscore, -3.0, 3.0)))
            
            if is_training and row.get('target', 0) == 0:
                profile['asns'].add(row['ASN'])
                profile['countries'].add(row['Country'])
                profile['cities'].add(row['City'])
                profile['devices'].add(row['Device Type'])
                profile['browsers'].add(str(row['Browser Name and Version']).split()[0])
                profile['oss'].add(str(row['OS Name and Version']).split()[0])
                profile['rtts'].append(curr_rtt)
                if len(profile['rtts']) > 20:
                    profile['rtts'].pop(0)
                self.user_profiles[uid] = profile
                
        df['asn_familiarity'] = asn_fam
        df['country_familiarity'] = country_fam
        df['city_familiarity'] = city_fam
        df['device_familiarity'] = device_fam
        df['browser_familiarity'] = browser_fam
        df['os_familiarity'] = os_fam
        df['rtt_zscore'] = rtt_zscores
        
        return df

    def train(self, csv_path="data/rba_curated_sample.csv"):
        print("[*] Training Behavioral RBA Engine on curated RBA dataset...")
        df_raw = pd.read_csv(csv_path, low_memory=False)
        
        # Target: 1 if Attack IP or Account Takeover, 0 otherwise
        df_raw['target'] = ((df_raw['Is Attack IP'] == True) | (df_raw['Is Account Takeover'] == True)).astype(int)
        
        # Split train/test with stratification
        train_df, test_df = train_test_split(df_raw, test_size=0.20, random_state=42, stratify=df_raw['target'])
        
        # Build Bayesian priors from train split only (prevent test leakage)
        self.build_priors(train_df)
        
        # Engineer features
        df_train_feats = self.engineer_features(train_df, is_training=True)
        df_test_feats = self.engineer_features(test_df, is_training=False)
        
        X_train = df_train_feats[self.feature_names]
        y_train = df_train_feats['target']
        X_test = df_test_feats[self.feature_names]
        y_test = df_test_feats['target']
        
        print(f"    Train size: {len(X_train)} (Attacks: {y_train.sum()}), Test size: {len(X_test)} (Attacks: {y_test.sum()})")
        
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Balanced, regularized HistGradientBoosting
        base_clf = HistGradientBoostingClassifier(
            max_iter=150,
            max_depth=6,
            min_samples_leaf=30,
            class_weight='balanced',
            l2_regularization=2.5,
            random_state=42
        )
        
        # Platt Scaling (Calibrated probabilities)
        self.model = CalibratedClassifierCV(estimator=base_clf, method='sigmoid', cv=3)
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        y_pred = (y_pred_proba >= 0.5).astype(int)
        
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        pr_auc = average_precision_score(y_test, y_pred_proba)
        cm = confusion_matrix(y_test, y_pred)
        
        print("\n=== Behavioral RBA Engine Evaluation ===")
        print(f"ROC-AUC: {roc_auc:.4f}")
        print(f"PR-AUC : {pr_auc:.4f}")
        print(f"Confusion Matrix:\n{cm}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Malicious/Compromise']))
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'user_profiles': self.user_profiles,
            'asn_risk_map': self.asn_risk_map,
            'country_risk_map': self.country_risk_map,
            'global_prior': self.global_prior,
            'metrics': {'roc_auc': roc_auc, 'pr_auc': pr_auc}
        }, self.model_path)
        print(f"[+] Successfully saved model to {self.model_path}")
        return {'roc_auc': roc_auc, 'pr_auc': pr_auc}

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _empty_profile() -> dict:
        return {'asns': set(), 'countries': set(), 'cities': set(),
                'devices': set(), 'browsers': set(), 'oss': set(), 'rtts': []}

    @staticmethod
    def _asn_key(raw):
        text = str(raw if raw is not None else '').strip()
        if text[:2].upper() == 'AS':
            text = text[2:]
        try:
            return int(text)
        except (ValueError, TypeError):
            return text

    @staticmethod
    def _first_token(value) -> str:
        tokens = str(value or '').split()
        return tokens[0] if tokens else ''

    def _build_features(self, session: dict):
        """Returns (feature_vector, named_features). Device type is compared case-insensitively because
        the RBA dataset stores it lower-case ('desktop') while clients send 'Desktop'."""
        uid = session.get('user_id', 'anonymous')
        profile = self.user_profiles.get(uid) or self._empty_profile()

        asn_key = self._asn_key(session.get('asn'))
        country = str(session.get('country') or '')
        known_asns = {str(a).upper().replace('AS', '') for a in profile['asns']}
        asn_fam = 1 if (asn_key != '' and str(asn_key) in known_asns) else 0
        country_fam = 1 if country and country in profile['countries'] else 0
        city_fam = 1 if session.get('city') in profile['cities'] else 0
        known_devices = {str(d).lower() for d in profile['devices']}
        device_fam = 1 if str(session.get('device_type') or '').lower() in known_devices else 0
        browser_fam = 1 if self._first_token(session.get('browser')) in profile['browsers'] else 0
        os_fam = 1 if self._first_token(session.get('os')) in profile['oss'] else 0

        asn_risk = self.asn_risk_map.get(asn_key, self.global_prior)
        country_risk = self.country_risk_map.get(country, self.global_prior)

        try:
            rtt = float(session.get('rtt_ms') or 100.0)
        except (TypeError, ValueError):
            rtt = 100.0
        if len(profile['rtts']) >= 2:
            zscore = (rtt - np.mean(profile['rtts'])) / (np.std(profile['rtts']) + 1e-5)
        else:
            zscore = 0.0
        zscore = float(np.clip(zscore, -3.0, 3.0))

        login_ok = float(session.get('login_successful', 1))
        named = {
            'asn_familiarity': asn_fam, 'country_familiarity': country_fam, 'city_familiarity': city_fam,
            'device_familiarity': device_fam, 'browser_familiarity': browser_fam, 'os_familiarity': os_fam,
            'asn_risk_prior': float(asn_risk), 'country_risk_prior': float(country_risk),
            'rtt_zscore': zscore, 'rtt_raw': rtt, 'login_successful': login_ok,
        }
        # Order the vector by the feature list stored with the trained model
        vector = np.array([[named[name] for name in self.feature_names]], dtype=np.float64)
        return vector, named

    def has_baseline(self, uid: str) -> bool:
        profile = self.user_profiles.get(uid)
        return bool(profile and (profile['asns'] or profile['countries'] or profile['devices']))

    def learn_session(self, uid: str, session: dict) -> dict:
        """Adds a *verified* (password + any required MFA) session to the user's baseline."""
        profile = self.user_profiles.setdefault(uid, self._empty_profile())
        asn_key = self._asn_key(session.get('asn'))
        if asn_key not in ('', 'UNKNOWN'):
            profile['asns'].add(asn_key)
        for field, key in (('countries', 'country'), ('cities', 'city')):
            value = session.get(key)
            if value and str(value).upper() not in ('UNKNOWN', 'XX'):
                profile[field].add(value)
        device = str(session.get('device_type') or '').lower()
        if device and device != 'unknown':
            profile['devices'].add(device)
        browser, os_name = self._first_token(session.get('browser')), self._first_token(session.get('os'))
        if browser and browser != 'Unknown':
            profile['browsers'].add(browser)
        if os_name and os_name != 'Unknown':
            profile['oss'].add(os_name)
        try:
            profile['rtts'].append(float(session.get('rtt_ms') or 0) or 50.0)
        except (TypeError, ValueError):
            pass
        del profile['rtts'][:-20]
        return profile

    def predict_session_risk(self, session: dict, return_features: bool = False):
        """Assesses application-level authentication risk in real time."""
        if self.model is None:
            self.load()
        vector, named = self._build_features(session)
        feats_scaled = (vector - self.scaler.mean_) / self.scaler.scale_
        risk = float(self.model.predict_proba(feats_scaled)[0, 1])
        return (risk, named) if return_features else risk

if __name__ == "__main__":
    rba = BehavioralRBAEngine()
    rba.train()
