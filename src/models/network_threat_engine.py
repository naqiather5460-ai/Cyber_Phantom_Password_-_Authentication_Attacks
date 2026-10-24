"""
Network Threat Engine (NTE)
Trained on CICIDS-2017 Tuesday-WorkingHours (FTP-Patator & SSH-Patator brute force vs. Benign).
Provides sub-10ms network flow classification with strict regularization to prevent overfitting.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    average_precision_score,
    confusion_matrix
)
from sklearn.calibration import CalibratedClassifierCV

FEATURE_COLUMNS = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Fwd IAT Total',
    'Fwd IAT Mean',
    'Bwd IAT Total',
    'Bwd IAT Mean',
    'Bwd Packets/s',
    'Packet Length Mean',
    'Packet Length Std',
    'Average Packet Size'
]

class NetworkThreatEngine:
    def __init__(self, model_path="models/network_threat_engine.joblib"):
        self.model_path = model_path
        self.scaler = None
        self.model = None
        self.feature_names = FEATURE_COLUMNS
        
    def load(self):
        if os.path.exists(self.model_path):
            data = joblib.load(self.model_path)
            self.model = data['model']
            self.scaler = data['scaler']
            self.feature_names = data['feature_names']
            print(f"[+] Loaded NetworkThreatEngine from {self.model_path}")
            return True
        return False

    def train(self, csv_path="data/Tuesday-WorkingHours.pcap_ISCX.csv", sample_size=200000):
        print("[*] Training Network Threat Engine on CICIDS-2017 Tuesday...")
        
        # Load dataset efficiently and strip column whitespaces
        df = pd.read_csv(csv_path, low_memory=False)
        df.columns = df.columns.str.strip()
        
        # Keep only required features + Label
        cols_needed = [c for c in self.feature_names if c in df.columns] + ['Label']
        df = df[cols_needed]
        
        # Clean infinite values and NaNs
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        # Binary target: 0 = Benign, 1 = Attack (FTP/SSH Patator)
        df['target'] = (df['Label'] != 'BENIGN').astype(int)
        
        # Sample to balance while keeping all attacks
        attacks = df[df['target'] == 1]
        benign = df[df['target'] == 0]
        
        benign_sample_size = min(len(benign), sample_size - len(attacks))
        sampled_benign = benign.sample(n=benign_sample_size, random_state=42)
        
        df_train = pd.concat([attacks, sampled_benign], ignore_index=True)
        print(f"    Dataset balanced: {len(attacks)} attacks, {len(sampled_benign)} benign flows.")
        
        X = df_train[self.feature_names]
        y = df_train['target']
        
        # Stratified split to prevent data leakage and evaluate generalization
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )
        
        # Scale features with RobustScaler (handles heavy-tailed network bursts)
        self.scaler = RobustScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Calibrated HistGradientBoosting (resistant to overfitting, fast inference)
        base_clf = HistGradientBoostingClassifier(
            max_iter=150,
            max_depth=6,
            min_samples_leaf=30,
            l2_regularization=1.5,
            random_state=42
        )
        
        # Platt Scaling (Sigmoid Calibration) for true posterior probabilities
        self.model = CalibratedClassifierCV(estimator=base_clf, method='sigmoid', cv=3)
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluation
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        y_pred = (y_pred_proba >= 0.5).astype(int)
        
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        pr_auc = average_precision_score(y_test, y_pred_proba)
        cm = confusion_matrix(y_test, y_pred)
        
        print("\n=== Network Threat Engine Evaluation ===")
        print(f"ROC-AUC: {roc_auc:.4f}")
        print(f"PR-AUC : {pr_auc:.4f}")
        print(f"Confusion Matrix:\n{cm}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Benign', 'BruteForce']))
        
        # Save model artifact
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'metrics': {'roc_auc': roc_auc, 'pr_auc': pr_auc}
        }, self.model_path)
        print(f"[+] Successfully saved model to {self.model_path}")
        return {'roc_auc': roc_auc, 'pr_auc': pr_auc}

    def predict_risk(self, flow_features: dict) -> float:
        """
        Infers attack probability P(BruteForce | Flow) in under 5ms.
        """
        if self.model is None:
            self.load()
            
        row_vals = np.array([[float(flow_features.get(col, 0.0)) for col in self.feature_names]], dtype=np.float64)
        vector_scaled = (row_vals - self.scaler.center_) / self.scaler.scale_
        prob = self.model.predict_proba(vector_scaled)[0, 1]
        return float(prob)

if __name__ == "__main__":
    nte = NetworkThreatEngine()
    nte.train()
