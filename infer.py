import json
import pandas as pd
import xgboost as xgb
import time

ML_ATTACK_THRESHOLD = 0.85

with open("whitelist.json") as f:
    _WHITELIST = set(json.load(f)["ips"])

class MLDetector:
    def __init__(self, model_path="v5_model.json"):
        self.model = xgb.XGBClassifier()
        self.model.load_model(model_path)
        self.features = self.model.get_booster().feature_names

    def predict(self, flow_features):
        df = pd.DataFrame([flow_features])
        df = df.reindex(columns=self.features, fill_value=0)
        confidence = float(self.model.predict_proba(df)[0][1])
        return confidence >= ML_ATTACK_THRESHOLD, round(confidence, 4)


def ml_worker(flow_queue, alert_queue, model_path="v5_model.json"):
    detector = MLDetector(model_path)
    while True:
        flow = flow_queue.get()
        src = flow.get("src", "unknown")

        if src in _WHITELIST:
            continue

        ml_flagged, confidence = detector.predict(flow["features"])
        sig_flagged = flow.get("sig_flagged", False)
        is_attack   = ml_flagged or sig_flagged

        if ml_flagged and sig_flagged:
            method = "ml+sig"
        elif sig_flagged:
            method = "sig"
        elif ml_flagged:
            method = "ml"
        else:
            method = "clean"

        alert_queue.put({
            "is_attack":  is_attack,
            "method":     method,
            "name":       "SIG Match" if (sig_flagged and not ml_flagged) else "ML Anomaly" if is_attack else "Clean flow",
            "src":        src,
            "confidence": confidence,
            "severity":   "CRIT" if is_attack else "OK",
            "time":       time.strftime("%H:%M:%S"),
            "dport":      flow.get("dport", 0),
        })