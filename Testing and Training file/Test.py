import pandas as pd
import xgboost as xgb
from sklearn.metrics import recall_score, precision_score

data = pd.read_csv("NF-ToN-IoT-v3.csv")

features = data.drop(columns=["Label", "Attack", "MIN_TTL", "MAX_TTL", "IPV4_SRC_ADDR", "IPV4_DST_ADDR"])
labels = data["Label"]

detector = xgb.XGBClassifier()
detector.load_model("v2_model.json")

trained_on = detector.get_booster().feature_names
features = features[trained_on]

guesses = detector.predict(features)

recall    = recall_score(labels, guesses)
precision = precision_score(labels, guesses)

print(f"recall : {recall:.4f}")
print(f"precision : {precision:.4f}")