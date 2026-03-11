import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import recall_score, precision_score


data = pd.read_csv("NF-UNSW-NB15-v3.csv")

features = data.drop(columns=["Label", "Attack"])
features = features.replace([np.inf, -np.inf], np.nan)
features = features.fillna(0)
features = features.drop(columns=["MIN_TTL", "MAX_TTL"]) 
labels = data["Label"]

normal_count = (labels == 0).sum()
attack_count = (labels == 1).sum()
class_weight = normal_count / attack_count

f_train, f_test, l_train, l_test = train_test_split(
    features, labels,
    test_size=0.2,
    random_state=42,
    stratify=labels
)

detector = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=4,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=class_weight,
    tree_method="hist",
    n_jobs=-1,
    eval_metric="logloss",
    early_stopping_rounds=20,
    random_state=42
)

detector.fit(
    f_train, l_train,
    eval_set=[(f_test, l_test)],
    verbose=10
)

guesses = detector.predict(f_test)
recall    = recall_score(l_test, guesses)
precision = precision_score(l_test, guesses)

detector.save_model("v2_model.json")

print(f"recall    : {recall:.4f}")
print(f"precision : {precision:.4f}")