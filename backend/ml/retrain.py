import joblib
from sklearn.ensemble import IsolationForest
from backend.ml.feature_extractor import extract_features

normal_payloads = [
    "search=home",
    "q=about",
    "page=contact",
    "user=admin",
    "id=123",
    "filter=name",
]

X = [extract_features(p) for p in normal_payloads]

model = IsolationForest(
    n_estimators=300,
    contamination=0.08,
    random_state=42
)

model.fit(X)
joblib.dump(model, "backend/ml/model.pkl")

print(" ML model retrained successfully")
