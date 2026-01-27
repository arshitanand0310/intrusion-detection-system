import joblib
from sklearn.ensemble import IsolationForest
from feature_extractor import extract_features


normal_requests = [
    "/home",
    "/login?user=admin",
    "/profile?id=12",
    "/search?q=laptop",
    "/products?page=2",
]

X = [extract_features(r) for r in normal_requests]

model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

model.fit(X)

joblib.dump(model, "model.pkl")
print("ML IDS model trained and saved")
