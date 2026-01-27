import joblib
from backend.ml.feature_extractor import extract_features

model = joblib.load("backend/ml/model.pkl")

def predict(payload: str):
    features = extract_features(payload)
    prediction = model.predict([features])[0]
    score = model.decision_function([features])[0]

    return {
        "prediction": "ANOMALY" if prediction == -1 else "NORMAL",
        "score": round(score, 4)
    }
