import joblib
from backend.ml.feature_extractor import extract_features

model = joblib.load("backend/ml/model.pkl")

def is_anomalous(payload: str) -> bool:
    features = extract_features(payload)

    
    prediction = model.predict([features])[0]  

    
    if features[0] > 2000:          
        return True
    if features[-1] > 4.5:          
        return True

    return prediction == -1
