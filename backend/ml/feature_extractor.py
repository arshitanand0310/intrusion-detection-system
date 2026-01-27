import math
from collections import Counter

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def extract_features(payload: str):
    payload = payload.lower()

    return [
        len(payload),                     
        payload.count("'"),
        payload.count('"'),
        payload.count("--"),
        payload.count("<script"),
        payload.count(" or "),
        payload.count("="),
        shannon_entropy(payload),         
    ]
