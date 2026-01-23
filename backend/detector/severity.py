# backend/detector/severity.py

def calculate_severity(attack_type: str, attempts: int) -> str:
    attack_type = attack_type.lower()

    if attack_type == "brute force":
        if attempts >= 7:
            return "HIGH"
        elif attempts >= 4:
            return "MEDIUM"
        else:
            return "LOW"

    if attack_type == "sql injection":
        if attempts >= 2:
            return "HIGH"
        else:
            return "MEDIUM"

    if attack_type == "xss":
        if attempts >= 2:
            return "MEDIUM"
        else:
            return "LOW"

    return "LOW"
