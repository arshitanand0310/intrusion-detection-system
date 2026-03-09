def calculate_severity(attack_type: str, attempts: int) -> str:
    attack_type = attack_type.lower()

    
    if attempts <= 2:
        return "MONITOR"

    
    if "sql" in attack_type:
        if attempts >= 3:
            return "HIGH"

   
    if "xss" in attack_type:
        if attempts >= 3:
            return "HIGH"

    
    if "brute" in attack_type:
        if attempts >= 10:
            return "HIGH"
        elif attempts >= 5:
            return "MEDIUM"

    
    if "rate limit" in attack_type or "ddos" in attack_type:
        if attempts >= 100:
            return "HIGH"
        elif attempts >= 20:
            return "MEDIUM"

    
    if "ml anomaly" in attack_type or "zero-day" in attack_type:
        return "HIGH"

    return "LOW"
