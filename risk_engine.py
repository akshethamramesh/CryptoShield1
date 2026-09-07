def calculate_risk_v2(
    transaction_count=0,
    connected_wallets=0,
    rapid_movements=0,
    abnormal_alerts=0,
    fan_in=0,
    fan_out=0,
    max_hop=0,
    vasp_matches=0
):
    """
    CryptoShield Explainable Risk Engine V2.

    Returns:
        score
        level
        factors
    """

    score = 0
    factors = []

    # -----------------------------------------
    # 1. Transaction Activity
    # -----------------------------------------

    if transaction_count >= 100:
        score += 15
        factors.append({
            "indicator": "High transaction activity",
            "points": 15
        })

    elif transaction_count >= 50:
        score += 8
        factors.append({
            "indicator": "Moderate transaction activity",
            "points": 8
        })

    # -----------------------------------------
    # 2. Connected Wallet Network
    # -----------------------------------------

    if connected_wallets >= 20:
        score += 15
        factors.append({
            "indicator": "Large connected wallet network",
            "points": 15
        })

    elif connected_wallets >= 10:
        score += 8
        factors.append({
            "indicator": "Moderate connected wallet network",
            "points": 8
        })

    # -----------------------------------------
    # 3. Rapid Movement
    # -----------------------------------------

    if rapid_movements >= 10:
        score += 15
        factors.append({
            "indicator": "Frequent rapid fund movement",
            "points": 15
        })

    elif rapid_movements >= 5:
        score += 10
        factors.append({
            "indicator": "Rapid fund movement detected",
            "points": 10
        })

    # -----------------------------------------
    # 4. Abnormal Transactions
    # -----------------------------------------

    if abnormal_alerts >= 10:
        score += 15
        factors.append({
            "indicator": "Multiple abnormal transaction indicators",
            "points": 15
        })

    elif abnormal_alerts >= 5:
        score += 10
        factors.append({
            "indicator": "Several abnormal transaction indicators",
            "points": 10
        })

    elif abnormal_alerts > 0:
        score += 5
        factors.append({
            "indicator": "Abnormal transaction indicator detected",
            "points": 5
        })

    # -----------------------------------------
    # 5. Fan-Out
    # -----------------------------------------

    if fan_out >= 10:
        score += 10
        factors.append({
            "indicator": "Very high fan-out behavior",
            "points": 10
        })

    elif fan_out >= 5:
        score += 7
        factors.append({
            "indicator": "High fan-out behavior",
            "points": 7
        })

    # -----------------------------------------
    # 6. Fan-In
    # -----------------------------------------

    if fan_in >= 10:
        score += 10
        factors.append({
            "indicator": "Very high fan-in behavior",
            "points": 10
        })

    elif fan_in >= 5:
        score += 7
        factors.append({
            "indicator": "High fan-in behavior",
            "points": 7
        })

    # -----------------------------------------
    # 7. Multi-Hop
    # -----------------------------------------

    if max_hop >= 3:
        score += 10
        factors.append({
            "indicator": "Deep multi-hop fund movement",
            "points": 10
        })

    elif max_hop >= 2:
        score += 7
        factors.append({
            "indicator": "Multi-hop fund movement detected",
            "points": 7
        })

    # -----------------------------------------
    # 8. Potential VASP Association
    # -----------------------------------------

    if vasp_matches >= 2:
        score += 10
        factors.append({
            "indicator": "Multiple potential VASP associations",
            "points": 10
        })

    elif vasp_matches == 1:
        score += 5
        factors.append({
            "indicator": "Potential VASP association identified",
            "points": 5
        })

    # -----------------------------------------
    # Limit Score
    # -----------------------------------------

    score = min(score, 100)

    # -----------------------------------------
    # Risk Level
    # -----------------------------------------

    if score >= 70:
        level = "HIGH"

    elif score >= 40:
        level = "MEDIUM"

    else:
        level = "LOW"

    return score, level, factors
