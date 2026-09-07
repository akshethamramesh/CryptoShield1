# risk_engine.py


def calculate_risk_v3(
    transaction_count=0,
    connected_wallets=0,
    rapid_movements=0,
    abnormal_alerts=0,
    fan_in=0,
    fan_out=0,
    max_hop=0,
    vasp_matches=0,
    token_transactions=0,
    token_types=0
):
    """
    CryptoShield Explainable Risk Engine V3

    Risk score:
        0 - 100

    Important:
        This is an analytical risk indicator.
        It does NOT prove fraud or criminal activity.
    """

    score = 0
    factors = []

    # ========================================================
    # 1. TRANSACTION ACTIVITY
    # Maximum: 15
    # ========================================================

    if transaction_count >= 200:

        points = 15

        factors.append({
            "indicator": "Very high transaction activity",
            "points": points
        })

        score += points

    elif transaction_count >= 100:

        points = 12

        factors.append({
            "indicator": "High transaction activity",
            "points": points
        })

        score += points

    elif transaction_count >= 50:

        points = 7

        factors.append({
            "indicator": "Moderate transaction activity",
            "points": points
        })

        score += points


    # ========================================================
    # 2. CONNECTED WALLET NETWORK
    # Maximum: 15
    # ========================================================

    if connected_wallets >= 30:

        points = 15

        factors.append({
            "indicator": "Very large connected wallet network",
            "points": points
        })

        score += points

    elif connected_wallets >= 20:

        points = 12

        factors.append({
            "indicator": "Large connected wallet network",
            "points": points
        })

        score += points

    elif connected_wallets >= 10:

        points = 7

        factors.append({
            "indicator": "Moderate connected wallet network",
            "points": points
        })

        score += points


    # ========================================================
    # 3. RAPID FUND MOVEMENT
    # Maximum: 15
    # ========================================================

    if rapid_movements >= 20:

        points = 15

        factors.append({
            "indicator": "Very frequent rapid fund movement",
            "points": points
        })

        score += points

    elif rapid_movements >= 10:

        points = 12

        factors.append({
            "indicator": "Frequent rapid fund movement",
            "points": points
        })

        score += points

    elif rapid_movements >= 5:

        points = 7

        factors.append({
            "indicator": "Rapid fund movement detected",
            "points": points
        })

        score += points


    # ========================================================
    # 4. ABNORMAL TRANSACTIONS
    # Maximum: 15
    # ========================================================

    if abnormal_alerts >= 20:

        points = 15

        factors.append({
            "indicator": "Large number of abnormal transaction indicators",
            "points": points
        })

        score += points

    elif abnormal_alerts >= 10:

        points = 12

        factors.append({
            "indicator": "Multiple abnormal transaction indicators",
            "points": points
        })

        score += points

    elif abnormal_alerts >= 5:

        points = 8

        factors.append({
            "indicator": "Several abnormal transaction indicators",
            "points": points
        })

        score += points

    elif abnormal_alerts > 0:

        points = 4

        factors.append({
            "indicator": "Abnormal transaction indicator detected",
            "points": points
        })

        score += points


    # ========================================================
    # 5. FAN-OUT
    # Maximum: 10
    # ========================================================

    if fan_out >= 20:

        points = 10

        factors.append({
            "indicator": "Very high fan-out behavior",
            "points": points
        })

        score += points

    elif fan_out >= 10:

        points = 8

        factors.append({
            "indicator": "High fan-out behavior",
            "points": points
        })

        score += points

    elif fan_out >= 5:

        points = 5

        factors.append({
            "indicator": "Fund splitting / fan-out behavior",
            "points": points
        })

        score += points


    # ========================================================
    # 6. FAN-IN
    # Maximum: 10
    # ========================================================

    if fan_in >= 20:

        points = 10

        factors.append({
            "indicator": "Very high fan-in behavior",
            "points": points
        })

        score += points

    elif fan_in >= 10:

        points = 8

        factors.append({
            "indicator": "High fan-in behavior",
            "points": points
        })

        score += points

    elif fan_in >= 5:

        points = 5

        factors.append({
            "indicator": "Fund consolidation / fan-in behavior",
            "points": points
        })

        score += points


    # ========================================================
    # 7. MULTI-HOP MOVEMENT
    # Maximum: 10
    # ========================================================

    if max_hop >= 3:

        points = 10

        factors.append({
            "indicator": "Deep multi-hop fund movement",
            "points": points
        })

        score += points

    elif max_hop >= 2:

        points = 7

        factors.append({
            "indicator": "Multi-hop fund movement detected",
            "points": points
        })

        score += points


    # ========================================================
    # 8. VASP ASSOCIATION
    # Maximum: 5
    # ========================================================

    if vasp_matches >= 2:

        points = 5

        factors.append({
            "indicator": "Multiple potential VASP associations",
            "points": points
        })

        score += points

    elif vasp_matches == 1:

        points = 4

        factors.append({
            "indicator": "Potential VASP association identified",
            "points": points
        })

        score += points


    # ========================================================
    # 9. TOKEN ACTIVITY
    # Maximum: 10
    # ========================================================

    if token_transactions >= 100:

        points = 10

        factors.append({
            "indicator": "Very high token transfer activity",
            "points": points
        })

        score += points

    elif token_transactions >= 50:

        points = 8

        factors.append({
            "indicator": "High token transfer activity",
            "points": points
        })

        score += points

    elif token_transactions >= 10:

        points = 5

        factors.append({
            "indicator": "Significant token transfer activity",
            "points": points
        })

        score += points


    # ========================================================
    # 10. MULTIPLE TOKEN TYPES
    # Maximum: 5
    # ========================================================

    if token_types >= 10:

        points = 5

        factors.append({
            "indicator": "Multiple token types detected",
            "points": points
        })

        score += points

    elif token_types >= 5:

        points = 4

        factors.append({
            "indicator": "Several token types detected",
            "points": points
        })

        score += points

    elif token_types >= 2:

        points = 2

        factors.append({
            "indicator": "Multiple token types detected",
            "points": points
        })

        score += points


    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = min(
        int(score),
        100
    )


    # ========================================================
    # RISK LEVEL
    # ========================================================

    if score >= 70:

        level = "HIGH"

    elif score >= 40:

        level = "MEDIUM"

    else:

        level = "LOW"


    # ========================================================
    # SORT FACTORS
    # ========================================================

    factors.sort(
        key=lambda item: item.get(
            "points",
            0
        ),
        reverse=True
    )


    return (
        score,
        level,
        factors
    )


# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================

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

    return calculate_risk_v3(

        transaction_count=transaction_count,

        connected_wallets=connected_wallets,

        rapid_movements=rapid_movements,

        abnormal_alerts=abnormal_alerts,

        fan_in=fan_in,

        fan_out=fan_out,

        max_hop=max_hop,

        vasp_matches=vasp_matches,

        token_transactions=0,

        token_types=0
    )
