# ============================================================
# CryptoShield - Risk Engine V3
# ============================================================
#
# Purpose:
# Calculate an explainable blockchain risk score
# based on multiple observable transaction indicators.
#
# IMPORTANT:
# This score is an analytical indicator.
# It does NOT prove criminal activity or wallet ownership.
# ============================================================


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

    score = 0
    factors = []


    # ========================================================
    # 1. TRANSACTION ACTIVITY
    # Maximum: 10 points
    # ========================================================

    if transaction_count >= 100:

        score += 10

        factors.append({
            "indicator": "High transaction activity",
            "points": 10
        })

    elif transaction_count >= 50:

        score += 5

        factors.append({
            "indicator": "Moderate transaction activity",
            "points": 5
        })


    # ========================================================
    # 2. CONNECTED WALLET NETWORK
    # Maximum: 10 points
    # ========================================================

    if connected_wallets >= 20:

        score += 10

        factors.append({
            "indicator": "Large connected wallet network",
            "points": 10
        })

    elif connected_wallets >= 10:

        score += 5

        factors.append({
            "indicator": "Moderate connected wallet network",
            "points": 5
        })


    # ========================================================
    # 3. RAPID FUND MOVEMENT
    # Maximum: 10 points
    # ========================================================

    if rapid_movements >= 10:

        score += 10

        factors.append({
            "indicator": "Frequent rapid fund movement",
            "points": 10
        })

    elif rapid_movements >= 5:

        score += 6

        factors.append({
            "indicator": "Rapid fund movement detected",
            "points": 6
        })


    # ========================================================
    # 4. ABNORMAL TRANSACTION INDICATORS
    # Maximum: 15 points
    # ========================================================

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


    # ========================================================
    # 5. FAN-OUT
    # One wallet → many wallets
    # Maximum: 10 points
    # ========================================================

    if fan_out >= 10:

        score += 10

        factors.append({
            "indicator": "Very high fan-out behavior",
            "points": 10
        })

    elif fan_out >= 5:

        score += 6

        factors.append({
            "indicator": "High fan-out behavior",
            "points": 6
        })


    # ========================================================
    # 6. FAN-IN
    # Many wallets → one wallet
    # Maximum: 10 points
    # ========================================================

    if fan_in >= 10:

        score += 10

        factors.append({
            "indicator": "Very high fan-in behavior",
            "points": 10
        })

    elif fan_in >= 5:

        score += 6

        factors.append({
            "indicator": "High fan-in behavior",
            "points": 6
        })


    # ========================================================
    # 7. MULTI-HOP FUND MOVEMENT
    # Maximum: 10 points
    # ========================================================

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


    # ========================================================
    # 8. TOKEN TRANSFER ACTIVITY
    # Maximum: 10 points
    #
    # NOTE:
    # Token activity alone is NOT proof of fraud.
    # It is only an analytical indicator.
    # ========================================================

    if token_transactions >= 100:

        score += 10

        factors.append({
            "indicator": "High token-transfer activity",
            "points": 10
        })

    elif token_transactions >= 50:

        score += 6

        factors.append({
            "indicator": "Moderate token-transfer activity",
            "points": 6
        })

    elif token_transactions > 0:

        score += 3

        factors.append({
            "indicator": "Token-transfer activity detected",
            "points": 3
        })


    # ========================================================
    # 9. TOKEN DIVERSITY
    # Maximum: 5 points
    # ========================================================

    if token_types >= 3:

        score += 5

        factors.append({
            "indicator": "Multiple token types observed",
            "points": 5
        })

    elif token_types >= 2:

        score += 3

        factors.append({
            "indicator": "Multiple token types observed",
            "points": 3
        })


    # ========================================================
    # 10. POTENTIAL VASP ASSOCIATION
    # Maximum: 10 points
    #
    # NOTE:
    # This means potential association only.
    # It does NOT prove wallet ownership.
    # ========================================================

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


    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = min(score, 100)


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
    # RETURN
    # ========================================================

    return score, level, factors


# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================
#
# If older code calls calculate_risk(), it will still work.
# ============================================================

def calculate_risk(
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

    return calculate_risk_v3(
        transaction_count=transaction_count,
        connected_wallets=connected_wallets,
        rapid_movements=rapid_movements,
        abnormal_alerts=abnormal_alerts,
        fan_in=fan_in,
        fan_out=fan_out,
        max_hop=max_hop,
        vasp_matches=vasp_matches,
        token_transactions=token_transactions,
        token_types=token_types
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    score, level, factors = calculate_risk_v3(

        transaction_count=150,

        connected_wallets=25,

        rapid_movements=12,

        abnormal_alerts=8,

        fan_in=7,

        fan_out=11,

        max_hop=2,

        vasp_matches=1,

        token_transactions=120,

        token_types=4
    )


    print("=" * 50)
    print("CryptoShield Risk Engine Test")
    print("=" * 50)

    print(
        f"Risk Score : {score}/100"
    )

    print(
        f"Risk Level : {level}"
    )

    print("\nRisk Factors:")

    for factor in factors:

        print(
            f"- {factor['indicator']}: "
            f"+{factor['points']}"
        )
