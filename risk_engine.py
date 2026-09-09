"""
CryptoShield Risk Engine V3

Purpose:
    Calculate an explainable blockchain analytical risk score.

Important:
    This score is NOT a probability of fraud.
    It is NOT a legal determination.
    It represents the strength of configured blockchain
    risk indicators.
"""


# ============================================================
# RISK ENGINE V3
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
    """
    Calculate an explainable risk score out of 100.

    Maximum possible contribution:

        Transaction Activity  = 10
        Connected Network     = 10
        Rapid Movement        = 10
        Abnormal Activity     = 15
        Fan-Out                = 10
        Fan-In                 = 10
        Multi-Hop              = 10
        Token Activity        = 10
        Token Diversity       = 5
        VASP Association      = 10

        TOTAL                  = 100

    Returns:

        score
        level
        factors

    Example:

        score, level, factors = calculate_risk_v3(...)
    """

    # --------------------------------------------------------
    # Make sure numeric inputs are safe
    # --------------------------------------------------------

    try:
        transaction_count = int(transaction_count or 0)
    except Exception:
        transaction_count = 0

    try:
        connected_wallets = int(connected_wallets or 0)
    except Exception:
        connected_wallets = 0

    try:
        rapid_movements = int(rapid_movements or 0)
    except Exception:
        rapid_movements = 0

    try:
        abnormal_alerts = int(abnormal_alerts or 0)
    except Exception:
        abnormal_alerts = 0

    try:
        fan_in = int(fan_in or 0)
    except Exception:
        fan_in = 0

    try:
        fan_out = int(fan_out or 0)
    except Exception:
        fan_out = 0

    try:
        max_hop = int(max_hop or 0)
    except Exception:
        max_hop = 0

    try:
        vasp_matches = int(vasp_matches or 0)
    except Exception:
        vasp_matches = 0

    try:
        token_transactions = int(token_transactions or 0)
    except Exception:
        token_transactions = 0

    try:
        token_types = int(token_types or 0)
    except Exception:
        token_types = 0


    # ========================================================
    # INDIVIDUAL RISK FACTORS
    # ========================================================

    # --------------------------------------------------------
    # 1. TRANSACTION ACTIVITY - MAX 10
    # --------------------------------------------------------

    if transaction_count >= 1000:
        transaction_score = 10

    elif transaction_count >= 500:
        transaction_score = 8

    elif transaction_count >= 100:
        transaction_score = 6

    elif transaction_count >= 50:
        transaction_score = 3

    else:
        transaction_score = 0


    # --------------------------------------------------------
    # 2. CONNECTED NETWORK - MAX 10
    # --------------------------------------------------------

    if connected_wallets >= 100:
        network_score = 10

    elif connected_wallets >= 50:
        network_score = 8

    elif connected_wallets >= 20:
        network_score = 6

    elif connected_wallets >= 10:
        network_score = 3

    else:
        network_score = 0


    # --------------------------------------------------------
    # 3. RAPID MOVEMENT - MAX 10
    # --------------------------------------------------------

    if rapid_movements >= 50:
        rapid_score = 10

    elif rapid_movements >= 20:
        rapid_score = 8

    elif rapid_movements >= 10:
        rapid_score = 6

    elif rapid_movements >= 5:
        rapid_score = 3

    else:
        rapid_score = 0


    # --------------------------------------------------------
    # 4. ABNORMAL ACTIVITY - MAX 15
    # --------------------------------------------------------

    if abnormal_alerts >= 50:
        abnormal_score = 15

    elif abnormal_alerts >= 20:
        abnormal_score = 12

    elif abnormal_alerts >= 10:
        abnormal_score = 8

    elif abnormal_alerts >= 5:
        abnormal_score = 5

    elif abnormal_alerts >= 1:
        abnormal_score = 2

    else:
        abnormal_score = 0


    # --------------------------------------------------------
    # 5. FAN-OUT - MAX 10
    # --------------------------------------------------------

    if fan_out >= 50:
        fanout_score = 10

    elif fan_out >= 20:
        fanout_score = 8

    elif fan_out >= 10:
        fanout_score = 6

    elif fan_out >= 5:
        fanout_score = 3

    else:
        fanout_score = 0


    # --------------------------------------------------------
    # 6. FAN-IN - MAX 10
    # --------------------------------------------------------

    if fan_in >= 50:
        fanin_score = 10

    elif fan_in >= 20:
        fanin_score = 8

    elif fan_in >= 10:
        fanin_score = 6

    elif fan_in >= 5:
        fanin_score = 3

    else:
        fanin_score = 0


    # --------------------------------------------------------
    # 7. MULTI-HOP - MAX 10
    # --------------------------------------------------------

    if max_hop >= 4:
        hop_score = 10

    elif max_hop >= 3:
        hop_score = 8

    elif max_hop >= 2:
        hop_score = 6

    elif max_hop >= 1:
        hop_score = 2

    else:
        hop_score = 0


    # --------------------------------------------------------
    # 8. TOKEN ACTIVITY - MAX 10
    # --------------------------------------------------------

    if token_transactions >= 500:
        token_score = 10

    elif token_transactions >= 200:
        token_score = 8

    elif token_transactions >= 100:
        token_score = 6

    elif token_transactions >= 50:
        token_score = 4

    elif token_transactions >= 10:
        token_score = 2

    else:
        token_score = 0


    # --------------------------------------------------------
    # 9. TOKEN DIVERSITY - MAX 5
    # --------------------------------------------------------

    if token_types >= 20:
        token_type_score = 5

    elif token_types >= 10:
        token_type_score = 4

    elif token_types >= 5:
        token_type_score = 3

    elif token_types >= 2:
        token_type_score = 1

    else:
        token_type_score = 0


    # --------------------------------------------------------
    # 10. VASP ASSOCIATION - MAX 10
    # --------------------------------------------------------

    if vasp_matches >= 5:
        vasp_score = 10

    elif vasp_matches >= 3:
        vasp_score = 8

    elif vasp_matches >= 2:
        vasp_score = 6

    elif vasp_matches >= 1:
        vasp_score = 4

    else:
        vasp_score = 0


    # ========================================================
    # EXPLAINABLE FACTOR DICTIONARY
    # ========================================================

    factors = {

        "Transaction Activity":
            transaction_score,

        "Connected Network":
            network_score,

        "Rapid Fund Movement":
            rapid_score,

        "Abnormal Activity":
            abnormal_score,

        "Fan-Out / Fund Splitting":
            fanout_score,

        "Fan-In / Fund Consolidation":
            fanin_score,

        "Multi-Hop Fund Flow":
            hop_score,

        "Token Activity":
            token_score,

        "Token Diversity":
            token_type_score,

        "Potential VASP Association":
            vasp_score
    }


    # ========================================================
    # TOTAL SCORE
    # ========================================================

    score = sum(
        factors.values()
    )

    # Safety clamp
    score = max(
        0,
        min(
            100,
            score
        )
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


    return (
        score,
        level,
        factors
    )


# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================

def calculate_risk(
    transaction_count=0,
    connected_wallets=0,
    rapid_transfers=False,
    abnormal_alerts=0,
    fan_in=0,
    fan_out=0,
    max_hop=0,
    vasp_matches=0,
    token_transactions=0,
    token_types=0
):
    """
    Backward-compatible wrapper.

    Older versions of CryptoShield may call calculate_risk().
    """

    # Convert old boolean rapid_transfers input
    if isinstance(
        rapid_transfers,
        bool
    ):

        rapid_movements = (
            5
            if rapid_transfers
            else 0
        )

    else:

        try:
            rapid_movements = int(
                rapid_transfers or 0
            )
        except Exception:
            rapid_movements = 0


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
