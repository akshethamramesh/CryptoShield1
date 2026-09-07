def calculate_threat_score(
    transactions,
    dna,
    abnormal_results
):

    score = 0
    factors = []

    # -----------------------------------------
    # HIGH OUTGOING ACTIVITY
    # -----------------------------------------

    outgoing = dna[
        "outgoing_transactions"
    ]

    if outgoing >= 10:

        score += 10

        factors.append(
            "High outgoing transaction activity"
        )

    # -----------------------------------------
    # RAPID ACTIVITY
    # -----------------------------------------

    if dna["rapid_activity"]:

        score += 20

        factors.append(
            "Rapid fund movement detected"
        )

    # -----------------------------------------
    # FUND SPLITTING
    # -----------------------------------------

    if dna["fund_splitting"]:

        score += 15

        factors.append(
            "Fund splitting behaviour detected"
        )

    # -----------------------------------------
    # MANY NEW DESTINATIONS
    # -----------------------------------------

    if dna["rare_recipients"] >= 3:

        score += 15

        factors.append(
            "Multiple rare/new destinations detected"
        )

    # -----------------------------------------
    # HIGH RECIPIENT DIVERSITY
    # -----------------------------------------

    if dna["unique_recipients"] >= 10:

        score += 10

        factors.append(
            "High recipient diversity"
        )

    # -----------------------------------------
    # ABNORMAL TRANSACTIONS
    # -----------------------------------------

    high_abnormal = [

        result

        for result in abnormal_results

        if result.get("score", 0) >= 50
    ]

    if high_abnormal:

        score += 20

        factors.append(
            "High-severity abnormal transactions detected"
        )

    # -----------------------------------------
    # DNA SCORE
    # -----------------------------------------

    if dna["dna_score"] >= 70:

        score += 10

        factors.append(
            "Strongly irregular transaction DNA"
        )

    score = min(
        score,
        100
    )

    # -----------------------------------------
    # THREAT LEVEL
    # -----------------------------------------

    if score >= 70:

        level = "HIGH"

    elif score >= 40:

        level = "MEDIUM"

    else:

        level = "LOW"

    return {

        "score": score,

        "level": level,

        "factors": factors
    }
