from collections import Counter


def calculate_confidence(score):
    if score >= 80:
        return "High"
    elif score >= 60:
        return "Medium"
    else:
        return "Low"


def detect_fraud_patterns(
    transactions,
    trace_data,
    dna,
    abnormal
):
    """
    Explainable fraud-linked behaviour detection.

    This detects blockchain behaviour patterns.
    It does NOT prove criminal activity.
    """

    findings = []
    total_score = 0

    transaction_count = dna.get("transaction_count", 0)
    fan_in = dna.get("fan_in", 0)
    fan_out = dna.get("fan_out", 0)
    rapid_movements = dna.get("rapid_movements", 0)

    max_hop = trace_data.get("max_hop", 0)
    connected_wallets = len(
        trace_data.get("visited_wallets", [])
    )

    token_count = trace_data.get(
        "token_count",
        0
    )

    abnormal_count = len(abnormal)

    # --------------------------------------------------------
    # 1. FUND SPLITTING
    # --------------------------------------------------------

    if fan_out >= 5:

        strength = min(
            20,
            10 + (fan_out - 5)
        )

        total_score += strength

        findings.append({
            "type": "Fund Splitting",
            "category": "Distribution Pattern",
            "score": strength,
            "confidence": calculate_confidence(strength * 5),
            "evidence": (
                f"The reported wallet interacted with "
                f"{fan_out} outgoing destinations."
            )
        })

    # --------------------------------------------------------
    # 2. FUND CONSOLIDATION
    # --------------------------------------------------------

    if fan_in >= 5:

        strength = min(
            20,
            10 + (fan_in - 5)
        )

        total_score += strength

        findings.append({
            "type": "Fund Consolidation",
            "category": "Collection Pattern",
            "score": strength,
            "confidence": calculate_confidence(strength * 5),
            "evidence": (
                f"The reported wallet received funds from "
                f"{fan_in} incoming sources."
            )
        })

    # --------------------------------------------------------
    # 3. RAPID MOVEMENT
    # --------------------------------------------------------

    if rapid_movements >= 5:

        strength = 15

        if rapid_movements >= 20:
            strength = 20

        total_score += strength

        findings.append({
            "type": "Rapid Fund Movement",
            "category": "Temporal Pattern",
            "score": strength,
            "confidence": calculate_confidence(strength * 5),
            "evidence": (
                f"{rapid_movements} rapid movement events "
                f"were detected within short time intervals."
            )
        })

    # --------------------------------------------------------
    # 4. MULTI-HOP FLOW
    # --------------------------------------------------------

    if max_hop >= 2:

        strength = min(
            20,
            10 + ((max_hop - 2) * 5)
        )

        total_score += strength

        findings.append({
            "type": "Multi-Hop Fund Flow",
            "category": "Network Pattern",
            "score": strength,
            "confidence": calculate_confidence(strength * 5),
            "evidence": (
                f"Funds were observed across up to "
                f"{max_hop} wallet hops."
            )
        })

    # --------------------------------------------------------
    # 5. HIGH NETWORK CONNECTIVITY
    # --------------------------------------------------------

    if connected_wallets >= 20:

        strength = 10

        total_score += strength

        findings.append({
            "type": "High Wallet Connectivity",
            "category": "Network Pattern",
            "score": strength,
            "confidence": "Medium",
            "evidence": (
                f"{connected_wallets} wallets were observed "
                f"within the investigation network."
            )
        })

    # --------------------------------------------------------
    # 6. ABNORMAL TRANSACTIONS
    # --------------------------------------------------------

    if abnormal_count >= 5:

        strength = 10

        if abnormal_count >= 20:
            strength = 15

        total_score += strength

        findings.append({
            "type": "Abnormal Transaction Activity",
            "category": "Transaction Pattern",
            "score": strength,
            "confidence": calculate_confidence(strength * 5),
            "evidence": (
                f"{abnormal_count} transactions triggered "
                f"the current anomaly rules."
            )
        })

    # --------------------------------------------------------
    # 7. HIGH TRANSACTION ACTIVITY
    # --------------------------------------------------------

    if transaction_count >= 100:

        strength = 5

        if transaction_count >= 1000:
            strength = 10

        total_score += strength

        findings.append({
            "type": "High Transaction Activity",
            "category": "Activity Pattern",
            "score": strength,
            "confidence": "Medium",
            "evidence": (
                f"{transaction_count} blockchain transactions "
                f"were observed."
            )
        })

    # --------------------------------------------------------
    # 8. TOKEN ACTIVITY
    # --------------------------------------------------------

    if token_count >= 50:

        strength = 5

        total_score += strength

        findings.append({
            "type": "Significant Token Activity",
            "category": "Asset Pattern",
            "score": strength,
            "confidence": "Low",
            "evidence": (
                f"{token_count} token transfers were observed."
            )
        })

    # --------------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------------

    # Cap at 100
    fraud_score = min(
        100,
        total_score
    )

    if fraud_score >= 70:

        fraud_level = "HIGH"

    elif fraud_score >= 40:

        fraud_level = "MEDIUM"

    else:

        fraud_level = "LOW"

    # --------------------------------------------------------
    # COMBINED BEHAVIOUR
    # --------------------------------------------------------

    pattern_names = [
        item["type"]
        for item in findings
    ]

    if (
        "Fund Splitting" in pattern_names
        and
        "Rapid Fund Movement" in pattern_names
    ):

        findings.append({
            "type": "Coordinated Suspicious Behaviour",
            "category": "Combined Indicator",
            "score": 10,
            "confidence": "High",
            "evidence": (
                "Fund splitting and rapid movement "
                "were observed together."
            )
        })

        fraud_score = min(
            100,
            fraud_score + 10
        )

    if (
        "Multi-Hop Fund Flow" in pattern_names
        and
        "Abnormal Transaction Activity" in pattern_names
    ):

        findings.append({
            "type": "Layered Fund Movement",
            "category": "Combined Indicator",
            "score": 10,
            "confidence": "High",
            "evidence": (
                "Multi-hop movement and abnormal "
                "transaction activity were observed together."
            )
        })

        fraud_score = min(
            100,
            fraud_score + 10
        )

    # Recalculate level after combined indicators
    if fraud_score >= 70:

        fraud_level = "HIGH"

    elif fraud_score >= 40:

        fraud_level = "MEDIUM"

    else:

        fraud_level = "LOW"

    return {
        "fraud_score": fraud_score,
        "fraud_level": fraud_level,
        "patterns": findings,
        "pattern_count": len(findings)
    }
