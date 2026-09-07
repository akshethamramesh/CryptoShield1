from collections import Counter


def detect_abnormal_transactions(transactions):

    if not transactions:
        return []

    alerts = []

    # Count destinations
    destinations = Counter()

    for tx in transactions:
        destination = tx.get("to", "")
        if destination:
            destinations[destination] += 1

    for tx in transactions:

        score = 0
        reasons = []

        try:
            value = float(tx.get("value", 0))
        except:
            value = 0

        destination = tx.get("to", "")

        # Large transaction
        if value >= 5:
            score += 30
            reasons.append("Large transaction")

        # Rare destination
        if destination and destinations[destination] == 1:
            score += 10
            reasons.append("Rare destination")

        # Timestamp available
        if tx.get("timestamp"):
            score += 5

        if score >= 20:

            alerts.append({
                "hash": tx.get("hash", "Unknown"),
                "from": tx.get("from", "Unknown"),
                "to": tx.get("to", "Unknown"),
                "value": value,
                "asset": tx.get("asset", "ETH"),
                "score": score,
                "reason": ", ".join(reasons)
            })

    alerts.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return alerts


def detect_abnormal(transactions):
    return detect_abnormal_transactions(transactions)


def analyze_transactions(transactions):
    return detect_abnormal_transactions(transactions)
