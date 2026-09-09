from collections import Counter


def detect_abnormal_transactions(transactions):

    if not transactions:
        return []

    destination_counts = Counter(
        tx.get("to", "").lower()
        for tx in transactions
        if tx.get("to")
    )

    timestamps = []

    for tx in transactions:

        try:
            timestamps.append(
                int(tx.get("timeStamp", 0))
            )
        except Exception:
            timestamps.append(0)

    alerts = []

    for index, tx in enumerate(transactions):

        score = 0
        reasons = []

        try:
            value = float(
                tx.get("value", 0)
            )
        except Exception:
            value = 0

        if value >= 5:

            score += 30

            reasons.append(
                "Large value transfer"
            )

        receiver = tx.get(
            "to",
            ""
        ).lower()

        if receiver and destination_counts[receiver] <= 1:

            score += 10

            reasons.append(
                "Rare destination"
            )

        current_time = timestamps[index]

        if index > 0:

            previous_time = timestamps[index - 1]

            if (
                current_time
                and previous_time
                and abs(
                    current_time - previous_time
                ) <= 300
            ):

                score += 30

                reasons.append(
                    "Rapid fund movement"
                )

        if score >= 20:

            alerts.append(
                {
                    "hash": tx.get(
                        "hash",
                        "Unknown"
                    ),
                    "score": score,
                    "reason": ", ".join(reasons)
                }
            )

    alerts.sort(
        key=lambda x: x.get("score", 0),
        reverse=True
    )

    return alerts


def detect_abnormal(transactions):
    return detect_abnormal_transactions(
        transactions
    )


def analyze_transactions(transactions):
    return detect_abnormal_transactions(
        transactions
    )
