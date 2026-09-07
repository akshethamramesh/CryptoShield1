from collections import Counter


def detect_abnormal_transactions(transactions):
    """
    Detect potentially abnormal transaction patterns.

    This is an investigation-support rule engine.
    It does NOT determine criminal activity.
    """

    if not transactions:
        return []

    alerts = []

    # --------------------------------------------
    # Count destinations
    # --------------------------------------------

    destination_counts = Counter()

    for tx in transactions:

        destination = tx.get("to", "").lower()

        if destination:
            destination_counts[destination] += 1

    # --------------------------------------------
    # Calculate average transaction value
    # --------------------------------------------

    values = []

    for tx in transactions:

        try:
            value = float(tx.get("value", 0))
        except (TypeError, ValueError):
            value = 0

        if value > 0:
            values.append(value)

    average_value = (
        sum(values) / len(values)
        if values
        else 0
    )

    # --------------------------------------------
    # Check transactions
    # --------------------------------------------

    for index, tx in enumerate(transactions):

        try:
            value = float(tx.get("value", 0))
        except (TypeError, ValueError):
            value = 0

        tx_hash = tx.get(
            "hash",
            f"transaction_{index + 1}"
        )

        destination = tx.get(
            "to",
            ""
        )

        score = 0
        reasons = []

        # ----------------------------------------
        # Large transaction
        # ----------------------------------------

        if (
            average_value > 0
            and value >= average_value * 5
        ):

            score += 30

            reasons.append(
                "Transaction value is significantly "
                "higher than the wallet average"
            )

        # ----------------------------------------
        # Rare destination
        # ----------------------------------------

        if (
            destination
            and destination_counts[
                destination.lower()
            ] == 1
        ):

            score += 10

            reasons.append(
                "Destination appears only once"
            )

        # ----------------------------------------
        # Rapid movement
        # ----------------------------------------

        current_timestamp = tx.get(
            "timestamp"
        )

        if current_timestamp:

            try:
                current_time = int(
                    current_timestamp
                )
            except (TypeError, ValueError):
                current_time = None

            if current_time is not None:

                rapid_count = 0

                for other_tx in transactions:

                    other_timestamp = other_tx.get(
                        "timestamp"
                    )

                    if not other_timestamp:
                        continue

                    try:
                        other_time = int(
                            other_timestamp
                        )
                    except (
                        TypeError,
                        ValueError
                    ):
                        continue

                    if (
                        other_time != current_time
                        and abs(
                            other_time
                            - current_time
                        ) <= 60
                    ):

                        rapid_count += 1

                if rapid_count >= 2:

                    score += 30

                    reasons.append(
                        "Multiple transactions "
                        "occurred within a short time window"
                    )

        # ----------------------------------------
        # Create alert
        # ----------------------------------------

        if score >= 20:

            alerts.append({
                "hash": tx_hash,
                "tx_hash": tx_hash,
                "value": value,
                "score": score,
                "reason": "; ".join(
                    reasons
                ),
                "from": tx.get(
                    "from",
                    ""
                ),
                "to": destination
            })

    # --------------------------------------------
    # Sort highest risk first
    # --------------------------------------------

    alerts.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return alerts


# ------------------------------------------------
# Compatibility aliases
# ------------------------------------------------

def detect_abnormal(transactions):
    return detect_abnormal_transactions(
        transactions
    )


def analyze_transactions(transactions):
    return detect_abnormal_transactions(
        transactions
    )
