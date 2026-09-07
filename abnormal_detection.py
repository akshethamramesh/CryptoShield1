from datetime import datetime


def parse_timestamp(timestamp):

    if not timestamp:
        return None

    try:

        return datetime.fromisoformat(
            timestamp.replace(
                "Z",
                "+00:00"
            )
        )

    except:

        return None


def analyze_abnormal_transactions(
    transactions
):

    if not transactions:
        return []

    # Only financial transactions
    financial_transactions = []

    for tx in transactions:

        try:
            value = float(
                tx.get("value", 0)
            )
        except:
            value = 0

        if value > 0:
            financial_transactions.append(
                tx
            )

    if not financial_transactions:
        return []

    # Average value
    values = []

    for tx in financial_transactions:

        try:
            values.append(
                float(
                    tx.get(
                        "value",
                        0
                    )
                )
            )
        except:
            pass

    if not values:
        return []

    average_value = (
        sum(values) / len(values)
    )

    # Destination frequency
    destination_count = {}

    for tx in financial_transactions:

        destination = tx.get(
            "to",
            ""
        ).lower()

        if destination:

            destination_count[
                destination
            ] = (
                destination_count.get(
                    destination,
                    0
                ) + 1
            )

    # Rapid transactions
    timestamped = []

    for tx in financial_transactions:

        timestamp = parse_timestamp(
            tx.get(
                "timestamp",
                ""
            )
        )

        if timestamp:

            timestamped.append(
                (
                    timestamp,
                    tx
                )
            )

    timestamped.sort(
        key=lambda x: x[0]
    )

    rapid_hashes = set()

    for i in range(
        len(timestamped)
    ):

        start_time = (
            timestamped[i][0]
        )

        window_count = 1

        for j in range(
            i + 1,
            len(timestamped)
        ):

            difference = (
                timestamped[j][0]
                - start_time
            ).total_seconds()

            if difference <= 60:

                window_count += 1

                if window_count >= 3:

                    rapid_hashes.add(
                        timestamped[i][1].get(
                            "hash"
                        )
                    )

                    rapid_hashes.add(
                        timestamped[j][1].get(
                            "hash"
                        )
                    )

            else:

                break

    alerts = []

    seen_hashes = set()

    for tx in financial_transactions:

        tx_hash = tx.get(
            "hash",
            ""
        )

        if tx_hash in seen_hashes:
            continue

        value = float(
            tx.get(
                "value",
                0
            )
        )

        destination = tx.get(
            "to",
            ""
        ).lower()

        score = 0

        reasons = []

        # Large transaction
        if (
            average_value > 0
            and value >= average_value * 5
        ):

            score += 30

            reasons.append(
                "Transaction value is significantly above wallet average"
            )

        # Rare destination
        if (
            destination
            and destination_count.get(
                destination,
                0
            ) == 1
        ):

            score += 10

            reasons.append(
                "Destination appears only once in observed financial activity"
            )

        # Rapid movement
        if tx_hash in rapid_hashes:

            score += 30

            reasons.append(
                "Multiple transactions detected within 60 seconds"
            )

        if score >= 20:

            alerts.append(
                {
                    "hash": tx_hash,
                    "from": tx.get(
                        "from",
                        ""
                    ),
                    "to": tx.get(
                        "to",
                        ""
                    ),
                    "value": value,
                    "asset": tx.get(
                        "asset",
                        "ETH"
                    ),
                    "timestamp": tx.get(
                        "timestamp",
                        ""
                    ),
                    "score": score,
                    "reasons": reasons
                }
            )

            seen_hashes.add(
                tx_hash
            )

    alerts.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return alerts
