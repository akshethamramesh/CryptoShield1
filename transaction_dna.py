from collections import Counter
from datetime import datetime


def analyze_transaction_dna(transactions, start_wallet):
    """
    Generates a behavioral profile for a wallet based on
    the transactions collected by CryptoShield.
    """

    if not transactions:
        return {
            "transaction_count": 0,
            "average_transfer": 0,
            "total_volume": 0,
            "unique_senders": 0,
            "unique_receivers": 0,
            "fan_in": 0,
            "fan_out": 0,
            "rapid_movements": 0,
            "active_hours": {},
            "behavior_indicators": []
        }

    start_wallet = start_wallet.lower()

    senders = Counter()
    receivers = Counter()

    total_volume = 0
    valid_values = []

    timestamps = []

    for tx in transactions:

        sender = tx.get("from", "").lower()
        receiver = tx.get("to", "").lower()

        if sender:
            senders[sender] += 1

        if receiver:
            receivers[receiver] += 1

        try:
            value = float(tx.get("value", 0))
        except:
            value = 0

        if value > 0:
            total_volume += value
            valid_values.append(value)

        try:
            timestamp = int(tx.get("timeStamp", 0))
            if timestamp:
                timestamps.append(timestamp)
        except:
            pass

    transaction_count = len(transactions)

    average_transfer = (
        total_volume / len(valid_values)
        if valid_values
        else 0
    )

    # Wallet-specific connections
    outgoing = set()
    incoming = set()

    for tx in transactions:

        sender = tx.get("from", "").lower()
        receiver = tx.get("to", "").lower()

        if sender == start_wallet and receiver:
            outgoing.add(receiver)

        if receiver == start_wallet and sender:
            incoming.add(sender)

    fan_out = len(outgoing)
    fan_in = len(incoming)

    # Rapid movement detection
    timestamps.sort()

    rapid_movements = 0

    for i in range(1, len(timestamps)):
        if timestamps[i] - timestamps[i - 1] <= 300:
            rapid_movements += 1

    # Active hours
    active_hours = Counter()

    for timestamp in timestamps:
        try:
            hour = datetime.fromtimestamp(timestamp).hour
            active_hours[hour] += 1
        except:
            pass

    # Behavioral indicators
    indicators = []

    if fan_out >= 5:
        indicators.append(
            "High fan-out: funds moved to multiple destinations"
        )

    if fan_in >= 5:
        indicators.append(
            "High fan-in: funds received from multiple sources"
        )

    if rapid_movements >= 5:
        indicators.append(
            "Rapid fund movement detected"
        )

    if transaction_count >= 100:
        indicators.append(
            "High transaction activity"
        )

    if len(valid_values) >= 5 and average_transfer > 5:
        indicators.append(
            "High average transfer value"
        )

    return {
        "transaction_count": transaction_count,
        "average_transfer": average_transfer,
        "total_volume": total_volume,
        "unique_senders": len(senders),
        "unique_receivers": len(receivers),
        "fan_in": fan_in,
        "fan_out": fan_out,
        "rapid_movements": rapid_movements,
        "active_hours": dict(active_hours),
        "behavior_indicators": indicators
    }
