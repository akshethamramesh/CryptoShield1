from collections import Counter
from datetime import datetime


def analyze_transaction_dna(transactions, start_wallet):

    if not transactions:
        return {
            "transaction_count": 0,
            "native_transaction_count": 0,
            "token_transaction_count": 0,
            "native_volume": 0,
            "token_volume": 0,
            "average_native_transfer": 0,
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

    native_volume = 0
    token_volume = 0

    native_values = []
    token_values = []

    timestamps = []

    for tx in transactions:

        sender = tx.get("from", "").lower()
        receiver = tx.get("to", "").lower()

        if sender:
            senders[sender] += 1

        if receiver:
            receivers[receiver] += 1

        # ---------------------------------------------
        # Separate native and token transactions
        # ---------------------------------------------

        tx_type = tx.get("type", "native")

        try:
            value = float(tx.get("value", 0))
        except Exception:
            value = 0

        if tx_type == "token":

            token_volume += value
            token_values.append(value)

        else:

            native_volume += value
            native_values.append(value)

        # ---------------------------------------------
        # Timestamp
        # ---------------------------------------------

        try:

            timestamp = int(
                tx.get(
                    "timeStamp",
                    0
                )
            )

            if timestamp:
                timestamps.append(timestamp)

        except Exception:
            pass

    # ---------------------------------------------
    # Basic metrics
    # ---------------------------------------------

    transaction_count = len(transactions)

    native_transaction_count = sum(
        1
        for tx in transactions
        if tx.get("type", "native") != "token"
    )

    token_transaction_count = sum(
        1
        for tx in transactions
        if tx.get("type", "native") == "token"
    )

    average_native_transfer = (
        native_volume / len(native_values)
        if native_values
        else 0
    )

    # ---------------------------------------------
    # Fan in / Fan out
    # ---------------------------------------------

    outgoing = set()
    incoming = set()

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        if (
            sender == start_wallet
            and receiver
        ):

            outgoing.add(receiver)

        if (
            receiver == start_wallet
            and sender
        ):

            incoming.add(sender)

    fan_out = len(outgoing)
    fan_in = len(incoming)

    # ---------------------------------------------
    # Rapid movement
    #
    # Only compare transactions involving the
    # same wallet relationship instead of blindly
    # comparing the entire dataset.
    # ---------------------------------------------

    wallet_times = {}

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        try:

            timestamp = int(
                tx.get(
                    "timeStamp",
                    0
                )
            )

        except Exception:

            timestamp = 0

        if not timestamp:
            continue

        # Track activity by sender wallet

        if sender:

            wallet_times.setdefault(
                sender,
                []
            ).append(timestamp)

        # Track activity by receiver wallet

        if receiver:

            wallet_times.setdefault(
                receiver,
                []
            ).append(timestamp)

    rapid_movements = 0

    for wallet, times in wallet_times.items():

        times.sort()

        for i in range(1, len(times)):

            difference = (
                times[i] -
                times[i - 1]
            )

            if 0 < difference <= 300:

                rapid_movements += 1

    # ---------------------------------------------
    # Active hours
    # ---------------------------------------------

    active_hours = Counter()

    for timestamp in timestamps:

        try:

            hour = datetime.fromtimestamp(
                timestamp
            ).hour

            active_hours[hour] += 1

        except Exception:
            pass

    # ---------------------------------------------
    # Behavioral indicators
    # ---------------------------------------------

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

    if (
        native_values
        and average_native_transfer > 5
    ):

        indicators.append(
            "High average native-asset transfer value"
        )

    if token_transaction_count >= 50:

        indicators.append(
            "Significant token transfer activity"
        )

    return {

        "transaction_count":
            transaction_count,

        "native_transaction_count":
            native_transaction_count,

        "token_transaction_count":
            token_transaction_count,

        "native_volume":
            native_volume,

        "token_volume":
            token_volume,

        "average_native_transfer":
            average_native_transfer,

        # Keep old key for compatibility
        "average_transfer":
            average_native_transfer,

        # Keep old key for compatibility
        "total_volume":
            native_volume,

        "unique_senders":
            len(senders),

        "unique_receivers":
            len(receivers),

        "fan_in":
            fan_in,

        "fan_out":
            fan_out,

        "rapid_movements":
            rapid_movements,

        "active_hours":
            dict(active_hours),

        "behavior_indicators":
            indicators
    }
