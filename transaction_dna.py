from collections import Counter
from datetime import datetime


def parse_timestamp(timestamp):

    if not timestamp:
        return None

    try:

        if isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp)

        return datetime.fromisoformat(
            str(timestamp).replace("Z", "+00:00")
        )

    except Exception:
        return None


def calculate_transaction_dna(transactions, wallet):

    wallet = wallet.lower()

    incoming = []
    outgoing = []

    recipients = []
    senders = []

    timestamps = []

    # -----------------------------------------
    # COLLECT DATA
    # -----------------------------------------

    for tx in transactions:

        sender = str(
            tx.get("from", "")
        ).lower()

        receiver = str(
            tx.get("to", "")
        ).lower()

        try:
            value = float(tx.get("value", 0))
        except:
            value = 0

        # Ignore zero-value transactions
        # for financial behaviour analysis
        if value <= 0:
            continue

        if sender == wallet:

            outgoing.append(tx)

            if receiver:
                recipients.append(receiver)

        if receiver == wallet:

            incoming.append(tx)

            if sender:
                senders.append(sender)

        timestamp = parse_timestamp(
            tx.get("timestamp")
        )

        if timestamp:
            timestamps.append(timestamp)

    # -----------------------------------------
    # COUNTS
    # -----------------------------------------

    total_transactions = (
        len(incoming) +
        len(outgoing)
    )

    unique_recipients = len(
        set(recipients)
    )

    unique_senders = len(
        set(senders)
    )

    # -----------------------------------------
    # AMOUNTS
    # -----------------------------------------

    amounts = []

    for tx in outgoing:

        try:

            value = float(
                tx.get("value", 0)
            )

            if value > 0:
                amounts.append(value)

        except:
            pass

    if amounts:

        average_amount = (
            sum(amounts) /
            len(amounts)
        )

        maximum_amount = max(amounts)

    else:

        average_amount = 0
        maximum_amount = 0

    # -----------------------------------------
    # TIME ANALYSIS
    # -----------------------------------------

    timestamps.sort()

    time_gaps = []

    for i in range(
        1,
        len(timestamps)
    ):

        gap = (
            timestamps[i] -
            timestamps[i - 1]
        ).total_seconds()

        if gap >= 0:
            time_gaps.append(gap)

    if time_gaps:

        average_time_gap = (
            sum(time_gaps) /
            len(time_gaps)
        )

    else:

        average_time_gap = 0

    # -----------------------------------------
    # RAPID ACTIVITY
    # -----------------------------------------

    rapid_activity = False

    for i in range(
        len(timestamps)
    ):

        count = 1

        for j in range(
            i + 1,
            len(timestamps)
        ):

            difference = (
                timestamps[j] -
                timestamps[i]
            ).total_seconds()

            if difference <= 60:
                count += 1
            else:
                break

        if count >= 3:

            rapid_activity = True
            break

    # -----------------------------------------
    # RARE DESTINATIONS
    # -----------------------------------------

    recipient_counts = Counter(
        recipients
    )

    rare_recipients = [

        address

        for address, count
        in recipient_counts.items()

        if count == 1
    ]

    # -----------------------------------------
    # FUND SPLITTING
    # -----------------------------------------

    fund_splitting = (
        len(set(recipients)) >= 3
    )

    # -----------------------------------------
    # FUND CONSOLIDATION
    # -----------------------------------------

    fund_consolidation = (
        len(set(senders)) >= 3
    )

    # -----------------------------------------
    # ACTIVITY LEVEL
    # -----------------------------------------

    if total_transactions >= 100:

        activity_level = "VERY HIGH"

    elif total_transactions >= 50:

        activity_level = "HIGH"

    elif total_transactions >= 20:

        activity_level = "MEDIUM"

    else:

        activity_level = "LOW"

    # -----------------------------------------
    # RECIPIENT PATTERN
    # -----------------------------------------

    if unique_recipients >= 20:

        recipient_pattern = "VERY HIGH"

    elif unique_recipients >= 10:

        recipient_pattern = "HIGH"

    elif unique_recipients >= 5:

        recipient_pattern = "MEDIUM"

    else:

        recipient_pattern = "LOW"

    # -----------------------------------------
    # BEHAVIOUR SIGNALS
    # -----------------------------------------

    behaviour_signals = []

    if rapid_activity:

        behaviour_signals.append(
            "Rapid transaction activity"
        )

    if fund_splitting:

        behaviour_signals.append(
            "Fund splitting behaviour"
        )

    if fund_consolidation:

        behaviour_signals.append(
            "Fund consolidation behaviour"
        )

    if len(rare_recipients) >= 3:

        behaviour_signals.append(
            "Multiple rare destinations"
        )

    if unique_recipients >= 10:

        behaviour_signals.append(
            "High recipient diversity"
        )

    # -----------------------------------------
    # DNA SCORE
    # -----------------------------------------

    dna_score = 0

    if rapid_activity:
        dna_score += 25

    if fund_splitting:
        dna_score += 20

    if fund_consolidation:
        dna_score += 15

    if len(rare_recipients) >= 3:
        dna_score += 15

    if unique_recipients >= 10:
        dna_score += 15

    if total_transactions >= 100:
        dna_score += 10

    dna_score = min(
        dna_score,
        100
    )

    # -----------------------------------------
    # PROFILE
    # -----------------------------------------

    if dna_score >= 70:

        behaviour_profile = (
            "High-activity distribution pattern"
        )

    elif dna_score >= 40:

        behaviour_profile = (
            "Moderately irregular "
            "transaction pattern"
        )

    else:

        behaviour_profile = (
            "Relatively stable "
            "transaction pattern"
        )

    return {

        "wallet": wallet,

        "total_transactions":
            total_transactions,

        "incoming_transactions":
            len(incoming),

        "outgoing_transactions":
            len(outgoing),

        "unique_senders":
            unique_senders,

        "unique_recipients":
            unique_recipients,

        "average_amount":
            round(
                average_amount,
                6
            ),

        "maximum_amount":
            round(
                maximum_amount,
                6
            ),

        "average_time_gap_seconds":
            round(
                average_time_gap,
                2
            ),

        "rare_recipients":
            len(rare_recipients),

        "rapid_activity":
            rapid_activity,

        "fund_splitting":
            fund_splitting,

        "fund_consolidation":
            fund_consolidation,

        "activity_level":
            activity_level,

        "recipient_pattern":
            recipient_pattern,

        "behaviour_signals":
            behaviour_signals,

        "dna_score":
            dna_score,

        "behaviour_profile":
            behaviour_profile
    }
