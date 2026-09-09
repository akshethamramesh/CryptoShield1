from collections import Counter


# ============================================================
# ADDRESS NORMALIZATION
# ============================================================

def normalize_address(address):

    if not address:
        return ""

    return address.strip().lower()


# ============================================================
# SAFE FLOAT
# ============================================================

def safe_float(value):

    try:
        return float(value)

    except Exception:
        return 0.0


# ============================================================
# SAFE INT
# ============================================================

def safe_int(value):

    try:
        return int(value)

    except Exception:
        return 0


# ============================================================
# BUILD WALLET TRANSACTION MAP
# ============================================================

def build_wallet_transaction_map(
    transactions
):

    wallet_transactions = {}

    for tx in transactions:

        sender = normalize_address(
            tx.get(
                "from",
                ""
            )
        )

        receiver = normalize_address(
            tx.get(
                "to",
                ""
            )
        )

        participants = set()

        if sender:
            participants.add(
                sender
            )

        if receiver:
            participants.add(
                receiver
            )

        for wallet in participants:

            wallet_transactions.setdefault(
                wallet,
                []
            ).append(tx)

    return wallet_transactions


# ============================================================
# CALCULATE WALLET FEATURES
# ============================================================

def calculate_wallet_features(
    wallet,
    transactions,
    wallet_hops
):

    wallet = normalize_address(
        wallet
    )

    incoming = 0
    outgoing = 0

    incoming_wallets = set()
    outgoing_wallets = set()

    destinations = set()
    sources = set()

    timestamps = []

    abnormal_large_count = 0

    total_value = 0.0

    for tx in transactions:

        sender = normalize_address(
            tx.get(
                "from",
                ""
            )
        )

        receiver = normalize_address(
            tx.get(
                "to",
                ""
            )
        )

        value = safe_float(
            tx.get(
                "value",
                0
            )
        )

        total_value += value

        # ----------------------------------------------------
        # Incoming
        # ----------------------------------------------------

        if receiver == wallet:

            incoming += 1

            if sender and sender != wallet:

                incoming_wallets.add(
                    sender
                )

                sources.add(
                    sender
                )

        # ----------------------------------------------------
        # Outgoing
        # ----------------------------------------------------

        if sender == wallet:

            outgoing += 1

            if receiver and receiver != wallet:

                outgoing_wallets.add(
                    receiver
                )

                destinations.add(
                    receiver
                )

        # ----------------------------------------------------
        # Timestamp
        # ----------------------------------------------------

        timestamp = safe_int(
            tx.get(
                "timeStamp",
                0
            )
        )

        if timestamp:

            timestamps.append(
                timestamp
            )

        # ----------------------------------------------------
        # Large transfer indicator
        # ----------------------------------------------------

        if value >= 5:

            abnormal_large_count += 1

    # ========================================================
    # RAPID MOVEMENTS
    # ========================================================

    timestamps.sort()

    rapid_movements = 0

    for i in range(
        1,
        len(timestamps)
    ):

        difference = (
            timestamps[i]
            -
            timestamps[i - 1]
        )

        if (
            difference > 0
            and difference <= 300
        ):

            rapid_movements += 1

    # ========================================================
    # FAN IN / FAN OUT
    # ========================================================

    fan_in = len(
        incoming_wallets
    )

    fan_out = len(
        outgoing_wallets
    )

    # ========================================================
    # HOP
    # ========================================================

    hop = wallet_hops.get(
        wallet,
        0
    )

    # ========================================================
    # FEATURE RESULT
    # ========================================================

    return {

        "wallet":
            wallet,

        "hop":
            hop,

        "transaction_count":
            len(transactions),

        "incoming_transactions":
            incoming,

        "outgoing_transactions":
            outgoing,

        "incoming_wallets":
            fan_in,

        "outgoing_wallets":
            fan_out,

        "fan_in":
            fan_in,

        "fan_out":
            fan_out,

        "rapid_movements":
            rapid_movements,

        "large_transfers":
            abnormal_large_count,

        "total_value":
            total_value,

        "connected_wallets":
            len(
                incoming_wallets
                |
                outgoing_wallets
            )
    }


# ============================================================
# WALLET RISK SCORE
# ============================================================

def calculate_wallet_risk(
    features
):

    score = 0

    reasons = []

    # --------------------------------------------------------
    # Transaction activity
    # --------------------------------------------------------

    transaction_count = features[
        "transaction_count"
    ]

    if transaction_count >= 100:

        score += 20

        reasons.append(
            "High transaction activity"
        )

    elif transaction_count >= 50:

        score += 10

        reasons.append(
            "Elevated transaction activity"
        )

    # --------------------------------------------------------
    # Connected wallets
    # --------------------------------------------------------

    connected_wallets = features[
        "connected_wallets"
    ]

    if connected_wallets >= 20:

        score += 20

        reasons.append(
            "High number of connected wallets"
        )

    elif connected_wallets >= 10:

        score += 10

        reasons.append(
            "Multiple connected wallets"
        )

    # --------------------------------------------------------
    # Fan-out
    # --------------------------------------------------------

    fan_out = features[
        "fan_out"
    ]

    if fan_out >= 10:

        score += 15

        reasons.append(
            "High fan-out: funds moved to many destinations"
        )

    elif fan_out >= 5:

        score += 10

        reasons.append(
            "Multiple outgoing destinations"
        )

    # --------------------------------------------------------
    # Fan-in
    # --------------------------------------------------------

    fan_in = features[
        "fan_in"
    ]

    if fan_in >= 10:

        score += 15

        reasons.append(
            "High fan-in: funds received from many sources"
        )

    elif fan_in >= 5:

        score += 10

        reasons.append(
            "Multiple incoming sources"
        )

    # --------------------------------------------------------
    # Rapid movements
    # --------------------------------------------------------

    rapid_movements = features[
        "rapid_movements"
    ]

    if rapid_movements >= 10:

        score += 20

        reasons.append(
            "Frequent rapid fund movements"
        )

    elif rapid_movements >= 5:

        score += 15

        reasons.append(
            "Rapid fund movement detected"
        )

    elif rapid_movements >= 2:

        score += 5

        reasons.append(
            "Some rapid fund movements"
        )

    # --------------------------------------------------------
    # Large transfers
    # --------------------------------------------------------

    large_transfers = features[
        "large_transfers"
    ]

    if large_transfers >= 10:

        score += 10

        reasons.append(
            "Repeated large-value transfers"
        )

    elif large_transfers >= 5:

        score += 5

        reasons.append(
            "Multiple large-value transfers"
        )

    # --------------------------------------------------------
    # Multi-hop
    # --------------------------------------------------------

    hop = features[
        "hop"
    ]

    if hop >= 2:

        score += 10

        reasons.append(
            "Wallet observed in deeper tracing hop"
        )

    # --------------------------------------------------------
    # Cap score
    # --------------------------------------------------------

    score = min(
        score,
        100
    )

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    if score >= 70:

        level = "HIGH"

    elif score >= 40:

        level = "MEDIUM"

    else:

        level = "LOW"

    # --------------------------------------------------------
    # Default reason
    # --------------------------------------------------------

    if not reasons:

        reasons.append(
            "No strong predefined risk indicators"
        )

    return score, level, reasons


# ============================================================
# ANALYSE ALL DISCOVERED WALLETS
# ============================================================

def analyze_suspicious_wallets(
    transactions,
    wallet_hops,
    reported_wallet
):

    reported_wallet = normalize_address(
        reported_wallet
    )

    wallet_transaction_map = (
        build_wallet_transaction_map(
            transactions
        )
    )

    results = []

    # --------------------------------------------------------
    # Analyse every discovered wallet
    # --------------------------------------------------------

    for wallet, wallet_txs in (
        wallet_transaction_map.items()
    ):

        wallet = normalize_address(
            wallet
        )

        # Do not rank the original reported wallet
        if wallet == reported_wallet:

            continue

        features = calculate_wallet_features(
            wallet,
            wallet_txs,
            wallet_hops
        )

        score, level, reasons = (
            calculate_wallet_risk(
                features
            )
        )

        result = {

            **features,

            "risk_score":
                score,

            "risk_level":
                level,

            "reasons":
                reasons
        }

        results.append(
            result
        )

    # --------------------------------------------------------
    # Sort highest risk first
    # --------------------------------------------------------

    results.sort(
        key=lambda item:
            item.get(
                "risk_score",
                0
            ),
        reverse=True
    )

    # --------------------------------------------------------
    # Assign ranking
    # --------------------------------------------------------

    for index, result in enumerate(
        results,
        start=1
    ):

        result[
            "rank"
        ] = index

    return results


# ============================================================
# TOP 5
# ============================================================

def get_top_suspicious_wallets(
    transactions,
    wallet_hops,
    reported_wallet,
    limit=5
):

    results = analyze_suspicious_wallets(
        transactions,
        wallet_hops,
        reported_wallet
    )

    return results[
        :limit
    ]
