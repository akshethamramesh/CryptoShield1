from collections import defaultdict


# ============================================================
# NORMALIZE ADDRESS
# ============================================================

def normalize_address(address):

    if not address:
        return ""

    return address.strip().lower()


# ============================================================
# EXTRACT IMPORTANT ADDRESSES
# ============================================================

def extract_addresses_from_transactions(
    transactions
):

    addresses = set()

    for tx in transactions:

        sender = normalize_address(
            tx.get("from", "")
        )

        receiver = normalize_address(
            tx.get("to", "")
        )

        if sender:
            addresses.add(sender)

        if receiver:
            addresses.add(receiver)

    return addresses


# ============================================================
# FIND CONVERGENCE
# ============================================================

def detect_cross_case_convergence(
    current_case,
    previous_cases
):

    alerts = []

    current_case_id = current_case.get(
        "case_id",
        "CURRENT"
    )

    current_wallet = normalize_address(
        current_case.get(
            "wallet_address",
            ""
        )
    )

    current_destinations = {
        normalize_address(x)
        for x in current_case.get(
            "final_destinations",
            []
        )
        if x
    }

    current_wallets = {
        normalize_address(x)
        for x in current_case.get(
            "important_wallets",
            []
        )
        if x
    }

    # --------------------------------------------------------
    # Compare with previous cases
    # --------------------------------------------------------

    for previous_case in previous_cases:

        previous_case_id = previous_case.get(
            "case_id"
        )

        previous_wallet = normalize_address(
            previous_case.get(
                "wallet_address",
                ""
            )
        )

        # Never compare case with itself
        if (
            previous_case_id
            == current_case_id
        ):
            continue

        # ----------------------------------------------------
        # Destination comparison
        # ----------------------------------------------------

        previous_destinations = {
            normalize_address(x)
            for x in previous_case.get(
                "final_destinations",
                []
            )
            if x
        }

        shared_destinations = (
            current_destinations
            &
            previous_destinations
        )

        # ----------------------------------------------------
        # Intermediary wallet comparison
        # ----------------------------------------------------

        previous_wallets = {
            normalize_address(x)
            for x in previous_case.get(
                "important_wallets",
                []
            )
            if x
        }

        shared_wallets = (
            current_wallets
            &
            previous_wallets
        )

        # ----------------------------------------------------
        # Determine relationship
        # ----------------------------------------------------

        if not shared_destinations and not shared_wallets:

            continue

        reasons = []

        if shared_destinations:

            reasons.append(
                "Shared final destination"
            )

        if shared_wallets:

            reasons.append(
                "Shared intermediary wallet"
            )

        # ----------------------------------------------------
        # Calculate convergence strength
        # ----------------------------------------------------

        strength = "LOW"

        if (
            shared_destinations
            and shared_wallets
        ):

            strength = "HIGH"

        elif shared_destinations:

            strength = "HIGH"

        elif shared_wallets:

            strength = "MEDIUM"

        # ----------------------------------------------------
        # Create alert
        # ----------------------------------------------------

        alert = {

            "current_case_id":
                current_case_id,

            "previous_case_id":
                previous_case_id,

            "current_wallet":
                current_wallet,

            "previous_wallet":
                previous_wallet,

            "shared_destinations":
                list(shared_destinations),

            "shared_wallets":
                list(shared_wallets),

            "reasons":
                reasons,

            "strength":
                strength,

            "message":
                (
                    f"Potential cross-case link "
                    f"between {current_case_id} "
                    f"and {previous_case_id}"
                )
        }

        alerts.append(alert)

    return alerts


# ============================================================
# GROUP RELATED CASES
# ============================================================

def build_fraud_ring_clusters(
    convergence_alerts
):

    graph = defaultdict(set)

    for alert in convergence_alerts:

        case_a = alert[
            "current_case_id"
        ]

        case_b = alert[
            "previous_case_id"
        ]

        graph[case_a].add(case_b)

        graph[case_b].add(case_a)

    visited = set()

    clusters = []

    for case_id in graph:

        if case_id in visited:
            continue

        stack = [case_id]

        cluster = set()

        while stack:

            current = stack.pop()

            if current in visited:
                continue

            visited.add(current)

            cluster.add(current)

            for neighbour in graph[current]:

                if neighbour not in visited:

                    stack.append(neighbour)

        if len(cluster) >= 2:

            clusters.append(
                sorted(cluster)
            )

    return clusters


# ============================================================
# SUMMARY
# ============================================================

def convergence_summary(
    alerts
):

    if not alerts:

        return {
            "linked_cases": 0,
            "high_strength_links": 0,
            "medium_strength_links": 0
        }

    high = sum(
        1
        for alert in alerts
        if alert["strength"] == "HIGH"
    )

    medium = sum(
        1
        for alert in alerts
        if alert["strength"] == "MEDIUM"
    )

    return {

        "linked_cases":
            len(alerts),

        "high_strength_links":
            high,

        "medium_strength_links":
            medium
    }
