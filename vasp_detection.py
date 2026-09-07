# vasp_detection.py

# --------------------------------------------------
# DEMO VASP REGISTRY
# --------------------------------------------------
# These are fictional/demo addresses for prototype use.
# They are NOT real exchange wallet addresses.

VASP_REGISTRY = {
    "0x1111111111111111111111111111111111111111": {
        "name": "Demo Exchange Alpha",
        "type": "Centralized Exchange",
        "country": "Demo"
    },

    "0x2222222222222222222222222222222222222222": {
        "name": "Demo Exchange Beta",
        "type": "Centralized Exchange",
        "country": "Demo"
    },

    "0x3333333333333333333333333333333333333333": {
        "name": "Demo Exchange Gamma",
        "type": "Centralized Exchange",
        "country": "Demo"
    }
}


def detect_vasp(transactions):
    """
    Check whether transaction destinations/sources
    match the demo VASP registry.

    This provides an analytical association only.
    It does not prove ownership or criminal activity.
    """

    results = []
    found = set()

    if not transactions:
        return results

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        # Check sender
        if sender in VASP_REGISTRY:

            if sender not in found:

                info = VASP_REGISTRY[sender]

                results.append({
                    "address": tx.get(
                        "from",
                        ""
                    ),
                    "name": info["name"],
                    "type": info["type"],
                    "country": info["country"],
                    "confidence": "Demo registry match"
                })

                found.add(sender)

        # Check receiver
        if receiver in VASP_REGISTRY:

            if receiver not in found:

                info = VASP_REGISTRY[receiver]

                results.append({
                    "address": tx.get(
                        "to",
                        ""
                    ),
                    "name": info["name"],
                    "type": info["type"],
                    "country": info["country"],
                    "confidence": "Demo registry match"
                })

                found.add(receiver)

    return results


# Compatibility functions
def detect_vasp_association(transactions):
    return detect_vasp(transactions)


def find_vasp(transactions):
    return detect_vasp(transactions)
