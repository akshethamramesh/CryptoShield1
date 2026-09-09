VASP_REGISTRY = {

    "0x1111111111111111111111111111111111111111": {
        "name": "Demo Exchange Alpha",
        "type": "Centralized Exchange",
        "country": "Demo",
        "source": "CryptoShield Demo Registry"
    },

    "0x2222222222222222222222222222222222222222": {
        "name": "Demo Exchange Beta",
        "type": "Centralized Exchange",
        "country": "Demo",
        "source": "CryptoShield Demo Registry"
    },

    "0x3333333333333333333333333333333333333333": {
        "name": "Demo Exchange Gamma",
        "type": "Centralized Exchange",
        "country": "Demo",
        "source": "CryptoShield Demo Registry"
    }
}


def normalize_address(address):

    if not address:
        return ""

    return address.strip().lower()


def detect_vasp(transactions):

    results = []
    found = set()

    if not transactions:
        return results

    for tx in transactions:

        sender = normalize_address(
            tx.get("from", "")
        )

        receiver = normalize_address(
            tx.get("to", "")
        )

        participants = [
            ("sender", sender),
            ("receiver", receiver)
        ]

        for role, address in participants:

            if not address:
                continue

            if address not in VASP_REGISTRY:
                continue

            if address in found:
                continue

            info = VASP_REGISTRY[address]

            results.append(
                {
                    "address": address,
                    "name": info.get(
                        "name",
                        "Unknown VASP"
                    ),
                    "type": info.get(
                        "type",
                        "Unknown"
                    ),
                    "country": info.get(
                        "country",
                        "Unknown"
                    ),
                    "source": info.get(
                        "source",
                        "Unknown"
                    ),
                    "transaction_role": role,
                    "confidence": "Potential association"
                }
            )

            found.add(address)

    return results


def detect_vasp_association(transactions):
    return detect_vasp(transactions)


def find_vasp(transactions):
    return detect_vasp(transactions)
