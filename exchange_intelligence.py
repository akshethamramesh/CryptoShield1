import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LABEL_FILE = BASE_DIR / "exchange_labels.json"


def normalize_address(address):
    """Normalize an Ethereum/BSC wallet address."""
    if not address:
        return ""

    return address.strip().lower()


def load_exchange_labels(file_path=None):
    """
    Load exchange/VASP labels from a JSON file.

    Returns:
        dict: normalized wallet address -> exchange information
    """

    path = Path(file_path or DEFAULT_LABEL_FILE)

    if not path.exists():
        print(f"Exchange label file not found: {path}")
        return {}

    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            print("Invalid exchange label format.")
            return {}

        normalized = {}

        for address, info in data.items():
            normalized_address = normalize_address(address)

            if not normalized_address:
                continue

            if not isinstance(info, dict):
                continue

            normalized[normalized_address] = info

        return normalized

    except json.JSONDecodeError:
        print("Exchange label JSON is invalid.")
        return {}

    except OSError as error:
        print(f"Unable to read exchange label file: {error}")
        return {}

    except Exception as error:
        print(f"Unexpected exchange label error: {error}")
        return {}


def get_transaction_participants(transactions):
    """
    Extract sender and receiver addresses from transactions.

    Returns:
        set[str]
    """

    participants = set()

    if not transactions:
        return participants

    for transaction in transactions:

        sender = normalize_address(
            transaction.get("from", "")
        )

        receiver = normalize_address(
            transaction.get("to", "")
        )

        if sender:
            participants.add(sender)

        if receiver:
            participants.add(receiver)

    return participants


def check_exchange_associations(
    transactions,
    wallet_hops=None,
    label_file=None
):
    """
    Check transaction participants against known
    exchange/VASP labels.

    This function reports potential associations only.
    It does not claim ownership or criminal involvement.
    """

    labels = load_exchange_labels(label_file)

    if not labels:
        return []

    wallet_hops = wallet_hops or {}

    participants = get_transaction_participants(
        transactions
    )

    matches = []
    seen = set()

    for address in participants:

        if address not in labels:
            continue

        if address in seen:
            continue

        info = labels[address]

        hop = wallet_hops.get(address)

        transaction_roles = set()

        for transaction in transactions:

            sender = normalize_address(
                transaction.get("from", "")
            )

            receiver = normalize_address(
                transaction.get("to", "")
            )

            if sender == address:
                transaction_roles.add("sender")

            if receiver == address:
                transaction_roles.add("receiver")

        matches.append(
            {
                "address": address,
                "name": info.get(
                    "name",
                    "Unknown exchange"
                ),
                "type": info.get(
                    "type",
                    "Unknown"
                ),
                "country": info.get(
                    "country",
                    "Unknown"
                ),
                "label_source": info.get(
                    "label_source",
                    "Unknown"
                ),
                "hop": hop,
                "transaction_roles": sorted(
                    transaction_roles
                ),
                "association": (
                    "Potential exchange/VASP association"
                ),
                "investigative_note": (
                    "Blockchain evidence may support "
                    "a lawful request for additional "
                    "off-chain information by authorized "
                    "investigators."
                )
            }
        )

        seen.add(address)

    return matches


def summarize_exchange_associations(matches):
    """
    Create a compact summary for UI/reporting.
    """

    if not matches:
        return {
            "match_count": 0,
            "exchanges": []
        }

    exchanges = []

    for match in matches:
        exchanges.append(
            {
                "name": match.get(
                    "name",
                    "Unknown"
                ),
                "address": match.get(
                    "address",
                    ""
                ),
                "hop": match.get(
                    "hop"
                )
            }
        )

    return {
        "match_count": len(matches),
        "exchanges": exchanges
    }
