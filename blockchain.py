import os
import requests
from dotenv import load_dotenv

load_dotenv()

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

CHAIN_CONFIG = {
    "Ethereum": {
        "chain_id": "1"
    },
    "BSC": {
        "chain_id": "56"
    }
}

MAX_WALLETS_PER_HOP = 5
MAX_TRANSFERS_PER_WALLET = 100
MAX_PAGES = 3


def get_transactions(wallet_address, chain="Ethereum"):

    if not ETHERSCAN_API_KEY:
        raise ValueError(
            "ETHERSCAN_API_KEY not found in .env file."
        )

    wallet_address = wallet_address.strip()

    chain_id = CHAIN_CONFIG[chain]["chain_id"]

    url = "https://api.etherscan.io/v2/api"

    all_transactions = []

    for page in range(1, MAX_PAGES + 1):

        params = {
            "chainid": chain_id,
            "module": "account",
            "action": "txlist",
            "address": wallet_address,
            "startblock": 0,
            "endblock": 99999999,
            "page": page,
            "offset": MAX_TRANSFERS_PER_WALLET,
            "sort": "desc",
            "apikey": ETHERSCAN_API_KEY
        }

        try:
            response = requests.get(
                url,
                params=params,
                timeout=30
            )

            response.raise_for_status()

            data = response.json()

        except Exception as e:
            print("API error:", e)
            break

        result = data.get("result", [])

        if not isinstance(result, list):
            break

        for tx in result:

            try:
                value_eth = (
                    int(tx.get("value", "0")) / 10**18
                )
            except:
                value_eth = 0

            timestamp = tx.get("timeStamp", "")

            try:
                from datetime import datetime

                timestamp = datetime.fromtimestamp(
                    int(timestamp)
                ).isoformat() + "+00:00"

            except:
                pass

            normalized = {
                "hash": tx.get("hash", ""),
                "from": tx.get("from", "").lower(),
                "to": tx.get("to", "").lower(),
                "value": value_eth,
                "asset": "ETH",
                "timestamp": timestamp,
                "blockNumber": tx.get(
                    "blockNumber",
                    ""
                )
            }

            all_transactions.append(normalized)

        if len(result) < MAX_TRANSFERS_PER_WALLET:
            break

    return all_transactions


def wallet_relevance_score(
    wallet,
    transactions,
    parent_wallet=None
):

    wallet = wallet.lower()

    score = 0

    interaction_count = 0
    total_value = 0

    for tx in transactions:

        from_wallet = tx.get("from", "").lower()
        to_wallet = tx.get("to", "").lower()

        if (
            from_wallet == wallet
            or to_wallet == wallet
        ):

            interaction_count += 1

            try:
                total_value += float(
                    tx.get("value", 0)
                )
            except:
                pass

        if parent_wallet:

            parent_wallet = parent_wallet.lower()

            if (
                from_wallet == parent_wallet
                and to_wallet == wallet
            ) or (
                to_wallet == parent_wallet
                and from_wallet == wallet
            ):
                score += 30

    score += min(
        interaction_count * 2,
        30
    )

    if total_value > 0:
        score += 20

    if interaction_count >= 5:
        score += 10

    return score


def select_relevant_wallets(
    current_wallet,
    transactions,
    visited
):

    current_wallet = current_wallet.lower()

    candidates = {}

    for tx in transactions:

        from_wallet = tx.get(
            "from",
            ""
        ).lower()

        to_wallet = tx.get(
            "to",
            ""
        ).lower()

        if from_wallet == current_wallet:

            candidate = to_wallet

        elif to_wallet == current_wallet:

            candidate = from_wallet

        else:

            continue

        if not candidate:
            continue

        if candidate == current_wallet:
            continue

        if candidate in visited:
            continue

        candidates[candidate] = (
            candidates.get(candidate, 0) + 1
        )

    ranked = []

    for wallet, interactions in candidates.items():

        score = (
            interactions * 10
        )

        ranked.append(
            (
                wallet,
                score
            )
        )

    ranked.sort(
        key=lambda x: x[1],
        reverse=True
    )

    return [
        wallet
        for wallet, score
        in ranked[:MAX_WALLETS_PER_HOP]
    ]


def recursive_trace(
    wallet,
    chain="Ethereum",
    max_hops=1
):

    wallet = wallet.lower()

    visited = set()

    trace_nodes = []

    all_transactions = []

    current_level = [
        {
            "wallet": wallet,
            "hop": 0
        }
    ]

    visited.add(wallet)

    trace_nodes.append(
        {
            "wallet": wallet,
            "hop": 0,
            "relevance": 100
        }
    )

    for hop in range(1, max_hops + 1):

        next_level = []

        for node in current_level:

            current_wallet = node["wallet"]

            transactions = get_transactions(
                current_wallet,
                chain
            )

            all_transactions.extend(
                transactions
            )

            selected_wallets = (
                select_relevant_wallets(
                    current_wallet,
                    transactions,
                    visited
                )
            )

            for candidate in selected_wallets:

                if candidate in visited:
                    continue

                visited.add(candidate)

                relevance = (
                    wallet_relevance_score(
                        candidate,
                        transactions,
                        current_wallet
                    )
                )

                new_node = {
                    "wallet": candidate,
                    "hop": hop,
                    "relevance": relevance
                }

                trace_nodes.append(
                    new_node
                )

                next_level.append(
                    new_node
                )

        current_level = next_level

        if not current_level:
            break

    # Remove duplicate transactions
    unique_transactions = {}

    for tx in all_transactions:

        tx_hash = tx.get("hash")

        if tx_hash:
            unique_transactions[
                tx_hash
            ] = tx

    all_transactions = list(
        unique_transactions.values()
    )

    return trace_nodes, all_transactions


def print_transactions(
    transactions
):

    print("=" * 60)
    print("TRANSACTIONS")
    print("=" * 60)

    for tx in transactions:

        print(
            f"{tx.get('hash', '')[:20]}..."
        )

        print(
            "From:",
            tx.get("from")
        )

        print(
            "To:",
            tx.get("to")
        )

        print(
            "Value:",
            tx.get("value"),
            tx.get("asset")
        )

        print(
            "Timestamp:",
            tx.get("timestamp")
        )

        print("-" * 60)
