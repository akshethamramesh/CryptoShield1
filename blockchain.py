import os
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# Get API key from local .env OR Streamlit Cloud Secrets
try:
    cloud_key = st.secrets.get("ETHERSCAN_API_KEY", "")
except Exception:
    cloud_key = ""

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY") or cloud_key

CHAIN_IDS = {
    "Ethereum": 1,
    "BSC": 56
}

MAX_WALLETS_PER_HOP = 5
MAX_TRANSFERS_PER_WALLET = 100
MAX_PAGES = 3


def get_transactions(wallet_address, chain="Ethereum"):
    """Fetch normal transactions from Etherscan."""

    if not ETHERSCAN_API_KEY:
        raise RuntimeError(
            "ETHERSCAN_API_KEY is not configured. "
            "Add it in Streamlit Cloud Secrets."
        )

    wallet_address = wallet_address.strip()

    if not wallet_address.startswith("0x"):
        raise ValueError("Invalid wallet address.")

    chain_id = CHAIN_IDS.get(chain)

    if chain_id is None:
        raise ValueError(f"Unsupported blockchain: {chain}")

    url = "https://api.etherscan.io/v2/api"

    transactions = []

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

        response = requests.get(
            url,
            params=params,
            timeout=30
        )

        response.raise_for_status()

        data = response.json()

        result = data.get("result", [])

        if not isinstance(result, list):
            message = data.get("message", "Unknown API error")
            raise RuntimeError(
                f"Etherscan API error: {message}"
            )

        if not result:
            break

        for tx in result:

            sender = tx.get("from", "")
            receiver = tx.get("to", "")

            if not sender or not receiver:
                continue

            try:
                value_wei = int(tx.get("value", "0"))
                value_eth = value_wei / 10**18
            except Exception:
                value_eth = 0.0

            transactions.append({
                "hash": tx.get("hash", ""),
                "from": sender,
                "to": receiver,
                "value": value_eth,
                "asset": "ETH" if chain == "Ethereum" else "BNB",
                "timestamp": tx.get("timeStamp", ""),
                "blockNumber": tx.get("blockNumber", "")
            })

        if len(result) < MAX_TRANSFERS_PER_WALLET:
            break

    return transactions


def find_connected_wallets(wallet, transactions):
    """Find wallets directly connected to a wallet."""

    wallet = wallet.lower()

    connected = set()

    for tx in transactions:

        sender = tx["from"].lower()
        receiver = tx["to"].lower()

        if sender == wallet:
            connected.add(tx["to"])

        elif receiver == wallet:
            connected.add(tx["from"])

    return list(connected)


def rank_connected_wallets(wallet, transactions):
    """Rank connected wallets by interaction count."""

    wallet = wallet.lower()

    counts = {}

    for tx in transactions:

        sender = tx["from"].lower()
        receiver = tx["to"].lower()

        address = None

        if sender == wallet:
            address = tx["to"]

        elif receiver == wallet:
            address = tx["from"]

        if address:
            key = address.lower()

            if key not in counts:
                counts[key] = {
                    "address": address,
                    "count": 0
                }

            counts[key]["count"] += 1

    ranked = sorted(
        counts.values(),
        key=lambda x: x["count"],
        reverse=True
    )

    return [
        item["address"]
        for item in ranked
    ]


def trace_wallet(start_wallet, chain="Ethereum", max_hops=1):
    """
    Recursive multi-hop wallet tracing.
    """

    start_wallet = start_wallet.strip()

    visited = set()

    queue = [
        (start_wallet, 0)
    ]

    all_transactions = []

    while queue:

        current_wallet, current_hop = queue.pop(0)

        current_key = current_wallet.lower()

        if current_key in visited:
            continue

        visited.add(current_key)

        try:
            transactions = get_transactions(
                current_wallet,
                chain
            )
        except Exception as e:

            # Keep the trace alive even if one connected wallet
            # cannot be queried.
            continue

        all_transactions.extend(transactions)

        if current_hop >= max_hops:
            continue

        connected = rank_connected_wallets(
            current_wallet,
            transactions
        )

        connected = connected[
            :MAX_WALLETS_PER_HOP
        ]

        for wallet in connected:

            if wallet.lower() not in visited:

                queue.append(
                    (
                        wallet,
                        current_hop + 1
                    )
                )

    # Remove duplicate transactions
    unique_transactions = {}

    for tx in all_transactions:

        tx_hash = tx.get("hash")

        if tx_hash:
            unique_transactions[tx_hash] = tx

    final_transactions = list(
        unique_transactions.values()
    )

    # Collect wallets
    wallets = set()

    for tx in final_transactions:

        if tx.get("from"):
            wallets.add(tx["from"])

        if tx.get("to"):
            wallets.add(tx["to"])

    wallets.add(start_wallet)

    # Calculate hop levels
    hop_map = {
        start_wallet.lower(): 0
    }

    queue = [start_wallet]

    while queue:

        current = queue.pop(0)

        current_level = hop_map[
            current.lower()
        ]

        if current_level >= max_hops:
            continue

        for tx in final_transactions:

            sender = tx["from"]
            receiver = tx["to"]

            if sender.lower() == current.lower():

                receiver_key = receiver.lower()

                if receiver_key not in hop_map:

                    hop_map[
                        receiver_key
                    ] = current_level + 1

                    queue.append(receiver)

    actual_max_hop = max(
        hop_map.values(),
        default=0
    )

    return {
        "start_wallet": start_wallet,
        "chain": chain,
        "transactions": final_transactions,
        "wallets": list(wallets),
        "max_hop": actual_max_hop,
        "visited_wallets": list(visited)
    }


# Compatibility function
# If old code calls recursive_trace(), it will still work.
def recursive_trace(
    start_wallet,
    chain="Ethereum",
    max_hops=1
):
    return trace_wallet(
        start_wallet,
        chain,
        max_hops
    )
