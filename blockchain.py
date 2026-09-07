import os
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# --------------------------------------------------
# API KEY
# --------------------------------------------------

try:
    cloud_key = st.secrets.get("ETHERSCAN_API_KEY", "")
except Exception:
    cloud_key = ""

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY") or cloud_key


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

CHAIN_IDS = {
    "Ethereum": 1,
    "BSC": 56
}

MAX_WALLETS_PER_HOP = 5
MAX_TRANSFERS_PER_WALLET = 100
MAX_PAGES = 3


# --------------------------------------------------
# GET API URL
# --------------------------------------------------

def get_api_url(chain):

    if chain not in CHAIN_IDS:
        raise ValueError("Unsupported blockchain")

    return "https://api.etherscan.io/v2/api"


# --------------------------------------------------
# FETCH TRANSACTIONS
# --------------------------------------------------

def get_transactions(wallet_address, chain="Ethereum"):

    if not ETHERSCAN_API_KEY:
        raise RuntimeError(
            "ETHERSCAN_API_KEY not configured. "
            "Add it to Streamlit Secrets."
        )

    wallet_address = wallet_address.strip()

    if not wallet_address.startswith("0x"):
        raise ValueError("Invalid wallet address")

    chain_id = CHAIN_IDS.get(chain)

    if not chain_id:
        raise ValueError(f"Unsupported chain: {chain}")

    api_url = get_api_url(chain)

    transactions = []
    page = 1

    while page <= MAX_PAGES:

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
                api_url,
                params=params,
                timeout=30
            )

            response.raise_for_status()

            data = response.json()

        except requests.RequestException as e:
            raise RuntimeError(
                f"Etherscan API request failed: {e}"
            )

        except ValueError:
            raise RuntimeError(
                "Invalid response received from Etherscan."
            )

        result = data.get("result", [])

        # Etherscan can return a string message instead of transactions
        if not isinstance(result, list):
            break

        if len(result) == 0:
            break

        for tx in result:

            from_address = tx.get("from", "")
            to_address = tx.get("to", "")

            if not from_address or not to_address:
                continue

            try:
                value_wei = int(tx.get("value", "0"))
                value_eth = value_wei / 10**18
            except (ValueError, TypeError):
                value_eth = 0

            transactions.append({
                "hash": tx.get("hash", ""),
                "from": from_address,
                "to": to_address,
                "value": value_eth,
                "asset": "ETH",
                "timestamp": tx.get("timeStamp", ""),
                "blockNumber": tx.get("blockNumber", "")
            })

        if len(result) < MAX_TRANSFERS_PER_WALLET:
            break

        page += 1

    return transactions


# --------------------------------------------------
# FIND CONNECTED WALLETS
# --------------------------------------------------

def find_connected_wallets(wallet, transactions):

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


# --------------------------------------------------
# RANK CONNECTED WALLETS
# --------------------------------------------------

def rank_connected_wallets(wallet, transactions):

    wallet = wallet.lower()

    counts = {}

    for tx in transactions:

        sender = tx["from"].lower()
        receiver = tx["to"].lower()

        if sender == wallet:
            address = tx["to"]

        elif receiver == wallet:
            address = tx["from"]

        else:
            continue

        key = address.lower()

        counts[key] = counts.get(key, 0) + 1

    ranked = sorted(
        counts.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return [address for address, count in ranked]


# --------------------------------------------------
# RECURSIVE MULTI-HOP TRACE
# --------------------------------------------------

def trace_wallet(
    start_wallet,
    chain="Ethereum",
    max_hops=1
):

    start_wallet = start_wallet.strip()

    visited = set()
    all_transactions = []

    queue = [
        (start_wallet, 0)
    ]

    while queue:

        current_wallet, hop = queue.pop(0)

        current_key = current_wallet.lower()

        if current_key in visited:
            continue

        visited.add(current_key)

        # Fetch transactions
        try:
            transactions = get_transactions(
                current_wallet,
                chain
            )
        except Exception:
            continue

        # Store transactions
        all_transactions.extend(transactions)

        # Stop if maximum hop reached
        if hop >= max_hops:
            continue

        # Find connected wallets
        connected = rank_connected_wallets(
            current_wallet,
            transactions
        )

        # Limit number of wallets explored
        connected = connected[
            :MAX_WALLETS_PER_HOP
        ]

        for wallet in connected:

            wallet_key = wallet.lower()

            if wallet_key not in visited:

                queue.append(
                    (
                        wallet,
                        hop + 1
                    )
                )

    # --------------------------------------------------
    # REMOVE DUPLICATE TRANSACTIONS
    # --------------------------------------------------

    unique_transactions = {}

    for tx in all_transactions:

        tx_hash = tx.get("hash")

        if tx_hash:

            unique_transactions[tx_hash] = tx

    final_transactions = list(
        unique_transactions.values()
    )

    # --------------------------------------------------
    # BUILD WALLET LIST
    # --------------------------------------------------

    wallets = set()

    for tx in final_transactions:

        if tx.get("from"):
            wallets.add(tx["from"])

        if tx.get("to"):
            wallets.add(tx["to"])

    wallets.add(start_wallet)

    # --------------------------------------------------
    # CALCULATE MAX HOP
    # --------------------------------------------------

    hop_map = {
        start_wallet.lower(): 0
    }

    queue = [start_wallet]

    while queue:

        current = queue.pop(0)

        current_hop = hop_map[
            current.lower()
        ]

        if current_hop >= max_hops:
            continue

        for tx in final_transactions:

            sender = tx["from"]
            receiver = tx["to"]

            if sender.lower() == current.lower():

                key = receiver.lower()

                if key not in hop_map:

                    hop_map[key] = current_hop + 1
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


# --------------------------------------------------
# SIMPLE ANALYSIS FUNCTION
# --------------------------------------------------

def analyze_wallet(
    wallet_address,
    chain="Ethereum",
    max_hops=1
):

    result = trace_wallet(
        wallet_address,
        chain,
        max_hops
    )

    transactions = result["transactions"]

    connected_wallets = set()

    for tx in transactions:

        connected_wallets.add(
            tx["from"]
        )

        connected_wallets.add(
            tx["to"]
        )

    return {
        "wallet": wallet_address,
        "chain": chain,
        "transactions": transactions,
        "transaction_count": len(transactions),
        "connected_wallets": len(
            connected_wallets
        ),
        "max_hop": result["max_hop"],
        "wallets": result["wallets"]
    }
