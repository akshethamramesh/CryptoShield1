import os
import requests
from dotenv import load_dotenv
import streamlit as st

load_dotenv()


# --------------------------------------------------
# API KEY
# --------------------------------------------------

try:
    cloud_key = st.secrets.get("ETHERSCAN_API_KEY", "")
except Exception:
    cloud_key = ""

ETHERSCAN_API_KEY = (
    os.getenv("ETHERSCAN_API_KEY")
    or cloud_key
)


# --------------------------------------------------
# CHAIN CONFIG
# --------------------------------------------------

CHAIN_IDS = {
    "Ethereum": 1,
    "BSC": 56
}


# --------------------------------------------------
# LIMITS
# --------------------------------------------------

MAX_WALLETS_PER_HOP = 5
MAX_TRANSFERS_PER_WALLET = 100
MAX_PAGES = 3


# --------------------------------------------------
# GET TRANSACTIONS
# --------------------------------------------------

def get_transactions(wallet_address, chain="Ethereum"):

    if not ETHERSCAN_API_KEY:
        raise ValueError(
            "ETHERSCAN_API_KEY not found. "
            "Add it to .env or Streamlit Secrets."
        )

    chain_id = CHAIN_IDS.get(chain, 1)

    url = "https://api.etherscan.io/v2/api"

    params = {
        "chainid": chain_id,
        "module": "account",
        "action": "txlist",
        "address": wallet_address,
        "startblock": 0,
        "endblock": 99999999,
        "page": 1,
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

        if data.get("status") == "0":

            message = data.get(
                "message",
                "No transaction data"
            )

            # "No transactions found" is not a fatal error
            if "No transactions" in message:
                return []

            return []

        transactions = data.get("result", [])

        formatted = []

        for tx in transactions:

            try:
                value_eth = int(
                    tx.get("value", "0")
                ) / 10**18
            except:
                value_eth = 0

            formatted.append({
                "hash": tx.get("hash", ""),
                "from": tx.get("from", ""),
                "to": tx.get("to", ""),
                "value": value_eth,
                "asset": "ETH",
                "timestamp": tx.get(
                    "timeStamp",
                    ""
                ),
                "blockNumber": tx.get(
                    "blockNumber",
                    ""
                )
            })

        return formatted

    except requests.RequestException as e:

        raise RuntimeError(
            f"Blockchain API error: {e}"
        )


# --------------------------------------------------
# FIND CONNECTED WALLETS
# --------------------------------------------------

def find_connected_wallets(
    wallet,
    transactions
):

    wallet = wallet.lower()

    connected = []

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        if sender == wallet and receiver:
            connected.append(receiver)

        elif receiver == wallet and sender:
            connected.append(sender)

    return list(set(connected))


# --------------------------------------------------
# RANK WALLETS
# --------------------------------------------------

def rank_connected_wallets(
    wallet,
    transactions
):

    wallet = wallet.lower()

    interaction_count = {}

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        if sender == wallet and receiver:

            interaction_count[receiver] = (
                interaction_count.get(receiver, 0) + 1
            )

        elif receiver == wallet and sender:

            interaction_count[sender] = (
                interaction_count.get(sender, 0) + 1
            )

    ranked = sorted(
        interaction_count.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return [
        wallet_address
        for wallet_address, count in ranked[
            :MAX_WALLETS_PER_HOP
        ]
    ]


# --------------------------------------------------
# TRACE WALLET
# --------------------------------------------------

def trace_wallet(
    start_wallet,
    chain="Ethereum",
    max_hops=2
):

    start_wallet = start_wallet.strip()

    all_transactions = []

    visited = set()

    wallet_hops = {}

    hop_map = {}

    current_level = [
        start_wallet
    ]

    wallet_hops[
        start_wallet
    ] = 0

    hop_map[
        start_wallet.lower()
    ] = 0

    # ----------------------------------------------
    # BFS MULTI-HOP
    # ----------------------------------------------

    for hop in range(max_hops + 1):

        next_level = []

        for wallet in current_level:

            normalized_wallet = wallet.lower()

            if normalized_wallet in visited:
                continue

            visited.add(
                normalized_wallet
            )

            try:

                transactions = get_transactions(
                    wallet,
                    chain
                )

            except Exception as e:

                print(
                    f"Error scanning {wallet}: {e}"
                )

                transactions = []

            all_transactions.extend(
                transactions
            )

            # --------------------------------------
            # FIND NEXT WALLETS
            # --------------------------------------

            if hop < max_hops:

                connected = rank_connected_wallets(
                    wallet,
                    transactions
                )

                for next_wallet in connected:

                    normalized_next = (
                        next_wallet.lower()
                    )

                    if normalized_next not in visited:

                        if normalized_next not in hop_map:

                            hop_map[
                                normalized_next
                            ] = hop + 1

                            wallet_hops[
                                next_wallet
                            ] = hop + 1

                            next_level.append(
                                next_wallet
                            )

        current_level = next_level

        if not current_level:
            break

    # ----------------------------------------------
    # UNIQUE TRANSACTIONS
    # ----------------------------------------------

    unique_transactions = []

    transaction_hashes = set()

    for tx in all_transactions:

        tx_hash = tx.get(
            "hash",
            ""
        )

        if tx_hash not in transaction_hashes:

            transaction_hashes.add(
                tx_hash
            )

            unique_transactions.append(
                tx
            )

    # ----------------------------------------------
    # WALLETS
    # ----------------------------------------------

    wallets = set()

    for tx in unique_transactions:

        if tx.get("from"):
            wallets.add(
                tx["from"]
            )

        if tx.get("to"):
            wallets.add(
                tx["to"]
            )

    wallets.add(start_wallet)

    # ----------------------------------------------
    # MAX HOP
    # ----------------------------------------------

    max_hop_found = 0

    if hop_map:

        max_hop_found = max(
            hop_map.values()
        )

    return {

        "start_wallet":
            start_wallet,

        "chain":
            chain,

        "transactions":
            unique_transactions,

        "wallets":
            list(wallets),

        "max_hop":
            max_hop_found,

        "visited_wallets":
            list(visited),

        "hop_map":
            hop_map,

        "wallet_hops":
            wallet_hops
    }


# --------------------------------------------------
# COMPATIBILITY FUNCTION
# --------------------------------------------------

def recursive_trace(
    wallet,
    chain="Ethereum",
    max_hops=2
):

    return trace_wallet(
        wallet,
        chain,
        max_hops
    )
