import os
import requests
import streamlit as st

from dotenv import load_dotenv


load_dotenv()


try:
    cloud_key = st.secrets.get(
        "ETHERSCAN_API_KEY",
        ""
    )
except Exception:
    cloud_key = ""


ETHERSCAN_API_KEY = (
    os.getenv("ETHERSCAN_API_KEY")
    or cloud_key
)


ETHERSCAN_URL = (
    "https://api.etherscan.io/v2/api"
)


CHAIN_IDS = {
    "Ethereum": 1,
    "BSC": 56
}


MAX_WALLETS_PER_NODE = 5
MAX_TRANSFERS_PER_WALLET = 100
MAX_TOKEN_TRANSFERS_PER_WALLET = 100
MAX_PAGES = 3


def check_api_key():

    if not ETHERSCAN_API_KEY:

        raise ValueError(
            "ETHERSCAN_API_KEY not found. "
            "Check your .env file or Streamlit secrets."
        )


def convert_native_value(value):

    try:
        return float(value) / 10**18
    except Exception:
        return 0


def convert_token_value(value, decimals):

    try:
        return float(value) / (
            10 ** int(decimals)
        )
    except Exception:
        return 0


def get_transactions(
    wallet_address,
    chain="Ethereum"
):

    check_api_key()

    chain_id = CHAIN_IDS.get(
        chain,
        1
    )

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
                ETHERSCAN_URL,
                params=params,
                timeout=30
            )

            data = response.json()

        except Exception as error:

            raise RuntimeError(
                f"Etherscan request failed: {error}"
            )

        result = data.get(
            "result",
            []
        )

        if not isinstance(result, list):
            break

        for tx in result:

            normalized = {
                "hash": tx.get("hash", ""),
                "from": tx.get("from", ""),
                "to": tx.get("to", ""),
                "value": convert_native_value(
                    tx.get("value", 0)
                ),
                "asset": (
                    "ETH"
                    if chain == "Ethereum"
                    else "BNB"
                ),
                "type": "native",
                "timeStamp": tx.get(
                    "timeStamp",
                    0
                ),
                "blockNumber": tx.get(
                    "blockNumber",
                    0
                ),
                "isError": tx.get(
                    "isError",
                    "0"
                )
            }

            all_transactions.append(
                normalized
            )

        if len(result) < MAX_TRANSFERS_PER_WALLET:
            break

    return all_transactions


def get_token_transfers(
    wallet_address,
    chain="Ethereum"
):

    check_api_key()

    chain_id = CHAIN_IDS.get(
        chain,
        1
    )

    all_transactions = []

    for page in range(1, MAX_PAGES + 1):

        params = {
            "chainid": chain_id,
            "module": "account",
            "action": "tokentx",
            "address": wallet_address,
            "page": page,
            "offset": MAX_TOKEN_TRANSFERS_PER_WALLET,
            "sort": "desc",
            "apikey": ETHERSCAN_API_KEY
        }

        try:

            response = requests.get(
                ETHERSCAN_URL,
                params=params,
                timeout=30
            )

            data = response.json()

        except Exception as error:

            raise RuntimeError(
                f"Etherscan token request failed: {error}"
            )

        result = data.get(
            "result",
            []
        )

        if not isinstance(result, list):
            break

        for tx in result:

            decimals = tx.get(
                "tokenDecimal",
                "18"
            )

            normalized = {
                "hash": tx.get(
                    "hash",
                    ""
                ),
                "from": tx.get(
                    "from",
                    ""
                ),
                "to": tx.get(
                    "to",
                    ""
                ),
                "value": convert_token_value(
                    tx.get("value", 0),
                    decimals
                ),
                "asset": tx.get(
                    "tokenSymbol",
                    "TOKEN"
                ),
                "type": "token",
                "token_name": tx.get(
                    "tokenName",
                    "Unknown"
                ),
                "token_symbol": tx.get(
                    "tokenSymbol",
                    "TOKEN"
                ),
                "token_contract": tx.get(
                    "contractAddress",
                    ""
                ),
                "token_decimals": decimals,
                "timeStamp": tx.get(
                    "timeStamp",
                    0
                ),
                "blockNumber": tx.get(
                    "blockNumber",
                    0
                )
            }

            all_transactions.append(
                normalized
            )

        if len(result) < MAX_TOKEN_TRANSFERS_PER_WALLET:
            break

    return all_transactions


def deduplicate_transactions(
    transactions
):

    seen = set()
    result = []

    for tx in transactions:

        key = (
            tx.get("hash", ""),
            tx.get("type", "native"),
            tx.get(
                "token_contract",
                ""
            )
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(tx)

    return result


def get_all_transactions(
    wallet_address,
    chain="Ethereum"
):

    native = get_transactions(
        wallet_address,
        chain
    )

    token = get_token_transfers(
        wallet_address,
        chain
    )

    combined = native + token

    return deduplicate_transactions(
        combined
    )


def find_connected_wallets(
    transactions,
    wallet_address
):

    wallet_address = wallet_address.lower()

    connected = set()

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        if sender == wallet_address and receiver:
            connected.add(receiver)

        if receiver == wallet_address and sender:
            connected.add(sender)

    connected.discard(
        wallet_address
    )

    return list(connected)


def rank_connected_wallets(
    transactions,
    wallet_address
):

    wallet_address = wallet_address.lower()

    counts = {}

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        other = None

        if sender == wallet_address:
            other = receiver

        elif receiver == wallet_address:
            other = sender

        if not other:
            continue

        if other == wallet_address:
            continue

        counts[other] = (
            counts.get(other, 0) + 1
        )

    ranked = sorted(
        counts.items(),
        key=lambda item: item[1],
        reverse=True
    )

    return ranked


def trace_wallet(
    wallet_address,
    chain="Ethereum",
    max_hop=2
):

    wallet_address = wallet_address.strip()

    visited = set()
    hop_map = {}

    queue = [
        (
            wallet_address,
            0
        )
    ]

    all_transactions = []

    while queue:

        current_wallet, current_hop = queue.pop(0)

        current_wallet = current_wallet.lower()

        if current_wallet in visited:
            continue

        visited.add(current_wallet)

        hop_map[current_wallet] = current_hop

        try:

            transactions = get_all_transactions(
                current_wallet,
                chain
            )

        except Exception:
            transactions = []

        all_transactions.extend(
            transactions
        )

        if current_hop >= max_hop:
            continue

        ranked = rank_connected_wallets(
            transactions,
            current_wallet
        )

        next_wallets = [
            wallet
            for wallet, count in ranked[
                :MAX_WALLETS_PER_NODE
            ]
        ]

        for next_wallet in next_wallets:

            if next_wallet not in visited:

                queue.append(
                    (
                        next_wallet,
                        current_hop + 1
                    )
                )

    all_transactions = deduplicate_transactions(
        all_transactions
    )

    wallets = list(visited)

    connected_wallets = [
        wallet
        for wallet in wallets
        if wallet != wallet_address.lower()
    ]

    native_transactions = [
        tx
        for tx in all_transactions
        if tx.get("type") != "token"
    ]

    token_transactions = [
        tx
        for tx in all_transactions
        if tx.get("type") == "token"
    ]

    token_types = sorted(
        set(
            tx.get(
                "token_symbol",
                tx.get(
                    "asset",
                    "TOKEN"
                )
            )
            for tx in token_transactions
        )
    )

    return {
        "start_wallet": wallet_address,
        "chain": chain,
        "transactions": all_transactions,
        "wallets": wallets,
        "max_hop": max_hop,
        "visited_wallets": wallets,
        "hop_map": hop_map,
        "wallet_hops": hop_map,
        "connected_wallets": connected_wallets,
        "token_transactions": token_transactions,
        "native_transactions": native_transactions,
        "token_count": len(token_transactions),
        "native_count": len(native_transactions),
        "token_types": token_types
    }


def recursive_trace(
    wallet_address,
    chain="Ethereum",
    max_hop=2
):

    return trace_wallet(
        wallet_address,
        chain=chain,
        max_hop=max_hop
    )
