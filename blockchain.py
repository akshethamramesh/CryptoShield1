import os
import requests
import streamlit as st
from dotenv import load_dotenv
from collections import Counter

load_dotenv()


# ============================================================
# API KEY
# ============================================================

try:
    cloud_key = st.secrets.get("ETHERSCAN_API_KEY", "")
except Exception:
    cloud_key = ""

ETHERSCAN_API_KEY = (
    os.getenv("ETHERSCAN_API_KEY")
    or cloud_key
)


# ============================================================
# BLOCKCHAIN CONFIG
# ============================================================

CHAIN_IDS = {
    "Ethereum": 1,
    "BSC": 56
}


ETHERSCAN_URL = "https://api.etherscan.io/v2/api"


# ============================================================
# TRACE SETTINGS
# ============================================================

MAX_WALLETS_PER_NODE = 5
MAX_TRANSFERS_PER_WALLET = 100
MAX_PAGES = 3


# ============================================================
# GET TRANSACTIONS
# ============================================================

def get_transactions(wallet_address, chain="Ethereum"):

    if not ETHERSCAN_API_KEY:
        raise Exception(
            "ETHERSCAN_API_KEY not found. "
            "Add it to .env or Streamlit Cloud Secrets."
        )

    wallet_address = wallet_address.strip()

    chain_id = CHAIN_IDS.get(chain)

    if chain_id is None:
        raise Exception(
            f"Unsupported blockchain: {chain}"
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
                timeout=20
            )

            response.raise_for_status()

            data = response.json()

        except requests.RequestException as e:

            raise Exception(
                f"Blockchain API request failed: {e}"
            )

        except ValueError:

            raise Exception(
                "Invalid response received from blockchain API."
            )


        # ----------------------------------------------------
        # API RESPONSE
        # ----------------------------------------------------

        result = data.get("result", [])

        if isinstance(result, str):

            message = result

            if (
                "No transactions found" in message
                or "No records found" in message
            ):
                break

            raise Exception(
                f"Etherscan API error: {message}"
            )


        if not isinstance(result, list):
            break


        if not result:
            break


        # ----------------------------------------------------
        # NORMALIZE TRANSACTIONS
        # ----------------------------------------------------

        for tx in result:

            normalized_tx = {
                "hash": tx.get("hash", ""),

                "from": tx.get(
                    "from",
                    ""
                ),

                "to": tx.get(
                    "to",
                    ""
                ),

                "value": convert_eth_value(
                    tx.get("value", "0")
                ),

                "asset": "ETH",

                "timeStamp": tx.get(
                    "timeStamp",
                    ""
                ),

                "blockNumber": tx.get(
                    "blockNumber",
                    ""
                ),

                "gasUsed": tx.get(
                    "gasUsed",
                    ""
                ),

                "gasPrice": tx.get(
                    "gasPrice",
                    ""
                )
            }

            all_transactions.append(
                normalized_tx
            )


        # ----------------------------------------------------
        # STOP IF LAST PAGE
        # ----------------------------------------------------

        if len(result) < MAX_TRANSFERS_PER_WALLET:
            break


    # Remove duplicate transactions

    unique_transactions = {}

    for tx in all_transactions:

        tx_hash = tx.get("hash")

        if tx_hash:
            unique_transactions[tx_hash] = tx


    return list(
        unique_transactions.values()
    )


# ============================================================
# CONVERT WEI → ETH
# ============================================================

def convert_eth_value(value):

    try:

        return int(value) / 10**18

    except:

        try:
            return float(value)
        except:
            return 0


# ============================================================
# FIND CONNECTED WALLETS
# ============================================================

def find_connected_wallets(
    wallet_address,
    transactions
):

    wallet_address = wallet_address.lower()

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


        if sender == wallet_address:

            if receiver:
                connected.append(receiver)


        elif receiver == wallet_address:

            if sender:
                connected.append(sender)


    return list(
        set(connected)
    )


# ============================================================
# RANK CONNECTED WALLETS
# ============================================================

def rank_connected_wallets(
    wallet_address,
    transactions,
    limit=MAX_WALLETS_PER_NODE
):

    wallet_address = wallet_address.lower()

    interaction_counter = Counter()

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

            interaction_counter[
                receiver
            ] += 1


        elif receiver == wallet_address and sender:

            interaction_counter[
                sender
            ] += 1


    ranked = sorted(
        interaction_counter.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return [
        wallet
        for wallet, count in ranked[:limit]
    ]


# ============================================================
# MULTI-HOP WALLET TRACE
# ============================================================

def trace_wallet(
    wallet_address,
    chain="Ethereum",
    max_hop=2
):

    wallet_address = wallet_address.strip()

    if not wallet_address:

        raise Exception(
            "Wallet address cannot be empty."
        )


    # --------------------------------------------------------
    # BFS QUEUE
    # --------------------------------------------------------

    queue = [
        (
            wallet_address.lower(),
            0
        )
    ]


    visited = set()

    all_transactions = []

    all_wallets = set()

    wallet_hops = {}

    hop_map = {}


    # --------------------------------------------------------
    # BFS
    # --------------------------------------------------------

    while queue:

        current_wallet, current_hop = queue.pop(0)


        if current_wallet in visited:
            continue


        if current_hop > max_hop:
            continue


        visited.add(
            current_wallet
        )


        wallet_hops[
            current_wallet
        ] = current_hop


        hop_map[
            current_wallet
        ] = current_hop


        # ----------------------------------------------------
        # FETCH TRANSACTIONS
        # ----------------------------------------------------

        try:

            transactions = get_transactions(
                current_wallet,
                chain
            )

        except Exception as e:

            # Don't completely stop investigation
            # when one connected wallet fails.

            if current_hop == 0:

                raise e

            continue


        # ----------------------------------------------------
        # STORE TRANSACTIONS
        # ----------------------------------------------------

        all_transactions.extend(
            transactions
        )


        # ----------------------------------------------------
        # FIND CONNECTED WALLETS
        # ----------------------------------------------------

        connected_wallets = find_connected_wallets(
            current_wallet,
            transactions
        )


        # ----------------------------------------------------
        # RANK CONNECTIONS
        # ----------------------------------------------------

        ranked_wallets = rank_connected_wallets(
            current_wallet,
            transactions,
            limit=MAX_WALLETS_PER_NODE
        )


        # ----------------------------------------------------
        # ADD WALLETS
        # ----------------------------------------------------

        for wallet in connected_wallets:

            wallet_lower = wallet.lower()

            if wallet_lower != wallet_address.lower():

                all_wallets.add(
                    wallet_lower
                )


        # ----------------------------------------------------
        # CONTINUE TO NEXT HOP
        # ----------------------------------------------------

        if current_hop < max_hop:

            for next_wallet in ranked_wallets:

                next_wallet = next_wallet.lower()

                if next_wallet not in visited:

                    queue.append(
                        (
                            next_wallet,
                            current_hop + 1
                        )
                    )


    # ========================================================
    # REMOVE DUPLICATE TRANSACTIONS
    # ========================================================

    unique_transactions = {}

    for tx in all_transactions:

        tx_hash = tx.get(
            "hash",
            ""
        )

        if tx_hash:

            unique_transactions[
                tx_hash
            ] = tx


    final_transactions = list(
        unique_transactions.values()
    )


    # ========================================================
    # SORT BY TIMESTAMP
    # ========================================================

    try:

        final_transactions.sort(
            key=lambda x: int(
                x.get(
                    "timeStamp",
                    0
                ) or 0
            )
        )

    except:

        pass


    # ========================================================
    # RETURN RESULT
    # ========================================================

    return {

        "start_wallet":
            wallet_address,

        "chain":
            chain,

        "transactions":
            final_transactions,

        "wallets":
            list(all_wallets),

        "max_hop":
            max_hop,

        "visited_wallets":
            list(visited),

        "hop_map":
            hop_map,

        "wallet_hops":
            wallet_hops
    }


# ============================================================
# COMPATIBILITY FUNCTION
# ============================================================

def recursive_trace(
    wallet_address,
    chain="Ethereum",
    max_hop=2
):

    return trace_wallet(
        wallet_address=wallet_address,
        chain=chain,
        max_hop=max_hop
    )
