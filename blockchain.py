import os
import requests
from collections import Counter, deque
from dotenv import load_dotenv


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

# Streamlit Cloud Secrets support
try:
    import streamlit as st

    if not ETHERSCAN_API_KEY:
        ETHERSCAN_API_KEY = st.secrets.get(
            "ETHERSCAN_API_KEY",
            ""
        )

except Exception:
    pass


# ============================================================
# CONFIGURATION
# ============================================================

ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"

CHAIN_IDS = {
    "Ethereum": 1,
    "BSC": 56
}

MAX_WALLETS_PER_NODE = 3

MAX_TRANSFERS_PER_WALLET = 50

MAX_TOKEN_TRANSFERS_PER_WALLET = 50

MAX_PAGES = 1

REQUEST_TIMEOUT = 10


# ============================================================
# CACHE
# ============================================================

transaction_cache = {}


# ============================================================
# NORMALIZE ADDRESS
# ============================================================

def normalize_address(address):

    if not address:
        return ""

    return address.strip().lower()


# ============================================================
# ETHERSCAN API REQUEST
# ============================================================

def etherscan_request(params):

    if not ETHERSCAN_API_KEY:

        print(
            "ERROR: ETHERSCAN_API_KEY not found."
        )

        return []

    try:

        response = requests.get(
            ETHERSCAN_V2_URL,
            params=params,
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        data = response.json()

        result = data.get(
            "result",
            []
        )

        if isinstance(result, list):

            return result

        return []

    except requests.exceptions.Timeout:

        print(
            "Etherscan API timeout."
        )

        return []

    except requests.exceptions.RequestException as error:

        print(
            "Etherscan API request error:",
            error
        )

        return []

    except Exception as error:

        print(
            "Unexpected API error:",
            error
        )

        return []


# ============================================================
# NORMAL TRANSACTIONS
# ============================================================

def get_normal_transactions(
    wallet,
    chain="Ethereum"
):

    wallet = normalize_address(
        wallet
    )

    chain_id = CHAIN_IDS.get(
        chain,
        1
    )

    cache_key = (
        f"{chain}:{wallet}:normal"
    )

    if cache_key in transaction_cache:

        return transaction_cache[
            cache_key
        ]

    all_transactions = []

    for page in range(
        1,
        MAX_PAGES + 1
    ):

        params = {

            "chainid":
                chain_id,

            "module":
                "account",

            "action":
                "txlist",

            "address":
                wallet,

            "startblock":
                0,

            "endblock":
                99999999,

            "page":
                page,

            "offset":
                MAX_TRANSFERS_PER_WALLET,

            "sort":
                "desc",

            "apikey":
                ETHERSCAN_API_KEY
        }

        result = etherscan_request(
            params
        )

        if not result:

            break

        for tx in result:

            tx["type"] = "native"

            try:

                raw_value = int(
                    tx.get(
                        "value",
                        0
                    )
                )

                tx["value"] = (
                    raw_value / 10**18
                )

            except Exception:

                tx["value"] = 0

        all_transactions.extend(
            result
        )

        if len(result) < (
            MAX_TRANSFERS_PER_WALLET
        ):

            break

    all_transactions = (
        all_transactions[
            :MAX_TRANSFERS_PER_WALLET
        ]
    )

    transaction_cache[
        cache_key
    ] = all_transactions

    return all_transactions


# ============================================================
# TOKEN TRANSACTIONS
# ============================================================

def get_token_transactions(
    wallet,
    chain="Ethereum"
):

    wallet = normalize_address(
        wallet
    )

    chain_id = CHAIN_IDS.get(
        chain,
        1
    )

    cache_key = (
        f"{chain}:{wallet}:token"
    )

    if cache_key in transaction_cache:

        return transaction_cache[
            cache_key
        ]

    all_transactions = []

    for page in range(
        1,
        MAX_PAGES + 1
    ):

        params = {

            "chainid":
                chain_id,

            "module":
                "account",

            "action":
                "tokentx",

            "address":
                wallet,

            "startblock":
                0,

            "endblock":
                99999999,

            "page":
                page,

            "offset":
                MAX_TOKEN_TRANSFERS_PER_WALLET,

            "sort":
                "desc",

            "apikey":
                ETHERSCAN_API_KEY
        }

        result = etherscan_request(
            params
        )

        if not result:

            break

        for tx in result:

            tx["type"] = "token"

            try:

                raw_value = int(
                    tx.get(
                        "value",
                        0
                    )
                )

                decimals = int(
                    tx.get(
                        "tokenDecimal",
                        18
                    )
                )

                tx["value"] = (
                    raw_value /
                    (10 ** decimals)
                )

            except Exception:

                tx["value"] = 0

        all_transactions.extend(
            result
        )

        if len(result) < (
            MAX_TOKEN_TRANSFERS_PER_WALLET
        ):

            break

    all_transactions = (
        all_transactions[
            :MAX_TOKEN_TRANSFERS_PER_WALLET
        ]
    )

    transaction_cache[
        cache_key
    ] = all_transactions

    return all_transactions


# ============================================================
# DEDUPLICATE TRANSACTIONS
# ============================================================

def deduplicate_transactions(
    transactions
):

    seen = set()

    unique_transactions = []

    for tx in transactions:

        tx_hash = tx.get(
            "hash",
            ""
        )

        log_index = tx.get(
            "logIndex",
            ""
        )

        tx_type = tx.get(
            "type",
            "native"
        )

        identifier = (
            tx_hash,
            log_index,
            tx_type
        )

        if identifier in seen:

            continue

        seen.add(
            identifier
        )

        unique_transactions.append(
            tx
        )

    return unique_transactions


# ============================================================
# GET WALLET TRANSACTIONS
# ============================================================

def get_wallet_transactions(
    wallet,
    chain="Ethereum",
    include_tokens=True
):

    wallet = normalize_address(
        wallet
    )

    cache_key = (
        f"{chain}:{wallet}:combined"
    )

    if cache_key in transaction_cache:

        return transaction_cache[
            cache_key
        ]

    transactions = []

    # --------------------------------------------------------
    # Native transactions
    # --------------------------------------------------------

    native_transactions = (
        get_normal_transactions(
            wallet,
            chain
        )
    )

    transactions.extend(
        native_transactions
    )

    # --------------------------------------------------------
    # Token transactions
    # --------------------------------------------------------

    if include_tokens:

        token_transactions = (
            get_token_transactions(
                wallet,
                chain
            )
        )

        transactions.extend(
            token_transactions
        )

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    transactions = (
        deduplicate_transactions(
            transactions
        )
    )

    # --------------------------------------------------------
    # Sort latest first
    # --------------------------------------------------------

    transactions.sort(
        key=lambda tx: int(
            tx.get(
                "timeStamp",
                0
            )
        ),
        reverse=True
    )

    transaction_cache[
        cache_key
    ] = transactions

    return transactions


# ============================================================
# FIND CONNECTED WALLETS
# ============================================================

def find_connected_wallets(
    transactions,
    current_wallet
):

    current_wallet = normalize_address(
        current_wallet
    )

    wallet_counter = Counter()

    for tx in transactions:

        sender = normalize_address(
            tx.get(
                "from",
                ""
            )
        )

        receiver = normalize_address(
            tx.get(
                "to",
                ""
            )
        )

        if (
            sender
            and sender != current_wallet
        ):

            wallet_counter[
                sender
            ] += 1

        if (
            receiver
            and receiver != current_wallet
        ):

            wallet_counter[
                receiver
            ] += 1

    ranked_wallets = [

        wallet

        for wallet, count
        in wallet_counter.most_common(
            MAX_WALLETS_PER_NODE
        )

    ]

    return ranked_wallets


# ============================================================
# TRACE WALLET
# ============================================================

def trace_wallet(
    start_wallet,
    chain="Ethereum",
    max_hop=2
):

    start_wallet = normalize_address(
        start_wallet
    )

    if not start_wallet:

        return {
            "start_wallet": "",
            "chain": chain,
            "transactions": [],
            "visited_wallets": [],
            "connected_wallets": [],
            "wallet_hops": {},
            "connections": [],
            "max_hop": max_hop
        }

    # --------------------------------------------------------
    # BFS structures
    # --------------------------------------------------------

    queue = deque()

    queue.append(
        (
            start_wallet,
            0
        )
    )

    visited = set()

    wallet_hops = {}

    all_transactions = []

    connections = []

    # --------------------------------------------------------
    # Console information
    # --------------------------------------------------------

    print()
    print(
        "=========================================="
    )
    print(
        " CryptoShield Multi-Hop Tracing"
    )
    print(
        "=========================================="
    )
    print(
        "Reported Wallet:",
        start_wallet
    )
    print(
        "Blockchain:",
        chain
    )
    print(
        "Maximum Hop:",
        max_hop
    )
    print(
        "=========================================="
    )

    # --------------------------------------------------------
    # BFS
    # --------------------------------------------------------

    while queue:

        wallet, hop = queue.popleft()

        wallet = normalize_address(
            wallet
        )

        if wallet in visited:

            continue

        visited.add(
            wallet
        )

        wallet_hops[
            wallet
        ] = hop

        print(
            f"\n[Hop {hop}] Analysing: {wallet}"
        )

        # ----------------------------------------------------
        # Fetch transactions
        # ----------------------------------------------------

        transactions = (
            get_wallet_transactions(
                wallet,
                chain=chain,
                include_tokens=True
            )
        )

        print(
            f"Transactions: {len(transactions)}"
        )

        # ----------------------------------------------------
        # Attach tracing metadata
        # ----------------------------------------------------

        for tx in transactions:

            tx_copy = tx.copy()

            tx_copy[
                "traced_wallet"
            ] = wallet

            tx_copy[
                "hop"
            ] = hop

            all_transactions.append(
                tx_copy
            )

        # ----------------------------------------------------
        # Maximum hop
        # ----------------------------------------------------

        if hop >= max_hop:

            print(
                f"Maximum hop {max_hop} reached."
            )

            continue

        # ----------------------------------------------------
        # Connected wallets
        # ----------------------------------------------------

        connected_wallets = (
            find_connected_wallets(
                transactions,
                wallet
            )
        )

        print(
            "Top connected wallets:",
            len(
                connected_wallets
            )
        )

        # ----------------------------------------------------
        # Graph connections
        # ----------------------------------------------------

        for connected_wallet in (
            connected_wallets
        ):

            connected_wallet = normalize_address(
                connected_wallet
            )

            if not connected_wallet:

                continue

            if connected_wallet == wallet:

                continue

            connection = {

                "from":
                    wallet,

                "to":
                    connected_wallet,

                "hop":
                    hop + 1
            }

            edge_exists = any(

                existing["from"]
                == connection["from"]

                and

                existing["to"]
                == connection["to"]

                and

                existing["hop"]
                == connection["hop"]

                for existing in connections
            )

            if not edge_exists:

                connections.append(
                    connection
                )

            if connected_wallet not in visited:

                queue.append(
                    (
                        connected_wallet,
                        hop + 1
                    )
                )

    # ========================================================
    # FINAL CLEANUP
    # ========================================================

    all_transactions = (
        deduplicate_transactions(
            all_transactions
        )
    )

    all_transactions.sort(
        key=lambda tx: int(
            tx.get(
                "timeStamp",
                0
            )
        ),
        reverse=True
    )

    # ========================================================
    # RESULT
    # ========================================================

    result = {

        "start_wallet":
            start_wallet,

        "chain":
            chain,

        "transactions":
            all_transactions,

        "visited_wallets":
            list(visited),

        "connected_wallets":
            list(visited),

        "wallet_hops":
            wallet_hops,

        "connections":
            connections,

        "max_hop":
            max_hop
    }

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print(
        "=========================================="
    )
    print(
        " CryptoShield Tracing Completed"
    )
    print(
        "=========================================="
    )

    print(
        "Wallets analysed:",
        len(visited)
    )

    print(
        "Transactions analysed:",
        len(all_transactions)
    )

    print(
        "Graph connections:",
        len(connections)
    )

    print(
        "=========================================="
    )

    for wallet, wallet_hop in (
        wallet_hops.items()
    ):

        print(
            f"Hop {wallet_hop}: {wallet}"
        )

    return result


# ============================================================
# COMPATIBILITY FUNCTION
# ============================================================

def recursive_trace(
    wallet,
    chain="Ethereum",
    max_hop=2
):

    return trace_wallet(
        start_wallet=wallet,
        chain=chain,
        max_hop=max_hop
    )


# ============================================================
# CLEAR CACHE
# ============================================================

def clear_transaction_cache():

    transaction_cache.clear()

    print(
        "CryptoShield transaction cache cleared."
    )


# ============================================================
# IMPORTANT:
# app.py expects clear_cache()
# ============================================================

def clear_cache():

    clear_transaction_cache()


# ============================================================
# CACHE SIZE
# ============================================================

def get_cache_size():

    return len(
        transaction_cache
    )


# ============================================================
# TEST MODE
# ============================================================

if __name__ == "__main__":

    wallet = input(
        "Enter Ethereum wallet address: "
    ).strip()

    if not wallet:

        print(
            "Wallet address is required."
        )

        raise SystemExit

    result = trace_wallet(
        wallet,
        chain="Ethereum",
        max_hop=2
    )

    print(
        "\nWallets discovered:"
    )

    for wallet_address in (
        result["visited_wallets"]
    ):

        hop = result[
            "wallet_hops"
        ].get(
            wallet_address,
            0
        )

        print(
            f"Hop {hop}: {wallet_address}"
        )

    print(
        "\nGraph connections:"
    )

    for connection in (
        result["connections"]
    ):

        print(
            f"Hop {connection['hop']}: "
            f"{connection['from']} -> "
            f"{connection['to']}"
        )

    print(
        "\nTotal transactions:",
        len(
            result["transactions"]
        )
    )
