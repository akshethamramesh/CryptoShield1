import os
import requests
from collections import Counter, deque
from dotenv import load_dotenv


# ============================================================
# ENVIRONMENT / API KEY
# ============================================================

load_dotenv()

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

# Streamlit Cloud support
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

# Maximum number of connected wallets explored from one wallet
MAX_WALLETS_PER_NODE = 3

# Maximum transactions collected per wallet
MAX_TRANSFERS_PER_WALLET = 50

# Maximum token transactions collected per wallet
MAX_TOKEN_TRANSFERS_PER_WALLET = 50

# Number of API pages
MAX_PAGES = 1

REQUEST_TIMEOUT = 10


# ============================================================
# CACHE
# ============================================================

transaction_cache = {}


# ============================================================
# ADDRESS NORMALIZATION
# ============================================================

def normalize_address(address):
    """
    Normalize blockchain wallet address.
    """
    if not address:
        return ""

    return address.strip().lower()


# ============================================================
# ETHERSCAN API REQUEST
# ============================================================

def etherscan_request(params):
    """
    Send request to Etherscan V2 API.
    """

    if not ETHERSCAN_API_KEY:
        print("ERROR: ETHERSCAN_API_KEY not found.")
        return []

    try:
        response = requests.get(
            ETHERSCAN_V2_URL,
            params=params,
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        data = response.json()

        result = data.get("result", [])

        if isinstance(result, list):
            return result

        return []

    except requests.exceptions.Timeout:
        print("Etherscan API timeout.")
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
# NORMAL / NATIVE TRANSACTIONS
# ============================================================

def get_normal_transactions(
    wallet,
    chain="Ethereum"
):
    """
    Get native cryptocurrency transactions
    for a wallet.
    """

    wallet = normalize_address(wallet)

    chain_id = CHAIN_IDS.get(
        chain,
        1
    )

    cache_key = (
        f"{chain}:{wallet}:normal"
    )

    if cache_key in transaction_cache:
        return transaction_cache[cache_key]

    all_transactions = []

    for page in range(
        1,
        MAX_PAGES + 1
    ):

        params = {
            "chainid": chain_id,
            "module": "account",
            "action": "txlist",
            "address": wallet,
            "startblock": 0,
            "endblock": 99999999,
            "page": page,
            "offset": MAX_TRANSFERS_PER_WALLET,
            "sort": "desc",
            "apikey": ETHERSCAN_API_KEY
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

        if len(result) < MAX_TRANSFERS_PER_WALLET:
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
    """
    Get ERC-20 token transactions
    for a wallet.
    """

    wallet = normalize_address(wallet)

    chain_id = CHAIN_IDS.get(
        chain,
        1
    )

    cache_key = (
        f"{chain}:{wallet}:token"
    )

    if cache_key in transaction_cache:
        return transaction_cache[cache_key]

    all_transactions = []

    for page in range(
        1,
        MAX_PAGES + 1
    ):

        params = {
            "chainid": chain_id,
            "module": "account",
            "action": "tokentx",
            "address": wallet,
            "startblock": 0,
            "endblock": 99999999,
            "page": page,
            "offset": MAX_TOKEN_TRANSFERS_PER_WALLET,
            "sort": "desc",
            "apikey": ETHERSCAN_API_KEY
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

        if len(result) < MAX_TOKEN_TRANSFERS_PER_WALLET:
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
# TRANSACTION DEDUPLICATION
# ============================================================

def deduplicate_transactions(
    transactions
):
    """
    Remove duplicate transactions.

    Native transactions use:
        hash + type

    Token transactions use:
        hash + logIndex + type
    """

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

        seen.add(identifier)

        unique_transactions.append(
            tx
        )

    return unique_transactions


# ============================================================
# COMBINED WALLET TRANSACTIONS
# ============================================================

def get_wallet_transactions(
    wallet,
    chain="Ethereum",
    include_tokens=True
):
    """
    Get native + token transactions
    for a wallet.
    """

    wallet = normalize_address(wallet)

    cache_key = (
        f"{chain}:{wallet}:combined"
    )

    if cache_key in transaction_cache:
        return transaction_cache[cache_key]

    transactions = []

    # Native transactions
    native_transactions = (
        get_normal_transactions(
            wallet,
            chain
        )
    )

    transactions.extend(
        native_transactions
    )

    # Token transactions
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

    # Remove duplicates
    transactions = (
        deduplicate_transactions(
            transactions
        )
    )

    # Latest first
    transactions.sort(
        key=lambda tx: int(
            tx.get(
                "timeStamp",
                0
            ) or 0
        ),
        reverse=True
    )

    transaction_cache[
        cache_key
    ] = transactions

    return transactions


# ============================================================
# CONNECTED WALLETS
# ============================================================

def find_connected_wallets(
    transactions,
    current_wallet
):
    """
    Find wallets directly connected to
    current_wallet.

    IMPORTANT:
    This function only discovers candidate
    neighbours.

    It does NOT create graph edges.

    Actual graph direction is always taken from:

        transaction.from
                ↓
        transaction.to
    """

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

        # Incoming transaction:
        #
        # sender → current wallet
        #
        if (
            sender
            and sender != current_wallet
        ):
            wallet_counter[sender] += 1

        # Outgoing transaction:
        #
        # current wallet → receiver
        #
        if (
            receiver
            and receiver != current_wallet
        ):
            wallet_counter[receiver] += 1

    ranked_wallets = [
        wallet
        for wallet, count
        in wallet_counter.most_common(
            MAX_WALLETS_PER_NODE
        )
    ]

    return ranked_wallets


# ============================================================
# CREATE REAL TRANSACTION EDGES
# ============================================================

def build_transaction_edges(
    transactions
):
    """
    Build graph edges directly from
    blockchain transaction direction.

    Every edge is:

        transaction.from → transaction.to

    No artificial direction is created.
    """

    edges = []

    seen = set()

    if not transactions:
        return edges

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

        if not sender or not receiver:
            continue

        if sender == receiver:
            continue

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

        edge_id = (
            sender,
            receiver,
            tx_hash,
            log_index,
            tx_type
        )

        if edge_id in seen:
            continue

        seen.add(edge_id)

        edges.append(
            {
                "from": sender,
                "to": receiver,
                "tx_hash": tx_hash,
                "log_index": log_index,
                "type": tx_type,
                "value": tx.get(
                    "value",
                    0
                ),
                "timestamp": tx.get(
                    "timeStamp",
                    0
                )
            }
        )

    return edges


# ============================================================
# BFS HOP ASSIGNMENT
# ============================================================

def assign_wallet_hops(
    start_wallet,
    transactions,
    max_hop=2
):
    """
    Assign hop levels using BFS.

    Hop 0:
        Reported wallet

    Hop 1:
        Wallets directly connected to Hop 0

    Hop 2:
        Wallets connected to Hop 1

    Hop 3:
        Wallets connected to Hop 2

    Direction is NOT changed here.

    The hop calculation simply determines
    network distance from the reported wallet.
    """

    start_wallet = normalize_address(
        start_wallet
    )

    if not start_wallet:
        return {}

    edges = build_transaction_edges(
        transactions
    )

    # Build an undirected neighbour map
    # ONLY for discovering network distance.
    #
    # The actual graph arrows remain:
    #
    # from → to
    #
    neighbours = {}

    for edge in edges:

        sender = edge["from"]
        receiver = edge["to"]

        neighbours.setdefault(
            sender,
            set()
        ).add(receiver)

        neighbours.setdefault(
            receiver,
            set()
        ).add(sender)

    queue = deque()

    queue.append(
        (
            start_wallet,
            0
        )
    )

    wallet_hops = {
        start_wallet: 0
    }

    while queue:

        wallet, hop = queue.popleft()

        if hop >= max_hop:
            continue

        for neighbour in neighbours.get(
            wallet,
            set()
        ):

            if neighbour in wallet_hops:
                continue

            next_hop = hop + 1

            wallet_hops[
                neighbour
            ] = next_hop

            queue.append(
                (
                    neighbour,
                    next_hop
                )
            )

    return wallet_hops


# ============================================================
# FILTER EDGES INSIDE TRACED NETWORK
# ============================================================

def build_traced_connections(
    transactions,
    wallet_hops
):
    """
    Create final graph connections.

    Direction ALWAYS follows:

        transaction.from → transaction.to

    Hop is calculated from BFS distance.
    """

    edges = []

    seen = set()

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

        if not sender or not receiver:
            continue

        if sender == receiver:
            continue

        # Both wallets must be part
        # of the traced network.
        if sender not in wallet_hops:
            continue

        if receiver not in wallet_hops:
            continue

        sender_hop = wallet_hops[
            sender
        ]

        receiver_hop = wallet_hops[
            receiver
        ]

        # Edge belongs to the network
        # around the maximum traced hop.
        edge_hop = max(
            sender_hop,
            receiver_hop
        )

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

        edge_id = (
            sender,
            receiver,
            tx_hash,
            log_index,
            tx_type
        )

        if edge_id in seen:
            continue

        seen.add(edge_id)

        edges.append(
            {
                "from": sender,
                "to": receiver,
                "hop": edge_hop,
                "from_hop": sender_hop,
                "to_hop": receiver_hop,
                "tx_hash": tx_hash,
                "log_index": log_index,
                "type": tx_type,
                "value": tx.get(
                    "value",
                    0
                ),
                "timestamp": tx.get(
                    "timeStamp",
                    0
                )
            }
        )

    return edges


# ============================================================
# MAIN MULTI-HOP WALLET TRACE
# ============================================================

def trace_wallet(
    start_wallet,
    chain="Ethereum",
    max_hop=2
):
    """
    Main CryptoShield blockchain investigation.

    Workflow:

        Reported Wallet
              ↓
        Blockchain Data
              ↓
        BFS Hop Discovery
              ↓
        Transaction.from → Transaction.to
              ↓
        Correct Fund-Flow Connections
    """

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
    # STEP 1
    # Collect initial wallet transactions
    # --------------------------------------------------------

    start_transactions = (
        get_wallet_transactions(
            start_wallet,
            chain=chain,
            include_tokens=True
        )
    )

    print()
    print(
        "[Hop 0] Analysing:",
        start_wallet
    )

    print(
        "Transactions:",
        len(start_transactions)
    )

    # --------------------------------------------------------
    # STEP 2
    # Discover BFS wallet network
    #
    # This uses transaction participants only
    # to determine network distance.
    # --------------------------------------------------------

    wallet_hops = assign_wallet_hops(
        start_wallet,
        start_transactions,
        max_hop=max_hop
    )

    # --------------------------------------------------------
    # STEP 3
    # Analyse every discovered wallet
    # --------------------------------------------------------

    all_transactions = []

    visited = []

    queue = deque()

    queue.append(
        (
            start_wallet,
            0
        )
    )

    processed = set()

    while queue:

        wallet, hop = queue.popleft()

        wallet = normalize_address(
            wallet
        )

        if wallet in processed:
            continue

        processed.add(wallet)

        actual_hop = wallet_hops.get(
            wallet,
            hop
        )

        visited.append(wallet)

        print()
        print(
            f"[Hop {actual_hop}] Analysing:",
            wallet
        )

        transactions = (
            get_wallet_transactions(
                wallet,
                chain=chain,
                include_tokens=True
            )
        )

        print(
            "Transactions:",
            len(transactions)
        )

        # Add traced-wallet and hop metadata
        for tx in transactions:

            tx_copy = tx.copy()

            tx_copy[
                "traced_wallet"
            ] = wallet

            tx_copy[
                "hop"
            ] = actual_hop

            all_transactions.append(
                tx_copy
            )

        if actual_hop >= max_hop:

            print(
                f"Maximum hop {max_hop} reached."
            )

            continue

        connected_wallets = (
            find_connected_wallets(
                transactions,
                wallet
            )
        )

        print(
            "Top connected wallets:",
            len(connected_wallets)
        )

        for connected_wallet in connected_wallets:

            connected_wallet = (
                normalize_address(
                    connected_wallet
                )
            )

            if not connected_wallet:
                continue

            if connected_wallet == wallet:
                continue

            next_hop = actual_hop + 1

            if next_hop > max_hop:
                continue

            # Do NOT create a graph edge here.
            #
            # This is only a BFS queue operation.
            #
            # Actual graph edge will later be taken
            # directly from transaction.from/to.

            if (
                connected_wallet
                not in wallet_hops
            ):

                wallet_hops[
                    connected_wallet
                ] = next_hop

            if (
                connected_wallet
                not in processed
            ):

                queue.append(
                    (
                        connected_wallet,
                        next_hop
                    )
                )

    # --------------------------------------------------------
    # STEP 4
    # Deduplicate all transactions
    # --------------------------------------------------------

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
            ) or 0
        ),
        reverse=True
    )

    # --------------------------------------------------------
    # STEP 5
    # Recalculate BFS hops using complete data
    #
    # This improves accuracy because discovered wallets
    # may contain additional connections.
    # --------------------------------------------------------

    final_wallet_hops = assign_wallet_hops(
        start_wallet,
        all_transactions,
        max_hop=max_hop
    )

    # Make sure reported wallet is always Hop 0
    final_wallet_hops[
        start_wallet
    ] = 0

    # --------------------------------------------------------
    # STEP 6
    # Build technically correct transaction edges
    #
    # IMPORTANT:
    #
    # NEVER:
    #
    # current_wallet → connected_wallet
    #
    # unless transaction.from confirms it.
    #
    # ALWAYS:
    #
    # transaction.from → transaction.to
    # --------------------------------------------------------

    connections = (
        build_traced_connections(
            all_transactions,
            final_wallet_hops
        )
    )

    # --------------------------------------------------------
    # STEP 7
    # Final wallet list
    # --------------------------------------------------------

    visited_wallets = list(
        final_wallet_hops.keys()
    )

    # Keep deterministic order by hop
    visited_wallets.sort(
        key=lambda wallet: (
            final_wallet_hops.get(
                wallet,
                999
            ),
            wallet
        )
    )

    # --------------------------------------------------------
    # STEP 8
    # Connected wallets excludes reported wallet
    # --------------------------------------------------------

    connected_wallets = [
        wallet
        for wallet in visited_wallets
        if wallet != start_wallet
    ]

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    result = {

        "start_wallet":
            start_wallet,

        "chain":
            chain,

        "transactions":
            all_transactions,

        "visited_wallets":
            visited_wallets,

        "connected_wallets":
            connected_wallets,

        "wallet_hops":
            final_wallet_hops,

        "connections":
            connections,

        "max_hop":
            max_hop
    }

    # --------------------------------------------------------
    # CONSOLE SUMMARY
    # --------------------------------------------------------

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
        len(visited_wallets)
    )

    print(
        "Transactions analysed:",
        len(all_transactions)
    )

    print(
        "Correct graph connections:",
        len(connections)
    )

    print(
        "=========================================="
    )

    print()
    print(
        "Wallet Hop Structure:"
    )

    for wallet in visited_wallets:

        hop = final_wallet_hops.get(
            wallet,
            0
        )

        print(
            f"Hop {hop}: {wallet}"
        )

    print()
    print(
        "Transaction Flow:"
    )

    for connection in connections:

        print(
            f"Hop {connection['hop']}: "
            f"{connection['from']} "
            f"-> "
            f"{connection['to']}"
        )

    print()

    return result


# ============================================================
# COMPATIBILITY WRAPPER
# ============================================================

def recursive_trace(
    wallet,
    chain="Ethereum",
    max_hop=2
):
    """
    Backward-compatible wrapper.
    """

    return trace_wallet(
        start_wallet=wallet,
        chain=chain,
        max_hop=max_hop
    )


# ============================================================
# CACHE MANAGEMENT
# ============================================================

def clear_transaction_cache():
    """
    Clear blockchain transaction cache.
    """

    transaction_cache.clear()

    print(
        "CryptoShield transaction cache cleared."
    )


def clear_cache():
    """
    Compatibility wrapper used by app.py.
    """

    clear_transaction_cache()


def get_cache_size():
    """
    Return number of cached datasets.
    """

    return len(
        transaction_cache
    )


# ============================================================
# DIRECT TERMINAL TEST
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

    print()
    print(
        "=========================================="
    )
    print(
        "FINAL WALLET ANALYSIS"
    )
    print(
        "=========================================="
    )

    print(
        "\nWallets discovered:"
    )

    for wallet_address in result[
        "visited_wallets"
    ]:

        hop = result[
            "wallet_hops"
        ].get(
            wallet_address,
            0
        )

        print(
            f"Hop {hop}: "
            f"{wallet_address}"
        )

    print(
        "\nCorrect Blockchain Flow:"
    )

    for connection in result[
        "connections"
    ]:

        print(
            f"Hop {connection['hop']}: "
            f"{connection['from']} "
            f"-> "
            f"{connection['to']}"
        )

    print(
        "\nTotal transactions:",
        len(
            result[
                "transactions"
            ]
        )
    )

    print(
        "\nTotal wallets:",
        len(
            result[
                "visited_wallets"
            ]
        )
    )

    print(
        "\nTotal graph connections:",
        len(
            result[
                "connections"
            ]
        )
    )
