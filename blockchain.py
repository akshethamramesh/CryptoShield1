import os
import requests
from collections import Counter, deque
from dotenv import load_dotenv


# ============================================================
# CRYPTOSHIELD - BLOCKCHAIN ANALYTICS ENGINE
# ============================================================
#
# Workflow:
#
# Victim Reported Wallet
#          |
#        Hop 0
#          |
#     Blockchain TX
#          |
#        Hop 1
#          |
#     Blockchain TX
#          |
#        Hop 2
#          |
#     Blockchain TX
#          |
#        Hop 3
#
# IMPORTANT:
# Graph direction is ALWAYS taken from:
#
# transaction["from"] -> transaction["to"]
#
# BFS is used only to calculate hop distance.
#
# ============================================================


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()

ETHERSCAN_API_KEY = os.getenv(
    "ETHERSCAN_API_KEY"
)

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

ETHERSCAN_V2_URL = (
    "https://api.etherscan.io/v2/api"
)

CHAIN_IDS = {
    "Ethereum": 1,
    "BSC": 56
}

# Maximum number of wallets selected
# from each wallet during BFS discovery.
MAX_WALLETS_PER_NODE = 3

# Maximum native transactions per wallet.
MAX_TRANSFERS_PER_WALLET = 50

# Maximum token transactions per wallet.
MAX_TOKEN_TRANSFERS_PER_WALLET = 50

MAX_PAGES = 1

REQUEST_TIMEOUT = 15


# ============================================================
# CACHE
# ============================================================

transaction_cache = {}


# ============================================================
# ADDRESS NORMALIZATION
# ============================================================

def normalize_address(address):

    if not address:
        return ""

    return address.strip().lower()


# ============================================================
# ETHERSCAN API
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
# NATIVE TRANSACTIONS
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

            "chainid": chain_id,

            "module": "account",

            "action": "txlist",

            "address": wallet,

            "startblock": 0,

            "endblock": 99999999,

            "page": page,

            "offset":
                MAX_TRANSFERS_PER_WALLET,

            "sort": "desc",

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

            "chainid": chain_id,

            "module": "account",

            "action": "tokentx",

            "address": wallet,

            "startblock": 0,

            "endblock": 99999999,

            "page": page,

            "offset":
                MAX_TOKEN_TRANSFERS_PER_WALLET,

            "sort": "desc",

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
# GET ALL WALLET TRANSACTIONS
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

    # Native
    native_transactions = (
        get_normal_transactions(
            wallet,
            chain
        )
    )

    transactions.extend(
        native_transactions
    )

    # Token
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

    transactions = (
        deduplicate_transactions(
            transactions
        )
    )

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
# BUILD TRANSACTION GRAPH
# ============================================================

def build_transaction_graph(
    transactions
):
    """
    Build the REAL blockchain transaction graph.

    Every edge is:

        FROM -> TO

    directly from blockchain transaction data.
    """

    graph = {}

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

        if not sender:
            continue

        if not receiver:
            continue

        if sender == receiver:
            continue

        if sender not in graph:

            graph[sender] = set()

        if receiver not in graph:

            graph[receiver] = set()

        # Undirected relationship for
        # BFS hop discovery.
        #
        # IMPORTANT:
        # This does NOT change the actual
        # transaction direction.
        graph[sender].add(
            receiver
        )

        graph[receiver].add(
            sender
        )

    return graph


# ============================================================
# BFS HOP CALCULATION
# ============================================================

def calculate_wallet_hops(
    start_wallet,
    transactions,
    max_hop=3
):
    """
    Calculate hop distance from reported wallet.

    Hop 0 = reported wallet

    Hop 1 = directly connected wallet

    Hop 2 = two connections away

    Hop 3 = three connections away

    BFS treats relationships as undirected
    ONLY for calculating distance.

    Actual arrows are NOT created here.
    """

    start_wallet = normalize_address(
        start_wallet
    )

    if not start_wallet:

        return {}

    graph = build_transaction_graph(
        transactions
    )

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

        current_wallet, current_hop = (
            queue.popleft()
        )

        if current_hop >= max_hop:
            continue

        neighbours = graph.get(
            current_wallet,
            set()
        )

        for neighbour in neighbours:

            if neighbour in wallet_hops:
                continue

            next_hop = (
                current_hop + 1
            )

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
# REAL FUND FLOW EDGES
# ============================================================

def build_fund_flow_connections(
    transactions,
    wallet_hops,
    max_hop=3
):
    """
    Build visually correct fund-flow edges.

    Direction:

        transaction.from
                ↓
        transaction.to

    Hop is based on BFS distance.

    Example:

        Reported Wallet
             ↓
          Hop 1
             ↓
          Wallet B
             ↓
          Hop 2
             ↓
          Wallet C

    """

    connections = []

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

        if not sender:
            continue

        if not receiver:
            continue

        if sender == receiver:
            continue

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

        # Ignore connections beyond
        # requested maximum hop.
        if sender_hop > max_hop:
            continue

        if receiver_hop > max_hop:
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

        seen.add(
            edge_id
        )

        # Connection hop represents
        # the furthest node involved.
        connection_hop = max(
            sender_hop,
            receiver_hop
        )

        connections.append(
            {

                # REAL BLOCKCHAIN DIRECTION
                "from": sender,

                "to": receiver,

                # Hop information
                "hop": connection_hop,

                "from_hop":
                    sender_hop,

                "to_hop":
                    receiver_hop,

                # Transaction information
                "tx_hash":
                    tx_hash,

                "log_index":
                    log_index,

                "type":
                    tx_type,

                "value":
                    tx.get(
                        "value",
                        0
                    ),

                "timestamp":
                    tx.get(
                        "timeStamp",
                        0
                    )
            }
        )

    return connections


# ============================================================
# DISCOVER NEXT WALLETS
# ============================================================

def find_connected_wallets(
    transactions,
    current_wallet
):
    """
    Find candidate neighbouring wallets.

    This function does NOT create arrows.

    It is used only to decide which wallets
    should be investigated next.
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

        # Incoming
        if (
            sender
            and sender != current_wallet
        ):

            wallet_counter[
                sender
            ] += 1

        # Outgoing
        if (
            receiver
            and receiver != current_wallet
        ):

            wallet_counter[
                receiver
            ] += 1

    return [
        wallet
        for wallet, count
        in wallet_counter.most_common(
            MAX_WALLETS_PER_NODE
        )
    ]


# ============================================================
# MAIN TRACE FUNCTION
# ============================================================

def trace_wallet(
    start_wallet,
    chain="Ethereum",
    max_hop=3
):
    """
    Complete CryptoShield multi-hop investigation.
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
        "=================================================="
    )
    print(
        "       CRYPTOSHIELD MULTI-HOP BLOCKCHAIN"
    )
    print(
        "=================================================="
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
        "=================================================="
    )

    # --------------------------------------------------------
    # STEP 1
    # BFS queue
    # --------------------------------------------------------

    queue = deque()

    queue.append(
        (
            start_wallet,
            0
        )
    )

    processed = set()

    wallet_hops = {
        start_wallet: 0
    }

    all_transactions = []

    # --------------------------------------------------------
    # STEP 2
    # Explore wallets
    # --------------------------------------------------------

    while queue:

        current_wallet, current_hop = (
            queue.popleft()
        )

        current_wallet = normalize_address(
            current_wallet
        )

        if current_wallet in processed:
            continue

        processed.add(
            current_wallet
        )

        print()
        print(
            "--------------------------------------------------"
        )

        print(
            f"[HOP {current_hop}]"
        )

        print(
            "Wallet:",
            current_wallet
        )

        print(
            "--------------------------------------------------"
        )

        # ----------------------------------------------------
        # Collect transactions
        # ----------------------------------------------------

        transactions = (
            get_wallet_transactions(
                current_wallet,
                chain=chain,
                include_tokens=True
            )
        )

        print(
            "Transactions:",
            len(transactions)
        )

        # Add metadata
        for tx in transactions:

            tx_copy = tx.copy()

            tx_copy[
                "traced_wallet"
            ] = current_wallet

            tx_copy[
                "hop"
            ] = current_hop

            all_transactions.append(
                tx_copy
            )

        # ----------------------------------------------------
        # Stop at max hop
        # ----------------------------------------------------

        if current_hop >= max_hop:

            print(
                "Maximum hop reached."
            )

            continue

        # ----------------------------------------------------
        # Discover neighbouring wallets
        # ----------------------------------------------------

        connected_wallets = (
            find_connected_wallets(
                transactions,
                current_wallet
            )
        )

        print(
            "Candidate connected wallets:",
            len(connected_wallets)
        )

        for wallet in connected_wallets:

            wallet = normalize_address(
                wallet
            )

            if not wallet:
                continue

            if wallet == current_wallet:
                continue

            next_hop = (
                current_hop + 1
            )

            if next_hop > max_hop:
                continue

            if wallet not in wallet_hops:

                wallet_hops[
                    wallet
                ] = next_hop

                queue.append(
                    (
                        wallet,
                        next_hop
                    )
                )

    # --------------------------------------------------------
    # STEP 3
    # Deduplicate transactions
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

    print()
    print(
        "=================================================="
    )
    print(
        "Building final transaction network..."
    )
    print(
        "=================================================="
    )

    # --------------------------------------------------------
    # STEP 4
    # Recalculate hops from complete transaction set
    # --------------------------------------------------------

    final_wallet_hops = (
        calculate_wallet_hops(
            start_wallet,
            all_transactions,
            max_hop=max_hop
        )
    )

    # Always keep reported wallet Hop 0
    final_wallet_hops[
        start_wallet
    ] = 0

    # --------------------------------------------------------
    # STEP 5
    # Build REAL transaction arrows
    # --------------------------------------------------------

    connections = (
        build_fund_flow_connections(
            all_transactions,
            final_wallet_hops,
            max_hop=max_hop
        )
    )

    # --------------------------------------------------------
    # STEP 6
    # Sort wallets by hop
    # --------------------------------------------------------

    visited_wallets = list(
        final_wallet_hops.keys()
    )

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
    # Connected wallets
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

    # ========================================================
    # TERMINAL OUTPUT
    # ========================================================

    print()
    print(
        "=================================================="
    )
    print(
        "              HOP STRUCTURE"
    )
    print(
        "=================================================="
    )

    for hop_number in range(
        0,
        max_hop + 1
    ):

        wallets_at_hop = [

            wallet

            for wallet in visited_wallets

            if final_wallet_hops.get(
                wallet
            ) == hop_number
        ]

        if not wallets_at_hop:
            continue

        print()
        print(
            f"========== HOP {hop_number} =========="
        )

        for wallet in wallets_at_hop:

            print(
                wallet
            )

    # ========================================================
    # FUND FLOW OUTPUT
    # ========================================================

    print()
    print(
        "=================================================="
    )
    print(
        "             REAL FUND FLOW"
    )
    print(
        "=================================================="
    )

    if not connections:

        print(
            "No transaction connections found."
        )

    else:

        for connection in connections:

            print(
                f"[Hop {connection['hop']}] "
                f"{connection['from']} "
                f"-> "
                f"{connection['to']}"
            )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print(
        "=================================================="
    )
    print(
        "           CRYPTOSHIELD TRACE COMPLETE"
    )
    print(
        "=================================================="
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
        "Fund-flow connections:",
        len(connections)
    )

    print(
        "Maximum hop:",
        max_hop
    )

    print(
        "=================================================="
    )

    return result


# ============================================================
# COMPATIBILITY FUNCTION
# ============================================================

def recursive_trace(
    wallet,
    chain="Ethereum",
    max_hop=3
):

    return trace_wallet(
        start_wallet=wallet,
        chain=chain,
        max_hop=max_hop
    )


# ============================================================
# CACHE FUNCTIONS
# ============================================================

def clear_transaction_cache():

    transaction_cache.clear()

    print(
        "CryptoShield transaction cache cleared."
    )


def clear_cache():

    clear_transaction_cache()


def get_cache_size():

    return len(
        transaction_cache
    )


# ============================================================
# TERMINAL TEST
# ============================================================

if __name__ == "__main__":

    print()
    print(
        "=============================================="
    )
    print(
        "      CRYPTOSHIELD BLOCKCHAIN TEST"
    )
    print(
        "=============================================="
    )

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
        max_hop=3
    )

    print()
    print(
        "=============================================="
    )
    print(
        "FINAL GRAPH DATA"
    )
    print(
        "=============================================="
    )

    print()
    print(
        "Wallets:"
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

    print()
    print(
        "Connections:"
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

    print()
    print(
        "Total wallets:",
        len(
            result[
                "visited_wallets"
            ]
        )
    )

    print(
        "Total transactions:",
        len(
            result[
                "transactions"
            ]
        )
    )

    print(
        "Total connections:",
        len(
            result[
                "connections"
            ]
        )
    )
