import os
import requests
from dotenv import load_dotenv
from collections import defaultdict, deque

# ============================================================
# CRYPTOSHIELD - BSC WALLET INTELLIGENCE
# ============================================================

load_dotenv(".env")

API_KEY = os.getenv("ALCHEMY_API_KEY")

if not API_KEY:
    print("ERROR: ALCHEMY_API_KEY not found!")
    print("Check D:\\CryptoShield\\.env")
    exit()

BASE_URL = f"https://bnb-mainnet.g.alchemy.com/v2/{API_KEY}"


# ============================================================
# RPC REQUEST
# ============================================================

def rpc_request(method, params):

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    }

    try:

        response = requests.post(
            BASE_URL,
            json=payload,
            timeout=30
        )

        print("HTTP STATUS:", response.status_code)

        if response.status_code != 200:
            print("API ERROR:")
            print(response.text)
            return None

        data = response.json()

        if "error" in data:
            print("RPC ERROR:")
            print(data["error"])
            return None

        return data.get("result")

    except Exception as e:

        print("REQUEST ERROR:", e)
        return None


# ============================================================
# TEST CONNECTION
# ============================================================

def get_latest_block():

    result = rpc_request(
        "eth_blockNumber",
        []
    )

    if result:
        return int(result, 16)

    return None


# ============================================================
# GET TRANSFERS
# ============================================================

def get_transfers(wallet, direction, category):

    if direction == "from":

        address_filter = {
            "fromAddress": wallet
        }

    else:

        address_filter = {
            "toAddress": wallet
        }

    params = {
        **address_filter,

        "category": [
            category
        ],

        "withMetadata": True,

        "excludeZeroValue": True,

        "maxCount": "0x64"
    }

    result = rpc_request(
        "alchemy_getAssetTransfers",
        [params]
    )

    if result is None:
        return []

    return result.get(
        "transfers",
        []
    )


# ============================================================
# NORMALIZE TRANSACTION
# ============================================================

def normalize_transfer(tx, direction):

    return {
        "hash": tx.get(
            "hash",
            "N/A"
        ),

        "from": tx.get(
            "from",
            ""
        ),

        "to": tx.get(
            "to",
            ""
        ),

        "value": tx.get(
            "value",
            0
        ),

        "asset": tx.get(
            "asset",
            "UNKNOWN"
        ),

        "category": tx.get(
            "category",
            "UNKNOWN"
        ),

        "direction": direction,

        "block": tx.get(
            "blockNum",
            "UNKNOWN"
        ),

        "timestamp": tx.get(
            "metadata",
            {}
        ).get(
            "blockTimestamp",
            "UNKNOWN"
        )
    }


# ============================================================
# FETCH BSC WALLET HISTORY
# ============================================================

def get_wallet_history(wallet):

    print("\n======================================")
    print("FETCHING BSC WALLET HISTORY")
    print("======================================")

    transactions = []

    # IMPORTANT:
    # BSC Alchemy does NOT support "internal"
    # So we use only external + erc20.

    categories = [
        "external",
        "erc20"
    ]

    # --------------------------------------------------------
    # OUTGOING
    # --------------------------------------------------------

    for category in categories:

        print(
            f"\nChecking OUTGOING {category.upper()}..."
        )

        outgoing = get_transfers(
            wallet,
            "from",
            category
        )

        print(
            "Found:",
            len(outgoing)
        )

        for tx in outgoing:

            transactions.append(
                normalize_transfer(
                    tx,
                    "OUTGOING"
                )
            )

    # --------------------------------------------------------
    # INCOMING
    # --------------------------------------------------------

    for category in categories:

        print(
            f"\nChecking INCOMING {category.upper()}..."
        )

        incoming = get_transfers(
            wallet,
            "to",
            category
        )

        print(
            "Found:",
            len(incoming)
        )

        for tx in incoming:

            transactions.append(
                normalize_transfer(
                    tx,
                    "INCOMING"
                )
            )

    # --------------------------------------------------------
    # REMOVE DUPLICATES
    # --------------------------------------------------------

    unique = {}

    for tx in transactions:

        key = (
            tx["hash"],
            tx["from"],
            tx["to"],
            tx["asset"]
        )

        unique[key] = tx

    return list(
        unique.values()
    )


# ============================================================
# DISPLAY TRANSACTIONS
# ============================================================

def display_transactions(transactions):

    print("\n======================================")
    print("REAL BSC TRANSACTIONS")
    print("======================================")

    if not transactions:

        print("\nNo transactions found.")

        return

    for number, tx in enumerate(
        transactions,
        start=1
    ):

        print(
            f"\nTransaction #{number}"
        )

        print(
            "Hash      :",
            tx["hash"]
        )

        print(
            "From      :",
            tx["from"]
        )

        print(
            "To        :",
            tx["to"]
        )

        print(
            "Value     :",
            tx["value"]
        )

        print(
            "Asset     :",
            tx["asset"]
        )

        print(
            "Category  :",
            tx["category"]
        )

        print(
            "Direction :",
            tx["direction"]
        )

        print(
            "Block     :",
            tx["block"]
        )

        print(
            "Time      :",
            tx["timestamp"]
        )


# ============================================================
# FIND CONNECTED WALLETS
# ============================================================

def find_connected_wallets(
    wallet,
    transactions
):

    wallet = wallet.lower()

    connected = set()

    for tx in transactions:

        sender = tx["from"].lower()
        receiver = tx["to"].lower()

        if sender == wallet:

            connected.add(
                receiver
            )

        elif receiver == wallet:

            connected.add(
                sender
            )

    return connected


# ============================================================
# BUILD GRAPH
# ============================================================

def build_graph(transactions):

    graph = defaultdict(set)

    for tx in transactions:

        sender = tx["from"].lower()
        receiver = tx["to"].lower()

        if not sender or not receiver:
            continue

        graph[sender].add(receiver)
        graph[receiver].add(sender)

    return graph


# ============================================================
# MULTI-HOP TRACING
# ============================================================

def trace_wallet(
    start_wallet,
    transactions,
    max_hops=3
):

    start_wallet = start_wallet.lower()

    graph = build_graph(
        transactions
    )

    visited = set()

    queue = deque()

    queue.append(
        (
            start_wallet,
            0
        )
    )

    while queue:

        current, hop = queue.popleft()

        if current in visited:
            continue

        visited.add(current)

        if hop >= max_hops:
            continue

        for neighbour in graph.get(
            current,
            []
        ):

            if neighbour not in visited:

                queue.append(
                    (
                        neighbour,
                        hop + 1
                    )
                )

    return visited


# ============================================================
# SUSPICIOUS PATTERNS
# ============================================================

def detect_patterns(
    wallet,
    transactions
):

    wallet = wallet.lower()

    outgoing = []

    incoming = []

    for tx in transactions:

        if tx["from"].lower() == wallet:
            outgoing.append(tx)

        if tx["to"].lower() == wallet:
            incoming.append(tx)

    connected = find_connected_wallets(
        wallet,
        transactions
    )

    patterns = []

    # Fund splitting
    if len(outgoing) >= 3:

        patterns.append(
            "Fund splitting"
        )

    # Fund consolidation
    if len(incoming) >= 3:

        patterns.append(
            "Fund consolidation"
        )

    # High activity
    if len(transactions) >= 20:

        patterns.append(
            "High transaction activity"
        )

    # Many connections
    if len(connected) >= 10:

        patterns.append(
            "Large number of connected wallets"
        )

    return patterns


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk(
    transaction_count,
    connected_wallet_count,
    patterns
):

    score = 0

    if transaction_count >= 50:

        score += 25

    elif transaction_count >= 20:

        score += 15

    elif transaction_count >= 10:

        score += 10

    if connected_wallet_count >= 20:

        score += 25

    elif connected_wallet_count >= 10:

        score += 15

    elif connected_wallet_count >= 5:

        score += 10

    score += min(
        len(patterns) * 15,
        40
    )

    score = min(
        score,
        100
    )

    if score >= 70:

        level = "HIGH"

    elif score >= 40:

        level = "MEDIUM"

    else:

        level = "LOW"

    return score, level


# ============================================================
# VASP DEMO REGISTRY
# ============================================================

def check_vasp(wallet):

    demo_registry = {

        "0x0000000000000000000000000000000000000000":

        {
            "name": "Demo Exchange",
            "type": "Centralized Exchange"
        }
    }

    return demo_registry.get(
        wallet.lower()
    )


# ============================================================
# FIND VASP ASSOCIATIONS
# ============================================================

def find_vasp_associations(
    traced_wallets
):

    associations = []

    for wallet in traced_wallets:

        result = check_vasp(
            wallet
        )

        if result:

            associations.append(
                {
                    "wallet": wallet,
                    "name": result["name"],
                    "type": result["type"]
                }
            )

    return associations


# ============================================================
# FINAL REPORT
# ============================================================

def generate_report(
    wallet,
    transactions,
    connected_wallets,
    traced_wallets,
    patterns,
    risk_score,
    risk_level,
    vasp_associations
):

    print("\n")
    print(
        "================================================"
    )

    print(
        "          CRYPTOSHIELD REPORT"
    )

    print(
        "================================================"
    )

    print(
        "\nBlockchain:"
    )

    print(
        "BNB Smart Chain"
    )

    print(
        "\nSuspect Wallet:"
    )

    print(
        wallet
    )

    print(
        "\nTransactions:"
    )

    print(
        len(transactions)
    )

    print(
        "\nConnected Wallets:"
    )

    print(
        len(connected_wallets)
    )

    print(
        "\nWallets Traced:"
    )

    print(
        len(traced_wallets)
    )

    print(
        "\nRisk Score:"
    )

    print(
        f"{risk_score} / 100"
    )

    print(
        "\nRisk Level:"
    )

    print(
        risk_level
    )

    print(
        "\nSuspicious Patterns:"
    )

    if patterns:

        for pattern in patterns:

            print(
                " -",
                pattern
            )

    else:

        print(
            " - No major suspicious pattern detected"
        )

    print(
        "\nPotential VASP Associations:"
    )

    if vasp_associations:

        for item in vasp_associations:

            print(
                " -",
                item["name"]
            )

            print(
                "   Wallet:",
                item["wallet"]
            )

    else:

        print(
            " - No known demo association"
        )

    print(
        "\n================================================"
    )

    print(
        "Risk score is an analytical indicator,"
    )

    print(
        "not a criminal verdict."
    )

    print(
        "================================================"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n======================================"
    )

    print(
        "          🛡️ CRYPTOSHIELD"
    )

    print(
        " Blockchain Fraud Intelligence System"
    )

    print(
        "======================================"
    )

    wallet = input(
        "\nEnter BSC wallet address: "
    ).strip()

    if not wallet.startswith("0x"):

        print(
            "\nERROR: Wallet must start with 0x"
        )

        return

    if len(wallet) != 42:

        print(
            "\nERROR: Invalid wallet address."
        )

        return

    # --------------------------------------------------------
    # CONNECTION
    # --------------------------------------------------------

    print(
        "\nTesting BSC connection..."
    )

    latest_block = get_latest_block()

    if latest_block is None:

        print(
            "\nCould not connect to Alchemy."
        )

        return

    print(
        "\nLatest BSC Block:",
        latest_block
    )

    print(
        "\n✅ BSC CONNECTION SUCCESSFUL"
    )

    # --------------------------------------------------------
    # HISTORY
    # --------------------------------------------------------

    transactions = get_wallet_history(
        wallet
    )

    display_transactions(
        transactions
    )

    # --------------------------------------------------------
    # NO DATA
    # --------------------------------------------------------

    if not transactions:

        print(
            "\n======================================"
        )

        print(
            "NO BSC TRANSACTIONS FOUND"
        )

        print(
            "======================================"
        )

        print(
            "\nThis wallet may:"
        )

        print(
            "1. Have no BSC activity."
        )

        print(
            "2. Have activity on another blockchain."
        )

        print(
            "3. Have old BEP-2 activity."
        )

        return

    # --------------------------------------------------------
    # ANALYSIS
    # --------------------------------------------------------

    connected_wallets = find_connected_wallets(
        wallet,
        transactions
    )

    traced_wallets = trace_wallet(
        wallet,
        transactions,
        max_hops=3
    )

    patterns = detect_patterns(
        wallet,
        transactions
    )

    risk_score, risk_level = calculate_risk(
        len(transactions),
        len(connected_wallets),
        patterns
    )

    vasp_associations = find_vasp_associations(
        traced_wallets
    )

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    generate_report(
        wallet,
        transactions,
        connected_wallets,
        traced_wallets,
        patterns,
        risk_score,
        risk_level,
        vasp_associations
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()
