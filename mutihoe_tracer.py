import os
import requests
from dotenv import load_dotenv

# ==========================================
# LOAD ENVIRONMENT
# ==========================================

load_dotenv(".env")

API_KEY = os.getenv("ALCHEMY_API_KEY")

if not API_KEY:
    print("ERROR: ALCHEMY_API_KEY not found in .env")
    exit()


# ==========================================
# BLOCKCHAIN CONFIGURATION
# ==========================================

CHAINS = {

    "ethereum": {
        "name": "Ethereum",
        "url": f"https://eth-mainnet.g.alchemy.com/v2/{API_KEY}",
        "categories": [
            "external",
            "internal",
            "erc20"
        ]
    },

    "bsc": {
        "name": "BSC",
        "url": f"https://bnb-mainnet.g.alchemy.com/v2/{API_KEY}",
        "categories": [
            "external",
            "erc20"
        ]
    }

}


# ==========================================
# PERFORMANCE SETTINGS
# ==========================================

# Maximum wallets to expand from each wallet
MAX_WALLETS_PER_NODE = 5

# Maximum transfers kept for analysis
MAX_TRANSFERS_PER_NODE = 100

# Maximum API pages for one wallet
MAX_PAGES = 20


# ==========================================
# FETCH TRANSFERS FOR ONE WALLET
# ==========================================

def fetch_wallet_transfers(wallet, chain):

    config = CHAINS[chain]

    all_transfers = []

    for direction, address_field in [
        ("OUT", "fromAddress"),
        ("IN", "toAddress")
    ]:

        page_key = None
        page = 1

        while True:

            params = {

                "fromBlock": "0x0",

                "toBlock": "latest",

                "category": config["categories"],

                "excludeZeroValue": True,

                "withMetadata": True,

                "maxCount": "0x64",

                address_field: wallet
            }


            if page_key:

                params["pageKey"] = page_key


            payload = {

                "jsonrpc": "2.0",

                "id": page,

                "method": "alchemy_getAssetTransfers",

                "params": [params]

            }


            try:

                response = requests.post(

                    config["url"],

                    json=payload,

                    timeout=30

                )


                data = response.json()


                if "error" in data:

                    print(
                        "RPC ERROR:",
                        data["error"]
                    )

                    break


                result = data.get(
                    "result",
                    {}
                )


                transfers = result.get(
                    "transfers",
                    []
                )


                for tx in transfers:

                    tx["direction"] = direction

                    tx["chain"] = config["name"]

                    all_transfers.append(tx)


                page_key = result.get(
                    "pageKey"
                )


                if not page_key:

                    break


                page += 1


                if page > MAX_PAGES:

                    print(
                        "Page safety limit reached."
                    )

                    break


            except Exception as e:

                print(
                    "Request error:",
                    e
                )

                break


    return all_transfers


# ==========================================
# GET CONNECTED WALLETS
# ==========================================

def get_connected_wallets(
        wallet,
        transfers
):

    wallet = wallet.lower()

    connected = set()


    for tx in transfers:

        sender = tx.get("from")

        receiver = tx.get("to")


        if not sender or not receiver:

            continue


        sender = sender.lower()

        receiver = receiver.lower()


        # Ignore zero address

        if receiver == (
            "0x0000000000000000000000000000000000000000"
        ):

            continue


        if sender == wallet:

            if receiver != wallet:

                connected.add(receiver)


        elif receiver == wallet:

            if sender != wallet:

                connected.add(sender)


    return connected


# ==========================================
# SELECT IMPORTANT WALLETS
# ==========================================

def select_wallets(
        connected,
        transfers,
        current_wallet
):

    current_wallet = current_wallet.lower()

    wallet_scores = {}


    # --------------------------------------
    # Count interactions
    # --------------------------------------

    for wallet in connected:

        wallet_scores[wallet] = 0


    for tx in transfers:

        sender = str(
            tx.get("from", "")
        ).lower()

        receiver = str(
            tx.get("to", "")
        ).lower()


        if sender in wallet_scores:

            wallet_scores[sender] += 1


        if receiver in wallet_scores:

            wallet_scores[receiver] += 1


    # --------------------------------------
    # Sort by interaction count
    # --------------------------------------

    ranked_wallets = sorted(

        wallet_scores.items(),

        key=lambda item: item[1],

        reverse=True

    )


    # --------------------------------------
    # Select top wallets
    # --------------------------------------

    selected = [

        wallet

        for wallet, score in ranked_wallets

        if wallet != current_wallet

    ][:MAX_WALLETS_PER_NODE]


    return selected


# ==========================================
# RECURSIVE MULTI-HOP TRACE
# ==========================================

def recursive_trace(
        start_wallet,
        chain,
        max_hops=3
):

    start_wallet = start_wallet.lower()


    visited = set()


    queue = [

        (start_wallet, 0)

    ]


    discovered = []


    all_transfers = []


    print()

    print(
        "======================================"
    )

    print(
        "       RECURSIVE MULTI-HOP TRACE"
    )

    print(
        "======================================"
    )


    while queue:

        current_wallet, hop = queue.pop(0)


        current_wallet = current_wallet.lower()


        # ----------------------------------
        # Already visited?
        # ----------------------------------

        if current_wallet in visited:

            continue


        visited.add(
            current_wallet
        )


        print()

        print(
            f"Analyzing HOP {hop}:"
        )

        print(
            current_wallet
        )


        discovered.append(

            (current_wallet, hop)

        )


        # ----------------------------------
        # Maximum hop reached
        # ----------------------------------

        if hop >= max_hops:

            print(
                "Maximum hop reached."
            )

            continue


        # ----------------------------------
        # Fetch blockchain data
        # ----------------------------------

        transfers = fetch_wallet_transfers(

            current_wallet,

            chain

        )


        print(
            "Transfers found:",
            len(transfers)
        )


        # ----------------------------------
        # Limit transfers for analysis
        # ----------------------------------

        limited_transfers = transfers[
            :MAX_TRANSFERS_PER_NODE
        ]


        all_transfers.extend(
            limited_transfers
        )


        # ----------------------------------
        # Find connected wallets
        # ----------------------------------

        connected = get_connected_wallets(

            current_wallet,

            limited_transfers

        )


        print(
            "Connected wallets:",
            len(connected)
        )


        # ----------------------------------
        # Rank and select wallets
        # ----------------------------------

        selected_wallets = select_wallets(

            connected,

            limited_transfers,

            current_wallet

        )


        print(
            "Wallets selected for next hop:",
            len(selected_wallets)
        )


        # ----------------------------------
        # Add selected wallets to queue
        # ----------------------------------

        for next_wallet in selected_wallets:

            if next_wallet not in visited:

                queue.append(

                    (
                        next_wallet,

                        hop + 1

                    )

                )


    return discovered, all_transfers


# ==========================================
# DISPLAY TRACE
# ==========================================

def display_trace(
        discovered
):

    print()

    print(
        "======================================"
    )

    print(
        "          FUND FLOW MAP"
    )

    print(
        "======================================"
    )


    for wallet, hop in discovered:

        if hop == 0:

            label = "START"

        else:

            label = f"HOP {hop}"


        print(
            f"[{label}] {wallet}"
        )


# ==========================================
# PATTERN DETECTION
# ==========================================

def detect_patterns(
        discovered,
        transfers,
        start_wallet
):

    print()

    print(
        "======================================"
    )

    print(
        "       SUSPICIOUS PATTERNS"
    )

    print(
        "======================================"
    )


    found = False


    # --------------------------------------
    # Multi-hop
    # --------------------------------------

    max_hop = max(

        [hop for _, hop in discovered],

        default=0

    )


    if max_hop >= 2:

        print(
            "⚠️ Multi-hop fund movement detected"
        )

        found = True


    # --------------------------------------
    # Fund splitting
    # --------------------------------------

    start_wallet = start_wallet.lower()


    outgoing_targets = set()


    for tx in transfers:

        sender = str(
            tx.get("from", "")
        ).lower()

        receiver = str(
            tx.get("to", "")
        ).lower()


        if sender == start_wallet:

            if receiver != start_wallet:

                if receiver != (
                    "0x0000000000000000000000000000000000000000"
                ):

                    outgoing_targets.add(
                        receiver
                    )


    if len(outgoing_targets) >= 2:

        print(
            "⚠️ Fund splitting detected"
        )

        found = True


    # --------------------------------------
    # Fund consolidation
    # --------------------------------------

    incoming_sources = set()


    for tx in transfers:

        sender = str(
            tx.get("from", "")
        ).lower()

        receiver = str(
            tx.get("to", "")
        ).lower()


        if receiver == start_wallet:

            if sender != start_wallet:

                incoming_sources.add(
                    sender
                )


    if len(incoming_sources) >= 2:

        print(
            "⚠️ Fund consolidation detected"
        )

        found = True


    # --------------------------------------
    # No patterns
    # --------------------------------------

    if not found:

        print(
            "No major suspicious patterns detected."
        )


# ==========================================
# RISK SCORE
# ==========================================

def calculate_risk(
        discovered,
        transfers
):

    score = 0

    reasons = []


    max_hop = max(

        [hop for _, hop in discovered],

        default=0

    )


    wallet_count = len(
        discovered
    )


    transaction_count = len(
        transfers
    )


    # --------------------------------------
    # Multi-hop
    # --------------------------------------

    if max_hop >= 2:

        score += 20

        reasons.append(
            "Multi-hop fund movement"
        )


    # --------------------------------------
    # Large network
    # --------------------------------------

    if wallet_count >= 10:

        score += 20

        reasons.append(
            "Large connected wallet network"
        )


    # --------------------------------------
    # High activity
    # --------------------------------------

    if transaction_count >= 50:

        score += 20

        reasons.append(
            "High transaction activity"
        )


    # --------------------------------------
    # Very high activity
    # --------------------------------------

    if transaction_count >= 100:

        score += 20

        reasons.append(
            "Very high transaction activity"
        )


    # --------------------------------------
    # Extensive network
    # --------------------------------------

    if wallet_count >= 25:

        score += 20

        reasons.append(
            "Extensive fund-flow network"
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


    return score, level, reasons


# ==========================================
# MAIN PROGRAM
# ==========================================

print()

print(
    "======================================"
)

print(
    "          🛡️ CRYPTOSHIELD"
)

print(
    "       RECURSIVE TRACER"
)

print(
    "======================================"
)


# ------------------------------------------
# Wallet input
# ------------------------------------------

wallet = input(

    "\nEnter active EVM wallet address: "

).strip()


if not wallet.startswith("0x"):

    print(
        "❌ Invalid wallet address."
    )

    exit()


if len(wallet) != 42:

    print(
        "❌ Invalid wallet length."
    )

    exit()


# ------------------------------------------
# Chain input
# ------------------------------------------

chain = input(

    "\nChoose chain (Ethereum/BSC): "

).strip().lower()


if chain not in CHAINS:

    print(
        "❌ Invalid chain."
    )

    exit()


# ------------------------------------------
# Hop input
# ------------------------------------------

hops_input = input(

    "\nMaximum hops (1-3): "

).strip()


try:

    max_hops = int(
        hops_input
    )

except ValueError:

    max_hops = 3


max_hops = max(

    1,

    min(
        max_hops,
        3
    )

)


# ------------------------------------------
# Start
# ------------------------------------------

print()

print(

    f"Starting {CHAINS[chain]['name']} "
    f"trace..."

)

print(

    f"Maximum hops: {max_hops}"

)

print(

    f"Max wallets per node: "
    f"{MAX_WALLETS_PER_NODE}"

)


# ------------------------------------------
# Run tracer
# ------------------------------------------

discovered, transfers = recursive_trace(

    wallet,

    chain,

    max_hops

)


# ==========================================
# RESULTS
# ==========================================

display_trace(
    discovered
)


detect_patterns(

    discovered,

    transfers,

    wallet

)


score, level, reasons = calculate_risk(

    discovered,

    transfers

)


# ==========================================
# RISK RESULTS
# ==========================================

print()

print(
    "======================================"
)

print(
    "        CRYPTOSHIELD RISK"
)

print(
    "======================================"
)


print(

    "Transactions analyzed:",

    len(transfers)

)


print(

    "Wallets discovered:",

    len(discovered)

)


print(

    "Maximum hop reached:",

    max(

        [hop for _, hop in discovered],

        default=0

    )

)


print(

    "Risk Score:",

    f"{score}/100"

)


print(

    "Risk Level:",

    level

)


# ------------------------------------------
# Risk indicators
# ------------------------------------------

if reasons:

    print()

    print(
        "Risk Indicators:"
    )


    for reason in reasons:

        print(
            "•",
            reason
        )


# ==========================================
# COMPLETE
# ==========================================

print()

print(
    "======================================"
)

print(
    "          TRACE COMPLETE"
)

print(
    "======================================"
)


print()

print(

    "⚠️ Risk indicators are analytical "
    "signals, not proof of criminal activity."

)
