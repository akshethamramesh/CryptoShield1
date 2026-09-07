import streamlit as st
import os
import requests
from dotenv import load_dotenv


# =========================================================
# CONFIGURATION
# =========================================================

load_dotenv(".env")

API_KEY = os.getenv("ALCHEMY_API_KEY")


CHAINS = {

    "Ethereum": {
        "url": f"https://eth-mainnet.g.alchemy.com/v2/{API_KEY}",
        "categories": [
            "external",
            "internal",
            "erc20"
        ]
    },

    "BSC": {
        "url": f"https://bnb-mainnet.g.alchemy.com/v2/{API_KEY}",
        "categories": [
            "external",
            "erc20"
        ]
    }

}


MAX_WALLETS_PER_NODE = 5
MAX_TRANSFERS_PER_NODE = 100
MAX_PAGES = 20


ZERO_ADDRESS = (
    "0x0000000000000000000000000000000000000000"
)


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ CryptoShield")

st.subheader(
    "Blockchain Fraud Intelligence & Investigation System"
)

st.write(
    "Analyze a reported cryptocurrency wallet, "
    "trace fund movement across multiple hops, "
    "detect risk indicators, and identify potential "
    "VASP/exchange associations."
)


st.divider()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.header("Investigation Settings")


chain = st.sidebar.selectbox(
    "Blockchain",
    ["Ethereum", "BSC"]
)


wallet = st.sidebar.text_input(
    "Suspect Wallet Address",
    placeholder="0x..."
)


max_hops = st.sidebar.slider(
    "Maximum Hops",
    min_value=1,
    max_value=3,
    value=2
)


analyze_button = st.sidebar.button(
    "🔍 ANALYZE WALLET",
    use_container_width=True
)


# =========================================================
# VALIDATE WALLET
# =========================================================

def valid_wallet(wallet):

    if not wallet:

        return False

    if not wallet.startswith("0x"):

        return False

    if len(wallet) != 42:

        return False

    return True


# =========================================================
# FETCH TRANSFERS
# =========================================================

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

                "method":
                    "alchemy_getAssetTransfers",

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

                    tx["chain"] = chain

                    all_transfers.append(tx)


                page_key = result.get(
                    "pageKey"
                )


                if not page_key:

                    break


                page += 1


                if page > MAX_PAGES:

                    break


            except Exception:

                break


    return all_transfers


# =========================================================
# CONNECTED WALLETS
# =========================================================

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


        if receiver == ZERO_ADDRESS:

            continue


        if sender == wallet:

            if receiver != wallet:

                connected.add(receiver)


        elif receiver == wallet:

            if sender != wallet:

                connected.add(sender)


    return connected


# =========================================================
# SELECT TOP WALLETS
# =========================================================

def select_wallets(
        connected,
        transfers,
        current_wallet
):

    scores = {}


    for wallet in connected:

        scores[wallet] = 0


    for tx in transfers:

        sender = str(
            tx.get("from", "")
        ).lower()

        receiver = str(
            tx.get("to", "")
        ).lower()


        if sender in scores:

            scores[sender] += 1


        if receiver in scores:

            scores[receiver] += 1


    ranked = sorted(

        scores.items(),

        key=lambda x: x[1],

        reverse=True

    )


    selected = []


    for wallet, score in ranked:

        if wallet == current_wallet:

            continue

        selected.append(wallet)


        if len(selected) >= MAX_WALLETS_PER_NODE:

            break


    return selected


# =========================================================
# RECURSIVE TRACE
# =========================================================

def recursive_trace(
        start_wallet,
        chain,
        max_hops
):

    start_wallet = start_wallet.lower()


    queue = [
        (start_wallet, 0)
    ]


    visited = set()

    discovered = []

    all_transfers = []


    while queue:

        current_wallet, hop = queue.pop(0)


        current_wallet = current_wallet.lower()


        if current_wallet in visited:

            continue


        visited.add(current_wallet)


        discovered.append(
            (current_wallet, hop)
        )


        if hop >= max_hops:

            continue


        transfers = fetch_wallet_transfers(

            current_wallet,

            chain

        )


        limited = transfers[
            :MAX_TRANSFERS_PER_NODE
        ]


        all_transfers.extend(
            limited
        )


        connected = get_connected_wallets(

            current_wallet,

            limited

        )


        selected = select_wallets(

            connected,

            limited,

            current_wallet

        )


        for next_wallet in selected:

            if next_wallet not in visited:

                queue.append(

                    (
                        next_wallet,
                        hop + 1
                    )

                )


    return discovered, all_transfers


# =========================================================
# PATTERN DETECTION
# =========================================================

def detect_patterns(
        discovered,
        transfers,
        start_wallet
):

    patterns = []


    max_hop = max(

        [hop for _, hop in discovered],

        default=0

    )


    if max_hop >= 2:

        patterns.append(
            "Multi-hop fund movement"
        )


    start_wallet = start_wallet.lower()


    outgoing = set()

    incoming = set()


    for tx in transfers:

        sender = str(
            tx.get("from", "")
        ).lower()

        receiver = str(
            tx.get("to", "")
        ).lower()


        if sender == start_wallet:

            if receiver not in [
                start_wallet,
                ZERO_ADDRESS
            ]:

                outgoing.add(receiver)


        if receiver == start_wallet:

            if sender != start_wallet:

                incoming.add(sender)


    if len(outgoing) >= 2:

        patterns.append(
            "Fund splitting"
        )


    if len(incoming) >= 2:

        patterns.append(
            "Fund consolidation"
        )


    return patterns


# =========================================================
# RISK ENGINE
# =========================================================

def calculate_risk(
        discovered,
        transfers,
        patterns
):

    score = 0

    reasons = []


    wallet_count = len(
        discovered
    )


    transaction_count = len(
        transfers
    )


    max_hop = max(

        [hop for _, hop in discovered],

        default=0

    )


    # Multi-hop

    if max_hop >= 2:

        score += 20

        reasons.append(
            "Multi-hop fund movement"
        )


    # Network size

    if wallet_count >= 10:

        score += 20

        reasons.append(
            "Large connected wallet network"
        )


    # Transaction activity

    if transaction_count >= 50:

        score += 20

        reasons.append(
            "High transaction activity"
        )


    if transaction_count >= 100:

        score += 20

        reasons.append(
            "Very high transaction activity"
        )


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


# =========================================================
# ANALYZE BUTTON
# =========================================================

if analyze_button:

    if not API_KEY:

        st.error(
            "ALCHEMY_API_KEY not found in .env"
        )

        st.stop()


    if not valid_wallet(wallet):

        st.error(
            "Please enter a valid EVM wallet address."
        )

        st.stop()


    wallet = wallet.lower()


    # ---------------------------------------------
    # Progress
    # ---------------------------------------------

    with st.spinner(
        "🔍 Tracing blockchain fund flow..."
    ):

        discovered, transfers = recursive_trace(

            wallet,

            chain,

            max_hops

        )


        patterns = detect_patterns(

            discovered,

            transfers,

            wallet

        )


        score, level, reasons = calculate_risk(

            discovered,

            transfers,

            patterns

        )


    # =================================================
    # SUMMARY
    # =================================================

    st.success(
        "Blockchain analysis completed."
    )


    st.divider()


    col1, col2, col3, col4 = st.columns(4)


    with col1:

        st.metric(
            "Transactions",
            len(transfers)
        )


    with col2:

        st.metric(
            "Wallets Discovered",
            len(discovered)
        )


    with col3:

        st.metric(
            "Maximum Hop",
            max(
                [hop for _, hop in discovered],
                default=0
            )
        )


    with col4:

        st.metric(
            "Risk Score",
            f"{score}/100"
        )


    # =================================================
    # RISK LEVEL
    # =================================================

    st.subheader(
        "🚨 Risk Assessment"
    )


    if level == "HIGH":

        st.error(
            f"Risk Level: {level}"
        )

    elif level == "MEDIUM":

        st.warning(
            f"Risk Level: {level}"
        )

    else:

        st.success(
            f"Risk Level: {level}"
        )


    # =================================================
    # PATTERNS
    # =================================================

    st.subheader(
        "⚠️ Detected Risk Indicators"
    )


    if patterns:

        for pattern in patterns:

            st.warning(
                pattern
            )

    else:

        st.info(
            "No major analytical patterns detected."
        )


    # =================================================
    # RISK REASONS
    # =================================================

    if reasons:

        st.subheader(
            "📊 Risk Factors"
        )


        for reason in reasons:

            st.write(
                f"• {reason}"
            )


    # =================================================
    # WALLET TRACE
    # =================================================

    st.subheader(
        "🔗 Fund Flow Trace"
    )


    for address, hop in discovered:

        if hop == 0:

            label = "START"

        else:

            label = f"HOP {hop}"


        st.code(
            f"[{label}] {address}"
        )


    # =================================================
    # TRANSACTION DATA
    # =================================================

    st.subheader(
        "💸 Transaction Evidence"
    )


    if transfers:

        rows = []


        for tx in transfers[:100]:

            rows.append({

                "Direction":
                    tx.get("direction", ""),

                "From":
                    tx.get("from", ""),

                "To":
                    tx.get("to", ""),

                "Asset":
                    tx.get("asset", ""),

                "Value":
                    tx.get("value", ""),

                "Category":
                    tx.get("category", "")

            })


        st.dataframe(
            rows,
            use_container_width=True
        )

    else:

        st.info(
            "No transfers found."
        )


    # =================================================
    # INVESTIGATION CONCLUSION
    # =================================================

    st.divider()


    st.subheader(
        "📄 Investigation Summary"
    )


    st.write(
        f"""
        **Blockchain:** {chain}

        **Wallet:** `{wallet}`

        **Transactions analyzed:** {len(transfers)}

        **Wallets discovered:** {len(discovered)}

        **Maximum hop:** {max(
            [hop for _, hop in discovered],
            default=0
        )}

        **Risk score:** {score}/100

        **Risk level:** {level}
        """
    )


    st.info(
        "⚠️ Risk indicators are analytical signals "
        "and should not be treated as proof of criminal "
        "activity or identity."
    )


# =========================================================
# INITIAL SCREEN
# =========================================================

else:

    st.info(
        "Enter a reported wallet address and click "
        "'ANALYZE WALLET' to begin."
    )


    st.markdown(
        """
        ### CryptoShield Pipeline

        **Wallet → Blockchain Data → Multi-Hop Trace → 
        Pattern Detection → Risk Analysis → VASP Association**

        Designed for authorized blockchain investigation
        and analysis using publicly observable blockchain data.
        """
    )
