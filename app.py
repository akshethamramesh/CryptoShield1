import os
import tempfile
from datetime import datetime

import pandas as pd
import streamlit as st

from blockchain import trace_wallet
from transaction_dna import analyze_transaction_dna
from abnormal_detection import detect_abnormal_transactions
from vasp_detection import detect_vasp
from risk_engine import calculate_risk_v3
from report_generator import generate_pdf_report


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 0;
    }

    .subtitle {
        font-size: 18px;
        opacity: 0.70;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 25px;
        font-weight: 700;
        margin-top: 30px;
        margin-bottom: 15px;
    }

    .risk-high {
        padding: 20px;
        border-radius: 14px;
        border: 2px solid #ff4b4b;
        background: rgba(255, 75, 75, 0.10);
    }

    .risk-medium {
        padding: 20px;
        border-radius: 14px;
        border: 2px solid #ffa500;
        background: rgba(255, 165, 0, 0.10);
    }

    .risk-low {
        padding: 20px;
        border-radius: 14px;
        border: 2px solid #21c354;
        background: rgba(33, 195, 84, 0.10);
    }

    .wallet-card {
        padding: 15px;
        border-radius: 12px;
        border: 1px solid rgba(128,128,128,0.35);
        margin-bottom: 10px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SESSION STATE
# ============================================================

DEFAULT_STATE = {
    "analysis_done": False,
    "analysis_result": None,
    "dna_result": None,
    "abnormal_alerts": [],
    "vasp_results": [],
    "risk_score": 0,
    "risk_level": "LOW",
    "risk_factors": [],
    "patterns": [],
    "wallet_address": "",
    "chain": "Ethereum",
    "max_hop": 2
}

for key, value in DEFAULT_STATE.items():

    if key not in st.session_state:

        st.session_state[key] = value


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def format_address(address):

    if not address:
        return "Unknown"

    address = str(address)

    if len(address) <= 18:
        return address

    return (
        address[:10]
        + "..."
        + address[-8:]
    )


def normalize_address(address):

    if not address:
        return ""

    return str(address).strip().lower()


def safe_float(value):

    try:
        return float(value)
    except:
        return 0.0


def get_transaction_timestamp(tx):

    try:

        timestamp = int(
            tx.get(
                "timeStamp",
                0
            )
        )

        if timestamp <= 0:
            return None

        return datetime.fromtimestamp(
            timestamp
        )

    except:

        return None


# ============================================================
# PATTERN DETECTION
# ============================================================

def detect_patterns(
    transactions,
    dna,
    max_hop
):

    patterns = []

    fan_in = dna.get(
        "fan_in",
        0
    )

    fan_out = dna.get(
        "fan_out",
        0
    )

    rapid_movements = dna.get(
        "rapid_movements",
        0
    )

    token_transactions = sum(
        1
        for tx in transactions
        if tx.get("type") == "token"
    )

    # --------------------------------------------------------
    # FAN OUT
    # --------------------------------------------------------

    if fan_out >= 10:

        patterns.append(
            "Very high fan-out: funds moved to many destinations."
        )

    elif fan_out >= 5:

        patterns.append(
            "High fan-out: funds were distributed across multiple destinations."
        )

    # --------------------------------------------------------
    # FAN IN
    # --------------------------------------------------------

    if fan_in >= 10:

        patterns.append(
            "Very high fan-in: funds were consolidated from many sources."
        )

    elif fan_in >= 5:

        patterns.append(
            "High fan-in: funds were received from multiple sources."
        )

    # --------------------------------------------------------
    # MULTI HOP
    # --------------------------------------------------------

    if max_hop >= 3:

        patterns.append(
            "Deep multi-hop fund movement detected."
        )

    elif max_hop >= 2:

        patterns.append(
            "Multi-hop fund movement detected."
        )

    # --------------------------------------------------------
    # RAPID MOVEMENT
    # --------------------------------------------------------

    if rapid_movements >= 10:

        patterns.append(
            "Frequent rapid fund movement detected."
        )

    elif rapid_movements >= 5:

        patterns.append(
            "Rapid fund movement detected."
        )

    # --------------------------------------------------------
    # TRANSACTION ACTIVITY
    # --------------------------------------------------------

    if len(transactions) >= 200:

        patterns.append(
            "Very high transaction activity detected."
        )

    elif len(transactions) >= 100:

        patterns.append(
            "High transaction activity detected."
        )

    # --------------------------------------------------------
    # TOKEN ACTIVITY
    # --------------------------------------------------------

    if token_transactions >= 100:

        patterns.append(
            "High token transfer activity detected."
        )

    elif token_transactions > 0:

        patterns.append(
            "Token transfer activity detected."
        )

    return patterns


# ============================================================
# IMPORTANT WALLET ANALYSIS
# ============================================================

def calculate_wallet_importance(
    transactions,
    wallet,
    vasp_addresses
):

    wallet = normalize_address(
        wallet
    )

    incoming = 0
    outgoing = 0
    token_transfers = 0

    received_value = 0
    sent_value = 0

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

        value = safe_float(
            tx.get(
                "value",
                0
            )
        )

        if receiver == wallet:

            incoming += 1
            received_value += value

        if sender == wallet:

            outgoing += 1
            sent_value += value

        if (
            sender == wallet
            or receiver == wallet
        ):

            if tx.get(
                "type"
            ) == "token":

                token_transfers += 1

    importance = (
        incoming
        + outgoing
        + token_transfers
    )

    if wallet in vasp_addresses:

        importance += 100

    return {
        "importance": importance,
        "incoming": incoming,
        "outgoing": outgoing,
        "token_transfers": token_transfers,
        "received_value": received_value,
        "sent_value": sent_value
    }


# ============================================================
# FUND FLOW GRAPH
# ============================================================

def build_fund_flow_graph(
    transactions,
    start_wallet,
    hop_map,
    vasp_results,
    max_transactions=50
):

    try:

        from pyvis.network import Network

    except ImportError:

        st.error(
            "PyVis is not installed. Run: pip install pyvis"
        )

        return None

    start_wallet = normalize_address(
        start_wallet
    )

    vasp_addresses = {
        normalize_address(
            item.get(
                "address",
                ""
            )
        )
        for item in vasp_results
    }

    # --------------------------------------------------------
    # SCORE TRANSACTIONS
    # --------------------------------------------------------

    scored_transactions = []

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

        value = safe_float(
            tx.get(
                "value",
                0
            )
        )

        importance = 0

        # Directly connected to reported wallet
        if sender == start_wallet:

            importance += 100

        if receiver == start_wallet:

            importance += 100

        # Potential VASP
        if sender in vasp_addresses:

            importance += 80

        if receiver in vasp_addresses:

            importance += 80

        # Value contribution
        importance += min(
            value,
            20
        )

        scored_transactions.append(
            (
                importance,
                tx
            )
        )

    scored_transactions.sort(
        key=lambda x: x[0],
        reverse=True
    )

    selected_transactions = [
        tx
        for _, tx in scored_transactions[
            :max_transactions
        ]
    ]

    # --------------------------------------------------------
    # NETWORK
    # --------------------------------------------------------

    net = Network(
        height="650px",
        width="100%",
        directed=True,
        bgcolor="#111111",
        font_color="white"
    )

    net.barnes_hut(
        gravity=-30000,
        central_gravity=0.3,
        spring_length=180,
        spring_strength=0.04
    )

    added_nodes = set()

    # --------------------------------------------------------
    # ADD NODE
    # --------------------------------------------------------

    def add_node(address):

        address = normalize_address(
            address
        )

        if not address:
            return

        if address in added_nodes:
            return

        # --------------------------------------------
        # REPORTED WALLET
        # --------------------------------------------

        if address == start_wallet:

            net.add_node(
                address,
                label="🔴 REPORTED WALLET",
                color="#ff4b4b",
                size=35,
                title=(
                    "<b>REPORTED WALLET</b><br>"
                    f"Address: {address}<br>"
                    "Investigation starting point"
                )
            )

            added_nodes.add(
                address
            )

            return

        # --------------------------------------------
        # VASP
        # --------------------------------------------

        if address in vasp_addresses:

            vasp_info = next(
                (
                    item
                    for item in vasp_results
                    if normalize_address(
                        item.get(
                            "address",
                            ""
                        )
                    ) == address
                ),
                {}
            )

            net.add_node(
                address,
                label="🟣 POTENTIAL VASP",
                color="#9b59b6",
                size=30,
                title=(
                    "<b>POTENTIAL VASP / EXCHANGE</b><br>"
                    f"Address: {address}<br>"
                    f"Name: {vasp_info.get('name', 'Unknown')}<br>"
                    f"Type: {vasp_info.get('type', 'Unknown')}<br>"
                    f"Confidence: "
                    f"{vasp_info.get('confidence', 'Unknown')}"
                )
            )

            added_nodes.add(
                address
            )

            return

        # --------------------------------------------
        # HOP
        # --------------------------------------------

        hop = hop_map.get(
            address,
            0
        )

        if hop == 1:

            label = "🟡 HOP 1"
            color = "#f1c40f"
            size = 25

        elif hop == 2:

            label = "🟠 HOP 2"
            color = "#e67e22"
            size = 23

        elif hop >= 3:

            label = f"🟣 HOP {hop}"
            color = "#8e44ad"
            size = 21

        else:

            label = "⚪ CONNECTED"
            color = "#7f8c8d"
            size = 18

        net.add_node(
            address,
            label=label,
            color=color,
            size=size,
            title=(
                f"<b>{label}</b><br>"
                f"Address: {address}<br>"
                f"Investigation hop: {hop}"
            )
        )

        added_nodes.add(
            address
        )

    # --------------------------------------------------------
    # ADD EDGES
    # --------------------------------------------------------

    for tx in selected_transactions:

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

        add_node(sender)
        add_node(receiver)

        asset = tx.get(
            "asset",
            "ETH"
        )

        value = tx.get(
            "value",
            0
        )

        tx_type = tx.get(
            "type",
            "native"
        )

        tx_hash = tx.get(
            "hash",
            ""
        )

        title = (
            f"<b>FUND FLOW</b><br>"
            f"Asset: {asset}<br>"
            f"Value: {value}<br>"
            f"Type: {tx_type}<br>"
            f"TX: {tx_hash}"
        )

        net.add_edge(
            sender,
            receiver,
            title=title,
            arrows="to",
            width=2
        )

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    temp_dir = tempfile.mkdtemp()

    graph_path = os.path.join(
        temp_dir,
        "police_fund_flow.html"
    )

    net.save_graph(
        graph_path
    )

    return graph_path


# ============================================================
# TRACE PATH
# ============================================================

def find_trace_path(
    transactions,
    start_wallet,
    target_wallet
):

    start_wallet = normalize_address(
        start_wallet
    )

    target_wallet = normalize_address(
        target_wallet
    )

    # Build adjacency list

    adjacency = {}

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

        if sender not in adjacency:

            adjacency[sender] = []

        adjacency[sender].append(
            tx
        )

    # BFS

    queue = [
        (
            start_wallet,
            []
        )
    ]

    visited = {
        start_wallet
    }

    while queue:

        current_wallet, path = queue.pop(
            0
        )

        if current_wallet == target_wallet:

            return path

        for tx in adjacency.get(
            current_wallet,
            []
        ):

            next_wallet = normalize_address(
                tx.get(
                    "to",
                    ""
                )
            )

            if not next_wallet:
                continue

            if next_wallet in visited:
                continue

            visited.add(
                next_wallet
            )

            new_path = (
                path
                + [tx]
            )

            queue.append(
                (
                    next_wallet,
                    new_path
                )
            )

    return []


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title(
    "🛡️ CryptoShield"
)

st.sidebar.markdown(
    "### Police Blockchain Investigation"
)

st.sidebar.write(
    "Start with a victim-reported suspect wallet."
)

wallet_address_input = st.sidebar.text_input(
    "Reported Suspect Wallet",
    placeholder="0x..."
)

chain_input = st.sidebar.selectbox(
    "Blockchain",
    [
        "Ethereum",
        "BSC"
    ]
)

max_hop_input = st.sidebar.slider(
    "Maximum Investigation Hops",
    min_value=1,
    max_value=3,
    value=2
)

start_investigation = st.sidebar.button(
    "🔍 Start Investigation",
    use_container_width=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ CRYPTO SHIELD</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Blockchain Fraud Intelligence System'
    '</div>',
    unsafe_allow_html=True
)

st.info(
    "CryptoShield converts a victim-reported suspect wallet "
    "into an explainable blockchain investigation by tracing "
    "fund flows, detecting behavioral indicators, and "
    "highlighting potential VASP associations."
)

st.warning(
    "⚠️ Analytical intelligence only. "
    "A risk score does not prove fraud, criminal activity, "
    "wallet ownership, or identity."
)


# ============================================================
# START INVESTIGATION
# ============================================================

if start_investigation:

    if not wallet_address_input.strip():

        st.error(
            "Please enter a wallet address."
        )

        st.stop()

    wallet_address = (
        wallet_address_input
        .strip()
    )

    if not wallet_address.lower().startswith(
        "0x"
    ):

        st.error(
            "Invalid wallet address format."
        )

        st.stop()

    with st.spinner(
        "🔗 Collecting blockchain data..."
    ):

        try:

            result = trace_wallet(
                wallet_address,
                chain_input,
                max_hop_input
            )

        except Exception as e:

            st.error(
                f"Blockchain analysis failed: {e}"
            )

            st.stop()

    transactions = result.get(
        "transactions",
        []
    )

    native_transactions = result.get(
        "native_transactions",
        []
    )

    token_transactions = result.get(
        "token_transactions",
        []
    )

    token_count = result.get(
        "token_count",
        len(token_transactions)
    )

    native_count = result.get(
        "native_count",
        len(native_transactions)
    )

    token_types = result.get(
        "token_types",
        []
    )

    connected_wallets = result.get(
        "visited_wallets",
        result.get(
            "wallets",
            []
        )
    )

    # --------------------------------------------------------
    # DNA
    # --------------------------------------------------------

    with st.spinner(
        "🧬 Building transaction DNA..."
    ):

        dna_result = analyze_transaction_dna(
            transactions,
            wallet_address
        )

    # --------------------------------------------------------
    # ABNORMAL
    # --------------------------------------------------------

    with st.spinner(
        "🚨 Detecting abnormal transaction indicators..."
    ):

        abnormal_alerts = (
            detect_abnormal_transactions(
                transactions
            )
        )

    # --------------------------------------------------------
    # VASP
    # --------------------------------------------------------

    with st.spinner(
        "🏦 Checking potential VASP associations..."
    ):

        vasp_results = detect_vasp(
            transactions
        )

    # --------------------------------------------------------
    # RISK V3
    # --------------------------------------------------------

    risk_score, risk_level, risk_factors = (
        calculate_risk_v3(

            transaction_count=len(
                transactions
            ),

            connected_wallets=len(
                connected_wallets
            ),

            rapid_movements=dna_result.get(
                "rapid_movements",
                0
            ),

            abnormal_alerts=len(
                abnormal_alerts
            ),

            fan_in=dna_result.get(
                "fan_in",
                0
            ),

            fan_out=dna_result.get(
                "fan_out",
                0
            ),

            max_hop=result.get(
                "max_hop",
                max_hop_input
            ),

            vasp_matches=len(
                vasp_results
            ),

            token_transactions=token_count,

            token_types=len(
                token_types
            )
        )
    )

    # --------------------------------------------------------
    # PATTERNS
    # --------------------------------------------------------

    patterns = detect_patterns(
        transactions,
        dna_result,
        result.get(
            "max_hop",
            max_hop_input
        )
    )

    # --------------------------------------------------------
    # SAVE STATE
    # --------------------------------------------------------

    st.session_state.analysis_done = True

    st.session_state.analysis_result = result

    st.session_state.dna_result = dna_result

    st.session_state.abnormal_alerts = abnormal_alerts

    st.session_state.vasp_results = vasp_results

    st.session_state.risk_score = risk_score

    st.session_state.risk_level = risk_level

    st.session_state.risk_factors = risk_factors

    st.session_state.patterns = patterns

    st.session_state.wallet_address = wallet_address

    st.session_state.chain = chain_input

    st.session_state.max_hop = max_hop_input

    st.success(
        "✅ Investigation completed successfully."
    )


# ============================================================
# RESULTS
# ============================================================

if st.session_state.analysis_done:

    result = st.session_state.analysis_result

    dna_result = st.session_state.dna_result

    abnormal_alerts = st.session_state.abnormal_alerts

    vasp_results = st.session_state.vasp_results

    risk_score = st.session_state.risk_score

    risk_level = st.session_state.risk_level

    risk_factors = st.session_state.risk_factors

    patterns = st.session_state.patterns

    wallet_address = st.session_state.wallet_address

    chain = st.session_state.chain

    max_hop = st.session_state.max_hop

    transactions = result.get(
        "transactions",
        []
    )

    native_transactions = result.get(
        "native_transactions",
        []
    )

    token_transactions = result.get(
        "token_transactions",
        []
    )

    native_count = result.get(
        "native_count",
        len(native_transactions)
    )

    token_count = result.get(
        "token_count",
        len(token_transactions)
    )

    token_types = result.get(
        "token_types",
        []
    )

    connected_wallets = result.get(
        "visited_wallets",
        result.get(
            "wallets",
            []
        )
    )

    hop_map = result.get(
        "hop_map",
        {}
    )

    max_hop_result = result.get(
        "max_hop",
        max_hop
    )

    # ========================================================
    # 1. INVESTIGATION OVERVIEW
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '1️⃣ Investigation Overview'
        '</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Blockchain",
            chain
        )

    with col2:

        st.metric(
            "Transactions",
            len(transactions)
        )

    with col3:

        st.metric(
            "Connected Wallets",
            len(connected_wallets)
        )

    with col4:

        st.metric(
            "Max Hop",
            max_hop_result
        )

    st.write(
        "**Reported Wallet**"
    )

    st.code(
        wallet_address
    )


    # ========================================================
    # 2. RISK STATUS
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '2️⃣ Risk Status'
        '</div>',
        unsafe_allow_html=True
    )

    if risk_level == "HIGH":

        st.markdown(
            f"""
            <div class="risk-high">
                <h2>🔴 HIGH RISK</h2>
                <h1>{risk_score}/100</h1>
                Multiple analytical risk indicators were detected.
            </div>
            """,
            unsafe_allow_html=True
        )

    elif risk_level == "MEDIUM":

        st.markdown(
            f"""
            <div class="risk-medium">
                <h2>🟠 MEDIUM RISK</h2>
                <h1>{risk_score}/100</h1>
                Several analytical indicators were detected.
            </div>
            """,
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            f"""
            <div class="risk-low">
                <h2>🟢 LOW RISK</h2>
                <h1>{risk_score}/100</h1>
                Limited predefined indicators were detected.
            </div>
            """,
            unsafe_allow_html=True
        )


    # ========================================================
    # 3. EXPLAINABLE RISK
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '3️⃣ Explainable Risk Assessment'
        '</div>',
        unsafe_allow_html=True
    )

    if risk_factors:

        factor_rows = []

        for factor in risk_factors:

            factor_rows.append(
                {
                    "Risk Indicator":
                        factor.get(
                            "indicator",
                            "Unknown"
                        ),

                    "Points":
                        factor.get(
                            "points",
                            0
                        )
                }
            )

        factor_df = pd.DataFrame(
            factor_rows
        )

        st.dataframe(
            factor_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No predefined risk indicators detected."
        )


    # ========================================================
    # 4. POLICE FUND FLOW NETWORK
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '4️⃣ Police Fund Flow Network'
        '</div>',
        unsafe_allow_html=True
    )

    st.caption(
        "🔴 Reported Wallet   "
        "→ 🟡 Hop 1   "
        "→ 🟠 Hop 2   "
        "→ 🟣 Potential VASP"
    )

    st.write(
        "The graph highlights the important transaction "
        "connections instead of displaying every wallet at once."
    )

    graph_path = build_fund_flow_graph(
        transactions,
        wallet_address,
        hop_map,
        vasp_results
    )

    if graph_path:

        try:

            with open(
                graph_path,
                "r",
                encoding="utf-8"
            ) as graph_file:

                graph_html = graph_file.read()

            st.components.v1.html(
                graph_html,
                height=680,
                scrolling=True
            )

        except Exception as e:

            st.error(
                f"Unable to display graph: {e}"
            )


    # ========================================================
    # 5. TRACE PATH
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '5️⃣ 🔎 Trace Funds'
        '</div>',
        unsafe_allow_html=True
    )

    st.write(
        "Select a connected wallet and CryptoShield will "
        "try to reconstruct a direct transaction path "
        "from the reported wallet."
    )

    wallet_options = []

    for wallet in connected_wallets:

        if normalize_address(
            wallet
        ) != normalize_address(
            wallet_address
        ):

            wallet_options.append(
                wallet
            )

    if wallet_options:

        selected_wallet = st.selectbox(
            "Select wallet to trace",
            wallet_options,
            format_func=format_address
        )

        if st.button(
            "🔍 Trace Selected Path",
            use_container_width=True
        ):

            path = find_trace_path(
                transactions,
                wallet_address,
                selected_wallet
            )

            if path:

                st.success(
                    f"Trace path found: {len(path)} transaction(s)"
                )

                total_native = 0

                for index, tx in enumerate(
                    path,
                    start=1
                ):

                    sender = format_address(
                        tx.get(
                            "from",
                            ""
                        )
                    )

                    receiver = format_address(
                        tx.get(
                            "to",
                            ""
                        )
                    )

                    asset = tx.get(
                        "asset",
                        "ETH"
                    )

                    value = tx.get(
                        "value",
                        0
                    )

                    total_native += safe_float(
                        value
                    )

                    st.markdown(
                        f"""
                        ### Step {index}

                        `{sender}` ➡️ `{receiver}`

                        **{value} {asset}**

                        Transaction type:
                        `{tx.get('type', 'native')}`

                        Transaction:
                        `{format_address(tx.get('hash', ''))}`
                        """
                    )

                    st.divider()

            else:

                st.warning(
                    "No direct trace path was found "
                    "between the reported wallet and selected wallet."
                )

    else:

        st.info(
            "No connected wallets available for path tracing."
        )


    # ========================================================
    # 6. INVESTIGATION TIMELINE
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '6️⃣ 🕒 Investigation Timeline'
        '</div>',
        unsafe_allow_html=True
    )

    timeline_rows = []

    for tx in transactions:

        dt = get_transaction_timestamp(
            tx
        )

        if dt:

            time_string = dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        else:

            time_string = "Unknown"

        timeline_rows.append(
            {
                "Time":
                    time_string,

                "From":
                    format_address(
                        tx.get(
                            "from",
                            ""
                        )
                    ),

                "To":
                    format_address(
                        tx.get(
                            "to",
                            ""
                        )
                    ),

                "Asset":
                    tx.get(
                        "asset",
                        "ETH"
                    ),

                "Value":
                    tx.get(
                        "value",
                        0
                    ),

                "Type":
                    tx.get(
                        "type",
                        "native"
                    )
            }
        )

    if timeline_rows:

        timeline_df = pd.DataFrame(
            timeline_rows
        )

        timeline_df = timeline_df[
            timeline_df["Time"] != "Unknown"
        ]

        timeline_df = timeline_df.sort_values(
            "Time"
        )

        st.dataframe(
            timeline_df.head(100),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No timestamped transactions available."
        )


    # ========================================================
    # 7. TOKEN INTELLIGENCE
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '7️⃣ 🪙 Token Transfer Intelligence'
        '</div>',
        unsafe_allow_html=True
    )

    token_col1, token_col2, token_col3 = st.columns(3)

    with token_col1:

        st.metric(
            "Native Transactions",
            native_count
        )

    with token_col2:

        st.metric(
            "Token Transfers",
            token_count
        )

    with token_col3:

        st.metric(
            "Token Types",
            len(token_types)
        )

    if token_types:

        st.write(
            "**Detected Token Types**"
        )

        token_type_df = pd.DataFrame(
            {
                "Token": token_types
            }
        )

        st.dataframe(
            token_type_df,
            use_container_width=True,
            hide_index=True
        )

    if token_transactions:

        token_rows = []

        for tx in token_transactions[
            :100
        ]:

            token_rows.append(
                {
                    "From":
                        format_address(
                            tx.get(
                                "from",
                                ""
                            )
                        ),

                    "To":
                        format_address(
                            tx.get(
                                "to",
                                ""
                            )
                        ),

                    "Token":
                        tx.get(
                            "token_symbol",
                            tx.get(
                                "asset",
                                "Unknown"
                            )
                        ),

                    "Value":
                        tx.get(
                            "value",
                            0
                        ),

                    "Transaction":
                        format_address(
                            tx.get(
                                "hash",
                                ""
                            )
                        )
                }
            )

        token_df = pd.DataFrame(
            token_rows
        )

        st.dataframe(
            token_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No token transfers detected."
        )

    st.caption(
        "Token values are kept separate from native ETH/BNB "
        "amounts because different tokens use different "
        "units and decimals."
    )


    # ========================================================
    # 8. TRANSACTION DNA
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '8️⃣ 🧬 Transaction DNA'
        '</div>',
        unsafe_allow_html=True
    )

    dna1, dna2, dna3, dna4 = st.columns(4)

    with dna1:

        st.metric(
            "Transactions",
            dna_result.get(
                "transaction_count",
                0
            )
        )

    with dna2:

        st.metric(
            "Unique Senders",
            dna_result.get(
                "unique_senders",
                0
            )
        )

    with dna3:

        st.metric(
            "Unique Receivers",
            dna_result.get(
                "unique_receivers",
                0
            )
        )

    with dna4:

        st.metric(
            "Rapid Movements",
            dna_result.get(
                "rapid_movements",
                0
            )
        )

    dna5, dna6, dna7 = st.columns(3)

    with dna5:

        st.metric(
            "Fan-In",
            dna_result.get(
                "fan_in",
                0
            )
        )

    with dna6:

        st.metric(
            "Fan-Out",
            dna_result.get(
                "fan_out",
                0
            )
        )

    with dna7:

        native_asset = (
            "BNB"
            if chain == "BSC"
            else "ETH"
        )

        st.metric(
            f"Native {native_asset} Volume",
            round(
                dna_result.get(
                    "total_volume",
                    0
                ),
                4
            )
        )

    indicators = dna_result.get(
        "behavior_indicators",
        []
    )

    if indicators:

        st.write(
            "**Behavioral Indicators**"
        )

        for indicator in indicators:

            st.warning(
                indicator
            )


    # ========================================================
    # 9. FUND FLOW PATTERNS
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '9️⃣ 🔎 Detected Fund-Flow Patterns'
        '</div>',
        unsafe_allow_html=True
    )

    if patterns:

        for pattern in patterns:

            st.info(
                f"🔎 {pattern}"
            )

    else:

        st.success(
            "No major predefined patterns detected."
        )


    # ========================================================
    # 10. ABNORMAL TRANSACTIONS
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '🔟 🚨 Abnormal Transaction Analysis'
        '</div>',
        unsafe_allow_html=True
    )

    st.metric(
        "Abnormal Indicators",
        len(abnormal_alerts)
    )

    if abnormal_alerts:

        abnormal_rows = []

        for alert in abnormal_alerts[
            :100
        ]:

            abnormal_rows.append(
                {
                    "Transaction":
                        format_address(
                            alert.get(
                                "hash",
                                ""
                            )
                        ),

                    "Score":
                        alert.get(
                            "score",
                            0
                        ),

                    "Reason":
                        alert.get(
                            "reason",
                            "Unknown"
                        )
                }
            )

        abnormal_df = pd.DataFrame(
            abnormal_rows
        )

        st.dataframe(
            abnormal_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "No abnormal transaction indicators detected."
        )


    # ========================================================
    # 11. VASP
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '1️⃣1️⃣ 🏦 Potential VASP / Exchange Association'
        '</div>',
        unsafe_allow_html=True
    )

    if vasp_results:

        st.warning(
            "Potential association detected. "
            "This does not prove ownership or control of the wallet."
        )

        vasp_rows = []

        for vasp in vasp_results:

            vasp_rows.append(
                {
                    "Name":
                        vasp.get(
                            "name",
                            "Unknown"
                        ),

                    "Type":
                        vasp.get(
                            "type",
                            "Unknown"
                        ),

                    "Country":
                        vasp.get(
                            "country",
                            "Unknown"
                        ),

                    "Address":
                        format_address(
                            vasp.get(
                                "address",
                                ""
                            )
                        ),

                    "Confidence":
                        vasp.get(
                            "confidence",
                            "Unknown"
                        )
                }
            )

        vasp_df = pd.DataFrame(
            vasp_rows
        )

        st.dataframe(
            vasp_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No potential VASP association identified "
            "in the current registry."
        )


    # ========================================================
    # 12. WHY THIS WALLET MATTERS
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '1️⃣2️⃣ 🧠 Why This Wallet Matters'
        '</div>',
        unsafe_allow_html=True
    )

    vasp_addresses = {
        normalize_address(
            item.get(
                "address",
                ""
            )
        )
        for item in vasp_results
    }

    important_wallets = []

    for wallet in connected_wallets:

        if normalize_address(
            wallet
        ) == normalize_address(
            wallet_address
        ):

            continue

        wallet_stats = calculate_wallet_importance(
            transactions,
            wallet,
            vasp_addresses
        )

        important_wallets.append(
            (
                wallet_stats[
                    "importance"
                ],
                wallet,
                wallet_stats
            )
        )

    important_wallets.sort(
        key=lambda x: x[0],
        reverse=True
    )

    if important_wallets:

        for (
            importance,
            wallet,
            stats
        ) in important_wallets[:5]:

            hop = hop_map.get(
                normalize_address(
                    wallet
                ),
                0
            )

            st.markdown(
                f"""
                <div class="wallet-card">

                <h4>🔎 {format_address(wallet)}</h4>

                <b>Investigation Hop:</b> {hop}<br>

                <b>Incoming Transactions:</b>
                {stats['incoming']}<br>

                <b>Outgoing Transactions:</b>
                {stats['outgoing']}<br>

                <b>Token Transfers:</b>
                {stats['token_transfers']}<br>

                <b>Why it matters:</b>
                This wallet has significant connectivity
                within the analyzed fund-flow network.

                </div>
                """,
                unsafe_allow_html=True
            )

    else:

        st.info(
            "No additional important wallets identified."
        )


    # ========================================================
    # 13. TRANSACTION EVIDENCE
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '1️⃣3️⃣ 📋 Transaction Evidence'
        '</div>',
        unsafe_allow_html=True
    )

    evidence_rows = []

    for tx in transactions[
        :200
    ]:

        evidence_rows.append(
            {
                "From":
                    format_address(
                        tx.get(
                            "from",
                            ""
                        )
                    ),

                "To":
                    format_address(
                        tx.get(
                            "to",
                            ""
                        )
                    ),

                "Asset":
                    tx.get(
                        "asset",
                        "ETH"
                    ),

                "Value":
                    tx.get(
                        "value",
                        0
                    ),

                "Type":
                    tx.get(
                        "type",
                        "native"
                    ),

                "Transaction":
                    format_address(
                        tx.get(
                            "hash",
                            ""
                        )
                    )
            }
        )

    if evidence_rows:

        evidence_df = pd.DataFrame(
            evidence_rows
        )

        st.dataframe(
            evidence_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No transaction evidence available."
        )


    # ========================================================
    # 14. POLICE INVESTIGATION SUMMARY
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '1️⃣4️⃣ 🚔 Investigation Summary'
        '</div>',
        unsafe_allow_html=True
    )

    summary_col1, summary_col2 = st.columns(
        2
    )

    with summary_col1:

        st.write(
            f"""
            **Reported Wallet**

            `{wallet_address}`

            **Blockchain**

            `{chain}`

            **Transactions Analyzed**

            `{len(transactions)}`

            **Connected Wallets**

            `{len(connected_wallets)}`

            **Maximum Hop**

            `{max_hop_result}`
            """
        )

    with summary_col2:

        st.write(
            f"""
            **Native Transactions**

            `{native_count}`

            **Token Transfers**

            `{token_count}`

            **Token Types**

            `{len(token_types)}`

            **Abnormal Indicators**

            `{len(abnormal_alerts)}`

            **Potential VASP Associations**

            `{len(vasp_results)}`
            """
        )

    if risk_level == "HIGH":

        conclusion = (
            "The reported wallet exhibits multiple "
            "analytical risk indicators. The highlighted "
            "fund-flow paths and associated addresses "
            "should receive further investigative review."
        )

    elif risk_level == "MEDIUM":

        conclusion = (
            "The reported wallet exhibits several "
            "behavioral indicators that may require "
            "additional review and verification."
        )

    else:

        conclusion = (
            "The current analysis identified limited "
            "predefined risk indicators. Additional "
            "evidence may be required."
        )

    st.info(
        conclusion
    )


    # ========================================================
    # 15. PDF REPORT
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '1️⃣5️⃣ 📄 Investigation Report'
        '</div>',
        unsafe_allow_html=True
    )

    if st.button(
        "📄 Generate PDF Report",
        use_container_width=True
    ):

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".pdf"
        ) as temp_file:

            pdf_path = temp_file.name

        try:

            generate_pdf_report(

                file_path=pdf_path,

                wallet_address=wallet_address,

                chain=chain,

                transactions=transactions,

                connected_wallets=connected_wallets,

                max_hop=max_hop_result,

                abnormal_alerts=abnormal_alerts,

                vasp_results=vasp_results,

                risk_score=risk_score,

                risk_level=risk_level,

                patterns=patterns
            )

            with open(
                pdf_path,
                "rb"
            ) as pdf_file:

                pdf_bytes = pdf_file.read()

            st.download_button(
                label="⬇️ Download Investigation Report",
                data=pdf_bytes,
                file_name=(
                    "CryptoShield_Investigation_Report.pdf"
                ),
                mime="application/pdf",
                use_container_width=True
            )

        except Exception as e:

            st.error(
                f"PDF generation failed: {e}"
            )


    # ========================================================
    # 16. DISCLAIMER
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '⚠️ Disclaimer'
        '</div>',
        unsafe_allow_html=True
    )

    st.caption(
        """
        CryptoShield provides blockchain analytics and
        investigation intelligence. Risk scores, behavioral
        indicators, transaction patterns, and VASP associations
        are analytical outputs and should not be treated as
        definitive proof of fraud, criminal activity, identity,
        ownership, or guilt. Independent investigation and
        verification are required.
        """)


# ============================================================
# EMPTY STATE
# ============================================================

else:

    st.markdown(
        "### 🚀 Start a blockchain investigation"
    )

    st.write(
        """
        Enter a **victim-reported suspect wallet address**
        in the sidebar.

        CryptoShield will:

        1. 🔗 Collect blockchain transactions
        2. 🧭 Trace connected wallets
        3. 🕸️ Build a fund-flow network
        4. 🔎 Trace important paths
        5. 🕒 Build an investigation timeline
        6. 🪙 Analyze token transfers
        7. 🧬 Build transaction DNA
        8. 🚨 Detect abnormal indicators
        9. 🏦 Check potential VASP associations
        10. 📊 Calculate an explainable risk score
        11. 🚔 Produce an investigation summary
        12. 📄 Generate a PDF report
        """
    )

    st.info(
        "Investigation flow: "
        "**Reported Wallet → Blockchain Data → "
        "Multi-Hop Trace → Evidence → Risk Assessment → "
        "Investigation Lead**"
    )
