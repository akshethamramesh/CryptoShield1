import streamlit as st
import pandas as pd
import os
import tempfile
from datetime import datetime

from blockchain import trace_wallet
from transaction_dna import analyze_transaction_dna
from abnormal_detection import detect_abnormal_transactions
from risk_engine import calculate_risk_v3
from vasp_detection import detect_vasp
from report_generator import generate_pdf_report

from pyvis.network import Network
import streamlit.components.v1 as components


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 36px;
        font-weight: 800;
        margin-bottom: 5px;
    }

    .subtitle {
        font-size: 17px;
        color: #9ca3af;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 25px;
        font-weight: 750;
        margin-top: 25px;
        margin-bottom: 15px;
    }

    .finding-box {
        padding: 18px;
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.10);
        background: rgba(255,255,255,0.03);
        margin-bottom: 15px;
    }

    .risk-high {
        padding: 18px;
        border-radius: 12px;
        background: rgba(255,70,70,0.12);
        border: 1px solid rgba(255,70,70,0.35);
    }

    .risk-medium {
        padding: 18px;
        border-radius: 12px;
        background: rgba(255,180,50,0.12);
        border: 1px solid rgba(255,180,50,0.35);
    }

    .risk-low {
        padding: 18px;
        border-radius: 12px;
        background: rgba(50,200,120,0.12);
        border: 1px solid rgba(50,200,120,0.35);
    }

    .flow-card {
        padding: 18px;
        border-radius: 12px;
        background: rgba(255,255,255,0.035);
        border: 1px solid rgba(255,255,255,0.10);
        text-align: center;
        margin: 8px 0;
    }

    .flow-arrow {
        text-align: center;
        font-size: 28px;
        margin: 5px 0;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SESSION STATE
# ============================================================

if "investigation" not in st.session_state:
    st.session_state.investigation = None

if "dna" not in st.session_state:
    st.session_state.dna = None

if "abnormal" not in st.session_state:
    st.session_state.abnormal = []

if "vasp" not in st.session_state:
    st.session_state.vasp = []

if "risk" not in st.session_state:
    st.session_state.risk = None

if "patterns" not in st.session_state:
    st.session_state.patterns = []


# ============================================================
# HELPERS
# ============================================================

def normalize_address(address):

    if not address:
        return ""

    return str(address).strip().lower()


def format_address(address, chars=8):

    if not address:
        return "Unknown"

    address = str(address)

    if len(address) <= chars * 2:
        return address

    return f"{address[:chars]}...{address[-chars:]}"


def safe_float(value):

    try:
        return float(value)
    except Exception:
        return 0.0


def get_timestamp(tx):

    try:
        return int(tx.get("timeStamp", 0))
    except Exception:
        return 0


def format_time(timestamp):

    try:

        if not timestamp:
            return "Unknown"

        return datetime.fromtimestamp(
            int(timestamp)
        ).strftime("%Y-%m-%d %H:%M:%S")

    except Exception:

        return "Unknown"


# ============================================================
# PATTERN DETECTION
# ============================================================

def detect_patterns(transactions, trace_data):

    patterns = []

    if not transactions:
        return patterns

    # High transaction activity

    if len(transactions) >= 100:

        patterns.append({
            "pattern": "High transaction activity",
            "severity": "Medium",
            "description":
                f"{len(transactions)} transactions were observed "
                "in the analyzed network."
        })


    # Destination/source diversity

    destinations = set()
    sources = set()

    for tx in transactions:

        sender = normalize_address(
            tx.get("from", "")
        )

        receiver = normalize_address(
            tx.get("to", "")
        )

        if sender:
            sources.add(sender)

        if receiver:
            destinations.add(receiver)


    if len(destinations) >= 10:

        patterns.append({
            "pattern": "High destination diversity",
            "severity": "Medium",
            "description":
                f"Funds interacted with {len(destinations)} "
                "destination addresses."
        })


    if len(sources) >= 10:

        patterns.append({
            "pattern": "High source diversity",
            "severity": "Medium",
            "description":
                f"Funds were received from {len(sources)} "
                "source addresses."
        })


    # Rapid movement

    timestamps = []

    for tx in transactions:

        timestamp = get_timestamp(tx)

        if timestamp:
            timestamps.append(timestamp)


    timestamps.sort()

    rapid_count = 0

    for i in range(1, len(timestamps)):

        if timestamps[i] - timestamps[i - 1] <= 300:

            rapid_count += 1


    if rapid_count >= 5:

        patterns.append({
            "pattern": "Rapid fund movement",
            "severity": "High",
            "description":
                f"{rapid_count} rapid transaction intervals "
                "were detected."
        })


    # Multi-hop

    max_hop = trace_data.get(
        "max_hop",
        0
    )

    if max_hop >= 2:

        patterns.append({
            "pattern": "Multi-hop fund movement",
            "severity": "High",
            "description":
                f"Fund-flow relationships were traced up to "
                f"{max_hop} hops."
        })


    # Token activity

    token_count = trace_data.get(
        "token_count",
        0
    )

    token_types = trace_data.get(
        "token_types",
        []
    )

    if token_count > 0:

        patterns.append({
            "pattern": "Token transfer activity",
            "severity": "Informational",
            "description":
                f"{token_count} token transfers involving "
                f"{len(token_types)} token types were observed."
        })


    return patterns


# ============================================================
# WALLET IMPORTANCE
# ============================================================

def wallet_importance(
    wallet,
    transactions,
    start_wallet
):

    wallet = normalize_address(wallet)
    start_wallet = normalize_address(start_wallet)

    if wallet == start_wallet:
        return 999999

    count = 0

    for tx in transactions:

        sender = normalize_address(
            tx.get("from", "")
        )

        receiver = normalize_address(
            tx.get("to", "")
        )

        if wallet == sender or wallet == receiver:

            count += 1


    return count


# ============================================================
# BUILD FUND FLOW GRAPH
# ============================================================

def build_fund_flow_graph(
    trace_data,
    vasp_matches
):

    transactions = trace_data.get(
        "transactions",
        []
    )

    start_wallet = normalize_address(
        trace_data.get(
            "start_wallet",
            ""
        )
    )

    wallet_hops = trace_data.get(
        "wallet_hops",
        {}
    )


    # --------------------------------------------------------
    # Network
    # --------------------------------------------------------

    net = Network(
        height="650px",
        width="100%",
        bgcolor="#111111",
        font_color="white",
        directed=True
    )


    net.set_options(
        """
        {
            "nodes": {
                "shape": "dot",
                "font": {
                    "size": 15,
                    "color": "white"
                },
                "borderWidth": 2
            },

            "edges": {
                "arrows": {
                    "to": {
                        "enabled": true
                    }
                },

                "smooth": {
                    "type": "curvedCW",
                    "roundness": 0.2
                },

                "font": {
                    "size": 11,
                    "color": "white"
                }
            },

            "physics": {
                "enabled": false
            },

            "layout": {
                "hierarchical": {
                    "enabled": true,
                    "direction": "LR",
                    "sortMethod": "directed",
                    "levelSeparation": 220,
                    "nodeSpacing": 150
                }
            },

            "interaction": {
                "hover": true,
                "navigationButtons": true,
                "zoomView": true
            }
        }
        """
    )


    # --------------------------------------------------------
    # VASP addresses
    # --------------------------------------------------------

    vasp_addresses = set()

    for item in vasp_matches:

        address = normalize_address(
            item.get(
                "address",
                ""
            )
        )

        if address:
            vasp_addresses.add(address)


    # --------------------------------------------------------
    # Wallet scores
    # --------------------------------------------------------

    wallet_scores = {}

    for wallet in wallet_hops:

        wallet_scores[wallet] = wallet_importance(
            wallet,
            transactions,
            start_wallet
        )


    # --------------------------------------------------------
    # Add nodes
    # --------------------------------------------------------

    for wallet, hop in wallet_hops.items():

        wallet = normalize_address(wallet)

        if not wallet:
            continue


        if wallet == start_wallet:

            label = "REPORTED\nWALLET"

            title = (
                "<b>Reported Suspect Wallet</b><br>"
                f"Address: {wallet}"
            )

            size = 38

            color = "#ff4b4b"


        elif wallet in vasp_addresses:

            label = "POTENTIAL\nVASP"

            matched = next(
                (
                    x for x in vasp_matches
                    if normalize_address(
                        x.get("address", "")
                    ) == wallet
                ),
                {}
            )

            title = (
                "<b>Potential VASP Association</b><br>"
                f"Name: {matched.get('name', 'Unknown')}<br>"
                f"Address: {wallet}<br>"
                "Status: Potential association"
            )

            size = 34

            color = "#b26cff"


        else:

            label = (
                f"HOP {hop}\n"
                f"{format_address(wallet, 6)}"
            )

            title = (
                "<b>Connected Wallet</b><br>"
                f"Address: {wallet}<br>"
                f"Hop: {hop}<br>"
                f"Interactions: {wallet_scores.get(wallet, 0)}"
            )

            size = max(
                22,
                min(
                    32,
                    20 + wallet_scores.get(wallet, 0)
                )
            )

            if hop == 1:

                color = "#ffd43b"

            elif hop == 2:

                color = "#ff9f43"

            else:

                color = "#9b8cff"


        net.add_node(
            wallet,
            label=label,
            title=title,
            color=color,
            size=size,
            level=hop
        )


    # --------------------------------------------------------
    # Edge aggregation
    # --------------------------------------------------------

    edge_data = {}


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

        if sender not in wallet_hops:
            continue

        if receiver not in wallet_hops:
            continue


        token_contract = tx.get(
            "token_contract",
            ""
        )


        key = (
            sender,
            receiver,
            token_contract
        )


        if key not in edge_data:

            edge_data[key] = {
                "count": 0,
                "value": 0,
                "asset": tx.get(
                    "asset",
                    "Unknown"
                ),
                "hash": tx.get(
                    "hash",
                    ""
                )
            }


        edge_data[key]["count"] += 1

        edge_data[key]["value"] += safe_float(
            tx.get(
                "value",
                0
            )
        )


    # --------------------------------------------------------
    # Top edges
    # --------------------------------------------------------

    sorted_edges = sorted(
        edge_data.items(),
        key=lambda x: x[1]["count"],
        reverse=True
    )


    sorted_edges = sorted_edges[:40]


    for (
        sender,
        receiver,
        token_contract
    ), info in sorted_edges:

        value = info["value"]

        count = info["count"]

        asset = info["asset"]


        value_text = (
            f"{value:.4f} {asset}"
            if asset
            else f"{value:.4f}"
        )


        title = (
            "<b>Fund Flow</b><br>"
            f"From: {sender}<br>"
            f"To: {receiver}<br>"
            f"Asset: {asset}<br>"
            f"Observed value: {value_text}<br>"
            f"Transactions: {count}<br>"
            f"Transaction: {info['hash']}"
        )


        net.add_edge(
            sender,
            receiver,
            title=title,
            label=f"{count} tx",
            width=min(
                6,
                1 + count * 0.5
            )
        )


    return net


# ============================================================
# FIND TRACE PATH
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

        if not sender or not receiver:
            continue


        graph.setdefault(
            sender,
            []
        ).append(
            receiver
        )


    queue = [
        (
            start_wallet,
            [start_wallet]
        )
    ]

    visited = {
        start_wallet
    }


    while queue:

        current, path = queue.pop(0)


        if current == target_wallet:

            return path


        for next_wallet in graph.get(
            current,
            []
        ):

            if next_wallet in visited:
                continue


            visited.add(
                next_wallet
            )


            queue.append(
                (
                    next_wallet,
                    path + [next_wallet]
                )
            )


    return []


# ============================================================
# FIND BEST FLOW PATH
# ============================================================

def find_best_flow_path(
    transactions,
    start_wallet,
    wallet_hops,
    vasp_matches
):

    start_wallet = normalize_address(
        start_wallet
    )


    vasp_addresses = {
        normalize_address(
            x.get(
                "address",
                ""
            )
        )
        for x in vasp_matches
    }


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

        if not sender or not receiver:
            continue

        if sender not in wallet_hops:
            continue

        if receiver not in wallet_hops:
            continue


        graph.setdefault(
            sender,
            []
        ).append(
            receiver
        )


    queue = [
        (
            start_wallet,
            [start_wallet]
        )
    ]


    visited = {
        start_wallet
    }


    best_path = [
        start_wallet
    ]


    while queue:

        current, path = queue.pop(0)


        # VASP is preferred endpoint

        if (
            current in vasp_addresses
            and len(path) > 1
        ):

            return path


        if len(path) > len(best_path):

            best_path = path


        for next_wallet in graph.get(
            current,
            []
        ):

            if next_wallet in visited:
                continue


            visited.add(
                next_wallet
            )


            queue.append(
                (
                    next_wallet,
                    path + [next_wallet]
                )
            )


    return best_path


# ============================================================
# INVESTIGATION FINDINGS
# ============================================================

def create_investigation_finding(
    trace_data,
    dna,
    abnormal,
    vasp,
    risk
):

    score, level, factors = risk


    findings = []


    transaction_count = dna.get(
        "transaction_count",
        0
    )

    rapid = dna.get(
        "rapid_movements",
        0
    )

    fan_in = dna.get(
        "fan_in",
        0
    )

    fan_out = dna.get(
        "fan_out",
        0
    )

    max_hop = trace_data.get(
        "max_hop",
        0
    )

    token_count = trace_data.get(
        "token_count",
        0
    )


    if transaction_count >= 100:

        findings.append(
            f"High transaction activity: "
            f"{transaction_count} transactions analyzed."
        )


    if max_hop >= 2:

        findings.append(
            f"Multi-hop movement was observed up to "
            f"{max_hop} hops."
        )


    if rapid >= 5:

        findings.append(
            f"{rapid} rapid movement intervals were detected."
        )


    if fan_out >= 5:

        findings.append(
            f"High fan-out behavior was observed with "
            f"{fan_out} destinations."
        )


    if fan_in >= 5:

        findings.append(
            f"High fan-in behavior was observed with "
            f"{fan_in} sources."
        )


    if token_count > 0:

        findings.append(
            f"{token_count} token transfers were observed."
        )


    if vasp:

        findings.append(
            f"{len(vasp)} potential VASP association(s) "
            "were identified."
        )

    else:

        findings.append(
            "No verified VASP association was identified "
            "in the current registry."
        )


    return findings


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        "# 🛡️ CryptoShield"
    )

    st.markdown(
        "**Blockchain Fraud Intelligence**"
    )

    st.caption(
        "Start with a victim-reported suspect wallet."
    )


    st.divider()


    reported_wallet = st.text_input(
        "Reported Suspect Wallet",
        placeholder="0x..."
    )


    blockchain = st.selectbox(
        "Blockchain",
        [
            "Ethereum",
            "BSC"
        ]
    )


    max_hops = st.slider(
        "Maximum Investigation Hops",
        min_value=1,
        max_value=3,
        value=2
    )


    start_button = st.button(
        "🔎 Start Investigation",
        use_container_width=True
    )


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ CryptoShield</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Real-Time Blockchain Fraud Intelligence & Fund-Flow Investigation'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# START INVESTIGATION
# ============================================================

if start_button:

    if not reported_wallet:

        st.error(
            "Please enter a reported suspect wallet address."
        )

        st.stop()


    reported_wallet = reported_wallet.strip()


    if not reported_wallet.startswith("0x"):

        st.error(
            "Please enter a valid EVM wallet address."
        )

        st.stop()


    with st.spinner(
        "🔎 Collecting blockchain evidence and tracing fund flows..."
    ):

        try:

            # IMPORTANT:
            # blockchain.py expects max_hop, NOT max_hops

            trace_data = trace_wallet(
                reported_wallet,
                chain=blockchain,
                max_hop=max_hops
            )


            transactions = trace_data.get(
                "transactions",
                []
            )


            dna = analyze_transaction_dna(
                transactions,
                reported_wallet
            )


            abnormal = detect_abnormal_transactions(
                transactions
            )


            vasp = detect_vasp(
                transactions
            )


            patterns = detect_patterns(
                transactions,
                trace_data
            )


            risk = calculate_risk_v3(

                transaction_count=dna.get(
                    "transaction_count",
                    0
                ),

                connected_wallets=len(
                    trace_data.get(
                        "visited_wallets",
                        []
                    )
                ),

                rapid_movements=dna.get(
                    "rapid_movements",
                    0
                ),

                abnormal_alerts=len(
                    abnormal
                ),

                fan_in=dna.get(
                    "fan_in",
                    0
                ),

                fan_out=dna.get(
                    "fan_out",
                    0
                ),

                max_hop=trace_data.get(
                    "max_hop",
                    0
                ),

                vasp_matches=len(
                    vasp
                ),

                token_transactions=trace_data.get(
                    "token_count",
                    0
                ),

                token_types=len(
                    trace_data.get(
                        "token_types",
                        []
                    )
                )
            )


            st.session_state.investigation = trace_data

            st.session_state.dna = dna

            st.session_state.abnormal = abnormal

            st.session_state.vasp = vasp

            st.session_state.risk = risk

            st.session_state.patterns = patterns


            st.success(
                "Investigation completed successfully."
            )


        except Exception as e:

            st.error(
                f"Investigation failed: {e}"
            )

            st.stop()


# ============================================================
# NO INVESTIGATION
# ============================================================

if st.session_state.investigation is None:

    st.info(
        "👈 Enter a victim-reported suspect wallet and "
        "click **Start Investigation**."
    )


    st.markdown(
        """
        ### 🔍 What CryptoShield investigates

        **Reported Wallet**
        ↓
        **Blockchain Data**
        ↓
        **Multi-Hop Fund Tracing**
        ↓
        **Suspicious Pattern Detection**
        ↓
        **Explainable Risk Score**
        ↓
        **Potential VASP Association**
        ↓
        **Investigation Report**

        CryptoShield provides analytical investigation leads.
        It does not declare a wallet or person criminal.
        """
    )

    st.stop()


# ============================================================
# LOAD INVESTIGATION
# ============================================================

trace_data = st.session_state.investigation

dna = st.session_state.dna

abnormal = st.session_state.abnormal

vasp = st.session_state.vasp

risk = st.session_state.risk

patterns = st.session_state.patterns


transactions = trace_data.get(
    "transactions",
    []
)


start_wallet = trace_data.get(
    "start_wallet",
    reported_wallet
)


score, risk_level, risk_factors = risk


# ============================================================
# 1. INVESTIGATION OVERVIEW
# ============================================================

st.markdown(
    '<div class="section-title">'
    '1️⃣ Investigation Overview'
    '</div>',
    unsafe_allow_html=True
)


col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Reported Wallet",
        format_address(
            start_wallet
        )
    )


with col2:

    st.metric(
        "Blockchain",
        blockchain
    )


with col3:

    st.metric(
        "Transactions",
        len(transactions)
    )


with col4:

    st.metric(
        "Maximum Hop",
        trace_data.get(
            "max_hop",
            0
        )
    )


# ============================================================
# 2. RISK STATUS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '2️⃣ Risk Status'
    '</div>',
    unsafe_allow_html=True
)


if risk_level == "HIGH":

    risk_class = "risk-high"
    emoji = "🔴"

elif risk_level == "MEDIUM":

    risk_class = "risk-medium"
    emoji = "🟠"

else:

    risk_class = "risk-low"
    emoji = "🟢"


st.markdown(
    f"""
    <div class="{risk_class}">

        <h2>{emoji} {risk_level} RISK</h2>

        <h1>{score}/100</h1>

        <p>
        Analytical risk score based on observed blockchain
        indicators. This is not a criminal verdict.
        </p>

    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# 3. EXPLAINABLE RISK
# ============================================================

st.markdown(
    '<div class="section-title">'
    '3️⃣ Explainable Risk Assessment'
    '</div>',
    unsafe_allow_html=True
)


if risk_factors:

    factor_df = pd.DataFrame(
        risk_factors
    )


    st.dataframe(
        factor_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No significant risk factors were triggered."
    )


# ============================================================
# 4. FUND FLOW INVESTIGATION
# ============================================================

st.markdown(
    '<div class="section-title">'
    '4️⃣ 🧭 Police Fund-Flow Investigation'
    '</div>',
    unsafe_allow_html=True
)


st.write(
    """
    The reported wallet is the starting point.
    CryptoShield follows connected transaction relationships
    across multiple hops and highlights important fund-flow paths.
    """
)


# ------------------------------------------------------------
# Primary path
# ------------------------------------------------------------

best_path = find_best_flow_path(
    transactions,
    start_wallet,
    trace_data.get(
        "wallet_hops",
        {}
    ),
    vasp
)


if best_path:

    st.markdown(
        "### 🔎 Primary Traced Path"
    )


    vasp_addresses = {
        normalize_address(
            x.get(
                "address",
                ""
            )
        )
        for x in vasp
    }


    for index, wallet in enumerate(
        best_path
    ):

        hop_number = trace_data.get(
            "wallet_hops",
            {}
        ).get(
            wallet,
            index
        )


        if normalize_address(wallet) == normalize_address(
            start_wallet
        ):

            label = "🔴 REPORTED WALLET"


        elif normalize_address(wallet) in vasp_addresses:

            label = "🟣 POTENTIAL VASP"


        else:

            label = f"🟡 HOP {hop_number}"


        st.markdown(
            f"""
            <div class="flow-card">

                <h3>{label}</h3>

                <p>
                <b>{format_address(wallet, 10)}</b>
                </p>

                <small>{wallet}</small>

            </div>
            """,
            unsafe_allow_html=True
        )


        if index < len(best_path) - 1:

            st.markdown(
                '<div class="flow-arrow">⬇️</div>',
                unsafe_allow_html=True
            )


else:

    st.info(
        "No clear multi-hop path was reconstructed."
    )


# ------------------------------------------------------------
# Interactive graph
# ------------------------------------------------------------

st.markdown(
    "### 🌐 Interactive Fund-Flow Network"
)


net = build_fund_flow_graph(
    trace_data,
    vasp
)


with tempfile.NamedTemporaryFile(
    delete=False,
    suffix=".html"
) as tmp:

    graph_path = tmp.name


net.save_graph(
    graph_path
)


with open(
    graph_path,
    "r",
    encoding="utf-8"
) as file:

    graph_html = file.read()


components.html(
    graph_html,
    height=680,
    scrolling=True
)


try:

    os.remove(
        graph_path
    )

except Exception:

    pass


# ============================================================
# 5. TRACE FUNDS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '5️⃣ 🔍 Trace Funds'
    '</div>',
    unsafe_allow_html=True
)


wallet_options = list(
    trace_data.get(
        "wallet_hops",
        {}
    ).keys()
)


if wallet_options:

    selected_wallet = st.selectbox(
        "Select a wallet to trace",
        wallet_options,
        format_func=lambda x:
            f"HOP {trace_data.get('wallet_hops', {}).get(x, '?')} — "
            f"{format_address(x, 10)}"
    )


    if st.button(
        "Trace Transaction Path"
    ):

        path = find_trace_path(
            transactions,
            start_wallet,
            selected_wallet
        )


        if path:

            st.markdown(
                "### 🧭 Reconstructed Path"
            )


            for i, wallet in enumerate(path):

                st.write(
                    f"**{i}.** `{wallet}`"
                )

        else:

            st.warning(
                "No transaction path could be reconstructed."
            )


# ============================================================
# 6. TIMELINE
# ============================================================

st.markdown(
    '<div class="section-title">'
    '6️⃣ 🕒 Investigation Timeline'
    '</div>',
    unsafe_allow_html=True
)


timeline_rows = []


sorted_transactions = sorted(
    transactions,
    key=lambda x: get_timestamp(x)
)


for tx in sorted_transactions[:100]:

    timeline_rows.append({

        "Time":
            format_time(
                get_timestamp(tx)
            ),

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
                "Unknown"
            ),

        "Value":
            tx.get(
                "value",
                0
            ),

        "Type":
            tx.get(
                "type",
                "Unknown"
            )
    })


if timeline_rows:

    st.dataframe(
        pd.DataFrame(
            timeline_rows
        ),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No timestamped transactions available."
    )


# ============================================================
# 7. TOKEN INTELLIGENCE
# ============================================================

st.markdown(
    '<div class="section-title">'
    '7️⃣ 🪙 Token Transfer Intelligence'
    '</div>',
    unsafe_allow_html=True
)


token_transactions = trace_data.get(
    "token_transactions",
    []
)

native_transactions = trace_data.get(
    "native_transactions",
    []
)

token_types = trace_data.get(
    "token_types",
    []
)


col1, col2, col3 = st.columns(3)


with col1:

    st.metric(
        "Native Transactions",
        len(native_transactions)
    )


with col2:

    st.metric(
        "Token Transfers",
        len(token_transactions)
    )


with col3:

    st.metric(
        "Token Types",
        len(token_types)
    )


if token_types:

    st.markdown(
        "### Detected Token Types"
    )


    token_rows = []

    for token in token_types:

        token_rows.append(
            {
                "Token": token
            }
        )


    st.dataframe(
        pd.DataFrame(
            token_rows
        ),
        use_container_width=True,
        hide_index=True
    )


if token_transactions:

    st.markdown(
        "### Recent Token Transfers"
    )


    token_rows = []


    for tx in token_transactions[:100]:

        token_rows.append({

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
        })


    st.dataframe(
        pd.DataFrame(
            token_rows
        ),
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# 8. TRANSACTION DNA
# ============================================================

st.markdown(
    '<div class="section-title">'
    '8️⃣ 🧬 Transaction DNA'
    '</div>',
    unsafe_allow_html=True
)


col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Unique Senders",
        dna.get(
            "unique_senders",
            0
        )
    )


with col2:

    st.metric(
        "Unique Receivers",
        dna.get(
            "unique_receivers",
            0
        )
    )


with col3:

    st.metric(
        "Fan-In",
        dna.get(
            "fan_in",
            0
        )
    )


with col4:

    st.metric(
        "Fan-Out",
        dna.get(
            "fan_out",
            0
        )
    )


col1, col2, col3 = st.columns(3)


with col1:

    st.metric(
        "Rapid Movements",
        dna.get(
            "rapid_movements",
            0
        )
    )


with col2:

    st.metric(
        "Average Transfer",
        f"{dna.get('average_transfer', 0):.4f}"
    )


with col3:

    st.metric(
        "Total Observed Volume",
        f"{dna.get('total_volume', 0):.4f}"
    )


if dna.get(
    "behavior_indicators"
):

    st.markdown(
        "### Behavioral Indicators"
    )


    for indicator in dna.get(
        "behavior_indicators",
        []
    ):

        st.write(
            f"• {indicator}"
        )


# ============================================================
# 9. PATTERNS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '9️⃣ 🚨 Detected Fund-Flow Patterns'
    '</div>',
    unsafe_allow_html=True
)


if patterns:

    for pattern in patterns:

        st.markdown(
            f"""
            <div class="finding-box">

                <h4>{pattern.get('pattern', 'Unknown')}</h4>

                <p>
                <b>Severity:</b>
                {pattern.get('severity', 'Informational')}
                </p>

                <p>
                {pattern.get('description', '')}
                </p>

            </div>
            """,
            unsafe_allow_html=True
        )

else:

    st.info(
        "No significant fund-flow patterns detected."
    )


# ============================================================
# 10. ABNORMAL TRANSACTIONS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '🔟 Abnormal Transaction Analysis'
    '</div>',
    unsafe_allow_html=True
)


if abnormal:

    abnormal_df = pd.DataFrame(
        abnormal
    )


    st.dataframe(
        abnormal_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No abnormal transaction indicators were detected "
        "by the current rules."
    )


# ============================================================
# 11. VASP
# ============================================================

st.markdown(
    '<div class="section-title">'
    '1️⃣1️⃣ 🏦 Potential VASP / Exchange Association'
    '</div>',
    unsafe_allow_html=True
)


if vasp:

    st.success(
        f"{len(vasp)} potential VASP association(s) identified."
    )


    vasp_df = pd.DataFrame(
        vasp
    )


    st.dataframe(
        vasp_df,
        use_container_width=True,
        hide_index=True
    )


    st.warning(
        "A potential association does not prove wallet ownership "
        "or criminal activity. Investigators must independently "
        "verify the attribution."
    )


else:

    st.info(
        "No verified VASP association was identified "
        "in the current registry."
    )


    st.caption(
        "This does not mean the investigation failed. "
        "Fund-flow paths and behavioral indicators remain "
        "useful investigation leads."
    )


# ============================================================
# 12. WHY THIS WALLET MATTERS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '1️⃣2️⃣ 🎯 Why This Wallet Matters'
    '</div>',
    unsafe_allow_html=True
)


findings = create_investigation_finding(
    trace_data,
    dna,
    abnormal,
    vasp,
    risk
)


for finding in findings:

    st.markdown(
        f"• {finding}"
    )


# ============================================================
# 13. INVESTIGATION CONCLUSION
# ============================================================

st.markdown(
    '<div class="section-title">'
    '1️⃣3️⃣ 🧾 Investigation Conclusion'
    '</div>',
    unsafe_allow_html=True
)


if risk_level == "HIGH":

    conclusion = (
        f"The analyzed reported wallet exhibits multiple "
        f"blockchain risk indicators with an analytical "
        f"risk score of {score}/100. "
    )

elif risk_level == "MEDIUM":

    conclusion = (
        f"The analyzed reported wallet exhibits several "
        f"blockchain risk indicators with an analytical "
        f"risk score of {score}/100. "
    )

else:

    conclusion = (
        f"The analyzed reported wallet currently shows "
        f"limited risk indicators with an analytical "
        f"risk score of {score}/100. "
    )


if trace_data.get(
    "max_hop",
    0
) >= 2:

    conclusion += (
        f"Fund-flow relationships were traced across up to "
        f"{trace_data.get('max_hop', 0)} hops. "
    )


if dna.get(
    "rapid_movements",
    0
) >= 5:

    conclusion += (
        "Rapid fund movement indicators were observed. "
    )


if vasp:

    conclusion += (
        "A potential VASP association was identified and "
        "should be independently verified. "
    )

else:

    conclusion += (
        "No verified VASP association was identified "
        "in the current registry. "
    )


conclusion += (
    "The results represent analytical investigation leads "
    "and should not be treated as proof of criminal activity."
)


st.markdown(
    f"""
    <div class="finding-box">

        <h3>🔎 Final Finding</h3>

        <p>{conclusion}</p>

    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# 14. TRANSACTION EVIDENCE
# ============================================================

st.markdown(
    '<div class="section-title">'
    '1️⃣4️⃣ 📋 Transaction Evidence'
    '</div>',
    unsafe_allow_html=True
)


if transactions:

    evidence_rows = []


    for tx in transactions[:100]:

        evidence_rows.append({

            "Hash":
                format_address(
                    tx.get(
                        "hash",
                        ""
                    ),
                    10
                ),

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
                    "Unknown"
                ),

            "Value":
                tx.get(
                    "value",
                    0
                ),

            "Type":
                tx.get(
                    "type",
                    "Unknown"
                ),

            "Time":
                format_time(
                    get_timestamp(tx)
                )
        })


    st.dataframe(
        pd.DataFrame(
            evidence_rows
        ),
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# 15. INVESTIGATION SUMMARY
# ============================================================

st.markdown(
    '<div class="section-title">'
    '1️⃣5️⃣ 📌 Investigation Summary'
    '</div>',
    unsafe_allow_html=True
)


summary = {

    "Reported Wallet":
        start_wallet,

    "Blockchain":
        blockchain,

    "Transactions Analyzed":
        len(transactions),

    "Connected Wallets":
        len(
            trace_data.get(
                "visited_wallets",
                []
            )
        ),

    "Maximum Hop":
        trace_data.get(
            "max_hop",
            0
        ),

    "Rapid Movements":
        dna.get(
            "rapid_movements",
            0
        ),

    "Token Transfers":
        trace_data.get(
            "token_count",
            0
        ),

    "Token Types":
        len(
            trace_data.get(
                "token_types",
                []
            )
        ),

    "Potential VASP Associations":
        len(vasp),

    "Risk Score":
        f"{score}/100",

    "Risk Level":
        risk_level
}


summary_df = pd.DataFrame(
    list(
        summary.items()
    ),
    columns=[
        "Investigation Metric",
        "Result"
    ]
)


st.dataframe(
    summary_df,
    use_container_width=True,
    hide_index=True
)


# ============================================================
# 16. PDF REPORT
# ============================================================

st.markdown(
    '<div class="section-title">'
    '1️⃣6️⃣ 📄 Investigation Report'
    '</div>',
    unsafe_allow_html=True
)


if st.button(
    "📄 Generate Investigation Report"
):

    try:

        pdf_path = generate_pdf_report(
            start_wallet,
            blockchain,
            trace_data,
            dna,
            patterns,
            abnormal,
            vasp,
            risk
        )


        with open(
            pdf_path,
            "rb"
        ) as pdf_file:

            st.download_button(
                label="⬇️ Download Investigation Report",
                data=pdf_file,
                file_name="CryptoShield_Investigation_Report.pdf",
                mime="application/pdf"
            )


    except TypeError:

        st.warning(
            "Your current report_generator.py uses a different "
            "function signature."
        )

    except Exception as e:

        st.error(
            f"Report generation failed: {e}"
        )


# ============================================================
# DISCLAIMER
# ============================================================

st.divider()


st.caption(
    """
    ⚠️ DISCLAIMER:
    CryptoShield is an analytical blockchain investigation prototype.
    Risk scores, behavioral indicators and VASP associations are not
    criminal determinations. Wallet ownership and attribution must be
    independently verified using appropriate investigative procedures
    and authoritative evidence.
    """
)
