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
        font-size: 38px;
        font-weight: 800;
        margin-bottom: 4px;
    }

    .subtitle {
        font-size: 17px;
        color: #9ca3af;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 25px;
        font-weight: 750;
        margin-top: 30px;
        margin-bottom: 15px;
    }

    .risk-high {
        padding: 20px;
        border-radius: 14px;
        background: rgba(255, 75, 75, 0.12);
        border: 1px solid rgba(255, 75, 75, 0.35);
        margin-bottom: 15px;
    }

    .risk-medium {
        padding: 20px;
        border-radius: 14px;
        background: rgba(255, 180, 50, 0.12);
        border: 1px solid rgba(255, 180, 50, 0.35);
        margin-bottom: 15px;
    }

    .risk-low {
        padding: 20px;
        border-radius: 14px;
        background: rgba(50, 200, 120, 0.12);
        border: 1px solid rgba(50, 200, 120, 0.35);
        margin-bottom: 15px;
    }

    .flow-card {
        padding: 18px;
        border-radius: 12px;
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.12);
        text-align: center;
        margin-top: 10px;
        margin-bottom: 10px;
    }

    .finding-box {
        padding: 18px;
        border-radius: 12px;
        background: rgba(255,255,255,0.035);
        border: 1px solid rgba(255,255,255,0.10);
        margin-bottom: 15px;
    }

    .flow-arrow {
        text-align: center;
        font-size: 26px;
        margin: 4px;
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

if "selected_chain" not in st.session_state:
    st.session_state.selected_chain = "Ethereum"


# ============================================================
# HELPER FUNCTIONS
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


def get_native_symbol(chain):
    if chain == "BSC":
        return "BNB"
    return "ETH"


# ============================================================
# PATTERN DETECTION
# ============================================================

def detect_patterns(transactions, trace_data, dna):

    patterns = []

    if not transactions:
        return patterns

    transaction_count = len(transactions)

    if transaction_count >= 100:
        patterns.append({
            "pattern": "High transaction activity",
            "severity": "Medium",
            "description":
                f"{transaction_count} transactions were observed "
                "in the analyzed blockchain network."
        })

    sources = set()
    destinations = set()

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
                f"Funds were associated with {len(sources)} "
                "source addresses."
        })

    rapid_movements = dna.get(
        "rapid_movements",
        0
    )

    if rapid_movements >= 5:
        patterns.append({
            "pattern": "Rapid fund movement",
            "severity": "High",
            "description":
                f"{rapid_movements} rapid movement indicators "
                "were observed across wallet activity."
        })

    max_hop = trace_data.get(
        "max_hop",
        0
    )

    if max_hop >= 2:
        patterns.append({
            "pattern": "Multi-hop fund movement",
            "severity": "High",
            "description":
                f"Transaction relationships were reconstructed "
                f"up to {max_hop} hops."
        })

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

def wallet_importance(wallet, transactions, start_wallet):

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
# FUND FLOW GRAPH
# ============================================================

def build_fund_flow_graph(trace_data, vasp_matches):

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
              "roundness": 0.15
            },

            "font": {
              "size": 10,
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

    wallet_scores = {}

    for wallet in wallet_hops:

        wallet_scores[wallet] = wallet_importance(
            wallet,
            transactions,
            start_wallet
        )

    for wallet, hop in wallet_hops.items():

        wallet = normalize_address(wallet)

        if not wallet:
            continue

        if wallet == start_wallet:

            label = "REPORTED\nWALLET"
            color = "#ff4b4b"
            size = 38

            title = (
                "<b>Reported Suspect Wallet</b><br>"
                f"{wallet}<br>"
                "Investigation starting point"
            )

        elif wallet in vasp_addresses:

            label = "POTENTIAL\nVASP"
            color = "#b26cff"
            size = 34

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
                f"Source: {matched.get('source', 'Unknown')}<br>"
                "Requires independent verification"
            )

        else:

            label = (
                f"HOP {hop}\n"
                f"{format_address(wallet, 6)}"
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

            title = (
                "<b>Connected Wallet</b><br>"
                f"Address: {wallet}<br>"
                f"Hop: {hop}<br>"
                f"Observed interactions: "
                f"{wallet_scores.get(wallet, 0)}"
            )

        net.add_node(
            wallet,
            label=label,
            title=title,
            color=color,
            size=size,
            level=hop
        )

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

        asset = tx.get(
            "asset",
            "Unknown"
        )

        tx_type = tx.get(
            "type",
            "native"
        )

        key = (
            sender,
            receiver,
            asset,
            tx_type
        )

        if key not in edge_data:

            edge_data[key] = {
                "count": 0,
                "value": 0,
                "asset": asset,
                "type": tx_type,
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

    sorted_edges = sorted(
        edge_data.items(),
        key=lambda x: x[1]["count"],
        reverse=True
    )

    sorted_edges = sorted_edges[:40]

    for key, info in sorted_edges:

        sender = key[0]
        receiver = key[1]

        count = info["count"]
        asset = info["asset"]
        value = info["value"]

        title = (
            "<b>Fund Flow</b><br>"
            f"From: {sender}<br>"
            f"To: {receiver}<br>"
            f"Asset: {asset}<br>"
            f"Observed amount: {value:.6f}<br>"
            f"Transactions: {count}<br>"
            f"Type: {info['type']}"
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
# TRACE PATH
# ============================================================

def find_trace_path(
    transactions,
    start_wallet,
    target_wallet
):

    start_wallet = normalize_address(start_wallet)
    target_wallet = normalize_address(target_wallet)

    graph = {}

    for tx in transactions:

        sender = normalize_address(
            tx.get("from", "")
        )

        receiver = normalize_address(
            tx.get("to", "")
        )

        if not sender or not receiver:
            continue

        graph.setdefault(
            sender,
            []
        ).append(receiver)

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

            visited.add(next_wallet)

            queue.append(
                (
                    next_wallet,
                    path + [next_wallet]
                )
            )

    return []


# ============================================================
# BEST FLOW PATH
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
        ).append(receiver)

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

            visited.add(next_wallet)

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

def create_investigation_findings(
    trace_data,
    dna,
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
            f"Multi-hop movement was observed "
            f"up to {max_hop} hops."
        )

    if rapid >= 5:

        findings.append(
            f"{rapid} rapid activity indicators "
            "were observed."
        )

    if fan_out >= 5:

        findings.append(
            f"High fan-out behavior: "
            f"{fan_out} destination wallets."
        )

    if fan_in >= 5:

        findings.append(
            f"High fan-in behavior: "
            f"{fan_in} source wallets."
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
            "No matching VASP label was found "
            "in the currently configured registry."
        )

    return findings


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("# 🛡️ CryptoShield")

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
        use_container_width=True,
        type="primary"
    )


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ CryptoShield</div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="subtitle">
    Real-Time Blockchain Fraud Intelligence & Fund-Flow Investigation
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# INVESTIGATION
# ============================================================

if start_button:

    if not reported_wallet:

        st.error(
            "Please enter a reported suspect wallet address."
        )

        st.stop()

    reported_wallet = reported_wallet.strip()

    if (
        not reported_wallet.startswith("0x")
        or len(reported_wallet) != 42
    ):

        st.error(
            "Please enter a valid EVM wallet address."
        )

        st.stop()

    with st.spinner(
        "🔎 Collecting blockchain evidence and tracing fund flows..."
    ):

        try:

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
                trace_data,
                dna
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
            st.session_state.selected_chain = blockchain

            st.success(
                "Investigation completed successfully."
            )

        except Exception as e:

            st.error(
                f"Investigation failed: {e}"
            )

            st.stop()


# ============================================================
# EMPTY STATE
# ============================================================

if st.session_state.investigation is None:

    st.info(
        "👈 Enter a victim-reported suspect wallet and "
        "click **Start Investigation**."
    )

    st.markdown(
        """
        ### 🔎 Investigation Workflow

        Reported Wallet  
        ↓  
        Blockchain Transactions  
        ↓  
        Multi-Hop Fund Tracing  
        ↓  
        Behavioral Pattern Detection  
        ↓  
        Explainable Risk Assessment  
        ↓  
        Potential VASP Association  
        ↓  
        Investigation Report
        """
    )

    st.stop()


# ============================================================
# LOAD RESULTS
# ============================================================

trace_data = st.session_state.investigation
dna = st.session_state.dna
abnormal = st.session_state.abnormal
vasp = st.session_state.vasp
risk = st.session_state.risk
patterns = st.session_state.patterns

selected_chain = st.session_state.selected_chain

transactions = trace_data.get(
    "transactions",
    []
)

start_wallet = trace_data.get(
    "start_wallet",
    ""
)

score, risk_level, risk_factors = risk

native_symbol = get_native_symbol(
    selected_chain
)


# ============================================================
# 1 OVERVIEW
# ============================================================

st.markdown(
    '<div class="section-title">1️⃣ Investigation Overview</div>',
    unsafe_allow_html=True
)

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Reported Wallet",
        format_address(start_wallet)
    )

with col2:

    st.metric(
        "Blockchain",
        selected_chain
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
# 2 RISK
# ============================================================

st.markdown(
    '<div class="section-title">2️⃣ Risk Status</div>',
    unsafe_allow_html=True
)

if risk_level == "HIGH":

    risk_class = "risk-high"
    risk_emoji = "🔴"

elif risk_level == "MEDIUM":

    risk_class = "risk-medium"
    risk_emoji = "🟠"

else:

    risk_class = "risk-low"
    risk_emoji = "🟢"

st.markdown(
    f"""
    <div class="{risk_class}">
        <h2>{risk_emoji} {risk_level} RISK</h2>
        <h1>{score}/100</h1>
        <p>
        Explainable analytical risk based on observed
        blockchain behavior. This score is not a criminal verdict.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# 3 EXPLAINABLE RISK
# ============================================================

st.markdown(
    '<div class="section-title">3️⃣ Explainable Risk Assessment</div>',
    unsafe_allow_html=True
)

if risk_factors:

    if isinstance(risk_factors, list):

        try:
            st.dataframe(
                pd.DataFrame(risk_factors),
                use_container_width=True,
                hide_index=True
            )

        except Exception:

            for factor in risk_factors:
                st.write(f"• {factor}")

    elif isinstance(risk_factors, dict):

        st.dataframe(
            pd.DataFrame(
                list(risk_factors.items()),
                columns=[
                    "Risk Factor",
                    "Contribution"
                ]
            ),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.write(risk_factors)

else:

    st.info(
        "No significant risk factors triggered."
    )


# ============================================================
# 4 POLICE FUND FLOW
# ============================================================

st.markdown(
    '<div class="section-title">4️⃣ 🧭 Police Fund-Flow Investigation</div>',
    unsafe_allow_html=True
)

st.write(
    """
    CryptoShield reconstructs transaction relationships starting
    from the victim-reported suspect wallet and follows important
    connected addresses across multiple hops.
    """
)

best_path = find_best_flow_path(
    transactions,
    start_wallet,
    trace_data.get(
        "wallet_hops",
        {}
    ),
    vasp
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

if best_path:

    st.markdown(
        "### 🔎 Primary Traced Path"
    )

    for index, wallet in enumerate(
        best_path
    ):

        hop = trace_data.get(
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

            label = f"🟡 HOP {hop}"

        st.markdown(
            f"""
            <div class="flow-card">
                <h3>{label}</h3>
                <p><b>{format_address(wallet, 10)}</b></p>
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
        "No multi-hop path could be reconstructed."
    )


# ============================================================
# GRAPH
# ============================================================

st.markdown(
    "### 🌐 Interactive Fund-Flow Network"
)

try:

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
        os.remove(graph_path)
    except Exception:
        pass

except Exception as e:

    st.warning(
        f"Graph rendering unavailable: {e}"
    )


# ============================================================
# 5 TRACE FUNDS
# ============================================================

st.markdown(
    '<div class="section-title">5️⃣ 🔍 Trace Funds</div>',
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
            f"HOP "
            f"{trace_data.get('wallet_hops', {}).get(x, '?')} — "
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
                "### 🧭 Reconstructed Transaction Path"
            )

            for index, wallet in enumerate(path):

                if index == 0:
                    st.write(
                        f"🔴 **Reported Wallet:** `{wallet}`"
                    )
                else:
                    st.write(
                        f"➡️ **Hop {index}:** `{wallet}`"
                    )

        else:

            st.warning(
                "No directed transaction path could be reconstructed."
            )


# ============================================================
# 6 TIMELINE
# ============================================================

st.markdown(
    '<div class="section-title">6️⃣ 🕒 Investigation Timeline</div>',
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
        "No transaction timeline available."
    )


# ============================================================
# 7 TOKEN INTELLIGENCE
# ============================================================

st.markdown(
    '<div class="section-title">7️⃣ 🪙 Token Transfer Intelligence</div>',
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

    token_type_rows = [
        {
            "Token": token
        }
        for token in token_types
    ]

    st.dataframe(
        pd.DataFrame(
            token_type_rows
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

            "Tx Hash":
                format_address(
                    tx.get(
                        "hash",
                        ""
                    ),
                    10
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
# 8 TRANSACTION DNA
# ============================================================

st.markdown(
    '<div class="section-title">8️⃣ 🧬 Transaction DNA</div>',
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

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Rapid Activity Indicators",
        dna.get(
            "rapid_movements",
            0
        )
    )

with col2:

    st.metric(
        "Native Transactions",
        dna.get(
            "native_transaction_count",
            0
        )
    )

with col3:

    st.metric(
        f"Native Volume ({native_symbol})",
        f"{dna.get('native_volume', 0):,.6f}"
    )

with col4:

    st.metric(
        f"Avg Native Transfer ({native_symbol})",
        f"{dna.get('average_native_transfer', 0):,.6f}"
    )

st.caption(
    "Native asset volume is calculated separately from token "
    "amounts to avoid mixing ETH/BNB with ERC-20/BEP-20 units."
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
# 9 PATTERNS
# ============================================================

st.markdown(
    '<div class="section-title">9️⃣ 🚨 Detected Fund-Flow Patterns</div>',
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
        "No significant behavioral patterns detected."
    )


# ============================================================
# 10 ABNORMAL
# ============================================================

st.markdown(
    '<div class="section-title">🔟 Abnormal Transaction Analysis</div>',
    unsafe_allow_html=True
)

if abnormal:

    st.dataframe(
        pd.DataFrame(
            abnormal
        ),
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No abnormal transaction indicators were triggered "
        "by the current rules."
    )


# ============================================================
# 11 VASP
# ============================================================

st.markdown(
    '<div class="section-title">1️⃣1️⃣ 🏦 Potential VASP / Exchange Association</div>',
    unsafe_allow_html=True
)

if vasp:

    st.success(
        f"{len(vasp)} potential VASP association(s) identified."
    )

    st.dataframe(
        pd.DataFrame(
            vasp
        ),
        use_container_width=True,
        hide_index=True
    )

    st.warning(
        "Potential association does not prove wallet ownership, "
        "exchange custody, or criminal activity. Attribution must "
        "be independently verified."
    )

else:

    st.info(
        "No matching VASP label was found in the currently "
        "configured registry."
    )

    st.caption(
        "This does not mean the wallet has no exchange connection. "
        "It only means the current registry did not return a match."
    )


# ============================================================
# 12 WHY WALLET MATTERS
# ============================================================

st.markdown(
    '<div class="section-title">1️⃣2️⃣ 🎯 Why This Wallet Matters</div>',
    unsafe_allow_html=True
)

findings = create_investigation_findings(
    trace_data,
    dna,
    vasp,
    risk
)

for finding in findings:

    st.write(
        f"• {finding}"
    )


# ============================================================
# 13 CONCLUSION
# ============================================================

st.markdown(
    '<div class="section-title">1️⃣3️⃣ 🧾 Investigation Conclusion</div>',
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
        f"The analyzed reported wallet currently exhibits "
        f"limited blockchain risk indicators with an "
        f"analytical risk score of {score}/100. "
    )

if trace_data.get(
    "max_hop",
    0
) >= 2:

    conclusion += (
        f"Transaction relationships were reconstructed across "
        f"up to {trace_data.get('max_hop', 0)} hops. "
    )

if dna.get(
    "rapid_movements",
    0
) >= 5:

    conclusion += (
        "Repeated rapid transaction activity indicators "
        "were observed. "
    )

if vasp:

    conclusion += (
        "Potential VASP association information was identified "
        "and should be independently verified. "
    )

else:

    conclusion += (
        "No matching VASP label was found in the currently "
        "configured registry. "
    )

conclusion += (
    "These results are analytical investigation leads and "
    "should not be interpreted as proof of criminal activity."
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
# 14 TRANSACTION EVIDENCE
# ============================================================

st.markdown(
    '<div class="section-title">1️⃣4️⃣ 📋 Transaction Evidence</div>',
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
# 15 SUMMARY
# ============================================================

st.markdown(
    '<div class="section-title">1️⃣5️⃣ 📌 Investigation Summary</div>',
    unsafe_allow_html=True
)

summary = {

    "Reported Wallet":
        start_wallet,

    "Blockchain":
        selected_chain,

    "Transactions Analyzed":
        len(transactions),

    "Native Transactions":
        dna.get(
            "native_transaction_count",
            0
        ),

    "Token Transactions":
        dna.get(
            "token_transaction_count",
            0
        ),

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

    "Fan-In":
        dna.get(
            "fan_in",
            0
        ),

    "Fan-Out":
        dna.get(
            "fan_out",
            0
        ),

    "Rapid Activity Indicators":
        dna.get(
            "rapid_movements",
            0
        ),

    f"Native Volume ({native_symbol})":
        f"{dna.get('native_volume', 0):,.6f}",

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

st.dataframe(
    pd.DataFrame(
        list(
            summary.items()
        ),
        columns=[
            "Investigation Metric",
            "Result"
        ]
    ),
    use_container_width=True,
    hide_index=True
)


# ============================================================
# 16 REPORT
# ============================================================

st.markdown(
    '<div class="section-title">1️⃣6️⃣ 📄 Investigation Report</div>',
    unsafe_allow_html=True
)

if st.button(
    "📄 Generate Investigation Report"
):

    try:

        pdf_path = generate_pdf_report(
            start_wallet,
            selected_chain,
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

            pdf_data = pdf_file.read()

        st.download_button(
            label="⬇️ Download Investigation Report",
            data=pdf_data,
            file_name="CryptoShield_Investigation_Report.pdf",
            mime="application/pdf"
        )

    except TypeError as e:

        st.warning(
            "Your report_generator.py function signature "
            "does not match the current app."
        )

        st.code(
            str(e)
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
    CryptoShield is a blockchain investigation and analytical
    intelligence prototype. Risk scores, behavioral indicators,
    fund-flow relationships, and potential VASP associations are
    investigation leads only. They do not establish wallet ownership,
    identity, exchange custody, or criminal activity. Investigators
    must independently verify attribution using authoritative evidence
    and lawful investigative procedures.
    """
)
