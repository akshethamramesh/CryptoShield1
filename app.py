import streamlit as st
import pandas as pd
from datetime import datetime
import tempfile
import os

from blockchain import trace_wallet
from transaction_dna import analyze_transaction_dna
from abnormal_detection import detect_abnormal_transactions
from risk_engine import calculate_risk_v3
from fraud_detector import detect_fraud_patterns
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
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

.block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
}

.hero {
    padding: 28px;
    border-radius: 18px;
    background: linear-gradient(
        135deg,
        rgba(30, 41, 59, 0.95),
        rgba(15, 23, 42, 0.98)
    );
    border: 1px solid rgba(148,163,184,0.2);
    margin-bottom: 25px;
}

.hero h1 {
    margin-bottom: 5px;
    font-size: 42px;
}

.hero p {
    color: #cbd5e1;
    font-size: 17px;
}

.metric-card {
    padding: 18px;
    border-radius: 14px;
    background: rgba(15,23,42,0.7);
    border: 1px solid rgba(148,163,184,0.18);
    margin-bottom: 10px;
}

.metric-title {
    color: #94a3b8;
    font-size: 14px;
}

.metric-value {
    font-size: 25px;
    font-weight: 700;
}

.risk-high {
    padding: 22px;
    border-radius: 16px;
    background: rgba(127,29,29,0.25);
    border: 1px solid rgba(248,113,113,0.4);
    margin-bottom: 15px;
}

.risk-medium {
    padding: 22px;
    border-radius: 16px;
    background: rgba(120,53,15,0.25);
    border: 1px solid rgba(251,191,36,0.4);
    margin-bottom: 15px;
}

.risk-low {
    padding: 22px;
    border-radius: 16px;
    background: rgba(20,83,45,0.25);
    border: 1px solid rgba(74,222,128,0.4);
    margin-bottom: 15px;
}

.fraud-card {
    padding: 22px;
    border-radius: 16px;
    background: rgba(30,41,59,0.65);
    border: 1px solid rgba(148,163,184,0.18);
    margin-bottom: 15px;
}

.info-card {
    padding: 20px;
    border-radius: 14px;
    background: rgba(30,41,59,0.55);
    border: 1px solid rgba(148,163,184,0.15);
}

.section-title {
    margin-top: 28px;
    margin-bottom: 15px;
}

.small-text {
    color: #94a3b8;
    font-size: 13px;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# SESSION STATE
# ============================================================

defaults = {
    "investigation_done": False,
    "trace_data": None,
    "dna": None,
    "patterns": [],
    "abnormal": [],
    "vasp": [],
    "risk": None,
    "fraud": None,
    "reported_wallet": "",
    "blockchain": "Ethereum",
    "max_hops": 2
}

for key, value in defaults.items():

    if key not in st.session_state:
        st.session_state[key] = value


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def native_symbol(chain):

    if chain == "BSC":
        return "BNB"

    return "ETH"


def short_address(address):

    if not address:
        return "Unknown"

    if len(address) < 12:
        return address

    return f"{address[:6]}...{address[-6:]}"


def detect_patterns(transactions, trace_data, dna):

    patterns = []

    transaction_count = dna.get(
        "transaction_count",
        len(transactions)
    )

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

    token_count = trace_data.get(
        "token_count",
        0
    )

    max_hop = trace_data.get(
        "max_hop",
        0
    )

    wallets = trace_data.get(
        "visited_wallets",
        []
    )

    if transaction_count >= 100:

        patterns.append({
            "pattern": "High transaction activity",
            "severity": "Medium",
            "description":
                "The wallet shows a high number of observed blockchain transactions."
        })

    if fan_out >= 5:

        patterns.append({
            "pattern": "Fund splitting / fan-out",
            "severity": "High",
            "description":
                "Funds are distributed toward multiple destination wallets."
        })

    if fan_in >= 5:

        patterns.append({
            "pattern": "Fund consolidation / fan-in",
            "severity": "High",
            "description":
                "The wallet receives funds from multiple source wallets."
        })

    if rapid_movements >= 5:

        patterns.append({
            "pattern": "Rapid fund movement",
            "severity": "High",
            "description":
                "Multiple wallet activities occur within short time intervals."
        })

    if max_hop >= 2:

        patterns.append({
            "pattern": "Multi-hop fund flow",
            "severity": "High",
            "description":
                "Observed funds can propagate through multiple connected wallets."
        })

    if token_count >= 50:

        patterns.append({
            "pattern": "Significant token activity",
            "severity": "Medium",
            "description":
                "The investigation includes a significant number of token transfers."
        })

    if len(wallets) >= 20:

        patterns.append({
            "pattern": "Large connected wallet network",
            "severity": "Medium",
            "description":
                "The reported wallet is connected to a relatively large observed network."
        })

    return patterns


def create_investigation_findings(
    trace_data,
    dna,
    vasp,
    risk,
    fraud
):

    findings = []

    transaction_count = dna.get(
        "transaction_count",
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

    rapid = dna.get(
        "rapid_movements",
        0
    )

    token_count = trace_data.get(
        "token_count",
        0
    )

    max_hop = trace_data.get(
        "max_hop",
        0
    )

    fraud_score = fraud.get(
        "fraud_score",
        0
    )

    if transaction_count >= 100:

        findings.append(
            "High transaction activity was observed."
        )

    if max_hop >= 2:

        findings.append(
            "Funds can be traced across multiple wallet hops."
        )

    if rapid >= 5:

        findings.append(
            "Rapid wallet activity was detected."
        )

    if fan_out >= 5:

        findings.append(
            "Multiple outgoing destinations indicate fan-out behaviour."
        )

    if fan_in >= 5:

        findings.append(
            "Multiple incoming sources indicate fan-in behaviour."
        )

    if token_count > 0:

        findings.append(
            f"{token_count} token transfers were observed."
        )

    if vasp:

        findings.append(
            "Potential VASP/exchange associations were detected from the configured registry."
        )

    if fraud_score >= 70:

        findings.append(
            "Multiple behavioural indicators combine into a high fraud-linked activity score."
        )

    elif fraud_score >= 40:

        findings.append(
            "Several behavioural indicators require additional investigation."
        )

    else:

        findings.append(
            "Limited fraud-linked behavioural indicators were observed."
        )

    return findings


# ============================================================
# NETWORK GRAPH
# ============================================================

def create_network_graph(trace_data):

    wallets = trace_data.get(
        "visited_wallets",
        []
    )

    hop_map = trace_data.get(
        "hop_map",
        {}
    )

    start_wallet = trace_data.get(
        "start_wallet",
        ""
    )

    transactions = trace_data.get(
        "transactions",
        []
    )

    net = Network(
        height="650px",
        width="100%",
        bgcolor="#0f172a",
        font_color="white",
        directed=True
    )

    net.barnes_hut()

    # Add wallet nodes
    for wallet in wallets:

        hop = hop_map.get(
            wallet,
            0
        )

        if wallet.lower() == start_wallet.lower():

            net.add_node(
                wallet,
                label=f"REPORTED\n{short_address(wallet)}",
                title="Victim-reported suspect wallet",
                shape="box",
                size=30
            )

        else:

            net.add_node(
                wallet,
                label=f"HOP {hop}\n{short_address(wallet)}",
                title=f"Observed wallet at hop {hop}",
                shape="dot",
                size=20
            )

    # Add edges
    added_edges = set()

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        )

        receiver = tx.get(
            "to",
            ""
        )

        if not sender or not receiver:
            continue

        sender_match = None
        receiver_match = None

        for wallet in wallets:

            if wallet.lower() == sender.lower():
                sender_match = wallet

            if wallet.lower() == receiver.lower():
                receiver_match = wallet

        if not sender_match or not receiver_match:
            continue

        edge_key = (
            sender_match.lower(),
            receiver_match.lower()
        )

        if edge_key in added_edges:
            continue

        added_edges.add(edge_key)

        net.add_edge(
            sender_match,
            receiver_match,
            arrows="to"
        )

    return net


def render_network_graph(trace_data):

    try:

        net = create_network_graph(
            trace_data
        )

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".html"
        ) as tmp:

            path = tmp.name

        net.save_graph(path)

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            html = file.read()

        components.html(
            html,
            height=680,
            scrolling=True
        )

        try:
            os.remove(path)
        except Exception:
            pass

    except Exception as e:

        st.error(
            f"Unable to render network graph: {e}"
        )


# ============================================================
# HEADER
# ============================================================

st.markdown("""
<div class="hero">

<h1>🛡️ CryptoShield</h1>

<p>
Blockchain Fraud Intelligence & Investigation System
</p>

<p class="small-text">
Convert a victim-reported suspect wallet into an explainable
blockchain investigation.
</p>

</div>
""", unsafe_allow_html=True)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("🔎 Investigation")

    reported_wallet = st.text_input(
        "Reported Suspect Wallet",
        value=st.session_state.reported_wallet,
        placeholder="0x..."
    )

    blockchain = st.selectbox(
        "Blockchain",
        ["Ethereum", "BSC"],
        index=(
            0
            if st.session_state.blockchain == "Ethereum"
            else 1
        )
    )

    max_hops = st.slider(
        "Maximum Investigation Hops",
        min_value=1,
        max_value=3,
        value=st.session_state.max_hops
    )

    start_button = st.button(
        "🔎 Start Investigation",
        use_container_width=True,
        type="primary"
    )

    st.divider()

    st.markdown("""
### Investigation Workflow

**1.** Victim reports wallet

**2.** Blockchain data collection

**3.** Multi-hop fund tracing

**4.** Transaction DNA analysis

**5.** Behaviour detection

**6.** Fraud-linked pattern detection

**7.** Explainable risk scoring

**8.** VASP intelligence

**9.** Investigation report

---

### ⚠️ Important

CryptoShield provides analytical indicators.

It does **not** declare a wallet or person criminal.
""")


# ============================================================
# START INVESTIGATION
# ============================================================

if start_button:

    reported_wallet = reported_wallet.strip()

    if not reported_wallet:

        st.error(
            "Please enter a wallet address."
        )

        st.stop()

    if not reported_wallet.startswith("0x"):

        st.error(
            "Wallet address must start with 0x."
        )

        st.stop()

    if len(reported_wallet) != 42:

        st.error(
            "Invalid Ethereum/BSC wallet address."
        )

        st.stop()

    # Save current settings
    st.session_state.reported_wallet = reported_wallet
    st.session_state.blockchain = blockchain
    st.session_state.max_hops = max_hops

    with st.spinner(
        "Running CryptoShield investigation..."
    ):

        try:

            # =================================================
            # 1. BLOCKCHAIN TRACE
            # =================================================

            trace_data = trace_wallet(
                reported_wallet,
                chain=blockchain,
                max_hop=max_hops
            )

            transactions = trace_data.get(
                "transactions",
                []
            )

            # =================================================
            # 2. TRANSACTION DNA
            # =================================================

            dna = analyze_transaction_dna(
                transactions,
                reported_wallet
            )

            # =================================================
            # 3. ABNORMAL TRANSACTION DETECTION
            # =================================================

            abnormal = detect_abnormal_transactions(
                transactions
            )

            # =================================================
            # 4. GENERAL PATTERN DETECTION
            # =================================================

            patterns = detect_patterns(
                transactions,
                trace_data,
                dna
            )

            # =================================================
            # 5. VASP DETECTION
            # =================================================

            vasp = detect_vasp(
                transactions
            )

            # =================================================
            # 6. FRAUD DETECTION ENGINE
            # =================================================

            fraud = detect_fraud_patterns(
                transactions,
                trace_data,
                dna,
                abnormal
            )

            # =================================================
            # 7. RISK ENGINE
            # =================================================

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

            # =================================================
            # SAVE RESULTS
            # =================================================

            st.session_state.trace_data = trace_data
            st.session_state.dna = dna
            st.session_state.patterns = patterns
            st.session_state.abnormal = abnormal
            st.session_state.vasp = vasp
            st.session_state.risk = risk
            st.session_state.fraud = fraud
            st.session_state.investigation_done = True

            st.success(
                "✅ Investigation completed successfully."
            )

        except Exception as e:

            st.error(
                f"Investigation failed: {e}"
            )

            st.stop()


# ============================================================
# RESULTS
# ============================================================

if st.session_state.investigation_done:

    trace_data = st.session_state.trace_data
    dna = st.session_state.dna
    patterns = st.session_state.patterns
    abnormal = st.session_state.abnormal
    vasp = st.session_state.vasp
    risk = st.session_state.risk
    fraud = st.session_state.fraud

    start_wallet = trace_data.get(
        "start_wallet",
        st.session_state.reported_wallet
    )

    selected_chain = trace_data.get(
        "chain",
        st.session_state.blockchain
    )

    risk_score = risk[0]
    risk_level = risk[1]

    fraud_score = fraud.get(
        "fraud_score",
        0
    )

    fraud_level = fraud.get(
        "fraud_level",
        "LOW"
    )

    fraud_patterns = fraud.get(
        "patterns",
        []
    )


    # ========================================================
    # OVERVIEW
    # ========================================================

    st.markdown(
        '<h2 class="section-title">📊 Investigation Overview</h2>',
        unsafe_allow_html=True
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:

        st.metric(
            "Reported Wallet",
            short_address(start_wallet)
        )

    with c2:

        st.metric(
            "Blockchain",
            selected_chain
        )

    with c3:

        st.metric(
            "Transactions",
            f"{dna.get('transaction_count', 0):,}"
        )

    with c4:

        st.metric(
            "Maximum Hop",
            trace_data.get(
                "max_hop",
                0
            )
        )


    # ========================================================
    # RISK ASSESSMENT
    # ========================================================

    st.markdown(
        '<h2 class="section-title">🚨 Blockchain Risk Assessment</h2>',
        unsafe_allow_html=True
    )

    if risk_level == "HIGH":

        st.markdown(
            f"""
            <div class="risk-high">

            <h2>🔴 HIGH RISK</h2>

            <h1>{risk_score}/100</h1>

            <p>
            Multiple blockchain behaviour indicators suggest
            elevated analytical risk.
            </p>

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

            <p>
            Several blockchain indicators require
            additional investigation.
            </p>

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

            <p>
            Limited risk indicators were observed
            within the analysed dataset.
            </p>

            </div>
            """,
            unsafe_allow_html=True
        )


    # ========================================================
    # FRAUD DETECTION ENGINE
    # ========================================================

    st.markdown(
        '<h2 class="section-title">🚨 Fraud Detection Engine</h2>',
        unsafe_allow_html=True
    )

    if fraud_level == "HIGH":

        st.error(
            f"🚨 Potential Fraud-Linked Activity Detected — "
            f"Behaviour Score: {fraud_score}/100"
        )

    elif fraud_level == "MEDIUM":

        st.warning(
            f"⚠️ Suspicious Behaviour Indicators Detected — "
            f"Behaviour Score: {fraud_score}/100"
        )

    else:

        st.success(
            f"🟢 Limited Fraud-Linked Indicators — "
            f"Behaviour Score: {fraud_score}/100"
        )

    st.caption(
        "This score represents explainable blockchain behaviour indicators, "
        "not a legal determination of fraud."
    )


    # ========================================================
    # DETECTED FRAUD PATTERNS
    # ========================================================

    st.markdown(
        '<h3>🔍 Detected Fraud-Linked Behaviour</h3>',
        unsafe_allow_html=True
    )

    if fraud_patterns:

        for item in fraud_patterns:

            pattern_type = item.get(
                "type",
                "Unknown"
            )

            category = item.get(
                "category",
                "Unknown"
            )

            confidence = item.get(
                "confidence",
                "Unknown"
            )

            evidence = item.get(
                "evidence",
                ""
            )

            score = item.get(
                "score",
                0
            )

            with st.expander(
                f"🔎 {pattern_type} — {confidence} confidence"
            ):

                a, b, c = st.columns(3)

                with a:

                    st.metric(
                        "Indicator Score",
                        score
                    )

                with b:

                    st.metric(
                        "Confidence",
                        confidence
                    )

                with c:

                    st.metric(
                        "Category",
                        category
                    )

                st.write(
                    f"**Evidence:** {evidence}"
                )

    else:

        st.info(
            "No predefined fraud-linked behaviour patterns were detected."
        )


    # ========================================================
    # WHY FLAGGED?
    # ========================================================

    st.markdown(
        '<h3>🧠 Why Did CryptoShield Flag This Wallet?</h3>',
        unsafe_allow_html=True
    )

    if fraud_patterns:

        for item in fraud_patterns:

            st.write(
                f"✓ **{item.get('type', 'Unknown')}** — "
                f"{item.get('evidence', '')}"
            )

    else:

        st.write(
            "No significant behavioural indicators were detected."
        )


    # ========================================================
    # TRANSACTION INTELLIGENCE
    # ========================================================

    st.markdown(
        '<h2 class="section-title">💰 Transaction Intelligence</h2>',
        unsafe_allow_html=True
    )

    native_asset = native_symbol(
        selected_chain
    )

    m1, m2, m3, m4 = st.columns(4)

    with m1:

        st.metric(
            "Native Transactions",
            f"{dna.get('native_transaction_count', 0):,}"
        )

    with m2:

        st.metric(
            "Token Transfers",
            f"{dna.get('token_transaction_count', 0):,}"
        )

    with m3:

        st.metric(
            "Token Types",
            f"{len(trace_data.get('token_types', [])):,}"
        )

    with m4:

        st.metric(
            "Connected Wallets",
            f"{len(trace_data.get('visited_wallets', [])):,}"
        )


    m5, m6, m7, m8 = st.columns(4)

    with m5:

        st.metric(
            "Unique Senders",
            f"{dna.get('unique_senders', 0):,}"
        )

    with m6:

        st.metric(
            "Unique Receivers",
            f"{dna.get('unique_receivers', 0):,}"
        )

    with m7:

        st.metric(
            "Fan-In",
            f"{dna.get('fan_in', 0):,}"
        )

    with m8:

        st.metric(
            "Fan-Out",
            f"{dna.get('fan_out', 0):,}"
        )


    # ========================================================
    # NATIVE ASSET VOLUME
    # ========================================================

    st.markdown(
        '<h3>Native Asset Analysis</h3>',
        unsafe_allow_html=True
    )

    native_volume = dna.get(
        "native_volume",
        0
    )

    avg_native_transfer = dna.get(
        "average_native_transfer",
        0
    )

    v1, v2 = st.columns(2)

    with v1:

        st.metric(
            f"Observed Native Volume ({native_asset})",
            f"{native_volume:.6f}"
        )

    with v2:

        st.metric(
            f"Average Native Transfer ({native_asset})",
            f"{avg_native_transfer:.6f}"
        )

    st.caption(
        "Native-asset volume is calculated separately from token transfer amounts."
    )


    # ========================================================
    # MULTI-HOP TRACE
    # ========================================================

    st.markdown(
        '<h2 class="section-title">🧭 Multi-Hop Fund Trace</h2>',
        unsafe_allow_html=True
    )

    wallet_hops = trace_data.get(
        "wallet_hops",
        {}
    )

    if wallet_hops:

        sorted_wallets = sorted(
            wallet_hops.items(),
            key=lambda x: x[1]
        )

        for wallet, hop in sorted_wallets:

            if wallet.lower() == start_wallet.lower():

                st.success(
                    f"🚩 Reported Wallet → {short_address(wallet)}"
                )

            else:

                st.info(
                    f"Hop {hop} → {short_address(wallet)}"
                )

    else:

        st.info(
            "No multi-hop wallet path was generated."
        )


    # ========================================================
    # NETWORK GRAPH
    # ========================================================

    st.markdown(
        '<h2 class="section-title">🕸️ Wallet Investigation Network</h2>',
        unsafe_allow_html=True
    )

    render_network_graph(
        trace_data
    )


    # ========================================================
    # INVESTIGATION FINDINGS
    # ========================================================

    st.markdown(
        '<h2 class="section-title">🔍 Investigation Findings</h2>',
        unsafe_allow_html=True
    )

    findings = create_investigation_findings(
        trace_data,
        dna,
        vasp,
        risk,
        fraud
    )

    for finding in findings:

        st.write(
            f"• {finding}"
        )


    # ========================================================
    # EXPLAINABLE RISK
    # ========================================================

    st.markdown(
        '<h2 class="section-title">🧠 Explainable Risk Score</h2>',
        unsafe_allow_html=True
    )

    factors = {}

    if len(risk) >= 3:

        factors = risk[2]

    if factors:

        factor_rows = []

        for factor, value in factors.items():

            factor_rows.append({
                "Risk Factor": factor,
                "Contribution": value
            })

        st.dataframe(
            pd.DataFrame(factor_rows),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "Risk factor details are not available."
        )


    # ========================================================
    # GENERAL SUSPICIOUS PATTERNS
    # ========================================================

    st.markdown(
        '<h2 class="section-title">🚩 Blockchain Behaviour Patterns</h2>',
        unsafe_allow_html=True
    )

    if patterns:

        pattern_rows = []

        for item in patterns:

            pattern_rows.append({
                "Pattern": item.get(
                    "pattern",
                    "Unknown"
                ),
                "Severity": item.get(
                    "severity",
                    "Unknown"
                ),
                "Description": item.get(
                    "description",
                    ""
                )
            })

        st.dataframe(
            pd.DataFrame(pattern_rows),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "No major predefined blockchain behaviour patterns were detected."
        )


    # ========================================================
    # ABNORMAL TRANSACTIONS
    # ========================================================

    st.markdown(
        '<h2 class="section-title">⚠️ Abnormal Transaction Analysis</h2>',
        unsafe_allow_html=True
    )

    if abnormal:

        abnormal_rows = []

        for item in abnormal[:100]:

            abnormal_rows.append({
                "Transaction Hash": item.get(
                    "hash",
                    "Unknown"
                ),
                "Score": item.get(
                    "score",
                    0
                ),
                "Reason": item.get(
                    "reason",
                    ""
                )
            })

        st.dataframe(
            pd.DataFrame(abnormal_rows),
            use_container_width=True,
            hide_index=True
        )

        if len(abnormal) > 100:

            st.caption(
                f"Showing top 100 abnormal transactions out of {len(abnormal)}."
            )

    else:

        st.success(
            "No abnormal transactions detected by the current rules."
        )


    # ========================================================
    # VASP INTELLIGENCE
    # ========================================================

    st.markdown(
        '<h2 class="section-title">🏦 VASP / Exchange Intelligence</h2>',
        unsafe_allow_html=True
    )

    if vasp:

        vasp_rows = []

        for item in vasp:

            vasp_rows.append({

                "Name":
                    item.get(
                        "name",
                        "Unknown"
                    ),

                "Type":
                    item.get(
                        "type",
                        "Unknown"
                    ),

                "Country":
                    item.get(
                        "country",
                        "Unknown"
                    ),

                "Address":
                    item.get(
                        "address",
                        "Unknown"
                    ),

                "Role":
                    item.get(
                        "transaction_role",
                        "Unknown"
                    ),

                "Confidence":
                    item.get(
                        "confidence",
                        "Potential association"
                    ),

                "Source":
                    item.get(
                        "source",
                        "Unknown"
                    )
            })

        st.dataframe(
            pd.DataFrame(vasp_rows),
            use_container_width=True,
            hide_index=True
        )

        st.warning(
            "A VASP match indicates only a potential association based on "
            "the configured registry. It does not prove ownership or criminal activity."
        )

    else:

        st.info(
            "No matching VASP label was found in the currently configured registry."
        )


    # ========================================================
    # TRANSACTION DNA
    # ========================================================

    st.markdown(
        '<h2 class="section-title">🧬 Transaction DNA</h2>',
        unsafe_allow_html=True
    )

    dna_data = {

        "Metric": [

            "Transaction Count",
            "Native Transactions",
            "Token Transactions",
            "Unique Senders",
            "Unique Receivers",
            "Fan-In",
            "Fan-Out",
            "Rapid Movements"

        ],

        "Value": [

            dna.get(
                "transaction_count",
                0
            ),

            dna.get(
                "native_transaction_count",
                0
            ),

            dna.get(
                "token_transaction_count",
                0
            ),

            dna.get(
                "unique_senders",
                0
            ),

            dna.get(
                "unique_receivers",
                0
            ),

            dna.get(
                "fan_in",
                0
            ),

            dna.get(
                "fan_out",
                0
            ),

            dna.get(
                "rapid_movements",
                0
            )

        ]
    }

    st.dataframe(
        pd.DataFrame(dna_data),
        use_container_width=True,
        hide_index=True
    )


    # ========================================================
    # ACTIVITY HOURS
    # ========================================================

    st.markdown(
        '<h3>⏰ Activity by Hour</h3>',
        unsafe_allow_html=True
    )

    active_hours = dna.get(
        "active_hours",
        {}
    )

    if active_hours:

        hour_rows = []

        for hour, count in sorted(
            active_hours.items()
        ):

            hour_rows.append({
                "Hour": hour,
                "Transactions": count
            })

        st.dataframe(
            pd.DataFrame(hour_rows),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No timestamp activity data available."
        )


    # ========================================================
    # TOKEN INTELLIGENCE
    # ========================================================

    st.markdown(
        '<h2 class="section-title">🪙 Token Intelligence</h2>',
        unsafe_allow_html=True
    )

    token_transactions = trace_data.get(
        "token_transactions",
        []
    )

    if token_transactions:

        token_rows = []

        for tx in token_transactions[:100]:

            token_rows.append({

                "Token":
                    tx.get(
                        "token_symbol",
                        tx.get(
                            "asset",
                            "Unknown"
                        )
                    ),

                "Token Name":
                    tx.get(
                        "token_name",
                        "Unknown"
                    ),

                "From":
                    short_address(
                        tx.get(
                            "from",
                            ""
                        )
                    ),

                "To":
                    short_address(
                        tx.get(
                            "to",
                            ""
                        )
                    ),

                "Amount":
                    tx.get(
                        "value",
                        "0"
                    ),

                "Hash":
                    tx.get(
                        "hash",
                        "Unknown"
                    )

            })

        st.dataframe(
            pd.DataFrame(token_rows),
            use_container_width=True,
            hide_index=True
        )

        if len(token_transactions) > 100:

            st.caption(
                f"Showing first 100 token transfers out of "
                f"{len(token_transactions)}."
            )

    else:

        st.info(
            "No token transfer records were observed."
        )


    # ========================================================
    # TRANSACTION EVIDENCE
    # ========================================================

    st.markdown(
        '<h2 class="section-title">📑 Transaction Evidence</h2>',
        unsafe_allow_html=True
    )

    all_transactions = trace_data.get(
        "transactions",
        []
    )

    if all_transactions:

        evidence_rows = []

        for tx in all_transactions[:100]:

            evidence_rows.append({

                "Type":
                    tx.get(
                        "type",
                        "native"
                    ),

                "Asset":
                    tx.get(
                        "asset",
                        "Unknown"
                    ),

                "From":
                    short_address(
                        tx.get(
                            "from",
                            ""
                        )
                    ),

                "To":
                    short_address(
                        tx.get(
                            "to",
                            ""
                        )
                    ),

                "Value":
                    tx.get(
                        "value",
                        "0"
                    ),

                "Hash":
                    tx.get(
                        "hash",
                        "Unknown"
                    )

            })

        st.dataframe(
            pd.DataFrame(evidence_rows),
            use_container_width=True,
            hide_index=True
        )

        if len(all_transactions) > 100:

            st.caption(
                f"Showing first 100 transactions out of "
                f"{len(all_transactions)}."
            )

    else:

        st.info(
            "No transaction evidence available."
        )


    # ========================================================
    # INVESTIGATION CONCLUSION
    # ========================================================

    st.markdown(
        '<h2 class="section-title">📝 Investigation Conclusion</h2>',
        unsafe_allow_html=True
    )

    st.markdown(
        f"""
        <div class="info-card">

        <h3>CryptoShield Analytical Conclusion</h3>

        <p>
        The reported wallet was analysed on the
        <b>{selected_chain}</b> blockchain.
        The investigation observed
        <b>{dna.get("transaction_count", 0):,}</b>
        transactions and explored up to
        <b>{trace_data.get("max_hop", 0)}</b>
        wallet hops.
        </p>

        <p>
        Blockchain analytical risk score:
        <b>{risk_score}/100 ({risk_level})</b>
        </p>

        <p>
        Fraud-linked behaviour score:
        <b>{fraud_score}/100 ({fraud_level})</b>
        </p>

        <p>
        The system identified
        <b>{len(fraud_patterns)}</b>
        behavioural indicators and
        <b>{len(abnormal)}</b>
        abnormal transaction alerts.
        </p>

        <p>
        These results are investigative indicators and
        should be combined with additional evidence before
        making enforcement or attribution decisions.
        </p>

        </div>
        """,
        unsafe_allow_html=True
    )


    # ========================================================
    # PDF REPORT
    # ========================================================

    st.markdown(
        '<h2 class="section-title">📄 Investigation Report</h2>',
        unsafe_allow_html=True
    )

    st.write(
        "Generate an investigation-ready PDF containing the analysed evidence."
    )

    if st.button(
        "📄 Generate PDF Report",
        use_container_width=True
    ):

        try:

            # IMPORTANT:
            # Current report_generator.py signature:
            #
            # generate_pdf_report(
            #     start_wallet,
            #     selected_chain,
            #     trace_data,
            #     dna,
            #     risk_score,
            #     risk_level,
            #     patterns,
            #     abnormal
            # )

            pdf_path = generate_pdf_report(

                start_wallet,

                selected_chain,

                trace_data,

                dna,

                risk_score,

                risk_level,

                patterns,

                abnormal

            )

            with open(
                pdf_path,
                "rb"
            ) as pdf_file:

                pdf_data = pdf_file.read()

            st.download_button(

                label="⬇️ Download Investigation Report",

                data=pdf_data,

                file_name=(
                    f"CryptoShield_Report_"
                    f"{start_wallet[:10]}.pdf"
                ),

                mime="application/pdf",

                use_container_width=True
            )

        except Exception as e:

            st.error(
                f"PDF report generation failed: {e}"
            )


    # ========================================================
    # DISCLAIMER
    # ========================================================

    st.divider()

    st.warning("""
### ⚠️ Investigation Disclaimer

CryptoShield is a blockchain analytics and investigation
support system.

The risk score, fraud-linked behaviour score, suspicious
patterns, abnormal transaction alerts, and VASP associations
are analytical indicators.

They do not independently establish criminal activity,
wallet ownership, or legal responsibility.

Final conclusions must be verified using additional
investigative evidence and appropriate legal procedures.
""")


# ============================================================
# INITIAL SCREEN
# ============================================================

else:

    st.markdown(
        """
        <div class="info-card">

        <h2>👋 Welcome to CryptoShield</h2>

        <p>
        Enter a victim-reported suspect wallet address from
        the sidebar to begin the investigation.
        </p>

        <h3>🔍 What CryptoShield does</h3>

        <ul>

        <li>Collects blockchain transaction data</li>

        <li>Traces connected wallets across multiple hops</li>

        <li>Builds transaction behaviour DNA</li>

        <li>Detects abnormal transaction activity</li>

        <li>Identifies fraud-linked behaviour patterns</li>

        <li>Calculates an explainable blockchain risk score</li>

        <li>Calculates a fraud-linked behaviour score</li>

        <li>Checks potential VASP/exchange associations</li>

        <li>Visualizes the wallet network</li>

        <li>Generates an investigation report</li>

        </ul>

        <h3>🎯 Core Idea</h3>

        <p>
        <b>Victim-Reported Wallet → Blockchain Evidence →
        Behaviour Analysis → Fraud-Linked Pattern Detection →
        Explainable Risk Assessment → Investigation Report</b>
        </p>

        </div>
        """,
        unsafe_allow_html=True
    )
