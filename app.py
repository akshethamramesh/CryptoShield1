import streamlit as st
import pandas as pd
import tempfile
import os
from datetime import datetime

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
# PAGE CONFIGURATION
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

st.markdown(
    """
    <style>

    .main-title {
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 0px;
    }

    .sub-title {
        font-size: 18px;
        color: #777;
        margin-top: 0px;
    }

    .risk-high {
        padding: 18px;
        border-radius: 12px;
        text-align: center;
        font-size: 25px;
        font-weight: 700;
        border: 2px solid #ff4b4b;
    }

    .risk-medium {
        padding: 18px;
        border-radius: 12px;
        text-align: center;
        font-size: 25px;
        font-weight: 700;
        border: 2px solid #ffa500;
    }

    .risk-low {
        padding: 18px;
        border-radius: 12px;
        text-align: center;
        font-size: 25px;
        font-weight: 700;
        border: 2px solid #28a745;
    }

    .info-box {
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #ddd;
        margin-bottom: 10px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ CRYPTO SHIELD</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="sub-title">'
    'Blockchain Fraud Intelligence & Investigation System'
    '</div>',
    unsafe_allow_html=True
)

st.divider()


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🔎 Investigation")

st.sidebar.markdown(
    """
    **CryptoShield Workflow**

    1. Report suspect wallet
    2. Collect blockchain data
    3. Trace connected wallets
    4. Analyze transaction behaviour
    5. Detect suspicious patterns
    6. Calculate explainable risk
    7. Detect potential VASP association
    8. Visualize wallet network
    9. Generate investigation report
    """
)

st.sidebar.divider()

blockchain = st.sidebar.selectbox(
    "Blockchain",
    ["Ethereum", "BSC"]
)

max_hops = st.sidebar.slider(
    "Maximum tracing hops",
    min_value=1,
    max_value=3,
    value=2
)

reported_wallet = st.sidebar.text_input(
    "Reported Suspect Wallet",
    placeholder="0x..."
)

analyze_button = st.sidebar.button(
    "🚀 Analyze Wallet",
    use_container_width=True
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def short_address(address, chars=12):
    if not address:
        return ""

    address = str(address)

    if len(address) <= chars * 2:
        return address

    return address[:chars] + "..." + address[-chars:]


def short_hash(value, chars=18):
    if not value:
        return ""

    value = str(value)

    if len(value) <= chars:
        return value

    return value[:chars] + "..."


def get_risk_class(level):
    level = str(level).upper()

    if level == "HIGH":
        return "risk-high"

    if level == "MEDIUM":
        return "risk-medium"

    return "risk-low"


def build_transaction_dataframe(transactions):
    rows = []

    for tx in transactions:

        rows.append(
            {
                "Hash": tx.get("hash", ""),
                "From": tx.get("from", ""),
                "To": tx.get("to", ""),
                "Value": tx.get("value", 0),
                "Asset": tx.get("asset", "ETH"),
                "Type": tx.get("type", "native"),
                "Timestamp": tx.get("timeStamp", "")
            }
        )

    return pd.DataFrame(rows)


def build_network_graph(transactions, start_wallet):

    net = Network(
        height="650px",
        width="100%",
        directed=True,
        bgcolor="#ffffff",
        font_color="#000000"
    )

    net.set_options(
        """
        {
            "nodes": {
                "shape": "dot",
                "size": 20,
                "font": {
                    "size": 14
                }
            },
            "edges": {
                "arrows": {
                    "to": {
                        "enabled": true
                    }
                },
                "smooth": true
            },
            "physics": {
                "enabled": true,
                "stabilization": {
                    "iterations": 200
                }
            }
        }
        """
    )

    added_nodes = set()

    start_wallet = start_wallet.lower()

    for tx in transactions:

        sender = str(tx.get("from", "")).lower()
        receiver = str(tx.get("to", "")).lower()

        if not sender or not receiver:
            continue

        if sender not in added_nodes:

            if sender == start_wallet:
                net.add_node(
                    sender,
                    label="Reported Wallet",
                    title=sender,
                    size=30
                )
            else:
                net.add_node(
                    sender,
                    label=short_address(sender),
                    title=sender
                )

            added_nodes.add(sender)

        if receiver not in added_nodes:

            if receiver == start_wallet:
                net.add_node(
                    receiver,
                    label="Reported Wallet",
                    title=receiver,
                    size=30
                )
            else:
                net.add_node(
                    receiver,
                    label=short_address(receiver),
                    title=receiver
                )

            added_nodes.add(receiver)

        value = tx.get("value", 0)
        asset = tx.get("asset", "ETH")

        net.add_edge(
            sender,
            receiver,
            title=f"{value} {asset}"
        )

    return net


# ============================================================
# SESSION STATE
# ============================================================

if "analysis_complete" not in st.session_state:
    st.session_state.analysis_complete = False

if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = None


# ============================================================
# MAIN ANALYSIS
# ============================================================

if analyze_button:

    if not reported_wallet.strip():

        st.error(
            "Please enter the reported suspect wallet address."
        )

        st.stop()

    reported_wallet = reported_wallet.strip()

    # --------------------------------------------------------
    # BASIC VALIDATION
    # --------------------------------------------------------

    if not reported_wallet.startswith("0x"):

        st.error(
            "Invalid wallet format. Ethereum/BSC addresses should start with 0x."
        )

        st.stop()

    if len(reported_wallet) != 42:

        st.warning(
            "The wallet address should normally contain 42 characters."
        )

    # --------------------------------------------------------
    # API / BLOCKCHAIN ANALYSIS
    # --------------------------------------------------------

    progress = st.progress(0)

    status = st.empty()

    try:

        status.info(
            "🔗 Connecting to blockchain data source..."
        )

        progress.progress(10)

        # ----------------------------------------------------
        # MULTI-HOP TRACE
        # ----------------------------------------------------

        status.info(
            "🕸️ Reconstructing blockchain transaction network..."
        )

        trace_data = trace_wallet(
            reported_wallet,
            chain=blockchain,
            max_hop=max_hops
        )

        progress.progress(30)

        transactions = trace_data.get(
            "transactions",
            []
        )

        # ----------------------------------------------------
        # TRANSACTION DNA
        # ----------------------------------------------------

        status.info(
            "🧬 Analyzing transaction DNA..."
        )

        dna = analyze_transaction_dna(
            transactions,
            reported_wallet
        )

        progress.progress(45)

        # ----------------------------------------------------
        # ABNORMAL TRANSACTIONS
        # ----------------------------------------------------

        status.info(
            "🚨 Detecting abnormal transactions..."
        )

        abnormal = detect_abnormal_transactions(
            transactions
        )

        progress.progress(55)

        # ----------------------------------------------------
        # FRAUD PATTERN DETECTION
        # ----------------------------------------------------

        status.info(
            "🔍 Detecting suspicious fund-flow behaviour..."
        )

        fraud = detect_fraud_patterns(
            transactions,
            trace_data,
            dna,
            abnormal
        )

        patterns = fraud.get(
            "patterns",
            []
        )

        fraud_score = fraud.get(
            "fraud_score",
            0
        )

        fraud_level = fraud.get(
            "fraud_level",
            "LOW"
        )

        progress.progress(65)

        # ----------------------------------------------------
        # VASP DETECTION
        # ----------------------------------------------------

        status.info(
            "🏦 Checking potential VASP associations..."
        )

        vasp = detect_vasp(
            transactions
        )

        progress.progress(75)

        # ----------------------------------------------------
        # RISK ENGINE
        # ----------------------------------------------------

        status.info(
            "📊 Calculating explainable risk score..."
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

        risk_score = risk[0]

        risk_level = risk[1]

        factors = (
            risk[2]
            if len(risk) > 2
            else {}
        )

        progress.progress(90)

        # ----------------------------------------------------
        # SAVE ANALYSIS
        # ----------------------------------------------------

        st.session_state.analysis_data = {

            "wallet": reported_wallet,

            "chain": blockchain,

            "trace": trace_data,

            "transactions": transactions,

            "dna": dna,

            "abnormal": abnormal,

            "fraud": fraud,

            "patterns": patterns,

            "vasp": vasp,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "risk_factors": factors,

            "fraud_score": fraud_score,

            "fraud_level": fraud_level
        }

        st.session_state.analysis_complete = True

        progress.progress(100)

        status.success(
            "✅ Blockchain investigation completed."
        )

    except Exception as e:

        progress.empty()

        status.empty()

        st.error(
            f"❌ Analysis failed: {str(e)}"
        )

        st.info(
            "Check your API key, wallet address, blockchain selection, "
            "and blockchain API availability."
        )

        st.stop()


# ============================================================
# DISPLAY RESULTS
# ============================================================

if st.session_state.analysis_complete:

    data = st.session_state.analysis_data

    wallet = data["wallet"]

    chain = data["chain"]

    trace_data = data["trace"]

    transactions = data["transactions"]

    dna = data["dna"]

    abnormal = data["abnormal"]

    fraud = data["fraud"]

    patterns = data["patterns"]

    vasp = data["vasp"]

    risk_score = data["risk_score"]

    risk_level = data["risk_level"]

    factors = data["risk_factors"]

    fraud_score = data["fraud_score"]

    fraud_level = data["fraud_level"]


    # ========================================================
    # INVESTIGATION SUMMARY
    # ========================================================

    st.header("🔎 Investigation Summary")

    st.markdown(
        f"""
        **Reported Suspect Wallet**

        `{wallet}`
        """
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
            len(
                trace_data.get(
                    "visited_wallets",
                    []
                )
            )
        )

    with col4:

        st.metric(
            "Maximum Hop",
            trace_data.get(
                "max_hop",
                0
            )
        )


    # ========================================================
    # RISK SCORE
    # ========================================================

    st.header("📊 Blockchain Risk Assessment")

    risk_css = get_risk_class(
        risk_level
    )

    st.markdown(
        f"""
        <div class="{risk_css}">
            Risk Score: {risk_score}/100
            <br>
            Risk Level: {risk_level}
        </div>
        """,
        unsafe_allow_html=True
    )

    st.write("")

    if risk_level == "HIGH":

        st.error(
            "⚠️ High-risk indicators detected. "
            "Further investigation is recommended."
        )

    elif risk_level == "MEDIUM":

        st.warning(
            "⚠️ Moderate-risk indicators detected. "
            "Additional investigation may be required."
        )

    else:

        st.success(
            "No strong predefined high-risk indicators detected."
        )


    # ========================================================
    # FRAUD DETECTION ENGINE
    # ========================================================

    st.header("🚨 Fraud Detection Engine")

    f1, f2, f3 = st.columns(3)

    with f1:

        st.metric(
            "Fraud Behaviour Score",
            f"{fraud_score}/100"
        )

    with f2:

        st.metric(
            "Fraud Behaviour Level",
            fraud_level
        )

    with f3:

        st.metric(
            "Patterns Detected",
            len(patterns)
        )


    # ========================================================
    # DETECTED FRAUD BEHAVIOUR
    # ========================================================

    st.subheader(
        "🔍 Detected Fraud-Linked Behaviour"
    )

    if patterns:

        for pattern in patterns:

            if isinstance(pattern, dict):

                name = pattern.get(
                    "pattern",
                    pattern.get(
                        "name",
                        "Suspicious pattern"
                    )
                )

                confidence = pattern.get(
                    "confidence",
                    ""
                )

                explanation = pattern.get(
                    "description",
                    pattern.get(
                        "reason",
                        ""
                    )
                )

                st.markdown(
                    f"""
                    **🚨 {name}**

                    {explanation}

                    Confidence: **{confidence}**
                    """
                )

            else:

                st.markdown(
                    f"• {pattern}"
                )

    else:

        st.info(
            "No predefined suspicious behaviour patterns detected."
        )


    # ========================================================
    # WHY FLAGGED
    # ========================================================

    st.subheader(
        "💡 Why Was This Wallet Flagged?"
    )

    if factors:

        factor_rows = []

        for factor, value in factors.items():

            factor_rows.append(
                {
                    "Risk Factor": factor,
                    "Contribution": value
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
            "Risk factor details are not available."
        )


    # ========================================================
    # TRANSACTION INTELLIGENCE
    # ========================================================

    st.header(
        "🧬 Transaction Intelligence"
    )

    t1, t2, t3, t4 = st.columns(4)

    with t1:

        st.metric(
            "Total Transactions",
            dna.get(
                "transaction_count",
                0
            )
        )

    with t2:

        st.metric(
            "Native Transactions",
            dna.get(
                "native_transaction_count",
                0
            )
        )

    with t3:

        st.metric(
            "Token Transactions",
            dna.get(
                "token_transaction_count",
                0
            )
        )

    with t4:

        st.metric(
            "Rapid Movements",
            dna.get(
                "rapid_movements",
                0
            )
        )


    t5, t6, t7, t8 = st.columns(4)

    with t5:

        st.metric(
            "Unique Senders",
            dna.get(
                "unique_senders",
                0
            )
        )

    with t6:

        st.metric(
            "Unique Receivers",
            dna.get(
                "unique_receivers",
                0
            )
        )

    with t7:

        st.metric(
            "Fan-In",
            dna.get(
                "fan_in",
                0
            )
        )

    with t8:

        st.metric(
            "Fan-Out",
            dna.get(
                "fan_out",
                0
            )
        )


    # ========================================================
    # VOLUME
    # ========================================================

    st.subheader(
        "💰 Transaction Volume"
    )

    v1, v2, v3 = st.columns(3)

    with v1:

        st.metric(
            "Native Volume",
            f"{dna.get('native_volume', 0):,.6f}"
        )

    with v2:

        st.metric(
            "Token Volume",
            f"{dna.get('token_volume', 0):,.6f}"
        )

    with v3:

        st.metric(
            "Average Native Transfer",
            f"{dna.get('average_native_transfer', 0):,.6f}"
        )


    # ========================================================
    # MULTI-HOP TRACE
    # ========================================================

    st.header(
        "🕸️ Multi-Hop Fund Flow"
    )

    hop_map = trace_data.get(
        "hop_map",
        {}
    )

    wallet_hops = trace_data.get(
        "wallet_hops",
        {}
    )

    if wallet_hops:

        hop_rows = []

        for address, hop in wallet_hops.items():

            hop_rows.append(
                {
                    "Wallet": address,
                    "Hop": hop
                }
            )

        hop_df = pd.DataFrame(
            hop_rows
        )

        hop_df = hop_df.sort_values(
            by="Hop"
        )

        st.dataframe(
            hop_df,
            use_container_width=True,
            hide_index=True
        )

    elif hop_map:

        hop_rows = []

        for hop, wallets in hop_map.items():

            for address in wallets:

                hop_rows.append(
                    {
                        "Wallet": address,
                        "Hop": hop
                    }
                )

        hop_df = pd.DataFrame(
            hop_rows
        )

        st.dataframe(
            hop_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No multi-hop wallet mapping available."
        )


    # ========================================================
    # WALLET NETWORK
    # ========================================================

    st.header(
        "🌐 Wallet Network"
    )

    if transactions:

        try:

            network = build_network_graph(
                transactions,
                wallet
            )

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".html"
            ) as tmp:

                graph_path = tmp.name

            network.save_graph(
                graph_path
            )

            with open(
                graph_path,
                "r",
                encoding="utf-8"
            ) as f:

                graph_html = f.read()

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

        except Exception as e:

            st.warning(
                f"Unable to render network graph: {e}"
            )

    else:

        st.info(
            "No transactions available for network visualization."
        )


    # ========================================================
    # GENERAL PATTERNS
    # ========================================================

    st.header(
        "📌 General Transaction Patterns"
    )

    behaviour_indicators = dna.get(
        "behavior_indicators",
        []
    )

    if behaviour_indicators:

        for indicator in behaviour_indicators:

            st.markdown(
                f"• {indicator}"
            )

    else:

        st.info(
            "No additional predefined transaction behaviour indicators."
        )


    # ========================================================
    # ABNORMAL TRANSACTIONS
    # ========================================================

    st.header(
        "🚨 Abnormal Transactions"
    )

    if abnormal:

        abnormal_rows = []

        for alert in abnormal:

            abnormal_rows.append(
                {
                    "Transaction": alert.get(
                        "hash",
                        "Unknown"
                    ),
                    "Score": alert.get(
                        "score",
                        0
                    ),
                    "Reason": alert.get(
                        "reason",
                        "Abnormal activity"
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
            "No abnormal transactions detected."
        )


    # ========================================================
    # VASP ASSOCIATION
    # ========================================================

    st.header(
        "🏦 Potential VASP / Exchange Association"
    )

    if vasp:

        vasp_rows = []

        for item in vasp:

            vasp_rows.append(
                {
                    "Name": item.get(
                        "name",
                        "Unknown"
                    ),
                    "Type": item.get(
                        "type",
                        "Unknown"
                    ),
                    "Country": item.get(
                        "country",
                        "Unknown"
                    ),
                    "Address": item.get(
                        "address",
                        "Unknown"
                    ),
                    "Role": item.get(
                        "transaction_role",
                        "Unknown"
                    ),
                    "Confidence": item.get(
                        "confidence",
                        "Potential association"
                    ),
                    "Source": item.get(
                        "source",
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
            "No potential VASP association identified."
        )

    st.caption(
        "VASP association is an analytical match and does not prove "
        "wallet ownership or criminal activity."
    )


    # ========================================================
    # TOKEN INTELLIGENCE
    # ========================================================

    st.header(
        "🪙 Token Intelligence"
    )

    token_count = trace_data.get(
        "token_count",
        0
    )

    native_count = trace_data.get(
        "native_count",
        0
    )

    token_types = trace_data.get(
        "token_types",
        []
    )

    c1, c2, c3 = st.columns(3)

    with c1:

        st.metric(
            "Token Transfers",
            token_count
        )

    with c2:

        st.metric(
            "Native Transfers",
            native_count
        )

    with c3:

        st.metric(
            "Token Types",
            len(token_types)
        )

    if token_types:

        st.write(
            "Detected token types:"
        )

        st.write(
            ", ".join(
                map(
                    str,
                    token_types
                )
            )
        )


    # ========================================================
    # TRANSACTION EVIDENCE
    # ========================================================

    st.header(
        "📑 Transaction Evidence"
    )

    if transactions:

        transaction_df = build_transaction_dataframe(
            transactions
        )

        display_df = transaction_df.copy()

        if "Hash" in display_df.columns:

            display_df["Hash"] = display_df[
                "Hash"
            ].apply(
                short_hash
            )

        if "From" in display_df.columns:

            display_df["From"] = display_df[
                "From"
            ].apply(
                short_address
            )

        if "To" in display_df.columns:

            display_df["To"] = display_df[
                "To"
            ].apply(
                short_address
            )

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No transaction evidence available."
        )


    # ========================================================
    # INVESTIGATION FINDINGS
    # ========================================================

    st.header(
        "📝 Investigation Findings"
    )

    finding_text = []

    finding_text.append(
        f"Blockchain analyzed: {chain}"
    )

    finding_text.append(
        f"Reported wallet: {wallet}"
    )

    finding_text.append(
        f"Transactions analyzed: {len(transactions)}"
    )

    finding_text.append(
        "Connected wallets: "
        f"{len(trace_data.get('visited_wallets', []))}"
    )

    finding_text.append(
        f"Maximum tracing hop: "
        f"{trace_data.get('max_hop', 0)}"
    )

    finding_text.append(
        f"Risk assessment: "
        f"{risk_score}/100 ({risk_level})"
    )

    finding_text.append(
        f"Fraud behaviour assessment: "
        f"{fraud_score}/100 ({fraud_level})"
    )

    for item in finding_text:

        st.markdown(
            f"• {item}"
        )


    # ========================================================
    # CONCLUSION
    # ========================================================

    st.header(
        "📋 Investigation Conclusion"
    )

    st.write(
        f"""
        CryptoShield reconstructed the available blockchain transaction
        flow from the reported suspect wallet on the {chain} blockchain.

        The analysis covered {len(transactions)} transactions,
        {len(trace_data.get('visited_wallets', []))} connected wallets,
        and up to {trace_data.get('max_hop', 0)} tracing hops.

        The resulting analytical risk score is
        {risk_score}/100 ({risk_level}).
        """
    )


    # ========================================================
    # PDF REPORT
    # ========================================================

    st.header(
        "📄 Investigation Report"
    )

    st.write(
        "Generate an investigation-ready PDF containing the "
        "blockchain evidence and analytical findings."
    )

    if st.button(
        "📥 Generate PDF Investigation Report",
        use_container_width=True
    ):

        try:

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".pdf"
            ) as tmp:

                pdf_path = tmp.name

            # IMPORTANT:
            # This matches the current report_generator.py signature.

            generate_pdf_report(

                pdf_path,

                wallet,

                chain,

                transactions,

                trace_data.get(
                    "visited_wallets",
                    []
                ),

                trace_data.get(
                    "max_hop",
                    0
                ),

                abnormal,

                vasp,

                risk_score,

                risk_level,

                patterns
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

            try:

                os.remove(
                    pdf_path
                )

            except Exception:

                pass

            st.success(
                "✅ Investigation report generated successfully."
            )

        except Exception as e:

            st.error(
                f"❌ PDF generation failed: {str(e)}"
            )


    # ========================================================
    # DISCLAIMER
    # ========================================================

    st.divider()

    st.warning(
        """
        ⚠️ IMPORTANT DISCLAIMER

        CryptoShield provides analytical blockchain intelligence only.

        A high risk score, suspicious transaction pattern, or potential
        VASP association does NOT establish criminal activity, identify
        a person as guilty, or prove wallet ownership.

        Findings should be independently verified by authorized
        investigators and supported by additional evidence.
        """
    )


# ============================================================
# DEFAULT LANDING PAGE
# ============================================================

else:

    st.info(
        "👈 Enter a reported suspect wallet address from the "
        "investigation sidebar and click **Analyze Wallet**."
    )

    st.markdown(
        """
        ## 🔐 What CryptoShield Does

        CryptoShield converts a **victim-reported suspect wallet**
        into an explainable blockchain investigation.

        ### Investigation Pipeline

        **Reported Wallet**
        ↓

        **Blockchain Data Collection**
        ↓

        **Multi-Hop Fund Flow Reconstruction**
        ↓

        **Transaction DNA Analysis**
        ↓

        **Abnormal Transaction Detection**
        ↓

        **Fraud Behaviour Detection**
        ↓

        **Explainable Risk Scoring**
        ↓

        **Potential VASP Association**
        ↓

        **Wallet Network Visualization**
        ↓

        **Investigation Report**

        ### Core Technologies

        - 🐍 Python
        - 🔗 Etherscan API
        - 🌐 Ethereum / BNB Chain
        - 🕸️ NetworkX
        - 📊 Pandas
        - 🌐 PyVis
        - 🖥️ Streamlit
        - 📄 ReportLab
        """
    )

    st.divider()

    st.caption(
        "CryptoShield — Blockchain Fraud Intelligence System"
    )
