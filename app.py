import streamlit as st
import pandas as pd
from pyvis.network import Network
from streamlit.components.v1 import html
from blockchain import recursive_trace
from abnormal_detection import detect_abnormal_transactions
from vasp_detection import detect_vasp
from report_generator import generate_pdf_report

import tempfile
import os
from datetime import datetime


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# TITLE
# ============================================================

st.title("🛡️ CryptoShield")
st.subheader("Blockchain Fraud Intelligence System")

st.write(
    "Analyze a reported cryptocurrency wallet, trace fund flows, "
    "detect suspicious patterns, identify potential VASP associations, "
    "and generate an investigation report."
)

st.divider()


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.header("⚙️ Investigation Settings")

chain = st.sidebar.selectbox(
    "Select Blockchain",
    ["Ethereum", "BSC"]
)

wallet_address = st.sidebar.text_input(
    "Reported Suspect Wallet Address",
    placeholder="0x..."
)

max_hop = st.sidebar.slider(
    "Maximum Trace Hops",
    min_value=1,
    max_value=3,
    value=2
)

analyze_button = st.sidebar.button(
    "🔍 Analyze Wallet",
    use_container_width=True
)


# ============================================================
# DEMO DATA
# ============================================================

demo_transactions = [
    {
        "hash": "demo_tx_001",
        "from": "DEMO_SUSPECT_A",
        "to": "DEMO_WALLET_B",
        "value": 5,
        "asset": "ETH",
        "timeStamp": "1757000000"
    },
    {
        "hash": "demo_tx_002",
        "from": "DEMO_SUSPECT_A",
        "to": "DEMO_WALLET_C",
        "value": 3,
        "asset": "ETH",
        "timeStamp": "1757000060"
    },
    {
        "hash": "demo_tx_003",
        "from": "DEMO_SUSPECT_A",
        "to": "DEMO_WALLET_D",
        "value": 2,
        "asset": "ETH",
        "timeStamp": "1757000120"
    },
    {
        "hash": "demo_tx_004",
        "from": "DEMO_WALLET_B",
        "to": "DEMO_WALLET_E",
        "value": 4.8,
        "asset": "ETH",
        "timeStamp": "1757000180"
    },
    {
        "hash": "demo_tx_005",
        "from": "DEMO_WALLET_C",
        "to": "DEMO_WALLET_E",
        "value": 2.9,
        "asset": "ETH",
        "timeStamp": "1757000240"
    },
    {
        "hash": "demo_tx_006",
        "from": "DEMO_WALLET_D",
        "to": "DEMO_WALLET_F",
        "value": 1.9,
        "asset": "ETH",
        "timeStamp": "1757000300"
    },
    {
        "hash": "demo_tx_007",
        "from": "DEMO_WALLET_E",
        "to": "0x1111111111111111111111111111111111111111",
        "value": 7.7,
        "asset": "ETH",
        "timeStamp": "1757000360"
    }
]


# ============================================================
# ANALYSIS
# ============================================================

if analyze_button:

    if not wallet_address:
        st.warning("⚠️ Please enter a wallet address.")
        st.stop()

    # --------------------------------------------------------
    # DEMO MODE
    # --------------------------------------------------------

    if wallet_address.upper() == "DEMO":

        st.info("🧪 Demo Suspicious Wallet Mode")

        transactions = demo_transactions

        connected_wallets = list({
            tx["from"]
            for tx in transactions
            if tx["from"] != "DEMO_SUSPECT_A"
        })

        connected_wallets += list({
            tx["to"]
            for tx in transactions
            if tx["to"] != "DEMO_SUSPECT_A"
        })

        connected_wallets = list(set(connected_wallets))

        actual_max_hop = 3

    # --------------------------------------------------------
    # REAL WALLET MODE
    # --------------------------------------------------------

    else:

        with st.spinner("⛓️ Fetching blockchain transactions..."):

            result = recursive_trace(
                wallet_address,
                chain,
                max_hop=max_hop
            )

        transactions = result.get(
            "transactions",
            []
        )

        connected_wallets = result.get(
            "wallets",
            []
        )

        actual_max_hop = result.get(
            "max_hop",
            max_hop
        )

        if not transactions:

            st.error(
                "❌ No transactions found. "
                "Check the wallet address, blockchain, or API configuration."
            )

            st.stop()


    # ========================================================
    # BASIC METRICS
    # ========================================================

    st.header("📊 Investigation Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Transactions",
        len(transactions)
    )

    col2.metric(
        "Connected Wallets",
        len(connected_wallets)
    )

    col3.metric(
        "Maximum Hop",
        actual_max_hop
    )

    # ========================================================
    # ABNORMAL DETECTION
    # ========================================================

    abnormal_alerts = detect_abnormal_transactions(
        transactions
    )

    col4.metric(
        "Abnormal Alerts",
        len(abnormal_alerts)
    )


    # ========================================================
    # TRANSACTION TIMELINE
    # ========================================================

    st.divider()

    st.header("⏱️ Transaction Timeline")

    timeline_data = []

    for tx in transactions[:50]:

        timestamp = tx.get(
            "timeStamp",
            tx.get("timestamp", "")
        )

        # Convert Unix timestamp
        try:
            if timestamp:
                readable_time = datetime.fromtimestamp(
                    int(timestamp)
                ).strftime("%d-%m-%Y %H:%M:%S")
            else:
                readable_time = "Unknown"
        except:
            readable_time = str(timestamp)

        timeline_data.append({
            "Time": readable_time,
            "From": tx.get("from", "Unknown"),
            "To": tx.get("to", "Unknown"),
            "Value": tx.get("value", 0),
            "Asset": tx.get("asset", "ETH"),
            "Transaction": tx.get("hash", "")[:18] + "..."
        })

    if timeline_data:

        timeline_df = pd.DataFrame(
            timeline_data
        )

        st.dataframe(
            timeline_df,
            use_container_width=True,
            hide_index=True
        )

        if len(transactions) > 50:

            st.caption(
                f"Showing first 50 transactions "
                f"out of {len(transactions)}."
            )

    else:

        st.info(
            "No transaction timeline available."
        )


    # ========================================================
    # ABNORMAL TRANSACTIONS
    # ========================================================

    st.divider()

    st.header("🚨 Abnormal Transaction Detection")

    if abnormal_alerts:

        alert_df = pd.DataFrame(
            abnormal_alerts
        )

        st.dataframe(
            alert_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "No abnormal transactions detected."
        )


    # ========================================================
    # VASP DETECTION
    # ========================================================

    st.divider()

    st.header("🏦 Potential VASP Association")

    vasp_results = detect_vasp(
        transactions
    )

    if vasp_results:

        vasp_df = pd.DataFrame(
            vasp_results
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


    # ========================================================
    # PATTERN DETECTION
    # ========================================================

    st.divider()

    st.header("🧠 Detected Blockchain Patterns")

    patterns = []

    senders = {}
    receivers = {}

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        senders[sender] = senders.get(
            sender,
            0
        ) + 1

        receivers[receiver] = receivers.get(
            receiver,
            0
        ) + 1


    # Fund splitting
    for sender, count in senders.items():

        if count >= 3:

            patterns.append(
                f"Fund splitting detected from {sender[:12]}..."
            )

            break


    # Consolidation
    for receiver, count in receivers.items():

        if count >= 3:

            patterns.append(
                f"Fund consolidation detected at {receiver[:12]}..."
            )

            break


    # Multi-hop
    if actual_max_hop >= 2:

        patterns.append(
            "Multi-hop fund movement detected."
        )


    # VASP proximity
    if vasp_results:

        patterns.append(
            "Potential VASP/exchange association detected."
        )


    if patterns:

        for pattern in patterns:

            st.warning(
                f"⚠️ {pattern}"
            )

    else:

        st.success(
            "No major predefined patterns detected."
        )


    # ========================================================
    # RISK SCORE
    # ========================================================

    st.divider()

    st.header("📈 Explainable Risk Assessment")

    risk_score = 0


    # Transaction volume
    if len(transactions) > 100:

        risk_score += 25

    elif len(transactions) > 50:

        risk_score += 15


    # Connected wallets
    if len(connected_wallets) > 20:

        risk_score += 25

    elif len(connected_wallets) > 10:

        risk_score += 15


    # Abnormal transactions
    if len(abnormal_alerts) > 0:

        risk_score += 20


    # Multi-hop
    if actual_max_hop >= 2:

        risk_score += 15


    # VASP
    if vasp_results:

        risk_score += 15


    risk_score = min(
        risk_score,
        100
    )


    if risk_score >= 70:

        risk_level = "HIGH"

    elif risk_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    c1, c2 = st.columns(2)

    c1.metric(
        "Risk Score",
        f"{risk_score}/100"
    )

    c2.metric(
        "Risk Level",
        risk_level
    )


    # ========================================================
    # FUND FLOW GRAPH
    # ========================================================

    st.divider()

    st.header("🕸️ Fund Flow Network")

    net = Network(
        height="600px",
        width="100%",
        directed=True,
        bgcolor="#ffffff",
        font_color="#000000"
    )

    added_nodes = set()

    for tx in transactions[:100]:

        sender = tx.get(
            "from",
            "Unknown"
        )

        receiver = tx.get(
            "to",
            "Unknown"
        )

        if not sender or not receiver:

            continue


        if sender not in added_nodes:

            net.add_node(
                sender,
                label=sender[:12],
                title=sender,
                shape="dot"
            )

            added_nodes.add(sender)


        if receiver not in added_nodes:

            net.add_node(
                receiver,
                label=receiver[:12],
                title=receiver,
                shape="dot"
            )

            added_nodes.add(receiver)


        net.add_edge(
            sender,
            receiver,
            title=f"{tx.get('value', 0)} {tx.get('asset', 'ETH')}"
        )


    if added_nodes:

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".html"
        ) as temp_graph:

            graph_path = temp_graph.name

        try:

            net.write_html(
                graph_path,
                open_browser=False
            )

            with open(
                graph_path,
                "r",
                encoding="utf-8"
            ) as f:

                graph_html = f.read()

            html(
                graph_html,
                height=620,
                scrolling=True
            )

        finally:

            if os.path.exists(graph_path):

                os.remove(graph_path)


    # ========================================================
    # INVESTIGATION SUMMARY
    # ========================================================

    st.divider()

    st.header("📝 Investigation Summary")

    st.write(
        f"""
        **Reported Wallet:** `{wallet_address}`

        **Blockchain:** {chain}

        **Transactions Analyzed:** {len(transactions)}

        **Connected Wallets:** {len(connected_wallets)}

        **Maximum Trace Depth:** {actual_max_hop} hops

        **Abnormal Alerts:** {len(abnormal_alerts)}

        **Potential VASP Matches:** {len(vasp_results)}

        **Analytical Risk Score:** {risk_score}/100

        **Risk Level:** {risk_level}
        """
    )

    st.info(
        "⚠️ CryptoShield provides analytical intelligence only. "
        "A risk score or suspicious pattern does not establish "
        "criminal activity or identify a person as guilty."
    )


    # ========================================================
    # PDF REPORT
    # ========================================================

    st.divider()

    st.header("📄 Investigation Report")

    pdf_path = None

    try:

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".pdf"
        ) as temp_file:

            pdf_path = temp_file.name


        generate_pdf_report(
            file_path=pdf_path,
            wallet_address=wallet_address,
            chain=chain,
            transactions=transactions,
            connected_wallets=connected_wallets,
            max_hop=actual_max_hop,
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

            pdf_data = pdf_file.read()


        st.download_button(
            label="📥 Download Investigation Report PDF",
            data=pdf_data,
            file_name="CryptoShield_Investigation_Report.pdf",
            mime="application/pdf",
            use_container_width=True
        )

    except Exception as e:

        st.error(
            f"PDF generation failed: {e}"
        )

    finally:

        if pdf_path and os.path.exists(pdf_path):

            os.remove(pdf_path)
