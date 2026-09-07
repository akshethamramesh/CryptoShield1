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
    "Convert a reported cryptocurrency wallet address into "
    "explainable blockchain investigation intelligence."
)

st.warning(
    "⚠️ CryptoShield provides analytical intelligence only. "
    "A suspicious pattern or risk score does not prove criminal activity."
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("⚙️ Investigation Settings")

analysis_mode = st.sidebar.selectbox(
    "Analysis Mode",
    [
        "Real Wallet Analysis",
        "Demo Suspicious Wallet"
    ]
)

chain = st.sidebar.selectbox(
    "Blockchain",
    [
        "Ethereum",
        "BSC"
    ]
)

max_hops = st.sidebar.slider(
    "Maximum Trace Hops",
    min_value=1,
    max_value=3,
    value=2
)


# ============================================================
# DEMO DATA
# ============================================================

DEMO_WALLET = "DEMO_SUSPECT_A"

demo_transactions = [
    {
        "hash": "demo_tx_001",
        "from": "DEMO_SUSPECT_A",
        "to": "DEMO_WALLET_B",
        "value": 5.0,
        "asset": "ETH",
        "timestamp": "1757000000",
        "blockNumber": "DEMO_1001"
    },
    {
        "hash": "demo_tx_002",
        "from": "DEMO_SUSPECT_A",
        "to": "DEMO_WALLET_C",
        "value": 3.0,
        "asset": "ETH",
        "timestamp": "1757000020",
        "blockNumber": "DEMO_1002"
    },
    {
        "hash": "demo_tx_003",
        "from": "DEMO_SUSPECT_A",
        "to": "DEMO_WALLET_D",
        "value": 2.0,
        "asset": "ETH",
        "timestamp": "1757000040",
        "blockNumber": "DEMO_1003"
    },
    {
        "hash": "demo_tx_004",
        "from": "DEMO_WALLET_B",
        "to": "DEMO_WALLET_E",
        "value": 4.5,
        "asset": "ETH",
        "timestamp": "1757000100",
        "blockNumber": "DEMO_1004"
    },
    {
        "hash": "demo_tx_005",
        "from": "DEMO_WALLET_C",
        "to": "DEMO_WALLET_E",
        "value": 2.5,
        "asset": "ETH",
        "timestamp": "1757000120",
        "blockNumber": "DEMO_1005"
    },
    {
        "hash": "demo_tx_006",
        "from": "DEMO_WALLET_D",
        "to": "DEMO_WALLET_F",
        "value": 1.8,
        "asset": "ETH",
        "timestamp": "1757000150",
        "blockNumber": "DEMO_1006"
    },
    {
        "hash": "demo_tx_007",
        "from": "DEMO_WALLET_E",
        "to": "0x1111111111111111111111111111111111111111",
        "value": 7.0,
        "asset": "ETH",
        "timestamp": "1757000200",
        "blockNumber": "DEMO_1007"
    }
]


# ============================================================
# WALLET INPUT
# ============================================================

if analysis_mode == "Real Wallet Analysis":

    wallet_address = st.sidebar.text_input(
        "Reported Suspect Wallet",
        placeholder="0x..."
    )

else:

    wallet_address = DEMO_WALLET

    st.sidebar.info(
        "Demo mode uses simulated blockchain transactions. "
        "No real funds or suspicious activity are created."
    )


# ============================================================
# START BUTTON
# ============================================================

analyze_button = st.sidebar.button(
    "🔍 Start Investigation",
    use_container_width=True
)


# ============================================================
# ANALYSIS
# ============================================================

if analyze_button:

    # ========================================================
    # VALIDATION
    # ========================================================

    if analysis_mode == "Real Wallet Analysis":

        if not wallet_address:

            st.error(
                "Please enter a wallet address."
            )

            st.stop()

        wallet_address = wallet_address.strip()

        if not wallet_address.startswith("0x"):

            st.error(
                "Invalid wallet address format."
            )

            st.stop()


    # ========================================================
    # BLOCKCHAIN DATA
    # ========================================================

    with st.spinner(
        "🔄 Collecting blockchain transactions..."
    ):

        if analysis_mode == "Demo Suspicious Wallet":

            transactions = demo_transactions

            connected_wallets = list(
                set(
                    [
                        tx["from"]
                        for tx in transactions
                    ]
                    +
                    [
                        tx["to"]
                        for tx in transactions
                    ]
                )
            )

            hop_map = {

                "DEMO_SUSPECT_A": 0,

                "DEMO_WALLET_B": 1,

                "DEMO_WALLET_C": 1,

                "DEMO_WALLET_D": 1,

                "DEMO_WALLET_E": 2,

                "DEMO_WALLET_F": 2,

                "0x1111111111111111111111111111111111111111": 3
            }

            visited_wallets = connected_wallets

            actual_max_hop = 3

        else:

            try:

                trace_result = recursive_trace(
                    wallet_address,
                    chain,
                    max_hops
                )

                transactions = trace_result.get(
                    "transactions",
                    []
                )

                connected_wallets = trace_result.get(
                    "wallets",
                    []
                )

                hop_map = trace_result.get(
                    "hop_map",
                    {}
                )

                visited_wallets = trace_result.get(
                    "visited_wallets",
                    []
                )

                actual_max_hop = trace_result.get(
                    "max_hop",
                    max_hops
                )

            except Exception as e:

                st.error(
                    f"Blockchain analysis failed: {e}"
                )

                st.stop()


    # ========================================================
    # TRANSACTION CHECK
    # ========================================================

    if not transactions:

        st.warning(
            "No transactions were found for this wallet."
        )

        st.stop()


    # ========================================================
    # ABNORMAL TRANSACTION DETECTION
    # ========================================================

    with st.spinner(
        "🧠 Detecting suspicious transaction patterns..."
    ):

        abnormal_alerts = detect_abnormal_transactions(
            transactions
        )


    # ========================================================
    # VASP DETECTION
    # ========================================================

    with st.spinner(
        "🏦 Checking potential VASP associations..."
    ):

        vasp_results = detect_vasp(
            transactions
        )


    # ========================================================
    # TRANSACTION STATISTICS
    # ========================================================

    recipients = set()

    senders = set()

    outgoing_count = 0

    incoming_count = 0


    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        )

        receiver = tx.get(
            "to",
            ""
        )

        if sender:

            senders.add(
                sender.lower()
            )

        if receiver:

            recipients.add(
                receiver.lower()
            )

        if sender.lower() == wallet_address.lower():

            outgoing_count += 1

        if receiver.lower() == wallet_address.lower():

            incoming_count += 1


    # ========================================================
    # RISK SCORE
    # ========================================================

    risk_score = 0


    # High transaction activity
    if len(transactions) >= 5:

        risk_score += 15


    # Multiple recipients
    if len(recipients) >= 2:

        risk_score += 20


    # Multiple incoming sources
    if len(senders) >= 2:

        risk_score += 15


    # Multi-hop movement
    if actual_max_hop >= 2:

        risk_score += 20


    # Abnormal transactions
    if len(abnormal_alerts) >= 2:

        risk_score += 15


    # VASP association
    if len(vasp_results) > 0:

        risk_score += 15


    risk_score = min(
        risk_score,
        100
    )


    # ========================================================
    # RISK LEVEL
    # ========================================================

    if risk_score >= 70:

        risk_level = "HIGH"

    elif risk_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # ========================================================
    # PATTERN DETECTION
    # ========================================================

    patterns = []


    if len(transactions) >= 5:

        patterns.append(
            "High transaction activity"
        )


    if len(recipients) >= 2:

        patterns.append(
            "Fund splitting"
        )


    if len(senders) >= 2:

        patterns.append(
            "Multiple incoming sources"
        )


    if actual_max_hop >= 2:

        patterns.append(
            "Multi-hop fund movement"
        )


    if len(abnormal_alerts) >= 2:

        patterns.append(
            "Abnormal transaction activity"
        )


    if len(vasp_results) > 0:

        patterns.append(
            "Potential VASP association"
        )


    # ========================================================
    # SUCCESS MESSAGE
    # ========================================================

    st.success(
        "✅ Investigation completed successfully."
    )


    # ========================================================
    # INVESTIGATION OVERVIEW
    # ========================================================

    st.markdown("---")

    st.subheader(
        "🎯 Investigation Overview"
    )


    col1, col2, col3, col4, col5 = st.columns(5)


    with col1:

        st.metric(
            "Transactions",
            len(transactions)
        )


    with col2:

        st.metric(
            "Connected Wallets",
            len(connected_wallets)
        )


    with col3:

        st.metric(
            "Max Hop",
            actual_max_hop
        )


    with col4:

        st.metric(
            "Risk Score",
            f"{risk_score}/100"
        )


    with col5:

        st.metric(
            "Alerts",
            len(abnormal_alerts)
        )


    # ========================================================
    # RISK ASSESSMENT
    # ========================================================

    st.markdown("---")

    st.subheader(
        "🚨 Risk Assessment"
    )


    if risk_level == "HIGH":

        st.error(
            f"🔴 HIGH RISK — {risk_score}/100"
        )

    elif risk_level == "MEDIUM":

        st.warning(
            f"🟠 MEDIUM RISK — {risk_score}/100"
        )

    else:

        st.success(
            f"🟢 LOW RISK — {risk_score}/100"
        )


    st.caption(
        "Risk score represents analytical indicators only "
        "and does not establish criminal activity."
    )


    # ========================================================
    # TRANSACTION DNA
    # ========================================================

    st.markdown("---")

    st.subheader(
        "🧬 Transaction DNA"
    )


    dna_score = 0


    if len(transactions) >= 50:

        dna_score += 25


    if len(recipients) >= 10:

        dna_score += 25


    if outgoing_count >= 20:

        dna_score += 25


    if actual_max_hop >= 2:

        dna_score += 25


    dna_score = min(
        dna_score,
        100
    )


    dna_col1, dna_col2, dna_col3, dna_col4 = st.columns(4)


    with dna_col1:

        st.metric(
            "Unique Recipients",
            len(recipients)
        )


    with dna_col2:

        st.metric(
            "Outgoing Transactions",
            outgoing_count
        )


    with dna_col3:

        st.metric(
            "Incoming Transactions",
            incoming_count
        )


    with dna_col4:

        st.metric(
            "DNA Score",
            f"{dna_score}/100"
        )


    # ========================================================
    # DETECTED PATTERNS
    # ========================================================

    st.markdown("---")

    st.subheader(
        "🔎 Detected Patterns"
    )


    if patterns:

        for pattern in patterns:

            st.info(
                f"• {pattern}"
            )

    else:

        st.success(
            "No major predefined patterns detected."
        )


    # ========================================================
    # ABNORMAL TRANSACTIONS
    # ========================================================

    st.markdown("---")

    st.subheader(
        "⚠️ Abnormal Transactions"
    )


    if abnormal_alerts:

        alert_rows = []


        for alert in abnormal_alerts:

            alert_rows.append(
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


        st.dataframe(
            pd.DataFrame(alert_rows),
            use_container_width=True
        )

    else:

        st.success(
            "No abnormal transactions detected."
        )


    # ========================================================
    # FUND FLOW
    # ========================================================

    st.markdown("---")

    st.subheader(
        "💸 Fund Flow"
    )


    flow_rows = []


    for tx in transactions:

        flow_rows.append(
            {
                "From": tx.get(
                    "from",
                    ""
                ),

                "To": tx.get(
                    "to",
                    ""
                ),

                "Value": tx.get(
                    "value",
                    0
                ),

                "Asset": tx.get(
                    "asset",
                    "ETH"
                ),

                "Transaction Hash": tx.get(
                    "hash",
                    ""
                ),

                "Hop": hop_map.get(
                    tx.get("from", ""),
                    hop_map.get(
                        tx.get("to", ""),
                        "?"
                    )
                )
            }
        )


    flow_df = pd.DataFrame(
        flow_rows
    )


    st.dataframe(
        flow_df,
        use_container_width=True
    )


    # ========================================================
    # NETWORK GRAPH
    # ========================================================

    st.markdown("---")

    st.subheader(
        "🕸️ Multi-Hop Fund Flow Network"
    )


    graph = Network(
        height="600px",
        width="100%",
        bgcolor="#ffffff",
        font_color="#000000",
        directed=True
    )


    graph.set_options(
        """
        {
          "physics": {
            "enabled": true,
            "stabilization": {
              "iterations": 200
            }
          },
          "interaction": {
            "hover": true,
            "navigationButtons": true
          }
        }
        """
    )


    # --------------------------------------------------------
    # ADD NODES
    # --------------------------------------------------------

    all_nodes = set()


    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        )

        receiver = tx.get(
            "to",
            ""
        )

        if sender:

            all_nodes.add(sender)

        if receiver:

            all_nodes.add(receiver)


    for node in all_nodes:

        if node.lower() == wallet_address.lower():

            label = "🚨 REPORTED WALLET"

            title = (
                f"Reported Wallet\n{node}"
            )

        else:

            hop = hop_map.get(
                node,
                "?"
            )

            label = (
                f"H{hop}\n"
                f"{node[:8]}..."
            )

            title = (
                f"Wallet: {node}\n"
                f"Hop: {hop}"
            )


        graph.add_node(
            node,
            label=label,
            title=title
        )


    # --------------------------------------------------------
    # ADD EDGES
    # --------------------------------------------------------

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        )

        receiver = tx.get(
            "to",
            ""
        )

        value = tx.get(
            "value",
            0
        )

        asset = tx.get(
            "asset",
            "ETH"
        )

        tx_hash = tx.get(
            "hash",
            ""
        )


        if sender and receiver:

            graph.add_edge(
                sender,
                receiver,
                label=f"{value} {asset}",
                title=f"TX: {tx_hash}"
            )


    graph_html = graph.generate_html()


    html(
        graph_html,
        height=620
    )


    # ========================================================
    # VASP ASSOCIATION
    # ========================================================

    st.markdown("---")

    st.subheader(
        "🏦 Potential VASP Association"
    )


    if vasp_results:

        vasp_rows = []


        for vasp in vasp_results:

            vasp_rows.append(
                {
                    "Name": vasp.get(
                        "name",
                        "Unknown"
                    ),

                    "Type": vasp.get(
                        "type",
                        "Unknown"
                    ),

                    "Address": vasp.get(
                        "address",
                        "Unknown"
                    ),

                    "Confidence": vasp.get(
                        "confidence",
                        "Unknown"
                    )
                }
            )


        st.dataframe(
            pd.DataFrame(vasp_rows),
            use_container_width=True
        )


        st.caption(
            "VASP association is based on available registry "
            "matches and should be independently verified."
        )

    else:

        st.info(
            "No potential VASP association identified."
        )


    # ========================================================
    # EVIDENCE SUMMARY
    # ========================================================

    st.markdown("---")

    st.subheader(
        "📋 Investigation Evidence"
    )


    evidence = {

        "Reported Wallet":
            wallet_address,

        "Blockchain":
            chain,

        "Transactions Analyzed":
            len(transactions),

        "Connected Wallets":
            len(connected_wallets),

        "Maximum Hop":
            actual_max_hop,

        "Detected Patterns":
            len(patterns),

        "Abnormal Alerts":
            len(abnormal_alerts),

        "Potential VASP Matches":
            len(vasp_results),

        "Risk Score":
            f"{risk_score}/100",

        "Risk Level":
            risk_level
    }


    evidence_df = pd.DataFrame(
        list(evidence.items()),
        columns=[
            "Evidence",
            "Result"
        ]
    )


    st.dataframe(
        evidence_df,
        use_container_width=True
    )


    # ========================================================
    # PDF INVESTIGATION REPORT
    # ========================================================

    st.markdown("---")

    st.subheader(
        "📄 Investigation Report"
    )


    st.write(
        "Generate a professional PDF investigation report "
        "from the current blockchain analysis."
    )


    # Create temporary PDF file
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


    finally:

        if os.path.exists(pdf_path):

            try:

                os.remove(pdf_path)

            except Exception:

                pass


    # ========================================================
    # CONCLUSION
    # ========================================================

    st.markdown("---")

    st.subheader(
        "🧾 Investigation Conclusion"
    )


    st.write(
        f"""
        CryptoShield analyzed the reported wallet on the
        **{chain}** blockchain and reconstructed the available
        transaction flow up to **{actual_max_hop} hops**.

        The system analyzed **{len(transactions)} transactions**,
        identified **{len(connected_wallets)} connected wallets**,
        detected **{len(patterns)} behavioral indicators**, and
        generated a risk score of **{risk_score}/100 ({risk_level})**.
        """
    )


    st.info(
        "CryptoShield does not declare who is guilty. "
        "It reconstructs the blockchain money trail and "
        "provides explainable investigation intelligence "
        "for investigators."
    )


# ============================================================
# DEFAULT SCREEN
# ============================================================

else:

    st.info(
        "👈 Select the analysis mode and click "
        "**Start Investigation** to begin."
    )


    st.markdown("---")


    st.subheader(
        "🔄 CryptoShield Workflow"
    )


    st.write(
        """
        **Reported Wallet**
        ↓
        **Blockchain Data Collection**
        ↓
        **Multi-Hop Fund Tracing**
        ↓
        **Suspicious Pattern Detection**
        ↓
        **Explainable Risk Scoring**
        ↓
        **Potential VASP Association**
        ↓
        **PDF Investigation Report**
        """
    )


    st.markdown("---")


    st.subheader(
        "🎯 What CryptoShield Provides"
    )


    col1, col2, col3 = st.columns(3)


    with col1:

        st.markdown(
            """
            ### 🔍 Trace

            Reconstructs the movement of funds
            across connected wallets.
            """
        )


    with col2:

        st.markdown(
            """
            ### 🧠 Analyze

            Detects predefined suspicious
            transaction behavior.
            """
        )


    with col3:

        st.markdown(
            """
            ### 📄 Report

            Generates a professional PDF
            investigation report.
            """
        )
