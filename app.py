import streamlit as st
import pandas as pd

from pyvis.network import Network

from blockchain import recursive_trace
from abnormal_detection import detect_abnormal_transactions
from vasp_detection import detect_vasp

from demo_data import (
    get_demo_transactions,
    get_demo_wallet
)


# ==================================================
# PAGE CONFIG
# ==================================================

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
)


# ==================================================
# TITLE
# ==================================================

st.title("🛡️ CryptoShield")

st.subheader(
    "Blockchain Fraud Intelligence System"
)

st.write(
    "Analyze a victim-reported cryptocurrency wallet, "
    "trace connected wallets, detect suspicious patterns, "
    "and identify potential VASP associations."
)

st.info(
    "CryptoShield provides analytical risk indicators. "
    "It does not determine whether a person or wallet "
    "is criminal."
)


# ==================================================
# SIDEBAR
# ==================================================

st.sidebar.header(
    "Investigation Settings"
)


analysis_mode = st.sidebar.radio(
    "Analysis Mode",
    [
        "Real Wallet",
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
    max_value=2,
    value=2
)


# ==================================================
# WALLET INPUT
# ==================================================

if analysis_mode == "Real Wallet":

    wallet_address = st.sidebar.text_input(
        "Suspect Wallet Address",
        placeholder="0x..."
    )

else:

    wallet_address = get_demo_wallet()

    st.sidebar.success(
        "Demo suspicious wallet loaded"
    )

    st.sidebar.code(
        wallet_address
    )


start_investigation = st.sidebar.button(
    "🔍 Start Investigation",
    type="primary"
)


# ==================================================
# INVESTIGATION
# ==================================================

if start_investigation:

    # ----------------------------------------------
    # DEMO MODE
    # ----------------------------------------------

    if analysis_mode == "Demo Suspicious Wallet":

        wallet_address = get_demo_wallet()

        transactions = get_demo_transactions()

        wallets = set()

        for tx in transactions:

            wallets.add(
                tx["from"]
            )

            wallets.add(
                tx["to"]
            )

        hop_map = {

            "demo_suspect_a": 0,

            "demo_wallet_b": 1,
            "demo_wallet_c": 1,
            "demo_wallet_d": 1,

            "demo_wallet_e": 2,
            "demo_wallet_f": 2,

            "0x1111111111111111111111111111111111111111": 3
        }

        wallet_hops = {

            "DEMO_SUSPECT_A": 0,

            "DEMO_WALLET_B": 1,
            "DEMO_WALLET_C": 1,
            "DEMO_WALLET_D": 1,

            "DEMO_WALLET_E": 2,
            "DEMO_WALLET_F": 2,

            "0x1111111111111111111111111111111111111111": 3
        }

        trace_result = {

            "start_wallet":
                wallet_address,

            "chain":
                "Demo Ethereum",

            "transactions":
                transactions,

            "wallets":
                list(wallets),

            "max_hop":
                3,

            "visited_wallets":
                list(wallets),

            "hop_map":
                hop_map,

            "wallet_hops":
                wallet_hops
        }

    # ----------------------------------------------
    # REAL WALLET
    # ----------------------------------------------

    else:

        if not wallet_address:

            st.error(
                "Please enter a wallet address."
            )

            st.stop()

        with st.spinner(
            "Analyzing blockchain..."
        ):

            try:

                trace_result = recursive_trace(
                    wallet_address,
                    chain,
                    max_hops
                )

            except Exception as e:

                st.error(
                    f"Investigation failed: {e}"
                )

                st.stop()

    # ==================================================
    # EXTRACT DATA
    # ==================================================

    transactions = trace_result.get(
        "transactions",
        []
    )

    wallets = trace_result.get(
        "wallets",
        []
    )

    max_hop = trace_result.get(
        "max_hop",
        0
    )

    wallet_hops = trace_result.get(
        "wallet_hops",
        {}
    )

    # ==================================================
    # NORMALIZE HOP MAP
    # ==================================================

    normalized_hops = {}

    for wallet, hop in wallet_hops.items():

        normalized_hops[
            wallet.lower()
        ] = hop

    # ==================================================
    # ABNORMAL TRANSACTIONS
    # ==================================================

    abnormal_alerts = (
        detect_abnormal_transactions(
            transactions
        )
    )

    # ==================================================
    # VASP DETECTION
    # ==================================================

    vasp_results = detect_vasp(
        transactions
    )

    # ==================================================
    # PATTERN ANALYSIS
    # ==================================================

    outgoing_count = 0
    incoming_count = 0

    outgoing_recipients = set()
    incoming_senders = set()

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        if sender == wallet_address.lower():

            outgoing_count += 1

            if receiver:
                outgoing_recipients.add(
                    receiver
                )

        if receiver == wallet_address.lower():

            incoming_count += 1

            if sender:
                incoming_senders.add(
                    sender
                )

    # ==================================================
    # RISK SCORE
    # ==================================================

    risk_score = 0
    risk_reasons = []

    # Multiple transactions
    if len(transactions) >= 5:

        risk_score += 15

        risk_reasons.append(
            "Multiple transaction activity"
        )

    # Multiple recipients
    if len(outgoing_recipients) >= 2:

        risk_score += 20

        risk_reasons.append(
            "Fund splitting / multiple recipients"
        )

    # Multiple incoming sources
    if len(incoming_senders) >= 2:

        risk_score += 15

        risk_reasons.append(
            "Fund consolidation"
        )

    # Multi-hop
    if max_hop >= 2:

        risk_score += 20

        risk_reasons.append(
            "Multi-hop fund movement"
        )

    # Abnormal transactions
    if len(abnormal_alerts) >= 2:

        risk_score += 15

        risk_reasons.append(
            "Abnormal transaction indicators"
        )

    # VASP
    if len(vasp_results) > 0:

        risk_score += 15

        risk_reasons.append(
            "Potential VASP association"
        )

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

    # ==================================================
    # SUMMARY METRICS
    # ==================================================

    st.markdown("---")

    st.header(
        "📊 Investigation Summary"
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
            len(wallets)
        )

    with col3:

        st.metric(
            "Trace Depth",
            f"H{max_hop}"
        )

    with col4:

        st.metric(
            "Abnormal Alerts",
            len(abnormal_alerts)
        )

    with col5:

        st.metric(
            "VASP Matches",
            len(vasp_results)
        )

    # ==================================================
    # RISK
    # ==================================================

    st.markdown("---")

    st.header(
        "🚨 Explainable Risk Assessment"
    )

    if risk_level == "HIGH":

        st.error(
            f"Risk Score: {risk_score}/100 — HIGH"
        )

    elif risk_level == "MEDIUM":

        st.warning(
            f"Risk Score: {risk_score}/100 — MEDIUM"
        )

    else:

        st.success(
            f"Risk Score: {risk_score}/100 — LOW"
        )

    if risk_reasons:

        st.write(
            "**Detected indicators:**"
        )

        for reason in risk_reasons:

            st.write(
                f"• {reason}"
            )

    else:

        st.write(
            "No major risk indicators detected."
        )

    # ==================================================
    # TRANSACTION DNA
    # ==================================================

    st.markdown("---")

    st.header(
        "🧬 Transaction DNA"
    )

    dna_score = 0
    dna_reasons = []

    if len(transactions) >= 5:

        dna_score += 25

        dna_reasons.append(
            "High transaction activity"
        )

    if len(outgoing_recipients) >= 2:

        dna_score += 25

        dna_reasons.append(
            "Multiple recipients"
        )

    if outgoing_count >= 3:

        dna_score += 25

        dna_reasons.append(
            "High outgoing activity"
        )

    if max_hop >= 2:

        dna_score += 25

        dna_reasons.append(
            "Multi-hop movement"
        )

    st.progress(
        dna_score / 100
    )

    st.write(
        f"Transaction DNA Score: "
        f"**{dna_score}/100**"
    )

    for reason in dna_reasons:

        st.write(
            f"• {reason}"
        )

    # ==================================================
    # ABNORMAL TRANSACTIONS
    # ==================================================

    st.markdown("---")

    st.header(
        "⚠️ Abnormal Transaction Detection"
    )

    if abnormal_alerts:

        abnormal_df = pd.DataFrame(
            abnormal_alerts
        )

        st.dataframe(
            abnormal_df,
            use_container_width=True
        )

    else:

        st.success(
            "No abnormal transaction indicators detected."
        )

    # ==================================================
    # FUND FLOW
    # ==================================================

    st.markdown("---")

    st.header(
        "💸 Fund Flow"
    )

    if transactions:

        flow_data = []

        for tx in transactions:

            flow_data.append({

                "From":
                    tx.get(
                        "from",
                        ""
                    ),

                "To":
                    tx.get(
                        "to",
                        ""
                    ),

                "Amount":
                    tx.get(
                        "value",
                        0
                    ),

                "Asset":
                    tx.get(
                        "asset",
                        "ETH"
                    ),

                "Transaction Hash":
                    tx.get(
                        "hash",
                        ""
                    )
            })

        flow_df = pd.DataFrame(
            flow_data
        )

        st.dataframe(
            flow_df,
            use_container_width=True
        )

    # ==================================================
    # GRAPH
    # ==================================================

    st.markdown("---")

    st.header(
        "🕸️ Multi-Hop Wallet Investigation Graph"
    )

    st.caption(
        "H0 = reported wallet | "
        "H1/H2/H3 = connected wallets discovered "
        "during tracing."
    )

    net = Network(
        height="650px",
        width="100%",
        directed=True,
        bgcolor="#0E1117",
        font_color="white"
    )

    net.set_options(
        """
        {
          "nodes": {
            "shape": "dot",
            "size": 22,
            "font": {
              "size": 14,
              "color": "white"
            }
          },
          "edges": {
            "arrows": {
              "to": {
                "enabled": true
              }
            },
            "font": {
              "size": 10,
              "color": "white"
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

    # ----------------------------------------------
    # ADD NODES
    # ----------------------------------------------

    graph_nodes = set()

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
            graph_nodes.add(sender)

        if receiver:
            graph_nodes.add(receiver)

    # ----------------------------------------------
    # NODE LABELS
    # ----------------------------------------------

    for node in graph_nodes:

        normalized = node.lower()

        hop = normalized_hops.get(
            normalized
        )

        if normalized == wallet_address.lower():

            label = "🚨 SUSPECT\nH0"

            title = (
                f"Reported Suspect Wallet\n"
                f"{node}\n"
                f"Hop: 0"
            )

        elif hop is not None:

            label = (
                f"H{hop}\n"
                f"{node[:8]}..."
            )

            title = (
                f"Wallet: {node}\n"
                f"Hop: {hop}"
            )

        else:

            label = (
                f"{node[:8]}..."
            )

            title = (
                f"Wallet: {node}\n"
                f"Hop: Unknown"
            )

        net.add_node(
            node,
            label=label,
            title=title
        )

    # ----------------------------------------------
    # EDGES
    # ----------------------------------------------

    for tx in transactions[:100]:

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

        amount = tx.get(
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

        edge_label = (
            f"{amount:.4f} {asset}"
        )

        edge_title = (
            f"Transaction: {tx_hash}\n"
            f"Amount: {amount} {asset}"
        )

        net.add_edge(
            sender,
            receiver,
            label=edge_label,
            title=edge_title
        )

    # ----------------------------------------------
    # SHOW GRAPH
    # ----------------------------------------------

    try:

        html = net.generate_html()

        st.components.v1.html(
            html,
            height=700,
            scrolling=True
        )

    except Exception as e:

        st.error(
            f"Graph generation failed: {e}"
        )

    # ==================================================
    # VASP
    # ==================================================

    st.markdown("---")

    st.header(
        "🏦 Potential VASP Association"
    )

    if vasp_results:

        for vasp in vasp_results:

            st.info(

                f"**{vasp['name']}**\n\n"

                f"Type: {vasp['type']}\n\n"

                f"Country: {vasp['country']}\n\n"

                f"Address: `{vasp['address']}`\n\n"

                f"Confidence: {vasp['confidence']}"
            )

    else:

        st.write(
            "No VASP match found in the current registry."
        )

    st.caption(
        "VASP results represent potential address association "
        "based on the configured registry. They are not proof "
        "of criminal activity."
    )

    # ==================================================
    # TRANSACTION EVIDENCE
    # ==================================================

    st.markdown("---")

    st.header(
        "📋 Transaction Evidence"
    )

    if transactions:

        evidence = []

        for tx in transactions:

            evidence.append({

                "Transaction":
                    tx.get(
                        "hash",
                        ""
                    ),

                "From":
                    tx.get(
                        "from",
                        ""
                    ),

                "To":
                    tx.get(
                        "to",
                        ""
                    ),

                "Amount":
                    tx.get(
                        "value",
                        0
                    ),

                "Asset":
                    tx.get(
                        "asset",
                        "ETH"
                    ),

                "Block":
                    tx.get(
                        "blockNumber",
                        ""
                    )
            })

        evidence_df = pd.DataFrame(
            evidence
        )

        st.dataframe(
            evidence_df,
            use_container_width=True
        )

    # ==================================================
    # FINAL SUMMARY
    # ==================================================

    st.markdown("---")

    st.header(
        "📝 Investigation Conclusion"
    )

    st.write(
        f"""
        The reported wallet was analyzed on the
        **{trace_result.get('chain', chain)}** network.

        **Transactions analyzed:** {len(transactions)}

        **Connected wallets:** {len(wallets)}

        **Maximum trace depth:** H{max_hop}

        **Abnormal indicators:** {len(abnormal_alerts)}

        **Potential VASP associations:** {len(vasp_results)}

        **Risk score:** {risk_score}/100

        **Risk level:** {risk_level}
        """
    )

    st.warning(
        "This analysis is decision-support evidence only. "
        "Investigators should independently verify all "
        "blockchain evidence before taking action."
    )

else:

    # ==================================================
    # INITIAL SCREEN
    # ==================================================

    st.markdown("---")

    st.header(
        "🚀 How CryptoShield Works"
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.subheader(
            "1️⃣ Report"
        )

        st.write(
            "Investigator enters the "
            "victim-reported wallet."
        )

    with col2:

        st.subheader(
            "2️⃣ Trace"
        )

        st.write(
            "CryptoShield follows the "
            "fund flow across multiple hops."
        )

    with col3:

        st.subheader(
            "3️⃣ Analyze"
        )

        st.write(
            "Suspicious patterns, risk indicators "
            "and potential VASP associations are shown."
        )

    st.markdown("---")

    st.info(
        "💡 For your SIH presentation, use "
        "**Demo Suspicious Wallet** first to demonstrate "
        "the complete investigation flow without sending "
        "or moving real cryptocurrency."
    )
