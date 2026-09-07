import os
import tempfile

import streamlit as st
import pandas as pd
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components

from blockchain import trace_wallet
from transaction_dna import analyze_transaction_dna
from abnormal_detection import detect_abnormal_transactions
from vasp_detection import detect_vasp
from risk_engine import calculate_risk_v2
from report_generator import generate_pdf_report


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

    .subtitle {
        font-size: 18px;
        opacity: 0.75;
        margin-bottom: 20px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ CryptoShield</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">Blockchain Fraud Intelligence System</div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    CryptoShield converts a **victim-reported suspect wallet address**
    into an explainable blockchain investigation by tracing fund flows,
    analyzing wallet behavior, detecting suspicious indicators,
    and identifying potential VASP / exchange associations.
    """
)

st.warning(
    "⚠️ Analytical intelligence only. A risk score or suspicious "
    "pattern does not establish criminal activity or identify a person as guilty."
)

st.divider()


# ============================================================
# SESSION STATE
# ============================================================

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

if "dna_result" not in st.session_state:
    st.session_state.dna_result = None

if "abnormal_alerts" not in st.session_state:
    st.session_state.abnormal_alerts = None

if "vasp_results" not in st.session_state:
    st.session_state.vasp_results = None


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🔎 Investigation")

st.sidebar.markdown(
    "Enter the wallet address reported by the victim or investigator."
)

wallet_address = st.sidebar.text_input(
    "Reported Wallet Address",
    placeholder="0x..."
)

chain = st.sidebar.selectbox(
    "Blockchain",
    [
        "Ethereum",
        "BSC"
    ]
)

max_hop = st.sidebar.slider(
    "Maximum Trace Hop",
    min_value=1,
    max_value=3,
    value=2
)

st.sidebar.markdown("---")

analyze_button = st.sidebar.button(
    "🚀 Start Investigation",
    use_container_width=True
)


# ============================================================
# PATTERN DETECTION
# ============================================================

def detect_patterns(
    transactions,
    start_wallet,
    wallet_hops
):

    patterns = []

    if not transactions:
        return patterns

    start_wallet = start_wallet.lower()

    outgoing = set()
    incoming = set()
    timestamps = []

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        if sender == start_wallet and receiver:
            outgoing.add(receiver)

        if receiver == start_wallet and sender:
            incoming.add(sender)

        try:

            timestamp = int(
                tx.get(
                    "timeStamp",
                    0
                )
            )

            if timestamp:
                timestamps.append(timestamp)

        except:
            pass

    # --------------------------------------------------------
    # Fan-out
    # --------------------------------------------------------

    if len(outgoing) >= 10:

        patterns.append(
            "Very high fund splitting / fan-out behavior"
        )

    elif len(outgoing) >= 5:

        patterns.append(
            "Fund splitting / fan-out behavior detected"
        )

    # --------------------------------------------------------
    # Fan-in
    # --------------------------------------------------------

    if len(incoming) >= 10:

        patterns.append(
            "Very high fund consolidation / fan-in behavior"
        )

    elif len(incoming) >= 5:

        patterns.append(
            "Fund consolidation / fan-in behavior detected"
        )

    # --------------------------------------------------------
    # Multi-hop
    # --------------------------------------------------------

    max_detected_hop = 0

    if wallet_hops:

        try:

            max_detected_hop = max(
                wallet_hops.values()
            )

        except:
            max_detected_hop = 0

    if max_detected_hop >= 3:

        patterns.append(
            f"Deep multi-hop fund movement detected up to Hop {max_detected_hop}"
        )

    elif max_detected_hop >= 2:

        patterns.append(
            "Multi-hop fund movement detected"
        )

    # --------------------------------------------------------
    # Rapid transaction sequence
    # --------------------------------------------------------

    timestamps.sort()

    rapid_count = 0

    for i in range(
        1,
        len(timestamps)
    ):

        if (
            timestamps[i]
            - timestamps[i - 1]
            <= 300
        ):

            rapid_count += 1

    if rapid_count >= 10:

        patterns.append(
            "Frequent rapid transaction sequence detected"
        )

    elif rapid_count >= 5:

        patterns.append(
            "Rapid transaction sequence detected"
        )

    return patterns


# ============================================================
# NODE INFORMATION
# ============================================================

def get_node_info(
    address,
    wallet_hops,
    start_wallet,
    vasp_addresses
):

    address_lower = address.lower()
    start_wallet = start_wallet.lower()

    if address_lower == start_wallet:

        return (
            "🔴 Reported Wallet",
            0
        )

    if address_lower in vasp_addresses:

        return (
            "🏦 Potential VASP",
            wallet_hops.get(
                address_lower,
                "?"
            )
        )

    hop = wallet_hops.get(
        address_lower,
        "?"
    )

    if hop == 1:

        return (
            "🟡 Hop 1",
            hop
        )

    elif hop == 2:

        return (
            "🟠 Hop 2",
            hop
        )

    elif isinstance(
        hop,
        int
    ) and hop >= 3:

        return (
            "🟣 Hop 3+",
            hop
        )

    return (
        "⚪ Wallet",
        hop
    )


# ============================================================
# FUND FLOW GRAPH
# ============================================================

def build_fund_flow_graph(
    transactions,
    start_wallet,
    wallet_hops,
    vasp_results
):

    graph = nx.DiGraph()

    start_wallet = start_wallet.lower()

    # --------------------------------------------------------
    # VASP addresses
    # --------------------------------------------------------

    vasp_addresses = set()

    for vasp in vasp_results:

        address = vasp.get(
            "address",
            ""
        ).lower()

        if address:

            vasp_addresses.add(
                address
            )

    # --------------------------------------------------------
    # Add nodes
    # --------------------------------------------------------

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        if sender:
            graph.add_node(sender)

        if receiver:
            graph.add_node(receiver)

    graph.add_node(start_wallet)

    # --------------------------------------------------------
    # Add edges
    # --------------------------------------------------------

    for tx in transactions:

        sender = tx.get(
            "from",
            ""
        ).lower()

        receiver = tx.get(
            "to",
            ""
        ).lower()

        if not sender or not receiver:
            continue

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

        try:

            value_label = (
                f"{float(value):.4f} {asset}"
            )

        except:

            value_label = (
                f"{value} {asset}"
            )

        title = (
            f"<b>Transaction</b><br>"
            f"From: {sender}<br>"
            f"To: {receiver}<br>"
            f"Value: {value_label}<br>"
            f"Hash: {tx_hash}"
        )

        if graph.has_edge(
            sender,
            receiver
        ):

            graph[sender][receiver]["weight"] += 1

        else:

            graph.add_edge(
                sender,
                receiver,
                label=value_label,
                title=title,
                weight=1
            )

    # --------------------------------------------------------
    # PyVis
    # --------------------------------------------------------

    net = Network(
        height="650px",
        width="100%",
        directed=True,
        bgcolor="#ffffff",
        font_color="#111111"
    )

    net.set_options(
        """
        {
            "nodes": {
                "shape": "dot",
                "size": 22,
                "font": {
                    "size": 14
                }
            },

            "edges": {
                "arrows": {
                    "to": {
                        "enabled": true,
                        "scaleFactor": 0.7
                    }
                },

                "font": {
                    "size": 10,
                    "align": "middle"
                },

                "smooth": {
                    "enabled": true,
                    "type": "dynamic"
                }
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

    # --------------------------------------------------------
    # Add visual nodes
    # --------------------------------------------------------

    for node in graph.nodes:

        role, hop = get_node_info(
            node,
            wallet_hops,
            start_wallet,
            vasp_addresses
        )

        if len(node) > 16:

            display_address = (
                node[:8]
                + "..."
                + node[-6:]
            )

        else:

            display_address = node

        label = (
            f"{role}\n"
            f"{display_address}"
        )

        title = (
            f"Role: {role}<br>"
            f"Address: {node}<br>"
            f"Hop: {hop}"
        )

        if node == start_wallet:

            node_color = "#ff4b4b"

        elif node in vasp_addresses:

            node_color = "#9b59b6"

        elif hop == 1:

            node_color = "#f1c40f"

        elif hop == 2:

            node_color = "#e67e22"

        elif isinstance(
            hop,
            int
        ) and hop >= 3:

            node_color = "#8e44ad"

        else:

            node_color = "#95a5a6"

        net.add_node(
            node,
            label=label,
            title=title,
            color=node_color
        )

    # --------------------------------------------------------
    # Add visual edges
    # --------------------------------------------------------

    for source, target, data in graph.edges(
        data=True
    ):

        net.add_edge(
            source,
            target,
            label=data.get(
                "label",
                ""
            ),
            title=data.get(
                "title",
                ""
            ),
            width=min(
                1 + data.get(
                    "weight",
                    1
                ),
                6
            )
        )

    return net, graph


# ============================================================
# START INVESTIGATION
# ============================================================

if analyze_button:

    if not wallet_address:

        st.error(
            "❌ Please enter a reported wallet address."
        )

    else:

        try:

            with st.spinner(
                "🔍 Collecting blockchain data and reconstructing fund flow..."
            ):

                result = trace_wallet(
                    wallet_address,
                    chain=chain,
                    max_hop=max_hop
                )

            st.session_state.analysis_result = result

            transactions = result.get(
                "transactions",
                []
            )

            # ------------------------------------------------
            # Transaction DNA
            # ------------------------------------------------

            dna = analyze_transaction_dna(
                transactions,
                wallet_address
            )

            st.session_state.dna_result = dna

            # ------------------------------------------------
            # Abnormal detection
            # ------------------------------------------------

            abnormal_alerts = (
                detect_abnormal_transactions(
                    transactions
                )
            )

            st.session_state.abnormal_alerts = (
                abnormal_alerts
            )

            # ------------------------------------------------
            # VASP Intelligence
            # ------------------------------------------------

            vasp_results = detect_vasp(
                transactions
            )

            st.session_state.vasp_results = (
                vasp_results
            )

            st.success(
                "✅ Investigation completed successfully."
            )

        except Exception as e:

            st.error(
                f"❌ Investigation failed: {e}"
            )


# ============================================================
# RESULTS
# ============================================================

result = st.session_state.analysis_result


if result:

    transactions = result.get(
        "transactions",
        []
    )

    connected_wallets = result.get(
        "wallets",
        []
    )

    wallet_hops = result.get(
        "wallet_hops",
        {}
    )

    dna = (
        st.session_state.dna_result
        or {}
    )

    abnormal_alerts = (
        st.session_state.abnormal_alerts
        or []
    )

    vasp_results = (
        st.session_state.vasp_results
        or []
    )

    # ========================================================
    # RISK ENGINE V2
    # ========================================================

    risk_score, risk_level, risk_factors = (
        calculate_risk_v2(

            transaction_count=len(
                transactions
            ),

            connected_wallets=len(
                connected_wallets
            ),

            rapid_movements=dna.get(
                "rapid_movements",
                0
            ),

            abnormal_alerts=len(
                abnormal_alerts
            ),

            fan_in=dna.get(
                "fan_in",
                0
            ),

            fan_out=dna.get(
                "fan_out",
                0
            ),

            max_hop=result.get(
                "max_hop",
                0
            ),

            vasp_matches=len(
                vasp_results
            )
        )
    )

    # ========================================================
    # OVERVIEW
    # ========================================================

    st.header(
        "📊 Investigation Overview"
    )

    col1, col2, col3, col4 = st.columns(4)

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
            "Maximum Hop",
            result.get(
                "max_hop",
                0
            )
        )

    with col4:

        st.metric(
            "Risk Score",
            f"{risk_score}/100"
        )

    # ========================================================
    # RISK STATUS
    # ========================================================

    if risk_level == "HIGH":

        st.error(
            "🔴 HIGH RISK — Multiple suspicious behavioral indicators detected."
        )

    elif risk_level == "MEDIUM":

        st.warning(
            "🟠 MEDIUM RISK — Some suspicious behavioral indicators detected."
        )

    else:

        st.success(
            "🟢 LOW RISK — Limited predefined suspicious indicators detected."
        )

    # ========================================================
    # EXPLAINABLE RISK
    # ========================================================

    st.header(
        "🧠 Explainable Risk Assessment"
    )

    risk_col1, risk_col2 = st.columns(2)

    with risk_col1:

        st.metric(
            "Risk Score",
            f"{risk_score}/100"
        )

    with risk_col2:

        st.metric(
            "Risk Level",
            risk_level
        )

    st.markdown(
        "### 📌 Contributing Evidence"
    )

    if risk_factors:

        risk_data = []

        for factor in risk_factors:

            risk_data.append({
                "Indicator": factor.get(
                    "indicator",
                    ""
                ),
                "Risk Contribution": (
                    f'+{factor.get("points", 0)}'
                )
            })

        risk_df = pd.DataFrame(
            risk_data
        )

        st.dataframe(
            risk_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No major predefined risk indicators contributed to the score."
        )

    st.caption(
        "Risk scoring represents analytical indicators only "
        "and does not establish criminal activity."
    )

    st.divider()

    # ========================================================
    # TRANSACTION DNA
    # ========================================================

    st.header(
        "🧬 Transaction DNA"
    )

    native_asset = (
        "BNB"
        if chain == "BSC"
        else "ETH"
    )

    dna_col1, dna_col2, dna_col3 = (
        st.columns(3)
    )

    with dna_col1:

        st.metric(
            "Transactions",
            dna.get(
                "transaction_count",
                0
            )
        )

    with dna_col2:

        st.metric(
            "Average Transfer",
            f'{dna.get("average_transfer", 0):.4f} {native_asset}'
        )

    with dna_col3:

        st.metric(
            "Total Volume",
            f'{dna.get("total_volume", 0):.4f} {native_asset}'
        )

    dna_col1, dna_col2, dna_col3 = (
        st.columns(3)
    )

    with dna_col1:

        st.metric(
            "Unique Senders",
            dna.get(
                "unique_senders",
                0
            )
        )

    with dna_col2:

        st.metric(
            "Unique Receivers",
            dna.get(
                "unique_receivers",
                0
            )
        )

    with dna_col3:

        st.metric(
            "Rapid Movements",
            dna.get(
                "rapid_movements",
                0
            )
        )

    st.markdown(
        "### 🔀 Wallet Behavior"
    )

    behavior_col1, behavior_col2 = (
        st.columns(2)
    )

    with behavior_col1:

        st.metric(
            "Fan-In",
            dna.get(
                "fan_in",
                0
            )
        )

    with behavior_col2:

        st.metric(
            "Fan-Out",
            dna.get(
                "fan_out",
                0
            )
        )

    st.markdown(
        "### 🚨 Behavioral Indicators"
    )

    indicators = dna.get(
        "behavior_indicators",
        []
    )

    if indicators:

        for indicator in indicators:

            st.warning(
                f"⚠️ {indicator}"
            )

    else:

        st.success(
            "No major predefined behavioral indicators detected."
        )

    st.divider()

    # ========================================================
    # FUND FLOW NETWORK
    # ========================================================

    st.header(
        "🌐 Fund Flow Network V2"
    )

    st.markdown(
        """
        **Legend**

        🔴 Reported Wallet &nbsp;&nbsp;
        🟡 Hop 1 &nbsp;&nbsp;
        🟠 Hop 2 &nbsp;&nbsp;
        🟣 Hop 3+ &nbsp;&nbsp;
        🏦 Potential VASP
        """
    )

    graph_transactions = transactions[:100]

    net, graph = build_fund_flow_graph(
        graph_transactions,
        wallet_address,
        wallet_hops,
        vasp_results
    )

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".html"
    ) as tmp_file:

        graph_path = tmp_file.name

    net.save_graph(
        graph_path
    )

    try:

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

    finally:

        try:

            os.unlink(
                graph_path
            )

        except:
            pass

    st.info(
        """
        **Flow interpretation**

        🔴 Reported Wallet → investigation starting point

        🟡 Hop 1 → directly connected wallets

        🟠 Hop 2 → wallets reached through another wallet

        🟣 Hop 3+ → deeper network connections

        🏦 Potential VASP → address matching the available VASP registry
        """
    )

    st.write(
        f"**Graph Nodes:** {graph.number_of_nodes()}  | "
        f"**Graph Edges:** {graph.number_of_edges()}  | "
        f"**Transactions Displayed:** {min(len(transactions), 100)}"
    )

    st.divider()

    # ========================================================
    # PATTERNS
    # ========================================================

    st.header(
        "🧩 Detected Fund-Flow Patterns"
    )

    patterns = detect_patterns(
        transactions,
        wallet_address,
        wallet_hops
    )

    if patterns:

        for pattern in patterns:

            st.warning(
                f"⚠️ {pattern}"
            )

    else:

        st.success(
            "No major predefined fund-flow patterns detected."
        )

    st.divider()

    # ========================================================
    # ABNORMAL TRANSACTIONS
    # ========================================================

    st.header(
        "🚨 Abnormal Transaction Analysis"
    )

    if abnormal_alerts:

        abnormal_df = pd.DataFrame(
            abnormal_alerts
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

    st.divider()

    # ========================================================
    # VASP / EXCHANGE INTELLIGENCE
    # ========================================================

    st.header(
        "🏦 Potential VASP / Exchange Association"
    )

    if vasp_results:

        vasp_df = pd.DataFrame(
            vasp_results
        )

        display_columns = [
            "name",
            "type",
            "country",
            "address",
            "transaction_role",
            "confidence",
            "source"
        ]

        available_columns = [
            column
            for column in display_columns
            if column in vasp_df.columns
        ]

        st.dataframe(
            vasp_df[
                available_columns
            ],
            use_container_width=True,
            hide_index=True
        )

        st.warning(
            """
            ⚠️ VASP / exchange associations are based on the
            available address-label registry.

            A registry match does not prove wallet ownership,
            involvement in fraud, or criminal activity.

            Independent verification is required.
            """
        )

    else:

        st.info(
            "No potential VASP / exchange association identified "
            "from the available registry."
        )

    st.divider()

    # ========================================================
    # TRANSACTION EVIDENCE
    # ========================================================

    st.header(
        "📋 Transaction Evidence"
    )

    if transactions:

        display_transactions = []

        for tx in transactions[:100]:

            display_transactions.append({

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

                "Value":
                    tx.get(
                        "value",
                        0
                    ),

                "Asset":
                    tx.get(
                        "asset",
                        native_asset
                    ),

                "Timestamp":
                    tx.get(
                        "timeStamp",
                        ""
                    )
            })

        tx_df = pd.DataFrame(
            display_transactions
        )

        st.dataframe(
            tx_df,
            use_container_width=True,
            hide_index=True
        )

        if len(transactions) > 100:

            st.info(
                f"Showing first 100 of {len(transactions)} "
                "transactions analyzed."
            )

    else:

        st.info(
            "No transaction evidence available."
        )

    st.divider()

    # ========================================================
    # INVESTIGATION SUMMARY
    # ========================================================

    st.header(
        "📝 Investigation Summary"
    )

    summary_col1, summary_col2 = (
        st.columns(2)
    )

    with summary_col1:

        st.write(
            f"**Reported Wallet:** `{wallet_address}`"
        )

        st.write(
            f"**Blockchain:** {chain}"
        )

        st.write(
            f"**Transactions Analyzed:** {len(transactions)}"
        )

        st.write(
            f"**Connected Wallets:** {len(connected_wallets)}"
        )

    with summary_col2:

        st.write(
            f"**Maximum Hop:** {result.get('max_hop', 0)}"
        )

        st.write(
            f"**Risk Score:** {risk_score}/100"
        )

        st.write(
            f"**Risk Level:** {risk_level}"
        )

        st.write(
            f"**Potential VASP Matches:** {len(vasp_results)}"
        )

    st.divider()

    # ========================================================
    # PDF REPORT
    # ========================================================

    st.header(
        "📄 Investigation Report"
    )

    if st.button(
        "📥 Generate PDF Report",
        use_container_width=True
    ):

        try:

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".pdf"
            ) as pdf_file:

                pdf_path = pdf_file.name

            generate_pdf_report(
                file_path=pdf_path,
                wallet_address=wallet_address,
                chain=chain,
                transactions=transactions,
                connected_wallets=connected_wallets,
                max_hop=result.get(
                    "max_hop",
                    max_hop
                ),
                abnormal_alerts=abnormal_alerts,
                vasp_results=vasp_results,
                risk_score=risk_score,
                risk_level=risk_level,
                patterns=patterns
            )

            with open(
                pdf_path,
                "rb"
            ) as file:

                pdf_bytes = file.read()

            st.download_button(
                label="⬇️ Download Investigation Report",
                data=pdf_bytes,
                file_name="CryptoShield_Investigation_Report.pdf",
                mime="application/pdf",
                use_container_width=True
            )

            try:

                os.unlink(
                    pdf_path
                )

            except:
                pass

        except Exception as e:

            st.error(
                f"❌ PDF generation failed: {e}"
            )

    st.divider()

    # ========================================================
    # DISCLAIMER
    # ========================================================

    st.info(
        """
        **Investigation Disclaimer**

        CryptoShield provides blockchain analytics and investigative
        intelligence.

        Wallet addresses, transaction behavior, VASP associations,
        and analytical risk scores do not by themselves prove
        criminal activity or identify a real-world individual.

        Findings should be independently verified by authorized
        investigators.
        """
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🛡️ CryptoShield — Blockchain Fraud Intelligence System"
)

st.caption(
    "DINO — Digital Investigation & Network Observatory"
)
