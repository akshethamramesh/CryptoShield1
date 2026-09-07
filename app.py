import streamlit as st
import pandas as pd
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import tempfile
import os

from blockchain import trace_wallet
from abnormal_detection import detect_abnormal_transactions
from vasp_detection import detect_vasp
from transaction_dna import analyze_transaction_dna
from report_generator import generate_pdf_report


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# TITLE
# =========================================================

st.title("🛡️ CryptoShield")
st.subheader("Blockchain Fraud Intelligence System")

st.markdown(
    """
    **CryptoShield** analyzes a victim-reported cryptocurrency wallet,
    reconstructs fund movement across blockchain transactions,
    detects suspicious behavioral patterns, and identifies potential
    VASP/exchange associations.

    > ⚠️ This system provides analytical intelligence only.
    > It does not establish criminal activity or identify a person as guilty.
    """
)

st.divider()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.header("🔎 Investigation Input")

wallet_address = st.sidebar.text_input(
    "Reported Suspect Wallet",
    placeholder="0x..."
)

chain = st.sidebar.selectbox(
    "Blockchain",
    ["Ethereum", "BSC"]
)

max_hop = st.sidebar.slider(
    "Maximum Trace Hops",
    min_value=1,
    max_value=3,
    value=2
)

analyze_button = st.sidebar.button(
    "🚀 Start Investigation",
    use_container_width=True
)


# =========================================================
# SESSION STATE
# =========================================================

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

if "dna_result" not in st.session_state:
    st.session_state.dna_result = None

if "abnormal_alerts" not in st.session_state:
    st.session_state.abnormal_alerts = None

if "vasp_results" not in st.session_state:
    st.session_state.vasp_results = None


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def calculate_risk(
    transaction_count,
    connected_wallets,
    rapid_movements,
    abnormal_alerts,
    vasp_results,
    fan_in,
    fan_out,
    max_hop
):
    """
    Explainable prototype risk score.
    This is an analytical score, not a criminal verdict.
    """

    score = 0
    reasons = []

    # Transaction activity
    if transaction_count >= 100:
        score += 15
        reasons.append("High transaction activity")

    # Connected wallets
    if connected_wallets >= 20:
        score += 15
        reasons.append("Large connected wallet network")

    # Rapid movements
    if rapid_movements >= 5:
        score += 15
        reasons.append("Rapid fund movement detected")

    # Abnormal transactions
    if len(abnormal_alerts) >= 5:
        score += 15
        reasons.append("Multiple abnormal transaction indicators")

    # Fan-out
    if fan_out >= 5:
        score += 10
        reasons.append("High fan-out behavior")

    # Fan-in
    if fan_in >= 5:
        score += 10
        reasons.append("High fan-in behavior")

    # Multi-hop
    if max_hop >= 2:
        score += 10
        reasons.append("Multi-hop fund movement observed")

    # VASP association
    if len(vasp_results) > 0:
        score += 10
        reasons.append("Potential VASP association identified")

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, reasons


def detect_patterns(transactions, start_wallet, wallet_hops):
    """
    Detect high-level fund-flow patterns.
    """

    patterns = []

    if not transactions:
        return patterns

    start_wallet = start_wallet.lower()

    outgoing = set()
    incoming = set()

    for tx in transactions:

        sender = tx.get("from", "").lower()
        receiver = tx.get("to", "").lower()

        if sender == start_wallet and receiver:
            outgoing.add(receiver)

        if receiver == start_wallet and sender:
            incoming.add(sender)

    # Fan-out
    if len(outgoing) >= 5:
        patterns.append(
            "Fund splitting / fan-out behavior detected"
        )

    # Fan-in
    if len(incoming) >= 5:
        patterns.append(
            "Fund consolidation / fan-in behavior detected"
        )

    # Multi-hop
    max_detected_hop = max(
        wallet_hops.values()
    ) if wallet_hops else 0

    if max_detected_hop >= 2:
        patterns.append(
            f"Multi-hop fund movement detected up to Hop {max_detected_hop}"
        )

    # Rapid transfers
    timestamps = []

    for tx in transactions:

        try:
            timestamp = int(tx.get("timeStamp", 0))
            if timestamp:
                timestamps.append(timestamp)
        except:
            pass

    timestamps.sort()

    rapid_count = 0

    for i in range(1, len(timestamps)):

        if timestamps[i] - timestamps[i - 1] <= 300:
            rapid_count += 1

    if rapid_count >= 5:
        patterns.append(
            "Rapid transaction sequence detected"
        )

    return patterns


def get_node_info(
    address,
    wallet_hops,
    start_wallet,
    vasp_addresses
):

    address_lower = address.lower()

    if address_lower == start_wallet.lower():
        return "🔴 Reported Wallet", 0

    if address_lower in vasp_addresses:
        return "🏦 Potential VASP", wallet_hops.get(
            address_lower,
            "?"
        )

    hop = wallet_hops.get(
        address_lower,
        "?"
    )

    if hop == 1:
        return "🟡 Hop 1", hop

    elif hop == 2:
        return "🟠 Hop 2", hop

    elif isinstance(hop, int) and hop >= 3:
        return "🟣 Hop 3+", hop

    return "⚪ Wallet", hop


def build_fund_flow_graph(
    transactions,
    start_wallet,
    wallet_hops,
    vasp_results
):

    graph = nx.DiGraph()

    start_wallet = start_wallet.lower()

    vasp_addresses = set()

    for vasp in vasp_results:

        address = vasp.get(
            "address",
            ""
        ).lower()

        if address:
            vasp_addresses.add(address)

    # -----------------------------------------------------
    # Add nodes
    # -----------------------------------------------------

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

    # Ensure reported wallet exists
    graph.add_node(start_wallet)

    # -----------------------------------------------------
    # Add edges
    # -----------------------------------------------------

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

        edge_label = (
            f"{value:.4f} {asset}"
            if isinstance(value, float)
            else f"{value} {asset}"
        )

        title = (
            f"Transaction\n"
            f"From: {sender}\n"
            f"To: {receiver}\n"
            f"Value: {edge_label}\n"
            f"Hash: {tx_hash}"
        )

        if graph.has_edge(sender, receiver):

            graph[sender][receiver]["weight"] += 1

        else:

            graph.add_edge(
                sender,
                receiver,
                label=edge_label,
                title=title,
                weight=1
            )

    # -----------------------------------------------------
    # PyVis
    # -----------------------------------------------------

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
                "enabled": true
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

    # -----------------------------------------------------
    # Nodes
    # -----------------------------------------------------

    for node in graph.nodes:

        role, hop = get_node_info(
            node,
            wallet_hops,
            start_wallet,
            vasp_addresses
        )

        display_address = (
            node[:8] + "..." + node[-6:]
            if len(node) > 16
            else node
        )

        label = (
            f"{role}\n"
            f"{display_address}"
        )

        title = (
            f"Role: {role}<br>"
            f"Address: {node}<br>"
            f"Hop: {hop}"
        )

        # Actual node color
        if node == start_wallet:
            node_color = "#ff4b4b"

        elif node in vasp_addresses:
            node_color = "#9b59b6"

        elif hop == 1:
            node_color = "#f1c40f"

        elif hop == 2:
            node_color = "#e67e22"

        elif isinstance(hop, int) and hop >= 3:
            node_color = "#8e44ad"

        else:
            node_color = "#95a5a6"

        net.add_node(
            node,
            label=label,
            title=title,
            color=node_color
        )

    # -----------------------------------------------------
    # Edges
    # -----------------------------------------------------

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
                1 + data.get("weight", 1),
                6
            )
        )

    return net, graph


# =========================================================
# INVESTIGATION
# =========================================================

if analyze_button:

    if not wallet_address:

        st.error(
            "Please enter a reported wallet address."
        )

    else:

        try:

            with st.spinner(
                "🔍 Collecting blockchain data and tracing fund flow..."
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

            connected_wallets = result.get(
                "wallets",
                []
            )

            wallet_hops = result.get(
                "wallet_hops",
                {}
            )

            # -------------------------------------------------
            # Transaction DNA
            # -------------------------------------------------

            dna = analyze_transaction_dna(
                transactions,
                wallet_address
            )

            st.session_state.dna_result = dna

            # -------------------------------------------------
            # Abnormal transactions
            # -------------------------------------------------

            abnormal_alerts = detect_abnormal_transactions(
                transactions
            )

            st.session_state.abnormal_alerts = (
                abnormal_alerts
            )

            # -------------------------------------------------
            # VASP
            # -------------------------------------------------

            vasp_results = detect_vasp(
                transactions
            )

            st.session_state.vasp_results = (
                vasp_results
            )

            st.success(
                "✅ Blockchain investigation completed."
            )

        except Exception as e:

            st.error(
                f"❌ Investigation failed: {e}"
            )


# =========================================================
# DISPLAY RESULTS
# =========================================================

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

    dna = st.session_state.dna_result or {}

    abnormal_alerts = (
        st.session_state.abnormal_alerts or []
    )

    vasp_results = (
        st.session_state.vasp_results or []
    )

    # =====================================================
    # RISK SCORE
    # =====================================================

    risk_score, risk_level, risk_reasons = (
        calculate_risk(
            transaction_count=len(transactions),
            connected_wallets=len(
                connected_wallets
            ),
            rapid_movements=dna.get(
                "rapid_movements",
                0
            ),
            abnormal_alerts=abnormal_alerts,
            vasp_results=vasp_results,
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
            )
        )
    )

    # =====================================================
    # OVERVIEW
    # =====================================================

    st.header("📊 Investigation Overview")

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
            "Max Hop",
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

    # =====================================================
    # RISK LEVEL
    # =====================================================

    if risk_level == "HIGH":

        st.error(
            f"🔴 Risk Level: {risk_level}"
        )

    elif risk_level == "MEDIUM":

        st.warning(
            f"🟠 Risk Level: {risk_level}"
        )

    else:

        st.success(
            f"🟢 Risk Level: {risk_level}"
        )

    if risk_reasons:

        st.markdown(
            "### 🧠 Risk Factors"
        )

        for reason in risk_reasons:

            st.write(
                f"• {reason}"
            )

    st.divider()

    # =====================================================
    # TRANSACTION DNA
    # =====================================================

    st.header("🧬 Transaction DNA")

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
            f'{dna.get("average_transfer", 0):.4f} ETH'
        )

    with dna_col3:

        st.metric(
            "Total Volume",
            f'{dna.get("total_volume", 0):.4f} ETH'
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

    # =====================================================
    # FUND FLOW V2
    # =====================================================

    st.header("🌐 Fund Flow Network V2")

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

    net, graph = build_fund_flow_graph(
        transactions[:100],
        wallet_address,
        wallet_hops,
        vasp_results
    )

    # Save temporary HTML
    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".html"
    ) as tmp_file:

        graph_path = tmp_file.name

    net.save_graph(
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

        os.unlink(
            graph_path
        )

    except:

        pass

    st.info(
        f"""
        **Flow interpretation:**

        🔴 Reported wallet → starting point

        🟡 Hop 1 → directly connected wallets

        🟠 Hop 2 → wallets reached through another wallet

        🟣 Hop 3+ → deeper network connections

        🏦 Potential VASP → wallet matching the available registry
        """

    )

    st.write(
        f"**Graph nodes:** {graph.number_of_nodes()}  |  "
        f"**Graph edges:** {graph.number_of_edges()}  |  "
        f"**Transactions displayed:** {min(len(transactions), 100)}"
    )

    st.divider()

    # =====================================================
    # DETECTED PATTERNS
    # =====================================================

    st.header("🧩 Detected Fund-Flow Patterns")

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

    # =====================================================
    # ABNORMAL TRANSACTIONS
    # =====================================================

    st.header("🚨 Abnormal Transaction Analysis")

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

    # =====================================================
    # VASP ASSOCIATION
    # =====================================================

    st.header("🏦 Potential VASP Association")

    if vasp_results:

        vasp_df = pd.DataFrame(
            vasp_results
        )

        st.dataframe(
            vasp_df,
            use_container_width=True,
            hide_index=True
        )

        st.warning(
            "VASP matches are analytical associations based "
            "on the available registry and require independent verification."
        )

    else:

        st.info(
            "No potential VASP association identified."
        )

    st.divider()

    # =====================================================
    # TRANSACTION TABLE
    # =====================================================

    st.header("📋 Transaction Evidence")

    if transactions:

        display_transactions = []

        for tx in transactions[:100]:

            display_transactions.append({
                "Transaction": tx.get(
                    "hash",
                    ""
                ),
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
                "Timestamp": tx.get(
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
                f"Showing 100 of {len(transactions)} transactions."
            )

    else:

        st.info(
            "No transactions available."
        )

    st.divider()

    # =====================================================
    # INVESTIGATION SUMMARY
    # =====================================================

    st.header("📝 Investigation Summary")

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
            f"**Maximum Hop:** {max_hop}"
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

    # =====================================================
    # PDF REPORT
    # =====================================================

    st.header("📄 Investigation Report")

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
                max_hop=max_hop,
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

                st.download_button(
                    label="⬇️ Download Investigation Report",
                    data=file,
                    file_name="CryptoShield_Investigation_Report.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )

        except Exception as e:

            st.error(
                f"PDF generation failed: {e}"
            )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "CryptoShield — Blockchain Fraud Intelligence System | "
    "DINO: Digital Investigation & Network Observatory"
)
