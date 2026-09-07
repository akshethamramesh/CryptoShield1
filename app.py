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
# HEADER
# ============================================================

st.title("🛡️ CryptoShield")

st.subheader(
    "Blockchain Fraud Intelligence System"
)

st.write(
    "Analyze a reported cryptocurrency wallet, trace fund flows, "
    "detect suspicious patterns, identify potential VASP associations, "
    "and generate an investigation report."
)

st.divider()


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.header(
    "⚙️ Investigation Settings"
)

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
# DEMO TRANSACTIONS
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
# HELPER FUNCTIONS
# ============================================================

def format_timestamp(timestamp):

    try:

        if not timestamp:
            return "Unknown"

        return datetime.fromtimestamp(
            int(timestamp)
        ).strftime(
            "%d-%m-%Y %H:%M:%S"
        )

    except:

        return str(timestamp)


def short_address(address):

    address = str(address)

    if len(address) <= 18:
        return address

    return (
        address[:8]
        + "..."
        + address[-6:]
    )


def get_transaction_hop(
    tx,
    wallet_hops,
    start_wallet
):

    sender = str(
        tx.get("from", "")
    ).lower()

    receiver = str(
        tx.get("to", "")
    ).lower()

    start_wallet = str(
        start_wallet
    ).lower()

    if sender in wallet_hops:
        return wallet_hops[sender]

    if receiver in wallet_hops:
        return wallet_hops[receiver]

    if sender == start_wallet:
        return 0

    return "-"


def get_indicator(
    tx,
    abnormal_hashes,
    vasp_addresses,
    wallet_hops
):

    tx_hash = tx.get(
        "hash",
        ""
    )

    sender = str(
        tx.get("from", "")
    ).lower()

    receiver = str(
        tx.get("to", "")
    ).lower()


    if tx_hash in abnormal_hashes:

        return "🚨 Abnormal"


    if (
        sender in vasp_addresses
        or receiver in vasp_addresses
    ):

        return "🏦 VASP"


    sender_hop = wallet_hops.get(
        sender,
        0
    )

    receiver_hop = wallet_hops.get(
        receiver,
        0
    )

    if (
        sender_hop >= 1
        or receiver_hop >= 2
    ):

        return "🔗 Multi-Hop"


    return "Normal"


# ============================================================
# FUND FLOW V2 HELPER
# ============================================================

def get_node_info(
    address,
    wallet_hops,
    start_wallet,
    vasp_addresses
):

    address_lower = str(
        address
    ).lower()

    start_lower = str(
        start_wallet
    ).lower()


    # --------------------------------------------------------
    # Reported wallet
    # --------------------------------------------------------

    if address_lower == start_lower:

        return (
            "🔴",
            "Reported Wallet",
            0
        )


    # --------------------------------------------------------
    # VASP
    # --------------------------------------------------------

    if address_lower in vasp_addresses:

        hop = wallet_hops.get(
            address_lower,
            3
        )

        return (
            "🏦",
            "Potential VASP",
            hop
        )


    # --------------------------------------------------------
    # Normal wallet
    # --------------------------------------------------------

    hop = wallet_hops.get(
        address_lower,
        1
    )


    if hop == 1:

        return (
            "🟡",
            "Hop 1 Wallet",
            hop
        )

    elif hop == 2:

        return (
            "🟠",
            "Hop 2 Wallet",
            hop
        )

    else:

        return (
            "🟣",
            f"Hop {hop} Wallet",
            hop
        )


# ============================================================
# MAIN ANALYSIS
# ============================================================

if analyze_button:

    # ========================================================
    # VALIDATION
    # ========================================================

    if not wallet_address:

        st.warning(
            "⚠️ Please enter a wallet address."
        )

        st.stop()


    # ========================================================
    # DEMO MODE
    # ========================================================

    if wallet_address.upper() == "DEMO":

        st.info(
            "🧪 Demo Suspicious Wallet Mode"
        )

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

        connected_wallets = list(
            set(connected_wallets)
        )

        actual_max_hop = 3

        wallet_hops = {

            "demo_suspect_a": 0,

            "demo_wallet_b": 1,
            "demo_wallet_c": 1,
            "demo_wallet_d": 1,

            "demo_wallet_e": 2,
            "demo_wallet_f": 2,

            "0x1111111111111111111111111111111111111111": 3
        }


    # ========================================================
    # REAL WALLET MODE
    # ========================================================

    else:

        with st.spinner(
            "⛓️ Fetching blockchain transactions..."
        ):

            try:

                result = recursive_trace(
                    wallet_address,
                    chain,
                    max_hop=max_hop
                )

            except Exception as e:

                st.error(
                    f"❌ Blockchain analysis failed: {e}"
                )

                st.stop()


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

        wallet_hops = result.get(
            "wallet_hops",
            result.get(
                "hop_map",
                {}
            )
        )


        if not transactions:

            st.error(
                "❌ No transactions found."
            )

            st.stop()


    # ========================================================
    # NORMALIZE HOP MAP
    # ========================================================

    normalized_wallet_hops = {}

    for address, hop in wallet_hops.items():

        normalized_wallet_hops[
            str(address).lower()
        ] = hop

    wallet_hops = normalized_wallet_hops


    # ========================================================
    # ABNORMAL DETECTION
    # ========================================================

    abnormal_alerts = detect_abnormal_transactions(
        transactions
    )

    abnormal_hashes = set()

    for alert in abnormal_alerts:

        tx_hash = alert.get(
            "hash",
            ""
        )

        abnormal_hashes.add(
            tx_hash
        )


    # ========================================================
    # VASP DETECTION
    # ========================================================

    vasp_results = detect_vasp(
        transactions
    )

    vasp_addresses = set()

    for vasp in vasp_results:

        address = str(
            vasp.get(
                "address",
                ""
            )
        ).lower()

        vasp_addresses.add(
            address
        )


    # ========================================================
    # INVESTIGATION OVERVIEW
    # ========================================================

    st.header(
        "📊 Investigation Overview"
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Transactions",
        len(transactions)
    )

    c2.metric(
        "Connected Wallets",
        len(connected_wallets)
    )

    c3.metric(
        "Maximum Hop",
        actual_max_hop
    )

    c4.metric(
        "Abnormal Alerts",
        len(abnormal_alerts)
    )


    # ========================================================
    # TRANSACTION TIMELINE
    # ========================================================

    st.divider()

    st.header(
        "⏱️ Transaction Timeline"
    )

    st.caption(
        "Chronological reconstruction of observed fund movements."
    )


    timeline_data = []

    for tx in transactions:

        timestamp = tx.get(
            "timeStamp",
            tx.get(
                "timestamp",
                ""
            )
        )

        hop = get_transaction_hop(
            tx,
            wallet_hops,
            wallet_address
        )

        indicator = get_indicator(
            tx,
            abnormal_hashes,
            vasp_addresses,
            wallet_hops
        )


        timeline_data.append({

            "Time":
                format_timestamp(timestamp),

            "From":
                short_address(
                    tx.get(
                        "from",
                        "Unknown"
                    )
                ),

            "To":
                short_address(
                    tx.get(
                        "to",
                        "Unknown"
                    )
                ),

            "Value":
                tx.get(
                    "value",
                    0
                ),

            "Asset":
                tx.get(
                    "asset",
                    "ETH"
                ),

            "Hop":
                hop,

            "Indicator":
                indicator,

            "Transaction":
                short_address(
                    tx.get(
                        "hash",
                        ""
                    )
                )
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

    else:

        st.info(
            "No timeline data available."
        )


    # ========================================================
    # ABNORMAL TRANSACTIONS
    # ========================================================

    st.divider()

    st.header(
        "🚨 Abnormal Transaction Detection"
    )


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
    # VASP ASSOCIATION
    # ========================================================

    st.divider()

    st.header(
        "🏦 Potential VASP Association"
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

    st.header(
        "🧠 Detected Blockchain Patterns"
    )


    patterns = []

    senders = {}
    receivers = {}


    for tx in transactions:

        sender = str(
            tx.get(
                "from",
                ""
            )
        ).lower()

        receiver = str(
            tx.get(
                "to",
                ""
            )
        ).lower()


        senders[sender] = (
            senders.get(
                sender,
                0
            ) + 1
        )

        receivers[receiver] = (
            receivers.get(
                receiver,
                0
            ) + 1
        )


    if any(
        count >= 3
        for count in senders.values()
    ):

        patterns.append(
            "Fund splitting detected."
        )


    if any(
        count >= 3
        for count in receivers.values()
    ):

        patterns.append(
            "Fund consolidation detected."
        )


    if actual_max_hop >= 2:

        patterns.append(
            "Multi-hop fund movement detected."
        )


    if vasp_results:

        patterns.append(
            "Potential VASP association detected."
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
    # EXPLAINABLE RISK SCORE
    # ========================================================

    st.divider()

    st.header(
        "📈 Explainable Risk Assessment"
    )


    risk_factors = []

    risk_score = 0


    # Transaction activity

    if len(transactions) > 100:

        score = 25

    elif len(transactions) > 50:

        score = 15

    else:

        score = 0


    risk_score += score

    risk_factors.append({

        "Factor":
            "Transaction Activity",

        "Score":
            score,

        "Reason":
            f"{len(transactions)} transactions analyzed"
    })


    # Connected wallets

    if len(connected_wallets) > 20:

        score = 25

    elif len(connected_wallets) > 10:

        score = 15

    else:

        score = 0


    risk_score += score

    risk_factors.append({

        "Factor":
            "Connected Wallets",

        "Score":
            score,

        "Reason":
            f"{len(connected_wallets)} connected wallets"
    })


    # Abnormal activity

    if len(abnormal_alerts) > 0:

        score = 20

    else:

        score = 0


    risk_score += score

    risk_factors.append({

        "Factor":
            "Abnormal Transactions",

        "Score":
            score,

        "Reason":
            f"{len(abnormal_alerts)} abnormal alert(s)"
    })


    # Multi-hop

    if actual_max_hop >= 2:

        score = 15

    else:

        score = 0


    risk_score += score

    risk_factors.append({

        "Factor":
            "Multi-Hop Movement",

        "Score":
            score,

        "Reason":
            f"Trace depth: {actual_max_hop} hop(s)"
    })


    # VASP

    if vasp_results:

        score = 15

    else:

        score = 0


    risk_score += score

    risk_factors.append({

        "Factor":
            "Potential VASP Association",

        "Score":
            score,

        "Reason":
            f"{len(vasp_results)} registry match(es)"
    })


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
        "Overall Risk Score",
        f"{risk_score}/100"
    )

    c2.metric(
        "Risk Level",
        risk_level
    )


    st.subheader(
        "🔍 Why this score?"
    )


    risk_df = pd.DataFrame(
        risk_factors
    )

    st.dataframe(
        risk_df,
        use_container_width=True,
        hide_index=True
    )


    # ========================================================
    # FUND FLOW NETWORK V2
    # ========================================================

    st.divider()

    st.header(
        "🕸️ Fund Flow Network V2"
    )

    st.caption(
        "Visual reconstruction of the reported wallet's "
        "observed transaction network."
    )


    # --------------------------------------------------------
    # LEGEND
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # CREATE NETWORK
    # --------------------------------------------------------

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
                "font": {
                    "size": 16
                },
                "borderWidth": 2
            },

            "edges": {
                "arrows": {
                    "to": {
                        "enabled": true,
                        "scaleFactor": 0.7
                    }
                },

                "smooth": {
                    "enabled": true,
                    "type": "dynamic"
                },

                "font": {
                    "size": 11
                }
            },

            "physics": {
                "enabled": true,

                "barnesHut": {
                    "gravitationalConstant": -3000,
                    "centralGravity": 0.2,
                    "springLength": 180,
                    "springConstant": 0.04,
                    "damping": 0.09
                },

                "stabilization": {
                    "enabled": true,
                    "iterations": 200
                }
            },

            "interaction": {
                "hover": true,
                "navigationButtons": true,
                "keyboard": true
            }
        }
        """
    )


    # --------------------------------------------------------
    # ADD NODES + EDGES
    # --------------------------------------------------------

    added_nodes = set()

    max_graph_transactions = 100


    for tx in transactions[:max_graph_transactions]:

        sender = str(
            tx.get(
                "from",
                ""
            )
        ).strip()

        receiver = str(
            tx.get(
                "to",
                ""
            )
        ).strip()


        if not sender or not receiver:

            continue


        sender_color, sender_type, sender_hop = get_node_info(
            sender,
            wallet_hops,
            wallet_address,
            vasp_addresses
        )


        receiver_color, receiver_type, receiver_hop = get_node_info(
            receiver,
            wallet_hops,
            wallet_address,
            vasp_addresses
        )


        # ----------------------------------------------------
        # Sender Node
        # ----------------------------------------------------

        if sender not in added_nodes:

            sender_title = (
                f"<b>{sender_type}</b><br>"
                f"Address: {sender}<br>"
                f"Hop: {sender_hop}"
            )


            net.add_node(

                sender,

                label=(
                    f"{sender_color} "
                    f"{short_address(sender)}"
                ),

                title=sender_title,

                shape="dot",

                size=28 if sender_hop == 0 else 20
            )


            added_nodes.add(
                sender
            )


        # ----------------------------------------------------
        # Receiver Node
        # ----------------------------------------------------

        if receiver not in added_nodes:

            receiver_title = (
                f"<b>{receiver_type}</b><br>"
                f"Address: {receiver}<br>"
                f"Hop: {receiver_hop}"
            )


            net.add_node(

                receiver,

                label=(
                    f"{receiver_color} "
                    f"{short_address(receiver)}"
                ),

                title=receiver_title,

                shape="dot",

                size=28 if receiver_hop == 0 else 20
            )


            added_nodes.add(
                receiver
            )


        # ----------------------------------------------------
        # EDGE
        # ----------------------------------------------------

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


        edge_title = (
            f"<b>Fund Transfer</b><br>"
            f"Value: {value} {asset}<br>"
            f"Transaction: {tx_hash}"
        )


        net.add_edge(

            sender,

            receiver,

            title=edge_title,

            label=f"{value} {asset}",

            arrows="to"
        )


    # --------------------------------------------------------
    # RENDER GRAPH
    # --------------------------------------------------------

    if added_nodes:

        graph_path = None


        try:

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".html"
            ) as temp_graph:

                graph_path = temp_graph.name


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
                height=680,
                scrolling=True
            )


        except Exception as e:

            st.error(
                f"Fund flow graph failed: {e}"
            )


        finally:

            if (
                graph_path
                and os.path.exists(graph_path)
            ):

                os.remove(
                    graph_path
                )


    else:

        st.info(
            "No transaction relationships available "
            "to build the graph."
        )


    # ========================================================
    # FLOW INTERPRETATION
    # ========================================================

    st.subheader(
        "🔎 Flow Interpretation"
    )


    st.write(
        f"""
The reported wallet is treated as **Hop 0**.
Connected wallets are progressively mapped as **Hop 1, Hop 2,
and Hop 3+** based on the available trace results.

The graph currently contains **{len(added_nodes)} observed nodes**
and up to **{min(len(transactions), max_graph_transactions)} displayed transactions**.
"""
    )


    # ========================================================
    # INVESTIGATION SUMMARY
    # ========================================================

    st.divider()

    st.header(
        "📝 Investigation Summary"
    )


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

    st.header(
        "📄 Investigation Report"
    )


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

            label=(
                "📥 Download Investigation "
                "Report PDF"
            ),

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

        if (
            pdf_path
            and os.path.exists(pdf_path)
        ):

            os.remove(
                pdf_path
            )
