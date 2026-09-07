import os
import tempfile
from collections import Counter

import streamlit as st
import pandas as pd

from blockchain import trace_wallet
from transaction_dna import analyze_transaction_dna
from abnormal_detection import detect_abnormal_transactions
from vasp_detection import detect_vasp
from risk_engine import calculate_risk_v3
from report_generator import generate_pdf_report


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
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
        margin-bottom: 0;
    }

    .subtitle {
        font-size: 18px;
        opacity: 0.75;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 25px;
        font-weight: 700;
        margin-top: 25px;
        margin-bottom: 12px;
    }

    .risk-high {
        padding: 18px;
        border-radius: 12px;
        border: 2px solid #ff4b4b;
        background: rgba(255, 75, 75, 0.10);
    }

    .risk-medium {
        padding: 18px;
        border-radius: 12px;
        border: 2px solid #ffa500;
        background: rgba(255, 165, 0, 0.10);
    }

    .risk-low {
        padding: 18px;
        border-radius: 12px;
        border: 2px solid #21c354;
        background: rgba(33, 195, 84, 0.10);
    }

    .small-note {
        font-size: 13px;
        opacity: 0.7;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SESSION STATE
# ============================================================

if "analysis_done" not in st.session_state:
    st.session_state.analysis_done = False

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

if "dna_result" not in st.session_state:
    st.session_state.dna_result = None

if "abnormal_alerts" not in st.session_state:
    st.session_state.abnormal_alerts = []

if "vasp_results" not in st.session_state:
    st.session_state.vasp_results = []

if "risk_score" not in st.session_state:
    st.session_state.risk_score = 0

if "risk_level" not in st.session_state:
    st.session_state.risk_level = "LOW"

if "risk_factors" not in st.session_state:
    st.session_state.risk_factors = []


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def detect_patterns(
    transactions,
    dna,
    max_hop
):
    """
    Detect high-level fund-flow patterns.
    """

    patterns = []

    fan_in = dna.get("fan_in", 0)
    fan_out = dna.get("fan_out", 0)
    rapid_movements = dna.get(
        "rapid_movements",
        0
    )

    if fan_out >= 5:
        patterns.append(
            "Fund splitting / high fan-out behavior detected"
        )

    if fan_in >= 5:
        patterns.append(
            "Fund consolidation / high fan-in behavior detected"
        )

    if max_hop >= 2:
        patterns.append(
            "Multi-hop fund movement detected"
        )

    if rapid_movements >= 5:
        patterns.append(
            "Rapid fund movement detected"
        )

    if len(transactions) >= 100:
        patterns.append(
            "High transaction activity detected"
        )

    token_transactions = sum(
        1
        for tx in transactions
        if tx.get("type") == "token"
    )

    if token_transactions > 0:
        patterns.append(
            "Token transfer activity detected"
        )

    return patterns


def get_node_info(
    address,
    start_wallet,
    hop_map,
    vasp_addresses
):
    """
    Return graph node styling information.
    """

    address_lower = address.lower()
    start_lower = start_wallet.lower()

    if address_lower == start_lower:
        return {
            "color": "red",
            "size": 30,
            "title": "Reported Suspect Wallet"
        }

    if address_lower in vasp_addresses:
        return {
            "color": "purple",
            "size": 25,
            "title": "Potential VASP / Exchange"
        }

    hop = hop_map.get(
        address_lower,
        0
    )

    if hop == 1:
        return {
            "color": "yellow",
            "size": 22,
            "title": "Hop 1 Wallet"
        }

    if hop == 2:
        return {
            "color": "orange",
            "size": 20,
            "title": "Hop 2 Wallet"
        }

    if hop >= 3:
        return {
            "color": "purple",
            "size": 18,
            "title": f"Hop {hop} Wallet"
        }

    return {
        "color": "gray",
        "size": 15,
        "title": "Connected Wallet"
    }


def build_fund_flow_graph(
    transactions,
    start_wallet,
    hop_map,
    vasp_results
):
    """
    Build interactive PyVis graph.
    """

    try:
        from pyvis.network import Network
    except ImportError:
        st.warning(
            "PyVis is not installed. Run: pip install pyvis"
        )
        return None

    net = Network(
        height="650px",
        width="100%",
        directed=True,
        bgcolor="#111111",
        font_color="white"
    )

    net.barnes_hut(
        gravity=-25000,
        central_gravity=0.2,
        spring_length=150,
        spring_strength=0.03
    )

    vasp_addresses = {
        item.get("address", "").lower()
        for item in vasp_results
    }

    added_nodes = set()

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

        # ----------------------------------------------------
        # SENDER
        # ----------------------------------------------------

        if sender not in added_nodes:

            info = get_node_info(
                sender,
                start_wallet,
                hop_map,
                vasp_addresses
            )

            net.add_node(
                sender,
                label=sender[:10] + "...",
                color=info["color"],
                size=info["size"],
                title=(
                    f"{info['title']}<br>"
                    f"Address: {sender}"
                )
            )

            added_nodes.add(sender)

        # ----------------------------------------------------
        # RECEIVER
        # ----------------------------------------------------

        if receiver not in added_nodes:

            info = get_node_info(
                receiver,
                start_wallet,
                hop_map,
                vasp_addresses
            )

            net.add_node(
                receiver,
                label=receiver[:10] + "...",
                color=info["color"],
                size=info["size"],
                title=(
                    f"{info['title']}<br>"
                    f"Address: {receiver}"
                )
            )

            added_nodes.add(receiver)

        # ----------------------------------------------------
        # EDGE
        # ----------------------------------------------------

        asset = tx.get(
            "asset",
            "ETH"
        )

        value = tx.get(
            "value",
            0
        )

        tx_type = tx.get(
            "type",
            "native"
        )

        tx_hash = tx.get(
            "hash",
            ""
        )

        edge_title = (
            f"Asset: {asset}<br>"
            f"Value: {value}<br>"
            f"Type: {tx_type}<br>"
            f"TX: {tx_hash}"
        )

        net.add_edge(
            sender,
            receiver,
            title=edge_title,
            arrows="to"
        )

    # --------------------------------------------------------
    # SAVE HTML
    # --------------------------------------------------------

    temp_dir = tempfile.mkdtemp()

    graph_path = os.path.join(
        temp_dir,
        "fund_flow_graph.html"
    )

    net.save_graph(
        graph_path
    )

    return graph_path


def format_address(address):
    if not address:
        return "Unknown"

    if len(address) <= 18:
        return address

    return (
        address[:10]
        + "..."
        + address[-8:]
    )


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title(
    "🛡️ CryptoShield"
)

st.sidebar.markdown(
    "### Blockchain Fraud Intelligence"
)

st.sidebar.markdown(
    """
    Enter a **reported suspect wallet address**
    and CryptoShield will perform blockchain analysis.
    """
)

wallet_address = st.sidebar.text_input(
    "Reported Suspect Wallet Address",
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
    "Maximum Investigation Hops",
    min_value=1,
    max_value=3,
    value=2
)

start_investigation = st.sidebar.button(
    "🔍 Start Investigation",
    use_container_width=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ CRYPTO SHIELD</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Blockchain Fraud Intelligence System'
    '</div>',
    unsafe_allow_html=True
)

st.info(
    "CryptoShield analyzes a victim-reported suspect wallet. "
    "It traces blockchain fund flows, detects suspicious "
    "behavioral patterns, identifies potential VASP associations, "
    "and generates an explainable analytical risk assessment."
)

st.warning(
    "⚠️ Analytical intelligence only. "
    "A risk score does not prove criminal activity or identify "
    "a person as guilty."
)


# ============================================================
# INVESTIGATION
# ============================================================

if start_investigation:

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

    # --------------------------------------------------------
    # START
    # --------------------------------------------------------

    with st.spinner(
        "Collecting blockchain transactions..."
    ):

        try:

            result = trace_wallet(
                wallet_address,
                chain,
                max_hop
            )

        except Exception as e:

            st.error(
                f"Blockchain analysis failed: {e}"
            )

            st.stop()

    transactions = result.get(
        "transactions",
        []
    )

    connected_wallets = result.get(
        "visited_wallets",
        result.get(
            "wallets",
            []
        )
    )

    hop_map = result.get(
        "hop_map",
        {}
    )

    native_transactions = result.get(
        "native_transactions",
        []
    )

    token_transactions = result.get(
        "token_transactions",
        []
    )

    token_count = result.get(
        "token_count",
        len(token_transactions)
    )

    native_count = result.get(
        "native_count",
        len(native_transactions)
    )

    token_types = result.get(
        "token_types",
        []
    )

    # --------------------------------------------------------
    # TRANSACTION DNA
    # --------------------------------------------------------

    dna_result = analyze_transaction_dna(
        transactions,
        wallet_address
    )

    # --------------------------------------------------------
    # ABNORMAL TRANSACTIONS
    # --------------------------------------------------------

    abnormal_alerts = detect_abnormal_transactions(
        transactions
    )

    # --------------------------------------------------------
    # VASP DETECTION
    # --------------------------------------------------------

    vasp_results = detect_vasp(
        transactions
    )

    # --------------------------------------------------------
    # RISK ENGINE V3
    # --------------------------------------------------------

    risk_score, risk_level, risk_factors = (
        calculate_risk_v3(

            transaction_count=len(
                transactions
            ),

            connected_wallets=len(
                connected_wallets
            ),

            rapid_movements=dna_result.get(
                "rapid_movements",
                0
            ),

            abnormal_alerts=len(
                abnormal_alerts
            ),

            fan_in=dna_result.get(
                "fan_in",
                0
            ),

            fan_out=dna_result.get(
                "fan_out",
                0
            ),

            max_hop=result.get(
                "max_hop",
                max_hop
            ),

            vasp_matches=len(
                vasp_results
            ),

            token_transactions=token_count,

            token_types=len(
                token_types
            )
        )
    )

    # --------------------------------------------------------
    # PATTERNS
    # --------------------------------------------------------

    patterns = detect_patterns(
        transactions,
        dna_result,
        result.get(
            "max_hop",
            max_hop
        )
    )

    # --------------------------------------------------------
    # SAVE SESSION
    # --------------------------------------------------------

    st.session_state.analysis_done = True

    st.session_state.analysis_result = result

    st.session_state.dna_result = dna_result

    st.session_state.abnormal_alerts = abnormal_alerts

    st.session_state.vasp_results = vasp_results

    st.session_state.risk_score = risk_score

    st.session_state.risk_level = risk_level

    st.session_state.risk_factors = risk_factors

    st.session_state.patterns = patterns

    st.success(
        "Blockchain investigation completed."
    )


# ============================================================
# DISPLAY RESULTS
# ============================================================

if st.session_state.analysis_done:

    result = st.session_state.analysis_result

    dna_result = st.session_state.dna_result

    abnormal_alerts = st.session_state.abnormal_alerts

    vasp_results = st.session_state.vasp_results

    risk_score = st.session_state.risk_score

    risk_level = st.session_state.risk_level

    risk_factors = st.session_state.risk_factors

    patterns = st.session_state.get(
        "patterns",
        []
    )

    transactions = result.get(
        "transactions",
        []
    )

    connected_wallets = result.get(
        "visited_wallets",
        result.get(
            "wallets",
            []
        )
    )

    max_hop_result = result.get(
        "max_hop",
        max_hop
    )

    token_transactions = result.get(
        "token_transactions",
        []
    )

    native_transactions = result.get(
        "native_transactions",
        []
    )

    token_count = result.get(
        "token_count",
        len(token_transactions)
    )

    native_count = result.get(
        "native_count",
        len(native_transactions)
    )

    token_types = result.get(
        "token_types",
        []
    )

    hop_map = result.get(
        "hop_map",
        {}
    )

    # ========================================================
    # 1. INVESTIGATION OVERVIEW
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '1️⃣ Investigation Overview'
        '</div>',
        unsafe_allow_html=True
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
            len(connected_wallets)
        )

    with col4:
        st.metric(
            "Maximum Hop",
            max_hop_result
        )

    st.code(
        wallet_address,
        language=None
    )


    # ========================================================
    # 2. RISK STATUS
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '2️⃣ Risk Status'
        '</div>',
        unsafe_allow_html=True
    )

    if risk_level == "HIGH":

        st.markdown(
            f"""
            <div class="risk-high">

            <h2>🔴 HIGH RISK</h2>

            <h1>{risk_score}/100</h1>

            Multiple blockchain behavior indicators
            require further investigation.

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

            Several analytical indicators were detected.

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

            Limited predefined risk indicators were detected.

            </div>
            """,
            unsafe_allow_html=True
        )


    # ========================================================
    # 3. EXPLAINABLE RISK ASSESSMENT
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '3️⃣ Explainable Risk Assessment'
        '</div>',
        unsafe_allow_html=True
    )

    if risk_factors:

        factor_data = []

        for factor in risk_factors:

            factor_data.append(
                {
                    "Risk Indicator":
                        factor.get(
                            "indicator",
                            "Unknown"
                        ),

                    "Contribution":
                        factor.get(
                            "points",
                            0
                        )
                }
            )

        factor_df = pd.DataFrame(
            factor_data
        )

        st.dataframe(
            factor_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No major predefined risk indicators detected."
        )


    # ========================================================
    # 4. TOKEN TRANSFER INTELLIGENCE
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '4️⃣ Token Transfer Intelligence'
        '</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Native Transactions",
            native_count
        )

    with col2:

        st.metric(
            "Token Transfers",
            token_count
        )

    with col3:

        st.metric(
            "Token Types",
            len(token_types)
        )

    if token_types:

        st.write(
            "**Detected Token Types:**"
        )

        token_type_df = pd.DataFrame(
            {
                "Token": token_types
            }
        )

        st.dataframe(
            token_type_df,
            use_container_width=True,
            hide_index=True
        )

    if token_transactions:

        st.write(
            "**Token Transfer Evidence**"
        )

        token_rows = []

        for tx in token_transactions[:100]:

            token_rows.append(
                {
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

                    "TX Hash":
                        format_address(
                            tx.get(
                                "hash",
                                ""
                            )
                        )
                }
            )

        token_df = pd.DataFrame(
            token_rows
        )

        st.dataframe(
            token_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No token transfers were detected "
            "for the analyzed wallet network."
        )

    st.caption(
        "Token transfer amounts are kept separate from native "
        "ETH/BNB volume because different tokens use different "
        "units and decimals."
    )


    # ========================================================
    # 5. TRANSACTION DNA
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '5️⃣ Transaction DNA'
        '</div>',
        unsafe_allow_html=True
    )

    native_asset = (
        "BNB"
        if chain == "BSC"
        else "ETH"
    )

    dna_col1, dna_col2, dna_col3, dna_col4 = st.columns(4)

    with dna_col1:

        st.metric(
            "Transaction Count",
            dna_result.get(
                "transaction_count",
                0
            )
        )

    with dna_col2:

        st.metric(
            "Unique Senders",
            dna_result.get(
                "unique_senders",
                0
            )
        )

    with dna_col3:

        st.metric(
            "Unique Receivers",
            dna_result.get(
                "unique_receivers",
                0
            )
        )

    with dna_col4:

        st.metric(
            "Rapid Movements",
            dna_result.get(
                "rapid_movements",
                0
            )
        )

    dna_col5, dna_col6, dna_col7 = st.columns(3)

    with dna_col5:

        st.metric(
            "Fan-In",
            dna_result.get(
                "fan_in",
                0
            )
        )

    with dna_col6:

        st.metric(
            "Fan-Out",
            dna_result.get(
                "fan_out",
                0
            )
        )

    with dna_col7:

        st.metric(
            f"Native {native_asset} Volume",
            round(
                dna_result.get(
                    "total_volume",
                    0
                ),
                4
            )
        )

    if dna_result.get(
        "behavior_indicators"
    ):

        st.write(
            "**Behavioral Indicators**"
        )

        for indicator in dna_result[
            "behavior_indicators"
        ]:

            st.warning(
                indicator
            )


    # ========================================================
    # 6. FUND FLOW NETWORK
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '6️⃣ Fund Flow Network'
        '</div>',
        unsafe_allow_html=True
    )

    graph_path = build_fund_flow_graph(
        transactions,
        wallet_address,
        hop_map,
        vasp_results
    )

    if graph_path:

        try:

            with open(
                graph_path,
                "r",
                encoding="utf-8"
            ) as graph_file:

                graph_html = graph_file.read()

            st.components.v1.html(
                graph_html,
                height=680,
                scrolling=True
            )

        except Exception as e:

            st.error(
                f"Unable to display graph: {e}"
            )


    # ========================================================
    # 7. DETECTED PATTERNS
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '7️⃣ Detected Fund-Flow Patterns'
        '</div>',
        unsafe_allow_html=True
    )

    if patterns:

        for pattern in patterns:

            st.info(
                f"🔎 {pattern}"
            )

    else:

        st.success(
            "No major predefined fund-flow patterns detected."
        )


    # ========================================================
    # 8. ABNORMAL TRANSACTIONS
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '8️⃣ Abnormal Transaction Analysis'
        '</div>',
        unsafe_allow_html=True
    )

    st.metric(
        "Abnormal Indicators",
        len(abnormal_alerts)
    )

    if abnormal_alerts:

        abnormal_rows = []

        for alert in abnormal_alerts[:100]:

            abnormal_rows.append(
                {
                    "Transaction":
                        format_address(
                            alert.get(
                                "hash",
                                ""
                            )
                        ),

                    "Score":
                        alert.get(
                            "score",
                            0
                        ),

                    "Reason":
                        alert.get(
                            "reason",
                            "Unknown"
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
            "No abnormal transaction indicators detected."
        )


    # ========================================================
    # 9. VASP ASSOCIATION
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '9️⃣ Potential VASP / Exchange Association'
        '</div>',
        unsafe_allow_html=True
    )

    if vasp_results:

        st.warning(
            "Potential association detected. "
            "This does NOT prove wallet ownership."
        )

        vasp_rows = []

        for vasp in vasp_results:

            vasp_rows.append(
                {
                    "Name":
                        vasp.get(
                            "name",
                            "Unknown"
                        ),

                    "Type":
                        vasp.get(
                            "type",
                            "Unknown"
                        ),

                    "Country":
                        vasp.get(
                            "country",
                            "Unknown"
                        ),

                    "Address":
                        format_address(
                            vasp.get(
                                "address",
                                ""
                            )
                        ),

                    "Confidence":
                        vasp.get(
                            "confidence",
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
            "No potential VASP association "
            "was identified in the current registry."
        )


    # ========================================================
    # 10. TRANSACTION EVIDENCE
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '🔟 Transaction Evidence'
        '</div>',
        unsafe_allow_html=True
    )

    if transactions:

        evidence_rows = []

        for tx in transactions[:200]:

            evidence_rows.append(
                {
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
                            "ETH"
                        ),

                    "Value":
                        tx.get(
                            "value",
                            0
                        ),

                    "Type":
                        tx.get(
                            "type",
                            "native"
                        ),

                    "Transaction":
                        format_address(
                            tx.get(
                                "hash",
                                ""
                            )
                        )
                }
            )

        evidence_df = pd.DataFrame(
            evidence_rows
        )

        st.dataframe(
            evidence_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No transactions available."
        )


    # ========================================================
    # 11. INVESTIGATION SUMMARY
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '1️⃣1️⃣ Investigation Summary'
        '</div>',
        unsafe_allow_html=True
    )

    st.write(
        f"""
        CryptoShield analyzed the reported wallet on the
        **{chain} blockchain**.

        **Transactions analyzed:** {len(transactions)}

        **Connected wallets:** {len(connected_wallets)}

        **Maximum investigation depth:** {max_hop_result} hops

        **Native transactions:** {native_count}

        **Token transfers:** {token_count}

        **Token types detected:** {len(token_types)}

        **Potential VASP associations:** {len(vasp_results)}

        **Abnormal transaction indicators:** {len(abnormal_alerts)}

        **Analytical risk score:** {risk_score}/100

        **Risk level:** {risk_level}
        """
    )


    # ========================================================
    # 12. PDF REPORT
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '1️⃣2️⃣ Investigation Report'
        '</div>',
        unsafe_allow_html=True
    )

    if st.button(
        "📄 Generate PDF Report",
        use_container_width=True
    ):

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

                max_hop=max_hop_result,

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

                pdf_bytes = pdf_file.read()

            st.download_button(
                label="⬇️ Download Investigation Report",
                data=pdf_bytes,
                file_name="CryptoShield_Investigation_Report.pdf",
                mime="application/pdf",
                use_container_width=True
            )

        except Exception as e:

            st.error(
                f"PDF generation failed: {e}"
            )


    # ========================================================
    # 13. DISCLAIMER
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '⚠️ Disclaimer'
        '</div>',
        unsafe_allow_html=True
    )

    st.caption(
        """
        CryptoShield provides blockchain analytics and
        investigation intelligence. Risk scores, behavioral
        indicators, transaction patterns, and VASP associations
        are analytical outputs and should not be treated as
        definitive proof of fraud, criminal activity, identity,
        ownership, or guilt. Independent investigation and
        verification are required.
        """
    )


# ============================================================
# EMPTY STATE
# ============================================================

else:

    st.markdown(
        "### 🚀 Start an investigation"
    )

    st.write(
        """
        Enter a **reported suspect wallet address** in the
        sidebar and click **Start Investigation**.

        CryptoShield will:

        1. 🔗 Collect blockchain transactions
        2. 🧭 Trace connected wallets
        3. 🕸️ Reconstruct multi-hop fund flow
        4. 🪙 Analyze token transfers
        5. 🧬 Build transaction behavioral DNA
        6. 🚨 Detect abnormal activity
        7. 🏦 Identify potential VASP associations
        8. 📊 Calculate an explainable risk score
        9. 📄 Generate an investigation report
        """
    )

    st.info(
        "Demo flow: Reported Wallet → Blockchain Data → "
        "Multi-Hop Tracing → Pattern Detection → "
        "Risk Assessment → Investigation Intelligence"
    )
