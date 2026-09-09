import streamlit as st
import pandas as pd
from pathlib import Path
import os
import html

# ============================================================
# CRYPTOSHIELD MODULES
# ============================================================

from blockchain import trace_wallet

from transaction_dna import (
    analyze_transaction_dna
)

from abnormal_detection import (
    detect_abnormal_transactions
)

from vasp_detection import (
    detect_vasp
)

from report_generator import (
    generate_pdf_report
)

from case_store import (
    init_database,
    save_case,
    get_all_cases
)

from convergence_detection import (
    detect_cross_case_convergence
)


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
# DATABASE INITIALIZATION
# ============================================================

init_database()


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
        color: #777;
        margin-bottom: 25px;
    }

    .risk-high {
        padding: 18px;
        border-radius: 12px;
        border: 2px solid #ff4b4b;
        background-color: rgba(255, 75, 75, 0.08);
    }

    .risk-medium {
        padding: 18px;
        border-radius: 12px;
        border: 2px solid #ffa500;
        background-color: rgba(255, 165, 0, 0.08);
    }

    .risk-low {
        padding: 18px;
        border-radius: 12px;
        border: 2px solid #21c354;
        background-color: rgba(33, 195, 84, 0.08);
    }

    .case-box {
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #555;
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
    '<div class="main-title">🛡️ CryptoShield</div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="subtitle">
    Blockchain Fraud Intelligence & Cross-Case Investigation Platform
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("🔎 Investigation")

    blockchain = st.selectbox(
        "Select Blockchain",
        [
            "Ethereum",
            "BSC"
        ]
    )

    reported_wallet = st.text_input(
        "Victim-Reported Suspect Wallet",
        placeholder="0x..."
    )

    max_hops = st.slider(
        "Maximum Tracing Hops",
        min_value=1,
        max_value=2,
        value=2
    )

    st.caption(
        "Fast investigation mode: traces the reported wallet "
        "and the most relevant connected wallets."
    )

    analyze_button = st.button(
        "🚀 Analyze Wallet",
        use_container_width=True,
        type="primary"
    )

    st.divider()

    st.header("📁 Case Database")

    try:

        total_cases = len(
            get_all_cases()
        )

    except Exception:

        total_cases = 0

    st.metric(
        "Stored Investigation Cases",
        total_cases
    )


# ============================================================
# VALIDATE WALLET
# ============================================================

def valid_wallet(address):

    if not address:
        return False

    address = address.strip()

    return (
        address.startswith("0x")
        and len(address) == 42
    )


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk(
    transaction_count,
    connected_wallets,
    rapid_movements,
    abnormal_count,
    pattern_count
):

    score = 0

    if transaction_count >= 100:
        score += 20

    elif transaction_count >= 50:
        score += 10

    if connected_wallets >= 20:
        score += 20

    elif connected_wallets >= 10:
        score += 10

    if rapid_movements >= 5:
        score += 20

    elif rapid_movements >= 2:
        score += 10

    if abnormal_count >= 5:
        score += 20

    elif abnormal_count >= 2:
        score += 10

    if pattern_count >= 3:
        score += 20

    elif pattern_count >= 1:
        score += 10

    score = min(
        score,
        100
    )

    if score >= 70:

        level = "HIGH"

    elif score >= 40:

        level = "MEDIUM"

    else:

        level = "LOW"

    return score, level


# ============================================================
# PATTERN DETECTION
# ============================================================

def detect_patterns(
    transactions,
    start_wallet,
    max_hop
):

    patterns = []

    start_wallet = (
        start_wallet.lower()
    )

    incoming = 0
    outgoing = 0

    destinations = set()
    sources = set()

    hop_values = set()

    for tx in transactions:

        sender = (
            tx.get("from", "")
            .lower()
        )

        receiver = (
            tx.get("to", "")
            .lower()
        )

        if sender == start_wallet:

            outgoing += 1

            if receiver:

                destinations.add(
                    receiver
                )

        if receiver == start_wallet:

            incoming += 1

            if sender:

                sources.add(
                    sender
                )

        try:

            hop = int(
                tx.get(
                    "hop",
                    0
                )
            )

            hop_values.add(hop)

        except Exception:

            pass

    # --------------------------------------------------------
    # Fund splitting
    # --------------------------------------------------------

    if len(destinations) >= 5:

        patterns.append(
            "Fund splitting / high fan-out"
        )

    # --------------------------------------------------------
    # Fund consolidation
    # --------------------------------------------------------

    if len(sources) >= 5:

        patterns.append(
            "Fund consolidation / high fan-in"
        )

    # --------------------------------------------------------
    # Multi-hop movement
    # --------------------------------------------------------

    if max_hop >= 2 and len(hop_values) > 1:

        patterns.append(
            "Multi-hop fund movement"
        )

    # --------------------------------------------------------
    # High activity
    # --------------------------------------------------------

    if len(transactions) >= 100:

        patterns.append(
            "High transaction activity"
        )

    # --------------------------------------------------------
    # Rapid movement
    # --------------------------------------------------------

    timestamps = []

    for tx in transactions:

        try:

            timestamp = int(
                tx.get(
                    "timeStamp",
                    0
                )
            )

            if timestamp:

                timestamps.append(
                    timestamp
                )

        except Exception:

            pass

    timestamps.sort()

    rapid_count = 0

    for i in range(
        1,
        len(timestamps)
    ):

        if (
            0
            <
            timestamps[i]
            -
            timestamps[i - 1]
            <=
            300
        ):

            rapid_count += 1

    if rapid_count >= 5:

        patterns.append(
            "Rapid fund movement"
        )

    return list(
        dict.fromkeys(patterns)
    )


# ============================================================
# DESTINATION EXTRACTION
# ============================================================

def extract_final_destinations(
    transactions,
    reported_wallet
):

    reported_wallet = (
        reported_wallet.lower()
    )

    deepest_hop = 0

    for tx in transactions:

        try:

            hop = int(
                tx.get(
                    "hop",
                    0
                )
            )

            deepest_hop = max(
                deepest_hop,
                hop
            )

        except Exception:

            pass

    destinations = []

    for tx in transactions:

        try:

            hop = int(
                tx.get(
                    "hop",
                    0
                )
            )

        except Exception:

            hop = 0

        receiver = (
            tx.get(
                "to",
                ""
            )
            .lower()
        )

        if (
            receiver
            and receiver != reported_wallet
        ):

            # Prefer deepest-hop destinations
            if hop == deepest_hop:

                destinations.append(
                    receiver
                )

    # If no deepest-hop destination,
    # fall back to all receivers
    if not destinations:

        for tx in transactions:

            receiver = (
                tx.get(
                    "to",
                    ""
                )
                .lower()
            )

            if (
                receiver
                and receiver != reported_wallet
            ):

                destinations.append(
                    receiver
                )

    return list(
        dict.fromkeys(
            destinations
        )
    )


# ============================================================
# GRAPH
# ============================================================

def create_graph(
    connections,
    reported_wallet
):

    try:

        from pyvis.network import Network

    except ImportError:

        st.warning(
            "PyVis is not installed. "
            "Run: pip install pyvis"
        )

        return None

    net = Network(
        height="650px",
        width="100%",
        bgcolor="#ffffff",
        font_color="#222222",
        directed=True
    )

    net.set_options(
        """
        {
          "nodes": {
            "shape": "dot",
            "size": 18,
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
              "size": 11,
              "align": "middle"
            }
          },
          "physics": {
            "enabled": true,
            "stabilization": {
              "iterations": 100
            }
          }
        }
        """
    )

    reported_wallet = (
        reported_wallet.lower()
    )

    nodes_added = set()

    for connection in connections:

        source = (
            connection.get(
                "from",
                ""
            )
            .lower()
        )

        target = (
            connection.get(
                "to",
                ""
            )
            .lower()
        )

        hop = connection.get(
            "hop",
            1
        )

        if not source or not target:

            continue

        # ----------------------------------------------------
        # Source node
        # ----------------------------------------------------

        if source not in nodes_added:

            if source == reported_wallet:

                label = (
                    "🚨 REPORTED WALLET"
                )

            else:

                label = (
                    source[:8]
                    + "..."
                    + source[-6:]
                )

            net.add_node(
                source,
                label=label,
                title=(
                    f"Wallet: {source}<br>"
                    f"Hop: {max(hop - 1, 0)}"
                )
            )

            nodes_added.add(
                source
            )

        # ----------------------------------------------------
        # Target node
        # ----------------------------------------------------

        if target not in nodes_added:

            label = (
                target[:8]
                + "..."
                + target[-6:]
            )

            net.add_node(
                target,
                label=label,
                title=(
                    f"Wallet: {target}<br>"
                    f"Hop: {hop}"
                )
            )

            nodes_added.add(
                target
            )

        # ----------------------------------------------------
        # Edge
        # ----------------------------------------------------

        net.add_edge(
            source,
            target,
            label=f"Hop {hop}",
            title=(
                f"Fund flow connection<br>"
                f"Tracing Hop: {hop}"
            )
        )

    # --------------------------------------------------------
    # Save graph
    # --------------------------------------------------------

    graph_path = (
        Path(__file__).resolve().parent
        / "cryptoshield_graph.html"
    )

    net.save_graph(
        str(graph_path)
    )

    return graph_path


# ============================================================
# MAIN ANALYSIS
# ============================================================

if analyze_button:

    # --------------------------------------------------------
    # Validate input
    # --------------------------------------------------------

    if not valid_wallet(
        reported_wallet
    ):

        st.error(
            "Please enter a valid Ethereum/BSC wallet address."
        )

        st.stop()

    reported_wallet = (
        reported_wallet.strip()
    )

    # --------------------------------------------------------
    # Start analysis
    # --------------------------------------------------------

    with st.spinner(
        "🔍 Tracing blockchain fund flow..."
    ):

        try:

            trace_result = trace_wallet(
                reported_wallet,
                chain=blockchain,
                max_hop=max_hops
            )

        except Exception as e:

            st.error(
                f"Blockchain tracing failed: {e}"
            )

            st.stop()

    # --------------------------------------------------------
    # Extract tracing results
    # --------------------------------------------------------

    transactions = (
        trace_result.get(
            "transactions",
            []
        )
    )

    connected_wallets = (
        trace_result.get(
            "connected_wallets",
            []
        )
    )

    connections = (
        trace_result.get(
            "connections",
            []
        )
    )

    # --------------------------------------------------------
    # Transaction DNA
    # --------------------------------------------------------

    transaction_dna = (
        analyze_transaction_dna(
            transactions,
            reported_wallet
        )
    )

    # --------------------------------------------------------
    # Abnormal transactions
    # --------------------------------------------------------

    abnormal_alerts = (
        detect_abnormal_transactions(
            transactions
        )
    )

    # --------------------------------------------------------
    # VASP detection
    # --------------------------------------------------------

    vasp_results = (
        detect_vasp(
            transactions
        )
    )

    # --------------------------------------------------------
    # Pattern detection
    # --------------------------------------------------------

    patterns = detect_patterns(
        transactions,
        reported_wallet,
        max_hops
    )

    # --------------------------------------------------------
    # Risk score
    # --------------------------------------------------------

    risk_score, risk_level = (
        calculate_risk(

            transaction_count=len(
                transactions
            ),

            connected_wallets=len(
                connected_wallets
            ),

            rapid_movements=
                transaction_dna.get(
                    "rapid_movements",
                    0
                ),

            abnormal_count=len(
                abnormal_alerts
            ),

            pattern_count=len(
                patterns
            )
        )
    )

    # --------------------------------------------------------
    # Final destinations
    # --------------------------------------------------------

    final_destinations = (
        extract_final_destinations(
            transactions,
            reported_wallet
        )
    )

    # ========================================================
    # CROSS-CASE CONVERGENCE
    # ========================================================

    previous_cases = (
        get_all_cases()
    )

    current_case_preview = {

        "case_id": "CURRENT",

        "wallet_address":
            reported_wallet,

        "final_destinations":
            final_destinations,

        "important_wallets":
            connected_wallets
    }

    convergence_alerts = (
        detect_cross_case_convergence(
            current_case_preview,
            previous_cases
        )
    )

    # ========================================================
    # SAVE CASE
    # ========================================================

    native_volume = (
        transaction_dna.get(
            "native_volume",
            0
        )
    )

    case_id = save_case(

        wallet_address=
            reported_wallet,

        chain=
            blockchain,

        traced_value=
            native_volume,

        risk_score=
            risk_score,

        risk_level=
            risk_level,

        max_hop=
            max_hops,

        final_destinations=
            final_destinations,

        important_wallets=
            connected_wallets,

        hop_paths=
            connections
    )

    # ========================================================
    # STORE RESULTS IN SESSION
    # ========================================================

    st.session_state[
        "last_case_id"
    ] = case_id

    st.session_state[
        "last_wallet"
    ] = reported_wallet

    st.session_state[
        "last_trace"
    ] = trace_result

    # ========================================================
    # CASE HEADER
    # ========================================================

    st.success(
        f"✅ Investigation Case Created: {case_id}"
    )

    st.caption(
        "The reported wallet is treated as an investigation "
        "input. Risk indicators do not constitute a criminal verdict."
    )

    # ========================================================
    # CROSS-CASE ALERT
    # ========================================================

    if convergence_alerts:

        st.error(
            "🚨 CROSS-CASE CONVERGENCE DETECTED"
        )

        st.markdown(
            """
            ### ⚠️ Potential Linked Fraud Cases

            CryptoShield found blockchain entities shared
            with previously analysed complaints. This may
            indicate a potential relationship between cases
            and should be investigated further.
            """
        )

        for alert in convergence_alerts:

            strength = alert.get(
                "strength",
                "MEDIUM"
            )

            st.warning(
                f"""
                🔗 **Potential Case Link**

                Current Case: `{case_id}`

                Previous Case: `{alert["previous_case_id"]}`

                Link Strength: **{strength}**

                Reason:
                {", ".join(alert["reasons"])}
                """
            )

            if alert.get(
                "shared_destinations"
            ):

                st.write(
                    "**Shared destination:**"
                )

                for address in (
                    alert[
                        "shared_destinations"
                    ]
                ):

                    st.code(
                        address
                    )

            if alert.get(
                "shared_wallets"
            ):

                st.write(
                    "**Shared intermediary wallet:**"
                )

                for address in (
                    alert[
                        "shared_wallets"
                    ]
                ):

                    st.code(
                        address
                    )

    else:

        st.info(
            "🔎 No cross-case convergence detected "
            "with previously stored complaints."
        )

    # ========================================================
    # TOP METRICS
    # ========================================================

    st.subheader(
        "📊 Investigation Overview"
    )

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:

        st.metric(
            "Risk Score",
            f"{risk_score}/100"
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
            "Max Hop",
            max_hops
        )

    with col5:

        st.metric(
            "Potential Links",
            len(convergence_alerts)
        )

    # ========================================================
    # RISK STATUS
    # ========================================================

    if risk_level == "HIGH":

        st.error(
            f"🔴 HIGH RISK — Score {risk_score}/100"
        )

    elif risk_level == "MEDIUM":

        st.warning(
            f"🟠 MEDIUM RISK — Score {risk_score}/100"
        )

    else:

        st.success(
            f"🟢 LOW RISK — Score {risk_score}/100"
        )

    # ========================================================
    # TABS
    # ========================================================

    (
        overview_tab,
        graph_tab,
        dna_tab,
        abnormal_tab,
        vasp_tab,
        cases_tab,
        report_tab
    ) = st.tabs(
        [
            "📊 Overview",
            "🕸️ Fund Flow Graph",
            "🧬 Transaction DNA",
            "🚨 Abnormal Activity",
            "🏦 VASP Analysis",
            "🔗 Cross-Case Intelligence",
            "📄 Investigation Report"
        ]
    )

    # ========================================================
    # OVERVIEW TAB
    # ========================================================

    with overview_tab:

        st.subheader(
            "Investigation Summary"
        )

        st.write(
            f"**Reported Wallet:** "
            f"`{reported_wallet}`"
        )

        st.write(
            f"**Blockchain:** "
            f"`{blockchain}`"
        )

        st.write(
            f"**Investigation Case:** "
            f"`{case_id}`"
        )

        st.write(
            f"**Tracing Depth:** "
            f"`{max_hops} hops`"
        )

        st.divider()

        st.subheader(
            "Detected Behaviour"
        )

        if patterns:

            for pattern in patterns:

                st.warning(
                    f"⚠️ {pattern}"
                )

        else:

            st.success(
                "No major predefined suspicious patterns detected."
            )

        st.divider()

        st.subheader(
            "Investigation Interpretation"
        )

        if risk_level == "HIGH":

            st.write(
                """
                The wallet exhibits multiple blockchain
                indicators associated with elevated risk.
                Investigators should examine the traced
                fund-flow paths, connected wallets and
                potential exchange/VASP associations.
                """
            )

        elif risk_level == "MEDIUM":

            st.write(
                """
                The wallet exhibits some potentially
                suspicious behavioural indicators.
                Additional investigation is recommended.
                """
            )

        else:

            st.write(
                """
                The available blockchain indicators do not
                currently produce a high-risk assessment.
                """
            )

    # ========================================================
    # GRAPH TAB
    # ========================================================

    with graph_tab:

        st.subheader(
            "🕸️ Multi-Hop Fund Flow Network"
        )

        st.write(
            """
            The graph represents the movement of funds from
            the reported wallet through connected wallets.
            Each edge displays the tracing hop.
            """
        )

        if connections:

            graph_path = create_graph(
                connections,
                reported_wallet
            )

            if graph_path:

                with open(
                    graph_path,
                    "r",
                    encoding="utf-8"
                ) as file:

                    graph_html = file.read()

                st.components.v1.html(
                    graph_html,
                    height=680,
                    scrolling=True
                )

        else:

            st.warning(
                "No wallet connections were discovered "
                "for graph construction."
            )

        st.divider()

        st.subheader(
            "Hop-Level Connections"
        )

        if connections:

            graph_rows = []

            for connection in connections:

                graph_rows.append(
                    {
                        "From":
                            connection.get(
                                "from",
                                ""
                            ),

                        "To":
                            connection.get(
                                "to",
                                ""
                            ),

                        "Hop":
                            connection.get(
                                "hop",
                                0
                            )
                    }
                )

            st.dataframe(
                pd.DataFrame(
                    graph_rows
                ),
                use_container_width=True
            )

    # ========================================================
    # TRANSACTION DNA TAB
    # ========================================================

    with dna_tab:

        st.subheader(
            "🧬 Transaction Behaviour DNA"
        )

        c1, c2, c3 = st.columns(3)

        with c1:

            st.metric(
                "Total Transactions",
                transaction_dna.get(
                    "transaction_count",
                    0
                )
            )

        with c2:

            st.metric(
                "Unique Senders",
                transaction_dna.get(
                    "unique_senders",
                    0
                )
            )

        with c3:

            st.metric(
                "Unique Receivers",
                transaction_dna.get(
                    "unique_receivers",
                    0
                )
            )

        c4, c5, c6 = st.columns(3)

        with c4:

            st.metric(
                "Fan-In",
                transaction_dna.get(
                    "fan_in",
                    0
                )
            )

        with c5:

            st.metric(
                "Fan-Out",
                transaction_dna.get(
                    "fan_out",
                    0
                )
            )

        with c6:

            st.metric(
                "Rapid Movements",
                transaction_dna.get(
                    "rapid_movements",
                    0
                )
            )

        st.divider()

        st.write(
            "**Behaviour Indicators**"
        )

        indicators = transaction_dna.get(
            "behavior_indicators",
            []
        )

        if indicators:

            for indicator in indicators:

                st.warning(
                    f"⚠️ {indicator}"
                )

        else:

            st.info(
                "No predefined behaviour indicators detected."
            )

    # ========================================================
    # ABNORMAL TAB
    # ========================================================

    with abnormal_tab:

        st.subheader(
            "🚨 Abnormal Transaction Detection"
        )

        st.metric(
            "Flagged Transactions",
            len(abnormal_alerts)
        )

        if abnormal_alerts:

            abnormal_rows = []

            for alert in abnormal_alerts:

                abnormal_rows.append(
                    {
                        "Transaction Hash":
                            alert.get(
                                "hash",
                                "Unknown"
                            ),

                        "Score":
                            alert.get(
                                "score",
                                0
                            ),

                        "Reason":
                            alert.get(
                                "reason",
                                ""
                            )
                    }
                )

            st.dataframe(
                pd.DataFrame(
                    abnormal_rows
                ),
                use_container_width=True
            )

        else:

            st.success(
                "No abnormal transactions detected."
            )

    # ========================================================
    # VASP TAB
    # ========================================================

    with vasp_tab:

        st.subheader(
            "🏦 Potential VASP / Exchange Association"
        )

        if vasp_results:

            for vasp in vasp_results:

                st.info(
                    f"""
                    **{vasp.get("name", "Unknown VASP")}**

                    Type: {vasp.get("type", "Unknown")}

                    Country: {vasp.get("country", "Unknown")}

                    Address: `{vasp.get("address", "")}`

                    Confidence: {vasp.get("confidence", "Potential association")}
                    """
                )

        else:

            st.info(
                "No registered VASP/exchange association "
                "was identified in the current registry."
            )

            st.caption(
                "For a production system, this registry should "
                "be replaced or supplemented with authoritative "
                "VASP/address intelligence."
            )

    # ========================================================
    # CROSS CASE TAB
    # ========================================================

    with cases_tab:

        st.subheader(
            "🔗 Cross-Case Intelligence"
        )

        all_cases = get_all_cases()

        st.metric(
            "Total Stored Cases",
            len(all_cases)
        )

        if convergence_alerts:

            st.error(
                f"🚨 {len(convergence_alerts)} "
                f"potential cross-case link(s) detected"
            )

            for alert in convergence_alerts:

                st.markdown(
                    f"""
                    ### 🔗 {alert["previous_case_id"]}

                    **Relationship strength:** \
                    {alert["strength"]}

                    **Reasons:** \
                    {", ".join(alert["reasons"])}
                    """
                )

                if alert[
                    "shared_destinations"
                ]:

                    st.write(
                        "**Shared destination(s)**"
                    )

                    for address in (
                        alert[
                            "shared_destinations"
                        ]
                    ):

                        st.code(
                            address
                        )

                if alert[
                    "shared_wallets"
                ]:

                    st.write(
                        "**Shared intermediary wallet(s)**"
                    )

                    for address in (
                        alert[
                            "shared_wallets"
                        ]
                    ):

                        st.code(
                            address
                        )

                st.divider()

        else:

            st.success(
                "No potential cross-case links detected."
            )

        # ----------------------------------------------------
        # Previous cases
        # ----------------------------------------------------

        st.subheader(
            "📁 Previous Investigation Cases"
        )

        if all_cases:

            case_rows = []

            for case in all_cases:

                case_rows.append(
                    {
                        "Case ID":
                            case.get(
                                "case_id"
                            ),

                        "Wallet":
                            case.get(
                                "wallet_address"
                            ),

                        "Chain":
                            case.get(
                                "chain"
                            ),

                        "Risk":
                            case.get(
                                "risk_level"
                            ),

                        "Score":
                            case.get(
                                "risk_score"
                            ),

                        "Created":
                            case.get(
                                "created_at"
                            )
                    }
                )

            st.dataframe(
                pd.DataFrame(
                    case_rows
                ),
                use_container_width=True
            )

        else:

            st.info(
                "No previous investigation cases."
            )

    # ========================================================
    # REPORT TAB
    # ========================================================

    with report_tab:

        st.subheader(
            "📄 Investigation Report"
        )

        st.write(
            """
            Generate an investigation-ready PDF containing
            the wallet analysis, risk assessment, behavioural
            indicators, fund-flow evidence and potential VASP
            associations.
            """
        )

        if st.button(
            "📄 Generate PDF Report",
            type="primary"
        ):

            report_path = (
                Path(__file__).resolve().parent
                / f"{case_id}_CryptoShield_Report.pdf"
            )

            try:

                generate_pdf_report(

                    file_path=
                        str(report_path),

                    wallet_address=
                        reported_wallet,

                    chain=
                        blockchain,

                    transactions=
                        transactions,

                    connected_wallets=
                        connected_wallets,

                    max_hop=
                        max_hops,

                    abnormal_alerts=
                        abnormal_alerts,

                    vasp_results=
                        vasp_results,

                    risk_score=
                        risk_score,

                    risk_level=
                        risk_level,

                    patterns=
                        patterns
                )

                st.success(
                    "✅ PDF report generated successfully."
                )

                with open(
                    report_path,
                    "rb"
                ) as pdf_file:

                    st.download_button(

                        label=
                            "⬇️ Download Investigation Report",

                        data=
                            pdf_file,

                        file_name=
                            report_path.name,

                        mime=
                            "application/pdf"
                    )

            except Exception as e:

                st.error(
                    f"Report generation failed: {e}"
                )

    # ========================================================
    # RAW TRANSACTION DATA
    # ========================================================

    st.divider()

    with st.expander(
        "🔍 View Raw Blockchain Transactions"
    ):

        if transactions:

            display_rows = []

            for tx in transactions:

                display_rows.append(
                    {
                        "Hash":
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

                        "Type":
                            tx.get(
                                "type",
                                "native"
                            ),

                        "Hop":
                            tx.get(
                                "hop",
                                0
                            ),

                        "Time":
                            tx.get(
                                "timeStamp",
                                ""
                            )
                    }
                )

            st.dataframe(
                pd.DataFrame(
                    display_rows
                ),
                use_container_width=True,
                height=500
            )

        else:

            st.info(
                "No transaction data available."
            )


# ============================================================
# LANDING PAGE
# ============================================================

else:

    st.info(
        "👈 Enter a victim-reported suspect wallet address "
        "and click **Analyze Wallet** to start an investigation."
    )

    st.divider()

    st.subheader(
        "🎯 What CryptoShield Does"
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.markdown(
            """
            ### 🔎 1. Trace

            Automatically trace the movement of funds
            across connected blockchain wallets.
            """
        )

    with col2:

        st.markdown(
            """
            ### 🧬 2. Analyse

            Detect suspicious transaction behaviour,
            abnormal activity and fund-flow patterns.
            """
        )

    with col3:

        st.markdown(
            """
            ### 🔗 3. Correlate

            Compare independent victim complaints to
            identify potential cross-case convergence.
            """
        )

    st.divider()

    st.subheader(
        "🏆 Key Innovation"
    )

    st.markdown(
        """
        > **CryptoShield goes beyond analysing a single wallet.
        > It correlates blockchain traces across multiple
        > victim-reported cases to surface potential hidden
        > connections between complaints.**
        """
    )

    st.warning(
        """
        ⚠️ **Investigation disclaimer:** CryptoShield provides
        analytical indicators and potential associations based
        on blockchain data. A risk score or convergence alert
        does not by itself establish criminal activity or the
        identity of a person.
        """
    )
