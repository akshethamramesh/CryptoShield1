import streamlit as st
import pandas as pd
import os


# ========================================================
# BLOCKCHAIN
# ========================================================

from blockchain import (
    trace_wallet,
    clear_cache
)


# ========================================================
# TRANSACTION DNA
# ========================================================

from transaction_dna import (
    analyze_transaction_dna
)


# ========================================================
# ABNORMAL DETECTION
# ========================================================

from abnormal_detection import (
    detect_abnormal_transactions
)


# ========================================================
# VASP DETECTION
# ========================================================

from vasp_detection import (
    detect_vasp
)


# ========================================================
# CASE STORE
# ========================================================

from case_store import (
    save_case,
    get_all_cases,
    get_case,
    get_other_cases
)


# ========================================================
# CROSS CASE INTELLIGENCE
# ========================================================

from convergence_detection import (
    detect_cross_case_convergence,
    build_fraud_ring_clusters,
    convergence_summary
)


# ========================================================
# PDF REPORT
# ========================================================

from report_generator import (
    generate_pdf_report
)


# ========================================================
# SUSPICIOUS WALLET DETECTION
# ========================================================

from suspicious_wallet_detection import (
    analyze_suspicious_wallets
)


# ========================================================
# PAGE CONFIG
# ========================================================

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
)


# ========================================================
# CUSTOM CSS
# ========================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 5px;
    }

    .sub-title {
        font-size: 18px;
        color: #777;
        margin-bottom: 25px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ========================================================
# HEADER
# ========================================================

st.markdown(
    '<div class="main-title">🛡️ CryptoShield</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="sub-title">'
    'Blockchain Fraud Intelligence & Investigation System'
    '</div>',
    unsafe_allow_html=True
)


# ========================================================
# SESSION STATE
# ========================================================

if "trace_result" not in st.session_state:

    st.session_state.trace_result = None


if "case_id" not in st.session_state:

    st.session_state.case_id = None


# ========================================================
# SIDEBAR
# ========================================================

with st.sidebar:

    st.header(
        "⚙️ Investigation Settings"
    )

    chain = st.selectbox(
        "Blockchain",
        [
            "Ethereum",
            "BSC"
        ]
    )

    max_hop = st.slider(
        "Maximum tracing hop",
        min_value=1,
        max_value=3,
        value=2
    )

    st.divider()

    st.subheader(
        "🧹 Cache"
    )

    if st.button(
        "Clear Blockchain Cache",
        use_container_width=True
    ):

        clear_cache()

        st.session_state.trace_result = None

        st.success(
            "Blockchain cache cleared."
        )


# ========================================================
# WALLET INPUT
# ========================================================

st.subheader(
    "🔍 Victim-Reported Suspect Wallet"
)

st.write(
    """
    Enter the wallet address reported by the victim
    or investigator. CryptoShield analyses blockchain
    activity connected to this reported wallet.
    """
)

reported_wallet_input = st.text_input(
    "Ethereum / BSC Wallet Address",
    placeholder="0x..."
)


# ========================================================
# ANALYSE BUTTON
# ========================================================

analyse_button = st.button(
    "🚀 Start Blockchain Investigation",
    type="primary",
    use_container_width=True
)


# ========================================================
# START INVESTIGATION
# ========================================================

if analyse_button:

    if not reported_wallet_input:

        st.error(
            "Please enter a wallet address."
        )

        st.stop()

    reported_wallet = (
        reported_wallet_input
        .strip()
        .lower()
    )

    if not reported_wallet.startswith("0x"):

        st.error(
            "Invalid wallet address format."
        )

        st.stop()

    if len(reported_wallet) != 42:

        st.error(
            "Wallet address should contain 42 characters."
        )

        st.stop()

    with st.spinner(
        "🔎 Collecting blockchain transactions..."
    ):

        try:

            trace_result = trace_wallet(
                reported_wallet,
                chain=chain,
                max_hop=max_hop
            )

            st.session_state.trace_result = (
                trace_result
            )

        except Exception as error:

            st.error(
                f"Blockchain analysis failed: {error}"
            )

            st.stop()


# ========================================================
# LOAD TRACE RESULT
# ========================================================

trace_result = (
    st.session_state.trace_result
)


if trace_result is None:

    st.info(
        "👆 Enter a reported suspect wallet address "
        "and start the investigation."
    )

    st.stop()


# ========================================================
# TRACE DATA
# ========================================================

reported_wallet = trace_result.get(
    "start_wallet",
    ""
)

transactions = trace_result.get(
    "transactions",
    []
)

connected_wallets = trace_result.get(
    "connected_wallets",
    []
)

wallet_hops = trace_result.get(
    "wallet_hops",
    {}
)

connections = trace_result.get(
    "connections",
    []
)


# ========================================================
# TRANSACTION DNA
# ========================================================

transaction_dna = analyze_transaction_dna(
    transactions,
    reported_wallet
)


# ========================================================
# ABNORMAL ACTIVITY
# ========================================================

abnormal_alerts = (
    detect_abnormal_transactions(
        transactions
    )
)


# ========================================================
# VASP ANALYSIS
# ========================================================

vasp_results = detect_vasp(
    transactions
)


# ========================================================
# SUSPICIOUS WALLET ANALYSIS
# ========================================================

suspicious_wallets = (
    analyze_suspicious_wallets(
        transactions,
        wallet_hops,
        reported_wallet
    )
)

top_5_suspicious_wallets = (
    suspicious_wallets[:5]
)


# ========================================================
# BASIC RISK SCORE
# ========================================================

transaction_count = (
    transaction_dna.get(
        "transaction_count",
        0
    )
)


connected_count = len(
    [
        wallet
        for wallet in connected_wallets
        if wallet.lower()
        != reported_wallet.lower()
    ]
)


rapid_movements = (
    transaction_dna.get(
        "rapid_movements",
        0
    )
)


risk_score = 0


if transaction_count > 100:

    risk_score += 25

elif transaction_count > 50:

    risk_score += 15


if connected_count > 20:

    risk_score += 25

elif connected_count > 10:

    risk_score += 15


if rapid_movements >= 5:

    risk_score += 30

elif rapid_movements >= 2:

    risk_score += 15


if len(abnormal_alerts) >= 10:

    risk_score += 20

elif len(abnormal_alerts) >= 5:

    risk_score += 10


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


# ========================================================
# PATTERN DETECTION
# ========================================================

patterns = []


if transaction_count >= 100:

    patterns.append(
        "High transaction activity"
    )


if connected_count >= 10:

    patterns.append(
        "Large connected-wallet network"
    )


if rapid_movements >= 5:

    patterns.append(
        "Rapid fund movement"
    )


if len(abnormal_alerts) >= 5:

    patterns.append(
        "Multiple abnormal transaction indicators"
    )


if max_hop >= 2 and connections:

    patterns.append(
        "Multi-hop fund movement observed"
    )


if vasp_results:

    patterns.append(
        "Potential VASP / exchange association"
    )


# ========================================================
# FINAL DESTINATIONS
# ========================================================

final_destinations = []


for wallet, hop in wallet_hops.items():

    if hop != max_hop:

        continue

    wallet_lower = wallet.lower()

    if wallet_lower == reported_wallet.lower():

        continue

    final_destinations.append(
        wallet_lower
    )


final_destinations = list(
    dict.fromkeys(
        final_destinations
    )
)


# ========================================================
# IMPORTANT WALLETS
# ========================================================

important_wallets = [

    wallet

    for wallet in connected_wallets

    if wallet.lower()
    != reported_wallet.lower()

]


# ========================================================
# SAVE CASE
# ========================================================

try:

    current_case_id = save_case(
        wallet_address=reported_wallet,
        chain=chain,
        traced_value=transaction_dna.get(
            "native_volume",
            0
        ),
        risk_score=risk_score,
        risk_level=risk_level,
        max_hop=max_hop,
        final_destinations=final_destinations,
        important_wallets=important_wallets,
        hop_paths=connections
    )

    st.session_state.case_id = (
        current_case_id
    )

except Exception:

    current_case_id = (
        st.session_state.case_id
    )


# ========================================================
# TABS
# ========================================================

(
    overview_tab,
    graph_tab,
    suspicious_tab,
    dna_tab,
    abnormal_tab,
    vasp_tab,
    cases_tab,
    report_tab
) = st.tabs(
    [
        "📊 Overview",
        "🕸️ Fund Flow Graph",
        "🔎 Suspicious Wallets",
        "🧬 Transaction DNA",
        "🚨 Abnormal Activity",
        "🏦 VASP Analysis",
        "🔗 Cross-Case Intelligence",
        "📄 Investigation Report"
    ]
)


# ========================================================
# OVERVIEW
# ========================================================

with overview_tab:

    st.subheader(
        "📊 Investigation Overview"
    )

    st.write(
        "Reported wallet:"
    )

    st.code(
        reported_wallet
    )

    st.divider()

    c1, c2, c3, c4 = st.columns(4)

    with c1:

        st.metric(
            "Risk Score",
            f"{risk_score}/100"
        )

    with c2:

        st.metric(
            "Risk Level",
            risk_level
        )

    with c3:

        st.metric(
            "Transactions",
            transaction_count
        )

    with c4:

        st.metric(
            "Connected Wallets",
            connected_count
        )

    st.divider()

    c1, c2, c3, c4 = st.columns(4)

    with c1:

        st.metric(
            "Maximum Hop",
            max_hop
        )

    with c2:

        st.metric(
            "Rapid Movements",
            rapid_movements
        )

    with c3:

        st.metric(
            "Abnormal Alerts",
            len(abnormal_alerts)
        )

    with c4:

        st.metric(
            "Potential VASP",
            len(vasp_results)
        )

    st.divider()

    st.subheader(
        "🧠 Detected Behaviour"
    )

    if patterns:

        for pattern in patterns:

            st.warning(
                f"⚠️ {pattern}"
            )

    else:

        st.success(
            "No major predefined behavioural patterns detected."
        )

    st.divider()

    st.info(
        """
        CryptoShield provides analytical intelligence
        from blockchain data. A risk score is not proof
        that a wallet owner or person committed fraud.
        """
    )


# ========================================================
# FUND FLOW GRAPH
# ========================================================

with graph_tab:

    st.subheader(
        "🕸️ Multi-Hop Fund Flow"
    )

    st.write(
        """
        Wallets discovered during automated tracing
        are shown with their tracing hop.
        """
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

        graph_df = pd.DataFrame(
            graph_rows
        )

        st.dataframe(
            graph_df,
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        st.subheader(
            "🔗 Fund Flow Connections"
        )

        for connection in connections:

            source = connection.get(
                "from",
                ""
            )

            destination = connection.get(
                "to",
                ""
            )

            hop = connection.get(
                "hop",
                0
            )

            st.write(
                f"**Hop {hop}:** "
                f"`{source[:10]}...` → "
                f"`{destination[:10]}...`"
            )

    else:

        st.info(
            "No multi-hop connections found."
        )


# ========================================================
# SUSPICIOUS WALLET TAB
# ========================================================

with suspicious_tab:

    st.subheader(
        "🔎 Top 5 High-Risk Wallets"
    )

    st.write(
        """
        CryptoShield ranks wallets discovered during
        multi-hop tracing using observable blockchain
        behaviour and predefined risk indicators.
        """
    )

    st.warning(
        """
        ⚠️ A high-risk wallet is an analytical indicator,
        not proof that a person or entity committed fraud.
        """
    )

    # ----------------------------------------------------
    # SUMMARY
    # ----------------------------------------------------

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Wallets Analysed",
            len(suspicious_wallets)
        )

    with col2:

        high_count = sum(
            1
            for wallet in suspicious_wallets
            if wallet.get(
                "risk_level"
            ) == "HIGH"
        )

        st.metric(
            "High-Risk Wallets",
            high_count
        )

    with col3:

        st.metric(
            "Top Suspicious Wallets",
            min(
                5,
                len(suspicious_wallets)
            )
        )

    st.divider()

    # ----------------------------------------------------
    # TOP 5
    # ----------------------------------------------------

    if top_5_suspicious_wallets:

        table_rows = []

        for wallet in (
            top_5_suspicious_wallets
        ):

            address = wallet.get(
                "wallet",
                ""
            )

            table_rows.append(
                {
                    "Rank":
                        wallet.get(
                            "rank",
                            0
                        ),

                    "Wallet":
                        (
                            address[:10]
                            + "..."
                            + address[-8:]
                        ),

                    "Hop":
                        wallet.get(
                            "hop",
                            0
                        ),

                    "Risk Score":
                        wallet.get(
                            "risk_score",
                            0
                        ),

                    "Risk":
                        wallet.get(
                            "risk_level",
                            "LOW"
                        ),

                    "Transactions":
                        wallet.get(
                            "transaction_count",
                            0
                        ),

                    "Connected":
                        wallet.get(
                            "connected_wallets",
                            0
                        ),

                    "Rapid":
                        wallet.get(
                            "rapid_movements",
                            0
                        )
                }
            )

        st.dataframe(
            pd.DataFrame(
                table_rows
            ),
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        # ------------------------------------------------
        # SELECT WALLET
        # ------------------------------------------------

        wallet_options = [

            wallet.get(
                "wallet",
                ""
            )

            for wallet
            in top_5_suspicious_wallets

        ]

        selected_wallet = st.selectbox(
            "🔍 Select a wallet for detailed investigation",
            wallet_options,
            format_func=lambda address:
                (
                    address[:10]
                    + "..."
                    + address[-8:]
                )
        )

        selected_data = None

        for wallet in (
            top_5_suspicious_wallets
        ):

            if wallet.get(
                "wallet"
            ) == selected_wallet:

                selected_data = wallet

                break

        # ------------------------------------------------
        # PROFILE
        # ------------------------------------------------

        if selected_data:

            st.subheader(
                "🕵️ Wallet Investigation Profile"
            )

            address = selected_data.get(
                "wallet",
                ""
            )

            risk_score_value = (
                selected_data.get(
                    "risk_score",
                    0
                )
            )

            risk_level_value = (
                selected_data.get(
                    "risk_level",
                    "LOW"
                )
            )

            st.code(
                address
            )

            if risk_level_value == "HIGH":

                st.error(
                    f"🔴 HIGH RISK — "
                    f"{risk_score_value}/100"
                )

            elif risk_level_value == "MEDIUM":

                st.warning(
                    f"🟠 MEDIUM RISK — "
                    f"{risk_score_value}/100"
                )

            else:

                st.success(
                    f"🟢 LOW RISK — "
                    f"{risk_score_value}/100"
                )

            # --------------------------------------------
            # METRICS
            # --------------------------------------------

            p1, p2, p3, p4 = st.columns(4)

            with p1:

                st.metric(
                    "Tracing Hop",
                    selected_data.get(
                        "hop",
                        0
                    )
                )

            with p2:

                st.metric(
                    "Transactions",
                    selected_data.get(
                        "transaction_count",
                        0
                    )
                )

            with p3:

                st.metric(
                    "Incoming",
                    selected_data.get(
                        "incoming_transactions",
                        0
                    )
                )

            with p4:

                st.metric(
                    "Outgoing",
                    selected_data.get(
                        "outgoing_transactions",
                        0
                    )
                )

            p5, p6, p7, p8 = st.columns(4)

            with p5:

                st.metric(
                    "Fan-In",
                    selected_data.get(
                        "fan_in",
                        0
                    )
                )

            with p6:

                st.metric(
                    "Fan-Out",
                    selected_data.get(
                        "fan_out",
                        0
                    )
                )

            with p7:

                st.metric(
                    "Connected Wallets",
                    selected_data.get(
                        "connected_wallets",
                        0
                    )
                )

            with p8:

                st.metric(
                    "Rapid Movements",
                    selected_data.get(
                        "rapid_movements",
                        0
                    )
                )

            # --------------------------------------------
            # REASONS
            # --------------------------------------------

            st.divider()

            st.subheader(
                "⚠️ Risk Indicators"
            )

            reasons = selected_data.get(
                "reasons",
                []
            )

            if reasons:

                for reason in reasons:

                    st.warning(
                        f"• {reason}"
                    )

            else:

                st.info(
                    "No strong predefined risk indicators."
                )

            # --------------------------------------------
            # TRANSFER INDICATORS
            # --------------------------------------------

            st.divider()

            st.subheader(
                "💰 Transfer Indicators"
            )

            st.write(
                f"**Large-value transfer indicators:** "
                f"{selected_data.get('large_transfers', 0)}"
            )

            st.write(
                f"**Observed transaction value:** "
                f"{selected_data.get('total_value', 0):.4f}"
            )

            # --------------------------------------------
            # INTERPRETATION
            # --------------------------------------------

            st.divider()

            st.subheader(
                "🧠 Investigation Interpretation"
            )

            if risk_level_value == "HIGH":

                st.write(
                    """
                    This wallet shows multiple observable
                    blockchain indicators that justify
                    prioritising it for further investigation.

                    Investigators should examine its transaction
                    history, counterparties, fund-flow paths and
                    potential entity associations.
                    """
                )

            elif risk_level_value == "MEDIUM":

                st.write(
                    """
                    This wallet shows some elevated-risk
                    behavioural indicators. Additional
                    blockchain investigation is recommended.
                    """
                )

            else:

                st.write(
                    """
                    This wallet currently shows limited
                    predefined risk indicators.
                    """
                )

    else:

        st.info(
            "No connected wallets were available for "
            "suspicious-wallet ranking."
        )


# ========================================================
# TRANSACTION DNA
# ========================================================

with dna_tab:

    st.subheader(
        "🧬 Transaction DNA"
    )

    c1, c2, c3, c4 = st.columns(4)

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
            "Native Transactions",
            transaction_dna.get(
                "native_transaction_count",
                0
            )
        )

    with c3:

        st.metric(
            "Token Transactions",
            transaction_dna.get(
                "token_transaction_count",
                0
            )
        )

    with c4:

        st.metric(
            "Rapid Movements",
            transaction_dna.get(
                "rapid_movements",
                0
            )
        )

    st.divider()

    c1, c2, c3, c4 = st.columns(4)

    with c1:

        st.metric(
            "Unique Senders",
            transaction_dna.get(
                "unique_senders",
                0
            )
        )

    with c2:

        st.metric(
            "Unique Receivers",
            transaction_dna.get(
                "unique_receivers",
                0
            )
        )

    with c3:

        st.metric(
            "Fan-In",
            transaction_dna.get(
                "fan_in",
                0
            )
        )

    with c4:

        st.metric(
            "Fan-Out",
            transaction_dna.get(
                "fan_out",
                0
            )
        )

    st.divider()

    st.subheader(
        "💰 Transfer Volume"
    )

    st.write(
        f"Native volume: "
        f"{transaction_dna.get('native_volume', 0):.4f}"
    )

    st.write(
        f"Token volume: "
        f"{transaction_dna.get('token_volume', 0):.4f}"
    )

    st.write(
        f"Average native transfer: "
        f"{transaction_dna.get('average_native_transfer', 0):.4f}"
    )

    st.divider()

    st.subheader(
        "🧠 Behaviour Indicators"
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

        st.success(
            "No major predefined indicators detected."
        )


# ========================================================
# ABNORMAL ACTIVITY
# ========================================================

with abnormal_tab:

    st.subheader(
        "🚨 Abnormal Transaction Activity"
    )

    st.write(
        f"Detected alerts: {len(abnormal_alerts)}"
    )

    if abnormal_alerts:

        alert_rows = []

        for alert in abnormal_alerts:

            alert_rows.append(
                {
                    "Transaction":
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
                alert_rows
            ),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "No abnormal transaction indicators detected."
        )


# ========================================================
# VASP ANALYSIS
# ========================================================

with vasp_tab:

    st.subheader(
        "🏦 Potential VASP / Exchange Association"
    )

    st.write(
        """
        CryptoShield checks observed transaction participants
        against the configured VASP/exchange intelligence registry.
        """
    )

    if vasp_results:

        for result in vasp_results:

            st.info(
                f"""
                **Potential association**

                Name: {result.get('name', 'Unknown')}

                Type: {result.get('type', 'Unknown')}

                Country: {result.get('country', 'Unknown')}

                Address: {result.get('address', 'Unknown')}

                Transaction role:
                {result.get('transaction_role', 'Unknown')}

                Confidence:
                {result.get('confidence', 'Unknown')}
                """
            )

    else:

        st.warning(
            "No configured VASP association detected."
        )


# ========================================================
# CROSS-CASE INTELLIGENCE
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

    st.divider()

    current_case = None

    if st.session_state.case_id:

        current_case = get_case(
            st.session_state.case_id
        )

    if current_case:

        previous_cases = get_other_cases(
            st.session_state.case_id
        )

        convergence_alerts = (
            detect_cross_case_convergence(
                current_case,
                previous_cases
            )
        )

        summary = convergence_summary(
            convergence_alerts
        )

        c1, c2, c3 = st.columns(3)

        with c1:

            st.metric(
                "Linked Cases",
                summary.get(
                    "linked_cases",
                    0
                )
            )

        with c2:

            st.metric(
                "High Strength Links",
                summary.get(
                    "high_strength_links",
                    0
                )
            )

        with c3:

            st.metric(
                "Medium Strength Links",
                summary.get(
                    "medium_strength_links",
                    0
                )
            )

        st.divider()

        if convergence_alerts:

            st.subheader(
                "🚨 Potential Cross-Case Links"
            )

            for alert in convergence_alerts:

                strength = alert.get(
                    "strength",
                    "LOW"
                )

                if strength == "HIGH":

                    st.error(
                        f"🔴 {alert.get('message')}"
                    )

                elif strength == "MEDIUM":

                    st.warning(
                        f"🟠 {alert.get('message')}"
                    )

                else:

                    st.info(
                        f"🟢 {alert.get('message')}"
                    )

                st.write(
                    "Reasons: "
                    + ", ".join(
                        alert.get(
                            "reasons",
                            []
                        )
                    )
                )

                shared_destinations = (
                    alert.get(
                        "shared_destinations",
                        []
                    )
                )

                shared_wallets = (
                    alert.get(
                        "shared_wallets",
                        []
                    )
                )

                if shared_destinations:

                    st.write(
                        "**Shared destinations:**"
                    )

                    for address in (
                        shared_destinations
                    ):

                        st.code(
                            address
                        )

                if shared_wallets:

                    st.write(
                        "**Shared intermediary wallets:**"
                    )

                    for address in (
                        shared_wallets
                    ):

                        st.code(
                            address
                        )

                st.divider()

            clusters = (
                build_fraud_ring_clusters(
                    convergence_alerts
                )
            )

            if clusters:

                st.subheader(
                    "🕸️ Potential Fraud-Ring Clusters"
                )

                for cluster in clusters:

                    st.write(
                        " → ".join(
                            cluster
                        )
                    )

        else:

            st.success(
                "No cross-case convergence detected."
            )

    else:

        st.info(
            "Current case information is not available."
        )


# ========================================================
# INVESTIGATION REPORT
# ========================================================

with report_tab:

    st.subheader(
        "📄 Investigation Report"
    )

    st.write(
        """
        Generate an investigation-ready PDF containing
        blockchain analysis and detected indicators.
        """
    )

    report_filename = (
        "CryptoShield_Investigation_Report.pdf"
    )

    if st.button(
        "📄 Generate Investigation PDF",
        use_container_width=True
    ):

        try:

            report_path = generate_pdf_report(
                file_path=report_filename,
                wallet_address=reported_wallet,
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

            st.success(
                "Investigation report generated successfully."
            )

            if os.path.exists(
                report_path
            ):

                with open(
                    report_path,
                    "rb"
                ) as file:

                    st.download_button(
                        label=(
                            "⬇️ Download Investigation Report"
                        ),
                        data=file,
                        file_name=os.path.basename(
                            report_path
                        ),
                        mime="application/pdf",
                        use_container_width=True
                    )

        except Exception as error:

            st.error(
                f"Report generation failed: {error}"
            )


# ========================================================
# FOOTER
# ========================================================

st.divider()

st.caption(
    """
    🛡️ CryptoShield — Blockchain Fraud Intelligence System

    Analytical results are intended to support investigation
    and prioritisation. They do not constitute proof of criminal
    activity or identification of a wallet owner.
    """
)
