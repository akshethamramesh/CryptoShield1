import streamlit as st
import pandas as pd
from datetime import datetime
from pathlib import Path
from fund_flow_graph import render_fund_flow_graph
# ============================================================
# CRYPTO SHIELD
# Blockchain Fraud Intelligence System
# ============================================================

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# IMPORT PROJECT MODULES
# ============================================================

try:
    from blockchain import trace_wallet
except Exception as e:
    trace_wallet = None
    BLOCKCHAIN_ERROR = str(e)

try:
    from transaction_dna import analyze_transaction_dna
except Exception:
    analyze_transaction_dna = None

try:
    from abnormal_detection import detect_abnormal_transactions
except Exception:
    detect_abnormal_transactions = None

try:
    from vasp_detection import detect_vasp
except Exception:
    detect_vasp = None

try:
    from exchange_intelligence import (
        check_exchange_associations,
        summarize_exchange_associations
    )
except Exception:
    check_exchange_associations = None
    summarize_exchange_associations = None

try:
    from case_store import (
        init_database,
        save_case,
        get_all_cases,
        get_case
    )
except Exception:
    init_database = None
    save_case = None
    get_all_cases = None
    get_case = None

try:
    from convergence_detection import (
        detect_cross_case_convergence,
        build_fraud_ring_clusters,
        convergence_summary
    )
except Exception:
    detect_cross_case_convergence = None
    build_fraud_ring_clusters = None
    convergence_summary = None

try:
    from fund_flow_graph import render_fund_flow_graph
except Exception:
    render_fund_flow_graph = None


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
        color: #9CA3AF;
        margin-top: 0;
    }

    .section-title {
        font-size: 25px;
        font-weight: 700;
    }

    .risk-box {
        padding: 18px;
        border-radius: 12px;
        margin-bottom: 10px;
    }

    .small-text {
        color: #9CA3AF;
        font-size: 13px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SESSION STATE
# ============================================================

if "analysis_complete" not in st.session_state:
    st.session_state.analysis_complete = False

if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = {}

if "case_id" not in st.session_state:
    st.session_state.case_id = None


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

if init_database:
    try:
        init_database()
    except Exception:
        pass


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalize_address(address):
    if not address:
        return ""

    return str(address).strip().lower()


def short_address(address):
    if not address:
        return "Unknown"

    address = str(address)

    if len(address) <= 14:
        return address

    return address[:8] + "..." + address[-6:]


def calculate_risk_score(
    transaction_count,
    fan_in,
    fan_out,
    rapid_movements,
    abnormal_count,
    exchange_count,
    cross_case_count
):
    """
    Explainable rule-based risk score.

    This is an analytical indicator, NOT a criminal verdict.
    """

    score = 0

    if transaction_count >= 100:
        score += 15
    elif transaction_count >= 50:
        score += 8

    if fan_in >= 5:
        score += 10

    if fan_out >= 5:
        score += 10

    if rapid_movements >= 5:
        score += 15

    if abnormal_count >= 5:
        score += 15
    elif abnormal_count > 0:
        score += 8

    if exchange_count > 0:
        score += 10

    if cross_case_count > 0:
        score += 15

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def extract_hop_wallets(wallet_hops):
    result = {}

    if not wallet_hops:
        return result

    for wallet, hop in wallet_hops.items():

        wallet = normalize_address(wallet)

        try:
            hop = int(hop)
        except Exception:
            continue

        result[wallet] = hop

    return result


def extract_tracing_result(result):
    """
    Make the application tolerant of different trace_wallet
    return structures.
    """

    transactions = []
    wallet_hops = {}
    connections = []
    final_destinations = []
    important_wallets = []

    if not result:
        return (
            transactions,
            wallet_hops,
            connections,
            final_destinations,
            important_wallets
        )

    # --------------------------------------------------------
    # Dictionary result
    # --------------------------------------------------------

    if isinstance(result, dict):

        transactions = result.get(
            "transactions",
            result.get("all_transactions", [])
        )

        wallet_hops = result.get(
            "wallet_hops",
            result.get("hops", {})
        )

        connections = result.get(
            "connections",
            result.get("fund_flow_connections", [])
        )

        final_destinations = result.get(
            "final_destinations",
            []
        )

        important_wallets = result.get(
            "important_wallets",
            []
        )

    # --------------------------------------------------------
    # Tuple/list result
    # --------------------------------------------------------

    elif isinstance(result, (tuple, list)):

        if len(result) >= 1:
            transactions = result[0]

        if len(result) >= 2:
            wallet_hops = result[1]

        if len(result) >= 3:
            connections = result[2]

        if len(result) >= 4:
            final_destinations = result[3]

        if len(result) >= 5:
            important_wallets = result[4]

    if not isinstance(transactions, list):
        transactions = list(transactions or [])

    if not isinstance(wallet_hops, dict):
        wallet_hops = {}

    if not isinstance(connections, list):
        connections = list(connections or [])

    if not isinstance(final_destinations, list):
        final_destinations = list(final_destinations or [])

    if not isinstance(important_wallets, list):
        important_wallets = list(important_wallets or [])

    return (
        transactions,
        wallet_hops,
        connections,
        final_destinations,
        important_wallets
    )


def build_connections_from_transactions(
    transactions,
    wallet_hops
):
    """
    Build ACTUAL transaction-direction connections.

    from -> to

    Hop numbers are NOT used to invent direction.
    """

    connections = []
    seen = set()

    for tx in transactions:

        sender = normalize_address(
            tx.get("from", "")
        )

        receiver = normalize_address(
            tx.get("to", "")
        )

        if not sender or not receiver:
            continue

        if sender == receiver:
            continue

        key = (
            sender,
            receiver
        )

        if key in seen:
            continue

        seen.add(key)

        connections.append(
            {
                "from": sender,
                "to": receiver,
                "from_hop": wallet_hops.get(sender),
                "to_hop": wallet_hops.get(receiver)
            }
        )

    return connections


def generate_report_data(
    wallet_address,
    chain,
    transactions,
    wallet_hops,
    connections,
    dna,
    abnormal,
    vasp_matches,
    exchange_matches,
    cross_case_alerts,
    risk_score,
    risk_level
):
    return {
        "case_id": st.session_state.case_id,
        "wallet_address": wallet_address,
        "chain": chain,
        "generated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "transaction_count": len(transactions),
        "wallet_count": len(wallet_hops),
        "connection_count": len(connections),
        "transaction_dna": dna,
        "abnormal_transactions": abnormal,
        "vasp_matches": vasp_matches,
        "exchange_matches": exchange_matches,
        "cross_case_alerts": cross_case_alerts,
        "risk_score": risk_score,
        "risk_level": risk_level
    }


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        "# 🛡️ CryptoShield"
    )

    st.caption(
        "Blockchain Fraud Intelligence System"
    )

    st.divider()

    st.markdown("### 🔍 Investigation")

    wallet_address = st.text_input(
        "Reported Suspect Wallet",
        placeholder="0x...",
        help=(
            "Enter the wallet address reported by "
            "the victim or investigator."
        )
    )

    chain = st.selectbox(
        "Blockchain",
        [
            "Ethereum"
        ]
    )

    max_hop = st.slider(
        "Maximum tracing hop",
        min_value=1,
        max_value=3,
        value=2
    )

    st.divider()

    analyze_button = st.button(
        "🚀 Analyse Wallet",
        type="primary",
        use_container_width=True
    )

    st.divider()

    st.caption(
        "CryptoShield performs blockchain analytics "
        "and provides investigation intelligence."
    )


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ CryptoShield</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Blockchain Fraud Intelligence System'
    '</div>',
    unsafe_allow_html=True
)

st.write("")

st.info(
    "CryptoShield analyses a victim-reported wallet address. "
    "It does not automatically identify a person or declare "
    "that a wallet owner is criminal."
)


# ============================================================
# ANALYSE WALLET
# ============================================================

if analyze_button:

    wallet_address = normalize_address(
        wallet_address
    )

    if not wallet_address:

        st.error(
            "Please enter a wallet address."
        )

        st.stop()

    if not wallet_address.startswith("0x"):

        st.error(
            "Please enter a valid Ethereum-style wallet address."
        )

        st.stop()

    if len(wallet_address) != 42:

        st.warning(
            "The wallet address should normally contain "
            "42 characters including 0x."
        )

    if trace_wallet is None:

        st.error(
            "blockchain.py could not be imported."
        )

        if "BLOCKCHAIN_ERROR" in globals():

            st.code(
                BLOCKCHAIN_ERROR
            )

        st.stop()

    # --------------------------------------------------------
    # Start analysis
    # --------------------------------------------------------

    with st.spinner(
        "Collecting blockchain data and tracing fund flow..."
    ):

        try:

            result = trace_wallet(
                wallet_address,
                max_hop=max_hop
            )

        except TypeError:

            try:
                result = trace_wallet(
                    wallet_address,
                    max_hops=max_hop
                )

            except TypeError:

                try:
                    result = trace_wallet(
                        wallet_address
                    )

                except Exception as error:

                    st.error(
                        f"Blockchain tracing failed: {error}"
                    )

                    st.stop()

            except Exception as error:

                st.error(
                    f"Blockchain tracing failed: {error}"
                )

                st.stop()

        except Exception as error:

            st.error(
                f"Blockchain tracing failed: {error}"
            )

            st.stop()

    (
        transactions,
        wallet_hops,
        connections,
        final_destinations,
        important_wallets
    ) = extract_tracing_result(result)

    wallet_hops = extract_hop_wallets(
        wallet_hops
    )

    # --------------------------------------------------------
    # Build actual transaction connections
    # --------------------------------------------------------

    if not connections:

        connections = build_connections_from_transactions(
            transactions,
            wallet_hops
        )

    # --------------------------------------------------------
    # Transaction DNA
    # --------------------------------------------------------

    dna = {}

    if analyze_transaction_dna:

        try:

            dna = analyze_transaction_dna(
                transactions,
                wallet_address
            )

        except Exception as error:

            dna = {
                "error": str(error)
            }

    # --------------------------------------------------------
    # Abnormal transactions
    # --------------------------------------------------------

    abnormal = []

    if detect_abnormal_transactions:

        try:

            abnormal = detect_abnormal_transactions(
                transactions
            )

        except Exception:
            abnormal = []

    # --------------------------------------------------------
    # VASP analysis
    # --------------------------------------------------------

    vasp_matches = []

    if detect_vasp:

        try:

            vasp_matches = detect_vasp(
                transactions
            )

        except Exception:
            vasp_matches = []

    # --------------------------------------------------------
    # Exchange intelligence
    # --------------------------------------------------------

    exchange_matches = []

    exchange_summary = {
        "match_count": 0,
        "exchanges": []
    }

    if check_exchange_associations:

        try:

            exchange_matches = check_exchange_associations(
                transactions,
                wallet_hops=wallet_hops
            )

            if summarize_exchange_associations:

                exchange_summary = (
                    summarize_exchange_associations(
                        exchange_matches
                    )
                )

        except Exception:
            exchange_matches = []

    # --------------------------------------------------------
    # Cross-case intelligence
    # --------------------------------------------------------

    cross_case_alerts = []

    previous_cases = []

    if get_all_cases:

        try:
            previous_cases = get_all_cases()
        except Exception:
            previous_cases = []

    temporary_case = {
        "case_id": "CURRENT",
        "wallet_address": wallet_address,
        "chain": chain,
        "final_destinations": final_destinations,
        "important_wallets": important_wallets
    }

    if detect_cross_case_convergence:

        try:

            cross_case_alerts = (
                detect_cross_case_convergence(
                    temporary_case,
                    previous_cases
                )
            )

        except Exception:

            cross_case_alerts = []

    # --------------------------------------------------------
    # Risk score
    # --------------------------------------------------------

    transaction_count = len(
        transactions
    )

    fan_in = dna.get(
        "fan_in",
        0
    ) if isinstance(dna, dict) else 0

    fan_out = dna.get(
        "fan_out",
        0
    ) if isinstance(dna, dict) else 0

    rapid_movements = dna.get(
        "rapid_movements",
        0
    ) if isinstance(dna, dict) else 0

    risk_score, risk_level = calculate_risk_score(
        transaction_count,
        fan_in,
        fan_out,
        rapid_movements,
        len(abnormal),
        len(exchange_matches),
        len(cross_case_alerts)
    )

    # --------------------------------------------------------
    # Store analysis
    # --------------------------------------------------------

    st.session_state.analysis_data = {
        "wallet_address": wallet_address,
        "chain": chain,
        "transactions": transactions,
        "wallet_hops": wallet_hops,
        "connections": connections,
        "final_destinations": final_destinations,
        "important_wallets": important_wallets,
        "dna": dna,
        "abnormal": abnormal,
        "vasp_matches": vasp_matches,
        "exchange_matches": exchange_matches,
        "exchange_summary": exchange_summary,
        "cross_case_alerts": cross_case_alerts,
        "risk_score": risk_score,
        "risk_level": risk_level
    }

    st.session_state.analysis_complete = True

    # --------------------------------------------------------
    # Save case
    # --------------------------------------------------------

    if save_case:

        try:

            case_id = save_case(
                wallet_address=wallet_address,
                chain=chain,
                traced_value=(
                    dna.get(
                        "total_volume",
                        0
                    )
                    if isinstance(dna, dict)
                    else 0
                ),
                risk_score=risk_score,
                risk_level=risk_level,
                max_hop=max_hop,
                final_destinations=final_destinations,
                important_wallets=important_wallets,
                hop_paths=connections
            )

            st.session_state.case_id = case_id

        except Exception:
            st.session_state.case_id = None

    st.success(
        "Blockchain analysis completed successfully."
    )


# ============================================================
# SHOW RESULTS
# ============================================================

if st.session_state.analysis_complete:

    data = st.session_state.analysis_data

    wallet_address = data[
        "wallet_address"
    ]

    transactions = data[
        "transactions"
    ]

    wallet_hops = data[
        "wallet_hops"
    ]

    connections = data[
        "connections"
    ]

    dna = data[
        "dna"
    ]

    abnormal = data[
        "abnormal"
    ]

    vasp_matches = data[
        "vasp_matches"
    ]

    exchange_matches = data[
        "exchange_matches"
    ]

    exchange_summary = data[
        "exchange_summary"
    ]

    cross_case_alerts = data[
        "cross_case_alerts"
    ]

    risk_score = data[
        "risk_score"
    ]

    risk_level = data[
        "risk_level"
    ]

    # ========================================================
    # TOP METRICS
    # ========================================================

    st.markdown(
        "## 📊 Investigation Overview"
    )

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:

        st.metric(
            "Transactions",
            len(transactions)
        )

    with col2:

        st.metric(
            "Wallets Traced",
            len(wallet_hops)
        )

    with col3:

        st.metric(
            "Connections",
            len(connections)
        )

    with col4:

        st.metric(
            "Risk Score",
            f"{risk_score}/100"
        )

    with col5:

        st.metric(
            "Risk Level",
            risk_level
        )

    st.write("")

    st.code(
        wallet_address
    )

    # ========================================================
    # TABS
    # ========================================================

    tabs = st.tabs(
        [
            "📋 Overview",
            "🕸️ Fund Flow Graph",
            "🚨 Suspicious Wallets",
            "🧬 Transaction DNA",
            "⚠️ Abnormal Activity",
            "🏦 VASP Analysis",
            "🏦 Exchange Intelligence",
            "🔗 Cross-Case Intelligence",
            "📄 Investigation Report"
        ]
    )

    # ========================================================
    # TAB 1 - OVERVIEW
    # ========================================================

    with tabs[0]:

        st.subheader(
            "Investigation Summary"
        )

        col1, col2 = st.columns(2)

        with col1:

            st.markdown(
                "### Reported Wallet"
            )

            st.code(
                wallet_address
            )

            st.markdown(
                "### Blockchain"
            )

            st.write(
                data["chain"]
            )

        with col2:

            st.markdown(
                "### Analytical Risk"
            )

            if risk_level == "HIGH":

                st.error(
                    f"HIGH — {risk_score}/100"
                )

            elif risk_level == "MEDIUM":

                st.warning(
                    f"MEDIUM — {risk_score}/100"
                )

            else:

                st.success(
                    f"LOW — {risk_score}/100"
                )

        st.divider()

        st.markdown(
            "### Investigation Workflow"
        )

        st.write(
            """
            Reported Wallet
            →
            Blockchain Data
            →
            Multi-Hop Tracing
            →
            Wallet Network
            →
            Behaviour Analysis
            →
            Risk Assessment
            →
            Investigation Intelligence
            """
        )

        st.divider()

        st.markdown(
            "### Key Findings"
        )

        findings = []

        findings.append(
            f"{len(transactions)} blockchain transactions analysed."
        )

        findings.append(
            f"{len(wallet_hops)} wallet nodes identified in the traced network."
        )

        findings.append(
            f"{len(connections)} unique fund-flow connections identified."
        )

        if abnormal:

            findings.append(
                f"{len(abnormal)} abnormal transaction candidates detected."
            )

        if exchange_matches:

            findings.append(
                f"{len(exchange_matches)} potential exchange/VASP endpoint associations identified."
            )

        if cross_case_alerts:

            findings.append(
                f"{len(cross_case_alerts)} potential cross-case links identified."
            )

        for finding in findings:

            st.write(
                "• " + finding
            )

        st.caption(
            "These findings are analytical indicators and should "
            "be validated by authorized investigators."
        )

 # ========================================================
# TAB 2 - FUND FLOW GRAPH
# ========================================================

with tabs[1]:

    st.subheader(
        "🕸️ Interconnected Fund Flow Network"
    )

    st.write(
        "Actual blockchain transaction direction is shown as "
        "`from → to`. Hop numbers describe tracing distance."
    )

    # ----------------------------------------------------
    # VISUAL GRAPH
    # ----------------------------------------------------

    if transactions:

        render_fund_flow_graph(
            transactions=transactions,
            wallet_hops=wallet_hops,
            start_wallet=wallet_address,
            max_nodes=40,
            max_edges=80
        )

    else:

        st.warning(
            "No blockchain transactions available "
            "for fund-flow visualization."
        )

    # ----------------------------------------------------
    # CONNECTION TABLE
    # ----------------------------------------------------

    st.divider()

    st.markdown(
        "### 🔄 Fund Flow Connections"
    )

    if connections:

        display_connections = []

        for connection in connections[:80]:

            sender = connection.get(
                "from",
                ""
            )

            receiver = connection.get(
                "to",
                ""
            )

            display_connections.append(
                {
                    "From": short_address(sender),
                    "To": short_address(receiver),

                    "From Hop": connection.get(
                        "from_hop",
                        "-"
                    ),

                    "To Hop": connection.get(
                        "to_hop",
                        "-"
                    )
                }
            )

        st.dataframe(
            pd.DataFrame(
                display_connections
            ),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No fund-flow connections found."
        )
    # ========================================================
    # TAB 3 - SUSPICIOUS WALLETS
    # ========================================================

    with tabs[2]:

        st.subheader(
            "🚨 Suspicious Wallet Candidates"
        )

        wallet_scores = []

        for wallet, hop in wallet_hops.items():

            wallet_tx = []

            for tx in transactions:

                sender = normalize_address(
                    tx.get("from", "")
                )

                receiver = normalize_address(
                    tx.get("to", "")
                )

                if wallet in (
                    sender,
                    receiver
                ):

                    wallet_tx.append(tx)

            wallet_score = 0

            reasons = []

            if len(wallet_tx) >= 10:

                wallet_score += 20

                reasons.append(
                    "High transaction activity"
                )

            incoming = 0
            outgoing = 0

            for tx in wallet_tx:

                sender = normalize_address(
                    tx.get("from", "")
                )

                receiver = normalize_address(
                    tx.get("to", "")
                )

                if receiver == wallet:
                    incoming += 1

                if sender == wallet:
                    outgoing += 1

            if incoming >= 5:

                wallet_score += 20

                reasons.append(
                    "High fan-in"
                )

            if outgoing >= 5:

                wallet_score += 20

                reasons.append(
                    "High fan-out"
                )

            if hop >= 2:

                wallet_score += 10

                reasons.append(
                    "Multi-hop participant"
                )

            if wallet in [
                normalize_address(
                    match.get("address", "")
                )
                for match in exchange_matches
            ]:

                wallet_score += 15

                reasons.append(
                    "Potential exchange/VASP association"
                )

            wallet_score = min(
                wallet_score,
                100
            )

            if wallet_score >= 70:

                level = "HIGH"

            elif wallet_score >= 40:

                level = "MEDIUM"

            else:

                level = "LOW"

            wallet_scores.append(
                {
                    "Wallet": short_address(wallet),
                    "Full Address": wallet,
                    "Hop": hop,
                    "Transactions": len(wallet_tx),
                    "Incoming": incoming,
                    "Outgoing": outgoing,
                    "Risk Score": wallet_score,
                    "Risk Level": level,
                    "Reason": "; ".join(reasons)
                }
            )

        wallet_scores.sort(
            key=lambda x: x["Risk Score"],
            reverse=True
        )

        if wallet_scores:

            st.dataframe(
                pd.DataFrame(
                    wallet_scores[:20]
                ),
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info(
                "No wallet candidates available."
            )

        st.caption(
            "Wallet ranking represents analytical risk indicators, "
            "not proof of criminal activity."
        )

    # ========================================================
    # TAB 4 - TRANSACTION DNA
    # ========================================================

    with tabs[3]:

        st.subheader(
            "🧬 Transaction DNA"
        )

        if isinstance(dna, dict) and "error" not in dna:

            col1, col2, col3, col4 = st.columns(4)

            with col1:

                st.metric(
                    "Transaction Count",
                    dna.get(
                        "transaction_count",
                        len(transactions)
                    )
                )

            with col2:

                st.metric(
                    "Unique Senders",
                    dna.get(
                        "unique_senders",
                        0
                    )
                )

            with col3:

                st.metric(
                    "Unique Receivers",
                    dna.get(
                        "unique_receivers",
                        0
                    )
                )

            with col4:

                st.metric(
                    "Rapid Movements",
                    dna.get(
                        "rapid_movements",
                        0
                    )
                )

            st.divider()

            col1, col2, col3, col4 = st.columns(4)

            with col1:

                st.metric(
                    "Fan-In",
                    dna.get(
                        "fan_in",
                        0
                    )
                )

            with col2:

                st.metric(
                    "Fan-Out",
                    dna.get(
                        "fan_out",
                        0
                    )
                )

            with col3:

                st.metric(
                    "Native Transactions",
                    dna.get(
                        "native_transaction_count",
                        0
                    )
                )

            with col4:

                st.metric(
                    "Token Transactions",
                    dna.get(
                        "token_transaction_count",
                        0
                    )
                )

            st.divider()

            st.markdown(
                "### Behaviour Indicators"
            )

            indicators = dna.get(
                "behavior_indicators",
                []
            )

            if indicators:

                for indicator in indicators:

                    st.warning(
                        indicator
                    )

            else:

                st.success(
                    "No configured behaviour indicators detected."
                )

        else:

            st.info(
                "Transaction DNA unavailable."
            )

    # ========================================================
    # TAB 5 - ABNORMAL ACTIVITY
    # ========================================================

    with tabs[4]:

        st.subheader(
            "⚠️ Abnormal Transaction Candidates"
        )

        if abnormal:

            rows = []

            for item in abnormal:

                rows.append(
                    {
                        "Transaction": short_address(
                            item.get(
                                "hash",
                                "Unknown"
                            )
                        ),
                        "Score": item.get(
                            "score",
                            0
                        ),
                        "Reason": item.get(
                            "reason",
                            ""
                        )
                    }
                )

            st.dataframe(
                pd.DataFrame(rows),
                use_container_width=True,
                hide_index=True
            )

        else:

            st.success(
                "No configured abnormal transaction patterns detected."
            )

        st.caption(
            "Abnormal activity is rule-based analytical detection "
            "and should be reviewed with the underlying transaction."
        )

    # ========================================================
    # TAB 6 - VASP
    # ========================================================

    with tabs[5]:

        st.subheader(
            "🏦 VASP Analysis"
        )

        if vasp_matches:

            rows = []

            for match in vasp_matches:

                rows.append(
                    {
                        "Address": short_address(
                            match.get(
                                "address",
                                ""
                            )
                        ),
                        "Name": match.get(
                            "name",
                            "Unknown"
                        ),
                        "Type": match.get(
                            "type",
                            "Unknown"
                        ),
                        "Country": match.get(
                            "country",
                            "Unknown"
                        ),
                        "Role": match.get(
                            "transaction_role",
                            ""
                        ),
                        "Confidence": match.get(
                            "confidence",
                            ""
                        )
                    }
                )

            st.dataframe(
                pd.DataFrame(rows),
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info(
                "No VASP labels matched the current transaction set."
            )

        st.warning(
            "A blockchain address match indicates a potential "
            "association only. It does not establish that the "
            "service provider or its customer participated in fraud."
        )

    # ========================================================
    # TAB 7 - EXCHANGE INTELLIGENCE
    # ========================================================

    with tabs[6]:

        st.subheader(
            "🏦 Exchange Intelligence"
        )

        st.write(
            "CryptoShield compares traced transaction participants "
            "against the configured exchange/VASP label database."
        )

        match_count = exchange_summary.get(
            "match_count",
            len(exchange_matches)
        )

        st.metric(
            "Potential Exchange/VASP Matches",
            match_count
        )

        if exchange_matches:

            rows = []

            for match in exchange_matches:

                rows.append(
                    {
                        "Exchange / VASP": match.get(
                            "name",
                            "Unknown"
                        ),
                        "Address": short_address(
                            match.get(
                                "address",
                                ""
                            )
                        ),
                        "Type": match.get(
                            "type",
                            "Unknown"
                        ),
                        "Country": match.get(
                            "country",
                            "Unknown"
                        ),
                        "Hop": match.get(
                            "hop"
                        ),
                        "Role": ", ".join(
                            match.get(
                                "transaction_roles",
                                []
                            )
                        ),
                        "Association": match.get(
                            "association",
                            ""
                        )
                    }
                )

            st.dataframe(
                pd.DataFrame(rows),
                use_container_width=True,
                hide_index=True
            )

            st.info(
                "Investigative next step: authorized investigators "
                "may use applicable legal process to request "
                "additional off-chain information from a service "
                "provider where legally permitted."
            )

        else:

            st.success(
                "No configured exchange labels matched the traced network."
            )

        st.caption(
            "The demo uses a sample exchange-label database. "
            "A production deployment would require a continuously "
            "updated and appropriately sourced label database."
        )

    # ========================================================
    # TAB 8 - CROSS CASE
    # ========================================================

    with tabs[7]:

        st.subheader(
            "🔗 Cross-Case Intelligence"
        )

        st.write(
            "CryptoShield compares the current investigation "
            "against previously stored cases."
        )

        if cross_case_alerts:

            for alert in cross_case_alerts:

                strength = alert.get(
                    "strength",
                    "LOW"
                )

                if strength == "HIGH":

                    st.error(
                        f"🔴 {alert.get('message', '')}"
                    )

                elif strength == "MEDIUM":

                    st.warning(
                        f"🟠 {alert.get('message', '')}"
                    )

                else:

                    st.info(
                        f"🟡 {alert.get('message', '')}"
                    )

                shared_destinations = alert.get(
                    "shared_destinations",
                    []
                )

                shared_wallets = alert.get(
                    "shared_wallets",
                    []
                )

                if shared_destinations:

                    st.write(
                        "**Shared destination:**"
                    )

                    for address in shared_destinations:

                        st.code(
                            short_address(address)
                        )

                if shared_wallets:

                    st.write(
                        "**Shared intermediary wallet:**"
                    )

                    for address in shared_wallets:

                        st.code(
                            short_address(address)
                        )

        else:

            st.success(
                "No cross-case convergence detected."
            )

        st.caption(
            "Cross-case links are potential investigative leads "
            "and require validation."
        )

    # ========================================================
    # TAB 9 - INVESTIGATION REPORT
    # ========================================================

    with tabs[8]:

        st.subheader(
            "📄 Investigation Report"
        )

        st.markdown(
            "### Case Information"
        )

        col1, col2 = st.columns(2)

        with col1:

            st.write(
                "**Case ID:**",
                st.session_state.case_id or "Not saved"
            )

            st.write(
                "**Reported Wallet:**"
            )

            st.code(
                wallet_address
            )

        with col2:

            st.write(
                "**Blockchain:**",
                data["chain"]
            )

            st.write(
                "**Generated:**",
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

        st.divider()

        st.markdown(
            "### Transaction Summary"
        )

        st.write(
            f"- Transactions analysed: {len(transactions)}"
        )

        st.write(
            f"- Wallet nodes: {len(wallet_hops)}"
        )

        st.write(
            f"- Fund-flow connections: {len(connections)}"
        )

        st.write(
            f"- Maximum observed hop: "
            f"{max(wallet_hops.values()) if wallet_hops else 0}"
        )

        st.divider()

        st.markdown(
            "### Risk Assessment"
        )

        st.metric(
            "Explainable Risk Score",
            f"{risk_score}/100"
        )

        st.write(
            f"Risk level: **{risk_level}**"
        )

        st.divider()

        st.markdown(
            "### Investigation Findings"
        )

        st.write(
            f"- Transaction DNA generated: "
            f"{'Yes' if dna else 'No'}"
        )

        st.write(
            f"- Abnormal transaction candidates: "
            f"{len(abnormal)}"
        )

        st.write(
            f"- Potential VASP associations: "
            f"{len(vasp_matches)}"
        )

        st.write(
            f"- Potential exchange associations: "
            f"{len(exchange_matches)}"
        )

        st.write(
            f"- Potential cross-case links: "
            f"{len(cross_case_alerts)}"
        )

        st.divider()

        st.markdown(
            "### Evidence Interpretation"
        )

        st.info(
            "This report contains blockchain-derived analytical "
            "indicators. It does not identify a person's real-world "
            "identity, establish criminal liability, or replace "
            "formal investigation."
        )

        # ----------------------------------------------------
        # JSON report
        # ----------------------------------------------------

        report_data = generate_report_data(
            wallet_address=wallet_address,
            chain=data["chain"],
            transactions=transactions,
            wallet_hops=wallet_hops,
            connections=connections,
            dna=dna,
            abnormal=abnormal,
            vasp_matches=vasp_matches,
            exchange_matches=exchange_matches,
            cross_case_alerts=cross_case_alerts,
            risk_score=risk_score,
            risk_level=risk_level
        )

        import json

        report_json = json.dumps(
            report_data,
            indent=4,
            default=str
        )

        st.download_button(
            "⬇️ Export Investigation Data (JSON)",
            data=report_json,
            file_name=(
                f"{st.session_state.case_id or 'cryptoshield_case'}.json"
            ),
            mime="application/json",
            use_container_width=True
        )


# ============================================================
# INITIAL SCREEN
# ============================================================

else:

    st.markdown(
        "## 🔎 Start an Investigation"
    )

    st.write(
        "Enter a victim-reported suspect wallet address "
        "from the sidebar and click **Analyse Wallet**."
    )

    st.divider()

    col1, col2, col3 = st.columns(3)

    with col1:

        st.markdown(
            "### 🔗 1. Blockchain Tracing"
        )

        st.write(
            "Collect transaction data and reconstruct "
            "multi-hop wallet connections."
        )

    with col2:

        st.markdown(
            "### 🧬 2. Behaviour Analysis"
        )

        st.write(
            "Generate Transaction DNA and detect "
            "suspicious behavioural indicators."
        )

    with col3:

        st.markdown(
            "### 🏦 3. Exchange Intelligence"
        )

        st.write(
            "Identify potential VASP or exchange "
            "associations from configured labels."
        )

    st.divider()

    st.markdown(
        "### 🛡️ Investigation Pipeline"
    )

    st.code(
        """
Reported Wallet
       ↓
Blockchain Data Collection
       ↓
BFS Multi-Hop Tracing
       ↓
Interconnected Wallet Graph
       ↓
Transaction DNA
       ↓
Abnormal Activity Detection
       ↓
VASP / Exchange Intelligence
       ↓
Cross-Case Intelligence
       ↓
Explainable Risk Assessment
       ↓
Investigation Report
        """
    )

    st.caption(
        "CryptoShield — From Suspicion to Structured Blockchain Intelligence"
    )
