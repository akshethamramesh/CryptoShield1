import streamlit as st
import streamlit.components.v1 as components

from blockchain import recursive_trace
from abnormal_detection import (
    analyze_abnormal_transactions
)
from vasp_detection import (
    analyze_vasp_associations
)

from pyvis.network import Network


# ==================================================
# PAGE CONFIG
# ==================================================

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
)


# ==================================================
# CUSTOM CSS
# ==================================================

st.markdown(
    """
    <style>

    .main {
        background-color: #0e1117;
    }

    .section-title {
        font-size: 26px;
        font-weight: 700;
        margin-top: 25px;
        margin-bottom: 15px;
    }

    .metric-card {
        background-color: #161b22;
        border-radius: 12px;
        padding: 18px;
        text-align: center;
        border: 1px solid #30363d;
    }

    .metric-title {
        font-size: 14px;
        color: #9da7b3;
    }

    .metric-value {
        font-size: 28px;
        font-weight: 700;
        margin-top: 5px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ==================================================
# SIDEBAR
# ==================================================

st.sidebar.title(
    "Investigation Settings"
)

chain = st.sidebar.selectbox(
    "Blockchain",
    [
        "Ethereum",
        "BSC"
    ]
)

wallet = st.sidebar.text_input(
    "Suspect Wallet Address",
    value="0x5c43B1eD97e52d009611D89b74fA829FE4ac56b1"
)

max_hops = st.sidebar.slider(
    "Maximum Hops",
    min_value=1,
    max_value=2,
    value=1
)

analyze_button = st.sidebar.button(
    "🔍 Analyze Wallet",
    use_container_width=True
)


# ==================================================
# HEADER
# ==================================================

st.title(
    "🛡️ CryptoShield"
)

st.subheader(
    "Blockchain Fraud Intelligence & Investigation System"
)


# ==================================================
# SESSION STATE
# ==================================================

if "analysis_done" not in st.session_state:

    st.session_state.analysis_done = False

if "trace_nodes" not in st.session_state:

    st.session_state.trace_nodes = []

if "transactions" not in st.session_state:

    st.session_state.transactions = []

if "abnormal_results" not in st.session_state:

    st.session_state.abnormal_results = []

if "vasp_results" not in st.session_state:

    st.session_state.vasp_results = []


# ==================================================
# ANALYSIS
# ==================================================

if analyze_button:

    if not wallet:

        st.error(
            "Please enter a wallet address."
        )

        st.stop()

    with st.spinner(
        "Analyzing blockchain transactions..."
    ):

        try:

            trace_nodes, transactions = recursive_trace(
                wallet,
                chain,
                max_hops
            )

            st.session_state.trace_nodes = (
                trace_nodes
            )

            st.session_state.transactions = (
                transactions
            )

            # Abnormal transaction analysis
            abnormal_results = (
                analyze_abnormal_transactions(
                    transactions
                )
            )

            st.session_state.abnormal_results = (
                abnormal_results
            )

            # VASP analysis
            vasp_results = (
                analyze_vasp_associations(
                    trace_nodes
                )
            )

            st.session_state.vasp_results = (
                vasp_results
            )

            st.session_state.analysis_done = True

            st.success(
                "Blockchain analysis completed."
            )

        except Exception as e:

            st.error(
                f"Analysis failed: {e}"
            )

            st.stop()


# ==================================================
# SHOW RESULTS
# ==================================================

if st.session_state.analysis_done:

    trace_nodes = (
        st.session_state.trace_nodes
    )

    transactions = (
        st.session_state.transactions
    )

    abnormal_results = (
        st.session_state.abnormal_results
    )

    vasp_results = (
        st.session_state.vasp_results
    )


    # ==================================================
    # CALCULATE METRICS
    # ==================================================

    wallet_count = len(
        trace_nodes
    )

    max_detected_hop = 0

    for node in trace_nodes:

        try:

            hop = int(
                node.get(
                    "hop",
                    0
                )
            )

            max_detected_hop = max(
                max_detected_hop,
                hop
            )

        except:

            pass


    # ==================================================
    # TRANSACTION DNA
    # ==================================================

    unique_recipients = set()

    outgoing_count = 0

    for tx in transactions:

        from_wallet = tx.get(
            "from",
            ""
        ).lower()

        to_wallet = tx.get(
            "to",
            ""
        ).lower()

        if from_wallet == wallet.lower():

            outgoing_count += 1

            if to_wallet:

                unique_recipients.add(
                    to_wallet
                )


    rapid_activity = False

    for alert in abnormal_results:

        for reason in alert.get(
            "reasons",
            []
        ):

            if "60 seconds" in reason:

                rapid_activity = True


    dna_score = 0

    if len(transactions) > 100:

        dna_score += 25

    if len(unique_recipients) > 20:

        dna_score += 25

    if outgoing_count > 20:

        dna_score += 15

    if rapid_activity:

        dna_score += 20

    if len(abnormal_results) > 0:

        dna_score += 15

    dna_score = min(
        dna_score,
        100
    )


    # ==================================================
    # THREAT SCORE
    # ==================================================

    threat_score = 0

    if len(transactions) > 100:

        threat_score += 20

    if len(abnormal_results) >= 5:

        threat_score += 20

    if rapid_activity:

        threat_score += 20

    if len(unique_recipients) > 20:

        threat_score += 20

    if max_detected_hop >= 2:

        threat_score += 10

    if dna_score >= 70:

        threat_score += 10

    threat_score = min(
        threat_score,
        100
    )


    # ==================================================
    # RISK SCORE
    # ==================================================

    risk_score = 0

    risk_factors = []

    if len(transactions) > 100:

        risk_score += 15

        risk_factors.append(
            "High transaction activity"
        )

    if wallet_count > 5:

        risk_score += 15

        risk_factors.append(
            "Multiple connected wallets"
        )

    if max_detected_hop >= 2:

        risk_score += 15

        risk_factors.append(
            "Multi-hop fund movement"
        )

    if abnormal_results:

        risk_score += 15

        risk_factors.append(
            "Abnormal transaction behaviour"
        )

    if dna_score >= 70:

        risk_score += 10

        risk_factors.append(
            "Irregular transaction DNA"
        )

    if threat_score >= 60:

        risk_score += 10

        risk_factors.append(
            "Moderate/high threat behaviour indicators"
        )

    if vasp_results:

        risk_score += 10

        risk_factors.append(
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
    # INVESTIGATION OVERVIEW
    # ==================================================

    st.markdown(
        '<div class="section-title">'
        '📊 Investigation Overview'
        '</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:

        st.metric(
            "Transactions",
            len(transactions)
        )

    with col2:

        st.metric(
            "Wallets",
            wallet_count
        )

    with col3:

        st.metric(
            "Maximum Hop",
            max_detected_hop
        )

    with col4:

        st.metric(
            "Abnormal Alerts",
            len(abnormal_results)
        )

    with col5:

        st.metric(
            "Risk Score",
            f"{risk_score}/100"
        )


    # ==================================================
    # RISK ASSESSMENT
    # ==================================================

    st.markdown(
        '<div class="section-title">'
        '⚠️ Risk Assessment'
        '</div>',
        unsafe_allow_html=True
    )

    if risk_level == "HIGH":

        st.error(
            f"### Risk Level: {risk_level}"
        )

    elif risk_level == "MEDIUM":

        st.warning(
            f"### Risk Level: {risk_level}"
        )

    else:

        st.success(
            f"### Risk Level: {risk_level}"
        )

    st.write(
        f"**Risk Score:** {risk_score}/100"
    )

    st.write(
        "**Risk Factors:**"
    )

    if risk_factors:

        for factor in risk_factors:

            st.write(
                f"• {factor}"
            )

    else:

        st.write(
            "• No major risk indicators detected"
        )


    # ==================================================
    # THREAT BEHAVIOUR
    # ==================================================

    st.markdown(
        '<div class="section-title">'
        '🚨 Threat Behaviour Analysis'
        '</div>',
        unsafe_allow_html=True
    )

    st.write(
        f"**Threat Score:** "
        f"{threat_score}/100"
    )

    threat_signals = []

    if len(transactions) > 100:

        threat_signals.append(
            "High transaction activity"
        )

    if len(abnormal_results) >= 5:

        threat_signals.append(
            "Multiple abnormal transaction signals"
        )

    if rapid_activity:

        threat_signals.append(
            "Rapid fund movement"
        )

    if len(unique_recipients) > 20:

        threat_signals.append(
            "High recipient diversity"
        )

    if max_detected_hop >= 2:

        threat_signals.append(
            "Multi-hop fund movement"
        )

    if dna_score >= 70:

        threat_signals.append(
            "Irregular transaction DNA"
        )

    for signal in threat_signals:

        st.write(
            f"✓ {signal}"
        )


    # ==================================================
    # TRANSACTION DNA
    # ==================================================

    st.markdown(
        '<div class="section-title">'
        '🧬 Transaction DNA'
        '</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "DNA Score",
            f"{dna_score}/100"
        )

    with col2:

        st.metric(
            "Unique Recipients",
            len(unique_recipients)
        )

    with col3:

        st.metric(
            "Rapid Activity",
            "YES"
            if rapid_activity
            else "NO"
        )

    if dna_score >= 70:

        behavior_profile = (
            "High-activity distribution pattern"
        )

    elif dna_score >= 40:

        behavior_profile = (
            "Moderate transaction activity pattern"
        )

    else:

        behavior_profile = (
            "Low-activity transaction pattern"
        )

    st.write(
        f"**Behaviour Profile:** "
        f"{behavior_profile}"
    )

    st.write(
        "**DNA Signals:**"
    )

    dna_signals = []

    if len(transactions) > 100:

        dna_signals.append(
            "High transaction activity"
        )

    if len(unique_recipients) > 20:

        dna_signals.append(
            "High recipient diversity"
        )

    if outgoing_count > 20:

        dna_signals.append(
            "High outgoing activity"
        )

    if rapid_activity:

        dna_signals.append(
            "Rapid transaction activity"
        )

    if dna_signals:

        for signal in dna_signals:

            st.write(
                f"✓ {signal}"
            )


    # ==================================================
    # ABNORMAL TRANSACTIONS
    # ==================================================

    st.markdown(
        '<div class="section-title">'
        '🚨 Abnormal Transaction Detection'
        '</div>',
        unsafe_allow_html=True
    )

    st.write(
        f"{len(abnormal_results)} potentially "
        f"abnormal financial transaction "
        f"pattern(s) detected."
    )

    for index, alert in enumerate(
        abnormal_results[:10],
        start=1
    ):

        with st.expander(
            f"Alert {index} — "
            f"Score {alert['score']}"
        ):

            st.write(
                "**Transaction:**"
            )

            st.code(
                alert["hash"]
            )

            st.write(
                f"**From:** "
                f"{alert['from']}"
            )

            st.write(
                f"**To:** "
                f"{alert['to']}"
            )

            st.write(
                f"**Value:** "
                f"{alert['value']} "
                f"{alert['asset']}"
            )

            st.write(
                f"**Timestamp:** "
                f"{alert['timestamp']}"
            )

            st.write(
                "**Reasons:**"
            )

            for reason in alert[
                "reasons"
            ]:

                st.write(
                    f"✓ {reason}"
                )


    # ==================================================
    # FUND FLOW TRACE
    # ==================================================

    st.markdown(
        '<div class="section-title">'
        '🔗 Fund Flow Trace'
        '</div>',
        unsafe_allow_html=True
    )

    st.write(
        f"**START** `{wallet}`"
    )

    for node in trace_nodes:

        if node.get("hop", 0) == 0:
            continue

        address = node.get(
            "wallet",
            ""
        )

        hop = node.get(
            "hop",
            0
        )

        st.write(
            f"↳ **HOP {hop}** "
            f"`{address}`"
        )


    # ==================================================
    # 🔥 ACTUAL GRAPH
    # ==================================================

    st.markdown(
        '<div class="section-title">'
        '🌐 Interactive Fund Flow Graph'
        '</div>',
        unsafe_allow_html=True
    )

    try:

        graph = Network(
            height="650px",
            width="100%",
            bgcolor="#0e1117",
            font_color="white",
            directed=True,
            cdn_resources="in_line"
        )

        graph.set_options(
            """
            {
              "nodes": {
                "shape": "dot",
                "size": 22,
                "font": {
                  "size": 14,
                  "color": "white"
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
                }
              },

              "physics": {
                "enabled": true,

                "stabilization": {
                  "enabled": true,
                  "iterations": 200
                },

                "barnesHut": {
                  "gravitationalConstant": -5000,
                  "centralGravity": 0.2,
                  "springLength": 180,
                  "springConstant": 0.04,
                  "damping": 0.09
                }
              },

              "interaction": {
                "hover": true,
                "navigationButtons": true,
                "zoomView": true
              }
            }
            """
        )

        # ------------------------------------------
        # ADD NODES
        # ------------------------------------------

        added_nodes = set()

        for node in trace_nodes:

            address = node.get(
                "wallet",
                ""
            )

            hop = node.get(
                "hop",
                0
            )

            if not address:
                continue

            address = address.lower()

            if address in added_nodes:
                continue

            added_nodes.add(
                address
            )

            short_address = (
                address[:6]
                + "..."
                + address[-4:]
            )

            if hop == 0:

                label = (
                    "START\n"
                    + short_address
                )

            else:

                label = (
                    f"HOP {hop}\n"
                    + short_address
                )

            graph.add_node(
                address,
                label=label,
                title=(
                    f"Wallet: {address}"
                    f"<br>Hop: {hop}"
                ),
                size=32
                if hop == 0
                else 22
            )


        # ------------------------------------------
        # ADD EDGES
        # ------------------------------------------

        added_edges = set()

        for tx in transactions:

            from_wallet = tx.get(
                "from",
                ""
            ).lower()

            to_wallet = tx.get(
                "to",
                ""
            ).lower()

            tx_hash = tx.get(
                "hash",
                ""
            )

            if not from_wallet:
                continue

            if not to_wallet:
                continue

            if (
                from_wallet
                not in added_nodes
            ):
                continue

            if (
                to_wallet
                not in added_nodes
            ):
                continue

            edge_key = (
                from_wallet,
                to_wallet,
                tx_hash
            )

            if edge_key in added_edges:

                continue

            added_edges.add(
                edge_key
            )

            try:

                value = float(
                    tx.get(
                        "value",
                        0
                    )
                )

                value_text = (
                    f"{value:.4f} ETH"
                )

            except:

                value_text = (
                    str(
                        tx.get(
                            "value",
                            0
                        )
                    )
                )

            graph.add_edge(
                from_wallet,
                to_wallet,
                title=(
                    f"Transaction"
                    f"<br>Value: "
                    f"{value_text}"
                    f"<br>Hash: "
                    f"{tx_hash[:16]}..."
                )
            )


        # ------------------------------------------
        # GENERATE HTML
        # ------------------------------------------

        graph_html = (
            graph.generate_html()
        )

        # ------------------------------------------
        # RENDER
        # ------------------------------------------

        components.html(
            graph_html,
            height=670,
            scrolling=True
        )

    except Exception as e:

        st.error(
            "Graph rendering failed."
        )

        st.code(
            str(e)
        )


    # ==================================================
    # VASP
    # ==================================================

    st.markdown(
        '<div class="section-title">'
        '🏦 Potential VASP Associations'
        '</div>',
        unsafe_allow_html=True
    )

    if vasp_results:

        for result in vasp_results:

            st.success(
                f"🏦 {result['name']}"
            )

            st.write(
                f"**Type:** "
                f"{result['type']}"
            )

            st.write(
                f"**Country:** "
                f"{result['country']}"
            )

            st.write(
                f"**Hop:** "
                f"{result['hop']}"
            )

            st.write(
                f"**Confidence:** "
                f"{result['confidence']}%"
            )

            st.write(
                "**Evidence:**"
            )

            for evidence in result[
                "evidence"
            ]:

                st.write(
                    f"✓ {evidence}"
                )

            st.code(
                result["wallet"]
            )

    else:

        st.info(
            "No known VASP association "
            "found in the current "
            "address intelligence registry."
        )

    st.warning(
        "VASP associations are analytical "
        "signals and should not be treated "
        "as proof of ownership or criminal activity."
    )


    # ==================================================
    # TRANSACTION EVIDENCE
    # ==================================================

    st.markdown(
        '<div class="section-title">'
        '📜 Transaction Evidence'
        '</div>',
        unsafe_allow_html=True
    )

    if transactions:

        evidence_rows = []

        for tx in transactions[:100]:

            evidence_rows.append(
                {
                    "Hash":
                        tx.get(
                            "hash",
                            ""
                        )[:18] + "...",

                    "From":
                        tx.get(
                            "from",
                            ""
                        )[:18] + "...",

                    "To":
                        tx.get(
                            "to",
                            ""
                        )[:18] + "...",

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

                    "Timestamp":
                        tx.get(
                            "timestamp",
                            ""
                        )
                }
            )

        st.dataframe(
            evidence_rows,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No transaction evidence available."
        )


    # ==================================================
    # INVESTIGATION SUMMARY
    # ==================================================

    st.markdown(
        '<div class="section-title">'
        '📝 Investigation Summary'
        '</div>',
        unsafe_allow_html=True
    )

    st.write(
        f"**Blockchain:** {chain}"
    )

    st.write(
        f"**Suspect Wallet:** "
        f"`{wallet}`"
    )

    st.write(
        f"**Transactions Analyzed:** "
        f"{len(transactions)}"
    )

    st.write(
        f"**Wallets Discovered:** "
        f"{wallet_count}"
    )

    st.write(
        f"**Maximum Hop:** "
        f"{max_detected_hop}"
    )

    st.write(
        f"**Abnormal Alerts:** "
        f"{len(abnormal_results)}"
    )

    st.write(
        f"**Transaction DNA:** "
        f"{dna_score}/100"
    )

    st.write(
        f"**Threat Score:** "
        f"{threat_score}/100"
    )

    st.write(
        f"**Potential VASP Associations:** "
        f"{len(vasp_results)}"
    )

    st.write(
        f"**Risk Score:** "
        f"{risk_score}/100"
    )

    st.write(
        f"**Risk Level:** "
        f"{risk_level}"
    )


    # ==================================================
    # DISCLAIMER
    # ==================================================

    st.info(
        "CryptoShield is an investigative analytics "
        "prototype. Blockchain patterns and VASP "
        "associations are analytical signals and "
        "require human verification."
    )
