import os
import tempfile

import streamlit as st

from blockchain import trace_wallet
from transaction_dna import analyze_transaction_dna
from abnormal_detection import detect_abnormal_transactions
from vasp_detection import detect_vasp
from report_generator import generate_pdf_report


st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# FUNCTIONS
# ============================================================

def calculate_risk(
    transaction_count,
    connected_wallets,
    rapid_movements,
    abnormal_count,
    pattern_count,
    vasp_count
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

    if abnormal_count >= 10:
        score += 15

    elif abnormal_count >= 5:
        score += 8

    if pattern_count >= 3:
        score += 15

    elif pattern_count >= 1:
        score += 8

    if vasp_count >= 1:
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


def detect_patterns(
    transactions,
    connected_wallets
):

    patterns = []

    if not transactions:
        return patterns

    senders = set()
    receivers = set()

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
            senders.add(sender)

        if receiver:
            receivers.add(receiver)

    if len(receivers) >= 5:

        patterns.append(
            {
                "pattern": "Fund Splitting",
                "description": (
                    "Funds are distributed across "
                    "multiple destination wallets."
                ),
                "confidence": "Analytical indicator"
            }
        )

    if len(senders) >= 5:

        patterns.append(
            {
                "pattern": "Fund Consolidation",
                "description": (
                    "The wallet interacts with funds "
                    "originating from multiple sources."
                ),
                "confidence": "Analytical indicator"
            }
        )

    if len(connected_wallets) >= 5:

        patterns.append(
            {
                "pattern": "Multi-Hop Network",
                "description": (
                    "The reported wallet is connected "
                    "to a broader transaction network."
                ),
                "confidence": "Analytical indicator"
            }
        )

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
                timestamps.append(timestamp)

        except Exception:
            pass

    timestamps.sort()

    rapid = 0

    for i in range(1, len(timestamps)):

        if (
            timestamps[i]
            - timestamps[i - 1]
            <= 300
        ):

            rapid += 1

    if rapid >= 5:

        patterns.append(
            {
                "pattern": "Rapid Fund Movement",
                "description": (
                    "Multiple transactions occurred "
                    "within short time intervals."
                ),
                "confidence": "Analytical indicator"
            }
        )

    return patterns


# ============================================================
# HEADER
# ============================================================

st.title(
    "🛡️ CryptoShield"
)

st.subheader(
    "Blockchain Fraud Intelligence & Investigation System"
)

st.write(
    "Convert a victim-reported suspect wallet "
    "into explainable blockchain investigation intelligence."
)

st.info(
    "CryptoShield analyzes a wallet address provided "
    "by the victim or investigator. It does not identify "
    "a person or automatically declare someone a criminal."
)


# ============================================================
# INPUT
# ============================================================

st.sidebar.header(
    "Investigation Input"
)

blockchain = st.sidebar.selectbox(
    "Select Blockchain",
    [
        "Ethereum",
        "BSC"
    ]
)

reported_wallet = st.sidebar.text_input(
    "Victim-Reported Suspect Wallet",
    placeholder="0x..."
)

max_hops = st.sidebar.slider(
    "Maximum Tracing Hops",
    min_value=1,
    max_value=3,
    value=2
)


analyze_button = st.sidebar.button(
    "🔍 Analyze Wallet",
    use_container_width=True
)


# ============================================================
# ANALYSIS
# ============================================================

if analyze_button:

    if not reported_wallet:

        st.error(
            "Please enter a wallet address."
        )

        st.stop()

    if not reported_wallet.startswith("0x"):

        st.error(
            "Please enter a valid EVM wallet address "
            "starting with 0x."
        )

        st.stop()

    with st.spinner(
        "Collecting blockchain data and tracing wallet network..."
    ):

        try:

            trace_data = trace_wallet(
                reported_wallet,
                chain=blockchain,
                max_hop=max_hops
            )

        except Exception as error:

            st.error(
                f"Analysis failed: {error}"
            )

            st.stop()

    transactions = trace_data.get(
        "transactions",
        []
    )

    connected_wallets = trace_data.get(
        "connected_wallets",
        []
    )

    # --------------------------------------------------------
    # DNA
    # --------------------------------------------------------

    dna = analyze_transaction_dna(
        transactions,
        reported_wallet
    )

    # --------------------------------------------------------
    # ABNORMAL
    # --------------------------------------------------------

    abnormal_alerts = detect_abnormal_transactions(
        transactions
    )

    # --------------------------------------------------------
    # PATTERNS
    # --------------------------------------------------------

    patterns = detect_patterns(
        transactions,
        connected_wallets
    )

    # --------------------------------------------------------
    # VASP
    # --------------------------------------------------------

    vasp_results = detect_vasp(
        transactions
    )

    # --------------------------------------------------------
    # RISK
    # --------------------------------------------------------

    risk_score, risk_level = calculate_risk(
        transaction_count=len(transactions),
        connected_wallets=len(connected_wallets),
        rapid_movements=dna.get(
            "rapid_movements",
            0
        ),
        abnormal_count=len(
            abnormal_alerts
        ),
        pattern_count=len(patterns),
        vasp_count=len(vasp_results)
    )

    # ========================================================
    # DASHBOARD
    # ========================================================

    st.success(
        "Blockchain analysis completed."
    )

    st.markdown(
        "## 📊 Investigation Overview"
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Transactions",
        len(transactions)
    )

    col2.metric(
        "Connected Wallets",
        len(connected_wallets)
    )

    col3.metric(
        "Tracing Hops",
        max_hops
    )

    col4.metric(
        "Risk Score",
        f"{risk_score}/100"
    )

    # ========================================================
    # RISK
    # ========================================================

    if risk_level == "HIGH":

        st.error(
            f"🚨 Analytical Risk Level: {risk_level}"
        )

    elif risk_level == "MEDIUM":

        st.warning(
            f"⚠️ Analytical Risk Level: {risk_level}"
        )

    else:

        st.success(
            f"✅ Analytical Risk Level: {risk_level}"
        )

    st.caption(
        "Risk score is an analytical indicator, "
        "not a criminal verdict."
    )

    # ========================================================
    # TRANSACTION DNA
    # ========================================================

    st.markdown(
        "## 🧬 Transaction DNA"
    )

    dna_col1, dna_col2, dna_col3, dna_col4 = st.columns(4)

    dna_col1.metric(
        "Native Transactions",
        dna.get(
            "native_transaction_count",
            0
        )
    )

    dna_col2.metric(
        "Token Transactions",
        dna.get(
            "token_transaction_count",
            0
        )
    )

    dna_col3.metric(
        "Unique Senders",
        dna.get(
            "unique_senders",
            0
        )
    )

    dna_col4.metric(
        "Unique Receivers",
        dna.get(
            "unique_receivers",
            0
        )
    )

    st.write(
        f"**Fan-in:** {dna.get('fan_in', 0)}"
    )

    st.write(
        f"**Fan-out:** {dna.get('fan_out', 0)}"
    )

    st.write(
        f"**Rapid movements:** "
        f"{dna.get('rapid_movements', 0)}"
    )

    if dna.get("behavior_indicators"):

        for indicator in dna[
            "behavior_indicators"
        ]:

            st.warning(
                f"• {indicator}"
            )

    # ========================================================
    # PATTERNS
    # ========================================================

    st.markdown(
        "## 🚨 Suspicious Behaviour Patterns"
    )

    if patterns:

        for pattern in patterns:

            st.warning(
                f"**{pattern['pattern']}**\n\n"
                f"{pattern['description']}\n\n"
                f"Confidence: {pattern['confidence']}"
            )

    else:

        st.info(
            "No predefined suspicious patterns detected."
        )

    # ========================================================
    # ABNORMAL TRANSACTIONS
    # ========================================================

    st.markdown(
        "## ⚠️ Abnormal Transactions"
    )

    if abnormal_alerts:

        for alert in abnormal_alerts[:20]:

            st.write(
                f"**Score:** {alert['score']} | "
                f"**Transaction:** {alert['hash']} | "
                f"**Reason:** {alert['reason']}"
            )

    else:

        st.info(
            "No abnormal transaction alerts."
        )

    # ========================================================
    # VASP
    # ========================================================

    st.markdown(
        "## 🏦 Potential VASP / Exchange Association"
    )

    if vasp_results:

        for vasp in vasp_results:

            st.warning(
                f"**{vasp['name']}**\n\n"
                f"Type: {vasp['type']}\n\n"
                f"Address: {vasp['address']}\n\n"
                f"Confidence: {vasp['confidence']}"
            )

    else:

        st.info(
            "No potential VASP association identified "
            "from the current registry."
        )

    # ========================================================
    # CONNECTED WALLETS
    # ========================================================

    st.markdown(
        "## 🔗 Connected Wallets"
    )

    if connected_wallets:

        for wallet in connected_wallets[:50]:

            st.code(
                wallet
            )

    else:

        st.info(
            "No connected wallets identified."
        )

    # ========================================================
    # RAW TRANSACTIONS
    # ========================================================

    st.markdown(
        "## 📜 Blockchain Transactions"
    )

    if transactions:

        display_rows = []

        for tx in transactions[:100]:

            display_rows.append(
                {
                    "Hash": tx.get(
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
                        ""
                    ),
                    "Type": tx.get(
                        "type",
                        ""
                    )
                }
            )

        st.dataframe(
            display_rows,
            use_container_width=True
        )

    # ========================================================
    # REPORT
    # ========================================================

    st.markdown(
        "## 📄 Investigation Report"
    )

    if st.button(
        "Generate PDF Report"
    ):

        temp_file = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".pdf"
        )

        temp_file.close()

        try:

            pdf_path = generate_pdf_report(
                file_path=temp_file.name,
                wallet_address=reported_wallet,
                chain=blockchain,
                transactions=transactions,
                connected_wallets=connected_wallets,
                max_hop=max_hops,
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

                st.download_button(
                    label="⬇️ Download Investigation Report",
                    data=pdf_file.read(),
                    file_name="CryptoShield_Investigation_Report.pdf",
                    mime="application/pdf"
                )

            st.success(
                "PDF report generated successfully."
            )

        except Exception as error:

            st.error(
                f"PDF generation failed: {error}"
            )

        finally:

            if os.path.exists(
                temp_file.name
            ):

                try:
                    os.remove(
                        temp_file.name
                    )
                except Exception:
                    pass


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "CryptoShield — Blockchain Fraud Intelligence & Investigation System"
)

st.caption(
    "Analytical intelligence only. "
    "Findings require independent verification."
)
