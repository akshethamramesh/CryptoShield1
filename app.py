import streamlit as st
import pandas as pd
import streamlit.components.v1 as components
from pyvis.network import Network

from blockchain import recursive_trace
from abnormal_detection import detect_abnormal_transactions
from vasp_detection import detect_vasp


# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------

st.set_page_config(
    page_title="CryptoShield",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# TITLE
# --------------------------------------------------

st.title("🛡️ CryptoShield")

st.subheader(
    "Blockchain Fraud Intelligence & Investigation System"
)

st.write(
    "Analyze a reported cryptocurrency wallet, "
    "trace fund movement, detect abnormal behaviour, "
    "and identify potential VASP associations."
)

st.warning(
    "CryptoShield provides analytical indicators only. "
    "A risk score or VASP association does not prove "
    "criminal activity or ownership."
)


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.header("Investigation Settings")

chain = st.sidebar.selectbox(
    "Blockchain",
    ["Ethereum", "BSC"]
)

wallet_address = st.sidebar.text_input(
    "Suspect Wallet Address"
)

max_hops = st.sidebar.slider(
    "Maximum Hops",
    min_value=1,
    max_value=2,
    value=1
)

analyze_button = st.sidebar.button(
    "🔍 Start Investigation",
    use_container_width=True
)


# --------------------------------------------------
# WAIT FOR INPUT
# --------------------------------------------------

if not analyze_button:

    st.info(
        "Enter a suspect wallet address from the sidebar "
        "and click Start Investigation."
    )

    st.markdown("### Investigation Flow")

    st.write(
        "Victim Report → Suspect Wallet → "
        "Blockchain Analysis → Multi-Hop Tracing → "
        "Behaviour Analysis → VASP Intelligence → Evidence"
    )

    st.stop()


# --------------------------------------------------
# VALIDATE WALLET
# --------------------------------------------------

if not wallet_address:

    st.error(
        "Please enter a wallet address."
    )

    st.stop()


if not wallet_address.startswith("0x"):

    st.error(
        "Invalid wallet address. "
        "Ethereum/BSC addresses normally start with 0x."
    )

    st.stop()


# --------------------------------------------------
# BLOCKCHAIN TRACE
# --------------------------------------------------

with st.spinner(
    "Analyzing blockchain transactions..."
):

    try:

        trace_result = recursive_trace(
            wallet_address,
            chain,
            max_hops
        )

    except Exception as e:

        st.error(
            f"Analysis failed: {str(e)}"
        )

        st.stop()


transactions = trace_result.get(
    "transactions",
    []
)

wallets = trace_result.get(
    "wallets",
    []
)

actual_max_hop = trace_result.get(
    "max_hop",
    0
)


# --------------------------------------------------
# BASIC METRICS
# --------------------------------------------------

transaction_count = len(
    transactions
)

wallet_count = len(
    wallets
)


# --------------------------------------------------
# ABNORMAL DETECTION
# --------------------------------------------------

try:

    abnormal_alerts = detect_abnormal_transactions(
        transactions
    )

except Exception:

    abnormal_alerts = []


abnormal_count = len(
    abnormal_alerts
)


# --------------------------------------------------
# VASP DETECTION
# --------------------------------------------------

try:

    vasp_results = detect_vasp(
        transactions
    )

except Exception:

    vasp_results = []


# --------------------------------------------------
# RISK CALCULATION
# --------------------------------------------------

risk_score = 0
risk_factors = []


if transaction_count >= 100:

    risk_score += 20

    risk_factors.append(
        "High transaction activity"
    )


if wallet_count >= 20:

    risk_score += 20

    risk_factors.append(
        "High wallet connectivity"
    )


if actual_max_hop >= 2:

    risk_score += 15

    risk_factors.append(
        "Multi-hop fund movement"
    )


if abnormal_count >= 5:

    risk_score += 25

    risk_factors.append(
        "Multiple abnormal transaction signals"
    )


if len(vasp_results) > 0:

    risk_score += 20

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


# --------------------------------------------------
# INVESTIGATION COMPLETED
# --------------------------------------------------

st.success(
    "Blockchain analysis completed."
)


# --------------------------------------------------
# OVERVIEW
# --------------------------------------------------

st.header("Investigation Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Transactions",
        transaction_count
    )

with col2:
    st.metric(
        "Wallets",
        wallet_count
    )

with col3:
    st.metric(
        "Maximum Hop",
        actual_max_hop
    )

with col4:
    st.metric(
        "Abnormal Alerts",
        abnormal_count
    )


# --------------------------------------------------
# RISK
# --------------------------------------------------

st.header("Risk Assessment")

col1, col2 = st.columns(2)

with col1:

    st.metric(
        "Risk Score",
        f"{risk_score}/100"
    )

    if risk_level == "HIGH":

        st.error(
            f"Risk Level: {risk_level}"
        )

    elif risk_level == "MEDIUM":

        st.warning(
            f"Risk Level: {risk_level}"
        )

    else:

        st.success(
            f"Risk Level: {risk_level}"
        )


with col2:

    st.write("### Risk Factors")

    if risk_factors:

        for factor in risk_factors:

            st.write(
                f"• {factor}"
            )

    else:

        st.write(
            "No major risk indicators detected."
        )


# --------------------------------------------------
# TRANSACTION DNA
# --------------------------------------------------

st.header("🧬 Transaction DNA")

if transactions:

    recipients = set()

    outgoing_count = 0
    incoming_count = 0

    for tx in transactions:

        sender = tx["from"].lower()
        receiver = tx["to"].lower()

        if sender == wallet_address.lower():

            outgoing_count += 1

            recipients.add(
                receiver
            )

        if receiver == wallet_address.lower():

            incoming_count += 1


    unique_recipients = len(
        recipients
    )

    dna_score = 0

    if transaction_count >= 50:
        dna_score += 25

    if unique_recipients >= 10:
        dna_score += 25

    if outgoing_count >= 20:
        dna_score += 25

    if actual_max_hop >= 2:
        dna_score += 25

    dna_score = min(
        dna_score,
        100
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric(
            "DNA Score",
            f"{dna_score}/100"
        )

    with c2:
        st.metric(
            "Unique Recipients",
            unique_recipients
        )

    with c3:
        st.metric(
            "Outgoing",
            outgoing_count
        )

    with c4:
        st.metric(
            "Incoming",
            incoming_count
        )

    if unique_recipients >= 10:

        st.info(
            "Behaviour Profile: "
            "High recipient diversity."
        )

    else:

        st.info(
            "Behaviour Profile: "
            "Normal recipient diversity."
        )


# --------------------------------------------------
# ABNORMAL TRANSACTIONS
# --------------------------------------------------

st.header(
    "🚨 Abnormal Transaction Detection"
)

if abnormal_alerts:

    st.write(
        f"{abnormal_count} potentially abnormal "
        "transaction pattern(s) detected."
    )

    for i, alert in enumerate(
        abnormal_alerts[:10],
        start=1
    ):

        if isinstance(alert, dict):

            tx_hash = alert.get(
                "hash",
                alert.get(
                    "tx_hash",
                    "Unknown"
                )
            )

            score = alert.get(
                "score",
                0
            )

            reason = alert.get(
                "reason",
                "Suspicious transaction pattern"
            )

            value = alert.get(
                "value",
                0
            )

            st.write(
                f"**Alert {i}** — "
                f"Score: {score} | "
                f"Value: {value} | "
                f"TX: `{tx_hash}`"
            )

            st.caption(
                reason
            )

        else:

            st.write(
                f"**Alert {i}:** {alert}"
            )

else:

    st.success(
        "No abnormal transaction patterns detected."
    )


# --------------------------------------------------
# FUND FLOW
# --------------------------------------------------

st.header("🔗 Fund Flow Trace")

st.write(
    f"**START:** `{wallet_address}`"
)

for tx in transactions[:30]:

    sender = tx["from"]

    receiver = tx["to"]

    value = tx["value"]

    if sender.lower() == wallet_address.lower():

        st.write(
            f"↳ **OUT** `{receiver}` — "
            f"{value:.6f} {tx['asset']}"
        )


# --------------------------------------------------
# GRAPH
# --------------------------------------------------

st.header("🌐 Transaction Graph")

if transactions:

    graph = Network(
        height="650px",
        width="100%",
        bgcolor="#0e1117",
        font_color="white",
        directed=True,
        cdn_resources="in_line"
    )

    graph.set_options("""
    {
      "nodes": {
        "font": {
          "size": 16
        }
      },
      "edges": {
        "arrows": {
          "to": {
            "enabled": true
          }
        },
        "smooth": {
          "enabled": true
        }
      },
      "physics": {
        "enabled": true
      }
    }
    """)

    added_nodes = set()

    for tx in transactions[:100]:

        sender = tx["from"]
        receiver = tx["to"]

        if sender not in added_nodes:

            graph.add_node(
                sender,
                label=sender[:10] + "...",
                title=sender
            )

            added_nodes.add(sender)

        if receiver not in added_nodes:

            graph.add_node(
                receiver,
                label=receiver[:10] + "...",
                title=receiver
            )

            added_nodes.add(receiver)

        graph.add_edge(
            sender,
            receiver,
            label=str(
                round(
                    tx["value"],
                    4
                )
            )
        )

    graph_html = graph.generate_html()

    components.html(
        graph_html,
        height=670,
        scrolling=True
    )

else:

    st.info(
        "No transactions available for graph generation."
    )


# --------------------------------------------------
# VASP
# --------------------------------------------------

st.header(
    "🏦 Potential VASP / Exchange Association"
)

if vasp_results:

    for result in vasp_results:

        if isinstance(result, dict):

            name = result.get(
                "name",
                "Unknown VASP"
            )

            vasp_type = result.get(
                "type",
                "Unknown"
            )

            country = result.get(
                "country",
                "Unknown"
            )

            st.info(
                f"**Potential Association:** {name}\n\n"
                f"Type: {vasp_type}\n\n"
                f"Country: {country}"
            )

        else:

            st.write(
                result
            )

    st.caption(
        "Association is an analytical signal and "
        "not proof of ownership or criminal activity."
    )

else:

    st.info(
        "No known/demo VASP association found."
    )


# --------------------------------------------------
# TRANSACTION EVIDENCE
# --------------------------------------------------

st.header(
    "📊 Transaction Evidence"
)

if transactions:

    rows = []

    for tx in transactions[:100]:

        rows.append({
            "Transaction": tx["hash"][:16] + "...",
            "From": tx["from"][:12] + "...",
            "To": tx["to"][:12] + "...",
            "Amount": round(
                tx["value"],
                6
            ),
            "Asset": tx["asset"],
            "Block": tx["blockNumber"]
        })

    df = pd.DataFrame(rows)

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No transaction evidence available."
    )


# --------------------------------------------------
# SUMMARY
# --------------------------------------------------

st.header(
    "📄 Investigation Summary"
)

summary_col1, summary_col2 = st.columns(2)

with summary_col1:

    st.write(
        f"**Blockchain:** {chain}"
    )

    st.write(
        f"**Suspect Wallet:** `{wallet_address}`"
    )

    st.write(
        f"**Transactions:** {transaction_count}"
    )

    st.write(
        f"**Wallets:** {wallet_count}"
    )

with summary_col2:

    st.write(
        f"**Maximum Hop:** {actual_max_hop}"
    )

    st.write(
        f"**Abnormal Alerts:** {abnormal_count}"
    )

    st.write(
        f"**Risk Score:** {risk_score}/100"
    )

    st.write(
        f"**Risk Level:** {risk_level}"
    )


st.markdown("---")

st.caption(
    "CryptoShield is an investigation-support prototype. "
    "Results should be verified using authoritative blockchain "
    "and VASP intelligence sources before operational use."
)
