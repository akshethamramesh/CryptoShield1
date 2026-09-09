import streamlit as st
import networkx as nx
from pyvis.network import Network


# ============================================================
# ADDRESS HELPERS
# ============================================================

def normalize_address(address):
    if not address:
        return ""

    return str(address).strip().lower()


def short_address(address):
    address = normalize_address(address)

    if not address:
        return "Unknown"

    if len(address) <= 14:
        return address

    return address[:6] + "..." + address[-4:]


# ============================================================
# HOP HELPERS
# ============================================================

def normalize_wallet_hops(wallet_hops):
    """
    Convert wallet_hops into:

        {
            wallet_address: hop_number
        }

    Supports values such as:
        0
        1
        "1"
        None
    """

    result = {}

    if not wallet_hops:
        return result

    for wallet, hop in wallet_hops.items():

        wallet = normalize_address(wallet)

        if not wallet:
            continue

        try:
            hop = int(hop)
        except Exception:
            continue

        if hop < 0:
            continue

        result[wallet] = hop

    return result


# ============================================================
# GET TRANSACTION CONNECTIONS
# ============================================================

def extract_transaction_edges(transactions):
    """
    Extract actual blockchain direction:

        from -> to

    Returns:
        {
            (sender, receiver): {
                "count": number,
                "transactions": [...]
            }
        }
    """

    edges = {}

    if not transactions:
        return edges

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

        key = (sender, receiver)

        if key not in edges:
            edges[key] = {
                "count": 0,
                "transactions": []
            }

        edges[key]["count"] += 1
        edges[key]["transactions"].append(tx)

    return edges


# ============================================================
# CALCULATE MISSING HOPS
# ============================================================

def calculate_missing_hops(graph, start_wallet, wallet_hops):
    """
    If some transaction wallets are not present in wallet_hops,
    calculate their distance from Hop 0 using BFS.
    """

    start_wallet = normalize_address(start_wallet)

    if not start_wallet:
        return wallet_hops

    if start_wallet not in graph:
        return wallet_hops

    try:
        distances = nx.single_source_shortest_path_length(
            graph,
            start_wallet
        )
    except Exception:
        return wallet_hops

    updated = dict(wallet_hops)

    for wallet, distance in distances.items():

        wallet = normalize_address(wallet)

        if wallet not in updated:
            updated[wallet] = distance

        else:
            # Keep the smaller hop distance
            try:
                updated[wallet] = min(
                    int(updated[wallet]),
                    int(distance)
                )
            except Exception:
                updated[wallet] = distance

    return updated


# ============================================================
# BUILD COMPLETE GRAPH
# ============================================================

def build_clean_graph(
    transactions,
    wallet_hops,
    start_wallet,
    max_nodes=40,
    max_edges=80
):
    """
    Build a directed fund-flow graph.

    IMPORTANT:
    We do NOT require both sender and receiver
    to already exist in wallet_hops.

    This fixes the "only one node showing" issue.
    """

    start_wallet = normalize_address(start_wallet)

    wallet_hops = normalize_wallet_hops(wallet_hops)

    transaction_edges = extract_transaction_edges(
        transactions
    )

    # --------------------------------------------------------
    # STEP 1
    # Create temporary graph using ALL transaction edges
    # --------------------------------------------------------

    full_graph = nx.DiGraph()

    for (sender, receiver), data in transaction_edges.items():

        full_graph.add_edge(
            sender,
            receiver,
            count=data["count"]
        )

    # --------------------------------------------------------
    # STEP 2
    # Calculate missing hop values
    # --------------------------------------------------------

    wallet_hops = calculate_missing_hops(
        full_graph,
        start_wallet,
        wallet_hops
    )

    # Force reported wallet = Hop 0
    if start_wallet:
        wallet_hops[start_wallet] = 0

    # --------------------------------------------------------
    # STEP 3
    # Build final graph
    # --------------------------------------------------------

    graph = nx.DiGraph()

    # Add reported wallet first
    if start_wallet:
        graph.add_node(
            start_wallet,
            hop=0
        )

    # --------------------------------------------------------
    # STEP 4
    # Select nodes based on BFS distance
    # --------------------------------------------------------

    selected_nodes = set()

    if start_wallet:
        selected_nodes.add(start_wallet)

    # Sort wallets by hop
    sorted_wallets = sorted(
        wallet_hops.items(),
        key=lambda item: (
            item[1],
            item[0]
        )
    )

    for wallet, hop in sorted_wallets:

        if len(selected_nodes) >= max_nodes:
            break

        selected_nodes.add(wallet)

    # --------------------------------------------------------
    # STEP 5
    # If still empty, use transaction participants
    # --------------------------------------------------------

    if len(selected_nodes) <= 1:

        for sender, receiver in transaction_edges:

            if len(selected_nodes) >= max_nodes:
                break

            selected_nodes.add(sender)

            if len(selected_nodes) >= max_nodes:
                break

            selected_nodes.add(receiver)

    # --------------------------------------------------------
    # STEP 6
    # Add selected nodes
    # --------------------------------------------------------

    for wallet in selected_nodes:

        hop = wallet_hops.get(wallet)

        if hop is None:

            # Calculate hop if possible
            if start_wallet and wallet in full_graph:

                try:
                    path_length = nx.shortest_path_length(
                        full_graph,
                        start_wallet,
                        wallet
                    )

                    hop = path_length

                except Exception:
                    hop = "?"

            else:
                hop = "?"

        graph.add_node(
            wallet,
            hop=hop
        )

    # --------------------------------------------------------
    # STEP 7
    # Add ACTUAL transaction edges
    # --------------------------------------------------------

    candidate_edges = []

    for (sender, receiver), data in transaction_edges.items():

        if sender not in selected_nodes:
            continue

        if receiver not in selected_nodes:
            continue

        sender_hop = graph.nodes[sender].get(
            "hop",
            "?"
        )

        receiver_hop = graph.nodes[receiver].get(
            "hop",
            "?"
        )

        # ----------------------------------------------------
        # Priority:
        # 1. Direct hop progression
        # 2. Same-hop connections
        # 3. Other connections
        # ----------------------------------------------------

        priority = 3

        try:

            sender_hop_int = int(sender_hop)
            receiver_hop_int = int(receiver_hop)

            if receiver_hop_int == sender_hop_int + 1:
                priority = 1

            elif receiver_hop_int == sender_hop_int:
                priority = 2

        except Exception:
            pass

        candidate_edges.append(
            (
                priority,
                -data["count"],
                sender,
                receiver,
                data["count"]
            )
        )

    # Sort:
    # First preserve hop-to-next-hop edges
    # Then high-frequency edges
    candidate_edges.sort(
        key=lambda item: (
            item[0],
            item[1]
        )
    )

    # --------------------------------------------------------
    # STEP 8
    # Add edges
    # --------------------------------------------------------

    for (
        priority,
        negative_count,
        sender,
        receiver,
        count
    ) in candidate_edges[:max_edges]:

        graph.add_edge(
            sender,
            receiver,
            count=count,
            priority=priority
        )

    # --------------------------------------------------------
    # STEP 9
    # Preserve at least one connection from Hop 0
    # --------------------------------------------------------

    if start_wallet in graph:

        outgoing = list(
            graph.out_edges(start_wallet)
        )

        if not outgoing:

            possible_edges = []

            for (
                sender,
                receiver
            ), data in transaction_edges.items():

                if sender == start_wallet:

                    possible_edges.append(
                        (
                            receiver,
                            data["count"]
                        )
                    )

            possible_edges.sort(
                key=lambda x: x[1],
                reverse=True
            )

            for receiver, count in possible_edges:

                if receiver not in graph:
                    continue

                graph.add_edge(
                    start_wallet,
                    receiver,
                    count=count,
                    priority=1
                )

                break

    return graph


# ============================================================
# NODE COLOR
# ============================================================

def get_hop_color(hop):

    try:
        hop = int(hop)
    except Exception:
        return "#94a3b8"

    if hop == 0:
        return "#22c55e"

    if hop == 1:
        return "#3b82f6"

    if hop == 2:
        return "#a855f7"

    if hop == 3:
        return "#f97316"

    return "#ef4444"


# ============================================================
# NODE SIZE
# ============================================================

def get_node_size(hop):

    try:
        hop = int(hop)
    except Exception:
        return 20

    if hop == 0:
        return 38

    if hop == 1:
        return 28

    if hop == 2:
        return 24

    if hop == 3:
        return 22

    return 20


# ============================================================
# RENDER GRAPH
# ============================================================

def render_fund_flow_graph(
    transactions,
    wallet_hops,
    start_wallet,
    max_nodes=40,
    max_edges=80
):

    # --------------------------------------------------------
    # BUILD GRAPH
    # --------------------------------------------------------

    graph = build_clean_graph(
        transactions=transactions,
        wallet_hops=wallet_hops,
        start_wallet=start_wallet,
        max_nodes=max_nodes,
        max_edges=max_edges
    )

    # --------------------------------------------------------
    # EMPTY GRAPH
    # --------------------------------------------------------

    if graph.number_of_nodes() == 0:

        st.warning(
            "No connected wallet transactions available "
            "for visualization."
        )

        return

    # --------------------------------------------------------
    # GRAPH HEADER
    # --------------------------------------------------------

    st.subheader(
        "🕸️ Multi-Hop Fund Flow Network"
    )

    st.caption(
        "Actual blockchain transaction direction: "
        "sender → receiver"
    )

    # --------------------------------------------------------
    # CREATE PYVIS NETWORK
    # --------------------------------------------------------

    net = Network(
        height="720px",
        width="100%",
        directed=True,
        bgcolor="#0E1117",
        font_color="white",
        notebook=False
    )

    # --------------------------------------------------------
    # PYVIS OPTIONS
    # --------------------------------------------------------

    net.set_options(
        """
        {
          "nodes": {
            "shape": "dot",
            "borderWidth": 2,
            "shadow": {
              "enabled": true
            },
            "font": {
              "size": 14,
              "face": "Arial",
              "color": "#ffffff"
            }
          },

          "edges": {
            "width": 2,
            "color": {
              "inherit": false,
              "color": "#64748b",
              "highlight": "#ffffff"
            },
            "arrows": {
              "to": {
                "enabled": true,
                "scaleFactor": 0.8
              }
            },
            "smooth": {
              "enabled": true,
              "type": "curvedCW",
              "roundness": 0.2
            },
            "font": {
              "size": 11,
              "color": "#ffffff",
              "strokeWidth": 3,
              "strokeColor": "#0E1117"
            }
          },

          "physics": {
            "enabled": true,
            "solver": "forceAtlas2Based",

            "forceAtlas2Based": {
              "gravitationalConstant": -70,
              "centralGravity": 0.015,
              "springLength": 180,
              "springConstant": 0.06,
              "damping": 0.45,
              "avoidOverlap": 1
            },

            "stabilization": {
              "enabled": true,
              "iterations": 250,
              "updateInterval": 25
            }
          },

          "interaction": {
            "hover": true,
            "dragNodes": true,
            "dragView": true,
            "zoomView": true,
            "navigationButtons": true,
            "keyboard": true,
            "tooltipDelay": 100
          }
        }
        """
    )

    # --------------------------------------------------------
    # ADD NODES
    # --------------------------------------------------------

    for node in graph.nodes():

        hop = graph.nodes[node].get(
            "hop",
            "?"
        )

        color = get_hop_color(hop)

        size = get_node_size(hop)

        # -----------------------------------------------
        # Connection count
        # -----------------------------------------------

        degree = graph.degree(node)

        incoming = graph.in_degree(node)

        outgoing = graph.out_degree(node)

        # -----------------------------------------------
        # Node title
        # -----------------------------------------------

        title = (
            f"<b>Wallet</b>: {node}<br>"
            f"<b>Hop</b>: {hop}<br>"
            f"<b>Total Connections</b>: {degree}<br>"
            f"<b>Incoming</b>: {incoming}<br>"
            f"<b>Outgoing</b>: {outgoing}"
        )

        # Reported wallet gets special label
        if normalize_address(node) == normalize_address(
            start_wallet
        ):

            label = (
                "🚨 REPORTED WALLET\n"
                + short_address(node)
            )

            size = 42

        else:

            label = (
                f"Hop {hop}\n"
                f"{short_address(node)}"
            )

        net.add_node(
            node,
            label=label,
            title=title,
            color={
                "background": color,
                "border": "#ffffff",
                "highlight": {
                    "background": color,
                    "border": "#ffffff"
                }
            },
            size=size,
            font={
                "color": "#ffffff",
                "size": 14
            }
        )

    # --------------------------------------------------------
    # ADD EDGES
    # --------------------------------------------------------

    for sender, receiver, data in graph.edges(
        data=True
    ):

        count = data.get(
            "count",
            1
        )

        sender_hop = graph.nodes[sender].get(
            "hop",
            "?"
        )

        receiver_hop = graph.nodes[receiver].get(
            "hop",
            "?"
        )

        # -----------------------------------------------
        # Edge label
        # -----------------------------------------------

        if count > 1:
            label = f"{count} tx"
        else:
            label = ""

        # -----------------------------------------------
        # Tooltip
        # -----------------------------------------------

        title = (
            "<b>Fund Flow</b><br>"
            f"{sender}<br>"
            "↓<br>"
            f"{receiver}<br><br>"
            f"<b>From Hop</b>: {sender_hop}<br>"
            f"<b>To Hop</b>: {receiver_hop}<br>"
            f"<b>Observed Transactions</b>: {count}"
        )

        # -----------------------------------------------
        # Highlight hop progression
        # -----------------------------------------------

        try:

            if int(receiver_hop) == int(sender_hop) + 1:

                edge_color = "#22c55e"
                edge_width = 3

            else:

                edge_color = "#64748b"
                edge_width = 2

        except Exception:

            edge_color = "#64748b"
            edge_width = 2

        net.add_edge(
            sender,
            receiver,
            title=title,
            label=label,
            arrows="to",
            color={
                "color": edge_color,
                "highlight": "#ffffff"
            },
            width=edge_width
        )

    # --------------------------------------------------------
    # SAVE HTML
    # --------------------------------------------------------

    html_file = "cryptoshield_fund_flow.html"

    net.save_graph(
        html_file
    )

    # --------------------------------------------------------
    # READ HTML
    # --------------------------------------------------------

    try:

        with open(
            html_file,
            "r",
            encoding="utf-8"
        ) as file:

            html = file.read()

    except Exception as error:

        st.error(
            f"Unable to load graph: {error}"
        )

        return

    # --------------------------------------------------------
    # DISPLAY
    # --------------------------------------------------------

    st.components.v1.html(
        html,
        height=740,
        scrolling=True
    )

    # ========================================================
    # GRAPH STATISTICS
    # ========================================================

    st.markdown(
        "### 📊 Fund Flow Statistics"
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Wallet Nodes",
            graph.number_of_nodes()
        )

    with col2:

        st.metric(
            "Fund Flow Connections",
            graph.number_of_edges()
        )

    with col3:

        hops = []

        for node in graph.nodes():

            hop = graph.nodes[node].get(
                "hop"
            )

            try:
                hops.append(int(hop))
            except Exception:
                pass

        maximum_hop = max(hops) if hops else 0

        st.metric(
            "Maximum Hop",
            maximum_hop
        )

    with col4:

        total_transactions = sum(
            data.get("count", 1)
            for _, _, data
            in graph.edges(data=True)
        )

        st.metric(
            "Observed Transactions",
            total_transactions
        )

    # ========================================================
    # LEGEND
    # ========================================================

    st.markdown(
        """
### 🎨 Graph Legend

🟢 **Hop 0** → Reported suspect wallet

🔵 **Hop 1** → Directly connected wallet

🟣 **Hop 2** → Two-step connected wallet

🟠 **Hop 3** → Three-step connected wallet

🔴 **Hop 4+** → Further traced wallet

**Green arrows** → Normal hop progression  
**Grey arrows** → Other observed blockchain connection

**Arrow direction:**  
`transaction.from → transaction.to`
"""
    )

    # ========================================================
    # DEBUG INFORMATION
    # ========================================================

    with st.expander(
        "🔧 Graph Debug Information"
    ):

        st.write(
            "Transactions received:",
            len(transactions or [])
        )

        st.write(
            "Wallet hops received:",
            len(wallet_hops or {})
        )

        st.write(
            "Graph nodes:",
            graph.number_of_nodes()
        )

        st.write(
            "Graph edges:",
            graph.number_of_edges()
        )

        if graph.number_of_nodes() > 0:

            st.write(
                "Displayed wallets:"
            )

            for node in graph.nodes():

                st.write(
                    f"Hop "
                    f"{graph.nodes[node].get('hop', '?')}: "
                    f"{node}"
                )
