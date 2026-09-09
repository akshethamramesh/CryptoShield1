import streamlit as st
import networkx as nx
from pyvis.network import Network


def short_address(address):
    """
    Convert a long wallet address into a readable form.
    """
    if not address:
        return "Unknown"

    address = str(address)

    if len(address) <= 14:
        return address

    return address[:6] + "..." + address[-4:]


def normalize_address(address):
    if not address:
        return ""

    return str(address).strip().lower()


def build_clean_graph(
    transactions,
    wallet_hops,
    start_wallet,
    max_nodes=35,
    max_edges=50
):
    """
    Build a clean directed graph from REAL transaction directions.

    Important:
        transaction.from -> transaction.to

    Hop numbers are used only to classify nodes.
    They do NOT change the transaction direction.
    """

    graph = nx.DiGraph()

    start_wallet = normalize_address(start_wallet)

    # ---------------------------------------------------------
    # 1. Add nodes that actually have a hop assignment
    # ---------------------------------------------------------

    valid_wallets = set()

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

        valid_wallets.add(wallet)

        graph.add_node(
            wallet,
            hop=hop
        )

    # Make sure starting wallet exists
    if start_wallet:

        graph.add_node(
            start_wallet,
            hop=0
        )

        valid_wallets.add(start_wallet)

    # ---------------------------------------------------------
    # 2. Build REAL transaction edges
    # ---------------------------------------------------------

    edge_counter = {}

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

        # Only wallets participating in our traced graph
        if sender not in valid_wallets:
            continue

        if receiver not in valid_wallets:
            continue

        edge = (sender, receiver)

        edge_counter[edge] = edge_counter.get(edge, 0) + 1

    # ---------------------------------------------------------
    # 3. Sort edges by importance
    # ---------------------------------------------------------

    sorted_edges = sorted(
        edge_counter.items(),
        key=lambda item: item[1],
        reverse=True
    )

    # ---------------------------------------------------------
    # 4. Limit edges for visual clarity
    # ---------------------------------------------------------

    selected_edges = sorted_edges[:max_edges]

    for (sender, receiver), count in selected_edges:

        graph.add_edge(
            sender,
            receiver,
            count=count
        )

    # ---------------------------------------------------------
    # 5. Keep important nodes
    # ---------------------------------------------------------

    if graph.number_of_nodes() > max_nodes:

        connected_nodes = set()

        # Always keep Hop 0
        connected_nodes.add(start_wallet)

        # Keep nodes participating in selected edges
        for sender, receiver in selected_edges:

            connected_nodes.add(sender)
            connected_nodes.add(receiver)

        # Add lower-hop nodes first
        remaining_nodes = [
            node
            for node in graph.nodes()
            if node not in connected_nodes
        ]

        remaining_nodes.sort(
            key=lambda node: graph.nodes[node].get(
                "hop",
                999
            )
        )

        available = max_nodes - len(connected_nodes)

        if available > 0:

            connected_nodes.update(
                remaining_nodes[:available]
            )

        graph = graph.subgraph(
            connected_nodes
        ).copy()

    return graph


def render_fund_flow_graph(
    transactions,
    wallet_hops,
    start_wallet,
    max_nodes=35,
    max_edges=50
):
    """
    Render the blockchain fund flow as an interactive
    interconnected-node diagram.
    """

    graph = build_clean_graph(
        transactions=transactions,
        wallet_hops=wallet_hops,
        start_wallet=start_wallet,
        max_nodes=max_nodes,
        max_edges=max_edges
    )

    if graph.number_of_nodes() == 0:

        st.warning(
            "No connected wallets available for visualization."
        )

        return

    # ---------------------------------------------------------
    # PyVis network
    # ---------------------------------------------------------

    net = Network(
        height="700px",
        width="100%",
        directed=True,
        bgcolor="#0E1117",
        font_color="white"
    )

    net.set_options(
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
                "scaleFactor": 0.8
              }
            },
            "smooth": {
              "enabled": true,
              "type": "dynamic"
            },
            "width": 2
          },

          "physics": {
            "enabled": true,
            "solver": "forceAtlas2Based",
            "forceAtlas2Based": {
              "gravitationalConstant": -40,
              "centralGravity": 0.01,
              "springLength": 160,
              "springConstant": 0.08,
              "damping": 0.4
            },
            "stabilization": {
              "enabled": true,
              "iterations": 200
            }
          },

          "interaction": {
            "hover": true,
            "navigationButtons": true,
            "zoomView": true,
            "dragNodes": true
          }
        }
        """
    )

    # ---------------------------------------------------------
    # Add nodes
    # ---------------------------------------------------------

    for node in graph.nodes():

        hop = graph.nodes[node].get(
            "hop",
            "?"
        )

        label = short_address(node)

        # Different visual size for Hop 0
        size = 32 if hop == 0 else 20

        title = (
            f"Wallet: {node}<br>"
            f"Hop: {hop}<br>"
            f"Connections: {graph.degree(node)}"
        )

        net.add_node(
            node,
            label=label,
            title=title,
            size=size,
            group=f"hop_{hop}"
        )

    # ---------------------------------------------------------
    # Add edges
    # ---------------------------------------------------------

    for sender, receiver, data in graph.edges(
        data=True
    ):

        count = data.get(
            "count",
            1
        )

        title = (
            f"Fund flow<br>"
            f"{short_address(sender)} → "
            f"{short_address(receiver)}<br>"
            f"Observed transactions: {count}"
        )

        net.add_edge(
            sender,
            receiver,
            title=title,
            label=str(count) if count > 1 else "",
            arrows="to"
        )

    # ---------------------------------------------------------
    # Generate HTML
    # ---------------------------------------------------------

    html_file = "cryptoshield_fund_flow.html"

    net.save_graph(html_file)

    # ---------------------------------------------------------
    # Display
    # ---------------------------------------------------------

    with open(
        html_file,
        "r",
        encoding="utf-8"
    ) as file:

        html = file.read()

    st.components.v1.html(
        html,
        height=720,
        scrolling=True
    )

    # ---------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------

    st.markdown("### 🔎 Graph Summary")

    col1, col2, col3 = st.columns(3)

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

        hops = [
            graph.nodes[node].get(
                "hop",
                0
            )
            for node in graph.nodes()
        ]

        max_hop = max(hops) if hops else 0

        st.metric(
            "Maximum Hop",
            max_hop
        )

    # ---------------------------------------------------------
    # Hop explanation
    # ---------------------------------------------------------

    st.markdown(
        """
        **Hop meaning**

        - 🟢 Hop 0 → Reported wallet
        - 🔵 Hop 1 → Directly connected wallet
        - 🟣 Hop 2 → Two-step connected wallet
        - 🟠 Hop 3+ → Further traced wallet

        **Arrow direction:**  
        `transaction.from → transaction.to`

        The graph shows blockchain transaction direction.
        Hop numbers are used only to describe tracing distance.
        """
    )
