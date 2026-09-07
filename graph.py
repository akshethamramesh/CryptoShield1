import networkx as nx
from pyvis.network import Network

# --------------------------------
# SAMPLE TRANSACTION DATA
# --------------------------------

transactions = [
    {"from": "Wallet_A", "to": "Wallet_B", "amount": 5000},
    {"from": "Wallet_A", "to": "Wallet_C", "amount": 3000},
    {"from": "Wallet_B", "to": "Wallet_D", "amount": 4500},
    {"from": "Wallet_C", "to": "Wallet_D", "amount": 2500},
    {"from": "Wallet_D", "to": "Exchange_X", "amount": 7000}
]


# --------------------------------
# CREATE GRAPH
# --------------------------------

graph = nx.DiGraph()

for tx in transactions:

    sender = tx["from"]
    receiver = tx["to"]
    amount = tx["amount"]

    graph.add_node(sender)
    graph.add_node(receiver)

    graph.add_edge(
        sender,
        receiver,
        amount=amount
    )


# --------------------------------
# CREATE VISUAL NETWORK
# --------------------------------

net = Network(
    height="700px",
    width="100%",
    directed=True,
    bgcolor="#ffffff"
)

net.from_nx(graph)


# --------------------------------
# ADD TRANSACTION AMOUNT
# --------------------------------

for edge in net.edges:

    sender = edge["from"]
    receiver = edge["to"]

    amount = graph[sender][receiver]["amount"]

    edge["label"] = f"₹{amount}"
    edge["title"] = f"Transaction Amount: ₹{amount}"


# --------------------------------
# GENERATE HTML
# --------------------------------

net.write_html("transaction_graph.html")

print("================================")
print("     TRANSACTION GRAPH")
print("================================")

print("Graph created successfully!")

print()
print("Open this file:")
print("transaction_graph.html")
