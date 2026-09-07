transactions = [
    {"from": "Wallet_A", "to": "Wallet_B", "amount": 5000},
    {"from": "Wallet_A", "to": "Wallet_C", "amount": 3000},
    {"from": "Wallet_B", "to": "Wallet_D", "amount": 4500},
    {"from": "Wallet_C", "to": "Wallet_D", "amount": 2500},
    {"from": "Wallet_D", "to": "Exchange_X", "amount": 7000}
]


def get_outgoing_wallets(wallet):
    wallets = []

    for tx in transactions:
        if tx["from"] == wallet:
            wallets.append(tx["to"])

    return wallets


def get_incoming_wallets(wallet):
    wallets = []

    for tx in transactions:
        if tx["to"] == wallet:
            wallets.append(tx["from"])

    return wallets


def trace_wallet(start_wallet):
    visited = set()
    queue = [(start_wallet, 0)]

    max_depth = 0
    exchange_reached = False

    while queue:

        current_wallet, depth = queue.pop(0)

        if current_wallet in visited:
            continue

        visited.add(current_wallet)

        if depth > max_depth:
            max_depth = depth

        if "Exchange" in current_wallet:
            exchange_reached = True

        for tx in transactions:

            if tx["from"] == current_wallet:

                next_wallet = tx["to"]

                if next_wallet not in visited:
                    queue.append((next_wallet, depth + 1))

    return visited, max_depth, exchange_reached


def detect_patterns(wallet):

    patterns = []

    outgoing = get_outgoing_wallets(wallet)
    incoming = get_incoming_wallets(wallet)

    if len(outgoing) >= 2:
        patterns.append("Fund splitting detected")

    if len(incoming) >= 2:
        patterns.append("Fund consolidation detected")

    wallets, max_depth, exchange_reached = trace_wallet(wallet)

    if max_depth >= 2:
        patterns.append("Multi-hop fund movement detected")

    if exchange_reached:
        patterns.append("Exchange reachable through fund flow")

    return patterns, max_depth, exchange_reached, wallets


suspect_wallet = "Wallet_A"

patterns, max_depth, exchange_reached, wallets = detect_patterns(
    suspect_wallet
)


print("================================")
print("       CRYPTOSHIELD")
print("  SUSPICIOUS PATTERN ANALYSIS")
print("================================")

print()

print("Suspect Wallet :", suspect_wallet)

print("Wallets Traced :", len(wallets))

print("Maximum Hop Depth :", max_depth)

print(
    "Exchange Reachable :",
    "YES" if exchange_reached else "NO"
)

print()

print("Suspicious Patterns:")

if len(patterns) == 0:
    print("- No suspicious pattern detected")
else:
    for pattern in patterns:
        print("- " + pattern)

print()

print("Wallet Flow:")

for wallet in wallets:
    print("->", wallet)

print()

print("================================")
