# CryptoShield - Multi-Hop Fund Flow Tracer

transactions = [
    {"from": "Wallet_A", "to": "Wallet_B", "amount": 5000},
    {"from": "Wallet_A", "to": "Wallet_C", "amount": 3000},
    {"from": "Wallet_B", "to": "Wallet_D", "amount": 4500},
    {"from": "Wallet_C", "to": "Wallet_D", "amount": 2500},
    {"from": "Wallet_D", "to": "Exchange_X", "amount": 7000}
]


def trace_wallet(start_wallet):
    visited = set()
    queue = [start_wallet]

    while queue:

        current_wallet = queue.pop(0)

        if current_wallet in visited:
            continue

        visited.add(current_wallet)

        for tx in transactions:

            if tx["from"] == current_wallet:
                next_wallet = tx["to"]

                if next_wallet not in visited:
                    queue.append(next_wallet)

    return visited


suspect_wallet = "Wallet_A"

result = trace_wallet(suspect_wallet)

print("================================")
print("       MULTI-HOP TRACE")
print("================================")

print("Starting Wallet:", suspect_wallet)
print()
print("Wallets found in fund flow:")

for wallet in result:
    print("→", wallet)
