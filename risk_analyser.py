

transactions = [
    {"from": "Wallet_A", "to": "Wallet_B", "amount": 5000},
    {"from": "Wallet_A", "to": "Wallet_C", "amount": 3000},
    {"from": "Wallet_B", "to": "Wallet_D", "amount": 4500},
    {"from": "Wallet_C", "to": "Wallet_D", "amount": 2500},
    {"from": "Wallet_D", "to": "Exchange_X", "amount": 7000}
]


def get_transaction_count(wallet):
    count = 0

    for tx in transactions:
        if tx["from"] == wallet or tx["to"] == wallet:
            count += 1

    return count


def get_connected_wallets(wallet):
    connected = set()

    for tx in transactions:

        if tx["from"] == wallet:
            connected.add(tx["to"])

        elif tx["to"] == wallet:
            connected.add(tx["from"])

    return connected


def has_exchange_interaction(wallet):
    for tx in transactions:

        if tx["from"] == wallet and "Exchange" in tx["to"]:
            return True

        if tx["to"] == wallet and "Exchange" in tx["from"]:
            return True

    return False


def calculate_risk(wallet):

    score = 0
    indicators = []

    transaction_count = get_transaction_count(wallet)
    connected_wallets = get_connected_wallets(wallet)
    exchange_interaction = has_exchange_interaction(wallet)

    # Transaction activity
    if transaction_count >= 5:
        score += 20
        indicators.append("High transaction activity")

    # Multiple wallet connections
    if len(connected_wallets) >= 2:
        score += 20
        indicators.append("Multiple wallet connections")

    # Exchange interaction
    if exchange_interaction:
        score += 25
        indicators.append("Exchange interaction detected")

    # Risk level
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, indicators


# Suspect wallet
suspect_wallet = "Wallet_A"

score, level, indicators = calculate_risk(suspect_wallet)

print("================================")
print("       CRYPTOSHIELD")
print("   AUTOMATIC RISK ANALYSIS")
print("================================")

print()

print("Suspect Wallet :", suspect_wallet)

print(
    "Transactions   :",
    get_transaction_count(suspect_wallet)
)

print(
    "Connected Wallets:",
    len(get_connected_wallets(suspect_wallet))
)

print(
    "Exchange Interaction:",
    "YES" if has_exchange_interaction(suspect_wallet)
    else "NO"
)

print()

print("Risk Score :", score, "/ 100")
print("Risk Level :", level)

print()

print("Risk Indicators:")

for indicator in indicators:
    print("⚠", indicator)

print()
print("================================")
