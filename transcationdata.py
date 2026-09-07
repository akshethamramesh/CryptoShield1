# CryptoShield - Transaction Analyzer

transactions = [
    {
        "from": "Wallet_A",
        "to": "Wallet_B",
        "amount": 5000,
    },
    {
        "from": "Wallet_A",
        "to": "Wallet_C",
        "amount": 3000,
    },
    {
        "from": "Wallet_B",
        "to": "Wallet_D",
        "amount": 4500,
    },
    {
        "from": "Wallet_C",
        "to": "Wallet_D",
        "amount": 2500,
    },
    {
        "from": "Wallet_D",
        "to": "Exchange_X",
        "amount": 7000,
    }
]


print("================================")
print("       TRANSACTION FLOW")
print("================================")

for tx in transactions:
    print(
        tx["from"],
        "→",
        tx["to"],
        "| Amount:",
        tx["amount"]
    )
