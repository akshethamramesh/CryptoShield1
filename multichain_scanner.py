import os
import requests
from dotenv import load_dotenv

# ==========================================
# LOAD API KEY
# ==========================================

load_dotenv(".env")

API_KEY = os.getenv("ALCHEMY_API_KEY")

if not API_KEY:
    print("ERROR: ALCHEMY_API_KEY not found in .env")
    exit()


# ==========================================
# BLOCKCHAIN CONFIGURATION
# ==========================================

CHAINS = {

    "ethereum": {
        "name": "Ethereum",
        "url": f"https://eth-mainnet.g.alchemy.com/v2/{API_KEY}",
        "categories": [
            "external",
            "internal",
            "erc20"
        ]
    },

    "bsc": {
        "name": "BNB Smart Chain",
        "url": f"https://bnb-mainnet.g.alchemy.com/v2/{API_KEY}",
        "categories": [
            "external",
            "erc20"
        ]
    }
}


# ==========================================
# VALIDATE WALLET
# ==========================================

def valid_evm_address(wallet):

    if not wallet.startswith("0x"):
        return False

    if len(wallet) != 42:
        return False

    try:
        int(wallet[2:], 16)
        return True

    except ValueError:
        return False


# ==========================================
# TEST BLOCKCHAIN CONNECTION
# ==========================================

def test_connection(url):

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_blockNumber",
        "params": []
    }

    try:

        response = requests.post(
            url,
            json=payload,
            timeout=20
        )

        print("HTTP STATUS:", response.status_code)

        data = response.json()

        if "result" not in data:
            print("RPC ERROR:")
            print(data)
            return False

        latest_block = int(data["result"], 16)

        print("Latest Block:", latest_block)

        return True

    except Exception as e:

        print("Connection Error:", e)

        return False


# ==========================================
# FETCH ONE DIRECTION WITH PAGINATION
# ==========================================

def fetch_direction(
        url,
        wallet,
        categories,
        direction
):

    transfers = []

    page_key = None

    page_number = 1

    while True:

        params = {

            "fromBlock": "0x0",

            "toBlock": "latest",

            "category": categories,

            "excludeZeroValue": True,

            "withMetadata": True,

            # 100 transfers per page
            "maxCount": "0x64"
        }

        if direction == "outgoing":

            params["fromAddress"] = wallet

        else:

            params["toAddress"] = wallet


        if page_key:

            params["pageKey"] = page_key


        payload = {

            "jsonrpc": "2.0",

            "id": page_number,

            "method": "alchemy_getAssetTransfers",

            "params": [params]
        }


        try:

            response = requests.post(
                url,
                json=payload,
                timeout=30
            )

            print(
                f"Page {page_number} HTTP:",
                response.status_code
            )

            data = response.json()


            if "error" in data:

                print("RPC ERROR:")

                print(data["error"])

                break


            result = data.get("result", {})

            page_transfers = result.get(
                "transfers",
                []
            )

            transfers.extend(
                page_transfers
            )


            print(
                "Transfers on page:",
                len(page_transfers)
            )


            page_key = result.get(
                "pageKey"
            )


            if not page_key:

                break


            page_number += 1


            # Safety limit for prototype
            if page_number > 20:

                print(
                    "Stopped after 20 pages "
                    "for prototype safety."
                )

                break


        except Exception as e:

            print(
                "Transfer fetch error:",
                e
            )

            break


    return transfers


# ==========================================
# FETCH WALLET HISTORY
# ==========================================

def fetch_wallet_history(
        wallet,
        chain
):

    config = CHAINS[chain]

    url = config["url"]

    categories = config["categories"]


    print()
    print("======================================")
    print(
        f"FETCHING {config['name'].upper()} HISTORY"
    )
    print("======================================")


    print()
    print("Checking OUTGOING...")

    outgoing = fetch_direction(
        url,
        wallet,
        categories,
        "outgoing"
    )

    print(
        "Total outgoing:",
        len(outgoing)
    )


    print()
    print("Checking INCOMING...")

    incoming = fetch_direction(
        url,
        wallet,
        categories,
        "incoming"
    )

    print(
        "Total incoming:",
        len(incoming)
    )


    return outgoing, incoming


# ==========================================
# NORMALIZE TRANSACTIONS
# ==========================================

def normalize_transactions(
        outgoing,
        incoming,
        chain_name
):

    transactions = []


    for tx in outgoing:

        transactions.append({

            "chain": chain_name,

            "direction": "OUT",

            "hash": tx.get(
                "hash",
                "N/A"
            ),

            "from": tx.get(
                "from",
                "N/A"
            ),

            "to": tx.get(
                "to",
                "N/A"
            ),

            "amount": tx.get(
                "value",
                0
            ),

            "asset": tx.get(
                "asset",
                "Unknown"
            ),

            "category": tx.get(
                "category",
                "Unknown"
            ),

            "timestamp": (
                tx.get("metadata", {})
                .get(
                    "blockTimestamp",
                    "Unknown"
                )
            )
        })


    for tx in incoming:

        transactions.append({

            "chain": chain_name,

            "direction": "IN",

            "hash": tx.get(
                "hash",
                "N/A"
            ),

            "from": tx.get(
                "from",
                "N/A"
            ),

            "to": tx.get(
                "to",
                "N/A"
            ),

            "amount": tx.get(
                "value",
                0
            ),

            "asset": tx.get(
                "asset",
                "Unknown"
            ),

            "category": tx.get(
                "category",
                "Unknown"
            ),

            "timestamp": (
                tx.get("metadata", {})
                .get(
                    "blockTimestamp",
                    "Unknown"
                )
            )
        })


    return transactions


# ==========================================
# CONNECTED WALLETS
# ==========================================

def find_connected_wallets(
        wallet,
        transactions
):

    connected = set()

    wallet = wallet.lower()


    for tx in transactions:

        sender = str(
            tx["from"]
        ).lower()

        receiver = str(
            tx["to"]
        ).lower()


        if sender == wallet:

            if receiver != "none":

                connected.add(
                    receiver
                )


        elif receiver == wallet:

            if sender != "none":

                connected.add(
                    sender
                )


    return connected


# ==========================================
# BASIC RISK ENGINE
# ==========================================

def calculate_risk(
        transaction_count,
        connected_wallet_count
):

    score = 0

    reasons = []


    if transaction_count >= 10:

        score += 20

        reasons.append(
            "High transaction activity"
        )


    if transaction_count >= 50:

        score += 15

        reasons.append(
            "Very high transaction activity"
        )


    if connected_wallet_count >= 5:

        score += 20

        reasons.append(
            "Multiple connected wallets"
        )


    if connected_wallet_count >= 20:

        score += 20

        reasons.append(
            "Large wallet interaction network"
        )


    if score >= 70:

        level = "HIGH"

    elif score >= 40:

        level = "MEDIUM"

    else:

        level = "LOW"


    return score, level, reasons


# ==========================================
# DISPLAY TRANSACTIONS
# ==========================================

def display_transactions(
        transactions,
        limit=20
):

    if not transactions:

        print()
        print(
            "No transactions found."
        )

        return


    print()
    print("======================================")
    print("REAL BLOCKCHAIN TRANSACTIONS")
    print("======================================")


    for index, tx in enumerate(
            transactions[:limit],
            start=1
    ):

        print()
        print(
            f"Transaction #{index}"
        )

        print(
            "Chain:",
            tx["chain"]
        )

        print(
            "Direction:",
            tx["direction"]
        )

        print(
            "From:",
            tx["from"]
        )

        print(
            "To:",
            tx["to"]
        )

        print(
            "Amount:",
            tx["amount"],
            tx["asset"]
        )

        print(
            "Category:",
            tx["category"]
        )

        print(
            "Time:",
            tx["timestamp"]
        )

        print(
            "Hash:",
            tx["hash"]
        )


    if len(transactions) > limit:

        print()
        print(
            f"... {len(transactions) - limit}"
            " more transactions hidden."
        )


# ==========================================
# ANALYZE CHAIN
# ==========================================

def analyze_chain(
        wallet,
        chain
):

    config = CHAINS[chain]


    print()
    print("======================================")

    print(
        "ANALYZING:",
        config["name"]
    )

    print("======================================")


    print()
    print("Testing connection...")


    if not test_connection(
            config["url"]
    ):

        print(
            "Connection failed."
        )

        return []


    print(
        "✅ CONNECTION SUCCESSFUL"
    )


    outgoing, incoming = (
        fetch_wallet_history(
            wallet,
            chain
        )
    )


    transactions = (
        normalize_transactions(

            outgoing,

            incoming,

            config["name"]
        )
    )


    display_transactions(
        transactions
    )


    connected = (
        find_connected_wallets(
            wallet,
            transactions
        )
    )


    score, level, reasons = (
        calculate_risk(

            len(transactions),

            len(connected)
        )
    )


    print()
    print("======================================")
    print("CRYPTOSHIELD ANALYSIS")
    print("======================================")


    print(
        "Blockchain:",
        config["name"]
    )

    print(
        "Transactions:",
        len(transactions)
    )

    print(
        "Connected Wallets:",
        len(connected)
    )

    print(
        "Risk Score:",
        f"{score}/100"
    )

    print(
        "Risk Level:",
        level
    )


    if reasons:

        print()
        print("Risk Indicators:")

        for reason in reasons:

            print(
                "-",
                reason
            )

    else:

        print()
        print(
            "No major risk indicators "
            "detected from current rules."
        )


    return transactions


# ==========================================
# MAIN PROGRAM
# ==========================================

print()
print("======================================")
print("          🛡️ CRYPTOSHIELD")
print(" Blockchain Fraud Intelligence System")
print("======================================")

wallet = input(
    "\nEnter wallet address: "
).strip()


if not valid_evm_address(wallet):

    print(
        "\n❌ Invalid EVM wallet address."
    )

    exit()


print()
print("Select Blockchain")
print()
print("1. Ethereum")
print("2. BNB Smart Chain")
print("3. Scan Both")


choice = input(
    "\nEnter choice (1/2/3): "
).strip()


all_transactions = []


if choice == "1":

    all_transactions.extend(

        analyze_chain(
            wallet,
            "ethereum"
        )
    )


elif choice == "2":

    all_transactions.extend(

        analyze_chain(
            wallet,
            "bsc"
        )
    )


elif choice == "3":

    ethereum_tx = analyze_chain(
        wallet,
        "ethereum"
    )

    bsc_tx = analyze_chain(
        wallet,
        "bsc"
    )

    all_transactions.extend(
        ethereum_tx
    )

    all_transactions.extend(
        bsc_tx
    )


    print()
    print("======================================")
    print("MULTI-CHAIN SUMMARY")
    print("======================================")


    print(
        "Ethereum Transactions:",
        len(ethereum_tx)
    )

    print(
        "BSC Transactions:",
        len(bsc_tx)
    )

    print(
        "Total Transactions:",
        len(all_transactions)
    )


    active_chains = []


    if ethereum_tx:

        active_chains.append(
            "Ethereum"
        )


    if bsc_tx:

        active_chains.append(
            "BNB Smart Chain"
        )


    if active_chains:

        print(
            "Activity Detected On:",
            ", ".join(active_chains)
        )

    else:

        print(
            "No supported-chain activity "
            "detected."
        )


else:

    print(
        "\n❌ Invalid choice."
    )

    exit()


print()
print("======================================")
print("ANALYSIS COMPLETE")
print("======================================")

print(
    "\n⚠️ Risk scores represent analytical "
    "indicators only, not proof of fraud."
)
