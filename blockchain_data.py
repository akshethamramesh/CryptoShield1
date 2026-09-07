import requests
import re

# ============================================================
# CRYPTOSHIELD
# MULTI-CHAIN BLOCKCHAIN DATA MODULE
# ============================================================

# ------------------------------------------------------------
# PUT YOUR NEW BITQUERY TOKEN HERE
# ------------------------------------------------------------

API_TOKEN = "ory_at_AOd5GYieGtQAKNClkCpyWyZiPw9mnasPxKh2pf3y-do.Vw5nZd9tQMEb7Mf3EzHDzwOFtvbHuWU8IWlw_BS_aBI"

BITQUERY_URL = "https://streaming.bitquery.io/graphql"


# ============================================================
# SUPPORTED BLOCKCHAINS
# ============================================================

NETWORKS = {
    "1": {
        "name": "Ethereum",
        "network": "eth"
    },

    "2": {
        "name": "BNB Smart Chain",
        "network": "bsc"
    },

    "3": {
        "name": "Polygon",
        "network": "matic"
    },

    "4": {
        "name": "Arbitrum",
        "network": "arbitrum"
    },

    "5": {
        "name": "Base",
        "network": "base"
    },

    "6": {
        "name": "Optimism",
        "network": "optimism"
    }
}


# ============================================================
# ETHEREUM / EVM ADDRESS VALIDATION
# ============================================================

def valid_evm_address(address):

    pattern = r"^0x[a-fA-F0-9]{40}$"

    return re.fullmatch(
        pattern,
        address
    ) is not None


# ============================================================
# SHOW BLOCKCHAIN MENU
# ============================================================

def show_networks():

    print()
    print("=" * 70)
    print("                 SELECT BLOCKCHAIN")
    print("=" * 70)

    print()

    for key, info in NETWORKS.items():

        print(
            key + ".",
            info["name"]
        )

    print()


# ============================================================
# FETCH TRANSACTIONS
# ============================================================

def get_transactions(
    wallet,
    network
):

    query = """
    query ($address: String!) {

        EVM(
            network: NETWORK_NAME,
            dataset: realtime
        ) {

            Transactions(

                where: {
                    any: [

                        {
                            Transaction: {
                                From: {
                                    is: $address
                                }
                            }
                        },

                        {
                            Transaction: {
                                To: {
                                    is: $address
                                }
                            }
                        }

                    ]
                }

                limit: {
                    count: 20
                }

                orderBy: {
                    descending: Block_Time
                }

            ) {

                Block {
                    Number
                    Time
                }

                Transaction {
                    Hash
                    From
                    To
                    Value
                }
            }
        }
    }
    """

    # --------------------------------------------------------
    # Replace network placeholder
    # --------------------------------------------------------

    query = query.replace(
        "NETWORK_NAME",
        network
    )


    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + API_TOKEN
    }


    payload = {

        "query": query,

        "variables": {
            "address": wallet
        }

    }


    print()
    print("Connecting to Bitquery...")
    print("Blockchain:", network)
    print()


    try:

        response = requests.post(

            BITQUERY_URL,

            headers=headers,

            json=payload,

            timeout=30

        )


    except requests.exceptions.Timeout:

        print("ERROR: Request timed out.")

        return []


    except requests.exceptions.ConnectionError:

        print("ERROR: Internet connection problem.")

        return []


    except requests.exceptions.RequestException as error:

        print("REQUEST ERROR:")
        print(error)

        return []


    print(
        "HTTP Status:",
        response.status_code
    )

    print()


    # ========================================================
    # AUTHENTICATION ERROR
    # ========================================================

    if response.status_code == 401:

        print("ERROR: 401 Unauthorized")

        print()
        print(
            "Your Bitquery token is invalid or expired."
        )

        return []


    # ========================================================
    # PLAN / PERMISSION ERROR
    # ========================================================

    if response.status_code == 403:

        print("ERROR: 403 Forbidden")

        print()
        print(
            "Your Bitquery plan does not allow this request."
        )

        print()
        print(response.text)

        return []


    # ========================================================
    # OTHER ERROR
    # ========================================================

    if response.status_code != 200:

        print("API ERROR:")

        print(response.text)

        return []


    # ========================================================
    # JSON
    # ========================================================

    try:

        data = response.json()

    except ValueError:

        print(
            "ERROR: Invalid JSON response."
        )

        return []


    # ========================================================
    # GRAPHQL ERROR
    # ========================================================

    if "errors" in data:

        print("GRAPHQL ERROR")
        print("-" * 60)

        for error in data["errors"]:

            print(
                error.get(
                    "message",
                    "Unknown error"
                )
            )

        print("-" * 60)

        return []


    # ========================================================
    # EXTRACT TRANSACTIONS
    # ========================================================

    try:

        transactions = (

            data["data"]
            ["EVM"]
            ["Transactions"]

        )

    except (KeyError, TypeError):

        print(
            "ERROR: Unexpected response."
        )

        print()

        print(data)

        return []


    return transactions


# ============================================================
# DISPLAY TRANSACTIONS
# ============================================================

def display_transactions(
    wallet,
    transactions,
    blockchain
):

    print()
    print("=" * 75)
    print("                    TRANSACTION DATA")
    print("=" * 75)

    print()

    print(
        "Blockchain:",
        blockchain
    )

    print(
        "Wallet:",
        wallet
    )


    if not transactions:

        print()
        print(
            "No recent transactions found."
        )

        print()

        print(
            "NOTE: Current Bitquery plan uses"
        )

        print(
            "the REALTIME dataset."
        )

        print(
            "Historical transactions may not appear."
        )

        return


    # ========================================================
    # TRANSACTIONS
    # ========================================================

    for number, item in enumerate(
        transactions,
        1
    ):

        tx = item.get(
            "Transaction",
            {}
        )

        block = item.get(
            "Block",
            {}
        )


        tx_hash = tx.get(
            "Hash",
            "Unknown"
        )

        sender = tx.get(
            "From",
            "Unknown"
        )

        receiver = tx.get(
            "To",
            "Unknown"
        )

        value = tx.get(
            "Value",
            "0"
        )

        block_number = block.get(
            "Number",
            "Unknown"
        )

        block_time = block.get(
            "Time",
            "Unknown"
        )


        if sender.lower() == wallet.lower():

            direction = "OUTGOING"

        else:

            direction = "INCOMING"


        print()
        print(
            "Transaction",
            number
        )

        print("-" * 75)

        print(
            "Direction :",
            direction
        )

        print(
            "From      :",
            sender
        )

        print(
            "To        :",
            receiver
        )

        print(
            "Value     :",
            value
        )

        print(
            "Block     :",
            block_number
        )

        print(
            "Time      :",
            block_time
        )

        print(
            "Hash      :",
            tx_hash
        )


# ============================================================
# FIND CONNECTED WALLETS
# ============================================================

def find_connected_wallets(
    wallet,
    transactions
):

    connected = set()


    for item in transactions:

        tx = item.get(
            "Transaction",
            {}
        )

        sender = tx.get(
            "From",
            ""
        )

        receiver = tx.get(
            "To",
            ""
        )


        if sender.lower() == wallet.lower():

            if receiver:

                connected.add(
                    receiver
                )


        elif receiver.lower() == wallet.lower():

            if sender:

                connected.add(
                    sender
                )


    return connected


# ============================================================
# BASIC RISK ANALYSIS
# ============================================================

def calculate_risk(
    transactions,
    connected
):

    score = 0

    reasons = []


    # --------------------------------------------------------
    # Transaction count
    # --------------------------------------------------------

    if len(transactions) >= 10:

        score += 20

        reasons.append(
            "High number of observed transactions"
        )


    # --------------------------------------------------------
    # Connected wallets
    # --------------------------------------------------------

    if len(connected) >= 5:

        score += 20

        reasons.append(
            "Multiple connected wallets"
        )


    # --------------------------------------------------------
    # Outgoing transfers
    # --------------------------------------------------------

    outgoing = 0


    for item in transactions:

        tx = item.get(
            "Transaction",
            {}
        )

        sender = tx.get(
            "From",
            ""
        )


        # We don't know the wallet here,
        # so this is counted later in main.
        pass


    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    if score >= 70:

        level = "HIGH"

    elif score >= 40:

        level = "MEDIUM"

    else:

        level = "LOW"


    return score, level, reasons


# ============================================================
# MAIN PROGRAM
# ============================================================

print()
print("=" * 75)
print("                         CRYPTOSHIELD")
print("                 MULTI-CHAIN DATA ANALYZER")
print("=" * 75)
print()


# ============================================================
# TOKEN CHECK
# ============================================================

if API_TOKEN == "PASTE_YOUR_NEW_BITQUERY_TOKEN_HERE":

    print(
        "ERROR: Add your NEW Bitquery token first."
    )

    print()

    print(
        'API_TOKEN = "YOUR_NEW_TOKEN"'
    )

    raise SystemExit


# ============================================================
# SELECT NETWORK
# ============================================================

show_networks()


choice = input(
    "Enter blockchain number: "
).strip()


if choice not in NETWORKS:

    print()
    print(
        "ERROR: Invalid blockchain selection."
    )

    raise SystemExit


blockchain = NETWORKS[choice]["name"]

network = NETWORKS[choice]["network"]


print()

print(
    "Selected:",
    blockchain
)


# ============================================================
# WALLET INPUT
# ============================================================

wallet = input(
    "Enter wallet address: "
).strip()


print()


# ============================================================
# ADDRESS VALIDATION
# ============================================================

if not valid_evm_address(wallet):

    print(
        "ERROR: Invalid EVM wallet address."
    )

    print()

    print(
        "For this version use:"
    )

    print(
        "0x + 40 hexadecimal characters"
    )

    raise SystemExit


# ============================================================
# FETCH DATA
# ============================================================

transactions = get_transactions(
    wallet,
    network
)


print()

print(
    "Transactions Found:",
    len(transactions)
)


# ============================================================
# DISPLAY
# ============================================================

display_transactions(
    wallet,
    transactions,
    blockchain
)


# ============================================================
# CONNECTED WALLETS
# ============================================================

connected = find_connected_wallets(
    wallet,
    transactions
)


print()
print("=" * 75)
print("                  CONNECTED WALLETS")
print("=" * 75)


if connected:

    for address in connected:

        print(
            "->",
            address
        )

else:

    print(
        "No connected wallets found."
    )


# ============================================================
# RISK ANALYSIS
# ============================================================

score, level, reasons = calculate_risk(
    transactions,
    connected
)


print()
print("=" * 75)
print("                     RISK ANALYSIS")
print("=" * 75)

print()

print(
    "Risk Score :",
    score,
    "/ 100"
)

print(
    "Risk Level :",
    level
)


if reasons:

    print()

    print("Indicators:")

    for reason in reasons:

        print(
            "->",
            reason
        )

else:

    print()

    print(
        "No strong indicators detected."
    )


# ============================================================
# END
# ============================================================

print()
print("=" * 75)
print("                CRYPTOSHIELD COMPLETE")
print("=" * 75)
print()
