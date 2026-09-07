import requests
import re

# ============================================================
# CRYPTOSHIELD - REAL ETHEREUM WALLET ANALYZER
# ============================================================

# IMPORTANT:
# Put your NEW Bitquery token between the quotes.
# Do NOT share your token in chat.
API_TOKEN = "ory_at_AOd5GYieGtQAKNClkCpyWyZiPw9mnasPxKh2pf3y-do.Vw5nZd9tQMEb7Mf3EzHDzwOFtvbHuWU8IWlw_BS_aBI"

URL = "https://streaming.bitquery.io/graphql"


# ============================================================
# CHECK ETHEREUM ADDRESS
# ============================================================

def valid_address(address):

    pattern = r"^0x[a-fA-F0-9]{40}$"

    return re.fullmatch(pattern, address) is not None


# ============================================================
# FETCH TRANSACTIONS
# ============================================================

def get_transactions(wallet):

    query = """
    query ($address: String!) {

        EVM(network: eth, dataset: realtime) {

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
    print()

    try:

        response = requests.post(
            URL,
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


    print("HTTP Status:", response.status_code)
    print()


    # ========================================================
    # STATUS CHECK
    # ========================================================

    if response.status_code == 401:

        print("ERROR: 401 Unauthorized")
        print()
        print("Your Bitquery token is invalid or expired.")
        return []


    if response.status_code == 403:

        print("ERROR: 403 Forbidden")
        print()
        print("Your Bitquery plan does not allow this request.")
        print()
        print(response.text)
        return []


    if response.status_code != 200:

        print("ERROR:", response.status_code)
        print()
        print(response.text)
        return []


    # ========================================================
    # JSON
    # ========================================================

    try:

        data = response.json()

    except ValueError:

        print("ERROR: Could not read Bitquery response.")
        return []


    # ========================================================
    # GRAPHQL ERROR
    # ========================================================

    if "errors" in data:

        print("GRAPHQL ERROR")
        print("------------------------------")

        for error in data["errors"]:

            print(
                error.get(
                    "message",
                    "Unknown error"
                )
            )

        print("------------------------------")

        return []


    # ========================================================
    # GET TRANSACTIONS
    # ========================================================

    try:

        transactions = data["data"]["EVM"]["Transactions"]

    except (KeyError, TypeError):

        print("ERROR: Unexpected response from Bitquery.")
        print()
        print(data)
        return []


    return transactions


# ============================================================
# DISPLAY TRANSACTIONS
# ============================================================

def display_transactions(wallet, transactions):

    print()
    print("=" * 75)
    print("                     TRANSACTION DATA")
    print("=" * 75)


    if not transactions:

        print()
        print("No recent transactions found.")
        print()
        print("Remember:")
        print("- Current API uses REALTIME dataset.")
        print("- Older transactions may not appear.")
        return


    for i, item in enumerate(transactions, 1):

        tx = item.get("Transaction", {})
        block = item.get("Block", {})

        tx_hash = tx.get("Hash", "Unknown")
        sender = tx.get("From", "Unknown")
        receiver = tx.get("To", "Unknown")
        value = tx.get("Value", "0")

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
        print("Transaction", i)
        print("-" * 75)

        print("Direction :", direction)
        print("From      :", sender)
        print("To        :", receiver)
        print("Value     :", value, "ETH")
        print("Block     :", block_number)
        print("Time      :", block_time)
        print("Hash      :", tx_hash)


# ============================================================
# WALLET ANALYSIS
# ============================================================

def analyze_wallet(wallet, transactions):

    incoming = 0
    outgoing = 0

    connected = set()

    total_value = 0.0


    for item in transactions:

        tx = item.get("Transaction", {})

        sender = tx.get("From", "")
        receiver = tx.get("To", "")
        value = tx.get("Value", 0)


        # Total ETH

        try:

            total_value += float(value)

        except:

            pass


        # Incoming

        if receiver.lower() == wallet.lower():

            incoming += 1

            if sender:

                connected.add(sender)


        # Outgoing

        elif sender.lower() == wallet.lower():

            outgoing += 1

            if receiver:

                connected.add(receiver)


    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 75)
    print("                       WALLET SUMMARY")
    print("=" * 75)

    print()
    print("Wallet            :", wallet)
    print("Transactions      :", len(transactions))
    print("Incoming          :", incoming)
    print("Outgoing          :", outgoing)
    print("Connected Wallets :", len(connected))
    print("Observed ETH      :", total_value)


    # ========================================================
    # BASIC RISK SCORE
    # ========================================================

    score = 0
    reasons = []


    if len(transactions) >= 10:

        score += 20

        reasons.append(
            "Many transactions observed"
        )


    if len(connected) >= 5:

        score += 20

        reasons.append(
            "Multiple connected wallets"
        )


    if outgoing >= 5:

        score += 20

        reasons.append(
            "Multiple outgoing transfers"
        )


    if score >= 60:

        level = "HIGH"

    elif score >= 30:

        level = "MEDIUM"

    else:

        level = "LOW"


    print()
    print("=" * 75)
    print("                       RISK ANALYSIS")
    print("=" * 75)

    print()
    print("Risk Score :", score, "/ 100")
    print("Risk Level :", level)


    if reasons:

        print()
        print("Indicators:")

        for reason in reasons:

            print("->", reason)

    else:

        print()
        print("No strong indicators from this basic analysis.")


# ============================================================
# MAIN
# ============================================================

print()
print("=" * 75)
print("                         CRYPTOSHIELD")
print("                REAL ETHEREUM WALLET ANALYZER")
print("=" * 75)
print()


# ============================================================
# TOKEN CHECK
# ============================================================

if API_TOKEN == "":

    print("ERROR:")
    print()
    print("You have not entered your Bitquery API token.")
    print()
    print("Open this file and change:")
    print()
    print('API_TOKEN = "PASTE_YOUR_NEW_BITQUERY_TOKEN_HERE"')
    print()
    print("Do NOT paste the token into ChatGPT.")

    raise SystemExit


# ============================================================
# WALLET INPUT
# ============================================================

wallet = input(
    "Enter Ethereum wallet address: "
).strip()


# ============================================================
# ADDRESS VALIDATION
# ============================================================

if not valid_address(wallet):

    print()
    print("ERROR: Invalid Ethereum wallet address.")
    print()
    print("Ethereum address format:")
    print("0x + 40 hexadecimal characters")
    print()

    raise SystemExit


# ============================================================
# FETCH
# ============================================================

print()
print("Wallet:")
print(wallet)

print()
print("Fetching REAL Ethereum blockchain data...")

transactions = get_transactions(wallet)


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
    transactions
)


# ============================================================
# ANALYZE
# ============================================================

analyze_wallet(
    wallet,
    transactions
)


# ============================================================
# END
# ============================================================

print()
print("=" * 75)
print("                 CRYPTOSHIELD COMPLETE")
print("=" * 75)
