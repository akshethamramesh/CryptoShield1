import requests
import re


# ============================================================
# CRYPTOSHIELD - BITQUERY ARCHIVE TEST
# ============================================================

API_TOKEN = "ory_at_AOd5GYieGtQAKNClkCpyWyZiPw9mnasPxKh2pf3y-do.Vw5nZd9tQMEb7Mf3EzHDzwOFtvbHuWU8IWlw_BS_aBI"

URL = "https://streaming.bitquery.io/graphql"


# ============================================================
# WALLET VALIDATION
# ============================================================

def valid_evm_address(address):

    pattern = r"^0x[a-fA-F0-9]{40}$"

    return re.fullmatch(pattern, address) is not None


# ============================================================
# ARCHIVE TRANSACTION QUERY
# ============================================================

def get_historical_transactions(wallet):

    query = """
    query ($address: String!) {

        EVM(
            network: eth
            dataset: archive
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
                        }

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
    print("Connecting to Bitquery Archive...")
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
    # UNAUTHORIZED
    # ========================================================

    if response.status_code == 401:

        print("ERROR: 401 Unauthorized")
        print()
        print("Your Bitquery token is invalid or expired.")

        return []


    # ========================================================
    # FORBIDDEN / ARCHIVE NOT ENABLED
    # ========================================================

    if response.status_code == 403:

        print("ERROR: 403 Forbidden")
        print()

        print("Archive access is not enabled for this account.")
        print()

        print(response.text)

        return []


    # ========================================================
    # OTHER HTTP ERROR
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

        print("ERROR: Invalid JSON response.")

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
    # GET TRANSACTIONS
    # ========================================================

    try:

        transactions = (
            data["data"]
            ["EVM"]
            ["Transactions"]
        )

    except (KeyError, TypeError):

        print("ERROR: Unexpected API response.")

        print(data)

        return []


    return transactions


# ============================================================
# DISPLAY
# ============================================================

def display_transactions(wallet, transactions):

    print()
    print("=" * 75)
    print("             HISTORICAL TRANSACTIONS")
    print("=" * 75)

    print()

    print("Wallet:")
    print(wallet)

    print()

    print(
        "Transactions Found:",
        len(transactions)
    )

    if not transactions:

        print()
        print("No historical transactions found.")

        return


    for i, item in enumerate(
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

        print()
        print("-" * 75)

        print(
            "Transaction:",
            i
        )

        print(
            "Block:",
            block.get(
                "Number",
                "Unknown"
            )
        )

        print(
            "Time:",
            block.get(
                "Time",
                "Unknown"
            )
        )

        print(
            "Hash:",
            tx.get(
                "Hash",
                "Unknown"
            )
        )

        print(
            "From:",
            tx.get(
                "From",
                "Unknown"
            )
        )

        print(
            "To:",
            tx.get(
                "To",
                "Unknown"
            )
        )

        print(
            "Value:",
            tx.get(
                "Value",
                "Unknown"
            )
        )


# ============================================================
# MAIN
# ============================================================

print()
print("=" * 75)
print("                    CRYPTOSHIELD")
print("                ARCHIVE DATA TEST")
print("=" * 75)


# ============================================================
# TOKEN CHECK
# ============================================================

if API_TOKEN == "PASTE_YOUR_NEW_BITQUERY_TOKEN_HERE":

    print()
    print("ERROR: Add your Bitquery token first.")
    print()

    raise SystemExit


# ============================================================
# WALLET INPUT
# ============================================================

print()

wallet = input(
    "Enter Ethereum wallet address: "
).strip()


# ============================================================
# VALIDATION
# ============================================================

if not valid_evm_address(wallet):

    print()
    print("ERROR: Invalid Ethereum wallet address.")

    print()
    print(
        "Expected format:"
    )

    print(
        "0x + 40 hexadecimal characters"
    )

    raise SystemExit


# ============================================================
# ARCHIVE QUERY
# ============================================================

transactions = get_historical_transactions(
    wallet
)


# ============================================================
# DISPLAY
# ============================================================

display_transactions(
    wallet,
    transactions
)


# ============================================================
# END
# ============================================================

print()
print("=" * 75)
print("                    TEST COMPLETE")
print("=" * 75)
print()
