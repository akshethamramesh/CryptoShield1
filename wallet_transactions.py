import requests

# ==========================================
# CRYPTOSHIELD
# REAL WALLET TRANSACTION FETCHER
# ==========================================

API_TOKEN = "ory_at_vPfcRbkBWAfIod9ewBAShCQWWRCkvDI7iJeocc8oajo.Ez_4Vru557CUuCA_4oWfqbdjrBj2wkZl-8_Az6bv-Mw"

URL = "https://streaming.bitquery.io/graphql"


# Ethereum wallet address
# This is a public address used only for testing.
WALLET_ADDRESS = input("Enter Ethereum wallet address: ").strip()


QUERY = """
query ($address: String!) {

    EVM(network: eth, dataset: realtime) {

        Transactions(
            where: {
                any: [
                    {Transaction: {From: {is: $address}}},
                    {Transaction: {To: {is: $address}}}
                ]
            }
            limit: {count: 10}
        ) {

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


HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + API_TOKEN
}


VARIABLES = {
    "address": WALLET_ADDRESS
}


print("================================")
print("       CRYPTOSHIELD")
print(" REAL WALLET TRANSACTIONS")
print("================================")
print()

print("Wallet:")
print(WALLET_ADDRESS)
print()

print("Connecting to Bitquery...")
print()


try:

    response = requests.post(
        URL,
        json={
            "query": QUERY,
            "variables": VARIABLES
        },
        headers=HEADERS,
        timeout=30
    )

    print("HTTP Status:", response.status_code)
    print()

    # ======================================
    # SUCCESS
    # ======================================

    if response.status_code == 200:

        data = response.json()

        if "errors" in data:

            print("GRAPHQL ERROR")
            print("--------------------------------")

            for error in data["errors"]:
                print(error.get("message", error))

            print("--------------------------------")

        else:

            transactions = data["data"]["EVM"]["Transactions"]

            print("Transactions Found:", len(transactions))
            print()

            print("--------------------------------")
            print("TRANSACTION DATA")
            print("--------------------------------")

            if len(transactions) == 0:

                print("No transactions found.")

            else:

                for i, tx in enumerate(transactions, start=1):

                    transaction = tx["Transaction"]

                    print()
                    print("Transaction", i)
                    print("Hash :", transaction["Hash"])
                    print("From :", transaction["From"])
                    print("To   :", transaction["To"])
                    print("Value:", transaction["Value"])

            print()
            print("================================")
            print(" REAL BLOCKCHAIN DATA RECEIVED")
            print("================================")


    # ======================================
    # AUTH ERROR
    # ======================================

    elif response.status_code == 401:

        print("ERROR: UNAUTHORIZED")
        print("--------------------------------")
        print("Token authentication failed.")
        print("--------------------------------")


    # ======================================
    # PERMISSION ERROR
    # ======================================

    elif response.status_code == 403:

        print("ERROR: FORBIDDEN")
        print("--------------------------------")
        print(response.text)
        print("--------------------------------")


    # ======================================
    # OTHER ERROR
    # ======================================

    else:

        print("API REQUEST FAILED")
        print("--------------------------------")
        print(response.text)
        print("--------------------------------")


except requests.exceptions.ConnectionError:

    print("ERROR: Could not connect to Bitquery.")


except requests.exceptions.Timeout:

    print("ERROR: Request timed out.")


except Exception as error:

    print("UNEXPECTED ERROR")
    print("--------------------------------")
    print(error)
    print("--------------------------------")


print()
print("Test finished.")
