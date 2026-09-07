import requests

# ==========================================
# CRYPTOSHIELD - BITQUERY API TEST
# ==========================================

API_TOKEN = "ory_at_vPfcRbkBWAfIod9ewBAShCQWWRCkvDI7iJeocc8oajo.Ez_4Vru557CUuCA_4oWfqbdjrBj2wkZl-8_Az6bv-Mw"

URL = "https://streaming.bitquery.io/graphql"

QUERY = """
query {
    EVM(network: eth, dataset: realtime) {
        Blocks(limit: {count: 3}) {
            Block {
                Number
            }
        }
    }
}
"""

HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + API_TOKEN
}

print("================================")
print("       CRYPTOSHIELD")
print("   BLOCKCHAIN API TEST")
print("================================")
print()

print("Connecting to Bitquery...")
print()

try:

    response = requests.post(
        URL,
        json={"query": QUERY},
        headers=HEADERS,
        timeout=30
    )

    print("HTTP Status:", response.status_code)
    print()

    if response.status_code == 200:

        data = response.json()

        if "errors" in data:

            print("GRAPHQL ERROR")
            print("--------------------------------")

            for error in data["errors"]:
                print(error.get("message", error))

            print("--------------------------------")

        else:

            print("SUCCESS! 🎉")
            print()
            print("Blockchain data received.")
            print()

            blocks = data["data"]["EVM"]["Blocks"]

            for block in blocks:
                print(
                    "Block Number:",
                    block["Block"]["Number"]
                )

            print()
            print("================================")
            print(" Bitquery API connection works!")
            print("================================")

    elif response.status_code == 401:

        print("ERROR: UNAUTHORIZED")
        print("--------------------------------")
        print("Token authentication failed.")
        print("--------------------------------")

    elif response.status_code == 403:

        print("ERROR: FORBIDDEN")
        print("--------------------------------")
        print("Your plan does not permit this request.")
        print()
        print(response.text)
        print("--------------------------------")

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
