import requests

# ============================================================
# CRYPTOSHIELD - BSC WALLET HISTORY
# ============================================================

ALCHEMY_API_KEY = "alch_TuXyU5rwJa2OGHlXYCjO0"

WALLET = "0x33a482418cbf3bef763af0f56651d4cc41a5c7af"

URL = f"https://bnb-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"


def get_transfers(direction):

    all_transfers = []
    page_key = None

    while True:

        params = {
            "fromBlock": "0x0",
            "toBlock": "latest",

            "category": ["erc20"],

            "withMetadata": True,
            "excludeZeroValue": False,

            "maxCount": "0x64"
        }

        # ---------------------------------------------
        # Incoming or outgoing
        # ---------------------------------------------

        if direction == "outgoing":
            params["fromAddress"] = WALLET

        elif direction == "incoming":
            params["toAddress"] = WALLET

        # ---------------------------------------------
        # Pagination
        # ---------------------------------------------

        if page_key:
            params["pageKey"] = page_key

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "alchemy_getAssetTransfers",
            "params": [params]
        }

        response = requests.post(URL, json=payload)

        print("\nHTTP STATUS:", response.status_code)

        data = response.json()

        # ---------------------------------------------
        # Error handling
        # ---------------------------------------------

        if "error" in data:

            print("\nERROR:")
            print(data["error"])

            break

        result = data.get("result", {})

        transfers = result.get("transfers", [])

        print(
            direction.upper(),
            "BATCH:",
            len(transfers)
        )

        all_transfers.extend(transfers)

        page_key = result.get("pageKey")

        if not page_key:
            break

    return all_transfers


# ============================================================
# OUTGOING
# ============================================================

print("\n==============================================")
print("CHECKING OUTGOING BEP-20 TRANSFERS")
print("==============================================")

outgoing = get_transfers("outgoing")


# ============================================================
# INCOMING
# ============================================================

print("\n==============================================")
print("CHECKING INCOMING BEP-20 TRANSFERS")
print("==============================================")

incoming = get_transfers("incoming")


# ============================================================
# DISPLAY RESULTS
# ============================================================

print("\n\n==============================================")
print("CRYPTOSHIELD - BSC WALLET HISTORY")
print("==============================================")

print("Wallet:")
print(WALLET)

print("\nOutgoing transfers:", len(outgoing))
print("Incoming transfers:", len(incoming))


# ============================================================
# OUTGOING DETAILS
# ============================================================

print("\n\n==============================================")
print("OUTGOING TRANSFERS")
print("==============================================")

for i, tx in enumerate(outgoing, 1):

    print("\n----------------------------------------------")
    print("Transaction:", i)

    print("Block:", tx.get("blockNum"))
    print("Hash:", tx.get("hash"))

    print("From:", tx.get("from"))
    print("To:", tx.get("to"))

    print("Amount:", tx.get("value"))
    print("Asset:", tx.get("asset"))

    metadata = tx.get("metadata")

    if metadata:
        print(
            "Timestamp:",
            metadata.get("blockTimestamp")
        )


# ============================================================
# INCOMING DETAILS
# ============================================================

print("\n\n==============================================")
print("INCOMING TRANSFERS")
print("==============================================")

for i, tx in enumerate(incoming, 1):

    print("\n----------------------------------------------")
    print("Transaction:", i)

    print("Block:", tx.get("blockNum"))
    print("Hash:", tx.get("hash"))

    print("From:", tx.get("from"))
    print("To:", tx.get("to"))

    print("Amount:", tx.get("value"))
    print("Asset:", tx.get("asset"))

    metadata = tx.get("metadata")

    if metadata:
        print(
            "Timestamp:",
            metadata.get("blockTimestamp")
        )


# ============================================================
# SUMMARY
# ============================================================

print("\n\n==============================================")
print("SUMMARY")
print("==============================================")

total = len(outgoing) + len(incoming)

print("Outgoing:", len(outgoing))
print("Incoming:", len(incoming))
print("Total:", total)

if total == 0:

    print("\nNo BEP-20 transfers found.")

else:

    print("\nBEP-20 activity found!")

print("\n==============================================")
print("DONE")
print("==============================================")
