import requests


API_KEY = "alch_TuXyU5rwJa2OGHlXYCjO0"

WALLET = "0xc3549a5184e9b1049258c5c14edbfb6309517ccb"

URL = (
    "https://eth-mainnet.g.alchemy.com/v2/"
    + API_KEY
)


def test(direction):

    print()
    print("=" * 70)
    print("TEST:", direction.upper())
    print("=" * 70)

    params = {
        "fromBlock": "0x0",
        "toBlock": "latest",
        "withMetadata": True,
        "excludeZeroValue": False,
        "maxCount": "0x64",
        "category": [
            "external",
            "erc20"
        ]
    }

    if direction == "from":
        params["fromAddress"] = WALLET
    else:
        params["toAddress"] = WALLET

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "alchemy_getAssetTransfers",
        "params": [params]
    }

    try:

        response = requests.post(
            URL,
            json=payload,
            timeout=30
        )

    except Exception as error:

        print("REQUEST ERROR:")
        print(error)

        return

    print()
    print("HTTP STATUS:", response.status_code)

    print()
    print("RAW RESPONSE:")
    print(response.text[:5000])

    if response.status_code != 200:
        return

    try:

        data = response.json()

    except Exception:

        print("Invalid JSON")
        return

    if "error" in data:

        print()
        print("ALCHEMY ERROR:")
        print(data["error"])

        return

    result = data.get(
        "result",
        {}
    )

    transfers = result.get(
        "transfers",
        []
    )

    print()
    print("TRANSFERS:", len(transfers))

    for i, tx in enumerate(transfers, 1):

        print()
        print("Transfer", i)
        print("-" * 50)

        print(
            "From:",
            tx.get("from")
        )

        print(
            "To:",
            tx.get("to")
        )

        print(
            "Value:",
            tx.get("value")
        )

        print(
            "Asset:",
            tx.get("asset")
        )

        print(
            "Category:",
            tx.get("category")
        )

        print(
            "Hash:",
            tx.get("hash")
        )


# ============================================================
# RUN BOTH DIRECTIONS
# ============================================================

print()
print("=" * 70)
print("              CRYPTOSHIELD ALCHEMY DEBUG")
print("=" * 70)

print()
print("Wallet:")
print(WALLET)

test("from")

test("to")

print()
print("=" * 70)
print("                    TEST COMPLETE")
print("=" * 70)
