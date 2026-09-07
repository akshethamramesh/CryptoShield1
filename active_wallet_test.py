import os
import requests
from dotenv import load_dotenv

# ==========================================
# CRYPTOSHIELD - ACTIVE WALLET TEST
# ==========================================

load_dotenv(".env")

API_KEY = os.getenv("ALCHEMY_API_KEY")

if not API_KEY:
    print("ERROR: ALCHEMY_API_KEY not found in .env")
    exit()


# ==========================================
# CHAIN CONFIG
# ==========================================

CHAINS = {
    "Ethereum": {
        "url": f"https://eth-mainnet.g.alchemy.com/v2/{API_KEY}",
        "categories": [
            "external",
            "internal",
            "erc20"
        ]
    },

    "BSC": {
        "url": f"https://bnb-mainnet.g.alchemy.com/v2/{API_KEY}",
        "categories": [
            "external",
            "erc20"
        ]
    }
}


# ==========================================
# FETCH TRANSFERS
# ==========================================

def get_transfers(wallet, chain):

    config = CHAINS[chain]

    url = config["url"]

    all_transfers = []

    directions = [
        ("OUTGOING", "fromAddress"),
        ("INCOMING", "toAddress")
    ]

    for direction_name, address_type in directions:

        print()
        print(f"Checking {chain} {direction_name}...")

        page_key = None
        page = 1

        while True:

            params = {
                "fromBlock": "0x0",
                "toBlock": "latest",
                "category": config["categories"],
                "excludeZeroValue": True,
                "withMetadata": True,
                "maxCount": "0x64",
                address_type: wallet
            }

            if page_key:
                params["pageKey"] = page_key

            payload = {
                "jsonrpc": "2.0",
                "id": page,
                "method": "alchemy_getAssetTransfers",
                "params": [params]
            }

            try:

                response = requests.post(
                    url,
                    json=payload,
                    timeout=30
                )

                data = response.json()

                if "error" in data:
                    print("RPC ERROR:")
                    print(data["error"])
                    break

                result = data.get(
                    "result",
                    {}
                )

                transfers = result.get(
                    "transfers",
                    []
                )

                print(
                    f"Page {page}: {len(transfers)} transfers"
                )

                for tx in transfers:

                    tx["direction"] = direction_name
                    tx["chain"] = chain

                all_transfers.extend(transfers)

                page_key = result.get(
                    "pageKey"
                )

                if not page_key:
                    break

                page += 1

                # Prevent huge requests during prototype
                if page > 20:
                    print(
                        "Stopped after 20 pages."
                    )
                    break

            except Exception as e:

                print(
                    "Request error:",
                    e
                )

                break

    return all_transfers


# ==========================================
# DISPLAY RESULTS
# ==========================================

def display_results(wallet, chain, transfers):

    print()
    print("======================================")
    print(f"{chain.upper()} RESULT")
    print("======================================")

    print(
        "Wallet:",
        wallet
    )

    print(
        "Transactions found:",
        len(transfers)
    )

    if not transfers:

        print(
            "No transfer activity detected."
        )

        return


    print()
    print("REAL TRANSACTIONS")
    print("--------------------------------------")

    for i, tx in enumerate(
        transfers[:10],
        start=1
    ):

        print()
        print(
            f"Transaction #{i}"
        )

        print(
            "Direction:",
            tx.get("direction")
        )

        print(
            "From:",
            tx.get("from")
        )

        print(
            "To:",
            tx.get("to")
        )

        print(
            "Asset:",
            tx.get("asset")
        )

        print(
            "Value:",
            tx.get("value")
        )

        print(
            "Category:",
            tx.get("category")
        )

        print(
            "Hash:",
            tx.get("hash")
        )


# ==========================================
# MAIN
# ==========================================

print()
print("======================================")
print("          🛡️ CRYPTOSHIELD")
print("     ACTIVE WALLET TEST")
print("======================================")

wallet = input(
    "\nEnter wallet address: "
).strip()


if not wallet.startswith("0x") or len(wallet) != 42:

    print(
        "\n❌ Invalid EVM wallet address."
    )

    exit()


print()
print("Scanning Ethereum and BSC...")


ethereum_transfers = get_transfers(
    wallet,
    "Ethereum"
)

bsc_transfers = get_transfers(
    wallet,
    "BSC"
)


display_results(
    wallet,
    "Ethereum",
    ethereum_transfers
)

display_results(
    wallet,
    "BSC",
    bsc_transfers
)


# ==========================================
# FINAL SUMMARY
# ==========================================

print()
print("======================================")
print("        MULTI-CHAIN SUMMARY")
print("======================================")

print(
    "Ethereum:",
    len(ethereum_transfers),
    "transactions"
)

print(
    "BSC:",
    len(bsc_transfers),
    "transactions"
)


if ethereum_transfers:

    print(
        "\n✅ Activity detected on Ethereum."
    )

if bsc_transfers:

    print(
        "✅ Activity detected on BSC."
    )

if not ethereum_transfers and not bsc_transfers:

    print(
        "\n⚠️ No activity detected on "
        "Ethereum or BSC."
    )


print()
print("======================================")
print("             TEST COMPLETE")
print("======================================")
