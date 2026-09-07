import os
import requests
from dotenv import load_dotenv

load_dotenv(".env")

API_KEY = os.getenv("ALCHEMY_API_KEY")

URL = f"https://eth-mainnet.g.alchemy.com/v2/{API_KEY}"

payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "alchemy_getAssetTransfers",
    "params": [{
        "fromBlock": "0x0",
        "toBlock": "latest",
        "fromAddress": "0xc3549a5184e9b1049258c5c14edbfb6309517ccb",
        "category": [
            "external",
            "internal",
            "erc20"
        ],
        "withMetadata": True,
        "excludeZeroValue": True,
        "maxCount": "0x64"
    }]
}

response = requests.post(
    URL,
    json=payload,
    timeout=30
)

print("HTTP STATUS:", response.status_code)

data = response.json()

print("\nFULL RESPONSE:")
print(data)
