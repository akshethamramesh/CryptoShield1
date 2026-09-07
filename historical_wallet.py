import requests
import json

ALCHEMY_API_KEY = "alch_TuXyU5rwJa2OGHlXYCjO0"

url = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"

wallet = "0xc3549a5184e9b1049258c5c14edbfb6309517ccb"

payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "alchemy_getAssetTransfers",
    "params": [{
        "fromBlock": "0x0",
        "toBlock": "latest",
        "fromAddress": wallet,
        "category": ["external"],
        "withMetadata": True,
        "excludeZeroValue": False,
        "maxCount": "0x5"
    }]
}

response = requests.post(url, json=payload)

print("HTTP STATUS:", response.status_code)
print("\nRAW RESPONSE:")
print(json.dumps(response.json(), indent=2))
