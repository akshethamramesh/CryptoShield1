import requests

ALCHEMY_API_KEY = "alch_TuXyU5rwJa2OGHlXYCjO0"

url = f"https://bnb-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"

payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "eth_blockNumber",
    "params": []
}

response = requests.post(url, json=payload)

print("HTTP STATUS:", response.status_code)
print(response.json())
