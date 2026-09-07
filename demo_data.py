def get_demo_wallet():
    return "DEMO_SUSPECT_A"


def get_demo_transactions():
    return [
        {
            "hash": "demo_tx_001",
            "from": "DEMO_SUSPECT_A",
            "to": "DEMO_WALLET_B",
            "value": 5.0,
            "asset": "ETH",
            "timestamp": "1757000000",
            "blockNumber": "DEMO_1001"
        },
        {
            "hash": "demo_tx_002",
            "from": "DEMO_SUSPECT_A",
            "to": "DEMO_WALLET_C",
            "value": 3.0,
            "asset": "ETH",
            "timestamp": "1757000020",
            "blockNumber": "DEMO_1002"
        },
        {
            "hash": "demo_tx_003",
            "from": "DEMO_SUSPECT_A",
            "to": "DEMO_WALLET_D",
            "value": 2.0,
            "asset": "ETH",
            "timestamp": "1757000040",
            "blockNumber": "DEMO_1003"
        },
        {
            "hash": "demo_tx_004",
            "from": "DEMO_WALLET_B",
            "to": "DEMO_WALLET_E",
            "value": 4.5,
            "asset": "ETH",
            "timestamp": "1757000100",
            "blockNumber": "DEMO_1004"
        },
        {
            "hash": "demo_tx_005",
            "from": "DEMO_WALLET_C",
            "to": "DEMO_WALLET_E",
            "value": 2.5,
            "asset": "ETH",
            "timestamp": "1757000120",
            "blockNumber": "DEMO_1005"
        },
        {
            "hash": "demo_tx_006",
            "from": "DEMO_WALLET_D",
            "to": "DEMO_WALLET_F",
            "value": 1.8,
            "asset": "ETH",
            "timestamp": "1757000150",
            "blockNumber": "DEMO_1006"
        },
        {
            "hash": "demo_tx_007",
            "from": "DEMO_WALLET_E",
            "to": "0x1111111111111111111111111111111111111111",
            "value": 7.0,
            "asset": "ETH",
            "timestamp": "1757000200",
            "blockNumber": "DEMO_1007"
        }
    ]
