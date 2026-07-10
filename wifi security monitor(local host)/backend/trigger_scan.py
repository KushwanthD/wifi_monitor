import requests
import json

url = "http://127.0.0.1:8000/api/agent/report"
headers = {"Content-Type": "application/json"}

payload = {
    "agent_id": "TEST-LAPTOP",
    "wifi": {
        "status": "connected",
        "interface_name": "Wi-Fi",
        "description": "Intel(R) Wi-Fi 6E AX211 160MHz",
        "mac_address": "00:11:22:33:44:55",
        "ssid": "NETGEAR-HOME",
        "bssid": "00:14:22:01:23:45",
        "band": "5 GHz",
        "channel": "6",
        "radio_type": "802.11ax",
        "authentication": "WPA2-Personal",
        "cipher": "CCMP",
        "receive_rate": "1201",
        "transmit_rate": "1201",
        "signal": 99
    },
    "devices": [
        {"ip": "192.168.1.100", "mac": "00:11:22:33:44:55", "vendor": "Apple", "is_host": True, "latency_ms": 0},
        {"ip": "192.168.1.101", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Unknown Device", "is_host": False, "latency_ms": 5},
        {"ip": "192.168.1.102", "mac": "11:22:33:44:55:66", "vendor": "Intel", "is_host": False, "latency_ms": 12}
    ],
    "wifi_scan": [
        {"ssid": "NETGEAR-HOME", "bssid": "00:14:22:01:23:45", "authentication": "WPA2-Personal", "channel": "6", "signal": 99},
        {"ssid": "Office_Secure", "bssid": "00:14:22:01:23:99", "authentication": "WPA3-Personal", "channel": "36", "signal": 80},
        {"ssid": "Open_WiFi", "bssid": "00:14:22:99:88:77", "authentication": "OPEN", "channel": "1", "signal": 60}
    ]
}

response = requests.post(url, headers=headers, data=json.dumps(payload))
print("Status Code:", response.status_code)
print("Response:", response.json())
