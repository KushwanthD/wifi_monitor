import requests
import json

url_asset = "http://127.0.0.1:8000/api/assets"
headers = {"Content-Type": "application/json"}

# Add expected AP
payload_asset = {
    "mac": "00:14:22:01:23:45",
    "type": "ap",
    "name": "HQ Core Access Point",
    "expected_vendor": "Cisco",
    "expected_channel": "36",
    "expected_encryption": "WPA3",
    "location": "Server Room",
    "owner": "Network Admin",
    "notes": "Main corporate AP"
}

res1 = requests.post(url_asset, headers=headers, data=json.dumps(payload_asset))
print("Register AP Asset status:", res1.status_code)

# Add expected client device
payload_asset2 = {
    "mac": "AA:BB:CC:DD:EE:FF",
    "type": "device",
    "name": "Accounting Printer",
    "expected_vendor": "HP",
    "expected_channel": None,
    "expected_encryption": None,
    "location": "Accounting Office",
    "owner": "Finance",
    "notes": "Managed printer"
}

res2 = requests.post(url_asset, headers=headers, data=json.dumps(payload_asset2))
print("Register Printer Asset status:", res2.status_code)

# Now trigger the scan again to see updated alerts and score!
url_scan = "http://127.0.0.1:8000/api/agent/report"
payload_scan = {
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

res3 = requests.post(url_scan, headers=headers, data=json.dumps(payload_scan))
print("Trigger scan updated status:", res3.status_code)
print("Updated Response:", res3.json())
