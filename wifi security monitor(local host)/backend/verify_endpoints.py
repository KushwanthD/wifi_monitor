import requests

BASE_URL = "http://127.0.0.1:8000"

def test_assets():
    print("=== Testing Assets Endpoint ===")
    res = requests.get(f"{BASE_URL}/api/assets")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.json()
    print(f"Registered Assets count: {len(data)}")
    for asset in data:
        print(f"- MAC: {asset['mac']} | Name: {asset['name']} | Type: {asset['type']} | Vendor: {asset.get('expected_vendor')} | Channel: {asset.get('expected_channel')}")
    print("PASS\n")

def test_compliance():
    print("=== Testing Compliance Endpoint ===")
    res = requests.get(f"{BASE_URL}/api/compliance/TEST-LAPTOP")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.json()
    print("Compliance Payload:", data)
    assert data["wpa3_status"] == 0, "WPA2 connection should yield wpa3_status = 0"
    assert data["default_ssid_status"] == 0, "SSID 'NETGEAR-HOME' should yield default_ssid_status = 0"
    assert data["score"] == 40, f"Expected compliance score = 40 (wps=1, open_network=1, pmf=0, default_ssid=0, wpa3=0 -> 2/5 * 100), got {data['score']}"
    print("PASS\n")

def test_html_report():
    print("=== Testing HTML Executive Report Export ===")
    res = requests.get(f"{BASE_URL}/api/reports/export/TEST-LAPTOP?format=html")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    html = res.text
    assert "WiFi Security Monitoring Tool Audit" in html, "Report header missing"
    assert "CIS Compliance Score" in html, "Compliance score missing"
    assert "Active Security Threats" in html, "Threat list header missing"
    print("Report HTML Sample Length:", len(html))
    print("PASS\n")

def test_csv_report():
    print("=== Testing CSV Report Export ===")
    res = requests.get(f"{BASE_URL}/api/reports/export/TEST-LAPTOP?format=csv")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert "text/csv" in res.headers.get("content-type", ""), f"Expected text/csv content-type, got {res.headers.get('content-type')}"
    lines = res.text.splitlines()
    print("CSV Headers:", lines[0])
    assert "REPORT SUMMARY" in lines[0], "Expected REPORT SUMMARY in CSV first line"
    print("PASS\n")

if __name__ == "__main__":
    try:
        test_assets()
        test_compliance()
        test_html_report()
        test_csv_report()
        print("ALL TESTS PASSED SUCCESSFULLY!")
    except AssertionError as e:
        print("TEST FAILURE:", e)
    except Exception as e:
        print("ERROR RUNNING TESTS:", e)
