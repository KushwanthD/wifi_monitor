with open("E:/vulnerabilities/wifi-security-monitor/frontend/app.js", "r", encoding="utf-8") as f:
    lines = f.readlines()

for idx, line in enumerate(lines):
    if "local-status-banner" in line or "banner" in line:
        print(f"Line {idx+1}: {line.strip()}")
