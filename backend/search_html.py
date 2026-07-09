with open("E:/vulnerabilities/wifi-security-monitor/frontend/index.html", "r", encoding="utf-8") as f:
    lines = f.readlines()

for idx, line in enumerate(lines):
    if "dl-banner" in line or "download-banner" in line:
        print(f"Line {idx+1}: {line.strip()}")
