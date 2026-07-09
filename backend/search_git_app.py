import subprocess

cmd = ["git", "log", "-p", "-G", "ping", "--", "frontend/app.js"]
result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore", cwd="E:/vulnerabilities/wifi-security-monitor")

print("LOG CONTAINING ping:")
lines = result.stdout.splitlines()
for idx, line in enumerate(lines[:500]):
    if "fetch" in line or "http" in line or "BASE_URL" in line:
        print(f"Line {idx}: {line}")
