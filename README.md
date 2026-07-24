# 🛡️ Aegis Security — WiFi Security Monitoring Tool

A real-time Wi-Fi threat detection, device inventory, and security compliance assessment platform with behavioral baselining and actionable threat intelligence.

## 🚀 Live Access
You can access the deployed web dashboard here:
👉 **[https://wifi-monitor-x7jk.onrender.com/](https://wifi-monitor-x7jk.onrender.com/)**

---

## 🛠️ How it Works

The application operates on a client-server architecture:
1. **Server Dashboard**: Deployed on Render, providing the central visualization and security scoring engine.
2. **Scan Agent**: A lightweight, non-offensive PowerShell client script (`agent.ps1`) runs on a local machine to perform local Wi-Fi interface auditing, network device discovery, and active port checks.

### Running the Client Scan Agent
1. Access the web dashboard on your computer.
2. Download the `run_wifimonitor.bat` file using the **"Download Agent (.bat)"** button.
3. Run the batch file on your machine.
4. Note your **Computer Name / Agent ID** shown in the terminal.
5. Enter this Agent ID on the dashboard to link the live feed.

---

## 📱 Live Mobile Dashboard
To monitor your network security on a mobile device:
1. Open the dashboard on your PC and pair it with a connected remote agent.
2. Click **"Mobile Connect"** in the sidebar to generate a 6-digit pairing code.
3. Open the same Render URL on your mobile phone.
4. Enter the 6-digit code to securely stream live security alerts and subnet device logs directly to your phone.
