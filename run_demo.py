"""
One-Click Interactive Demo Launcher for SIH26145 Platform.
Starts the FastAPI Backend, launches the SOC Web Dashboard in your browser,
and streams live traffic & synthetic attack threats in real time.
"""

import os
import sys
import time
import uvicorn
import webbrowser
import threading
import requests

def run_server():
    uvicorn.run("src.platform.api_server:app", host="127.0.0.1", port=8000, log_level="info")

def main():
    print("=========================================================================")
    print(" 🛡️  SIH26145 NETWORK SECURITY & THREAT INTELLIGENCE DEMO LAUNCHER     ")
    print("=========================================================================")
    print(" [1] Starting FastAPI Server & WebSocket Broadcaster at http://127.0.0.1:8000...")
    
    # Start server in background thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    time.sleep(2.0)
    print(" [2] Opening Interactive Web SOC Dashboard in default browser...")
    webbrowser.open("http://127.0.0.1:8000")
    
    print("\n=========================================================================")
    print("                      LIVE DEMO CONTROL MENU                             ")
    print("=========================================================================")
    print(" Choose an action to demonstrate real-time attack detection & SHAP alerts:")
    print("   1. ⚡ Inject DDoS Flood Attack")
    print("   2. 📡 Inject C2 Beaconing Attack")
    print("   3. 🌐 Inject DGA / DNS Tunneling Attack")
    print("   4. 🔒 Inject Encrypted Malware TLS Traffic")
    print("   5. 🔍 Inject Port Scanning Attack")
    print("   6. 📤 Inject Data Exfiltration Attack")
    print("   7. 🔄 Run Continuous Live Traffic & Random Attack Simulation")
    print("   0. 🚪 Exit Demo")
    print("=========================================================================\n")

    attack_map = {
        "1": "ddos",
        "2": "c2_beaconing",
        "3": "dga_dns_tunneling",
        "4": "malware_tls",
        "5": "port_scan",
        "6": "data_exfiltration"
    }

    try:
        while True:
            choice = input("Enter choice (1-7, 0 to exit): ").strip()
            if choice == "0":
                print("Exiting demo server...")
                break
            elif choice in attack_map:
                cat = attack_map[choice]
                print(f"--> Triggering live synthetic attack '{cat}'...")
                try:
                    res = requests.post(f"http://127.0.0.1:8000/api/v1/inject-attack?category={cat}")
                    if res.status_code == 200:
                        data = res.json()
                        print(f"    SUCCESS: Injected {data['packets_generated']} packets -> Reconstructed {data['flows_reconstructed']} flows -> Scored {data['incidents_detected']} Incidents!")
                    else:
                        print(f"    ERROR: {res.text}")
                except Exception as e:
                    print(f"    Connection Error: {e}")
            elif choice == "7":
                print("--> Running continuous live simulation (Press Ctrl+C to stop simulation loop)...")
                try:
                    categories = list(attack_map.values())
                    while True:
                        for cat in categories:
                            print(f"    [Simulating Traffic] Injecting {cat}...")
                            requests.post(f"http://127.0.0.1:8000/api/v1/inject-attack?category={cat}")
                            time.sleep(3.0)
                except KeyboardInterrupt:
                    print("\n--> Stopped continuous simulation loop.")
            else:
                print("Invalid choice. Please select 0 through 7.")
    except KeyboardInterrupt:
        print("\nExiting demo server...")

if __name__ == "__main__":
    main()
