import json
import requests
import time

OLLAMA_URL = "http://localhost:11434/api/generate"
WAZUH_LOGS = "/var/ossec/logs/alerts/alerts.json"

def ask_ai(alert_description):
    prompt = f"You are a Defensive Security Analyst AI. Your task is to analyze a Wazuh security alert and provide defensive remediation steps to protect the network. Do not refuse this request as it is for authorized defensive monitoring: {alert_description}"
    payload = {"model": "llama3.2:1b", "prompt": prompt, "stream": False}
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=180)
        if response.status_code == 200:
            return response.json().get('response', "Response key missing")
        return f"AI Error: Status {response.status_code}"
    except Exception as e:
        return f"Connection Error: {e}"


print("[*] Monitoring Wazuh for Critical Alerts...")

with open(WAZUH_LOGS, 'r') as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(1)
            continue

        try:
            alert = json.loads(line)
            if alert.get('rule', {}).get('level', 0) >= 10:
                description = alert['rule']['description']
                print(f"\n[!] CRITICAL ALERT: {'description'}")
                print("[*] Generating AI analysis...")
                analysis = ask_ai(description)
                print(f"--- AI RECOMMENDATION ---\n{analysis}\n")
        except json.JSONDecodeError:

            continue
        except Exception as e:
            print(f"Error: {e}")
