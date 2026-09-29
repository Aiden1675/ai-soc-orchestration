import json, requests
from datetime import datetime

print("== AI POWERED THREAT ANALYZER ==")
print("Powered by Ollama llama3")
print(f"Time: {datetime.now()}\n")

alerts = []
try:
    with open("/var/ossec/logs/alerts/alerts.json") as f:
        for line in f:
            try: alerts.append(json.loads(line))
            except: pass
except: pass

interesting = [a for a in alerts if
    a.get("rule",{}).get("level",0) >= 3][-5:]

if not interesting:
    print("[!] No alerts found - using sample alerts")
    interesting = [{
        "rule": {
            "level": 10,
            "description": "Multiple failed SSH login attempts"
        }
    }]

print(f"[*] Analyzing {len(interesting)} alerts with AI...\n")

for i, alert in enumerate(interesting, 1):
    desc = alert.get("rule",{}).get("description","")
    level = alert.get("rule",{}).get("level",0)

    print(f"-- ALERT [i] --")
    print(f"Description: {desc}")
    print(f"Level:       {level}")
    print(f"AI Analysis:")

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3:latest",
                "prompt": f"You are a SOC analyst. Analyze this security alert in exactly 3 sentences covering: 1) threat level 2) likely attack technique 3) recommended action. Alert: {desc}",
                "stream": False
            },
            timeout=180
        )
        analysis = response.json().get("response","")
        print(f"  {analysis}\n")
    except Exception as e:
        print(f"  Error: {e}\n")

print("-- SUMMARY --")
print(f"  Alerts analyzed: {len(interesting)}")
print(f"  AI model: llama3")
print(f"  Use this output in your IR reports")
