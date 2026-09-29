import subprocess, json, os, requests
from datetime import datetime
from collections import Counter

print("== SECURITY ORCHESTRATION ENGINE ==")
print(f"Time: {datetime.now()}\n")

results = {}

print("[1/6] Loading threat intelligence...")
try:
    r = requests.get(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        timeout=15
    )
    threat_ips = [l.strip() for l in r.text.splitlines()
        if l and not l.startswith("#")]
    results["threat_feed"] = len(threat_ips)
    print(f"      Loaded {len(threat_ips)} malicious IPs")
except Exception as e:
    threat_ips = []
    results["threat_feed"] = 0
    print("      Threat feed unavailable: " + repr(e))

print("[2/6] Parsing SIEM alerts...")
alerts = []
try:
    with open("/var/ossec/logs/alerts/alerts.json") as f:
        for line in f:
            try: alerts.append(json.loads(line))
            except: pass
except: pass
results["total_alerts"] = len(alerts)
print(f"      Parsed {len(alerts)} alerts")

print("[3/6] Extracting IOCs...")
iocs = set()
for a in alerts:
    ip = a.get("data",{}).get("scrip","")
    if ip and ip != "None":
        iocs.add(ip)
results["iocs"] = len(iocs)
print(f"      Found {len(iocs)} unique IPs")

print("[4/6] Correlating with threat feed...")
hits = [ip for ip in iocs if ip in threat_ips]
results["threat_hits"] = len(hits)
print(f"      Found {len(hits)} malicious IPs")

print("[5/6] Checking infrastructure...")
services = ["wazuh-manager","wazuh-indexer","wazuh-dashboard"]
down = []
for s in services:
    status = subprocess.run(
        ["systemctl","is-active",s],
        capture_output=True, text=True
    ).stdout.strip()
    if status != "active":
        down.append(s)
results["services_down"] = len(down)
print(f"      {len(services)-len(down)}/{len(services)} services healthy")

print("[6/6] Generating report...\n")

risk = 0
if hits: risk += 40
if down: risk += 30
if len(alerts) > 100: risk += 20
risk = min(100, risk)

critical = sum(1 for a in alerts if a.get("rule",{}).get("level",0) >= 12)
high = sum(1 for a in alerts if 8 <= a.get("rule",{}).get("level",0) < 12)
rules = Counter(a.get("rule",{}).get("description","") for a in alerts)

print("=" * 50)
print("  SECURITY ORCHESTRATION REPORT")
print(f"  {datetime.now()}")
print("=" * 50)
print(f"\n  THREAT INTELLIGENCE")
print(f"  Feed IPs loaded:    {results['threat_feed']}")
print(f"  IOCs extracted:     {results['iocs']}")
print(f"  Threat hits:        {results['threat_hits']}")

print(f"\n  SIEM ANALYSIS")
print(f"  Total alerts:       {results['total_alerts']}")
print(f"  Critical:           {critical}")
print(f"  High:               {high}")

print(f"\n INFRASTRUCTURE")
for s in services:
    status = subprocess.run(
        ["systemctl","is-active",s],
        capture_output=True, text=True
    ).stdout.strip()
    icon = "[UP]" if status == "active" else "[DOWN]"
    print(f"  {icon} {s}")

print(f"\n TOP RULES TRIGGERED")
for rule, count in rules.most_common(5):
    print(f"  {count:>4}x {rule[:45]}")

print(f"\n  RISK ASSESSMENT")
print(f"  Risk score:         {risk}/100")
print(f"  Rating: {'[AT RISK]' if risk >= 50 else '[MODERATE]' if risk >= 25 else '[SECURE]'}")

print("\n AUTOMATED ACTIONS")
if hits:
    print(f"  [!] Block {len(hits)} malicious IPs")
    for ip in hits:
        print(f"      sudo ufw deny from {ip}")
if down:
    print(f"  [!] Restart {len(down)} services")
    for s in down:
        print(f"      sudo systemctl restart {s}")
if not hits and not down:
    print("  [+] No immediate actions required")

print("=" * 50)

with open("orchestration_report.txt","w") as f:
    f.write(f"Orchestration Report - {datetime.now()}\n")
    f.write(f"Risk Score: {risk}/100\n")
    f.write(f"Alerts: {len(alerts)}\n")
    f.write(f"Threat hits: {len(hits)}\n")

print("\n[+] Report saved: orchestration_report.txt")
