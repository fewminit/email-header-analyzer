import re
import requests

def extract_ips(header):
    return re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", header)

def extract_auth_results(header):
    auth_results = {}
    spf = re.search(r'spf=(pass|fail|neutral)', header)
    dkim = re.search(r'dkim=(pass|fail|neutral)', header)
    dmarc = re.search(r'dmarc=(pass|fail|none)', header)

    if spf: auth_results['SPF'] = spf.group(1)
    if dkim: auth_results['DKIM'] = dkim.group(1)
    if dmarc: auth_results['DMARC'] = dmarc.group(1)

    return auth_results

def get_geo(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/").json()
        return f"{response.get('city', '')}, {response.get('country_name', '')}"
    except:
        return "Unknown Location"

def detect_spoofing(header):
    received = re.findall(r"Received: from\s(.+)", header)
    if len(received) < 2:
        return "Insufficient hops to analyze spoofing"
    first_hop = received[0]
    last_hop = received[-1]
    if first_hop != last_hop:
        return "⚠️ Potential spoofing: mismatch in received chain"
    return "✔️ No obvious spoofing detected"

def main():
    print("🔍Hey Akash here:), Paste your full email header below (end with a blank line):")
    lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        lines.append(line)

    header = "\n".join(lines)
    ips = extract_ips(header)
    auth = extract_auth_results(header)
    spoof = detect_spoofing(header)

    print("\n📊 Analysis Report:\n")
    print("🔹 IPs found in header:")
    for ip in ips:
        print(f"  - {ip} ({get_geo(ip)})")

    print("\n🔹 Authentication Results:")
    for k, v in auth.items():
        print(f"  {k}: {v}")

    print(f"\n🔹 Spoofing Check: {spoof}")

if __name__ == "__main__":
    main()
