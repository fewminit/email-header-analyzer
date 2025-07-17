# 📬 Email Header Analyzer
Hey Welcome here , the script is--
A Python CLI tool to analyze raw email headers for spoofing, authentication failures (SPF, DKIM, DMARC), and sender geolocation.

## 🧠 What It Does

- Extracts sender & relay IPs from email headers
- Checks SPF, DKIM, and DMARC authentication results
- Detects possible spoofing by comparing mail hops
- Geolocates IP addresses using ipapi.co

## 🚀 Run It

```bash
pip install requests
python email_header_analyzer.py
