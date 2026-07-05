# 🛡️ SOC Bulk IOC Aggregator & Triage Engine

<img width="1919" height="1070" alt="image" src="https://github.com/user-attachments/assets/9d5c6a24-cda5-43f6-a97c-2fc03b9fad68" />

<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/f02042c4-78e2-41a2-962b-b0a196fc5f89" />

<img width="1919" height="1073" alt="image" src="https://github.com/user-attachments/assets/753feb70-c65c-4cde-b372-273ce65dfbd7" />


## Overview
As a SOC Analyst, I built this tool to automate the tedious process of initial threat triage. Instead of manually querying individual IPs and file hashes across multiple browser tabs, this Python application processes bulk indicators concurrently, visualizes the risk, and generates a defanged markdown report ready for ticketing systems (like Jira or TheHive).

## 🚀 Features
* **Bulk Processing:** Paste dozens of IOCs at once; the engine auto-detects if they are IPv4 addresses or File Hashes.
* **Concurrent API Queries:** Hits VirusTotal, AbuseIPDB, and AlienVault OTX simultaneously using Python multithreading.
* **Visual Threat Matrix:** Built with Streamlit, the UI dynamically calculates risk levels and renders progress bars for malware engine hits.
* **One-Click Ticketing:** Automatically defangs malicious indicators (e.g., `8.8.8.8` to `8[.]8[.]8[.]8`) and generates perfectly aligned, copy-pasteable Markdown tables.

## 🛠️ Skills Demonstrated
* Security Automation & SOAR Concepts
* Python (Multithreading, Regex, Data manipulation with Pandas)
* REST API Integration & JSON Parsing
* Frontend UI Development (Streamlit)

## How to Use
1. Clone the repository.
2. Install requirements: `pip install -r requirements.txt`
3. Insert your own free API keys into the `API_KEYS` dictionary inside the script.
4. Run the app: `python -m streamlit run ioc_checker.py`
