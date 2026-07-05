import streamlit as st
import requests
import concurrent.futures
import re
import pandas as pd

# ==========================================
# CONFIGURATION - INSERT YOUR API KEYS HERE
# ==========================================
API_KEYS = {
    'virustotal': 'YOUR_VT_API_KEY_HERE',
    'abuseipdb': 'YOUR_ABUSEIPDB_API_KEY_HERE',
    'alienvault': 'YOUR_OTX_API_KEY_HERE'
}

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def detect_ioc_type(ioc):
    """Determines if the input is an IPv4 address or a file hash."""
    ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ipv4_pattern.match(ioc):
        return "ip"
    elif len(ioc) in [32, 40, 64]: # MD5, SHA-1, SHA-256
        return "hash"
    else:
        return "unknown"

def defang(ioc):
    """Defangs an IOC so it is not clickable/executable in ticketing systems."""
    return ioc.replace('.', '[.]')

# ==========================================
# API FUNCTIONS
# ==========================================
def check_virustotal(ioc, ioc_type):
    endpoint = "ip_addresses" if ioc_type == "ip" else "files"
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
    headers = {"x-apikey": API_KEYS['virustotal']}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0)
        return 0
    except:
        return "Error"

def check_abuseipdb(ioc, ioc_type):
    if ioc_type != "ip":
        return "N/A"
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Accept': 'application/json', 'Key': API_KEYS['abuseipdb']}
    try:
        response = requests.get(url, headers=headers, params={'ipAddress': ioc, 'maxAgeInDays': '90'})
        if response.status_code == 200:
            return f"{response.json()['data'].get('abuseConfidenceScore', 0)}%"
        return "Error"
    except:
        return "Error"

def check_alienvault(ioc, ioc_type):
    endpoint = "IPv4" if ioc_type == "ip" else "file"
    url = f"https://otx.alienvault.com/api/v1/indicators/{endpoint}/{ioc}/general"
    headers = {"X-OTX-API-KEY": API_KEYS['alienvault']}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get('pulse_info', {}).get('count', 0)
        return 0
    except:
        return "Error"

def process_single_ioc(ioc):
    """Worker function to process a single IOC across all APIs."""
    ioc_clean = ioc.strip()
    if not ioc_clean:
        return None
        
    ioc_type = detect_ioc_type(ioc_clean)
    if ioc_type == "unknown":
        return {
            "Indicator": ioc_clean, "Type": "UNKNOWN", 
            "VT Detections": "Error", "AbuseIPDB Score": "Error", "OTX Pulses": "Error"
        }
        
    vt_res = check_virustotal(ioc_clean, ioc_type)
    abuse_res = check_abuseipdb(ioc_clean, ioc_type)
    otx_res = check_alienvault(ioc_clean, ioc_type)
    
    return {
        "Indicator": ioc_clean,
        "Type": ioc_type.upper(),
        "VT Detections": vt_res,
        "AbuseIPDB Score": abuse_res,
        "OTX Pulses": otx_res
    }

# ==========================================
# STREAMLIT UI
# ==========================================
st.set_page_config(page_title="SOC Bulk IOC Aggregator", page_icon="🛡️", layout="wide")

st.title("🛡️ Bulk IOC Triage & Defanging Engine")
st.markdown("Paste a batch list of malicious indicators below (one per line) to parse, check reputation, and generate clean markdown metrics simultaneously.")
st.divider()

# Bulk Input Field
bulk_input = st.text_area("Paste Indicators Here (IPs or Hashes):", placeholder="8.8.8.8\n2e9f41ca2846683158cd2e108fe405079910bdd7\n192.0.2.1", height=200)

if st.button("Process Batch List", type="primary", use_container_width=True):
    ioc_list = [line.strip() for line in bulk_input.split('\n') if line.strip()]
    
    if not ioc_list:
        st.warning("⚠️ Input area is empty. Please paste your indicators first.")
    else:
        st.info(f"🚀 Processing {len(ioc_list)} total indicators in parallel...")
        
        # Parallel Execution Loop
        final_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ioc = {executor.submit(process_single_ioc, ioc): ioc for ioc in ioc_list}
            for future in concurrent.futures.as_completed(future_to_ioc):
                res = future.result()
                if res:
                    final_results.append(res)
        
        # Convert results list to Pandas Dataframe
        df = pd.DataFrame(final_results)
        
        # --- DATA ENRICHMENT: Calculate Visual Risk Levels ---
        def determine_risk(row):
            try:
                vt = int(row['VT Detections'])
                if vt > 15: return "🔴 CRITICAL"
                elif vt > 0: return "🟠 SUSPICIOUS"
                else: return "🟢 CLEAN"
            except:
                return "⚪ UNKNOWN"

        # Insert Risk Level column
        df.insert(1, "Risk Level", df.apply(determine_risk, axis=1))

        # Ensure VT Detections is numeric so the ProgressColumn works
        df['VT Detections'] = pd.to_numeric(df['VT Detections'], errors='coerce').fillna(0)
        
        # --- RENDER SUMMARY GRAPHIC TABLE ---
        st.subheader("📊 Visual Threat Matrix")
        
        st.dataframe(
            df,
            column_config={
                "Indicator": st.column_config.TextColumn("Target Indicator", width="large"),
                "Risk Level": st.column_config.TextColumn("Risk Severity", width="medium"),
                "VT Detections": st.column_config.ProgressColumn(
                    "VirusTotal Hits",
                    help="Total malicious detections from antivirus engines.",
                    format="%f engines",
                    min_value=0,
                    max_value=90, 
                ),
                "AbuseIPDB Score": st.column_config.TextColumn("AbuseIPDB Conf."),
                "OTX Pulses": st.column_config.NumberColumn("AlienVault Pulses")
            },
            use_container_width=True, 
            hide_index=True
        )
        st.divider()
        
        # --- GENERATE DEFANGED MARKDOWN REPORT (HIDDEN IN EXPANDER) ---
        st.subheader("📋 Ticketing Export")
        st.markdown("Your analysis is complete. Expand the section below to grab the raw markdown for your incident notes.")
        
        with st.expander("Click here to View and Copy Raw Markdown"):
            w_ioc = 68  
            w_typ = 6
            w_vt  = 21
            w_abu = 15
            w_otx = 17

            md_report = "### 🛡️ Bulk Threat Triage Summary Table\n\n"
            md_report += f"| {'Indicator (Defanged)'.ljust(w_ioc)} | {'Type'.ljust(w_typ)} | {'VirusTotal Detections'.ljust(w_vt)} | {'AbuseIPDB Conf.'.ljust(w_abu)} | {'AlienVault Pulses'.ljust(w_otx)} |\n"
            md_report += f"| {':---'.ljust(w_ioc)} | {':---'.ljust(w_typ)} | {':---'.ljust(w_vt)} | {':---'.ljust(w_abu)} | {':---'.ljust(w_otx)} |\n"
            
            for index, row in df.iterrows():
                defanged_ioc = f"`{defang(row['Indicator'])}`"
                vt_text = f"**{int(row['VT Detections'])}**"
                type_text = str(row['Type'])
                abuse_text = str(row['AbuseIPDB Score'])
                otx_text = str(row['OTX Pulses'])
                
                md_report += f"| {defanged_ioc.ljust(w_ioc)} | {type_text.ljust(w_typ)} | {vt_text.ljust(w_vt)} | {abuse_text.ljust(w_abu)} | {otx_text.ljust(w_otx)} |\n"
                
            # st.code forces the perfect monospaced font alignment and adds the copy button
            st.code(md_report, language="markdown")