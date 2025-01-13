from flask import Flask, render_template, request, jsonify
import logging
import requests

app = Flask(__name__)

# Configure the logger
log_file_path = "threat_detection.log"
logging.basicConfig(filename=log_file_path, level=logging.INFO, format="%(asctime)s - %(levelname)s: %(message)s")
logger = logging.getLogger("ThreatDetection")

 
# API keys
ABUSEIPDB_API_KEY = "68c8b2da5a37936ced6a34b6cf40eb3d97a160baecd6f6aa1c465be4adbab240a764b4981e59a157"
SAFE_BROWSING_API_KEY = "AIzaSyBUA_73Ui4vF7lPMKLhpoKJAzvhu0cjXcw"
VIRUSTOTAL_API_KEY = "4844b540a2a44109ff22275c746cebf0239a4627fe2cc2a1869ba9e4d48c17c9"

# Function to check IP with AbuseIPDB
def check_ip_with_abuseipdb(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip_address}

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        result = response.json()
        score = result.get("data", {}).get("abuseConfidenceScore", 0)
        return score >= 75, score
    return False, None

# Function to check URL with Google Safe Browsing
def check_url_with_safe_browsing(url):
    safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    params = {"key": SAFE_BROWSING_API_KEY}
    threat_info = {
        "client": {
            "clientId": "your-app-id",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        }
    }

    response = requests.post(safe_browsing_url, params=params, json=threat_info)
    if response.status_code == 200:
        result = response.json()
        return "matches" in result
    return False

# Function to check IP with VirusTotal
def check_with_virustotal(api_key, input_value):
    import base64

    base_url_ip = "https://www.virustotal.com/api/v3/ip_addresses"
    base_url_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}

    if input_value.count(".") == 3 and all(part.isdigit() for part in input_value.split(".")):
        # It's an IP address
        response = requests.get(f"{base_url_ip}/{input_value}", headers=headers)
    else:
        # It's a URL
        encoded_url = base64.urlsafe_b64encode(input_value.encode()).decode().strip()
        response = requests.get(f"{base_url_url}/{encoded_url}", headers=headers)

    if response.status_code == 200:
        result = response.json()
        malicious_count = result["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
        harmless_count = result["data"]["attributes"]["last_analysis_stats"].get("harmless", 0)

        if malicious_count > 0:
            logger.warning(f"Suspicious detected by VirusTotal: {input_value}")
            return "Suspicious"
        elif harmless_count > malicious_count:
            logger.info(f"Not flagged by VirusTotal: {input_value}")
            return "Not Suspicious"
        else:
            logger.info(f"Inconclusive result from VirusTotal for: {input_value}")
            return "Inconclusive"
    else:
        logger.error(f"Error checking input with VirusTotal. Status code: {response.status_code}")
        return "Error"

    
@app.route("/", methods=["GET", "POST"])
def home():
    result = None  # Set result to None by default
    if request.method == "POST":
        ip_address = request.form.get("ip")
        url = request.form.get("url")

        result = {}
        suspicious_count = 0  # Count of suspicious results

        # Check IP address with AbuseIPDB and VirusTotal
        if ip_address:
            # AbuseIPDB check
            abuseipdb_result, score = check_ip_with_abuseipdb(ip_address)
            result["AbuseIPDB (IP)"] = "Suspicious" if abuseipdb_result else "Not Suspicious"
            if abuseipdb_result:
                suspicious_count += 1

            # VirusTotal check for IP
            virustotal_ip_result = check_with_virustotal(VIRUSTOTAL_API_KEY, ip_address)
            result["VirusTotal (IP)"] = (
                "Suspicious" if virustotal_ip_result == "Suspicious" else "Not Suspicious"
            )
            if virustotal_ip_result == "Suspicious":
                suspicious_count += 1

        # Check URL with Google Safe Browsing and VirusTotal
        if url:
            # Google Safe Browsing check
            safe_browsing_result = check_url_with_safe_browsing(url)
            result["Google Safe Browsing (URL)"] = (
                "Suspicious" if safe_browsing_result else "Not Suspicious"
            )
            if safe_browsing_result:
                suspicious_count += 1

            # VirusTotal check for URL
            virustotal_url_result = check_with_virustotal(VIRUSTOTAL_API_KEY, url)
            result["VirusTotal (URL)"] = ( 
                "Suspicious" if virustotal_url_result == "Suspicious" else "Not Suspicious"
            )
            if virustotal_url_result == "Suspicious":
                suspicious_count += 1

   

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug="true")
