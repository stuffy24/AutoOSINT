import requests
import json
import socket
import subprocess
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Set your API keys
VIRUSTOTAL_API_KEY = "API_KEY"
ABUSEIPDB_API_KEY = "API_KEY"
SHODAN_API_KEY = "API_KEY"

# Define API URLs
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/domains/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
SHODAN_URL = "https://api.shodan.io/shodan/host/"

# Function to resolve domain to IP
def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"Error: Could not resolve {domain} to an IP address.")
        return None  # Return None if resolution fails

# Function to get WHOIS data
def get_whois(domain):
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        return result.stdout if result.returncode == 0 else "WHOIS lookup failed."
    except Exception as e:
        return f"Error fetching WHOIS data: {str(e)}"

# Function to get VirusTotal report
def get_virustotal_report(domain):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(VIRUSTOTAL_URL + domain, headers=headers)
    if response.status_code == 200:
        return response.json()
    return f"Error fetching VirusTotal data: {response.status_code}"

# Function to check AbuseIPDB reputation
def get_abuseipdb_report(ip):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "verbose": "true"}
    response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    return f"Error fetching AbuseIPDB data: {response.status_code}"

# Function to get Shodan report
def get_shodan_report(ip):
    response = requests.get(f"{SHODAN_URL}{ip}?key={SHODAN_API_KEY}")
    if response.status_code == 200:
        return response.json()
    return f"Error fetching Shodan data: {response.status_code}"

# Function to generate PDF report
def generate_report(domain, report):
    filename = f"osint_report_{domain}.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, f"OSINT Report for {domain}")
    c.drawString(100, 730, f"Date: {datetime.now().strftime('%Y-%m-%d')}")

    y_position = 700  # Starting Y position

    # Add sections to the report
    y_position = write_section(c, "WHOIS Data:", report.get("WHOIS", "No WHOIS data found"), y_position)
    y_position = write_section(c, "VirusTotal Report:", report.get("VirusTotal", "No data available"), y_position)
    y_position = write_section(c, "AbuseIPDB Report:", report.get("AbuseIPDB", "No data available"), y_position)
    y_position = write_section(c, "Shodan Report:", report.get("Shodan", "No data available"), y_position)

    c.save()
    print(f"Report saved: {filename}")


from reportlab.lib.utils import simpleSplit

from reportlab.lib.utils import simpleSplit

def write_section(c, title, data, y_position):
    """Write a section to the PDF, ensuring text wraps properly."""
    if y_position < 100:  # Create a new page if needed
        c.showPage()
        c.setFont("Helvetica", 12)
        y_position = 750

    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y_position, title)
    y_position -= 20  # Move down for content

    # Convert data to string if it's a dictionary (formatted JSON)
    if isinstance(data, dict):
        data = json.dumps(data, indent=4, sort_keys=True)
    
    # Wrap text properly
    c.setFont("Helvetica", 10)
    wrapped_text = simpleSplit(str(data), "Helvetica", 10, 400)  # Max width 400 pixels

    for line in wrapped_text:
        c.drawString(120, y_position, line)
        y_position -= 15
        if y_position < 50:  # Page break handling
            c.showPage()
            c.setFont("Helvetica", 10)
            y_position = 750

    return y_position  # Return updated y_position

    c.drawText(text)

    # Add sections to the report
    # Add sections to the report
    write_section("WHOIS Data:", report.get("WHOIS", "No WHOIS data found"))
    write_section("VirusTotal Report:", report.get("VirusTotal", "No data available"))
    write_section("AbuseIPDB Report:", report.get("AbuseIPDB", "No data available"))
    write_section("Shodan Report:", report.get("Shodan", "No data available"))


    c.save()
    print(f"Report saved: {filename}")

# Function to print JSON in a formatted way
def print_json_report(title, data):
    """Print JSON data properly and save full response to a file."""
    filename = "osint_output.txt"

    # Convert response to formatted JSON string
    if isinstance(data, dict):
        json_string = json.dumps(data, indent=4, sort_keys=True)
    else:
        json_string = str(data)

    # Print in terminal (line by line to avoid truncation)
    print(f"\n{title}:")
    for line in json_string.split("\n"):
        print(line)

    # Save full response to a file
    with open(filename, "a", encoding="utf-8") as file:
        file.write(f"\n{title}:\n")
        file.write(json_string + "\n" + "=" * 80 + "\n")  # Divider

    print(f"[✔] Full {title} saved to {filename}")





# Function to run OSINT automation
def run_osint(domain):
    print(f"Collecting OSINT for {domain}...\n")

    # WHOIS Info
    whois_data = get_whois(domain)
    print("\nWHOIS Data:")
    print(whois_data)

    # Resolve domain to IP
    ip = resolve_domain_to_ip(domain)
    if not ip:
        print(f"Could not resolve {domain} to an IP address.")
        return  # Stop execution if no IP is resolved

    print(f"Resolved {domain} to IP: {ip}")

    # VirusTotal Report
    vt_report = get_virustotal_report(domain)
    print_json_report("VirusTotal Report", vt_report)

    # AbuseIPDB Reputation
    abuse_report = get_abuseipdb_report(ip)
    print_json_report("AbuseIPDB Report", abuse_report)

    # Shodan Information
    shodan_report = get_shodan_report(ip)
    print_json_report("Shodan Report", shodan_report)


    # Aggregate Report
    report = {
        "WHOIS": whois_data,
        "VirusTotal": vt_report,
        "AbuseIPDB": abuse_report,
        "Shodan": shodan_report
    }

    # Generate PDF Report
    generate_report(domain, report)

    print(f"\nOSINT collection completed for {domain}. Report saved.")

# Run automation for a sample domain
if __name__ == "__main__":
    domain = input("Enter a domain to analyze: ")
    run_osint(domain)
