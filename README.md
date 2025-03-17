# AutoOSINT
This script automates Open-Source Intelligence (OSINT) collection for a given domain and provides a fully customizable reporting template. Users can modify the script to generate custom reports in different formats, adjust data sources, or add additional security checks.




🔍 Features
✅ Domain Resolution - Converts a domain name into an IP address
✅ WHOIS Lookup - Fetches domain registration details
✅ VirusTotal Scan - Checks domain reputation and security threats
✅ AbuseIPDB Analysis - Retrieves IP abuse reports and confidence scores
✅ Shodan Search - Gathers open ports, services, and vulnerabilities
✅ Report Generation - Saves results as a PDF report and a structured text file
✅ Formatted Output - Ensures long JSON responses are fully visible without truncation

📌 How It Works
The script prompts the user to enter a domain name.
It resolves the domain to an IP address.
The following OSINT queries are performed:
WHOIS lookup
VirusTotal domain analysis
AbuseIPDB IP reputation check
Shodan network scan
Results are displayed in the terminal and saved to a structured text file.
A PDF report is generated with detailed findings.

⚡ Installation & Usage
🔧 Requirements
Python 3.x
requests (for API calls)
reportlab (for PDF generation)
Install dependencies using:

bash
Copy
Edit
pip install requests reportlab
🚀 Run the Script
bash
Copy
Edit
python recon.py
Enter the domain name when prompted, and the script will collect OSINT data, display it, and generate reports.

🛡️ Notes
This script requires API keys for VirusTotal, AbuseIPDB, and Shodan.
Ensure your API keys are valid and properly set in the script.
Some WHOIS queries may be blocked depending on your network or registrar restrictions.
This script is for educational and security research purposes only.
👨‍💻 Contributing
Feel free to submit issues or pull requests if you have improvements or additional features to suggest!

📜 License
This project is released under the MIT License.

💡 Why Use This Script?
Quickly analyze any domain or IP for security research.
Save OSINT results without manually running multiple tools.
Generate clear and formatted reports for documentation.
🚀 Get started with your OSINT research today!
