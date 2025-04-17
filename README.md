Setup Steps
Step 1: Clone the Repository
Clone the Vuln-Scanner repository to your system
bash
git clone https://github.com/muhammad-khalid-bin-walid/Vuln-Scanner.git
cd Vuln-scanner
If you are not using a GitHub repository, copy the following files to a directory named vulnscanner:
•	vulnscanner.py (the main script)
•	config.yaml (configuration file)
•	report_template.html (HTML report template)
•	requirements.sh (dependency installation script)
Step 2: Install Dependencies
The requirements.sh script automates the installation of all dependencies and tools, including Python packages, Go-based tools, Ruby gems, and system utilities.
1.	Make the script executable:
bash
chmod +x requirements.sh
2.	Run the script as root:
bash
sudo ./requirements.sh
This script will:
•	Update package lists (apt-get update).
•	Install system dependencies (e.g., Python, Go, Ruby, curl, nmap).
•	Install Python packages (e.g., requests, pyyaml, weasyprint).
•	Install Go-based tools (e.g., Nuclei, Dalfox, Subfinder).
•	Install Ruby-based tools (e.g., WPScan, WhatWeb).
•	Clone and set up repositories for tools like XSStrike, SQLMap, Sn1per.
•	Create symbolic links for tool binaries in /usr/local/bin.
•	Update Nuclei templates (nuclei -update-templates).
•	Clean up temporary files.
Estimated Time: 30-60 minutes, depending on your system and network speed.
Troubleshooting:
•	If a tool fails to install, check the terminal output for errors.
•	Manually install missing tools (e.g., go install github.com/projectdiscovery/nuclei/v3@latest).
•	Ensure you have sufficient disk space and internet connectivity.
•	Check /var/log/apt or vulnscanner.log (created later) for detailed errors.
Step 3: Configure API Keys
API keys are required for target enrichment using Shodan, Censys, VirusTotal, DNSDB, and PassiveTotal. These are optional but recommended for enhanced reconnaissance.
1.	Open config.yaml in a text editor (e.g., nano config.yaml).
2.	Add your API keys in the scan_settings section:
yaml
scan_settings:
  shodan_api_key: "your_shodan_api_key"
  censys_api_id: "your_censys_api_id"
  censys_api_secret: "your_censys_api_secret"
  virustotal_api_key: "your_virustotal_api_key"
  dnsdb_api_key: "your_dnsdb_api_key"
  passivetotal_api_key: "your_passivetotal_api_key"
3.	Obtain API keys from:
o	Shodan: https://account.shodan.io/
o	Censys: https://censys.io/account
o	VirusTotal: https://www.virustotal.com/gui/join-us
o	DNSDB: https://www.dnsdb.info/
o	PassiveTotal (RiskIQ): https://community.riskiq.com/
4.	Save and close config.yaml.
Security Note: Keep API keys confidential and avoid exposing config.yaml in public repositories.
Step 4: Prepare Input Directory
Create a directory to store input files (subdomains, domains, JS files, paths, parameters, and logs).
bash
mkdir inputs
You can:
•	Manually create input files (e.g., inputs/subdomains.txt, inputs/domains.txt) with targets (one per line, e.g., subdomain.example.com or https://example.com).
•	Let the tool generate files during execution by selecting the generate option at prompts.
Example subdomains.txt:
sub1.example.com
sub2.example.com
Step 5: Verify Installation
Confirm that key tools are installed correctly by checking their versions:
bash
python3 --version
go version
nuclei -version
dalfox --version
xsstrike --version
zap-cli --version
nikto -Version
sqlmap --version
If any command fails, revisit Step 2 to troubleshoot the specific tool’s installation. For example:
•	For Nuclei: go install github.com/projectdiscovery/nuclei/v3@latest
•	For XSStrike: cd /opt/xsstrike && pip3 install -r requirements.txt
Step 6: Test the Scanner
Run the scanner to ensure it’s operational:
bash
python3 vulnscanner.py --input-dir inputs --config config.yaml --verbose
•	Expected Behavior:
o	The tool prompts for input files (e.g., Enter path for subdomains.txt).
o	Select skip for all prompts to test without inputs, or provide a file path.
o	The Kamehameha loading screen appears (if enabled in config.yaml).
o	The tool exits gracefully if no targets are provided.
•	Troubleshooting:
o	Permission Errors: Ensure inputs and scan_results directories are writable (chmod -R 755 inputs scan_results).
o	Missing Dependencies: Re-run requirements.sh or install missing Python packages (e.g., pip3 install pyyaml).
o	Tool Errors: Verify tool paths in config.yaml match installed locations (e.g., /usr/local/bin/nuclei).
Running the Scanner
To perform a full scan:
1.	Prepare input files or choose to generate them.
2.	Run the scanner:
bash
python3 vulnscanner.py --input-dir inputs --config config.yaml --verbose
3.	Respond to prompts:
o	For subdomains.txt, enter generate and provide a root domain (e.g., example.com) to use tools like Amass and Subfinder.
o	For other files, enter paths, generate, skip, or default.
o	Example:
o	Enter path for subdomains.txt (Enter for inputs/subdomains.txt, 'generate', 'skip', 'default'): generate
Enter root domain for subdomains generation (e.g., example.com): example.com
4.	Monitor the Kamehameha loading screen, which shows:
o	Animated Kamehameha ASCII art (configurable in config.yaml).
o	Targets scanned, elapsed time, and memory usage.
5.	Check outputs in scan_results/:
o	Per-Scan Reports: scan_results/per_scan_reports/<target_hash>/<tool>_report.<format> (JSON, TXT, Markdown, HTML).
o	Unified Report: scan_results/unified_report.<format> (JSON, HTML, PDF, CSV, XML, Markdown).
o	Logs: vulnscanner.log.
o	State: scan_results/scan_state.pkl for resuming scans.
Additional Configuration
Edit config.yaml to customize:
•	Tool Parameters: Adjust settings like nuclei_templates or xsstrike_params.
•	Scan Settings: Modify threads, timeout, rate_limit, or memory_limit_percent.
•	Notifications: Enable Slack, Discord, or Telegram notifications:
yaml
notifications:
  slack_webhook: "https://hooks.slack.com/services/xxx/yyy/zzz"
  enable: true
•	Kamehameha Loading Screen:
yaml
kamehameha:
  enable: true
  charge_time: 5
  theme: "blue"  # Options: blue, red, green, yellow
  animation_speed: 0.2

