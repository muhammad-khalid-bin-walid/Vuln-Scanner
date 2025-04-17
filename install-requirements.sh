# Python dependencies
pip install requests bs4 fuzzywuzzy validators pyyaml jinja2 tqdm python-Levenshtein shodan censys

# XSStrike
git clone https://github.com/s0md3v/XSStrike.git && cd XSStrike && pip install -r requirements.txt

# Dalfox
go install github.com/hahwul/dalfox/v2@latest

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# OWASP ZAP
sudo apt-get install zaproxy

# Wapiti
pip install wapiti3

# XSSer
pip install xsser

# XSpear
sudo apt-get install ruby && gem install xspear

# Nikto
sudo apt-get install nikto

# Arachni
sudo apt-get install arachni

# SQLMap
git clone https://github.com/sqlmapproject/sqlmap.git

# WhatWeb
sudo apt-get install whatweb

# Gobuster
go install github.com/OJ/gobuster/v3@latest

# Dirb
sudo apt-get install dirb

# Dirsearch
git clone https://github.com/maurosoria/dirsearch.git && cd dirsearch && pip install -r requirements.txt

# TestSSL
git clone https://github.com/drwetter/testssl.sh.git

# Wafw00f
pip install wafw00f

# Amass
go install -v github.com/owasp-amass/amass/v3/...@master

# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Assetfinder
go install -v github.com/tomnomnom/assetfinder@latest

# Waybackurls
go install -v github.com/tomnomnom/waybackurls@latest

# Gau
go install github.com/lc/gau/v2/cmd/gau@latest

# Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# FFUF
go install -v github.com/ffuf/ffuf@latest

# Update Nuclei templates
nuclei -update-templates
