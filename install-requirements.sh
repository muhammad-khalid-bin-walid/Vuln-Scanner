#!/bin/bash

# requirements.sh - Install dependencies and tools for VulnScanner
# Run this script as root or with sudo on a Debian-based system (e.g., Kali Linux)

echo "[*] Starting installation of VulnScanner dependencies and tools..."

# Exit on error
set -e

# Update package lists
echo "[*] Updating package lists..."
apt-get update

# Install system dependencies
echo "[*] Installing system dependencies..."
apt-get install -y \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    golang-go \
    ruby \
    libxml2-dev \
    libxslt-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    build-essential \
    zlib1g-dev \
    snapd \
    unzip \
    nmap \
    whois \
    dnsutils \
    chromium-browser \
    tor \
    proxychains

# Install Python packages
echo "[*] Installing Python packages..."
pip3 install --upgrade pip
pip3 install \
    requests \
    beautifulsoup4 \
    fuzzywuzzy \
    validators \
    pyyaml \
    jinja2 \
    tqdm \
    python-Levenshtein \
    shodan \
    censys \
    weasyprint \
    colorama \
    prompt_toolkit \
    virustotal-api \
    dnspython \
    passivetotal \
    psutil \
    aiohttp

# Install Go
echo "[*] Ensuring Go is installed..."
if ! command -v go &> /dev/null; then
    echo "[*] Installing Go..."
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    source ~/.bashrc
    rm go1.21.5.linux-amd64.tar.gz
else
    echo "[*] Go is already installed"
fi

# Install Go-based tools
echo "[*] Installing Go-based tools..."
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/OWASP/Amass/v4/...@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/epi052/feroxbuster/v2@latest

# Move Go binaries to /usr/local/bin
echo "[*] Moving Go binaries to /usr/local/bin..."
mv ~/go/bin/* /usr/local/bin/ 2>/dev/null || true

# Install Ruby-based tools
echo "[*] Installing Ruby-based tools..."
gem install wpscan
gem install whatweb

# Install OWASP ZAP
echo "[*] Installing OWASP ZAP..."
snap install zaproxy --classic

# Install Nikto
echo "[*] Installing Nikto..."
apt-get install -y nikto

# Install Arachni
echo "[*] Installing Arachni..."
wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
tar -xzf arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
mv arachni-1.5.1-0.5.12 /opt/arachni
ln -s /opt/arachni/bin/arachni /usr/local/bin/arachni
rm arachni-1.5.1-0.5.12-linux-x86_64.tar.gz

# Install W3af
echo "[*] Installing W3af..."
git clone https://github.com/andresriancho/w3af.git /opt/w3af
cd /opt/w3af
pip3 install -r requirements.txt
chmod +x w3af_console
ln -s /opt/w3af/w3af_console /usr/local/bin/w3af
cd -

# Install SQLMap
echo "[*] Installing SQLMap..."
git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Install NoSQLMap
echo "[*] Installing NoSQLMap..."
git clone https://github.com/codingo/NoSQLMap.git /opt/nosqlmap
cd /opt/nosqlmap
pip3 install -r requirements.txt
ln -s /opt/nosqlmap/nosqlmap.py /usr/local/bin/nosqlmap
cd -

# Install SQLNinja
echo "[*] Installing SQLNinja..."
apt-get install -y sqlninja

# Install CMSscan (example placeholder, replace with actual tool if available)
echo "[*] Installing CMSscan (placeholder)..."
# If CMSscan is a specific tool, replace with actual installation steps
# Example: git clone https://github.com/example/cmsscan.git /opt/cmsscan
# For now, skip or add a placeholder
touch /usr/local/bin/cmsscan
chmod +x /usr/local/bin/cmsscan
echo "#!/bin/bash" > /usr/local/bin/cmsscan
echo "echo 'CMSscan placeholder - replace with actual tool'" >> /usr/local/bin/cmsscan

# Install Gobuster
echo "[*] Installing Gobuster..."
apt-get install -y gobuster

# Install Dirb
echo "[*] Installing Dirb..."
apt-get install -y dirb

# Install Dirsearch
echo "[*] Installing Dirsearch..."
git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch
cd /opt/dirsearch
pip3 install -r requirements.txt
ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch
cd -

# Install TestSSL.sh
echo "[*] Installing TestSSL.sh..."
git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Install SSLyze
echo "[*] Installing SSLyze..."
pip3 install sslyze

# Install A2SV
echo "[*] Installing A2SV..."
git clone https://github.com/hahwul/a2sv.git /opt/a2sv
cd /opt/a2sv
pip3 install -r requirements.txt
ln -s /opt/a2sv/a2sv.py /usr/local/bin/a2sv
cd -

# Install Wafw00f
echo "[*] Installing Wafw00f..."
pip3 install wafw00f
ln -s $(which wafw00f) /usr/local/bin/wafw00f

# Install WhatWaf
echo "[*] Installing WhatWaf..."
git clone https://github.com/Ekultek/WhatWaf.git /opt/whatwaf
cd /opt/whatwaf
pip3 install -r requirements.txt
ln -s /opt/whatwaf/whatwaf.py /usr/local/bin/whatwaf
cd -

# Install WAFP (placeholder, as it may not be widely available)
echo "[*] Installing WAFP (placeholder)..."
# If WAFP is a specific tool, replace with actual installation steps
touch /usr/local/bin/wafp
chmod +x /usr/local/bin/wafp
echo "#!/bin/bash" > /usr/local/bin/wafp
echo "echo 'WAFP placeholder - replace with actual tool'" >> /usr/local/bin/wafp

# Install Sn1per
echo "[*] Installing Sn1per..."
git clone https://github.com/1N3/Sn1per.git /opt/sn1per
cd /opt/sn1per
bash install.sh
ln -s /opt/sn1per/sniper /usr/local/bin/sniper
cd -

# Install Findomain
echo "[*] Installing Findomain..."
wget https://github.com/Findomain/Findomain/releases/download/9.0.4/findomain-linux.zip
unzip findomain-linux.zip
mv findomain /usr/local/bin/
chmod +x /usr/local/bin/findomain
rm findomain-linux.zip

# Install Sublist3r
echo "[*] Installing Sublist3r..."
git clone https://github.com/aboul3la/Sublist3r.git /opt/sublist3r
cd /opt/sublist3r
pip3 install -r requirements.txt
ln -s /opt/sublist3r/sublist3r.py /usr/local/bin/sublist3r
cd -

# Install Photon
echo "[*] Installing Photon..."
git clone https://github.com/s0md3v/Photon.git /opt/photon
cd /opt/photon
pip3 install -r requirements.txt
ln -s /opt/photon/photon.py /usr/local/bin/photon
cd -

# Install XSStrike
echo "[*] Installing XSStrike..."
git clone https://github.com/s0md3v/XSStrike.git /opt/xsstrike
cd /opt/xsstrike
pip3 install -r requirements.txt
ln -s /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike
cd -

# Install JAWS (Just Another Web Scanner)
echo "[*] Installing JAWS..."
git clone https://github.com/stark0de/jaws.git /opt/jaws
cd /opt/jaws
pip3 install -r requirements.txt
ln -s /opt/jaws/jaws.py /usr/local/bin/jaws
cd -

# Install XSSer
echo "[*] Installing XSSer..."
pip3 install xsser
ln -s $(which xsser) /usr/local/bin/xsser

# Install XSpear
echo "[*] Installing XSpear..."
gem install xspear
ln -s $(which xspear) /usr/local/bin/xspear

# Install KXSS
echo "[*] Installing KXSS..."
go install github.com/tomnomnom/hacks/kxss@latest
mv ~/go/bin/kxss /usr/local/bin/

# Install SpiderFoot
echo "[*] Installing SpiderFoot..."
git clone https://github.com/smicallef/spiderfoot.git /opt/spiderfoot
cd /opt/spiderfoot
pip3 install -r requirements.txt
ln -s /opt/spiderfoot/sf.py /usr/local/bin/spiderfoot
cd -

# Install Arjun
echo "[*] Installing Arjun..."
git clone https://github.com/s0md3v/Arjun.git /opt/arjun
cd /opt/arjun
pip3 install -r requirements.txt
ln -s /opt/arjun/arjun.py /usr/local/bin/arjun
cd -

# Install Meg
echo "[*] Installing Meg..."
go install github.com/tomnomnom/meg@latest
mv ~/go/bin/meg /usr/local/bin/

# Install Httpprobe
echo "[*] Installing Httpprobe..."
go install github.com/tomnomnom/httprobe@latest
mv ~/go/bin/httprobe /usr/local/bin/

# Update Nuclei templates
echo "[*] Updating Nuclei templates..."
nuclei -update-templates

# Clean up
echo "[*] Cleaning up..."
apt-get clean
rm -rf /var/lib/apt/lists/*

echo "[*] Installation complete! All dependencies and tools are installed."
echo "[*] You may need to configure API keys in config.yaml for Shodan, Censys, VirusTotal, DNSDB, and PassiveTotal."
echo "[*] Run the scanner with: python3 vulnscanner.py --input-dir inputs --config config.yaml --verbose"
