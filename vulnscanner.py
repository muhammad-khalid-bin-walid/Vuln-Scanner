import os
import subprocess
import json
import logging
import yaml
import validators
import concurrent.futures
import argparse
import curses
import time
import csv
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from typing import List, Dict, Set, Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from tqdm import tqdm
import hashlib
import pickle
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import shodan
import censys.certificates
import virustotal_python
from colorama import Fore, init
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from weasyprint import HTML
import psutil
import asyncio
import aiohttp
from dnspython import dns.resolver
from passivetotal import AccountClient

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnscanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Single Kamehameha ASCII art
KAMEHAMEHA_ART = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢠⠳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⢸⢸⢳⡙⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠖⡏⠀⠀⠀⢸⠀⠐⡜⣆⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⢞⠵⢸⠀⠀⢀⡇⣸⠀⡆⠘⣌⢆⠀⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⢞⡵⠁⡆⡇⠀⡠⠋⡼⠀⠀⡇⠀⠘⠈⢧⡏⡄⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⠀⠀⠀⠀⢀⡴⣡⡯⠀⢀⡇⣧⠞⠁⡰⠃⠀⠀⣧⠀⠀⠀⢸⡇⢃⢸⢇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⡀⠀⠀⢠⢎⡜⡿⠁⠀⢸⣇⡵⠁⠀⠀⠀⠀⠀⣿⠀⠀⠀⠈⠀⢸⣸⠘⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⢣⠀⡴⣡⣿⠁⠃⠀⢀⣾⡿⠁⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠈⡏⠀⢇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⠈⢇⡇⣿⡏⠀⠀⠀⣼⣿⠃⠀⠀⠀⠀⢀⠇⡰⣿⠀⠀⠀⠀⠀⡇⠁⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⠐⠄⠀⠏⡇⠀⠀⣧⣿⡇⡀⡜⢰⠀⠀⡘⡐⠁⠏⡆⠀⠀⡄⢠⡇⡄⠀⠈⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠦⢠⣧⠀⣆⣿⣿⢁⣷⣇⡇⠀⣴⣯⠀⠀⠀⡇⠀⣸⡇⣾⡿⠁⠀⡀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⠀⠀⠀⢀⢀⢠⠀⠸⣿⣆⢹⣿⣿⣾⣿⣿⣠⢾⠛⠁⠀⠀⠀⡇⡠⡟⣿⣿⠃⠀⠀⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠘⡶⣄⠀⢸⠸⣼⣧⡀⣿⣿⣾⣿⣿⣿⣿⣿⡇⠘⠀⡀⠀⠀⢠⠟⠀⠃⢹⣥⠃⠀⢠⢏⣜⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠙⡌⠳⢄⣣⠹⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⡇⠀⠀⢀⣄⣴⡢⠀⠀⠀⡿⣯⠀⠐⠁⠘⣻⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠘⢎⢶⣍⣀⠈⢿⣿⣿⣿⣿⣿⣿⣦⠑⣤⡀⠀⣰⠟⡿⠁⠀⠀⠈⠀⠁⠀⠀⡀⡰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⢣⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠘⣷⣾⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⡵⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠑⣝⠻⠿⣿⣿⣿⣿⣿⣿⣿⣇⠀⣿⣿⣿⣇⣀⣤⠆⠀⠁⠀⠉⠀⠸⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⡇⢸⣿⣿⣿⣿⣿⣿⣿⣼⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠐⢤⡀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠱⢬⣙⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣏⡄⠀⠀⠀⠀⠀⠀⠈⠻⠆⠀⠈⠑⠒⣿⣦⣆⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

class VulnScanner:
    def __init__(self, input_dir: str, config_file: str = 'config.yaml', verbose: bool = False):
        self.input_dir = input_dir
        self.config = self.load_config(config_file)
        self.output_dir = self.config['output']['directory']
        self.per_scan_report_dir = os.path.join(self.output_dir, self.config['output']['per_scan_report_dir'])
        self.results = {}
        self.scanned_targets = set()
        self.state_file = os.path.join(self.output_dir, 'scan_state.pkl')
        self.session = self.setup_session()
        self.verbose = verbose
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.per_scan_report_dir, exist_ok=True)
        os.makedirs(self.input_dir, exist_ok=True)
        self.load_state()
        self.env = Environment(loader=FileSystemLoader('.'))
        self.shodan_api = self.setup_shodan()
        self.censys_api = self.setup_censys()
        self.virustotal_api = self.setup_virustotal()
        self.dnsdb_api = self.setup_dnsdb()
        self.passivetotal_api = self.setup_passivetotal()
        self.validate_tools()
        self.input_files = self.prompt_for_input_files()
        self.prompt_session = PromptSession(multiline=False, completer=WordCompleter(['generate', 'skip', 'default']))

    def load_config(self, config_file: str) -> Dict:
        """Load and validate configuration file."""
        if not os.path.exists(config_file):
            logger.error(f"Config file {config_file} not found")
            raise FileNotFoundError(f"Config file {config_file} not found")
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            if not config:
                raise ValueError("Empty configuration file")
            return config
        except Exception as e:
            logger.error(f"Error loading config {config_file}: {e}")
            raise

    def validate_tools(self) -> None:
        """Check if all tools are available."""
        for tool, path in self.config['tools'].items():
            if not path:
                continue
            if tool == 'custom_script':
                if not os.path.exists(path):
                    logger.warning(f"Custom script {path} not found")
            else:
                try:
                    subprocess.run([path, '--version'], capture_output=True, check=True, timeout=10)
                except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    logger.error(f"Tool {tool} not found or not executable at {path}")
                    raise RuntimeError(f"Tool {tool} not found or not executable at {path}")

    def setup_session(self) -> requests.Session:
        """Setup requests session with retries, proxy, and auth."""
        session = requests.Session()
        retries = Retry(total=self.config['scan_settings']['retries'], backoff_factor=1)
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        if self.config['scan_settings'].get('proxy'):
            session.proxies = {'http': self.config['scan_settings']['proxy'], 'https': self.config['scan_settings']['proxy']}
        session.cookies.update(self.config['auth'].get('cookies', {}))
        session.headers.update(self.config['auth'].get('headers', {}))
        if self.config['auth'].get('oauth_token'):
            session.headers['Authorization'] = f"Bearer {self.config['auth']['oauth_token']}"
        for key, value in self.config['auth'].get('api_tokens', {}).items():
            session.headers[key] = value
        return session

    def setup_shodan(self) -> Optional[shodan.Shodan]:
        """Setup Shodan API client."""
        api_key = self.config['scan_settings'].get('shodan_api_key')
        if api_key:
            try:
                return shodan.Shodan(api_key)
            except Exception as e:
                logger.error(f"Failed to setup Shodan: {e}")
        return None

    def setup_censys(self) -> Optional[censys.certificates.CensysCertificates]:
        """Setup Censys API client."""
        api_id = self.config['scan_settings'].get('censys_api_id')
        api_secret = self.config['scan_settings'].get('censys_api_secret')
        if api_id and api_secret:
            try:
                return censys.certificates.CensysCertificates(api_id, api_secret)
            except Exception as e:
                logger.error(f"Failed to setup Censys: {e}")
        return None

    def setup_virustotal(self) -> Optional[virustotal_python.VirusTotal]:
        """Setup VirusTotal API client."""
        api_key = self.config['scan_settings'].get('virustotal_api_key')
        if api_key:
            try:
                return virustotal_python.VirusTotal(api_key)
            except Exception as e:
                logger.error(f"Failed to setup VirusTotal: {e}")
        return None

    def setup_dnsdb(self) -> Optional[dns.resolver.Resolver]:
        """Setup DNSDB API client (simplified)."""
        api_key = self.config['scan_settings'].get('dnsdb_api_key')
        if api_key:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ['api.dnsdb.info']
                return resolver
            except Exception as e:
                logger.error(f"Failed to setup DNSDB: {e}")
        return None

    def setup_passivetotal(self) -> Optional[AccountClient]:
        """Setup PassiveTotal API client."""
        api_key = self.config['scan_settings'].get('passivetotal_api_key')
        if api_key:
            try:
                return AccountClient(api_key=api_key)
            except Exception as e:
                logger.error(f"Failed to setup PassiveTotal: {e}")
        return None

    async def async_http_request(self, url: str, method: str = 'GET') -> Optional[Dict]:
        """Perform asynchronous HTTP request."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, timeout=10) as response:
                    return await response.json() if response.content_type == 'application/json' else await response.text()
        except Exception as e:
            logger.error(f"Async HTTP request failed for {url}: {e}")
            return None

    def prompt_for_input_files(self) -> Dict[str, List[str]]:
        """Prompt user for input files and generate if needed."""
        files = {
            'subdomains': [],
            'domains': [],
            'js': [],
            'paths': [],
            'params': [],
            'logs': []
        }
        print(f"\n{Fore.CYAN}=== Input File Configuration ===")
        for file_type, default_file in self.config['input_files'].items():
            if file_type == 'logs':
                default_files = default_file
            else:
                default_files = [default_file]
            for default in default_files:
                path = os.path.join(self.input_dir, default)
                prompt = self.prompt_session.prompt(
                    f"Enter path for {default} (Enter for {path}, 'generate', 'skip', 'default'): "
                ).strip()
                if prompt.lower() == 'generate':
                    self.generate_input_file(file_type, path)
                elif prompt.lower() == 'skip':
                    continue
                elif prompt.lower() == 'default' or not prompt:
                    path = path
                else:
                    path = prompt
                if os.path.exists(path):
                    if file_type == 'logs':
                        files['logs'].append(path)
                    else:
                        files[file_type].append(path)
                else:
                    logger.warning(f"File {path} not found")
        return files

    def generate_input_file(self, file_type: str, output_path: str) -> None:
        """Generate input file using appropriate tools."""
        domain = self.prompt_session.prompt(f"Enter root domain for {file_type} generation (e.g., example.com): ").strip()
        if not validators.domain(domain):
            logger.error(f"Invalid domain: {domain}")
            return
        try:
            if file_type in ['subdomains', 'domains']:
                self.generate_subdomains(domain, output_path)
            elif file_type == 'js':
                self.generate_js_file(domain, output_path)
            elif file_type in ['paths', 'params']:
                self.generate_paths_params(domain, output_path)
            elif file_type == 'logs':
                self.generate_log_file(output_path)
            logger.info(f"Generated {file_type} file: {output_path}")
        except Exception as e:
            logger.error(f"Error generating {file_type} file: {e}")

    def generate_subdomains(self, domain: str, output_path: str) -> None:
        """Generate subdomains using multiple tools."""
        subdomains = set()
        temp_file = os.path.join(self.input_dir, f"temp_{domain}.txt")

        # Amass
        try:
            cmd = [self.config['tools']['amass']] + self.config['scan_settings']['amass_params'].split() + ['-d', domain, '-o', temp_file]
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600)
            subdomains.update(self.read_file(temp_file))
        except Exception as e:
            logger.error(f"Amass failed for {domain}: {e}")

        # Subfinder
        try:
            cmd = [self.config['tools']['subfinder'], '-d', domain, '-o', temp_file] + self.config['scan_settings']['subfinder_params'].split()
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            subdomains.update(self.read_file(temp_file))
        except Exception as e:
            logger.error(f"Subfinder failed for {domain}: {e}")

        # Findomain
        try:
            cmd = [self.config['tools']['findomain'], '-t', domain, '-o']
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            temp_findomain = f"{domain}.txt"
            subdomains.update(self.read_file(temp_findomain))
            if os.path.exists(temp_findomain):
                os.remove(temp_findomain)
        except Exception as e:
            logger.error(f"Findomain failed for {domain}: {e}")

        # Assetfinder
        try:
            cmd = [self.config['tools']['assetfinder'], '-subs-only', domain]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            with open(temp_file, 'w') as f:
                f.write(result.stdout)
            subdomains.update(self.read_file(temp_file))
        except Exception as e:
            logger.error(f"Assetfinder failed for {domain}: {e}")

        # Sublist3r
        try:
            cmd = ['python3', self.config['tools']['sublist3r'], '-d', domain, '-o', temp_file] + self.config['scan_settings']['sublist3r_params'].split()
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            subdomains.update(self.read_file(temp_file))
        except Exception as e:
            logger.error(f"Sublist3r failed for {domain}: {e}")

        # Filter live subdomains with Httpx
        live_file = os.path.join(self.input_dir, f"live_{domain}.txt")
        try:
            with open(temp_file, 'w') as f:
                f.write('\n'.join(subdomains))
            cmd = [self.config['tools']['httpx'], '-l', temp_file, '-o', live_file] + self.config['scan_settings']['httpx_params'].split()
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            subdomains = set(self.read_file(live_file))
        except Exception as e:
            logger.error(f"Httpx failed for {domain}: {e}")

        # Save to output
        try:
            with open(output_path, 'w') as f:
                f.write('\n'.join(subdomains))
        except Exception as e:
            logger.error(f"Error saving subdomains to {output_path}: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        if os.path.exists(live_file):
            os.remove(live_file)

    def generate_js_file(self, domain: str, output_path: str) -> None:
        """Generate JS file using Katana, Hakrawler, and Photon."""
        js_urls = set()
        temp_file = os.path.join(self.input_dir, f"temp_js_{domain}.txt")

        # Katana
        try:
            cmd = [self.config['tools']['katana'], '-u', f"https://{domain}"] + self.config['scan_settings']['katana_params'].split() + ['-o', temp_file]
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            js_urls.update(line for line in self.read_file(temp_file) if line.endswith('.js'))
        except Exception as e:
            logger.error(f"Katana failed for {domain}: {e}")

        # Hakrawler
        try:
            cmd = [self.config['tools']['hakrawler'], '-url', f"https://{domain}", '-depth', '3']
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            with open(temp_file, 'w') as f:
                f.write(result.stdout)
            js_urls.update(line for line in self.read_file(temp_file) if line.endswith('.js'))
        except Exception as e:
            logger.error(f"Hakrawler failed for {domain}: {e}")

        # Photon
        try:
            cmd = ['python3', self.config['tools']['photon'], '-u', f"https://{domain}", '-o', temp_file] + self.config['scan_settings']['photon_params'].split()
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            js_urls.update(line for line in self.read_file(temp_file) if line.endswith('.js'))
        except Exception as e:
            logger.error(f"Photon failed for {domain}: {e}")

        # Save to output
        try:
            with open(output_path, 'w') as f:
                f.write('\n'.join(js_urls) if js_urls else f"https://{domain}/script.js\nhttps://www.{domain}/app.js")
        except Exception as e:
            logger.error(f"Error saving JS file {output_path}: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)

    def generate_paths_params(self, domain: str, output_path: str) -> None:
        """Generate paths and parameters using multiple tools."""
        paths = set()
        temp_file = os.path.join(self.input_dir, f"temp_paths_{domain}.txt")

        # Waybackurls
        try:
            cmd = [self.config['tools']['waybackurls'], domain]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            with open(temp_file, 'w') as f:
                f.write(result.stdout)
            paths.update(self.read_file(temp_file))
        except Exception as e:
            logger.error(f"Waybackurls failed for {domain}: {e}")

        # Gau
        try:
            cmd = [self.config['tools']['gau'], domain] + self.config['scan_settings']['gau_params'].split()
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            with open(temp_file, 'w') as f:
                f.write(result.stdout)
            paths.update(self.read_file(temp_file))
        except Exception as e:
            logger.error(f"Gau failed for {domain}: {e}")

        # Hakrawler
        try:
            cmd = [self.config['tools']['hakrawler'], '-url', f"https://{domain}", '-depth', '3']
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            with open(temp_file, 'w') as f:
                f.write(result.stdout)
            paths.update(self.read_file(temp_file))
        except Exception as e:
            logger.error(f"Hakrawler failed for {domain}: {e}")

        # Arjun
        try:
            cmd = ['python3', self.config['tools']['arjun'], '-u', f"https://{domain}"] + self.config['scan_settings']['arjun_params'].split() + ['-o', temp_file]
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            paths.update(self.read_file(temp_file))
        except Exception as e:
            logger.error(f"Arjun failed for {domain}: {e}")

        # Save to output
        try:
            with open(output_path, 'w') as f:
                f.write('\n'.join(paths))
        except Exception as e:
            logger.error(f"Error saving paths to {output_path}: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)

    def generate_log_file(self, output_path: str) -> None:
        """Generate placeholder log file."""
        try:
            with open(output_path, 'w') as f:
                f.write(f"Sample log entry for {datetime.now()}\n")
        except Exception as e:
            logger.error(f"Error generating log file {output_path}: {e}")

    def save_state(self) -> None:
        """Save scan state to resume later."""
        try:
            with open(self.state_file, 'wb') as f:
                pickle.dump({'results': self.results, 'scanned_targets': self.scanned_targets}, f)
        except Exception as e:
            logger.error(f"Error saving state: {e}")

    def load_state(self) -> None:
        """Load scan state if exists."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'rb') as f:
                    state = pickle.load(f)
                    self.results = state['results']
                    self.scanned_targets = state['scanned_targets']
                logger.info("Loaded previous scan state")
            except Exception as e:
                logger.error(f"Error loading state: {e}")

    def read_file(self, file_path: str) -> List[str]:
        """Read lines from a file, ignoring empty lines."""
        if not os.path.exists(file_path):
            logger.warning(f"File {file_path} not found")
            return []
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return []

    def parse_log_files(self, log_files: List[str]) -> List[str]:
        """Extract URLs or domains from log files."""
        targets = []
        for fpath in log_files:
            lines = self.read_file(fpath)
            for line in lines:
                if validators.url(line) or validators.domain(line):
                    targets.append(line)
        return list(set(targets))

    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid URL or domain."""
        return validators.url(target) or validators.domain(target)

    def kamehameha_loading_screen(self, stdscr, total_targets: int, scan_type: str):
        """Display animated Kamehameha loading screen with single ASCII art."""
        if not self.config['kamehameha']['enable']:
            return
        color_map = {'blue': Fore.BLUE, 'red': Fore.RED, 'green': Fore.GREEN, 'yellow': Fore.YELLOW}
        theme = color_map.get(self.config['kamehameha']['theme'], Fore.BLUE)
        curses.curs_set(0)
        stdscr.timeout(100)
        charge_time = self.config['kamehameha']['charge_time']
        animation_speed = self.config['kamehameha']['animation_speed']
        start_time = time.time()
        pulse = 0
        completed_targets = 0

        while time.time() - start_time < charge_time or completed_targets < total_targets:
            stdscr.clear()
            # Pulsing effect by alternating brightness
            pulse_color = theme if pulse % 2 == 0 else Fore.WHITE
            stdscr.addstr(0, 0, f"{pulse_color}Charging Kamehameha for {scan_type}...\n{KAMEHAMEHA_ART}")
            stdscr.addstr(25, 0, f"Targets Scanned: {completed_targets}/{total_targets}")
            stdscr.addstr(26, 0, f"Elapsed Time: {int(time.time() - start_time)}s")
            stdscr.addstr(27, 0, f"Memory Usage: {psutil.virtual_memory().percent}%")
            stdscr.refresh()
            pulse += 1
            time.sleep(animation_speed)
            if time.time() - start_time > charge_time:
                completed_targets += 1
        stdscr.clear()
        stdscr.addstr(0, 0, f"{theme}KAMEHAMEHA UNLEASHED! Scanning complete.")
        stdscr.refresh()
        time.sleep(1)

    def send_notification(self, message: str) -> None:
        """Send notifications via multiple channels."""
        if not self.config['notifications']['enable']:
            return
        try:
            if self.config['notifications']['slack_webhook']:
                payload = {'text': message}
                requests.post(self.config['notifications']['slack_webhook'], json=payload)
            if self.config['notifications']['discord_webhook']:
                payload = {'content': message}
                requests.post(self.config['notifications']['discord_webhook'], json=payload)
            if self.config['notifications']['telegram_bot_token'] and self.config['notifications']['telegram_chat_id']:
                url = f"https://api.telegram.org/bot{self.config['notifications']['telegram_bot_token']}/sendMessage"
                payload = {'chat_id': self.config['notifications']['telegram_chat_id'], 'text': message}
                requests.post(url, json=payload)
            logger.info("Notification sent")
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")

    def generate_per_scan_report(self, target: str, tool: str, findings: Dict, output_file: str, start_time: datetime, end_time: datetime) -> str:
        """Generate per-scan report in multiple formats."""
        report_data = {
            'target': target,
            'tool': tool,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'parameters': self.config['scan_settings'].get(f'{tool}_params', ''),
            'vulnerabilities': findings.get('vulnerabilities', []),
            'output_file': output_file,
            'error': findings.get('error', None)
        }
        target_dir = os.path.join(self.per_scan_report_dir, hashlib.md5(target.encode()).hexdigest())
        os.makedirs(target_dir, exist_ok=True)
        report_base = os.path.join(target_dir, f"{tool}_report")

        report_formats = self.config['output']['per_scan_report_format']
        report_file = None
        try:
            if report_formats in ['json', 'all']:
                json_file = f"{report_base}.json"
                with open(json_file, 'w') as f:
                    json.dump(report_data, f, indent=2)
                report_file = json_file
            if report_formats in ['txt', 'all']:
                txt_file = f"{report_base}.txt"
                with open(txt_file, 'w') as f:
                    f.write(f"Scan Report\n")
                    f.write(f"Target: {target}\n")
                    f.write(f"Tool: {tool}\n")
                    f.write(f"Start Time: {start_time}\n")
                    f.write(f"End Time: {end_time}\n")
                    f.write(f"Parameters: {self.config['scan_settings'].get(f'{tool}_params', '')}\n")
                    f.write(f"Output File: {output_file}\n")
                    if report_data['error']:
                        f.write(f"Error: {report_data['error']}\n")
                    f.write("\nVulnerabilities:\n")
                    for vuln in report_data['vulnerabilities']:
                        f.write(f"- {vuln['vulnerability']} (Severity: {vuln['severity']})\n")
                        f.write(f"  Details: {vuln['details']}\n")
                if report_formats == 'txt':
                    report_file = txt_file
            if report_formats in ['markdown', 'all']:
                md_file = f"{report_base}.md"
                with open(md_file, 'w') as f:
                    f.write(f"# Scan Report\n")
                    f.write(f"- **Target**: {target}\n")
                    f.write(f"- **Tool**: {tool}\n")
                    f.write(f"- **Start Time**: {start_time}\n")
                    f.write(f"- **End Time**: {end_time}\n")
                    f.write(f"- **Parameters**: {self.config['scan_settings'].get(f'{tool}_params', '')}\n")
                    f.write(f"- **Output File**: {output_file}\n")
                    if report_data['error']:
                        f.write(f"- **Error**: {report_data['error']}\n")
                    f.write("\n## Vulnerabilities\n")
                    for vuln in report_data['vulnerabilities']:
                        f.write(f"- **{vuln['vulnerability']}** (Severity: {vuln['severity']})\n")
                        f.write(f"  - Details: {vuln['details']}\n")
                if report_formats == 'markdown':
                    report_file = md_file
            if report_formats in ['html', 'all']:
                html_file = f"{report_base}.html"
                template = self.env.get_template(self.config['output']['html_template'])
                with open(html_file, 'w') as f:
                    f.write(template.render(
                        results={target: {tool: findings}},
                        summary={'total_targets': 1, 'vulnerabilities': len(findings.get('vulnerabilities', [])),
                                 'critical': sum(1 for v in findings.get('vulnerabilities', []) if v['severity'] == 'Critical'),
                                 'high': sum(1 for v in findings.get('vulnerabilities', []) if v['severity'] == 'High'),
                                 'medium': sum(1 for v in findings.get('vulnerabilities', []) if v['severity'] == 'Medium'),
                                 'low': sum(1 for v in findings.get('vulnerabilities', []) if v['severity'] == 'Low')},
                        timestamp=start_time.isoformat()
                    ))
                if report_formats == 'html':
                    report_file = html_file
        except Exception as e:
            logger.error(f"Error generating report for {tool} on {target}: {e}")
        if report_data['vulnerabilities'] and any(v['severity'] in ['Critical', 'High'] for v in report_data['vulnerabilities']):
            self.send_notification(f"Critical/High severity vulnerability found on {target} with {tool}")
        return report_file

    def run_tool(self, cmd: List[str], target: str, output_file: str, tool_name: str) -> Dict:
        """Run a scanning tool with rate limiting and resource monitoring."""
        start_time = datetime.now()
        memory_usage = psutil.virtual_memory().percent
        if memory_usage > self.config['scan_settings']['memory_limit_percent']:
            logger.warning(f"High memory usage ({memory_usage}%), pausing scan")
            time.sleep(10)
        time.sleep(1 / self.config['scan_settings']['rate_limit'])
        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.config['scan_settings']['timeout']
            )
            findings = self.parse_tool_output(tool_name, result.stdout, output_file)
            end_time = datetime.now()
            findings['report_file'] = self.generate_per_scan_report(target, tool_name, findings, output_file, start_time, end_time)
            logger.info(f"Scan completed: {tool_name} on {target}")
            return findings
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            end_time = datetime.now()
            findings = {'vulnerabilities': [], 'error': str(e)}
            findings['report_file'] = self.generate_per_scan_report(target, tool_name, findings, output_file, start_time, end_time)
            logger.error(f"Scan failed: {tool_name} on {target}: {e}")
            return findings

    def parse_tool_output(self, tool: str, output: str, output_file: str) -> Dict:
        """Parse tool output and save to file."""
        try:
            with open(output_file, 'w') as f:
                f.write(output)
        except Exception as e:
            logger.error(f"Error saving output to {output_file}: {e}")
        findings = []
        for line in output.splitlines():
            if any(kw in line.lower() for kw in ['vulnerability', 'alert', 'found', 'detected']):
                severity = 'Medium'
                if 'critical' in line.lower():
                    severity = 'Critical'
                elif 'high' in line.lower():
                    severity = 'High'
                elif 'low' in line.lower():
                    severity = 'Low'
                findings.append({
                    'vulnerability': line.strip(),
                    'severity': severity,
                    'details': output_file
                })
        return {'vulnerabilities': findings, 'output_file': output_file}

    def run_xsstrike(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['xsstrike'], '-u', target] + self.config['scan_settings']['xsstrike_params'].split()
        return self.run_tool(cmd, target, output_file, 'xsstrike')

    def run_dalfox(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['dalfox'], 'url', target] + self.config['scan_settings']['dalfox_params'].split() + ['-o', output_file]
        return self.run_tool(cmd, target, output_file, 'dalfox')

    def run_nuclei(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['nuclei'], '-u', target, '-o', output_file, '-t', self.config['scan_settings']['nuclei_templates']]
        return self.run_tool(cmd, target, output_file, 'nuclei')

    def run_jaws(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['jaws'], '-u', target] + self.config['scan_settings']['jaws_params'].split() + ['-o', output_file]
        return self.run_tool(cmd, target, output_file, 'jaws')

    def run_zap(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['zap'], 'quick-scan'] + self.config['scan_settings']['zap_params'].split() + ['-r', target, '-o', output_file]
        return self.run_tool(cmd, target, output_file, 'zap')

    def run_wapiti(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['wapiti'], '-u', target, '-o', output_file] + self.config['scan_settings']['wapiti_params'].split()
        return self.run_tool(cmd, target, output_file, 'wapiti')

    def run_xsser(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['xsser'], '-u', target] + self.config['scan_settings']['xsser_params'].split()
        return self.run_tool(cmd, target, output_file, 'xsser')

    def run_xspear(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['xspear'], '-u', target] + self.config['scan_settings']['xspear_params'].split() + ['-o', output_file]
        return self.run_tool(cmd, target, output_file, 'xspear')

    def run_kxss(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['kxss'], '-u', target] + self.config['scan_settings']['kxss_params'].split()
        return self.run_tool(cmd, target, output_file, 'kxss')

    def run_nikto(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['nikto'], '-h', target, '-o', output_file] + self.config['scan_settings']['nikto_params'].split()
        return self.run_tool(cmd, target, output_file, 'nikto')

    def run_arachni(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['arachni'], '--report-save-path', output_file] + self.config['scan_settings']['arachni_params'].split() + [target]
        return self.run_tool(cmd, target, output_file, 'arachni')

    def run_w3af(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['w3af']] + self.config['scan_settings']['w3af_params'].split() + ['-t', target, '-o', output_file]
        return self.run_tool(cmd, target, output_file, 'w3af')

    def run_sqlmap(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['sqlmap'], '-u', target, '-o', output_file] + self.config['scan_settings']['sqlmap_params'].split()
        return self.run_tool(cmd, target, output_file, 'sqlmap')

    def run_nosqlmap(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['nosqlmap']] + self.config['scan_settings']['nosqlmap_params'].split() + ['-u', target, '-o', output_file]
        return self.run_tool(cmd, target, output_file, 'nosqlmap')

    def run_sqlninja(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['sqlninja']] + self.config['scan_settings']['sqlninja_params'].split() + ['-t', target, '-o', output_file]
        return self.run_tool(cmd, target, output_file, 'sqlninja')

    def run_whatweb(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['whatweb'], target] + self.config['scan_settings']['whatweb_params'].split() + ['--log-json', output_file]
        return self.run_tool(cmd, target, output_file, 'whatweb')

    def run_wpscan(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['wpscan'], '--url', target, '-o', output_file] + self.config['scan_settings']['wpscan_params'].split()
        return self.run_tool(cmd, target, output_file, 'wpscan')

    def run_cmsscan(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['cmsscan'], '-u', target, '-o', output_file] + self.config['scan_settings']['cmsscan_params'].split()
        return self.run_tool(cmd, target, output_file, 'cmsscan')

    def run_gobuster(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['gobuster']] + self.config['scan_settings']['gobuster_params'].split() + ['-u', target, '-o', output_file]
        return self.run_tool(cmd, target, output_file, 'gobuster')

    def run_dirb(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['dirb'], target] + self.config['scan_settings']['dirb_params'].split() + ['-o', output_file]
        return self.run_tool(cmd, target, output_file, 'dirb')

    def run_dirsearch(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['dirsearch'], '-u', target, '-o', output_file] + self.config['scan_settings']['dirsearch_params'].split()
        return self.run_tool(cmd, target, output_file, 'dirsearch')

    def run_feroxbuster(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['feroxbuster'], '-u', target, '-o', output_file] + self.config['scan_settings']['feroxbuster_params'].split()
        return self.run_tool(cmd, target, output_file, 'feroxbuster')

    def run_testssl(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['testssl'], target] + self.config['scan_settings']['testssl_params'].split() + ['--logfile', output_file]
        return self.run_tool(cmd, target, output_file, 'testssl')

    def run_sslyze(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['sslyze'], '--regular', target] + self.config['scan_settings']['sslyze_params'].split() + ['--json_out', output_file]
        return self.run_tool(cmd, target, output_file, 'sslyze')

    def run_a2sv(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['a2sv'], '-t', target, '-o', output_file] + self.config['scan_settings']['a2sv_params'].split()
        return self.run_tool(cmd, target, output_file, 'a2sv')

    def run_wafw00f(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['wafw00f'], target] + self.config['scan_settings']['wafw00f_params'].split() + ['-o', output_file]
        return self.run_tool(cmd, target, output_file, 'wafw00f')

    def run_whatwaf(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['whatwaf'], '-u', target] + self.config['scan_settings']['whatwaf_params'].split() + ['-o', output_file]
        return self.run_tool(cmd, target, output_file, 'whatwaf')

    def run_wafp(self, target: str, output_file: str) -> Dict:
        cmd = ['ruby', self.config['tools']['wafp'], '-u', target] + self.config['scan_settings']['wafp_params'].split() + ['-o', output_file]
        return self.run_tool(cmd, target, output_file, 'wafp')

    def run_sniper(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['sniper'], '-t', target] + self.config['scan_settings']['sniper_params'].split() + ['-o', output_file]
        return self.run_tool(cmd, target, output_file, 'sniper')

    def enrich_target(self, target: str) -> Dict:
        """Enrich target with Shodan, Censys, VirusTotal, DNSDB, and PassiveTotal."""
        enrichment = {}
        domain = urlparse(target).netloc or target

        # Shodan
        if self.shodan_api:
            try:
                results = self.shodan_api.search(f"hostname:{domain}")
                enrichment['shodan'] = results.get('matches', [])
            except Exception as e:
                logger.error(f"Shodan enrichment failed for {domain}: {e}")

        # Censys
        if self.censys_api:
            try:
                results = self.censys_api.search(f"dns.names: {domain}")
                enrichment['censys'] = list(results)
            except Exception as e:
                logger.error(f"Censys enrichment failed for {domain}: {e}")

        # VirusTotal
        if self.virustotal_api:
            try:
                with self.virustotal_api as vt:
                    response = vt.request(f"domains/{domain}")
                    enrichment['virustotal'] = response.data
            except Exception as e:
                logger.error(f"VirusTotal enrichment failed for {domain}: {e}")

        # DNSDB
        if self.dnsdb_api:
            try:
                answers = self.dnsdb_api.query(domain)
                enrichment['dnsdb'] = [str(rdata) for rdata in answers]
            except Exception as e:
                logger.error(f"DNSDB enrichment failed for {domain}: {e}")

        # PassiveTotal
        if self.passivetotal_api:
            try:
                results = self.passivetotal_api.get_passive_dns(query=domain)
                enrichment['passivetotal'] = results.get('results', [])
            except Exception as e:
                logger.error(f"PassiveTotal enrichment failed for {domain}: {e}")

        return enrichment

    def scan_target(self, target: str) -> None:
        """Scan a single target with all tools."""
        if target in self.scanned_targets:
            logger.info(f"Skipping already scanned target: {target}")
            return
        if not self.validate_target(target):
            logger.warning(f"Invalid target: {target}")
            return

        logger.info(f"Scanning target: {target}")
        target_dir = os.path.join(self.output_dir, hashlib.md5(target.encode()).hexdigest())
        os.makedirs(target_dir, exist_ok=True)
        self.results[target] = {}

        # Enrich target
        self.results[target]['enrichment'] = self.enrich_target(target)

        # Run all tools
        tools = [
            ('xsstrike', self.run_xsstrike), ('dalfox', self.run_dalfox), ('nuclei', self.run_nuclei),
            ('jaws', self.run_jaws), ('zap', self.run_zap), ('wapiti', self.run_wapiti),
            ('xsser', self.run_xsser), ('xspear', self.run_xspear), ('kxss', self.run_kxss),
            ('nikto', self.run_nikto), ('arachni', self.run_arachni), ('w3af', self.run_w3af),
            ('sqlmap', self.run_sqlmap), ('nosqlmap', self.run_nosqlmap), ('sqlninja', self.run_sqlninja),
            ('whatweb', self.run_whatweb), ('wpscan', self.run_wpscan), ('cmsscan', self.run_cmsscan),
            ('gobuster', self.run_gobuster), ('dirb', self.run_dirb), ('dirsearch', self.run_dirsearch),
            ('feroxbuster', self.run_feroxbuster), ('testssl', self.run_testssl), ('sslyze', self.run_sslyze),
            ('a2sv', self.run_a2sv), ('wafw00f', self.run_wafw00f), ('whatwaf', self.run_whatwaf),
            ('wafp', self.run_wafp), ('sniper', self.run_sniper)
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['scan_settings']['threads']) as executor:
            futures = []
            for tool_name, tool_func in tools:
                output_file = os.path.join(target_dir, f"{tool_name}_output.txt")
                futures.append(executor.submit(tool_func, target, output_file))
            for future, (tool_name, _) in zip(futures, tools):
                try:
                    self.results[target][tool_name] = future.result()
                except Exception as e:
                    logger.error(f"Error running {tool_name} on {target}: {e}")
                    self.results[target][tool_name] = {'vulnerabilities': [], 'error': str(e)}

        self.scanned_targets.add(target)
        self.save_state()

    def generate_unified_report(self) -> None:
        """Generate unified report in multiple formats."""
        timestamp = datetime.now().isoformat()
        summary = {
            'total_targets': len(self.results),
            'vulnerabilities': sum(len(scans.get(tool, {}).get('vulnerabilities', []))
                                  for target, scans in self.results.items() for tool in scans if tool != 'enrichment'),
            'critical': sum(1 for target, scans in self.results.items() for tool, findings in scans.items()
                            if tool != 'enrichment' for v in findings.get('vulnerabilities', []) if v['severity'] == 'Critical'),
            'high': sum(1 for target, scans in self.results.items() for tool, findings in scans.items()
                        if tool != 'enrichment' for v in findings.get('vulnerabilities', []) if v['severity'] == 'High'),
            'medium': sum(1 for target, scans in self.results.items() for tool, findings in scans.items()
                          if tool != 'enrichment' for v in findings.get('vulnerabilities', []) if v['severity'] == 'Medium'),
            'low': sum(1 for target, scans in self.results.items() for tool, findings in scans.items()
                       if tool != 'enrichment' for v in findings.get('vulnerabilities', []) if v['severity'] == 'Low')
        }

        # JSON report
        try:
            with open(os.path.join(self.output_dir, 'unified_report.json'), 'w') as f:
                json.dump({'results': self.results, 'summary': summary, 'timestamp': timestamp}, f, indent=2)
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")

        # HTML report
        try:
            template = self.env.get_template(self.config['output']['html_template'])
            html_content = template.render(results=self.results, summary=summary, timestamp=timestamp)
            html_file = os.path.join(self.output_dir, 'unified_report.html')
            with open(html_file, 'w') as f:
                f.write(html_content)
            if self.config['output']['pdf_report']:
                HTML(html_file).write_pdf(os.path.join(self.output_dir, 'unified_report.pdf'))
        except Exception as e:
            logger.error(f"Error generating HTML/PDF report: {e}")

        # CSV report
        if 'csv' in self.config['output']['export_formats']:
            try:
                with open(os.path.join(self.output_dir, 'unified_report.csv'), 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Target', 'Tool', 'Vulnerability', 'Severity', 'Details', 'Report File'])
                    for target, scans in self.results.items():
                        for tool, findings in scans.items():
                            if tool != 'enrichment':
                                for vuln in findings.get('vulnerabilities', []):
                                    writer.writerow([target, tool, vuln['vulnerability'], vuln['severity'], vuln['details'], findings.get('report_file', '')])
            except Exception as e:
                logger.error(f"Error generating CSV report: {e}")

        # XML report
        if 'xml' in self.config['output']['export_formats']:
            try:
                root = ET.Element("VulnScannerReport")
                root.set('timestamp', timestamp)
                summary_elem = ET.SubElement(root, "Summary")
                for key, value in summary.items():
                    ET.SubElement(summary_elem, key).text = str(value)
                results_elem = ET.SubElement(root, "Results")
                for target, scans in self.results.items():
                    target_elem = ET.SubElement(results_elem, "Target", name=target)
                    for tool, findings in scans.items():
                        if tool != 'enrichment':
                            tool_elem = ET.SubElement(target_elem, "Tool", name=tool)
                            for vuln in findings.get('vulnerabilities', []):
                                vuln_elem = ET.SubElement(tool_elem, "Vulnerability")
                                ET.SubElement(vuln_elem, "Name").text = vuln['vulnerability']
                                ET.SubElement(vuln_elem, "Severity").text = vuln['severity']
                                ET.SubElement(vuln_elem, "Details").text = vuln['details']
                                ET.SubElement(vuln_elem, "ReportFile").text = findings.get('report_file', '')
                tree = ET.ElementTree(root)
                tree.write(os.path.join(self.output_dir, 'unified_report.xml'))
            except Exception as e:
                logger.error(f"Error generating XML report: {e}")

        # Markdown report
        if 'markdown' in self.config['output']['export_formats']:
            try:
                with open(os.path.join(self.output_dir, 'unified_report.md'), 'w') as f:
                    f.write(f"# VulnScanner Unified Report\n")
                    f.write(f"**Generated on**: {timestamp}\n\n")
                    f.write(f"## Summary\n")
                    f.write(f"- **Total Targets Scanned**: {summary['total_targets']}\n")
                    f.write(f"- **Total Vulnerabilities Found**: {summary['vulnerabilities']}\n")
                    f.write(f"- **By Severity**: Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']}\n")
                    f.write(f"\n## Details\n")
                    for target, scans in self.results.items():
                        f.write(f"### Target: {target}\n")
                        for tool, findings in scans.items():
                            if tool != 'enrichment':
                                f.write(f"#### Tool: {tool}\n")
                                for vuln in findings.get('vulnerabilities', []):
                                    f.write(f"- **{vuln['vulnerability']}** (Severity: {vuln['severity']})\n")
                                    f.write(f"  - Details: {vuln['details']}\n")
                                    f.write(f"  - Report: {findings.get('report_file', 'N/A')}\n")
            except Exception as e:
                logger.error(f"Error generating Markdown report: {e}")

    def run(self) -> None:
        """Run the scanner on all targets."""
        targets = []
        for file_type, files in self.input_files.items():
            if file_type == 'logs':
                targets.extend(self.parse_log_files(files))
            else:
                for fpath in files:
                    targets.extend(self.read_file(fpath))
        targets = list(set(targets))

        if not targets:
            logger.error("No valid targets found")
            return

        logger.info(f"Starting scan on {len(targets)} targets")
        curses.wrapper(self.kamehameha_loading_screen, len(targets), "Vulnerability Scan")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['scan_settings']['threads']) as executor:
            list(tqdm(executor.map(self.scan_target, targets), total=len(targets), desc="Scanning Targets"))

        self.generate_unified_report()
        self.send_notification(f"Scan completed: {len(targets)} targets scanned, {sum(len(scans.get(tool, {}).get('vulnerabilities', [])) for target, scans in self.results.items() for tool in scans if tool != 'enrichment')} vulnerabilities found")
        logger.info("Scan completed")

def main():
    parser = argparse.ArgumentParser(description="Ultimate Kamehameha Vulnerability Scanner")
    parser.add_argument('--input-dir', default='inputs', help='Directory containing input files')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    scanner = VulnScanner(args.input_dir, args.config, args.verbose)
    scanner.run()

if __name__ == "__main__":
    main()
