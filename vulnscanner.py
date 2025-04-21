#!/usr/bin/env python3
import os
import subprocess
import json
import logging
import yaml
import validators
import concurrent.futures
import argparse
import time
import csv
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from typing import List, Dict, Optional, Callable
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from tqdm import tqdm
import hashlib
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import shodan
import censys.certificates
import virustotal_python
from colorama import Fore, init
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
import psutil
import asyncio
import aiohttp
from dnspython import dns.resolver
from passivetotal import AccountClient
from ratelimit import limits, sleep_and_retry
import jsonschema
import re
from pathlib import Path

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - Colombo's - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnscanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load ASCII art from external file
try:
    with open('kamehameha.txt', 'r') as f:
        KAMEHAMEHA_ART = f.read()
except FileNotFoundError:
    KAMEHAMEHA_ART = "KAMEHAMEHA Scanner\n"
    logger.warning("kamehameha.txt not found, using fallback text")

# Configuration schema for validation
CONFIG_SCHEMA = {
    "type": "object",
    "required": ["output", "scan_settings", "tools", "input_files"],
    "properties": {
        "output": {
            "type": "object",
            "required": ["directory", "per_scan_report_dir", "per_scan_report_format", "html_template", "export_formats"],
            "properties": {
                "directory": {"type": "string"},
                "per_scan_report_dir": {"type": "string"},
                "per_scan_report_format": {"type": "string", "enum": ["json", "txt", "markdown", "html", "all"]},
                "html_template": {"type": "string"},
                "pdf_report": {"type": "boolean"},
                "export_formats": {"type": "array", "items": {"type": "string", "enum": ["json", "html", "csv", "xml", "markdown"]}}
            }
        },
        "scan_settings": {
            "type": "object",
            "required": ["retries", "timeout", "rate_limit", "threads", "memory_limit_percent", "ffuf_wordlist"],
            "properties": {
                "retries": {"type": "integer", "minimum": 0},
                "timeout": {"type": "integer", "minimum": 1},
                "rate_limit": {"type": "integer", "minimum": 1},
                "threads": {"type": "integer", "minimum": 1},
                "memory_limit_percent": {"type": "number", "minimum": 0, "maximum": 100},
                "shodan_api_key": {"type": ["string", "null"]},
                "censys_api_id": {"type": ["string", "null"]},
                "censys_api_secret": {"type": ["string", "null"]},
                "virustotal_api_key": {"type": ["string", "null"]},
                "dnsdb_api_key": {"type": ["string", "null"]},
                "passivetotal_api_key": {"type": ["string", "null"]},
                "amass_params": {"type": "string"},
                "subfinder_params": {"type": "string"},
                "httpx_params": {"type": "string"},
                "nuclei_templates": {"type": "string"},
                "ffuf_wordlist": {"type": "string"},
                "ffuf_params": {"type": "string"},
                "nmap_params": {"type": "string"}
            }
        },
        "tools": {
            "type": "object",
            "properties": {
                "amass": {"type": "string"},
                "subfinder": {"type": "string"},
                "findomain": {"type": "string"},
                "assetfinder": {"type": "string"},
                "sublist3r": {"type": "string"},
                "httpx": {"type": "string"},
                "katana": {"type": "string"},
                "hakrawler": {"type": "string"},
                "photon": {"type": "string"},
                "waybackurls": {"type": "string"},
                "gau": {"type": "string"},
                "arjun": {"type": "string"},
                "nuclei": {"type": "string"},
                "xsstrike": {"type": "string"},
                "dalfox": {"type": "string"},
                "nikto": {"type": "string"},
                "testssl": {"type": "string"},
                "ffuf": {"type": "string"},
                "nmap": {"type": "string"}
            }
        },
        "input_files": {
            "type": "object",
            "required": ["subdomains", "domains", "js", "paths", "params", "logs"],
            "properties": {
                "subdomains": {"type": "string"},
                "domains": {"type": "string"},
                "js": {"type": "string"},
                "paths": {"type": "string"},
                "params": {"type": "string"},
                "logs": {"type": "array", "items": {"type": "string"}}
            }
        },
        "notifications": {
            "type": "object",
            "required": ["enable"],
            "properties": {
                "enable": {"type": "boolean"},
                "slack_webhook": {"type": ["string", "null"]},
                "discord_webhook": {"type": ["string", "null"]},
                "telegram_bot_token": {"type": ["string", "null"]},
                "telegram_chat_id": {"type": ["string", "null"]}
            }
        },
        "kamehameha": {
            "type": "object",
            "required": ["enable", "theme", "charge_time", "animation_speed"],
            "properties": {
                "enable": {"type": "boolean"},
                "theme": {"type": "string", "enum": ["blue", "red", "green", "yellow"]},
                "charge_time": {"type": "number", "minimum": 0},
                "animation_speed": {"type": "number", "minimum": 0}
            }
        }
    }
}

# Tool registry for scanning tools
TOOL_REGISTRY = {
    'nuclei': {
        'cmd': lambda cfg, target, output: [cfg['tools']['nuclei'], '-u', target, '-o', output, '-t', cfg['scan_settings']['nuclei_templates']],
        'parser': lambda output: [{'vulnerability': line, 'severity': 'Medium', 'details': line} for line in output.splitlines() if 'vuln' in line.lower()]
    },
    'xsstrike': {
        'cmd': lambda cfg, target, output: ['python3', cfg['tools']['xsstrike'], '-u', target] + cfg['scan_settings'].get('xsstrike_params', '').split(),
        'parser': lambda output: [{'vulnerability': line, 'severity': 'High', 'details': line} for line in output.splitlines() if 'xss' in line.lower()]
    },
    'dalfox': {
        'cmd': lambda cfg, target, output: [cfg['tools']['dalfox'], 'url', target, '-o', output] + cfg['scan_settings'].get('dalfox_params', '').split(),
        'parser': lambda output: [{'vulnerability': line, 'severity': 'High', 'details': line} for line in output.splitlines() if 'found' in line.lower()]
    },
    'nikto': {
        'cmd': lambda cfg, target, output: [cfg['tools']['nikto'], '-h', target, '-o', output] + cfg['scan_settings'].get('nikto_params', '').split(),
        'parser': lambda output: [{'vulnerability': line, 'severity': 'Medium', 'details': line} for line in output.splitlines() if 'alert' in line.lower()]
    },
    'testssl': {
        'cmd': lambda cfg, target, output: [cfg['tools']['testssl'], target, '--logfile', output] + cfg['scan_settings'].get('testssl_params', '').split(),
        'parser': lambda output: [{'vulnerability': line, 'severity': 'Medium', 'details': line} for line in output.splitlines() if 'vulnerable' in line.lower()]
    },
    'ffuf': {
        'cmd': lambda cfg, target, output: [cfg['tools']['ffuf'], '-u', f"{target}/FUZZ", '-w', cfg['scan_settings']['ffuf_wordlist'], '-o', output] + cfg['scan_settings'].get('ffuf_params', '').split(),
        'parser': lambda output: [
            {
                'vulnerability': f"Found resource: {item['url']}",
                'severity': 'Low' if item['status'] == 200 else 'Info',
                'details': f"Status: {item['status']}, Length: {item['length']}"
            }
            for item in json.loads(output).get('results', []) if item['status'] in [200, 301, 302]
        ]
    },
    'nmap': {
        'cmd': lambda cfg, target, output: [cfg['tools']['nmap'], '-oN', output] + cfg['scan_settings'].get('nmap_params', '').split() + [target],
        'parser': lambda output: [
            {
                'vulnerability': line.strip(),
                'severity': 'High' if 'critical' in line.lower() else 'Medium',
                'details': line.strip()
            }
            for line in output.splitlines() if 'VULNERABLE' in line or 'open port' in line.lower()
        ]
    }
}

class VulnScanner:
    def __init__(self, input_dir: str, config_file: str = 'config.yaml', verbose: bool = False, dry_run: bool = False):
        self.input_dir = Path(input_dir).resolve()
        self.config_file = Path(config_file).resolve()
        self.verbose = verbose
        self.dry_run = dry_run
        self.config = self.load_config()
        self.output_dir = Path(self.config['output']['directory']).resolve()
        self.per_scan_report_dir = self.output_dir / self.config['output']['per_scan_report_dir']
        self.results = {}
        self.scanned_targets = set()
        self.state_file = self.output_dir / 'scan_state.json'
        self.session = self.setup_session()
        self.env = Environment(loader=FileSystemLoader('.'))
        self.shodan_api = self.setup_shodan()
        self.censys_api = self.setup_censys()
        self.virustotal_api = self.setup_virustotal()
        self.dnsdb_api = self.setup_dnsdb()
        self.passivetotal_api = self.setup_passivetotal()
        self.validate_tools()
        self.input_files = self.prompt_for_input_files()
        self.prompt_session = PromptSession(multiline=False, completer=WordCompleter(['generate', 'skip', 'default']))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.per_scan_report_dir.mkdir(parents=True, exist_ok=True)
        self.input_dir.mkdir(parents=True, exist_ok=True)
        self.load_state()

    def load_config(self) -> Dict:
        """Load and validate configuration file."""
        if not self.config_file.exists():
            logger.error(f"Config file {self.config_file} not found")
            self.create_default_config()
        try:
            with self.config_file.open('r') as f:
                config = yaml.safe_load(f)
            if not config:
                raise ValueError("Empty configuration file")
            jsonschema.validate(config, CONFIG_SCHEMA)
            return config
        except (yaml.YAMLError, jsonschema.ValidationError) as e:
            logger.error(f"Invalid config {self.config_file}: {e}")
            raise

    def create_default_config(self) -> None:
        """Create a default configuration file."""
        default_config = {
            'output': {
                'directory': 'outputs',
                'per_scan_report_dir': 'reports',
                'per_scan_report_format': 'all',
                'html_template': 'templates/report.html',
                'pdf_report': True,
                'export_formats': ['json', 'html', 'csv', 'markdown']
            },
            'scan_settings': {
                'retries': 3,
                'timeout': 600,
                'rate_limit': 10,
                'threads': 5,
                'memory_limit_percent': 90,
                'amass_params': 'enum -active',
                'subfinder_params': '-all',
                'httpx_params': '-silent',
                'nuclei_templates': '/path/to/nuclei/templates',
                'ffuf_wordlist': '/path/to/wordlist.txt',
                'ffuf_params': '-c -t 50',
                'nmap_params': '--script vuln'
            },
            'tools': {tool: '' for tool in TOOL_REGISTRY},
            'input_files': {
                'subdomains': 'subdomains.txt',
                'domains': 'domains.txt',
                'js': 'jsfiles.txt',
                'paths': 'paths.txt',
                'params': 'params.txt',
                'logs': ['access.log', 'error.log']
            },
            'notifications': {
                'enable': False,
                'slack_webhook': None,
                'discord_webhook': None,
                'telegram_bot_token': None,
                'telegram_chat_id': None
            },
            'kamehameha': {
                'enable': True,
                'theme': 'blue',
                'charge_time': 5,
                'animation_speed': 0.2
            }
        }
        try:
            with self.config_file.open('w') as f:
                yaml.safe_dump(default_config, f)
            logger.info(f"Created default config at {self.config_file}")
        except IOError as e:
            logger.error(f"Failed to create default config: {e}")
            raise

    def validate_tools(self) -> None:
        """Check if all tools are available and executable."""
        for tool, path in self.config['tools'].items():
            if not path or tool not in TOOL_REGISTRY:
                continue
            path = Path(path).resolve()
            if not path.exists():
                logger.error(f"Tool {tool} not found at {path}")
                raise FileNotFoundError(f"Tool {tool} not found at {path}")
            try:
                subprocess.run([path, '--version'], capture_output=True, check=True, timeout=10)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
                logger.error(f"Tool {tool} at {path} not executable: {e}")
                raise RuntimeError(f"Tool {tool} not executable: {e}")

    def setup_session(self) -> requests.Session:
        """Setup requests session with retries and configuration."""
        session = requests.Session()
        retries = Retry(total=self.config['scan_settings']['retries'], backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        if proxy := self.config['scan_settings'].get('proxy'):
            session.proxies = {'http': proxy, 'https': proxy}
        session.headers.update(self.config.get('auth', {}).get('headers', {}))
        if token := self.config.get('auth', {}).get('oauth_token'):
            session.headers['Authorization'] = f"Bearer {token}"
        return session

    def setup_shodan(self) -> Optional[shodan.Shodan]:
        """Setup Shodan API client."""
        if api_key := self.config['scan_settings'].get('shodan_api_key'):
            try:
                return shodan.Shodan(api_key)
            except shodan.APIError as e:
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
        if api_key := self.config['scan_settings'].get('virustotal_api_key'):
            try:
                return virustotal_python.VirusTotal(api_key)
            except Exception as e:
                logger.error(f"Failed to setup VirusTotal: {e}")
        return None

    def setup_dnsdb(self) -> Optional[dns.resolver.Resolver]:
        """Setup DNSDB API client."""
        if api_key := self.config['scan_settings'].get('dnsdb_api_key'):
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ['api.dnsdb.info']
                return resolver
            except Exception as e:
                logger.error(f"Failed to setup DNSDB: {e}")
        return None

    def setup_passivetotal(self) -> Optional[AccountClient]:
        """Setup PassiveTotal API client."""
        if api_key := self.config['scan_settings'].get('passivetotal_api_key'):
            try:
                return AccountClient(api_key=api_key)
            except Exception as e:
                logger.error(f"Failed to setup PassiveTotal: {e}")
        return None

    @sleep_and_retry
    @limits(calls=10, period=60)
    async def async_http_request(self, url: str, method: str = 'GET') -> Optional[Dict]:
        """Perform asynchronous HTTP request with rate limiting."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, timeout=10) as response:
                    return await response.json() if response.content_type == 'application/json' else await response.text()
        except (aiohttp.ClientError, ValueError) as e:
            logger.error(f"Async HTTP request failed for {url}: {e}")
            return None

    def prompt_for_input_files(self) -> Dict[str, List[str]]:
        """Prompt user for input files and generate if needed."""
        files = {key: [] for key in ['subdomains', 'domains', 'js', 'paths', 'params', 'logs']}
        print(f"\n{Fore.CYAN}=== Input File Configuration ===")
        for file_type, default_file in self.config['input_files'].items():
            default_files = default_file if file_type == 'logs' else [default_file]
            for default in default_files:
                default_path = self.input_dir / default
                prompt = self.prompt_session.prompt(
                    f"Enter path for {default} (Enter for {default_path}, 'generate', 'skip', 'default'): "
                ).strip().lower()
                path = default_path
                if prompt == 'generate':
                    self.generate_input_file(file_type, default_path)
                elif prompt == 'skip':
                    continue
                elif prompt and prompt != 'default':
                    path = Path(prompt).resolve()
                if path.exists():
                    files[file_type].append(str(path))
                else:
                    logger.warning(f"File {path} does not exist")
        return files

    def generate_input_file(self, file_type: str, output_path: Path) -> None:
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

    def generate_subdomains(self, domain: str, output_path: Path) -> None:
        """Generate subdomains using multiple tools."""
        subdomains = set()
        temp_file = self.input_dir / f"temp_{domain}.txt"

        for tool, params in [
            ('amass', ['enum', '-d', domain, '-o', str(temp_file)] + self.config['scan_settings']['amass_params'].split()),
            ('subfinder', ['-d', domain, '-o', str(temp_file)] + self.config['scan_settings']['subfinder_params'].split()),
            ('findomain', ['-t', domain, '-o']),
            ('assetfinder', ['-subs-only', domain]),
            ('sublist3r', ['-d', domain, '-o', str(temp_file)] + self.config['scan_settings'].get('sublist3r_params', '').split())
        ]:
            if not self.config['tools'].get(tool):
                continue
            try:
                cmd = [self.config['tools'][tool]] + params if tool != 'sublist3r' else ['python3'] + [self.config['tools'][tool]] + params
                if tool == 'assetfinder':
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
                    with temp_file.open('w') as f:
                        f.write(result.stdout)
                elif tool == 'findomain':
                    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
                    temp_findomain = Path(f"{domain}.txt")
                    subdomains.update(self.read_file(temp_findomain))
                    temp_findomain.unlink(missing_ok=True)
                    continue
                else:
                    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
                subdomains.update(self.read_file(temp_file))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.error(f"{tool} failed for {domain}: {e}")

        live_file = self.input_dir / f"live_{domain}.txt"
        try:
            with temp_file.open('w') as f:
                f.write('\n'.join(subdomains))
            cmd = [self.config['tools']['httpx'], '-l', str(temp_file), '-o', str(live_file)] + self.config['scan_settings']['httpx_params'].split()
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            subdomains = set(self.read_file(live_file))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Httpx failed for {domain}: {e}")

        try:
            with output_path.open('w') as f:
                f.write('\n'.join(subdomains))
        except IOError as e:
            logger.error(f"Error saving subdomains to {output_path}: {e}")
        temp_file.unlink(missing_ok=True)
        live_file.unlink(missing_ok=True)

    def generate_js_file(self, domain: str, output_path: Path) -> None:
        """Generate JS file using Katana, Hakrawler, and Photon."""
        js_urls = set()
        temp_file = self.input_dir / f"temp_js_{domain}.txt"

        for tool, params in [
            ('katana', ['-u', f"https://{domain}", '-o', str(temp_file)] + psikodelya['scan_settings'].get('katana_params', '').split()),
            ('hakrawler', ['-url', f"https://{domain}", '-depth', '3']),
            ('photon', ['-u', f"https://{domain}", '-o', str(temp_file)] + self.config['scan_settings'].get('photon_params', '').split())
        ]:
            if not self.config['tools'].get(tool):
                continue
            try:
                cmd = [self.config['tools'][tool]] + params if tool != 'photon' else ['python3', self.config['tools'][tool]] + params
                if tool == 'hakrawler':
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
                    with temp_file.open('w') as f:
                        f.write(result.stdout)
                else:
                    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
                js_urls.update(line for line in self.read_file(temp_file) if line.endswith('.js'))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.error(f"{tool} failed for {domain}: {e}")

        try:
            with output_path.open('w') as f:
                f.write('\n'.join(js_urls) or f"https://{domain}/script.js\nhttps://www.{domain}/app.js")
        except IOError as e:
            logger.error(f"Error saving JS file {output_path}: {e}")
        temp_file.unlink(missing_ok=True)

    def generate_paths_params(self, domain: str, output_path: Path) -> None:
        """Generate paths and parameters using multiple tools."""
        paths = set()
        temp_file = self.input_dir / f"temp_paths_{domain}.txt"

        for tool, params in [
            ('waybackurls', [domain]),
            ('gau', [domain] + self.config['scan_settings'].get('gau_params', '').split()),
            ('hakrawler', ['-url', f"https://{domain}", '-depth', '3']),
            ('arjun', ['-u', f"https://{domain}", '-o', str(temp_file)] + self.config['scan_settings'].get('arjun_params', '').split())
        ]:
            if not self.config['tools'].get(tool):
                continue
            try:
                cmd = [self.config['tools'][tool]] + params if tool != 'arjun' else ['python3', self.config['tools'][tool]] + params
                if tool in ['waybackurls', 'hakrawler']:
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
                    with temp_file.open('w') as f:
                        f.write(result.stdout)
                else:
                    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
                paths.update(self.read_file(temp_file))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.error(f"{tool} failed for {domain}: {e}")

        try:
            with output_path.open('w') as f:
                f.write('\n'.join(paths))
        except IOError as e:
            logger.error(f"Error saving paths to {output_path}: {e}")
        temp_file.unlink(missing_ok=True)

    def generate_log_file(self, output_path: Path) -> None:
        """Generate placeholder log file."""
        try:
            with output_path.open('w') as f:
                f.write(f"Sample log entry for {datetime.now()}\n")
        except IOError as e:
            logger.error(f"Error generating log file {output_path}: {e}")

    def save_state(self) -> None:
        """Save scan state to resume later."""
        try:
            with self.state_file.open('w') as f:
                json.dump({'results': self.results, 'scanned_targets': list(self.scanned_targets)}, f)
        except IOError as e:
            logger.error(f"Error saving state: {e}")

    def load_state(self) -> None:
        """Load scan state if exists."""
        if self.state_file.exists():
            try:
                with self.state_file.open('r') as f:
                    state = json.load(f)
                self.results = state['results']
                self.scanned_targets = set(state['scanned_targets'])
                logger.info("Loaded previous scan state")
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Error loading state: {e}")

    def read_file(self, file_path: Path) -> List[str]:
        """Read lines from a file, ignoring empty lines."""
        if not file_path.exists():
            logger.warning(f"File {file_path} not found")
            return []
        try:
            with file_path.open('r') as f:
                return [line.strip() for line in f if line.strip()]
        except IOError as e:
            logger.error(f"Error reading {file_path}: {e}")
            return []

    def parse_log_files(self, log_files: List[str]) -> List[str]:
        """Extract URLs or domains from log files."""
        targets = []
        for fpath in log_files:
            for line in self.read_file(Path(fpath)):
                if validators.url(line) or validators.domain(line):
                    targets.append(line)
        return list(set(targets))

    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid URL, domain, or IP."""
        return bool(validators.url(target) or validators.domain(target) or validators.ipv4(target) or validators.ipv6(target))

    def kamehameha_loading_screen(self, total_targets: int, scan_type: str):
        """Display animated Kamehameha loading screen with tqdm."""
        if not self.config['kamehameha']['enable']:
            return
        color_map = {'blue': Fore.BLUE, 'red': Fore.RED, 'green': Fore.GREEN, 'yellow': Fore.YELLOW}
        theme = color_map.get(self.config['kamehameha']['theme'], Fore.BLUE)
        charge_time = self.config['kamehameha']['charge_time']
        start_time = time.time()

        with tqdm(total=total_targets, desc=f"{theme}Charging Kamehameha for {scan_type}", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
            while time.time() - start_time < charge_time or pbar.n < total_targets:
                pbar.set_postfix({
                    'Time': f"{int(time.time() - start_time)}s",
                    'Memory': f"{psutil.virtual_memory().percent}%"
                })
                time.sleep(self.config['kamehameha']['animation_speed'])
                if time.time() - start_time > charge_time:
                    pbar.update(1)
        print(f"{theme}KAMEHAMEHA UNLEASHED! Scanning complete.")

    def send_notification(self, message: str) -> None:
        """Send notifications via multiple channels."""
        if not self.config['notifications']['enable']:
            return
        for channel, url in [
            ('slack', self.config['notifications'].get('slack_webhook')),
            ('discord', self.config['notifications'].get('discord_webhook'))
        ]:
            if url and validators.url(url):
                try:
                    payload = {'text' if channel == 'slack' else 'content': message}
                    self.session.post(url, json=payload, timeout=10)
                    logger.info(f"Sent {channel} notification")
                except requests.RequestException as e:
                    logger.error(f"Failed to send {channel} notification: {e}")
        if token := self.config['notifications'].get('telegram_bot_token'):
            chat_id = self.config['notifications'].get('telegram_chat_id')
            if chat_id and validators.url(f"https://api.telegram.org"):
                try:
                    url = f"https://api.telegram.org/bot{token}/sendMessage"
                    payload = {'chat_id': chat_id, 'text': message}
                    self.session.post(url, json=payload, timeout=10)
                    logger.info("Sent Telegram notification")
                except requests.RequestException as e:
                    logger.error(f"Failed to send Telegram notification: {e}")

    def generate_per_scan_report(self, target: str, tool: str, findings: Dict, output_file: Path, start_time: datetime, end_time: datetime) -> str:
        """Generate per-scan report in multiple formats."""
        report_data = {
            'target': target,
            'tool': tool,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'parameters': self.config['scan_settings'].get(f'{tool}_params', ''),
            'vulnerabilities': findings.get('vulnerabilities', []),
            'output_file': str(output_file),
            'error': findings.get('error', None)
        }
        target_dir = self.per_scan_report_dir / hashlib.md5(target.encode()).hexdigest()
        target_dir.mkdir(parents=True, exist_ok=True)
        report_base = target_dir / f"{tool}_report"
        report_file = None

        try:
            report_format = self.config['output']['per_scan_report_format']
            if report_format in ['json', 'all']:
                json_file = report_base.with_suffix('.json')
                with json_file.open('w') as f:
                    json.dump(report_data, f, indent=2)
                report_file = json_file
            if report_format in ['txt', 'all']:
                txt_file = report_base.with_suffix('.txt')
                with txt_file.open('w') as f:
                    f.write(f"Scan Report\nTarget: {target}\nTool: {tool}\nStart Time: {start_time}\nEnd Time: {end_time}\n")
                    f.write(f"Parameters: {report_data['parameters']}\nOutput File: {report_data['output_file']}\n")
                    if report_data['error']:
                        f.write(f"Error: {report_data['error']}\n")
                    f.write("\nVulnerabilities:\n")
                    for vuln in report_data['vulnerabilities']:
                        f.write(f"- {vuln['vulnerability']} (Severity: {vuln['severity']})\n  Details: {vuln['details']}\n")
                if report_format == 'txt':
                    report_file = txt_file
            if report_format in ['markdown', 'all']:
                md_file = report_base.with_suffix('.md')
                with md_file.open('w') as f:
                    f.write(f"# Scan Report\n- **Target**: {target}\n- **Tool**: {tool}\n- **Start Time**: {start_time}\n")
                    f.write(f"- **End Time**: {end_time}\n- **Parameters**: {report_data['parameters']}\n- **Output File**: {report_data['output_file']}\n")
                    if report_data['error']:
                        f.write(f"- **Error**: {report_data['error']}\n")
                    f.write("\n## Vulnerabilities\n")
                    for vuln in report_data['vulnerabilities']:
                        f.write(f"- **{vuln['vulnerability']}** (Severity: {vuln['severity']})\n  - Details: {vuln['details']}\n")
                if report_format == 'markdown':
                    report_file = md_file
            if report_format in ['html', 'all']:
                html_file = report_base.with_suffix('.html')
                template = self.env.get_template(self.config['output']['html_template'])
                with html_file.open('w') as f:
                    f.write(template.render(
                        results={target: {tool: findings}},
                        summary={
                            'total_targets': 1,
                            'vulnerabilities': len(findings.get('vulnerabilities', [])),
                            'critical': sum(1 for v in findings.get('vulnerabilities', []) if v['severity'] == 'Critical'),
                            'high': sum(1 for v in findings.get('vulnerabilities', []) if v['severity'] == 'High'),
                            'medium': sum(1 for v in findings.get('vulnerabilities', []) if v['severity'] == 'Medium'),
                            'low': sum(1 for v in findings.get('vulnerabilities', []) if v['severity'] == 'Low')
                        },
                        timestamp=start_time.isoformat()
                    ))
                if report_format == 'html':
                    report_file = html_file
        except (IOError, jinja2.TemplateError) as e:
            logger.error(f"Error generating report for {tool} on {target}: {e}")

        if report_data['vulnerabilities'] and any(v['severity'] in ['Critical', 'High'] for v in report_data['vulnerabilities']):
            self.send_notification(f"Critical/High severity vulnerability found on {target} with {tool}")
        return str(report_file) if report_file else ''

    def run_tool(self, tool_name: str, target: str, output_file: Path) -> Dict:
        """Run a scanning tool with rate limiting and resource monitoring."""
        if tool_name not in TOOL_REGISTRY:
            return {'vulnerabilities': [], 'error': f"Tool {tool_name} not supported"}
        start_time = datetime.now()
        memory_usage = psutil.virtual_memory().percent
        if memory_usage > self.config['scan_settings']['memory_limit_percent']:
            logger.warning(f"High memory usage ({memory_usage}%), pausing scan")
            time.sleep(10)
        time.sleep(1 / self.config['scan_settings']['rate_limit'])

        if self.dry_run:
            logger.info(f"[Dry Run] Would run {tool_name} on {target}")
            return {'vulnerabilities': [], 'output_file': str(output_file), 'dry_run': True}

        try:
            cmd = TOOL_REGISTRY[tool_name]['cmd'](self.config, target, str(output_file))
            cmd = [str(arg) for arg in cmd if arg]  # Sanitize command arguments
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.config['scan_settings']['timeout']
            )
            findings = {
                'vulnerabilities': TOOL_REGISTRY[tool_name]['parser'](result.stdout),
                'output_file': str(output_file)
            }
            try:
                with output_file.open('w') as f:
                    f.write(result.stdout)
            except IOError as e:
                logger.error(f"Error saving output to {output_file}: {e}")
            end_time = datetime.now()
            findings['report_file'] = self.generate_per_scan_report(target, tool_name, findings, output_file, start_time, end_time)
            logger.info(f"Scan completed: {tool_name} on {target}")
            return findings
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            end_time = datetime.now()
            findings = {'vulnerabilities': [], 'error': str(e), 'output_file': str(output_file)}
            findings['report_file'] = self.generate_per_scan_report(target, tool_name, findings, output_file, start_time, end_time)
            logger.error(f"Scan failed: {tool_name} on {target}: {e}")
            return findings

    @sleep_and_retry
    @limits(calls=5, period=60)
    def enrich_target(self, target: str) -> Dict:
        """Enrich target with Shodan, Censys, VirusTotal, DNSDB, and PassiveTotal."""
        enrichment = {}
        domain = urlparse(target).netloc or target

        if self.shodan_api:
            try:
                results = self.shodan_api.search(f"hostname:{domain}")
                enrichment['shodan'] = results.get('matches', [])
            except shodan.APIError as e:
                logger.error(f"Shodan enrichment failed for {domain}: {e}")

        if self.censys_api:
            try:
                results = self.censys_api.search(f"dns.names: {domain}")
                enrichment['censys'] = list(results)
            except Exception as e:
                logger.error(f"Censys enrichment failed for {domain}: {e}")

        if self.virustotal_api:
            try:
                with self.virustotal_api as vt:
                    response = vt.request(f"domains/{domain}")
                    enrichment['virustotal'] = response.data
            except Exception as e:
                logger.error(f"VirusTotal enrichment failed for {domain}: {e}")

        if self.dnsdb_api:
            try:
                answers = self.dnsdb_api.query(domain)
                enrichment['dnsdb'] = [str(rdata) for rdata in answers]
            except Exception as e:
                logger.error(f"DNSDB enrichment failed for {domain}: {e}")

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
        target_dir = self.output_dir / hashlib.md5(target.encode()).hexdigest()
        target_dir.mkdir(parents=True, exist_ok=True)
        self.results[target] = {'enrichment': self.enrich_target(target)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['scan_settings']['threads']) as executor:
            futures = []
            for tool_name in TOOL_REGISTRY:
                if not self.config['tools'].get(tool_name):
                    continue
                output_file = target_dir / f"{tool_name}_output.txt"
                futures.append(executor.submit(self.run_tool, tool_name, target, output_file))
            for future, tool_name in zip(futures, TOOL_REGISTRY):
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

        try:
            with (self.output_dir / 'unified_report.json').open('w') as f:
                json.dump({'results': self.results, 'summary': summary, 'timestamp': timestamp}, f, indent=2)
        except IOError as e:
            logger.error(f"Error generating JSON report: {e}")

        try:
            template = self.env.get_template(self.config['output']['html_template'])
            html_content = template.render(results=self.results, summary=summary, timestamp=timestamp)
            html_file = self.output_dir / 'unified_report.html'
            with html_file.open('w') as f:
                f.write(html_content)
            if self.config['output']['pdf_report']:
                try:
                    from weasyprint import HTML
                    HTML(str(html_file)).write_pdf(self.output_dir / 'unified_report.pdf')
                except ImportError:
                    logger.warning("weasyprint not installed, skipping PDF report")
        except (jinja2.TemplateError, IOError) as e:
            logger.error(f"Error generating HTML/PDF report: {e}")

        if 'csv' in self.config['output']['export_formats']:
            try:
                with (self.output_dir / 'unified_report.csv').open('w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Target', 'Tool', 'Vulnerability', 'Severity', 'Details', 'Report File'])
                    for target, scans in self.results.items():
                        for tool, findings in scans.items():
                            if tool != 'enrichment':
                                for vuln in findings.get('vulnerabilities', []):
                                    writer.writerow([target, tool, vuln['vulnerability'], vuln['severity'], vuln['details'], findings.get('report_file', '')])
            except IOError as e:
                logger.error(f"Error generating CSV report: {e}")

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
                ET.ElementTree(root).write(self.output_dir / 'unified_report.xml')
            except IOError as e:
                logger.error(f"Error generating XML report: {e}")

        if 'markdown' in self.config['output']['export_formats']:
            try:
                with (self.output_dir / 'unified_report.md').open('w') as f:
                    f.write(f"# VulnScanner Unified Report\n**Generated on**: {timestamp}\n\n## Summary\n")
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
            except IOError as e:
                logger.error(f"Error generating Markdown report: {e}")

    def run(self) -> None:
        """Run the scanner on all targets."""
        targets = []
        for file_type, files in self.input_files.items():
            if file_type == 'logs':
                targets.extend(self.parse_log_files(files))
            else:
                for fpath in files:
                    targets.extend(self.read_file(Path(fpath)))
        targets = list(set(targets))

        if not targets:
            logger.error("No valid targets found")
            return

        logger.info(f"Starting scan on {len(targets)} targets")
        self.kamehameha_loading_screen(len(targets), "Vulnerability Scan")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['scan_settings']['threads']) as executor:
            list(tqdm(executor.map(self.scan_target, targets), total=len(targets), desc="Scanning Targets"))

        self.generate_unified_report()
        self.send_notification(f"Scan completed: {len(targets)} targets scanned, {sum(len(scans.get(tool, {}).get('vulnerabilities', [])) for target, scans in self.results.items() for tool in scans if tool != 'enrichment')} vulnerabilities found")
        logger.info("Scan completed")

def check_dependencies() -> None:
    """Check if required Python dependencies are installed."""
    required = ['yaml', 'validators', 'concurrent.futures', 'jinja2', 'tqdm', 'requests', 'colorama', 'prompt_toolkit', 'psutil', 'aiohttp', 'dnspython', 'ratelimit', 'jsonschema']
    missing = []
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        logger.error(f"Missing dependencies: {', '.join(missing)}. Install with `pip install {' '.join(missing)}`")
        raise ImportError(f"Missing dependencies: {', '.join(missing)}")

def main():
    parser = argparse.ArgumentParser(description="Ultimate Kamehameha Vulnerability Scanner")
    parser.add_argument('--input-dir', default='inputs', help='Directory containing input files')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--dry-run', action='store_true', help='Simulate scan without executing tools')
    args = parser.parse_args()

    check_dependencies()
    scanner = VulnScanner(args.input_dir, args.config, args.verbose, args.dry_run)
    scanner.run()

if __name__ == "__main__":
    main()
