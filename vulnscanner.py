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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnscanner.log'),
        logging.StreamHandler()
    ]
)

# Kamehameha ASCII art
KAMEHAMEHA_FRAMES = [
    """
    Kame...
    ⠘⣷⣶⣤⣄⡀
    ⠸⣿⣿⣿⣿⣷⡒⢄⡀
    ⢹⣿⣿⣿⣿⣿⣆⠙⡄
    """,
    """
    Hame...
    ⢸⣿⣿⣿⡇⠀⢧⢸⣿⣇⢸⣿⣷⡀⠈⢿⣿⡄
    ⠈⣿⣿⣿⣷⡀⠀⢻⣿⣿⡜⣿⣿⣷⡀⠈⢻⣷
    ⢰⣿⣿⠀⠈⢉⡶⢿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠙⢇
    """,
    """
    HAAAAA!
    ⢸⣿⣿⣿⡇⠀⢧⢸⣿⣇⢸⣿⣷⡀⠈⢿⣿⡄
    ⠈⣿⣿⣿⣷⡀⠀⢻⣿⣿⡜⣿⣿⣷⡀⠈⢻⣷
    ⢰⣿⣿⠀⠈⢉⡶⢿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠙⢇
    ⠀⠈⠉⠉⠉⠙⢻⣿⣿⣿⣿⣷⡀⠀⠀⠀⠻⣿
    """
]

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
        self.validate_tools()
        self.input_files = self.prompt_for_input_files()

    def load_config(self, config_file: str) -> Dict:
        """Load and validate configuration file."""
        if not os.path.exists(config_file):
            logging.error(f"Config file {config_file} not found")
            raise FileNotFoundError(f"Config file {config_file} not found")
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            if not config:
                raise ValueError("Empty configuration file")
            return config
        except Exception as e:
            logging.error(f"Error loading config {config_file}: {e}")
            raise

    def validate_tools(self) -> None:
        """Check if all tools are available."""
        for tool, path in self.config['tools'].items():
            if not path:
                continue
            if tool == 'custom_script':
                if not os.path.exists(path):
                    logging.warning(f"Custom script {path} not found")
            else:
                try:
                    subprocess.run([path, '--version'], capture_output=True, check=True, timeout=10)
                except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    logging.error(f"Tool {tool} not found or not executable at {path}")
                    raise RuntimeError(f"Tool {tool} not found or not executable at {path}")

    def setup_session(self) -> requests.Session:
        """Setup requests session with retries and proxy."""
        session = requests.Session()
        retries = Retry(total=self.config['scan_settings']['retries'], backoff_factor=1)
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        if self.config['scan_settings'].get('proxy'):
            session.proxies = {'http': self.config['scan_settings']['proxy'], 'https': self.config['scan_settings']['proxy']}
        session.cookies.update(self.config['auth'].get('cookies', {}))
        session.headers.update(self.config['auth'].get('headers', {}))
        return session

    def setup_shodan(self) -> Optional[shodan.Shodan]:
        """Setup Shodan API client."""
        api_key = self.config['scan_settings'].get('shodan_api_key')
        if api_key:
            try:
                return shodan.Shodan(api_key)
            except Exception as e:
                logging.error(f"Failed to setup Shodan: {e}")
        return None

    def setup_censys(self) -> Optional[censys.certificates.CensysCertificates]:
        """Setup Censys API client."""
        api_id = self.config['scan_settings'].get('censys_api_id')
        api_secret = self.config['scan_settings'].get('censys_api_secret')
        if api_id and api_secret:
            try:
                return censys.certificates.CensysCertificates(api_id, api_secret)
            except Exception as e:
                logging.error(f"Failed to setup Censys: {e}")
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
        print("\n=== Input File Configuration ===")
        for file_type, default_file in self.config['input_files'].items():
            if file_type == 'logs':
                default_files = default_file
            else:
                default_files = [default_file]
            for default in default_files:
                path = os.path.join(self.input_dir, default)
                prompt = input(f"Enter path for {default} (Enter to use {path}, 'generate' to create, 'skip' to ignore): ").strip()
                if prompt.lower() == 'generate':
                    self.generate_input_file(file_type, path)
                elif prompt.lower() == 'skip':
                    continue
                elif prompt:
                    path = prompt
                if os.path.exists(path):
                    if file_type == 'logs':
                        files['logs'].append(path)
                    else:
                        files[file_type].append(path)
                else:
                    logging.warning(f"File {path} not found")
        return files

    def generate_input_file(self, file_type: str, output_path: str) -> None:
        """Generate input file using appropriate tools."""
        domain = input(f"Enter root domain for {file_type} generation (e.g., example.com): ").strip()
        if not validators.domain(domain):
            logging.error(f"Invalid domain: {domain}")
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
            logging.info(f"Generated {file_type} file: {output_path}")
        except Exception as e:
            logging.error(f"Error generating {file_type} file: {e}")

    def generate_subdomains(self, domain: str, output_path: str) -> None:
        """Generate subdomains using Amass, Subfinder, Assetfinder, and Httpx."""
        subdomains = set()
        temp_file = os.path.join(self.input_dir, f"temp_{domain}.txt")

        # Amass
        try:
            cmd = [self.config['tools']['amass']] + self.config['scan_settings']['amass_params'].split() + ['-d', domain, '-o', temp_file]
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600)
            subdomains.update(self.read_file(temp_file))
        except Exception as e:
            logging.error(f"Amass failed for {domain}: {e}")

        # Subfinder
        try:
            cmd = [self.config['tools']['subfinder'], '-d', domain, '-o', temp_file] + self.config['scan_settings']['subfinder_params'].split()
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            subdomains.update(self.read_file(temp_file))
        except Exception as e:
            logging.error(f"Subfinder failed for {domain}: {e}")

        # Assetfinder
        try:
            cmd = [self.config['tools']['assetfinder'], '-subs-only', domain]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            with open(temp_file, 'w') as f:
                f.write(result.stdout)
            subdomains.update(self.read_file(temp_file))
        except Exception as e:
            logging.error(f"Assetfinder failed for {domain}: {e}")

        # Filter live subdomains with Httpx
        live_file = os.path.join(self.input_dir, f"live_{domain}.txt")
        try:
            with open(temp_file, 'w') as f:
                f.write('\n'.join(subdomains))
            cmd = [self.config['tools']['httpx'], '-l', temp_file, '-o', live_file] + self.config['scan_settings']['httpx_params'].split()
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            subdomains = set(self.read_file(live_file))
        except Exception as e:
            logging.error(f"Httpx failed for {domain}: {e}")

        # Save to output
        try:
            with open(output_path, 'w') as f:
                f.write('\n'.join(subdomains))
        except Exception as e:
            logging.error(f"Error saving subdomains to {output_path}: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        if os.path.exists(live_file):
            os.remove(live_file)

    def generate_js_file(self, domain: str, output_path: str) -> None:
        """Generate JS file using Katana."""
        try:
            cmd = [self.config['tools']['katana'], '-u', f"https://{domain}"] + self.config['scan_settings']['katana_params'].split() + [output_path]
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            # Filter for JS files
            lines = self.read_file(output_path)
            js_urls = [line for line in lines if line.endswith('.js')]
            with open(output_path, 'w') as f:
                f.write('\n'.join(js_urls))
        except Exception as e:
            logging.error(f"Error generating JS file {output_path}: {e}")
            # Fallback to placeholder
            with open(output_path, 'w') as f:
                f.write(f"https://{domain}/script.js\nhttps://www.{domain}/app.js")

    def generate_paths_params(self, domain: str, output_path: str) -> None:
        """Generate paths and parameters using Waybackurls and Gau."""
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
            logging.error(f"Waybackurls failed for {domain}: {e}")

        # Gau
        try:
            cmd = [self.config['tools']['gau'], domain] + self.config['scan_settings']['gau_params'].split()
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            with open(temp_file, 'w') as f:
                f.write(result.stdout)
            paths.update(self.read_file(temp_file))
        except Exception as e:
            logging.error(f"Gau failed for {domain}: {e}")

        # Save to output
        try:
            with open(output_path, 'w') as f:
                f.write('\n'.join(paths))
        except Exception as e:
            logging.error(f"Error saving paths to {output_path}: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)

    def generate_log_file(self, output_path: str) -> None:
        """Generate placeholder log file."""
        try:
            with open(output_path, 'w') as f:
                f.write(f"Sample log entry for {datetime.now()}\n")
        except Exception as e:
            logging.error(f"Error generating log file {output_path}: {e}")

    def save_state(self) -> None:
        """Save scan state to resume later."""
        try:
            with open(self.state_file, 'wb') as f:
                pickle.dump({'results': self.results, 'scanned_targets': self.scanned_targets}, f)
        except Exception as e:
            logging.error(f"Error saving state: {e}")

    def load_state(self) -> None:
        """Load scan state if exists."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'rb') as f:
                    state = pickle.load(f)
                    self.results = state['results']
                    self.scanned_targets = state['scanned_targets']
                logging.info("Loaded previous scan state")
            except Exception as e:
                logging.error(f"Error loading state: {e}")

    def read_file(self, file_path: str) -> List[str]:
        """Read lines from a file, ignoring empty lines."""
        if not os.path.exists(file_path):
            logging.warning(f"File {file_path} not found")
            return []
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logging.error(f"Error reading {file_path}: {e}")
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
        """Display animated Kamehameha loading screen."""
        if not self.config['kamehameha']['enable']:
            return
        curses.curs_set(0)
        stdscr.timeout(100)
        charge_time = self.config['kamehameha']['charge_time']
        start_time = time.time()
        frame_idx = 0
        completed_targets = 0

        while time.time() - start_time < charge_time or completed_targets < total_targets:
            stdscr.clear()
            frame = KAMEHAMEHA_FRAMES[frame_idx % len(KAMEHAMEHA_FRAMES)]
            stdscr.addstr(0, 0, f"Charging Kamehameha for {scan_type}...\n{frame}")
            stdscr.addstr(5, 0, f"Targets Scanned: {completed_targets}/{total_targets}")
            stdscr.addstr(6, 0, f"Elapsed Time: {int(time.time() - start_time)}s")
            stdscr.refresh()
            frame_idx += 1
            time.sleep(0.2)
            if time.time() - start_time > charge_time:
                completed_targets += 1
        stdscr.clear()
        stdscr.addstr(0, 0, "KAMEHAMEHA UNLEASHED! Scanning complete.")
        stdscr.refresh()
        time.sleep(1)

    def generate_per_scan_report(self, target: str, tool: str, findings: Dict, output_file: str, start_time: datetime, end_time: datetime) -> str:
        """Generate per-scan report in JSON and/or text format."""
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
            if report_formats in ['json', 'both']:
                json_file = f"{report_base}.json"
                with open(json_file, 'w') as f:
                    json.dump(report_data, f, indent=2)
                report_file = json_file
            if report_formats in ['txt', 'both']:
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
        except Exception as e:
            logging.error(f"Error generating report for {tool} on {target}: {e}")
        return report_file

    def run_tool(self, cmd: List[str], target: str, output_file: str, tool_name: str) -> Dict:
        """Run a scanning tool with rate limiting."""
        start_time = datetime.now()
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
            logging.info(f"Scan completed: {tool_name} on {target}")
            return findings
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            end_time = datetime.now()
            findings = {'vulnerabilities': [], 'error': str(e)}
            findings['report_file'] = self.generate_per_scan_report(target, tool_name, findings, output_file, start_time, end_time)
            logging.error(f"Scan failed: {tool_name} on {target}: {e}")
            return findings

    def parse_tool_output(self, tool: str, output: str, output_file: str) -> Dict:
        """Parse tool output and save to file."""
        try:
            with open(output_file, 'w') as f:
                f.write(output)
        except Exception as e:
            logging.error(f"Error saving output to {output_file}: {e}")
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

    def run_nikto(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['nikto'], '-h', target, '-o', output_file] + self.config['scan_settings']['nikto_params'].split()
        return self.run_tool(cmd, target, output_file, 'nikto')

    def run_arachni(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['arachni'], '--report-save-path', output_file] + self.config['scan_settings']['arachni_params'].split() + [target]
        return self.run_tool(cmd, target, output_file, 'arachni')

    def run_sqlmap(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['sqlmap'], '-u', target, '-o', output_file] + self.config['scan_settings']['sqlmap_params'].split()
        return self.run_tool(cmd, target, output_file, 'sqlmap')

    def run_whatweb(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['whatweb'], target, '--log-json', output_file] + self.config['scan_settings']['whatweb_params'].split()
        return self.run_tool(cmd, target, output_file, 'whatweb')

    def run_gobuster(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['gobuster']] + self.config['scan_settings']['gobuster_params'].split() + ['-u', target, '-o', output_file]
        return self.run_tool(cmd, target, output_file, 'gobuster')

    def run_dirb(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['dirb'], target, self.config['scan_settings']['dirb_params'], '-o', output_file]
        return self.run_tool(cmd, target, output_file, 'dirb')

    def run_dirsearch(self, target: str, output_file: str) -> Dict:
        cmd = ['python3', self.config['tools']['dirsearch'], '-u', target, '-o', output_file] + self.config['scan_settings']['dirsearch_params'].split()
        return self.run_tool(cmd, target, output_file, 'dirsearch')

    def run_testssl(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['testssl'], target, '--logfile', output_file] + self.config['scan_settings']['testssl_params'].split()
        return self.run_tool(cmd, target, output_file, 'testssl')

    def run_wafw00f(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['wafw00f'], target, '-o', output_file] + self.config['scan_settings']['wafw00f_params'].split()
        return self.run_tool(cmd, target, output_file, 'wafw00f')

    def run_ffuf(self, target: str, output_file: str) -> Dict:
        cmd = [self.config['tools']['ffuf'], '-u', f"{target}/FUZZ", '-o', output_file] + self.config['scan_settings']['ffuf_params'].split()
        return self.run_tool(cmd, target, output_file, 'ffuf')

    def run_custom_script(self, target: str, output_file: str) -> Dict:
        if not self.config['tools']['custom_script']:
            return {'vulnerabilities': [], 'error': 'No custom script defined'}
        cmd = [self.config['tools']['custom_script'], target, output_file]
        return self.run_tool(cmd, target, output_file, 'custom_script')

    def enrich_target(self, target: str) -> Dict:
        """Enrich target with Shodan/Censys data."""
        enrichment = {}
        domain = urlparse(target).netloc or target
        if self.shodan_api:
            try:
                results = self.shodan_api.search(f"hostname:{domain}")
                enrichment['shodan'] = {'hosts': results['total'], 'details': results['matches'][:5]}
            except Exception as e:
                enrichment['shodan'] = {'error': str(e)}
        if self.censys_api:
            try:
                results = self.censys_api.search(f"hosts: {domain}", per_page=5)
                enrichment['censys'] = {'hosts': len(results), 'details': results}
            except Exception as e:
                enrichment['censys'] = {'error': str(e)}
        return enrichment

    def scan_target(self, target: str, scan_type: str, tools: List[str]) -> Dict:
        """Scan a single target with specified tools."""
        target_hash = hashlib.md5(target.encode()).hexdigest()
        if target_hash in self.scanned_targets:
            if self.verbose:
                logging.info(f"Skipping already scanned target: {target}")
            return self.results.get(target, {})
        if not self.validate_target(target):
            logging.warning(f"Invalid target: {target}")
            return {}

        results = {'enrichment': self.enrich_target(target)}
        output_base = os.path.join(self.output_dir, target_hash)
        for tool in tools:
            output_file = f"{output_base}_{tool}.txt"
            if tool == 'xsstrike':
                results['xsstrike'] = self.run_xsstrike(target, output_file)
            elif tool == 'dalfox':
                results['dalfox'] = self.run_dalfox(target, output_file)
            elif tool == 'nuclei':
                results['nuclei'] = self.run_nuclei(target, output_file)
            elif tool == 'zap':
                results['zap'] = self.run_zap(target, output_file)
            elif tool == 'wapiti':
                results['wapiti'] = self.run_wapiti(target, output_file)
            elif tool == 'xsser':
                results['xsser'] = self.run_xsser(target, output_file)
            elif tool == 'xspear':
                results['xspear'] = self.run_xspear(target, output_file)
            elif tool == 'nikto':
                results['nikto'] = self.run_nikto(target, output_file)
            elif tool == 'arachni':
                results['arachni'] = self.run_arachni(target, output_file)
            elif tool == 'sqlmap':
                results['sqlmap'] = self.run_sqlmap(target, output_file)
            elif tool == 'whatweb':
                results['whatweb'] = self.run_whatweb(target, output_file)
            elif tool == 'gobuster':
                results['gobuster'] = self.run_gobuster(target, output_file)
            elif tool == 'dirb':
                results['dirb'] = self.run_dirb(target, output_file)
            elif tool == 'dirsearch':
                results['dirsearch'] = self.run_dirsearch(target, output_file)
            elif tool == 'testssl':
                results['testssl'] = self.run_testssl(target, output_file)
            elif tool == 'wafw00f':
                results['wafw00f'] = self.run_wafw00f(target, output_file)
            elif tool == 'ffuf':
                results['ffuf'] = self.run_ffuf(target, output_file)
            elif tool == 'custom_script':
                results['custom_script'] = self.run_custom_script(target, output_file)

        self.scanned_targets.add(target_hash)
        self.results[target] = results
        self.save_state()
        return results

    def scan_domains(self, domain_files: List[str]) -> None:
        """Scan domains with broad tools."""
        targets = []
        for fpath in domain_files:
            targets.extend(self.read_file(fpath))
        targets = list(set(targets))
        tools = ['nuclei', 'zap', 'wapiti', 'nikto', 'whatweb', 'gobuster', 'dirb', 'dirsearch', 'testssl', 'wafw00f', 'ffuf', 'custom_script']
        if self.config['kamehameha']['enable']:
            curses.wrapper(lambda stdscr: self.kamehameha_loading_screen(stdscr, len(targets), "domains"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['scan_settings']['threads']) as executor:
            futures = [executor.submit(self.scan_target, target, 'domain', tools) for target in targets]
            for future in tqdm(futures, total=len(targets), desc="Scanning domains"):
                future.result()

    def scan_js(self, js_files: List[str]) -> None:
        """Scan JavaScript files/URLs with XSS-focused tools."""
        targets = []
        for fpath in js_files:
            targets.extend(self.read_file(fpath))
        targets = list(set(targets))
        tools = ['xsstrike', 'dalfox', 'xsser', 'xspear', 'nuclei', 'custom_script']
        if self.config['kamehameha']['enable']:
            curses.wrapper(lambda stdscr: self.kamehameha_loading_screen(stdscr, len(targets), "JS files"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['scan_settings']['threads']) as executor:
            futures = [executor.submit(self.scan_target, target, 'js', tools) for target in targets]
            for future in tqdm(futures, total=len(targets), desc="Scanning JS files"):
                future.result()

    def scan_paths_params(self, path_files: List[str], param_files: List[str]) -> None:
        """Scan URLs/paths and parameters with XSS and injection tools."""
        targets = []
        for fpath in path_files + param_files:
            targets.extend(self.read_file(fpath))
        targets = list(set(targets))
        tools = ['xsstrike', 'dalfox', 'nuclei', 'xsser', 'xspear', 'sqlmap', 'arachni', 'custom_script']
        if self.config['kamehameha']['enable']:
            curses.wrapper(lambda stdscr: self.kamehameha_loading_screen(stdscr, len(targets), "paths/params"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['scan_settings']['threads']) as executor:
            futures = [executor.submit(self.scan_target, target, 'path', tools) for target in targets]
            for future in tqdm(futures, total=len(targets), desc="Scanning paths/params"):
                future.result()

    def scan_logs(self, log_files: List[str]) -> None:
        """Scan targets extracted from log files."""
        targets = self.parse_log_files(log_files)
        tools = ['nuclei', 'xsstrike', 'dalfox', 'xsser', 'xspear', 'sqlmap', 'whatweb', 'custom_script']
        if self.config['kamehameha']['enable']:
            curses.wrapper(lambda stdscr: self.kamehameha_loading_screen(stdscr, len(targets), "log targets"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['scan_settings']['threads']) as executor:
            futures = [executor.submit(self.scan_target, target, 'log', tools) for target in targets]
            for future in tqdm(futures, total=len(targets), desc="Scanning log targets"):
                future.result()

    def aggregate_results(self) -> Dict:
        """Aggregate results and generate unified reports."""
        summary = {
            'total_targets': len(self.results),
            'vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        for target, scans in self.results.items():
            for tool, result in scans.items():
                if tool == 'enrichment':
                    continue
                for vuln in result.get('vulnerabilities', []):
                    summary['vulnerabilities'] += 1
                    summary[vuln['severity'].lower()] += 1

        try:
            # Save JSON report
            json_report = os.path.join(self.output_dir, 'scan_results.json')
            with open(json_report, 'w') as f:
                json.dump(self.results, f, indent=2)

            # Generate HTML report
            template = self.env.get_template(self.config['output']['html_template'])
            html_report = os.path.join(self.output_dir, 'scan_results.html')
            with open(html_report, 'w') as f:
                f.write(template.render(
                    results=self.results,
                    summary=summary,
                    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
            if self.verbose:
                logging.info(f"Reports generated: {json_report}, {html_report}")
        except Exception as e:
            logging.error(f"Error generating reports: {e}")
        return summary

    def run(self, scan_types: Optional[List[str]] = None) -> None:
        """Main method to run the scanner."""
        try:
            scan_types = scan_types or ['subdomains', 'domains', 'js', 'paths', 'params', 'logs']

            if 'subdomains' in scan_types:
                logging.info("Starting subdomain scans...")
                self.scan_domains(self.input_files['subdomains'])
            if 'domains' in scan_types:
                logging.info("Starting domain scans...")
                self.scan_domains(self.input_files['domains'])
            if 'js' in scan_types:
                logging.info("Starting JavaScript scans...")
                self.scan_js(self.input_files['js'])
            if 'paths' in scan_types or 'params' in scan_types:
                logging.info("Starting path and parameter scans...")
                self.scan_paths_params(self.input_files['paths'], self.input_files['params'])
            if 'logs' in scan_types:
                logging.info("Starting log file scans...")
                self.scan_logs(self.input_files['logs'])

            summary = self.aggregate_results()
            logging.info(f"Scan completed. Targets: {summary['total_targets']}, Vulnerabilities: {summary['vulnerabilities']}")
        except Exception as e:
            logging.error(f"Critical error in scan: {e}")
            raise

def main():
    parser = argparse.ArgumentParser(description="VulnScanner: The Ultimate Kamehameha-Powered Vulnerability Scanner")
    parser.add_argument('--input-dir', default='input_files', help='Directory containing input files')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    parser.add_argument('--scan-types', nargs='+', choices=['subdomains', 'domains', 'js', 'paths', 'params', 'logs'],
                        help='Types of scans to run (default: all)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    try:
        scanner = VulnScanner(input_dir=args.input_dir, config_file=args.config, verbose=args.verbose)
        scanner.run(scan_types=args.scan_types)
    except Exception as e:
        logging.error(f"Failed to run scanner: {e}")
        exit(1)

if __name__ == "__main__":
    main()
