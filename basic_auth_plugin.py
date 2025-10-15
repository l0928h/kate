import logging
import requests
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from threading import Lock
import os
import csv
from datetime import datetime
from bs4 import BeautifulSoup
import random
from urllib.parse import urlparse, urlunparse

class BasicAuthPlugin:
    def __init__(
        self,
        threads=5,
        timeout=10,
        debug=False,
        proxy=None,
        proxy_pool=None,
        logger=None
    ):
        self.threads = threads
        self.timeout = timeout
        self.debug = debug
        self.proxy = proxy
        self.proxy_pool = proxy_pool or []
        self.logger = logger or self.setup_logger(debug)
        self.lock = Lock()

    def setup_logger(self, debug_mode):
        logger = logging.getLogger("basic_auth")
        logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
        if logger.hasHandlers():
            logger.handlers.clear()

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        log_filename = os.path.join(log_dir, f"basic_auth_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

        file_handler = logging.FileHandler(log_filename, encoding='utf-8')
        file_handler.setFormatter(formatter)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        return logger

    def get_random_proxy(self):
        if self.proxy_pool:
            selected = random.choice(self.proxy_pool)
        else:
            selected = self.proxy
        return {'http': selected, 'https': selected} if selected else None

    def _normalize_target(self, target, port):
        p = urlparse(target, scheme='http')
        if not p.netloc:
            netloc = f"{p.path}:{port}"
            path = ""
        else:
            host = p.hostname
            port0 = p.port or port
            netloc = f"{host}:{port0}"
            path = p.path
        return urlunparse((p.scheme, netloc, path or '', '', '', ''))

    def check_basic_auth_support(self, target_url, proxies=None):
        try:
            response = requests.get(target_url, timeout=self.timeout, verify=False, proxies=proxies)
            www_auth = response.headers.get('WWW-Authenticate', '')
            if response.status_code == 401 and 'Basic' in www_auth:
                return True, response.status_code
            soup = BeautifulSoup(response.text, 'html.parser')
            title_text = soup.title.string.strip() if soup.title and soup.title.string else ""
            if response.status_code == 401 and "Authorization" in title_text:
                return True, response.status_code
            return False, response.status_code
        except requests.RequestException as e:
            self.logger.error(f"Error checking Basic Auth for {target_url}: {e}")
            return False, None

    def attempt_basic_auth(self, target_url, username, password):
        proxies = self.get_random_proxy()
        supports, status = self.check_basic_auth_support(target_url, proxies=proxies)
        if not supports:
            return False, status, "Target does not support Basic Auth"

        parsed = urlparse(target_url)
        path = parsed.path or '/'
        if not os.path.splitext(path)[1] and not path.endswith('/'):
            target_url = target_url.rstrip('/') + '/'

        try:
            session = requests.Session()
            session.auth = HTTPBasicAuth(username, password)
            response = session.get(target_url, timeout=self.timeout, verify=False, proxies=proxies)
            if response.status_code == 200:
                return True, 200, "Successful login"
            return False, response.status_code, f"Failed with status {response.status_code}"
        except requests.RequestException as e:
            return False, None, str(e)

    def write_success_csv(self, file_path, target, port, username, password, status, response_code):
        with self.lock:
            with open(file_path, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["Target", "Port", "Username", "Password", "Status", "ResponseCode"])
                if csvfile.tell() == 0:
                    writer.writeheader()
                writer.writerow({
                    "Target": target,
                    "Port": port,
                    "Username": username,
                    "Password": password,
                    "Status": status,
                    "ResponseCode": response_code
                })

    def write_failure_csv(self, file_path, target, username, password, response_code, failure_reason):
        with self.lock:
            os.makedirs(os.path.dirname(file_path), exist_ok=True) 
            with open(file_path, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["Target", "Username", "Password", "ResponseCode", "FailureReason"])
                if csvfile.tell() == 0:
                    writer.writeheader()
                writer.writerow({
                    "Target": target,
                    "Username": username,
                    "Password": password,
                    "ResponseCode": response_code,
                    "FailureReason": failure_reason
                })

    def process_login(self, target, port, username, password, output_file, failed_log, timeout, retries):
        original_timeout = self.timeout
        self.timeout = timeout

        target_url = self._normalize_target(target, port)

        success = False
        last_status_msg = ""
        last_numeric = ""

        for attempt in range(1, int(retries) + 1):
            self.logger.debug(f"Attempt {attempt}/{retries} for {target_url} with {username}:{password}")
            success, code, msg = self.attempt_basic_auth(target_url, username, password)
            if success:
                last_status_msg = f"Success on attempt {attempt}"
                last_numeric = str(code)
                break
            last_status_msg = msg
            last_numeric = str(code) if code else ""

        if success:
            self.logger.info(f"✅ Successful login: {target_url} - {username}/{password}")
            self.write_success_csv(output_file, target, port, username, password, last_status_msg, last_numeric)
        elif failed_log:
            self.logger.warning(f"❌ Failed login: {target_url} - {username}/{password} | {last_status_msg}")
            self.write_failure_csv(failed_log, target, username, password, last_numeric, last_status_msg)

        self.timeout = original_timeout

    def run_multi_login(self, login_tasks, output_file, failed_log, timeout, retries):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for task in login_tasks:
                if len(task) == 4:
                    target, port, username, password = task
                    futures.append(executor.submit(
                        self.process_login,
                        target, port, username, password,
                        output_file, failed_log, timeout, retries
                    ))
            for f in tqdm(as_completed(futures), total=len(futures), desc="Basic Auth Login Attempts"):
                _ = f.result()




