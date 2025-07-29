#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_webshells.py (multithreaded 改版)

用法:
    python detect_webshells.py --input targets.txt [--threads 10]

脚本说明:
    - 从文件读取目标域名或 URL 列表
    - 若未指定协议，依序尝试 https:// 和 http://
    - 并行请求每个 URL，获取 HTTP 回应码并匹配 Webshell 登录表单特征
    - 将结果即时输出至屏幕，并实时写入 CSV 文件
    - CSV 列：url、status（HTTP 回应码 或 错误信息）、has_webshell（Yes/No）
"""

import argparse
import re
import csv
import sys
import threading
import requests
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 特征码列表（正则） ---
signatures = [
    re.compile(r'<form[^>]*method=["\']POST["\']', re.IGNORECASE),
    re.compile(r'Password\s*:', re.IGNORECASE),
    re.compile(r'<input[^>]*name=["\']password["\'][^>]*type=["\']password["\']', re.IGNORECASE),
    re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']action["\'][^>]*value=["\']login["\']', re.IGNORECASE),
]

def is_webshell(html: str) -> bool:
    """判断页面中是否包含所有特征码"""
    return all(sig.search(html) for sig in signatures)

def normalize_targets(lines):
    out = []
    for line in lines:
        host = line.strip()
        if not host:
            continue
        if host.startswith(('http://', 'https://')):
            out.append(host)
        else:
            out.append('https://' + host)
            out.append('http://'  + host)
    return out

def detect_and_write(input_file: str, output_file: str = 'results.csv', timeout: float = 3.0, threads: int = 10):
    # 打开 CSV 并写入表头
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['url', 'status', 'has_webshell'])
        csvfile.flush()

        # 读取并标准化目标列表
        with open(input_file, 'r', encoding='utf-8') as f:
            raw = f.readlines()
        urls = normalize_targets(raw)
        print(f"[*] 目标总数（含协议扩展）: {len(urls)}，使用线程数: {threads}")

        # 线程锁，用于保护打印与写入
        lock = threading.Lock()

        def process_url(url):
            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True)
                code = resp.status_code
                html = resp.text
                detected = is_webshell(html)
                status = code
                has = 'Yes' if detected else 'No'
                # 控制台输出与写 CSV 都需加锁
                with lock:
                    if detected:
                        print(f"[+] {code} Possible webshell: {url}")
                    else:
                        print(f"[-] {code} No shell: {url}")
                    writer.writerow([url, status, has])
                    csvfile.flush()
            except RequestException as e:
                status = f"Error: {e}"
                has = 'No'
                with lock:
                    print(f"[!] {url} connection failed: {e}", file=sys.stderr)
                    writer.writerow([url, status, has])
                    csvfile.flush()

        # 使用 ThreadPoolExecutor 并行处理
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(process_url, url) for url in urls]
            # 等待所有任务完成
            for _ in as_completed(futures):
                pass

    print(f"[*] 检测结束，结果已实时写入 {output_file}")

def main():
    parser = argparse.ArgumentParser(description="多线程检测 Webshell 登录界面（实时输出 CSV）")
    parser.add_argument('--input', '-i', required=True,
                        help="目标清单文件，每行域名或 URL")
    parser.add_argument('--output', '-o', default='results.csv',
                        help="输出 CSV 文件名，默认为 results.csv")
    parser.add_argument('--threads', '-t', type=int, default=10,
                        help="并行线程数，默认为 10")
    args = parser.parse_args()

    print(f"[*] 开始检测，输入文件：{args.input}，输出文件：{args.output}")
    detect_and_write(args.input, args.output, threads=args.threads)

if __name__ == "__main__":
    main()



