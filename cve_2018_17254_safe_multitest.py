#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2018-17254  多目標「安全」（非侵入）預檢腳本
-------------------------------------------------
用途：
  在 *已授權* 條件下，對多個站點進行「低風險、非破壞性」的預檢：
    1) 端點存在性：/plugins/editors/jckeditor/plugins/jtreelink/dialogs/links.php?parent=1
    2) 基準時延：重複請求取平均/離散度（用於後續人工時延判讀的參考）
    3) 參數布林切換對照：parent=1 vs parent=0 比較回應大小差異（不包含注入負載）

重要安全聲明：
  - 本腳本 **不包含** 任何利用負載（例如 SLEEP、UNION、LOAD_FILE 等），避免造成未經許可的資料外洩。
  - 若需進一步（侵入）驗證或取證，請於獲得書面授權後，自行在 `plugins/invasive.py` 中實作對應測試，
    或使用合規設定的商用/開源工具；請遵循當地法律與甲方授權範圍。

輸入：
  - 目標清單檔（每行一個 base URL 或網域，支援 http/https；無協定預設 https）
  - （可選）Proxy 清單檔（每行一條，如 http://user:pass@host:port）

輸出：
  - CSV 與 JSONL（--out-csv / --out-jsonl），欄位見 DataRow dataclass。

範例：
  python3 cve_2018_17254_safe_multitest.py \
    --targets targets.txt \
    --workers 16 --retries 1 --timeout 15 \
    --out-csv results.csv --out-jsonl results.jsonl \
    --insecure

targets.txt 範例：
  https://example.com
  example.org

作者：Alexia（僅供合規測試與教育用途）
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import hashlib
import json
import os
import random
import re
import string
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# -----------------------------
# 常量與工具
# -----------------------------
DEFAULT_ENDPOINT = "/plugins/editors/jckeditor/plugins/jtreelink/dialogs/links.php"
DEFAULT_PARAM = "parent"
DEFAULT_BASELINE_REPEATS = 5
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36",
]

RISK_HINT_NONE = "NONE"
RISK_HINT_ENDPOINT_ONLY = "ENDPOINT_PRESENT"
RISK_HINT_SIZE_DIFF = "SIZE_DIFF"
RISK_HINT_UNREACHABLE = "UNREACHABLE"

@dataclass
class DataRow:
    target: str
    final_url: str
    status_endpoint: Optional[int]
    resp_len_parent1: Optional[int]
    resp_len_parent0: Optional[int]
    size_delta: Optional[int]
    size_delta_ratio: Optional[float]
    baseline_avg_ms: Optional[float]
    baseline_p95_ms: Optional[float]
    baseline_raw_ms: List[float]
    hint: str
    note: str


# -----------------------------
# Session / HTTP
# -----------------------------

def build_session(timeout: int, retries: int, insecure: bool, proxy: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=0.4,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD"),
    )
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent": random.choice(UA_LIST)})
    s.verify = not insecure
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    # 封裝超時於 request() 時指定
    s.request_timeout = timeout
    return s


def norm_base(base: str) -> str:
    base = base.strip()
    if not base:
        return base
    if not base.startswith("http://") and not base.startswith("https://"):
        return f"https://{base}"
    return base


def join_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def with_cache_buster(url: str) -> str:
    cb = str(int(time.time() * 1000)) + ''.join(random.choices(string.digits, k=4))
    sep = '&' if '?' in url else '?'
    return f"{url}{sep}cb={cb}"


# -----------------------------
# 單目標測試
# -----------------------------

def check_endpoint(session: requests.Session, base: str, endpoint_path: str, param_name: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    url = join_url(base, endpoint_path)
    params = {param_name: "1"}
    try:
        r = session.get(url, params=params, timeout=session.request_timeout, allow_redirects=True)
        content = r.text or ""
        return r.status_code, len(r.content or b""), r.url
    except requests.RequestException as e:
        return None, None, None


def baseline_latency(session: requests.Session, base: str, endpoint_path: str, param_name: str, repeats: int) -> Tuple[Optional[float], Optional[float], List[float]]:
    url = join_url(base, endpoint_path)
    params = {param_name: "1"}
    samples: List[float] = []
    for _ in range(repeats):
        try:
            t0 = time.perf_counter()
            r = session.get(with_cache_buster(url), params=params, timeout=session.request_timeout, allow_redirects=True)
            _ = r.content
            dt = (time.perf_counter() - t0) * 1000.0
            samples.append(dt)
        except requests.RequestException:
            samples.append(float("nan"))
    clean = [x for x in samples if x == x]
    if not clean:
        return None, None, samples
    clean.sort()
    avg = sum(clean) / len(clean)
    p95 = clean[int(max(0, len(clean) * 0.95 - 1))]
    return avg, p95, samples


def boolean_toggle_size_diff(session: requests.Session, base: str, endpoint_path: str, param_name: str) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[float]]:
    url = join_url(base, endpoint_path)
    try:
        r1 = session.get(with_cache_buster(url), params={param_name: "1"}, timeout=session.request_timeout, allow_redirects=True)
        r0 = session.get(with_cache_buster(url), params={param_name: "0"}, timeout=session.request_timeout, allow_redirects=True)
        l1 = len(r1.content or b"")
        l0 = len(r0.content or b"")
        delta = l1 - l0
        ratio = (abs(delta) / max(1, l1)) if l1 else None
        return l1, l0, delta, ratio
    except requests.RequestException:
        return None, None, None, None


# -----------------------------
# 主管道
# -----------------------------

def test_one(base: str, endpoint_path: str, param_name: str, timeout: int, retries: int, insecure: bool, proxy: Optional[str]) -> DataRow:
    b = norm_base(base)
    s = build_session(timeout=timeout, retries=retries, insecure=insecure, proxy=proxy)

    status, length_p1, final_url = check_endpoint(s, b, endpoint_path, param_name)

    hint = RISK_HINT_UNREACHABLE if status is None else (
        RISK_HINT_ENDPOINT_ONLY if (status and 200 <= status < 400) else RISK_HINT_NONE
    )

    # 基準時延
    avg_ms, p95_ms, raw_ms = baseline_latency(s, b, endpoint_path, param_name, DEFAULT_BASELINE_REPEATS)

    # 參數布林切換（安全對照，無注入）
    l1, l0, delta, ratio = boolean_toggle_size_diff(s, b, endpoint_path, param_name)
    if ratio is not None and ratio >= 0.05:  # 5% 門檻，僅作為人工複核線索
        hint = RISK_HINT_SIZE_DIFF

    note = ""
    if status and status >= 400:
        note = f"HTTP {status}"

    return DataRow(
        target=b,
        final_url=final_url or "",
        status_endpoint=status,
        resp_len_parent1=l1,
        resp_len_parent0=l0,
        size_delta=delta,
        size_delta_ratio=ratio,
        baseline_avg_ms=avg_ms,
        baseline_p95_ms=p95_ms,
        baseline_raw_ms=[round(x, 2) if x == x else None for x in raw_ms],
        hint=hint,
        note=note,
    )


def load_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def pick_proxy(proxy_list: Optional[List[str]]) -> Optional[str]:
    if not proxy_list:
        return None
    return random.choice(proxy_list)


def main():
    ap = argparse.ArgumentParser(description="CVE-2018-17254 Safe Multi-Target Preflight")
    ap.add_argument("--targets", required=True, help="目標清單檔（每行一個 base URL 或網域）")
    ap.add_argument("--endpoint-path", default=DEFAULT_ENDPOINT, help=f"端點路徑（預設 {DEFAULT_ENDPOINT}）")
    ap.add_argument("--param-name", default=DEFAULT_PARAM, help=f"參數名稱（預設 {DEFAULT_PARAM}）")
    ap.add_argument("--workers", type=int, default=12, help="並發數（預設 12）")
    ap.add_argument("--timeout", type=int, default=15, help="單請求逾時秒數（預設 15）")
    ap.add_argument("--retries", type=int, default=1, help="自動重試次數（預設 1）")
    ap.add_argument("--proxy-file", help="Proxy 清單檔（每行一條，如 http://user:pass@host:port）")
    ap.add_argument("--out-csv", help="輸出 CSV 路徑")
    ap.add_argument("--out-jsonl", help="輸出 JSONL 路徑")
    ap.add_argument("--insecure", action="store_true", help="忽略憑證驗證（僅測試環境使用）")
    args = ap.parse_args()

    # 如果選了 --insecure，就抑制 InsecureRequestWarning 噪音（僅測試環境建議）。
    if args.insecure:
        try:
            import urllib3
            from urllib3.exceptions import InsecureRequestWarning
            urllib3.disable_warnings(category=InsecureRequestWarning)
        except Exception:
            pass


    targets = load_lines(args.targets)
    proxies = load_lines(args.proxy_file) if args.proxy_file else None

    rows: List[DataRow] = []

    def _job(t: str) -> DataRow:
        return test_one(
            base=t,
            endpoint_path=args.endpoint_path,
            param_name=args.param_name,
            timeout=args.timeout,
            retries=args.retries,
            insecure=args.insecure,
            proxy=pick_proxy(proxies),
        )

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(_job, t) for t in targets]
        for fut in cf.as_completed(futures):
            row = fut.result()
            rows.append(row)
            # 即時輸出一行摘要
            avg_str = (f"{row.baseline_avg_ms:.1f}" if (row.baseline_avg_ms is not None) else "nan")
            print(
                f"[DONE] {row.target} | status={row.status_endpoint} | len(p1/p0)={row.resp_len_parent1}/{row.resp_len_parent0} | "
                f"Δ={row.size_delta} ({(row.size_delta_ratio or 0)*100:.1f}%) | avg={avg_str}ms | hint={row.hint}"
            )

    # 輸出 CSV / JSONL
    if args.out_csv:
        import csv
        fieldnames = [f.name for f in dataclasses.fields(DataRow)]
        with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in rows:
                d = asdict(r)
                # baseline_raw_ms 存為 JSON 字串以便表格工具兼容
                d["baseline_raw_ms"] = json.dumps(d["baseline_raw_ms"], ensure_ascii=False)
                writer.writerow(d)
        print(f"[INFO] CSV written to {args.out_csv}")

    if args.out_jsonl:
        with open(args.out_jsonl, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")
        print(f"[INFO] JSONL written to {args.out_jsonl}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[WARN] Interrupted by user.")
        sys.exit(130)

