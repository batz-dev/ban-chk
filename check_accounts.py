#!/usr/bin/env python3
"""
Free Fire Ultra-Fast Bulk Account Ban & Status Checker (OB55)
Author: batz-dev

Features:
- Live streaming output (prints results immediately as each account completes)
- Highly reliable async concurrency with automatic 3x network retry & backoff
- Generates dynamic unique device fingerprints per account to prevent Garena rate-limiting
- Prioritized Active vs Banned detection (accurate In-Game UID & Region for Active, Ban Reason for Banned)
- Auto-exports: check_results.json, active_accounts.txt, banned_accounts.txt
"""

import sys
import os
import json
import asyncio
import uuid
import random
from datetime import datetime, timezone
import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

def encode_varint(v: int) -> bytes:
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)

def encode_proto_field(tag: int, val) -> bytes:
    if isinstance(val, int):
        header = encode_varint((tag << 3) | 0)
        return header + encode_varint(val)
    elif isinstance(val, str):
        b = val.encode('utf-8')
        header = encode_varint((tag << 3) | 2)
        return header + encode_varint(len(b)) + b
    elif isinstance(val, bytes):
        header = encode_varint((tag << 3) | 2)
        return header + encode_varint(len(val)) + val
    return b''

def build_payload(open_id: str, access_token: str, device_id: str = None) -> bytes:
    dev = device_id or f"Google|{uuid.uuid4()}"
    ip = f"{random.randint(100, 220)}.{random.randint(10, 200)}.{random.randint(10, 200)}.{random.randint(10, 200)}"
    fields = {
        3: str(datetime.now())[:-7],
        4: "free fire",
        5: 1,
        7: "2.133.9",
        8: "Android OS 10 / API-29 (QP1A.190711.020/1617006012)",
        9: "Handheld",
        10: "Vi India",
        11: "WIFI",
        12: 1600,
        13: 720,
        14: "320",
        15: "ARM64 FP ASIMD AES | 2301 | 8",
        16: 2799,
        17: "PowerVR Rogue GE8320",
        18: "OpenGL ES 3.2 build 1.11@5425693",
        19: dev,
        20: ip,
        21: "en",
        22: open_id,
        23: "4",
        24: "Handheld",
        25: "realme RMX2189",
        26: "SG",
        29: access_token,
        30: 1,
        41: "Vi India",
        42: "WIFI",
        57: "1ac4b80ecf0478a44203bf8fac6120f5",
        60: 19799,
        61: 2536,
        62: 5056,
        64: 2768,
        65: 19999,
        66: 2536,
        67: 19799,
        73: 1,
        74: "/data/app/com.dts.freefiremax-ShI7E0dK8p1IiZ785pvuVQ==/lib/arm64",
        76: 2,
        77: "38f4751a330688ab124c2c804cec90a5|/data/app/com.dts.freefiremax-ShI7E0dK8p1IiZ785pvuVQ==/base.apk",
        78: 2,
        79: 2,
        81: "64",
        83: "2019118527",
        86: "OpenGLES3",
        87: 3071,
        88: 4,
        92: 67920,
        93: "android_max",
        94: "KqsHT+UrR1HKqb6+1db+Ofei+NtZr2+hbiBo3yKDL8w+8E3S5qF2IgEEe1fFQFyHRzl4iyHjHp+QsfeLbjJ6+DidTiKxm0ak2uYYa6QR4nAUdlZR",
        95: 111107,
        96: '{"cur_rate":null,"support_etc2":true}',
        97: 1,
        98: 1,
        99: "4",
        100: "4",
        102: "",
        104: 83812,
        105: 1,
        106: "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a",
        107: "1.9393e7b8e53e8aeb"
    }
    raw = bytearray()
    for tag in sorted(fields.keys()):
        raw.extend(encode_proto_field(tag, fields[tag]))
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(bytes(raw), AES.block_size))

def decode_proto(data: bytes) -> dict:
    fields = {}
    i = 0
    blen = len(data)
    while i < blen:
        key = 0
        shift = 0
        while True:
            if i >= blen:
                return fields
            b = data[i]
            i += 1
            key |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        tag = key >> 3
        wire = key & 7
        if wire == 0:  # varint
            v = 0
            shift = 0
            while True:
                if i >= blen:
                    return fields
                b = data[i]
                i += 1
                v |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
            fields[tag] = v
        elif wire == 2:  # length-delimited
            v_len = 0
            shift = 0
            while True:
                if i >= blen:
                    return fields
                b = data[i]
                i += 1
                v_len |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
            if i + v_len > blen:
                return fields
            fields[tag] = data[i:i + v_len]
            i += v_len
        elif wire == 1:
            i += 8
        elif wire == 5:
            i += 4
        else:
            break
    return fields

def parse_login_response(content: bytes):
    if len(content) < 40:
        return "LOGIN_FAILED", "-", "-", "Empty or invalid response"

    # PRIORITY 1: Check for ACTIVE account across all valid offsets
    for offset in [64, 0] + list(range(1, 128)):
        if len(content) <= offset:
            continue
        fields = decode_proto(content[offset:])
        if not fields:
            continue

        # Active account MUST have In-Game UID (tag 1), Region (tag 2), and Token (tag 8)
        if 1 in fields and 2 in fields and 8 in fields:
            uid_val = str(fields[1])
            reg_val = fields[2].decode(errors='ignore') if isinstance(fields[2], (bytes, bytearray)) else str(fields[2])
            if uid_val.isdigit() and int(uid_val) > 0 and len(reg_val) in (2, 3, 4):
                return "ACTIVE", uid_val, reg_val, ""

    # PRIORITY 2: Check for BANNED account (only when NOT active and packet is small ban record)
    for offset in [64, 0] + list(range(1, 128)):
        if len(content) <= offset:
            continue
        fields = decode_proto(content[offset:])
        if not fields:
            continue

        if 13 in fields and len(content) < 500:
            sub = decode_proto(fields[13])
            reason = sub.get(4, b'').decode(errors='ignore') if isinstance(sub.get(4), (bytes, bytearray)) else str(sub.get(4, ''))
            details = f"Reason: {reason}" if reason else "Banned by Garena"
            return "BANNED", "-", "-", details

    return "UNKNOWN", "-", "-", ""

async def check_account(client: httpx.AsyncClient, uid: str, password: str, semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        result = {
            "guest_uid": uid,
            "password": password,
            "status": "UNKNOWN",
            "ingame_uid": "-",
            "region": "-",
            "details": ""
        }

        # 1. Garena OAuth Grant with up to 3 retries
        oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        oauth_headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "Dalvik/2.1.0",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        oauth_data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }

        res_json = None
        for attempt in range(3):
            try:
                r = await client.post(oauth_url, headers=oauth_headers, data=oauth_data, timeout=12)
                if r.status_code == 429:
                    await asyncio.sleep(1.0 * (attempt + 1))
                    continue
                res_json = r.json()
                break
            except Exception as e:
                if attempt == 2:
                    result["status"] = "NETWORK_ERROR"
                    result["details"] = f"Timeout/Disconnect ({str(e)})"
                    return result
                await asyncio.sleep(0.8 * (attempt + 1))

        if not res_json or "error" in res_json or not res_json.get("access_token"):
            result["status"] = "INVALID_CREDENTIALS"
            result["details"] = res_json.get("error", "Wrong UID or Password") if res_json else "No response"
            return result

        open_id = res_json["open_id"]
        access_token = res_json["access_token"]

        # 2. MajorLogin Authentication & Status Check
        login_url = "https://loginbp.ppmainecoonghj.com/MajorLogin"
        login_headers = {
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-TANBIR)",
            "Accept": "*/*",
            "Accept-Encoding": "deflate, gzip",
            "X-Ga-Sv": "1789534056",
            "Authorization": "Bearer",
            "X-Ga": "v1 1",
            "Releaseversion": "OB55",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.12f1"
        }

        dev_id = f"Google|{uuid.uuid4()}"
        payload = build_payload(open_id, access_token, dev_id)

        for attempt in range(3):
            try:
                r_login = await client.post(login_url, headers=login_headers, content=payload, timeout=12)
                if r_login.status_code == 200:
                    status, ingame_uid, region, details = parse_login_response(r_login.content)
                    result["status"] = status
                    result["ingame_uid"] = ingame_uid
                    result["region"] = region
                    result["details"] = details
                else:
                    err_text = r_login.text.strip()
                    if "BANNED" in err_text:
                        result["status"] = "BANNED"
                        result["details"] = err_text
                    else:
                        result["status"] = "LOGIN_FAILED"
                        result["details"] = err_text
                break
            except Exception as e:
                if attempt == 2:
                    result["status"] = "NETWORK_ERROR"
                    result["details"] = f"MajorLogin error ({str(e)})"
                    return result
                await asyncio.sleep(0.8 * (attempt + 1))

        return result

def load_accounts_from_file(file_path: str) -> list:
    if not os.path.exists(file_path):
        print(f"{RED}[!] File not found: {file_path}{RESET}")
        return []

    accounts = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    for u, p in data.items():
                        accounts.append((str(u).strip(), str(p).strip()))
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, str) and ":" in item:
                            u, p = item.split(":", 1)
                            accounts.append((u.strip(), p.strip()))
                        elif isinstance(item, dict):
                            u = item.get("uid") or item.get("id") or item.get("account")
                            p = item.get("password") or item.get("pass") or item.get("pwd")
                            if u and p:
                                accounts.append((str(u).strip(), str(p).strip()))
                            elif len(item) == 1:
                                u, p = list(item.items())[0]
                                accounts.append((str(u).strip(), str(p).strip()))
            except json.JSONDecodeError:
                for line in content.splitlines():
                    line = line.strip()
                    if line and ":" in line and not line.startswith("#"):
                        u, p = line.split(":", 1)
                        accounts.append((u.strip(), p.strip()))
    except Exception as e:
        print(f"{RED}[!] Error reading file: {e}{RESET}")

    return accounts

async def main():
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}      FREE FIRE ULTRA-FAST LIVE BAN & STATUS CHECKER (OB55)           {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input(f"{BOLD}Enter path to accounts JSON/TXT file: {RESET}").strip()

    if not file_path:
        print(f"{RED}[!] No file provided.{RESET}")
        return

    accounts = load_accounts_from_file(file_path)
    if not accounts:
        print(f"{RED}[!] No valid uid:pass pairs found in {file_path}.{RESET}")
        return

    total = len(accounts)
    print(f"{GREEN}[+] Loaded {total} accounts from {file_path}{RESET}")
    print(f"{CYAN}[i] Starting live checking with parallel workers (anti-rate-limit protected)...{RESET}\n")

    print(f"{BOLD}{'-' * 88}{RESET}")
    print(f"{BOLD}{'#':<6} | {'GUEST UID':<14} | {'INGAME UID':<14} | {'REGION':<7} | {'STATUS':<12} | {'DETAILS'}{RESET}")
    print(f"{BOLD}{'-' * 88}{RESET}")

    # Optimal concurrency to prevent Garena connection drops (5-8 workers)
    concurrency = min(8, max(3, total))
    semaphore = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=concurrency * 3, max_keepalive_connections=concurrency)
    client = httpx.AsyncClient(verify=False, timeout=15, limits=limits)

    completed_count = 0
    active_cnt = 0
    banned_cnt = 0
    invalid_cnt = 0

    results = []
    active_list = []
    banned_list = []

    lock = asyncio.Lock()

    async def worker(u: str, p: str):
        nonlocal completed_count, active_cnt, banned_cnt, invalid_cnt
        res = await check_account(client, u, p, semaphore)
        
        async with lock:
            completed_count += 1
            idx = completed_count
            status = res["status"]
            
            if status == "ACTIVE":
                active_cnt += 1
                status_str = f"{GREEN}ACTIVE{RESET}"
                active_list.append(f"{u}:{p}")
            elif "BANNED" in status:
                banned_cnt += 1
                status_str = f"{RED}BANNED{RESET}"
                banned_list.append(f"{u}:{p}")
            else:
                invalid_cnt += 1
                status_str = f"{YELLOW}{status[:12]}{RESET}"

            details = res.get("details", "")
            print(f"[{idx:<4}/{total}] | {res['guest_uid']:<14} | {res['ingame_uid']:<14} | {res['region']:<7} | {status_str:<21} | {details}")
            results.append(res)

    tasks = [worker(u, p) for u, p in accounts]
    await asyncio.gather(*tasks)
    await client.aclose()

    print(f"{BOLD}{'-' * 88}{RESET}")
    print(f"\n{BOLD}CHECK COMPLETED!{RESET}")
    print(f"Total: {total} | {GREEN}Active: {active_cnt}{RESET} | {RED}Banned: {banned_cnt}{RESET} | {YELLOW}Invalid/Error: {invalid_cnt}{RESET}\n")

    # Export results
    with open("check_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"{GREEN}[✓] Full JSON results saved to: check_results.json{RESET}")

    if active_list:
        with open("active_accounts.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(active_list) + "\n")
        print(f"{GREEN}[✓] Active accounts saved to: active_accounts.txt ({len(active_list)} accounts){RESET}")

    if banned_list:
        with open("banned_accounts.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(banned_list) + "\n")
        print(f"{RED}[✓] Banned accounts saved to: banned_accounts.txt ({len(banned_list)} accounts){RESET}")
    print()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Cancelled by user.{RESET}")
