#!/usr/bin/env python3
"""
Free Fire Bulk Account Ban & Status Checker (OB55)
Author: batz-dev

Checks Guest UID:Password accounts in bulk:
- Authenticates with Garena OAuth
- Resolves In-Game UID & Server Region via OB55 MajorLogin
- Cross-references Garena Anti-Hack API for Ban status & duration
- Supports JSON (dict, list) and plain text lines
- Fast asynchronous concurrent execution
"""

import sys
import os
import json
import asyncio
from datetime import datetime
import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Terminal Colors
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

def build_payload(open_id: str, access_token: str) -> bytes:
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
        19: "Google|9f7d6b8b-b10c-454a-852d-06332cd498eb",
        20: "151.158.158.220",
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

def parse_proto_response(response_bytes: bytes):
    """Zero-dependency protobuf decoder for MajorLoginRes."""
    for offset in [64, 0] + list(range(1, 128)):
        if len(response_bytes) <= offset:
            continue
        data = response_bytes[offset:]
        fields = {}
        i = 0
        try:
            while i < len(data):
                key = 0
                shift = 0
                while True:
                    if i >= len(data):
                        break
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
                        if i >= len(data):
                            break
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
                        if i >= len(data):
                            break
                        b = data[i]
                        i += 1
                        v_len |= (b & 0x7F) << shift
                        if (b & 0x80) == 0:
                            break
                        shift += 7
                    val = data[i:i + v_len]
                    i += v_len
                    fields[tag] = val
                elif wire == 1:
                    i += 8
                elif wire == 5:
                    i += 4
                else:
                    break

            if 1 in fields and 2 in fields:
                uid_val = str(fields[1])
                reg_val = fields[2].decode(errors='ignore')
                if uid_val.isdigit() and len(reg_val) in (2, 3, 4):
                    return uid_val, reg_val
        except Exception:
            pass
    return "-", "-"

async def check_account(client: httpx.AsyncClient, uid: str, password: str, semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        result = {
            "guest_uid": uid,
            "status": "UNKNOWN",
            "ingame_uid": "-",
            "region": "-",
            "details": ""
        }

        # 1. Garena OAuth Grant
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

        try:
            r = await client.post(oauth_url, headers=oauth_headers, data=oauth_data, timeout=12)
            res_json = r.json()
        except Exception as e:
            result["status"] = "NETWORK_ERROR"
            result["details"] = str(e)
            return result

        if "error" in res_json or not res_json.get("access_token"):
            result["status"] = "INVALID_CREDENTIALS"
            result["details"] = res_json.get("error", "Wrong UID or Password")
            return result

        open_id = res_json["open_id"]
        access_token = res_json["access_token"]

        # 2. MajorLogin to resolve Ingame UID & Region
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

        payload = build_payload(open_id, access_token)
        try:
            r_login = await client.post(login_url, headers=login_headers, content=payload, timeout=12)
            if r_login.status_code == 200:
                ingame_uid, region = parse_proto_response(r_login.content)
                result["ingame_uid"] = ingame_uid
                result["region"] = region
            else:
                err_text = r_login.text.strip()
                if "BANNED" in err_text:
                    result["status"] = "BANNED"
                    result["details"] = err_text
                    return result
        except Exception:
            pass

        # 3. Garena Official Anti-Hack Verification
        target_uid = result["ingame_uid"] if result["ingame_uid"] != "-" else uid
        antihack_url = f"https://ff.garena.com/api/antihack/check_banned?lang=en&uid={target_uid}"
        antihack_headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10)",
            "Accept": "application/json",
            "referer": "https://ff.garena.com/en/support/",
            "x-requested-with": "B6FksShzIgjfrYImLpTsadjS86sddhFH"
        }

        try:
            r_ban = await client.get(antihack_url, headers=antihack_headers, timeout=10)
            if r_ban.status_code == 200:
                ban_data = r_ban.json().get("data", {})
                is_banned = ban_data.get("is_banned", 0)
                period = ban_data.get("period", 0)
                if is_banned == 1:
                    result["status"] = "BANNED"
                    result["details"] = f"Duration: {period} hours" if period > 0 else "Permanent Ban"
                else:
                    result["status"] = "ACTIVE"
            else:
                result["status"] = "ACTIVE"
        except Exception:
            result["status"] = "ACTIVE"

        return result

def load_accounts_from_file(file_path: str) -> list:
    if not os.path.exists(file_path):
        print(f"{RED}[!] File not found: {file_path}{RESET}")
        return []

    accounts = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            # Try JSON first
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
                # Text lines: uid:pass
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
    print(f"{BOLD}{CYAN}          FREE FIRE BULK ACCOUNT BAN & STATUS CHECKER (OB55)           {RESET}")
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

    print(f"{GREEN}[+] Loaded {len(accounts)} accounts from {file_path}{RESET}")
    print(f"{CYAN}[i] Checking accounts concurrently... please wait.{RESET}\n")

    semaphore = asyncio.Semaphore(5)
    client = httpx.AsyncClient(verify=False, timeout=15)

    tasks = [check_account(client, u, p, semaphore) for u, p in accounts]
    results = await asyncio.gather(*tasks)
    await client.aclose()

    # Results Table
    print(f"{BOLD}{'-' * 80}{RESET}")
    print(f"{BOLD}{'GUEST UID':<15} | {'INGAME UID':<15} | {'REGION':<8} | {'STATUS':<15} | {'DETAILS'}{RESET}")
    print(f"{BOLD}{'-' * 80}{RESET}")

    active_cnt = 0
    banned_cnt = 0
    invalid_cnt = 0

    for r in results:
        status = r["status"]
        if status == "ACTIVE":
            status_color = f"{GREEN}{status:<15}{RESET}"
            active_cnt += 1
        elif "BANNED" in status:
            status_color = f"{RED}{status:<15}{RESET}"
            banned_cnt += 1
        else:
            status_color = f"{YELLOW}{status:<15}{RESET}"
            invalid_cnt += 1

        details = r.get("details", "")
        print(f"{r['guest_uid']:<15} | {r['ingame_uid']:<15} | {r['region']:<8} | {status_color} | {details}")

    print(f"{BOLD}{'-' * 80}{RESET}\n")
    print(f"{BOLD}SUMMARY:{RESET} Total: {len(results)} | {GREEN}Active: {active_cnt}{RESET} | {RED}Banned: {banned_cnt}{RESET} | {YELLOW}Invalid/Error: {invalid_cnt}{RESET}\n")

    output_json = "check_results.json"
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"{GREEN}[✓] Full results saved to: {output_json}{RESET}\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Cancelled by user.{RESET}")
