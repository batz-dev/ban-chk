# Free Fire Bulk Account Ban & Status Checker (OB55)

A fast, asynchronous Python tool to check Free Fire Guest accounts in bulk (`UID:Password`).

It authenticates through Garena OAuth, resolves the real **In-Game UID** and **Server Region** via OB55 MajorLogin, and queries the official Garena Anti-Hack API to detect whether accounts are **ACTIVE**, **BANNED** (with ban duration in hours), or have **INVALID CREDENTIALS**.

---

## Features

- **Bulk & Fast**: Asynchronously checks multiple accounts concurrently with rate-limit protection.
- **In-Game Details**: Resolves the account's actual In-Game Player UID and Server Region (`NA`, `BD`, `IND`, `SG`, `ME`, `BR`, etc.).
- **Accurate Ban Detection**: Queries the official Garena anti-hack system for ban status and duration (temporary vs. permanent).
- **Flexible Input Formats**: Automatically recognizes dictionary format, string arrays, list of objects, or plain text lines (`.txt`).
- **Zero Heavy Dependencies**: Pure Python protobuf parsing without external compiled `.proto` schemas.
- **Export Results**: Automatically writes structured output to `check_results.json`.

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/batz-dev/ban-chk.git
   cd ban-chk
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

### 1. Prepare your Accounts File

Supported formats:

**Dictionary Format (`accounts.json`):**
```json
{
  "7982138970": "ARIYAN_MAX_BD_3WA3ujD5",
  "8192837461": "PASSWORD_HERE"
}
```

**List Format:**
```json
[
  "7982138970:ARIYAN_MAX_BD_3WA3ujD5",
  "8192837461:PASSWORD_HERE"
]
```

**Plain Text Format (`accounts.txt`):**
```text
7982138970:ARIYAN_MAX_BD_3WA3ujD5
8192837461:PASSWORD_HERE
```

---

### 2. Run the Checker

Pass the file path directly:
```bash
python3 check_accounts.py accounts.json
```

Or run interactively (it will prompt for the file path):
```bash
python3 check_accounts.py
```

---

## Example Output

```text
========================================================================
          FREE FIRE BULK ACCOUNT BAN & STATUS CHECKER (OB55)           
========================================================================

[+] Loaded 2 accounts from accounts.json
[i] Checking accounts concurrently... please wait.

--------------------------------------------------------------------------------
GUEST UID       | INGAME UID      | REGION   | STATUS          | DETAILS
--------------------------------------------------------------------------------
7982138970      | 18397747738     | NA       | ACTIVE          | 
8192837461      | -               | -        | INVALID_CREDENTIALS | Wrong UID or Password
--------------------------------------------------------------------------------

SUMMARY: Total: 2 | Active: 1 | Banned: 0 | Invalid/Error: 1

[✓] Full results saved to: check_results.json
```

---

## License

MIT License. For educational and authorized account audit purposes only.
