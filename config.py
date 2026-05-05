# Roblox Checker Configuration
# ==========================================

# Funcaptcha Solver API (runs locally from funcaptcha-solver)
CAPTCHA_SOLVER_URL = "http://127.0.0.1:8003"

# Roblox Login API
ROBLOX_LOGIN_URL = "https://auth.roblox.com/v2/login"
ROBLOX_AUTH_URL = "https://auth.roblox.com"

# Funcaptcha keys for Roblox (from funcaptcha-solver presets)
ROBLOX_LOGIN_SITEKEY = "476068BF-9607-4799-B53D-966BE98E2B81"
ROBLOX_LOGIN_SITEURL = "https://www.roblox.com"
ROBLOX_LOGIN_APIURL = "https://arkoselabs.roblox.com"

ROBLOX_REGISTER_SITEKEY = "A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F"

# Chrome version for fingerprinting
CHROME_VERSION = "130"

# Threading
MAX_THREADS = 1
MAX_CAPTCHA_RETRIES = 3

# Proxy settings
PROXY_ENABLED = False
PROXY_FILE = "proxies.txt"

# Combo file — put your user:pass accounts here
COMBO_FILE = "accounts.txt"
COMBO_DELIMITER = ":"

# Output files
HITS_FILE = "results/hits.txt"
INVALID_FILE = "results/invalid.txt"
TWOSTEP_FILE = "results/2step.txt"
CAPTCHA_FILE = "results/captcha_failed.txt"
ERROR_FILE = "results/errors.txt"
LOCKED_FILE = "results/locked.txt"
COOKIE_FILE = "results/cookies.txt"

# User Agent
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

# Request timeout (seconds)
REQUEST_TIMEOUT = 30

# Delay between checks (seconds)
CHECK_DELAY = 1.0