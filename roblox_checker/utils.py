"""
Utility Functions
=================
Combo file parsing, proxy loading, result saving, and display formatting.
"""

import os
import sys
import time
import threading
from datetime import datetime

import config


class Stats:
    """Thread-safe statistics tracker for the checker."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self.total = 0
        self.checked = 0
        self.hits = 0
        self.invalid = 0
        self.two_step = 0
        self.captcha_failed = 0
        self.locked = 0
        self.errors = 0
        self.cpm = 0
        self._cpm_checked = 0
        self._cpm_time = time.time()

    def increment(self, result_type):
        """Increment a specific result counter."""
        with self._lock:
            self.checked += 1
            if result_type == "HIT":
                self.hits += 1
            elif result_type == "INVALID":
                self.invalid += 1
            elif result_type == "2STEP":
                self.two_step += 1
            elif result_type == "CAPTCHA_FAILED":
                self.captcha_failed += 1
            elif result_type == "LOCKED":
                self.locked += 1
            elif result_type == "ERROR":
                self.errors += 1

    def update_cpm(self):
        """Update the checks-per-minute calculation."""
        with self._lock:
            now = time.time()
            elapsed = now - self._cpm_time
            if elapsed >= 15:
                checked_diff = self.checked - self._cpm_checked
                self.cpm = int((checked_diff / elapsed) * 60)
                self._cpm_checked = self.checked
                self._cpm_time = now

    def __str__(self):
        return (
            f"Checked: {self.checked}/{self.total} | "
            f"Hits: {self.hits} | "
            f"2FA: {self.two_step} | "
            f"Invalid: {self.invalid} | "
            f"Locked: {self.locked} | "
            f"Captcha Fail: {self.captcha_failed} | "
            f"Errors: {self.errors} | "
            f"CPM: {self.cpm}"
        )


class ComboParser:
    """Parses combo files with user:pass format."""

    def __init__(self, filepath=None, delimiter=None):
        self.filepath = filepath or config.COMBO_FILE
        self.delimiter = delimiter or config.COMBO_DELIMITER
        self._combos = []
        self._lock = threading.Lock()
        self._index = 0

    def load(self):
        """Load combos from the file. Returns the number of combos loaded."""
        if not os.path.exists(self.filepath):
            print(f"[!] Combo file not found: {self.filepath}")
            return 0

        count = 0
        with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                parts = line.split(self.delimiter, 1)
                if len(parts) == 2:
                    username = parts[0].strip()
                    password = parts[1].strip()
                    if username and password:
                        self._combos.append((username, password))
                        count += 1

        return count

    def get_next(self):
        """Get the next combo in a thread-safe manner. Returns None when exhausted."""
        with self._lock:
            if self._index >= len(self._combos):
                return None
            combo = self._combos[self._index]
            self._index += 1
            return combo

    @property
    def total(self):
        return len(self._combos)

    @property
    def remaining(self):
        with self._lock:
            return len(self._combos) - self._index


class ProxyManager:
    """Manages proxy loading and rotation."""

    def __init__(self, filepath=None):
        self.filepath = filepath or config.PROXY_FILE
        self._proxies = []
        self._lock = threading.Lock()
        self._index = 0

    def load(self):
        """Load proxies from file. Returns the number of proxies loaded."""
        if not os.path.exists(self.filepath):
            return 0

        count = 0
        with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Support various proxy formats:
                # host:port
                # host:port:user:pass
                # user:pass@host:port
                # http://host:port
                # http://user:pass@host:port
                proxy = self._format_proxy(line)
                if proxy:
                    self._proxies.append(proxy)
                    count += 1

        return count

    def _format_proxy(self, proxy_str):
        """Format a proxy string into a proper URL."""
        proxy_str = proxy_str.strip()

        # Already has protocol
        if proxy_str.startswith(("http://", "https://", "socks4://", "socks5://")):
            return proxy_str

        # user:pass@host:port format
        if "@" in proxy_str:
            auth, host_port = proxy_str.rsplit("@", 1)
            return f"http://{auth}@{host_port}"

        # host:port:user:pass format
        parts = proxy_str.split(":")
        if len(parts) == 4:
            host, port, user, pwd = parts
            return f"http://{user}:{pwd}@{host}:{port}"
        elif len(parts) == 2:
            host, port = parts
            return f"http://{host}:{port}"

        return None

    def get_next(self):
        """Get the next proxy in rotation. Returns None if no proxies."""
        if not self._proxies:
            return None

        with self._lock:
            proxy = self._proxies[self._index % len(self._proxies)]
            self._index += 1
            return proxy

    @property
    def count(self):
        return len(self._proxies)


class ResultSaver:
    """Thread-safe file writer for categorizing checker results."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ensure_dirs()

    def _ensure_dirs(self):
        """Create the results directory if it doesn't exist."""
        os.makedirs("results", exist_ok=True)

    def save_hit(self, username, password, cookie=None, user_id=None,
                 display_name=None, robux=0, premium=False):
        """Save a successful login hit."""
        with self._lock:
            with open(config.HITS_FILE, "a", encoding="utf-8") as f:
                f.write(f"{username}:{password}")
                if cookie:
                    f.write(f" | Cookie: {cookie}")
                if user_id:
                    f.write(f" | UserID: {user_id}")
                if display_name:
                    f.write(f" | DisplayName: {display_name}")
                if robux > 0:
                    f.write(f" | Robux: {robux}")
                if premium:
                    f.write(f" | Premium: Yes")
                f.write("\n")

            # Also save the cookie separately for easy use
            if cookie:
                with open(config.COOKIE_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{username} | {cookie}\n")

    def save_invalid(self, username, password, error=None):
        """Save an invalid credential result."""
        with self._lock:
            with open(config.INVALID_FILE, "a", encoding="utf-8") as f:
                f.write(f"{username}:{password}")
                if error:
                    f.write(f" | {error}")
                f.write("\n")

    def save_two_step(self, username, password, challenge_id=None):
        """Save a 2FA-required result."""
        with self._lock:
            with open(config.TWOSTEP_FILE, "a", encoding="utf-8") as f:
                f.write(f"{username}:{password}")
                if challenge_id:
                    f.write(f" | ChallengeID: {challenge_id}")
                f.write("\n")

    def save_captcha_failed(self, username, password, captcha_id=None, error=None):
        """Save a captcha-failed result."""
        with self._lock:
            with open(config.CAPTCHA_FILE, "a", encoding="utf-8") as f:
                f.write(f"{username}:{password}")
                if captcha_id:
                    f.write(f" | CaptchaID: {captcha_id}")
                if error:
                    f.write(f" | {error}")
                f.write("\n")

    def save_locked(self, username, password, error=None):
        """Save a locked/banned account result."""
        with self._lock:
            with open(config.LOCKED_FILE, "a", encoding="utf-8") as f:
                f.write(f"{username}:{password}")
                if error:
                    f.write(f" | {error}")
                f.write("\n")

    def save_error(self, username, password, error=None):
        """Save an error result."""
        with self._lock:
            with open(config.ERROR_FILE, "a", encoding="utf-8") as f:
                f.write(f"{username}:{password}")
                if error:
                    f.write(f" | {error}")
                f.write("\n")


class Display:
    """Console display with colored output for the checker."""

    # ANSI color codes
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    # Color mapping for result types
    RESULT_COLORS = {
        "HIT": GREEN,
        "INVALID": RED,
        "2STEP": MAGENTA,
        "CAPTCHA_FAILED": YELLOW,
        "LOCKED": CYAN,
        "ERROR": GRAY,
    }

    @staticmethod
    def clear():
        """Clear the console."""
        os.system("cls" if os.name == "nt" else "clear")

    @classmethod
    def print_banner(cls):
        """Print the checker banner."""
        banner = f"""
{cls.CYAN}{cls.BOLD}╔══════════════════════════════════════════════════════════╗
║           {cls.WHITE}ROBLOX ACCOUNT CHECKER{cls.CYAN}                           ║
║           {cls.GRAY}Powered by Funcaptcha Solver{cls.CYAN}                      ║
╠══════════════════════════════════════════════════════════╣
║  {cls.GREEN}✓{cls.CYAN} Combo format: user:pass                              ║
║  {cls.GREEN}✓{cls.CYAN} API: auth.roblox.com/v2/login                         ║
║  {cls.GREEN}✓{cls.CYAN} Captcha: Arkose Labs Funcaptcha                       ║
║  {cls.GREEN}✓{cls.CYAN} Captcha Solver: Local funcaptcha-solver API            ║
╚══════════════════════════════════════════════════════════╝{cls.RESET}
"""
        print(banner)

    @classmethod
    def print_result(cls, result):
        """Print a colorized result to the console."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = cls.RESULT_COLORS.get(result.result_type, cls.WHITE)
        tag = result.result_type.ljust(14)

        line = f"{cls.GRAY}[{timestamp}]{cls.RESET} {color}[{tag}]{cls.RESET} {result.username}:{result.password}"

        if result.result_type == "HIT":
            if result.display_name:
                line += f" {cls.GREEN}| Name: {result.display_name}{cls.RESET}"
            if result.user_id:
                line += f" {cls.GREEN}| ID: {result.user_id}{cls.RESET}"
            if result.cookie:
                line += f" {cls.GREEN}| Cookie: {result.cookie[:40]}...{cls.RESET}"
        elif result.result_type == "2STEP":
            if result.challenge_id:
                line += f" {cls.MAGENTA}| ChallengeID: {result.challenge_id}{cls.RESET}"
        elif result.result_type in ("CAPTCHA_FAILED", "ERROR"):
            if result.error_message:
                line += f" {cls.YELLOW}| {result.error_message}{cls.RESET}"

        print(line)

    @classmethod
    def print_stats(cls, stats, elapsed):
        """Print the current statistics bar."""
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        line = (
            f"\r{cls.CYAN}{cls.BOLD}[STATS]{cls.RESET} "
            f"{cls.WHITE}Checked: {stats.checked}/{stats.total}{cls.RESET} | "
            f"{cls.GREEN}Hits: {stats.hits}{cls.RESET} | "
            f"{cls.MAGENTA}2FA: {stats.two_step}{cls.RESET} | "
            f"{cls.RED}Invalid: {stats.invalid}{cls.RESET} | "
            f"{cls.CYAN}Locked: {stats.locked}{cls.RESET} | "
            f"{cls.YELLOW}CapFail: {stats.captcha_failed}{cls.RESET} | "
            f"{cls.GRAY}Errors: {stats.errors}{cls.RESET} | "
            f"{cls.BLUE}CPM: {stats.cpm}{cls.RESET} | "
            f"{cls.WHITE}Time: {elapsed_str}{cls.RESET}"
        )
        print(line, end="", flush=True)

    @classmethod
    def info(cls, message):
        """Print an info message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{cls.GRAY}[{timestamp}]{cls.BLUE}[*]{cls.RESET} {message}")

    @classmethod
    def success(cls, message):
        """Print a success message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{cls.GRAY}[{timestamp}]{cls.GREEN}[✓]{cls.RESET} {message}")

    @classmethod
    def warning(cls, message):
        """Print a warning message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{cls.GRAY}[{timestamp}]{cls.YELLOW}[!]{cls.RESET} {message}")

    @classmethod
    def error(cls, message):
        """Print an error message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{cls.GRAY}[{timestamp}]{cls.RED}[✗]{cls.RESET} {message}")