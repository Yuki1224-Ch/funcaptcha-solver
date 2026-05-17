#!/usr/bin/env python3
"""
Roblox Account Checker - Entry Point
=====================================
Run this script to start the checker.

Usage:
    python run_checker.py [OPTIONS]

    Options:
      -c, --combo       Combo file path (default: combo.txt)
      -p, --proxies     Proxy file path (default: proxies.txt)
      -t, --threads     Number of threads (default: 5)
      --captcha-url     Captcha solver URL (default: http://127.0.0.1:8003)
      --use-proxies     Enable proxy usage
      --no-proxies      Disable proxy usage
      --delay           Delay between checks in seconds (default: 1.0)

    Defaults can be changed in roblox_checker/config.py.

Prerequisites:
    1. Start the funcaptcha-solver first:
       cd funcaptcha-solver && python main.py

    2. Put your accounts in combo.txt (one per line, format: user:pass)
       Lines starting with # are treated as comments and skipped.

    3. (Optional) Add proxies to proxies.txt and enable with --use-proxies

    4. Run this script:
       python run_checker.py
"""

import sys
import os

# Add the roblox_checker package to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from roblox_checker.checker import main

if __name__ == "__main__":
    main()