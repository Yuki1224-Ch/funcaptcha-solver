#!/usr/bin/env python3
"""
Roblox Account Checker - Entry Point
=====================================
Run this script to start the checker.

Usage:
    python run_checker.py

    That's it! No CLI arguments needed.
    All settings are in roblox_checker/config.py:
      - Combo file: accounts.txt
      - Threads: 1
      - Proxies: disabled by default

Prerequisites:
    1. Start the funcaptcha-solver first:
       cd funcaptcha-solver && python main.py

    2. Put your accounts in accounts.txt (one per line, format: user:pass)

    3. (Optional) Add proxies to proxies.txt and enable in config.py

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