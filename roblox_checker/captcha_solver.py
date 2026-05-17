"""
Funcaptcha Solver Client
========================
Communicates with the local funcaptcha-solver API to solve
Arkose Labs (Funcaptcha) challenges for Roblox login.
"""

import time
import requests
from . import config


class CaptchaSolver:
    """Client for the funcaptcha-solver Flask API."""

    def __init__(self, solver_url=None):
        self.solver_url = solver_url or config.CAPTCHA_SOLVER_URL
        self.session = requests.Session()

    def solve_roblox_login(self, blob=None, proxy=None):
        """
        Solve a Roblox login funcaptcha challenge.

        Args:
            blob: The dxBlob data from the Roblox login challenge response.
                  If None, the solver will attempt without blob data.
            proxy: Optional proxy string (e.g., "http://user:pass@host:port")

        Returns:
            dict with 'success', 'token', 'error' keys
        """
        task_payload = {
            "preset": "roblox_login",
            "chrome_version": config.CHROME_VERSION,
        }

        if blob:
            task_payload["blob"] = blob

        if proxy:
            task_payload["proxy"] = proxy

        try:
            # Create the captcha solving task
            create_resp = self.session.post(
                f"{self.solver_url}/funcaptcha/createTask",
                json=task_payload,
                timeout=30,
            )
            create_data = create_resp.json()

            if not create_data.get("success"):
                return {
                    "success": False,
                    "token": None,
                    "error": f"Failed to create task: {create_data.get('err', 'unknown')}",
                }

            task_id = create_data["task_id"]

            # Poll for the result
            max_wait = 120  # 2 minutes max
            start_time = time.time()

            while time.time() - start_time < max_wait:
                get_resp = self.session.post(
                    f"{self.solver_url}/funcaptcha/getTask",
                    json={"task_id": task_id},
                    timeout=30,
                )
                result = get_resp.json()

                if result.get("status") == "completed":
                    captcha_data = result.get("captcha", {})
                    if captcha_data.get("success"):
                        return {
                            "success": True,
                            "token": captcha_data.get("token"),
                            "error": None,
                            "solve_time": captcha_data.get("procces_time"),
                        }
                    else:
                        return {
                            "success": False,
                            "token": None,
                            "error": f"Captcha solve failed: {captcha_data.get('err', 'unknown')}",
                        }

                # Still processing, wait and retry
                time.sleep(2)

            return {
                "success": False,
                "token": None,
                "error": "Captcha solve timed out",
            }

        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "token": None,
                "error": "Cannot connect to captcha solver. Is it running on port 8003?",
            }
        except Exception as e:
            return {
                "success": False,
                "token": None,
                "error": f"Captcha solver error: {str(e)}",
            }

    def is_solver_running(self):
        """Check if the funcaptcha-solver API is reachable."""
        try:
            resp = self.session.get(f"{self.solver_url}/", timeout=5)
            return True
        except Exception:
            return False