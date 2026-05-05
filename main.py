from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from curl_cffi import requests as requests2
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request
from colorama import Fore as f
from colorama import Fore as b
from Crypto.Cipher import AES
from datetime import datetime
from io import BytesIO

import contextlib
import traceback
import threading
import binascii
import secrets
import hashlib
import logging
import string
import random
import struct
import urllib.parse
import base64
import execjs
import colr
import json
import uuid
import time
import sys
import os

# --- Node.js bridge setup with graceful fallback ---
# The `javascript` package (JSPyBridge) requires Node.js >= 16 to be installed
# and accessible on the system PATH. On Windows, Node.js may not be found
# automatically if installed via the Microsoft Store or in a non-standard location.
# We handle the import gracefully so the user gets a clear error message
# instead of a cryptic crash.

_jsdom = None
_create_script = None
_js_bridge_available = False

def _find_node_path():
    """Attempt to locate the Node.js executable on Windows."""
    if sys.platform != 'win32':
        return None  # On non-Windows, rely on standard PATH resolution

    # Common Node.js install locations on Windows
    possible_paths = [
        os.path.join(os.environ.get('PROGRAMFILES', ''), 'nodejs', 'node.exe'),
        os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'nodejs', 'node.exe'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'nodejs', 'node.exe'),
        os.path.join(os.environ.get('APPDATA', ''), 'nvm', 'v22.12.0', 'node.exe'),
    ]

    # Also try to find node via common version dirs in nvm
    nvm_home = os.environ.get('NVM_HOME', '')
    if nvm_home and os.path.isdir(nvm_home):
        try:
            for entry in os.listdir(nvm_home):
                node_exe = os.path.join(nvm_home, entry, 'node.exe')
                if os.path.isfile(node_exe):
                    possible_paths.append(node_exe)
        except OSError:
            pass

    for path in possible_paths:
        if path and os.path.isfile(path):
            return path

    return None

def _check_node_available():
    """Check if Node.js is available and meets the minimum version requirement."""
    import subprocess
    try:
        result = subprocess.run(
            ['node', '--version'],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            version_str = result.stdout.strip().lstrip('v')
            major = int(version_str.split('.')[0])
            return major >= 16, version_str
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Try finding node manually on Windows
    if sys.platform == 'win32':
        node_path = _find_node_path()
        if node_path:
            try:
                result = subprocess.run(
                    [node_path, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    version_str = result.stdout.strip().lstrip('v')
                    major = int(version_str.split('.')[0])
                    if major >= 16:
                        # Add node's directory to PATH so JSPyBridge can find it
                        node_dir = os.path.dirname(node_path)
                        os.environ['PATH'] = node_dir + os.pathsep + os.environ.get('PATH', '')
                        return True, version_str
            except Exception:
                pass

    return False, None

def _init_js_bridge():
    """Initialize the JSPyBridge (javascript package) connection to Node.js.

    This is called lazily when jsdom/create_script are first needed,
    rather than at module import time, so that the application can at
    least start up and provide a helpful error if Node.js is missing.
    """
    global _jsdom, _create_script, _js_bridge_available

    if _js_bridge_available:
        return True

    # First check that Node.js is present and new enough
    node_ok, node_version = _check_node_available()
    if not node_ok:
        print("\n" + "=" * 60)
        print("  ERROR: Node.js 16+ is required but was not found!")
        print("=" * 60)
        print()
        print("  The funcaptcha-solver needs Node.js (v16 or newer) to run")
        print("  the JavaScript bridge (JSPyBridge) for tguess generation.")
        print()
        print("  Please install Node.js from: https://nodejs.org/")
        print()
        print("  After installing Node.js:")
        print("    1. Restart your terminal / command prompt")
        print("    2. Verify:  node --version")
        print("    3. Install npm deps:  npm install jsdom")
        print("    4. Run this script again")
        print()
        if sys.platform == 'win32':
            print("  NOTE for Windows users:")
            print("    - If you installed Node.js via the Microsoft Store,")
            print("      it may not be on your PATH. Try installing from")
            print("      https://nodejs.org/ instead.")
            print("    - You may need to log out and log back in after")
            print("      installing Node.js for PATH changes to take effect.")
        print("=" * 60)
        print()
        _js_bridge_available = False
        return False

    # Node.js is available; now try importing the javascript bridge
    try:
        from javascript import require as _require
        _jsdom = _require('jsdom')
        _create_script = _require("vm").Script
        _js_bridge_available = True
        return True
    except Exception as e:
        print(f"\n  WARNING: Failed to initialize Node.js bridge: {e}")
        print("  The tguess (dapib) functionality will be unavailable.")
        print("  Make sure you have installed npm dependencies:")
        print("    npm install jsdom")
        print()
        _js_bridge_available = False
        return False

def get_jsdom():
    """Get the jsdom module, initializing the JS bridge if needed."""
    if _jsdom is None:
        _init_js_bridge()
    return _jsdom

def get_create_script():
    """Get the vm.Script constructor, initializing the JS bridge if needed."""
    if _create_script is None:
        _init_js_bridge()
    return _create_script

def is_js_bridge_available():
    """Check whether the Node.js bridge (used for tguess) is available."""
    return _js_bridge_available

# --- End Node.js bridge setup ---

logging.getLogger('werkzeug').setLevel(logging.ERROR)
with open("webgl.json") as file:
    webgls=json.loads(file.read())
with open("arkose.js") as file:
    gctx = execjs.compile(file.read())

class Utils:
    solved=0
    fail=0
    spm=0
    errors=0
    supc=0
    xxsupc=0

    @contextlib.contextmanager
    def suppress_output():
        with open(os.devnull, 'w') as devnull:
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            try:
                sys.stdout = devnull
                sys.stderr = devnull
                yield
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

    @staticmethod
    def find(data, value) -> str:
        for item in data:
            if item["key"]==value:
                return item["value"]

    @staticmethod
    def newrelic_time() -> str:
        ms = str(int(time.time() * 1000))
        return ms[:7] + "00" + ms[7:13]

    @staticmethod
    def hex(data: str) -> str:
        return ''.join(f'{byte:02x}' for byte in data)

    @staticmethod
    def convert_salt(words: list, sig_bytes: list) -> list:
        salt = b''
        for word in words:
            salt += struct.pack('>I', word & 0xFFFFFFFF)
        return salt[:sig_bytes]

    @staticmethod
    def randsalt(ctx) -> list:
        return ctx.call(
            'randsigbyte',
            8,
        )

    @staticmethod
    def int_to_bytes(n: str, length: int) -> bytes:
        return n.to_bytes(length, byteorder='big', signed=True)

    @staticmethod
    def to_sigbytes(words: list, sigBytes: int) -> list:
        result = b''.join(Utils.int_to_bytes(word, 4) for word in words)
        return result[:sigBytes]

    @staticmethod
    def bytes_to_buffer(data: bytes) -> list:
        buffer=BytesIO(data)
        buffer.seek(0)
        content = buffer.read()
        return list(content)

    @staticmethod
    def random_integer(value: int) -> int:
        max_random_value = (2**32 // value) * value
        while True:
            a = secrets.randbelow(2**32)
            if a < max_random_value:
                return a % value

    @staticmethod
    def dict_to_list(data: dict) -> list:
        result=[]
        for obj in data:
            result.append(data[obj])

        return result

    @staticmethod
    def uint8_array(size: int) -> list:
        v = bytearray(size)
        for i in range(len(v)):
            v[i] = Utils.random_integer(256)
        return Utils.bytes_to_buffer(v)

    @staticmethod
    def convert_key_to_sigbytes_format(key: bytes) -> list:
        key_words = []
        for i in range(0, len(key), 4):
            word = struct.unpack('>i', key[i:i+4])[0]
            key_words.append(word)
        return key_words

    @staticmethod
    def get_coords(num:int) -> tuple:
        map={
            1: [0,0,100,100],
            2: [100,0,200,100],
            3: [200,0,300,100],
            4: [0,100,100,200],
            5: [100,100,200,200],
            6: [200,100,300,200]
        }

        x1,y1,x2,y2=map[num]
        x = (x1 + x2) / 2
        y = (y1 + y2) / 2

        if random.randint(0,1):
            x+=random.uniform(10.00001,45.99999)
        else:
            x-=random.uniform(10.00001,45.99999)

        if random.randint(0,1):
            y+=random.randint(0,45)
        else:
            y-=random.randint(0,45)

        return (float(x), int(y))

    @staticmethod
    def grid_answer_dict(answer):
        x,y=Utils.get_coords(answer)

        return {
            "px": str(round((x / 300),2)),
            "py": str(round((y / 200),2)),
            "x": x,
            "y": y
        }

class Arkose:
    @staticmethod
    def decrypt_data(data, main):
        ciphertext = base64.b64decode(data['ct'])
        iv_bytes = binascii.unhexlify(data['iv'])
        salt_bytes = binascii.unhexlify(data['s'])
        salt_words = Arkose.from_sigbytes(salt_bytes)
        key_words = Arkose.generate_other_key(main, salt_words)
        key_bytes = Utils.to_sigbytes(key_words, 32)
        iv_bytes = Utils.to_sigbytes(key_words[-4:], 16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    @staticmethod
    def from_sigbytes(sigBytes: bytes) -> list:
        padded_length = (len(sigBytes) + 3) // 4 * 4
        padded_bytes = sigBytes.ljust(padded_length, b'\0')
        
        words = [int.from_bytes(padded_bytes[i:i+4], byteorder='big') for i in range(0, len(padded_bytes), 4)]
        return words

    @staticmethod
    def encrypt_double(self, main: str, extra: str) -> str:
        salt_words=Utils.randsalt(gctx)
        key_words= Arkose.generate_other_key(main, salt_words)
        key_bytes = Utils.to_sigbytes(key_words, 32)
        iv_bytes = Utils.to_sigbytes(key_words[-4:], 16)
        salt_bytes= Utils.to_sigbytes(salt_words, 8)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        ciphertext = cipher.encrypt(pad(extra.encode('utf-8'), AES.block_size))
  
        return json.dumps({
            "ct":base64.b64encode(ciphertext).decode(),
            "iv":Utils.hex(iv_bytes),
            "s": Utils.hex(salt_bytes)
        }).replace(" ","")

    def is_flagged(data):
        if not data or not isinstance(data, list):
            return False
        values = [value for d in data for value in d.values()]
        if not values:
            return False
        def ends_with_uppercase(value):
            return value and value[-1] in string.ascii_uppercase

        return all(ends_with_uppercase(value) for value in values)

    @staticmethod
    def t_guess(self, session_token:str, guesses:list, dapibCode:str) -> str:
        if not is_js_bridge_available():
            if not _init_js_bridge():
                logger.print("tguess skipped - Node.js bridge not available", f.RED + "Install Node.js 16+ and run: npm install jsdom")
                return None

        _jsdom_local = get_jsdom()
        _create_script_local = get_create_script()

        if _jsdom_local is None or _create_script_local is None:
            logger.print("tguess skipped - jsdom/vm not available", f.RED + "Install Node.js 16+ and run: npm install jsdom")
            return None

        sess,ion=session_token.split(".")
        answers=[]
        for guess in guesses:
            if "index" in str(guesses):
                answers.append({"index": json.loads(guess)["index"], sess:ion,})
            else:
                guess=json.loads(guess)
                answers.append({"px": guess['px'] ,"py": guess['py'], "x": guess['x'], "y": guess['y'], sess:ion})

        resource_loader = _jsdom_local.ResourceLoader({"userAgent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.chrome_version}.0.0.0 Safari/537.36"})
        vm = _jsdom_local.JSDOM("", {
            "runScripts": "dangerously",
            "resources": resource_loader,
            "pretendToBeVisual": True,
            "storageQuota": 10000000
        }).getInternalVMContext()

        _create_script_local("""
        response=null;

        window.parent.ae={"answer":answers}

        window.parent.ae[("dapibRecei" + "ve")]=function(data) {
        response=JSON.stringify(data);
        }
        """.replace("answers",json.dumps(answers).replace('"index"','index'))).runInContext(vm)

        _create_script_local(dapibCode).runInContext(vm)
        result=json.loads(_create_script_local("response").runInContext(vm))

        if Arkose.is_flagged(result["tanswer"]):
            for array in result["tanswer"]:
                for item in array:
                    array[item]=array[item][:-1]

        return Arkose.encrypt_double(self, session_token, json.dumps(result["tanswer"]).replace(" ",""))

    @staticmethod
    def generate_key_(password: str, salt: bytes, key_size: int, iterations: int) -> bytes:
        hasher = hashlib.md5()
        key = b''
        block = None
        
        while len(key) < key_size:
            if block:
                hasher.update(block)
            hasher.update(password.encode())
            hasher.update(salt)
            block = hasher.digest()
            hasher = hashlib.md5()
            
            for _ in range(1, iterations):
                hasher.update(block)
                block = hasher.digest()
                hasher = hashlib.md5()
            
            key += block
        
        return key[:key_size]

    @staticmethod
    def generate_other_key(data: str, salt: list) -> list:
        sig_bytes = 8
        key_size = 48
        iterations = 1
        salt = Utils.convert_salt(salt, sig_bytes)
        key = Arkose.generate_key_(data, salt, key_size, iterations)

        return Utils.convert_key_to_sigbytes_format(key)

    @staticmethod
    def encrypt_ct(text: bytes, key: bytes, iv: bytes) -> bytes:
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plain_text = padder.update(text) + padder.finalize()
        cipher_text = encryptor.update(padded_plain_text) + encryptor.finalize()
        return cipher_text

    @staticmethod
    def generate_key(ctx:execjs.compile, s_value:str, useragent:str) -> list:
        key=Utils.dict_to_list(ctx.call(
            'genkey',
            useragent,
            s_value
        ))
        return key

    @staticmethod
    def make_encrypted_dict(self, data:str) -> str:
        s_value=Utils.hex(Utils.uint8_array(8))
        iv_value=Utils.uint8_array(16)
        key=Arkose.generate_key(
            gctx, 
            s_value,
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.chrome_version}.0.0.0 Safari/537.36{self.x_ark_value}"
        )

        result=Arkose.encrypt_ct(
            text=bytes(data.encode()),
            key=bytes(key),
            iv=bytes(iv_value)
        )

        return json.dumps({
            "ct":base64.b64encode(result).decode(),
            "s":s_value,
            "iv":Utils.hex(iv_value)
        }).replace(" ","")

    @staticmethod
    def x_ark_value() -> str:
        now=int(time.time())
        return str(now - (now % 21600))
    
    @staticmethod
    def generate_pt():
        start_time = time.time()  
        time.sleep(random.uniform(0.04,0.07))         
        end_time = time.time()    
        
        pt = end_time - start_time 
        return pt

    @staticmethod
    def generate_aht(num_trials=random.randint(1,7)):
        total_time = 0
        
        for _ in range(num_trials):
            pt = Arkose.generate_pt()
            total_time += pt
        
        aht = total_time / num_trials
        return aht

    @staticmethod
    def generate_cs():
        return uuid.uuid4().hex[:10]

    @staticmethod
    def generate_g():
        return uuid.uuid4().hex[:12]

    @staticmethod
    def generate_h(cs, g):
        data_to_hash = cs + g
        h = hashlib.sha256(data_to_hash.encode()).hexdigest()
        return h

class logger:
    colors_table = {
        "green":"#65fb07",
        "red":"#Fb0707",
        "yellow":"#c4bc18",
        "magenta":"#b207f5",
        "blue":"#001aff",
        "cyan":"#07baf5",
        "gray":"#3a3d40", 
        "white":"#ffffff",
        "pink":"#c203fc",
        "light_blue":"#07f0ec",
        "orange":"#FFA200",
        "purple": "#4500d0"
    }

    def convert(color):
        if not color.__contains__("#"):
            return logger.colors_table[color]
        else:
            return color

    def color(c, obj):
        return colr.Colr().hex(logger.convert(c), obj)
    
    def print(*args:str) -> None:
        date=datetime.now().strftime(f'%H:%M:%S')
        print(f"{logger.color('white',date)} {f.BLUE}| {b.BLUE}{logger.color('purple','Funcaptcha')}{b.RESET} | {' | '.join(args)}".replace("|",f"{f.LIGHTBLACK_EX}|{f.WHITE}"))

class Funcaptcha:
    def __init__(self, apiurl, siteurl, sitekey, chrome_version, data, blob, custom_cookies, custom_locale, proxy=None) -> None:
        self.siteurl=siteurl
        self.sitekey=sitekey
        self.apiurl=apiurl
        self.blob=blob
        self.chrome_version=chrome_version
        self.useragent=f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.chrome_version}.0.0.0 Safari/537.36"
        self.session=requests2.Session(
            impersonate="chrome131",
            default_headers=False,
            verify=False,
        )

        if custom_cookies:
            self.session.cookies.update(custom_cookies)

        if custom_locale:
            self.locale=custom_locale
        else:
            self.locale="sv-SE"

        self.proxy = proxy
        if proxy:
            self.session.proxies={"https":proxy}

        self.x_ark_value=Arkose.x_ark_value()

        apijs_resp=self.session.get(f"{self.apiurl}/v2/{self.sitekey}/api.js",headers={
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': f'{self.locale},{self.locale.split("-")[0]};q=0.9,en-US;q=0.8,en;q=0.7',
            'connection': 'keep-alive',
            'host': self.apiurl.split('https://')[1],
            'sec-ch-ua': f'"Not)A;Brand";v="99", "Google Chrome";v="{self.chrome_version}", "Chromium";v="{self.chrome_version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'script',
            'sec-fetch-mode': 'no-cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.useragent,
        })
        self.cfuvid_cookie = ""
        cfuvid = apijs_resp.cookies.get('_cfuvid')
        if cfuvid:
            self.cfuvid_cookie = f"_cfuvid={cfuvid.split(';')[0]}"
        captchadata = apijs_resp.text.split("/enforcement.")

        self.capi_version=captchadata[0].split('"')[-1]
        self.enforcement_hash=captchadata[1].split('.html')[0]
        self.window__ancestor_origins=data["window__ancestor_origins"]
        self.window__tree_index=data["window__tree_index"]
        self.client_config__sitedata_location_href=data["client_config__sitedata_location_href"]
        self.window__tree_structure=data["window__tree_structure"]
            
        self.session.headers={
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": f"{self.locale},{self.locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Connection": "keep-alive",
            "Host": self.apiurl.split('https://')[1],
            "Referer": f"{self.apiurl}/v2/{self.capi_version}/enforcement.{self.enforcement_hash}.html",
            "sec-ch-ua": f"\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"{self.chrome_version}\", \"Chromium\";v=\"{self.chrome_version}\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.chrome_version}.0.0.0 Safari/537.36",
            "x-ark-esync-value": self.x_ark_value
        }

    def make_mm(self):
        x=random.randint(100,150)
        y=random.randint(30,90)
        
        return base64.b64encode(json.dumps({
            "mbio":f"38{random.randint(10,70)},0,{x},{y};38{random.randint(80,90)},1,{x},{y};38{random.randint(92,99)},2,{x},{y};",
            "tbio":f"34{random.randint(10,99)},0,{x},{y};",
            "kbio":""
        }).replace(" ","").encode()).decode()

    def answer(self, result, answers, i):
        data={
            'session_token': self.session_token,
            'game_token': self.gameid,
            'sid': self.r_continent,
            'guess': result,
            'render_type': 'canvas',
            'analytics_tier': '40',
            'bio': self.make_mm(),
            'is_compatibility_mode': 'false',
        }

        if self.dapibCode:
            tguess_result = Arkose.t_guess(self, self.session_token, answers, self.dapibCode)
            if tguess_result is not None:
                data['tguess'] = tguess_result
            else:
                logger.print("Proceeding without tguess - solve may fail", f.YELLOW + "Node.js bridge unavailable")

        response = self.session.post(f'{self.apiurl}/fc/ca/', data=data,headers={
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": f"{self.locale},{self.locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Host": self.apiurl.split("https://")[1],
            "Origin": self.apiurl,
            "Referer": f"{self.apiurl}/fc/assets/ec-game-core/game-core/{self.gc_version}/standard/index.html?session={self.token}&r={self.r_continent}&meta=3&meta_width=300&metabgclr=transparent&metaiconclr=%23555555&guitextcolor=%23000000&pk={self.sitekey}&dc=1&at=40&ag=101&cdn_url=https%3A%2F%2F{self.apiurl.split('https://')[1]}%2Fcdn%2Ffc&lurl=https%3A%2F%2Faudio-{self.r_continent}.arkoselabs.com&surl=https%3A%2F%2F{self.apiurl.split('https://')[1]}&smurl=https%3A%2F%2F{self.apiurl.split('https://')[1]}%2Fcdn%2Ffc%2Fassets%2Fstyle-manager&theme=default",
            "sec-ch-ua": f"\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"{self.chrome_version}\", \"Chromium\";v=\"{self.chrome_version}\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.chrome_version}.0.0.0 Safari/537.36",
            "X-NewRelic-Timestamp": Utils.newrelic_time(),
            "X-Requested-ID": Arkose.encrypt_double(self, f"REQUESTED{self.token}ID",json.dumps({"sc":[
                random.randint(100,300),
                random.randint(100,300)
            ]}).replace(" ","")),
            "X-Requested-With": "XMLHttpRequest"
        })
        return response.json()

    def _make_cookie_header(self, timestamp=None):
        parts = []
        if self.cfuvid_cookie:
            parts.append(self.cfuvid_cookie)
        if timestamp:
            parts.append(f"timestamp={timestamp}")
        return "; ".join(parts)

    def callback(self, data, cookies=None):
        self.session.post(f"{self.apiurl}/fc/a/", data=data, cookies=cookies)

    def solve(self):
        try:
            self.solve_time=time.time()
            challenge_data=self._generate_challenge()
            if "DENIED ACCESS" in str(challenge_data):
                return {"success":False, "err": f"gfct error: DENIED ACCESS", "token": None}

            # Extract game-core version from challenge response
            self.gc_version = "1.22.0"
            cdn_url = challenge_data.get("challenge_url_cdn", "")
            if "/bootstrap/" in cdn_url:
                self.gc_version = cdn_url.split("/bootstrap/")[1].split("/")[0]

            self.token=challenge_data["token"].split("|")[0]
            self.r_continent=challenge_data["token"].split("|r=")[1].split("|")[0]

            # Parse additional token fields
            raw_token = challenge_data["token"]
            self.at = raw_token.split("|at=")[1].split("|")[0] if "|at=" in raw_token else "40"
            self.ag = raw_token.split("|ag=")[1].split("|")[0] if "|ag=" in raw_token else "101"
            token_cdn = urllib.parse.unquote(raw_token.split("|cdn_url=")[1].split("|")[0]) if "|cdn_url=" in raw_token else f"{self.apiurl}/cdn/fc"
            token_surl = urllib.parse.unquote(raw_token.split("|surl=")[1].split("|")[0]) if "|surl=" in raw_token else self.apiurl
            token_smurl = urllib.parse.unquote(raw_token.split("|smurl=")[1].split("|")[0]) if "|smurl=" in raw_token else f"{self.apiurl}/cdn/fc/assets/style-manager"

            if "sup=1|" in challenge_data["token"]:
                # Suppressed token: init-load → game loaded → return
                self.session.headers = {
                    "accept": "*/*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": f"{self.locale},{self.locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7",
                    "connection": "keep-alive",
                    "host": self.apiurl.split('https://')[1],
                    "referer": f"{self.apiurl}/v2/{self.capi_version}/enforcement.{self.enforcement_hash}.html",
                    "sec-ch-ua": f"\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"{self.chrome_version}\", \"Chromium\";v=\"{self.chrome_version}\"",
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "\"Windows\"",
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-origin",
                    "user-agent": self.useragent,
                }
                init_ts = Arkose.x_ark_value()
                self.session.get(f'{self.apiurl}/fc/init-load/', params={'session_token': self.token}, cookies={**dict(self.session.cookies), "timestamp": init_ts})

                self.session.headers.update({
                    "sec-fetch-dest": "script",
                    "sec-fetch-mode": "no-cors",
                    "sec-fetch-site": "same-origin",
                })
                self.session.get(
                    f"{self.apiurl}/fc/a/",
                    params={
                        "callback": f"__jsonp_{str(int(time.time()*1000))}",
                        "category": "loaded",
                        "action": "game loaded",
                        "session_token": self.token,
                        "data[public_key]": self.sitekey,
                        "data[site]": self.siteurl
                    }
                )
                logger.print("Suppressed", "Waves: 0", f.LIGHTGREEN_EX+self.token)
                Utils.solved+=1
                Utils.supc+=1
                
                return {"success":True, "err": None, "token": challenge_data["token"], "procces_time": time.time()-self.solve_time}
            
            Utils.xxsupc+=1

            # Step 1: Load game-core index.html to get referer URL
            self.session.headers = {
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": f"{self.locale},{self.locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7",
                "connection": "keep-alive",
                "host": self.apiurl.split('https://')[1],
                "referer": f"{self.apiurl}/v2/{self.capi_version}/enforcement.{self.enforcement_hash}.html",
                "sec-ch-ua": f"\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"{self.chrome_version}\", \"Chromium\";v=\"{self.chrome_version}\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "iframe",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "same-origin",
                "upgrade-insecure-requests": "1",
                "user-agent": self.useragent,
            }
            referer=self.session.get(
                f'{self.apiurl}/fc/assets/ec-game-core/game-core/{self.gc_version}/standard/index.html',
                params={
                    'session': self.token,
                    'r': self.r_continent,
                    'lang': self.locale.split("-")[0],
                    'pk': self.sitekey,
                    'at': self.at,
                    'ag': self.ag,
                    'cdn_url': token_cdn,
                    'surl': token_surl,
                    'smurl': token_smurl,
                    'theme': 'default'
            }).url

            # Step 2: Arkose PoW (if enabled)
            if challenge_data.get("pow"):
                pow_resp = self.session.get(
                    f'{self.apiurl}/pows/setup',
                    params={'session_token': self.token},
                    cookies={**dict(self.session.cookies), "timestamp": Arkose.x_ark_value()},
                )
                pow_data = pow_resp.json()
                # Download the PoW HTML page (required by server)
                if pow_data.get("url"):
                    self.session.get(pow_data["url"])
                # Solve PoW via Node.js worker (handles obfuscated sequence JS)
                import requests as py_requests
                try:
                    pow_result = py_requests.post('http://127.0.0.1:8004/solve', json={
                        'pow_setup': pow_data,
                        'session_token': self.token,
                        'proxy': self.proxy if hasattr(self, 'proxy') else None,
                    }, timeout=90).json()
                except Exception as pow_err:
                    return {"success": False, "err": f"pow solver error: {pow_err}", "token": None}
                if not pow_result.get('success'):
                    return {"success": False, "err": f"pow solve failed: {pow_result.get('error')}", "token": None}
                pow_check_data = pow_result['result']
                pow_check_resp = self.session.post(
                    f'{self.apiurl}/pows/check',
                    json=pow_check_data,
                    cookies={**dict(self.session.cookies), "timestamp": Arkose.x_ark_value()},
                )

            # Step 3: init-load
            init_ts = Arkose.x_ark_value()
            self.session.headers = {
                "accept": "*/*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": f"{self.locale},{self.locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7",
                "connection": "keep-alive",
                "host": self.apiurl.split('https://')[1],
                "referer": f"{self.apiurl}/v2/{self.capi_version}/enforcement.{self.enforcement_hash}.html",
                "sec-ch-ua": f"\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"{self.chrome_version}\", \"Chromium\";v=\"{self.chrome_version}\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "user-agent": self.useragent,
            }
            self.session.get(f'{self.apiurl}/fc/init-load/', params={'session_token': self.token}, cookies={**dict(self.session.cookies), "timestamp": init_ts})

            # Step 4: Get challenge data (fc/gfct/) - BEFORE analytics
            ts2 = Utils.newrelic_time()
            self.session.headers = {
                "accept": "*/*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": f"{self.locale},{self.locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7",
                "cache-control": "no-cache",
                "connection": "keep-alive",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "host": self.apiurl.split('https://')[1],
                "origin": self.siteurl,
                "referer": referer,
                "sec-ch-ua": f"\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"{self.chrome_version}\", \"Chromium\";v=\"{self.chrome_version}\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "user-agent": self.useragent,
                "x-newrelic-timestamp": ts2,
                "x-requested-with": "XMLHttpRequest",
            }

            result=self._task_data(cookies={**dict(self.session.cookies), "timestamp": ts2})

            if result.get("error"):
                return {"success":False, "err": f"gfct error: {result['error']}", "token": None}

            self.gameid=result.get("challengeID") or result.get("challenge_id") or result.get("game_token")
            self.session_token=result["session_token"]

            # Step 3: Site URL analytics (AFTER gfct)
            ts = Utils.newrelic_time()
            self.callback({"sid": self.r_continent,"session_token": self.token,"analytics_tier": self.at,"disableCookies": "false","render_type": "canvas","is_compatibility_mode": "false","category": "Site URL","action": f"{self.apiurl}/v2/{self.capi_version}/enforcement.{self.enforcement_hash}.html"}, cookies={**dict(self.session.cookies), "timestamp": ts})

            # Step 4: Game loaded analytics
            self.callback({"sid": self.r_continent,"session_token": self.token,"analytics_tier": self.at,"disableCookies": "false","game_token": self.gameid,"game_type": "4","render_type": "canvas","is_compatibility_mode": "false","category": "loaded","action": "game loaded"}, cookies={**dict(self.session.cookies), "timestamp": Utils.newrelic_time()})
            
            answers=[]
            test=[]
            try:
                game=result["game_data"]["instruction_string"]
            except:
                game=result["game_data"]["game_variant"]

            waves=str(result["game_data"]["waves"])

            if int(waves)>=20:
                print(game, ':', str(waves))
                return {"success":False, "err": "too many waves"}

            if result.get("dapib_url"):
                self.dapibCode=self.session.get(result["dapib_url"]).text
                self.session.get(f"{self.apiurl}/params/sri/dapib/{result['dapib_url'].split(f'{self.r_continent}/')[1].split('.js')[0]}")
                
            else:
                self.dapibCode=0
            
            cs=Arkose.generate_cs()
            g= Arkose.generate_g()
            self.callback({"sid": self.r_continent,"session_token": self.token,"analytics_tier": "40","disableCookies": "true","game_token": self.gameid,"game_type": "4","render_type": "canvas","is_compatibility_mode": "false","category": "begin app", "action": "user clicked verify", "cs_": cs, "ct_": str(random.randint(10,99)), "g_": g, "h_": Arkose.generate_h(cs, g), "pt_": Arkose.generate_pt(), "aht_": Arkose.generate_aht()})
            
            image_encryption_enabled=result["game_data"]["customGUI"].get('encrypted_mode')
            if image_encryption_enabled:
                self.image_decryption_key = self.session.post(f'{self.apiurl}/fc/ekey/', data={
                    'session_token': self.session_token,
                    'game_token': self.gameid,
                    'sid': self.r_continent
                }).json()['decryption_key']

            for img in result["game_data"]["customGUI"]["_challenge_imgs"]:
                if image_encryption_enabled:
                    base64_img=Arkose.decrypt_data(self.session.get(img).json(), self.image_decryption_key).decode()
                else:
                    base64_img=base64.b64encode(self.session.get(img).content).decode()

                index=... #Do classification urself!!

                if result["game_data"]["gameType"]==3:
                    index+=1
                    
                test.append(str(index))

                if result["game_data"]["gameType"]==4:
                    answers.append(json.dumps({"index":index}).replace(" ",""))

                elif result["game_data"]["gameType"]==3:
                    answers.append(json.dumps(Utils.grid_answer_dict(index)).replace(" ",""))
                    
                solveresult=self.answer(
                    result=Arkose.encrypt_double(self, self.session_token, str([",".join(answers)]).replace("'","")),
                    answers=answers,
                    i=index
                )

                if image_encryption_enabled:
                    self.image_decryption_key=solveresult.get('decryption_key')

            if solveresult["solved"]:
                logger.print(game, f"Waves: {waves}", f"Answers: {str(len(test))}:[{','.join(test)}]", f.LIGHTGREEN_EX+self.token)
                Utils.solved+=1
                return {"success":True, "err": None, "token": challenge_data["token"], "procces_time": time.time()-self.solve_time}

            else:
                logger.print(game, f"Waves: {waves}", f"Answers: {str(len(test))}:[{','.join(test)}]", f.RED+"Failed to solve.")
                Utils.fail+=1
                return {"success":False, "err":"ai fail", "token": None}
            
        except Exception as err:
            tb = traceback.format_exc()
            Utils.errors+=1
            return {"success":False, "err": f"internal error: {str(err)}", "token": None}
            
    def _task_data(self, cookies=None):
        return self.session.post(f"{self.apiurl}/fc/gfct/",data={
            'token': self.token,
            'sid': self.r_continent,
            'render_type': 'canvas',
            'lang': '',
            'isAudioGame': 'false',
            'is_compatibility_mode': 'false',
            'apiBreakerVersion': 'green',
            'analytics_tier': self.at,
        }, cookies=cookies).json()

    def md5_hash(self, data):
        md5_hash = hashlib.md5()
        md5_hash.update(data.encode('utf-8'))
        return md5_hash.hexdigest()

    def process_fp(self, fpdata):
        result=[]
        for item in fpdata:
            result.append(item.split(":")[1])
        return ';'.join(result)

    def proccess_webgl2(self, data):
        result=[]

        for item in data:
            result.append(item["key"])
            result.append(item["value"])

        return ','.join(result)+',webgl_hash_webgl,'

    def find(self, data, key):
        for item in data:
            if item["key"]==key:
                return item["value"]
                
    def random_pixel_depth(self):
        pixel_depths = [24, 30]
        return random.choice(pixel_depths)
    
    def generate_h(self):
        logical_core_counts = [4, 8, 12, 16, 20, 24, 28, 32, 40, 64]
        return random.choice(logical_core_counts)

    def bda(self):
        time_now=time.time()

        resolutions = [
            (3440,1440,3440,1400),
            (1924,1007,1924,1007),
            (1920,1080,1920,1040),
            (1280,720,1280,672),
            (1920,1080,1920,1032),
            (1366,651,1366,651),
            (1366,768,1366,738),
            (1920,1080,1920,1050)
        ]
        height, width, awidth, aheight=random.choice(resolutions)

        canvases1=[
            "1815906631",
            "235298495",
            "1850036655",
            "-1661048561",
            "823022740",
            "-1712985017",
            "679642534",
            "512287303",
            "-1570039461",
            "11949726",
            "512287303",
            "-479006826",
            "-1124974951",
            "1999955435",
            "213013447",
            "-1058930346",
            "-1291191045",
            "-1338001587",
            "-1946591325",
            "-70526813",
            "-72944365",
            "1456333650",
            "1732442814",
            "631151448",
        ]

        audio_fps=["124.08072766105033","124.04651710136386","124.0807279153014","124.04344968475198","124.08072784824617","124.0396717004187","35.73832903057337","124.0807277960921","124.08075528279005","124.08072790785081","124.08072256811283","124.04345259929687","124.0434496849557","124.0434806260746","124.08072782589443","64.39679384598276","124.0434485301812","124.04423786447296","124.04453790388652","124.08072786314733","124.04569787243236","124.08072787804849","124.04211016517365","124.08072793765314","124.03962087413674","124.04457049137272","124.04344884395687","35.73833402246237","124.0434474653739","124.04855314017914","124.04347524535842","35.10893232002854","124.08072787802666","124.04048140646773","28.601430902344873","35.749968223273754","35.74996031448245","124.0434752900619","124.04347657808103","124.04215029208717","124.08072781844385","124.04369539513573","124.04384341745754","124.04557180271513","35.74996626004577","124.0807470110085","124.04066697827511","124.08072783334501","124.40494026464876","124.0434488439787","35.7383295930922","124.03549310178641","124.04304748237337","124.08075643483608","124.0437401577874","124.05001448364783","124.08072795627959","124.04345808873768","124.04051324382453","124.04347527516074","124.08072796745546","124.0431715620507"]
        colordepth = self.random_pixel_depth()
        self.cfp=random.choice(canvases1)
        fp1=[
         "DNT:unknown",
         f"L:{self.locale}",
         f"D:{colordepth}",
         "PR:1.100000023841858",
         f"S:{height},{width}",
         f"AS:{awidth},{aheight}",
         "TO:-120",
         "SS:true",
         "LS:true",
         "IDB:true",
         "B:false",
         "ODB:false",
         "CPUC:unknown",
         "PK:Win32",
         f"CFP:{self.cfp}",
         "FR:false",
         "FOS:false",
         "FB:false",
         "JSF:Arial,Arial Black,Arial Narrow,Calibri,Cambria,Cambria Math,Comic Sans MS,Consolas,Courier,Courier New,Georgia,Helvetica,Impact,Lucida Console,Lucida Sans Unicode,Microsoft Sans Serif,MS Gothic,MS PGothic,MS Sans Serif,MS Serif,Palatino Linotype,Segoe Print,Segoe Script,Segoe UI,Segoe UI Light,Segoe UI Semibold,Segoe UI Symbol,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings",
         "P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF",
         "T:0,false,false",
         f"H:{self.generate_h()}",
         "SWF:false"
      ]
        
        webgl=random.choice(random.choice(webgls)["webgl"])
        enhanced_fp=[
        {
            "key":"webgl_extensions",
            "value":webgl["webgl_extensions"]
        },
        {
            "key":"webgl_extensions_hash",
            "value":webgl["webgl_extensions_hash"]
        },
        {
            "key":"webgl_renderer",
            "value":webgl["webgl_renderer"]
        },
        {
            "key":"webgl_vendor",
            "value":webgl["webgl_vendor"]
        },
        {
            "key":"webgl_version",
            "value":webgl["webgl_version"]
        },
        {
            "key":"webgl_shading_language_version",
            "value":webgl["webgl_shading_language_version"]
        },
        {
            "key":"webgl_aliased_line_width_range",
            "value":webgl["webgl_aliased_line_width_range"]
        },
        {
            "key":"webgl_aliased_point_size_range",
            "value":webgl["webgl_aliased_point_size_range"]
        },
        {
            "key":"webgl_antialiasing",
            "value":"yes"
        },
        {
            "key":"webgl_bits",
            "value":webgl["webgl_bits"]
        },
        {
            "key":"webgl_max_params",
            "value":webgl["webgl_max_params"]
        },
        {
            "key":"webgl_max_viewport_dims",
            "value":webgl["webgl_max_viewport_dims"]
        },
        {
            "key":"webgl_unmasked_vendor",
            "value":webgl["webgl_unmasked_vendor"]
        },
        {
            "key":"webgl_unmasked_renderer",
            "value":webgl["webgl_unmasked_renderer"]
        },
        {
            "key":"webgl_vsf_params",
            "value":webgl["webgl_vsf_params"]
        },
        {
            "key":"webgl_vsi_params",
            "value":webgl["webgl_vsi_params"]
        },
        {
            "key":"webgl_fsf_params",
            "value":webgl["webgl_fsf_params"]
        },
        {
            "key":"webgl_fsi_params",
            "value":webgl["webgl_fsi_params"]
        }]

        enhanced_fp.append({
            "key":"webgl_hash_webgl",
            "value":gctx.call("x64hash128",self.proccess_webgl2(enhanced_fp))
        })

        enhanced_fp_more=[
            {
                "key":"user_agent_data_brands",
                "value":"Chromium,Not;A=Brand,Google Chrome"
            },
            {
                "key":"user_agent_data_mobile",
                "value":False
            },
            {
                "key":"navigator_connection_downlink",
                "value":10
            },
            {
                "key":"navigator_connection_downlink_max",
                "value":None
            },
            {
                "key":"network_info_rtt",
                "value":50
            },
            {
                "key":"network_info_save_data",
                "value":False
            },
            {
                "key":"network_info_rtt_type",
                "value":None
            },
            {
                "key":"screen_pixel_depth",
                "value":colordepth
            },
            {
                "key":"navigator_device_memory",
                "value":8
            },
            {
                "key":"navigator_pdf_viewer_enabled",
                "value":True
            },
            {
                "key":"navigator_languages",
                "value":"en-US,en"
            },
            {
                "key":"window_inner_width",
                "value":0
            },
            {
                "key":"window_inner_height",
                "value":0
            },
            {
                "key":"window_outer_width",
                "value":int(width)
            },
            {
                "key":"window_outer_height",
                "value":int(height)
            },
            {
                "key":"browser_detection_firefox",
                "value":False
            },
            {
                "key":"browser_detection_brave",
                "value":False
            },
            {
                "key":"browser_api_checks",
                "value":[
                    "permission_status: true",
                    "eye_dropper: true",
                    "audio_data: true",
                    "writable_stream: true",
                    "css_style_rule: true",
                    "navigator_ua: true",
                    "barcode_detector: false",
                    "display_names: true",
                    "contacts_manager: false",
                    "svg_discard_element: false",
                    "usb: defined",
                    "media_device: defined",
                    "playback_quality: true"
                ]
            },
            {
                "key":"browser_object_checks",
                "value":self.md5_hash("chrome")
            },
            {
                "key":"29s83ih9",
                "value":self.md5_hash("false")+"⁣"
            },
            {
                "key":"audio_codecs",
                "value":"{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"
            },
            {
                "key":"audio_codecs_extended_hash",
                "value":self.md5_hash('{"audio/mp4; codecs=\\"mp4a.40\\"":{"canPlay":"maybe","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.1\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.2\\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\\"mp4a.40.3\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.4\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.5\\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\\"mp4a.40.6\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.7\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.8\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.9\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.12\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.13\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.14\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.15\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.16\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.17\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.19\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.20\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.21\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.22\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.23\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.24\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.25\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.26\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.27\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.28\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.29\\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\\"mp4a.40.32\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.33\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.34\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.35\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.40.36\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"mp4a.66\\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\\"mp4a.67\\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\\"mp4a.68\\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\\"mp4a.69\\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\\"mp4a.6B\\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\\"mp3\\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\\"flac\\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\\"bogus\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"aac\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"ac3\\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\\"A52\\"":{"canPlay":"","mediaSource":false},"audio/mpeg; codecs=\\"mp3\\"":{"canPlay":"probably","mediaSource":false},"audio/wav; codecs=\\"0\\"":{"canPlay":"","mediaSource":false},"audio/wav; codecs=\\"2\\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\\"0\\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\\"1\\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\\"2\\"":{"canPlay":"","mediaSource":false},"audio/x-wav; codecs=\\"0\\"":{"canPlay":"","mediaSource":false},"audio/x-wav; codecs=\\"1\\"":{"canPlay":"probably","mediaSource":false},"audio/x-wav; codecs=\\"2\\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\\"0\\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\\"1\\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\\"2\\"":{"canPlay":"","mediaSource":false}}')
            },
            {
                "key":"video_codecs",
                "value":"{\"ogg\":\"\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"
            },
            {
                "key":"video_codecs_extended_hash",
                "value":self.md5_hash('{"video/mp4; codecs=\\"hev1.1.6.L93.90\\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\\"hvc1.1.6.L93.90\\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\\"hev1.1.6.L93.B0\\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\\"hvc1.1.6.L93.B0\\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\\"vp09.00.10.08\\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\\"vp09.00.50.08\\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\\"vp09.01.20.08.01\\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\\"vp09.01.20.08.01.01.01.01.00\\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\\"vp09.02.10.10.01.09.16.09.01\\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\\"av01.0.08M.08\\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\\"vorbis\\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\\"vp8\\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\\"vp8.0\\"":{"canPlay":"probably","mediaSource":false},"video/webm; codecs=\\"vp8.0, vorbis\\"":{"canPlay":"probably","mediaSource":false},"video/webm; codecs=\\"vp8, opus\\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\\"vp9\\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\\"vp9, vorbis\\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\\"vp9, opus\\"":{"canPlay":"probably","mediaSource":true},"video/x-matroska; codecs=\\"theora\\"":{"canPlay":"","mediaSource":false},"application/x-mpegURL; codecs=\\"avc1.42E01E\\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\\"dirac, vorbis\\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\\"theora, speex\\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\\"theora, vorbis\\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\\"theora, flac\\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\\"dirac, flac\\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\\"flac\\"":{"canPlay":"probably","mediaSource":false},"video/3gpp; codecs=\\"mp4v.20.8, samr\\"":{"canPlay":"","mediaSource":false}}')
            },
            {
                "key":"media_query_dark_mode",
                "value":False
            },
            {
                "key":"css_media_queries",
                "value":0
            },
            {
                "key":"css_color_gamut",
                "value":"srgb"
            },
            {
                "key":"css_contrast",
                "value":"no-preference"
            },
            {
                "key":"css_monochrome",
                "value":False
            },
            {
                "key":"css_pointer",
                "value":"fine"
            },
            {
                "key":"css_grid_support",
                "value":False
            },
            {
                "key":"headless_browser_phantom",
                "value":False
            },
            {
                "key":"headless_browser_selenium",
                "value":False
            },
            {
                "key":"headless_browser_nightmare_js",
                "value":False
            },
            {
                "key":"headless_browser_generic",
                "value":4
            },
            {
                "key":"1l2l5234ar2",
                "value":str(int(time_now*1000))+"⁣"
            },
            {
                "key":"document__referrer",
                "value":self.siteurl.rstrip("/")
            },
            {
                "key":"window__ancestor_origins",
                "value":self.window__ancestor_origins
            },
            {
                "key":"window__tree_index",
                "value":self.window__tree_index
            },
            {
                "key":"window__tree_structure",
                "value":self.window__tree_structure
            },
            {
                "key":"window__location_href",
                "value":f"{self.apiurl}/v2/{self.capi_version}/enforcement.{self.enforcement_hash}.html"
            },
            {
                "key":"client_config__sitedata_location_href",
                "value":self.client_config__sitedata_location_href
            },
            {
                "key":"client_config__language",
                "value":None
            },
            {
                "key":"client_config__surl",
                "value":self.apiurl
            },
            {
                "key":"c8480e29a",
                "value":self.md5_hash(self.apiurl)+"⁢"
            },
            {
                "key":"client_config__triggered_inline",
                "value":False
            },
            {
                "key":"mobile_sdk__is_sdk",
                "value":False
            },
            {
                "key":"audio_fingerprint",
                "value":random.choice(audio_fps)
            },
            {
                "key":"navigator_battery_charging",
                "value":True
            },
            {
                "key":"media_device_kinds",
                "value":["audioinput","videoinput","audiooutput"]
            },
            {
                "key":"media_devices_hash",
                "value":"199eba60310b53c200cc783906883c67"
            },
            {
                "key":"navigator_permissions_hash",
                "value":self.md5_hash("accelerometer|background-sync|camera|clipboard-read|clipboard-write|geolocation|gyroscope|magnetometer|microphone|midi|notifications|payment-handler|persistent-storage")
            },
            {
                "key":"math_fingerprint", 
                "value":self.md5_hash("1.4474840516030247,0.881373587019543,1.1071487177940904,0.5493061443340548,1.4645918875615231,-0.40677759702517235,-0.6534063185820197,9.199870313877772e+307,1.718281828459045,100.01040630344929,0.4828823513147936,1.9275814160560204e-50,7.888609052210102e+269,1.2246467991473532e-16,-0.7181630308570678,11.548739357257748,9.199870313877772e+307,-3.3537128705376014,0.12238344189440875")
            },
            {
                "key":"supported_math_functions",
                "value":self.md5_hash("abs,acos,acosh,asin,asinh,atan,atanh,atan2,ceil,cbrt,expm1,clz32,cos,cosh,exp,floor,fround,hypot,imul,log,log1p,log2,log10,max,min,pow,random,round,sign,sin,sinh,sqrt,tan,tanh,trunc")
            },
            {
                "key":"screen_orientation",
                "value":"landscape-primary"
            },
            {
                "key":"rtc_peer_connection",
                "value":5
            },
            {
                "key":"4b4b269e68",
                "value":str(uuid.uuid4()) #window.location.hash
            },
            {
                "key":"6a62b2a558",
                "value":self.enforcement_hash
            },
            {
                "key":"is_keyless",
                "value":False
            },
            {
                "key":"c2d2015",
                "value":"29d13b1af8803cb86c2697345d7ea9eb"
            },
            {
                "key":"43f2d94",
                "value":False
            },
            {
                "key":"20c15922",
                "value":True
            },
            {
                "key":"4f59ca8",
                "value":None
            },
            {
                "key":"3ea7194",
                "value":{"supported":True,"formats":["HDR10","HLG"],"isHDR":False}
            },
            {
                "key":"05d3d24",
                "value":"d53459d339bbc3faafe9c7c19c2105ca"
            },
            {
                "key":"speech_default_voice",
                "value":"Microsoft David - English (United States) || en-US"
            },
            {
                "key":"speech_voices_hash",
                "value":str(uuid.uuid4().hex)
            },
            {
                "key":"83eb055",
                "value":False
            },
            {
                "key":"4ca87df3d1",
                "value":"Ow=="
            },
            {
                "key":"867e25e5d4",
                "value":"Ow=="
            },
            {
                "key":"d4a306884c",
                "value":"Ow=="
            }]

        for item in enhanced_fp_more:
            enhanced_fp.append(item)

        fp=[
            {
                "key":"api_type",
                "value":"js"
            },
            {
                "key":"f",
                "value":gctx.call("x64hash128", self.process_fp(fp1), 0)
            },
            {
                "key":"n",
                "value":base64.b64encode(str(int(time_now)).encode()).decode()
            },
            {
                "key":"wh",
                "value": f"{str(uuid.uuid4().hex)}|72627afbfd19a741c7da1732218301ac"
            },
            {
                "key":"enhanced_fp",
                "value":enhanced_fp
            },
            {
                "key":"fe",
                "value":fp1
            },
            {
                "key":"ife_hash",
                "value": gctx.call("x64hash128", ", ".join(fp1), 38)
            },
            {
                "key":"jsbd",
                "value":"{\"HL\":6,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DMTO\":1,\"DOTO\":1}"
            }
        ]

        return base64.b64encode(Arkose.make_encrypted_dict(self, json.dumps(fp, separators=(',', ':'), ensure_ascii=False)).encode()).decode()

    def _generate_challenge(self) -> None:
        random.seed(random.randint(0, 2**64 -1))
        
        task={
            "bda":self.bda(),
            "public_key": self.sitekey,
            "site": self.siteurl,
            "userbrowser": self.useragent,
            "capi_version": self.capi_version,
            "capi_mode": "inline",
            "style_theme": "default",
            "rnd": str(random.uniform(0, 1)),
        }

        if self.sitekey=="747B83EC-2CA3-43AD-A7DF-701F286FBABA":
            task["data[origin_page]"]="github_signup_redesign"
        if self.blob:
            task["data[blob]"]=self.blob

        self.session.headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': f'{self.locale},{self.locale.split("-")[0]};q=0.9,en-US;q=0.8,en;q=0.7',
            'connection': 'keep-alive',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'host': self.apiurl.split('https://')[1],
            'origin': self.apiurl,
            'referer': f'{self.apiurl}/v2/{self.capi_version}/enforcement.{self.enforcement_hash}.html',
            'sec-ch-ua': f'"Not)A;Brand";v="99", "Google Chrome";v="{self.chrome_version}", "Chromium";v="{self.chrome_version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.useragent,
            'x-ark-esync-value': self.x_ark_value,
        }
        
        gt2_resp = self.session.post(
            f'{self.apiurl}/fc/gt2/public_key/{self.sitekey}',
            data=task,
            cookies={**dict(self.session.cookies), "timestamp": self.x_ark_value},
        )
        gt2_data = gt2_resp.json()
        return gt2_data

class _solver_stats:
    def calc_cpm():
        while True:
            try:
                before=Utils.solved
                time.sleep(15)
                after=Utils.solved
                Utils.spm = (after-before)*4
            except:
                Utils.spm=0

    def rate(thing,total):
        try:
            return str(round(thing/total*100,4))
        except:
            return "unknown"

    def title():
        time.sleep(1)
        os.system("cls" if sys.platform == "win32" else "clear")
        second=0;minute=0;hours=0;days=0

        while True:
            second+=1
            if second == 60: second = 0; minute+=1
            if minute == 60: minute = 0; hours+=1
            if hours == 24:  hours = 0; days+=1

            elapsed=f"{str(days).zfill(2)}:{str(hours).zfill(2)}:{str(minute).zfill(2)}:{str(second).zfill(2)}"

            title_text = f"Funcaptcha | solved: {str(Utils.solved)} | fail: {str(Utils.fail)} | spm: {str(Utils.spm)} | sup: {_solver_stats.rate(Utils.supc, Utils.supc+Utils.xxsupc)}% | suc: {_solver_stats.rate(Utils.solved, Utils.solved+Utils.fail)}% | errors: {str(Utils.errors)} | elapsed: {elapsed}"
            if sys.platform == 'win32':
                try:
                    import ctypes
                    ctypes.windll.kernel32.SetConsoleTitleW(title_text)
                except Exception:
                    pass
            else:
                sys.stdout.write(f"\x1b]2;{title_text}\x07")
            time.sleep(1)

threading.Thread(target=_solver_stats.title).start()
threading.Thread(target=_solver_stats.calc_cpm).start()

app = Flask(__name__)

class api:
    def __init__(self) -> None:
        self.pool={}
        self.valid_tasks=[]

    def solve(self, task_id):
        j,_=self.pool[task_id]
        result=Funcaptcha(
            apiurl=j["apiurl"],
            siteurl=j["siteurl"],
            sitekey=j["sitekey"],
            chrome_version=j["chrome_version"],
            data=j["data"],
            proxy=j.get("proxy"),
            blob=j.get("blob"),
            custom_cookies=j.get('custom_cookies'),
            custom_locale=j.get('custom_locale')
        ).solve()
        
        self.pool[task_id]=0,{
            "type": "FuncaptchaTask",
            "status": "completed",
            "task_id": task_id,
            "captcha": result
        }

class preset:
    def get():
        return {
            "linkedin_register":{
                "siteurl": 'https://iframe.arkoselabs.com',
                "sitekey": '9E881D9A-F495-4A23-BE4B-16067FF8CC3B',
                "apiurl": 'https://client-api.arkoselabs.com',
                "data": {
                    "window__ancestor_origins": ["https://iframe.arkoselabs.com","https://www.linkedin.com","https://www.linkedin.com","https://www.linkedin.com"],
                    "client_config__sitedata_location_href": "https://iframe.arkoselabs.com/9E881D9A-F495-4A23-BE4B-16067FF8CC3B/index.html",
                    "window__tree_structure": "[[],[[[[]]]]]",
                    'window__tree_index': [1,0,0,0]
                }
            },

            "match_login":{
                "siteurl": "https://match.com",
                "sitekey": "85800716-F435-4981-864C-8B90602D10F7",
                "apiurl": "https://client-api.arkoselabs.com",
                "data": {
                    "window__ancestor_origins":["https://match.com"],
                    "client_config__sitedata_location_href": "https://match.com/login",
                    "window__tree_structure": "[[]]",
                    'window__tree_index': [0]
                }
            },

            "twitter_register": {
                "siteurl": "https://iframe.arkoselabs.com",
                "sitekey": "2CB16598-CB82-4CF7-B332-5990DB66F3AB",
                "apiurl": "https://client-api.arkoselabs.com",
                "data": {
                    "window__ancestor_origins":["https://iframe.arkoselabs.com","https://x.com"],
                    "client_config__sitedata_location_href": "https://iframe.arkoselabs.com/2CB16598-CB82-4CF7-B332-5990DB66F3AB/index.html",
                    "window__tree_structure": "[[[]]]",
                    'window__tree_index': [0,0]
                }
            },
            "twitter_unlock": {
                "siteurl": 'https://iframe.arkoselabs.com',
                "sitekey": '0152B4EB-D2DC-460A-89A1-629838B529C9',
                "apiurl": 'https://client-api.arkoselabs.com',
                "data": {
                    "window__ancestor_origins":["https://iframe.arkoselabs.com","https://x.com"],
                    "client_config__sitedata_location_href": "https://iframe.arkoselabs.com/0152B4EB-D2DC-460A-89A1-629838B529C9/index.html",
                    "window__tree_structure": "[[[]]]",
                    'window__tree_index': [0,0]
                }
            },
            "roblox_register": {
                "siteurl": "https://www.roblox.com",
                "sitekey": "A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F",
                "apiurl": "https://arkoselabs.roblox.com",
                "data": {
                    "window__ancestor_origins":["https://www.roblox.com","https://www.roblox.com"],
                    "client_config__sitedata_location_href": "https://www.roblox.com/arkose/iframe",
                    "window__tree_structure": "[[[]]]",
                    'window__tree_index': [0,0]
                }
            },
            "roblox_login":{
                "siteurl": "https://www.roblox.com",
                "sitekey": "476068BF-9607-4799-B53D-966BE98E2B81",
                "apiurl": "https://arkoselabs.roblox.com",
                "data": {
                    "window__ancestor_origins":["https://www.roblox.com","https://www.roblox.com"],
                    "client_config__sitedata_location_href": "https://www.roblox.com/arkose/iframe",
                    "window__tree_structure": "[[],[[]]]",
                    'window__tree_index': [0,0]
                }
            },

            "github_register": {
                "siteurl": "https://octocaptcha.com",
                "sitekey": "747B83EC-2CA3-43AD-A7DF-701F286FBABA",
                "apiurl": "https://github-api.arkoselabs.com",
                "data": {
                    "window__ancestor_origins":["https://octocaptcha.com","https://github.com"],
                    "client_config__sitedata_location_href": "https://octocaptcha.com/",
                    "window__tree_structure": "[[[]]]",
                    'window__tree_index': [0,0]
                }
            },

            "snapchat_register": {
                "siteurl": "https://iframe.arkoselabs.com",
                "sitekey": "EA4B65CB-594A-438E-B4B5-D0DBA28C9334",
                "apiurl": "https://snap-api.arkoselabs.com",
                "blob": "undefined",
                "data": {
                    "window__ancestor_origins":["https://iframe.arkoselabs.com","https://accounts.snapchat.com"],
                    "client_config__sitedata_location_href": "https://iframe.arkoselabs.com/EA4B65CB-594A-438E-B4B5-D0DBA28C9334/lightbox.html",
                    "window__tree_structure":"[[[]]]",
                    'window__tree_index': [0,0]
                }
            },

            "outlook_register": {
                "siteurl": "https://iframe.arkoselabs.com",
                "sitekey": "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
                "apiurl": "https://client-api.arkoselabs.com",
                "data": {
                    "window__ancestor_origins":[
                        "https://iframe.arkoselabs.com",
                        "https://signup.live.com"
                    ],
                    "client_config__sitedata_location_href": "https://iframe.arkoselabs.com/B7D8911C-5CC8-A9A3-35B0-554ACEE604DA/index.html",
                    "window__tree_structure": "[[],[],[[]]]",
                    'window__tree_index': [2,0]
                },
            },
            "outlook_phone": {
                "siteurl": "https://iframe.arkoselabs.com",
                "sitekey": "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
                "apiurl": "https://client-api.arkoselabs.com",
                "data": {
                    "window__ancestor_origins":[
                        "https://iframe.arkoselabs.com",
                        "https://account.live.com"
                    ],
                    "client_config__sitedata_location_href": "https://iframe.arkoselabs.com/B7D8911C-5CC8-A9A3-35B0-554ACEE604DA/index.html",
                    "window__tree_structure": "[[[]]]",
                    'window__tree_index': [0,0]
                },
            }
        }

self=api()

@app.route('/funcaptcha/getTask', methods = ["POST"])
def getTask():
    try:
        j=request.get_json()
        _,task=self.pool[j["task_id"]]

        for valid_task in self.valid_tasks:
            if valid_task==j["task_id"]:
                threading.Thread(target=self.solve, args=[j["task_id"]]).start()
                self.valid_tasks.remove(j["task_id"])

        if task["status"]=="completed":
            del self.pool[j["task_id"]]

        return task
    
    except Exception:
        return {"success":False, "err": "invalid request"}

@app.route('/funcaptcha/createTask', methods = ["POST"])
def createTask():
    try:
        data=request.get_json()
        data={**data, **preset.get()[data["preset"]]}
        del data['preset']

        task_id=str(uuid.uuid4().hex)
        self.pool[task_id]=data, {
            "type": "FuncaptchaTask",
            "status": "processing",
            "task_id": task_id,
            "result": None
        }
        
        self.valid_tasks.append(task_id)
        return {"success": True, "task_id": task_id}
        
    except:
        return {"success":False, "err": "invalid request"}

app.run(port="8003", host="0.0.0.0", debug=False)
