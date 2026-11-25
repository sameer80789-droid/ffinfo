# -*- coding: utf-8 -*-
"""
Free Fire player info API  -  one file, made for Vercel (Python runtime + Flask).

    GET /info?uid=123456789        (also /api/info?uid=...)

The region is detected automatically. Game accounts come ONLY from the FF_ACCOUNTS_JSON
environment variable (never commit them):
    [{"uid":"...","password":"...","region":"PK"}, ...]
"""
import base64
import hmac
import json
import os
import re
import time
import uuid
import threading
import logging
import ipaddress
import urllib3
import requests
from urllib.parse import urlparse, quote
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, jsonify, request, Response

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ff")

# ==================== CONFIG ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

# ---- built-in setup: works right after deploy, no environment variables needed -----------------
# Game account used when FF_ACCOUNTS_JSON is not set. Keep this repository PRIVATE.
DEFAULT_ACCOUNTS = [
    {"uid": "8388541595",
     "password": "8480008F238A133455A6B6C5E983B6B00E112B7A0C0D7F320785CDCBB24ABC84",
     "region": "PK"},
]
ONLY_REGION = os.environ.get("FF_REGION", "PK").strip().upper()          # this deployment serves one server
API_SECRET = os.environ.get("FF_API_SECRET", "ncs")                     # ?secret=...  (or header X-API-Key)

LOGIN_HOST = "loginbp.ppmainecoonghj.com"
CLIENT_HOST = "clientbp.ppmainecoonghj.com"
FALLBACK_LOGIN_URL = f"https://{LOGIN_HOST}"
FALLBACK_GAME_SERVER = f"https://{CLIENT_HOST}"

FALLBACK_RELEASE = "OB55"
FALLBACK_GAME_VERSION = "1.132.17"


# Player-info request (GetPlayerPersonalShow). callSignSrc 7 = "viewing a profile", which is what the
# real game client sends. Set FF_INFO_CALLSIGN=0 to send only the UID like the old version did.
INFO_CALLSIGN = int(os.environ.get("FF_INFO_CALLSIGN", "7"))
INFO_UNITY_VERSION = os.environ.get("FF_INFO_UNITY_VERSION", "2018.4.12f1")

TIMEOUT_AUTH = 6
TIMEOUT_MAJOR = 8
TIMEOUT_PROFILE = 10
TIMEOUT_VERCONFIG = 6

SESSION_TTL = 20 * 60
PROFILE_TTL = 120
VERSION_TTL = 60 * 60
LOGIN_COOLDOWN = 30          # first failure; doubles on every further failure (see _set_cooldown)
LOGIN_COOLDOWN_MAX = 600
MIN_LOGIN_GAP = 2            # gap between two logins of the SAME region
GLOBAL_LOGIN_GAP = float(os.environ.get("FF_LOGIN_GAP", "1.5"))
LOGIN_ATTEMPTS = 2           # fresh token + MajorLogin tries before a region is put on cooldown

CDN_BASE = "https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{}.png"

REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th", "BD": "bn",
    "PK": "ur", "TW": "zh", "RU": "ru", "SAC": "es", "BR": "pt", "NA": "pt",
    "SG": "pt", "US": "pt", "EU": "en", "CIS": "ru",
}

# =====================================================================
# LEADERBOARD PAYLOAD REGION MAP
# EU   → SG   (EU served by Singapore cluster)
# CIS  → SG   (CIS served by Singapore cluster)
# Source: Free Fire Community API docs — "SG Region covers SG, ID, ME,
#         VN, TH, CIS, EU, TW, MY, PK, BD"
# =====================================================================
REGION_PAYLOAD_MAP = {
    "EU":  "SG",
    "CIS": "SG",
}

# IND ke alternate payload codes (India-only region)
REGION_ALT_PAYLOAD_CODES = {
    "IND": ["IND", "IN"],
}

# =====================================================================
# GAME SERVER CANDIDATES
# Sirf woh servers jo DNS resolve karte hain — dead URLs hata diye.
# =====================================================================
REGION_GAME_SERVER_CANDIDATES = {
    "IND": [
        "https://client.ind.freefiremobile.com",
        "https://clientbp.ppmainecoonghj.com",
    ],
    "NA":  ["https://client.us.freefiremobile.com",
            "https://clientbp.ppmainecoonghj.com"],
    "SAC": ["https://client.us.freefiremobile.com",
            "https://clientbp.ppmainecoonghj.com"],
    "US":  ["https://client.us.freefiremobile.com",
            "https://clientbp.ppmainecoonghj.com"],
    "BR":  ["https://client.us.freefiremobile.com",
            "https://clientbp.ppmainecoonghj.com"],
    "DEFAULT": ["https://clientbp.ppmainecoonghj.com"],
}

# Regions jinhe frontend pe disable kar sakte ho jab tak proper account na ho
REQUIRES_SPECIAL_ACCOUNT = {
    "IND": "India-cluster guest account (Free Fire India app) required",
}


# ==================== HTTP SESSION ====================
_http = requests.Session()
_http.verify = False
_http.headers.update({"Connection": "keep-alive"})
_adapter = HTTPAdapter(
    pool_connections=30, pool_maxsize=80,
    max_retries=Retry(total=1, backoff_factor=0.4,
                      status_forcelist=[500, 502, 503, 504],
                      allowed_methods=["GET", "POST"]),
)
_http.mount("https://", _adapter)
_http.mount("http://", _adapter)

# ==================== PROTOBUF ====================
def encode_varint(n: int) -> bytes:
    out = bytearray()
    if n < 0: n &= 0xFFFFFFFFFFFFFFFF
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def _pb_varint(fn, val): return encode_varint((fn << 3) | 0) + encode_varint(val)

def _pb_length(fn, val):
    enc = val.encode('utf-8') if isinstance(val, str) else val
    return encode_varint((fn << 3) | 2) + encode_varint(len(enc)) + enc

def create_proto(fields) -> bytes:
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(field, str): field = int(field)
        if isinstance(value, dict):
            packet.extend(_pb_length(field, bytes(create_proto(value))))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict): packet.extend(_pb_length(field, bytes(create_proto(item))))
                elif isinstance(item, str): packet.extend(_pb_length(field, item))
                elif isinstance(item, (bytes, bytearray)): packet.extend(_pb_length(field, bytes(item)))
                elif isinstance(item, bool): packet.extend(_pb_varint(field, 1 if item else 0))
                elif isinstance(item, int): packet.extend(_pb_varint(field, item))
        elif isinstance(value, bool): packet.extend(_pb_varint(field, 1 if value else 0))
        elif isinstance(value, int): packet.extend(_pb_varint(field, value))
        elif isinstance(value, str): packet.extend(_pb_length(field, value))
        elif isinstance(value, (bytes, bytearray)): packet.extend(_pb_length(field, bytes(value)))
    return bytes(packet)

def encrypt_aes(hex_data: str, key=AES_KEY, iv=AES_IV) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(hex_data), AES.block_size)).hex()

def decode_varint(data, offset):
    result = 0; shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80): return result, offset
        shift += 7
    return None, offset

def decode_protobuf(data):
    result = {}; offset = 0
    while offset < len(data):
        header, offset = decode_varint(data, offset)
        if header is None: break
        fn = header >> 3; wt = header & 0x7
        key = str(fn)
        if wt == 0:
            v, offset = decode_varint(data, offset)
            if v is not None:
                if key in result:
                    if not isinstance(result[key], list): result[key] = [result[key]]
                    result[key].append(v)
                else: result[key] = v
        elif wt == 2:
            length, offset = decode_varint(data, offset)
            if length is None: break
            value = data[offset:offset+length]; offset += length
            try:
                s = value.decode('utf-8')
                parsed = s if s else value.hex()
            except UnicodeDecodeError:
                nested = decode_protobuf(value)
                parsed = nested if nested else value.hex()
            if key in result:
                if not isinstance(result[key], list): result[key] = [result[key]]
                result[key].append(parsed)
            else: result[key] = parsed
        elif wt == 1: offset += 8
        elif wt == 5: offset += 4
        else: break
    return result

# ==================== VERSION CONFIG ====================
_version_cache = {}
_version_lock = threading.Lock()

def _fetch_app_version():
    return os.environ.get("FF_GAME_VERSION", FALLBACK_GAME_VERSION)

def version_config(region="BD", force=False):
    region = str(region or "BD").upper()
    now = time.time()
    if not force:
        with _version_lock:
            hit = _version_cache.get(region)
            if hit and now - hit[5] < VERSION_TTL:
                return hit

    app_version = _fetch_app_version()
    lang = REGION_LANG.get(region, "en")
    url = (f"https://version.ggwhitehawk.com/live/ver.php?version={app_version}"
           f"&lang={lang}&device=android&channel=android&appstore=googleplay"
           f"&region={region}&whitelist_version=1.3.0&whitelist_sp_version=1.0.0")
    try:
        r = _http.get(url, timeout=TIMEOUT_VERCONFIG)
        j = r.json()
        server_url = (j.get("server_url") or FALLBACK_LOGIN_URL).replace(
            "ggpolarbear.com", "ppmainecoonghj.com")
        remote_version = j.get("remote_version") or app_version
        release_version = j.get("latest_release_version") or FALLBACK_RELEASE
        gops = [u.strip() for u in (j.get("gop_url") or "").split(";") if u.strip()]
        gop_url = gops[0] if gops else "https://ffmconnect.ppmainecoonghj.com"

        result = (release_version, remote_version, server_url, gop_url, app_version, now)
        with _version_lock:
            _version_cache[region] = result
        log.info("[VER:%s] release=%s game=%s login=%s",
                 region, release_version, remote_version, server_url)
        return result
    except Exception as e:
        log.warning("[VER:%s] failed (%s) — fallback", region, e)
        result = (FALLBACK_RELEASE, FALLBACK_GAME_VERSION, FALLBACK_LOGIN_URL,
                  "https://ffmconnect.ppmainecoonghj.com", app_version, now)
        with _version_lock:
            _version_cache[region] = result
        return result

# ==================== AUTH ====================
# Garena answers HTTP 429 error_too_many_requests when this server's IP asks for too many guest tokens.
# Every extra try while blocked only makes it worse, so ONE 429 pauses ALL logins for a while.
_token_block = {"until": 0.0, "streak": 0}
THROTTLE_BASE = 300          # 5 min, doubles on every further 429 in a row, max 30 min

def _throttle_left():
    return max(0, _token_block["until"] - time.time())

def _note_throttle():
    n = _token_block["streak"]
    _token_block["streak"] = n + 1
    _token_block["until"] = time.time() + min(THROTTLE_BASE * (2 ** n), 1800)
    log.warning("Garena rate limit (429) on token grant -> all logins paused for %ds", _throttle_left())

def get_access_token(uid, password, region=""):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    hdrs = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "GarenaMSDK/4.0.44(SM-E135F ;Android 14;en;GB;)",
        "Connection": "Keep-Alive",
    }
    data = {"uid": str(uid), "password": password, "response_type": "token",
            "client_type": "2", "client_secret": HEX_KEY, "client_id": "100067"}
    why = ""
    for attempt in range(3):
        try:
            r = _http.post(url, headers=hdrs, data=data, timeout=TIMEOUT_AUTH)
            if r.status_code == 200:
                j = r.json()
                if j.get("open_id") and j.get("access_token"):
                    return j["open_id"], j["access_token"], j.get("platform", 4)
                why = f"HTTP 200 without token: keys={sorted(j)[:8]} error={str(j.get('error') or j.get('error_description') or '')[:80]}"
            else:
                why = f"HTTP {r.status_code} {r.text[:120]!r}"
                if r.status_code == 429:
                    _note_throttle()
                    break
        except Exception as e:
            why = f"exception {type(e).__name__}: {str(e)[:100]}"
            log.warning("get_access_token attempt %d: %s", attempt + 1, e)
        time.sleep(0.5 * (attempt + 1))
    log.warning("Token grant %s: %s", region, why)
    _login_errors[region] = f"guest token grant failed: {why}"
    return None

# The real game client puts its own public IP into the login request. A fixed foreign IP next to a
# datacenter connection looks fake, so use the server's real egress IP (cached). FF_EGRESS_IP overrides.
_egress = {"ip": None, "t": 0}
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
def _egress_ip():
    env = os.environ.get("FF_EGRESS_IP", "").strip()
    if _IP_RE.match(env): return env
    if _egress["ip"] and time.time() - _egress["t"] < 3600: return _egress["ip"]
    try:
        ip = requests.get("https://api.ipify.org", timeout=3).text.strip()
        if _IP_RE.match(ip):
            _egress.update(ip=ip, t=time.time())
            log.info("Egress IP = %s", ip)
            return ip
    except Exception as e:
        log.warning("egress ip lookup failed: %s", e)
    _egress.update(ip="104.28.197.151", t=time.time() - 3000)   # old constant, retry lookup in ~10 min
    return _egress["ip"]

def get_payload(access_token, open_id, platform, game_version, region="PK", lang_code=None):
    device_id = f"Google|{uuid.uuid4()}"
    reg_code = (region or "PK").upper()
    lang = lang_code or REGION_LANG.get(reg_code, "en")

    major_login = {
        "3": str(datetime.now())[:-7], "4": "free fire", "5": 1,
        "7": str(game_version),
        "8": "Android OS 14 / API-34 (UP1A.231005.007/E135FXXSEEZE2)",
        "9": "Handheld", "11": "CarrierDataNetwork",
        "12": 1672, "13": 750, "14": "338",
        "15": "ARMv7 VFPv3 NEON | 2002 | 8",
        "16": 3702, "17": "Mali-G52",
        "18": "OpenGL ES 3.2 v1.r38p1-01bet0-mbs2v41_0.6d20ec041e51b2f2d25dfc265586ebe8",
        "19": device_id, "20": _egress_ip(), "21": lang,
        "22": f"{open_id}", "23": f"{platform}", "24": "Handheld",
        "25": "samsung SM-E135F", "26": reg_code,
        "29": f"{access_token}", "30": 1, "42": "Cellular",
        "57": "7428b253defc164018c604a1ebbfebdf",
        "60": 52037, "61": 5355, "62": 3723, "63": 3,
        "64": 5483, "65": 52037, "66": 5483, "67": 52037,
        "73": 2,
        "74": "/data/app/~~yACsV8QOk9OexgajWQP30A==/com.dts.freefireth-Bi_wPVrrhYM2nYncc29q7Q==/lib/arm",
        "76": 1,
        "77": "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~yACsV8QOk9OexgajWQP30A==/com.dts.freefireth-Bi_wPVrrhYM2nYncc29q7Q==/base.apk",
        "78": 3, "79": 1, "81": "32", "83": "2019121229",
        "86": "OpenGLES2", "87": 8191, "88": int(platform),
        "92": 16091, "93": "android",
        "94": "KqsHT3Yeqo3RLRl8efNiL3aL/1SHwlSrtK0DwNAqdkNBQz70TeVy+icaIwuR3UK4b65Uf3IG5xBFEv0uu+jQZI+rOYCmNCsXjJT4QcZaYgoaaUGG",
        "95": 111107,
        "96": "{\"cur_rate\":null,\"support_etc2\":false}",
        "97": 1, "98": 1,
        "99": f"{platform}", "100": f"{platform}",
        "102": "4503454457550c0766",
        "104": 53792, "105": 1,
        "106": "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|6b2078db9d22dd98f8e9386a39af8462",
        "107": "c8e41b7a93f02d56e1a94c7b8203f5d1",
    }
    return bytes.fromhex(encrypt_aes(create_proto(major_login).hex()))

_login_errors = {}            # region -> last MajorLogin failure description (shown on /healthz)

def _describe_resp(content):
    """Short, secret-free description of a server reply, so a failed login can be diagnosed from logs."""
    try:
        d = decode_protobuf(content) or {}
    except Exception:
        d = {}
    parts = []
    for k, v in list(d.items())[:12]:
        if isinstance(v, int):
            parts.append(f"{k}={v}")
        elif isinstance(v, str) and len(v) <= 60 and not v.startswith("eyJ"):
            parts.append(f"{k}={v!r}")
        else:
            parts.append(f"{k}=<{type(v).__name__}>")
    txt = ""
    head = content[:80]
    if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head):
        txt = f" text={head.decode('ascii')!r}"
    return f"len={len(content)} head={content[:20].hex()} fields[{', '.join(parts)}]{txt}"

def major_login(payload, login_url, release_version, region=""):
    url = f"{login_url.rstrip('/')}/MajorLogin"
    req_headers = {
        "Accept": "*/*", "Authorization": "Bearer ",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": f"{release_version}",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1", "X-GA-SV": str(int(time.time())),
        "X-Unity-Version": "2018.4.12f1",
    }
    try:
        r = _http.post(url, headers=req_headers, data=payload, timeout=TIMEOUT_MAJOR)
        if r.status_code != 200:
            why = f"HTTP {r.status_code} {_describe_resp(r.content)}"
            log.warning("MajorLogin %s: %s", region, why)
            _login_errors[region] = why
            return None
        content = r.content
        best = None; best_score = -1
        for offset in [0, 64, 48, 32, 80, 16, 128, 8, 96, 60, 56, 40, 24, 20, 12, 4]:
            if offset >= len(content): continue
            cand = decode_protobuf(content[offset:])
            if not cand: continue
            has_jwt = "8" in cand
            has_url = "10" in cand
            score = len(cand) + (100 if has_jwt else 0) + (50 if has_url else 0)
            if score > best_score:
                best = cand; best_score = score
            if has_jwt and has_url: break
        if best and "8" in best:
            _login_errors.pop(region, None)
            return {str(k): {"data": v} for k, v in best.items()}
        why = f"HTTP 200 but no JWT in reply: {_describe_resp(content)}"
        log.warning("MajorLogin %s: %s", region, why)
        _login_errors[region] = why
        return None
    except Exception as e:
        why = f"exception {type(e).__name__}: {str(e)[:150]}"
        log.warning("MajorLogin %s: %s", region, why)
        _login_errors[region] = why
        return None

# ==================== ACCOUNTS ====================
_accounts_cache = {"t": 0, "data": []}
_accounts_lock = threading.Lock()

def load_accounts():
    with _accounts_lock:
        if time.time() - _accounts_cache["t"] < 30 and _accounts_cache["data"]:
            return _accounts_cache["data"]
        try:
            raw_env = os.environ.get("FF_ACCOUNTS_JSON", "").strip()
            data = json.loads(raw_env) if raw_env else list(DEFAULT_ACCOUNTS)
            if not isinstance(data, list): data = [data]
            data = [a for a in data if str(a.get("region", ONLY_REGION)).upper() == ONLY_REGION]   # one server only
            _accounts_cache["data"] = data
            _accounts_cache["t"] = time.time()
            log.info("Loaded %d accounts (pid %d)", len(data), os.getpid())
            return data
        except Exception as e:
            log.error("accounts.json / FF_ACCOUNTS_JSON load failed: %s", e)
            return []

_account_rotor = {}
_rotor_lock = threading.Lock()

def next_account(region):
    region = str(region or "").upper()
    accounts = load_accounts()
    pool = [a for a in accounts if str(a.get("region", "")).upper() == region]
    if not pool:
        log.warning("No account for region %s", region)
        return None
    if len(pool) == 1:
        return pool[0]
    with _rotor_lock:
        idx = _account_rotor.get(region, 0) % len(pool)
        _account_rotor[region] = idx + 1
    return pool[idx]

def default_region():
    accounts = load_accounts()
    if not accounts: return "PK"
    for a in accounts:
        if str(a.get("region", "")).upper() == "PK":
            return "PK"
    return str(accounts[0].get("region", "PK")).upper()

# ==================== SESSION CACHE ====================
_session_cache = {}           # region -> (jwt, game_server_or_None, ts)
_session_lock = threading.Lock()
_auth_locks = {}
_auth_locks_guard = threading.Lock()

_login_cooldown = {}
_last_login_at = {}
_cooldown_lock = threading.Lock()

def _auth_lock(region):
    with _auth_locks_guard:
        return _auth_locks.setdefault(region, threading.Lock())

def _cooldown_state(region):
    with _cooldown_lock:
        now = time.time()
        cd_left = max(0, _login_cooldown.get(region, 0) - now)
        gap_left = max(0, MIN_LOGIN_GAP - (now - _last_login_at.get(region, 0)))
        return cd_left, gap_left

_login_fail_streak = {}
_global_login_lock = threading.Lock()
_global_last_login = [0.0]

def _set_cooldown(region):
    """Cooldown doubles with every failed login in a row (30s, 60s, 120s ... max 10 min)."""
    with _cooldown_lock:
        n = _login_fail_streak.get(region, 0)
        _login_fail_streak[region] = n + 1
        _login_cooldown[region] = time.time() + min(LOGIN_COOLDOWN * (2 ** n), LOGIN_COOLDOWN_MAX)

def _clear_fail_streak(region):
    with _cooldown_lock:
        _login_fail_streak.pop(region, None)
        _login_cooldown.pop(region, None)

def _global_login_gate():
    """All regions log in from ONE server IP. Never send a burst: keep a small gap between any two logins."""
    with _global_login_lock:
        wait = GLOBAL_LOGIN_GAP - (time.time() - _global_last_login[0])
        if wait > 0:
            time.sleep(wait)
        _global_last_login[0] = time.time()

def _mark_login(region):
    with _cooldown_lock:
        _last_login_at[region] = time.time()

def _extract_game_server(res, region=""):
    """JWT field 10 se game server lo — lekin region ke candidates hain to None."""
    v = res.get("10")
    if isinstance(v, dict) and "data" in v:
        url = v["data"]
        if isinstance(url, str) and url.startswith("http"):
            url = url.replace("ggpolarbear.com", "ppmainecoonghj.com").rstrip("/")
            if url == FALLBACK_GAME_SERVER and region in REGION_GAME_SERVER_CANDIDATES:
                return None
            return url
    if region in REGION_GAME_SERVER_CANDIDATES:
        return None
    return FALLBACK_GAME_SERVER

def _jwt_claims(jwt):
    """Non-secret claims of the JWT, only for the log (which region / server the token belongs to)."""
    try:
        part = str(jwt).split(".")[1]
        j = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        return {k: j[k] for k in ("lock_region", "noti_region", "country_code", "exp") if k in j}
    except Exception:
        return {}

def get_session(region, force=False):
    region = str(region).upper()

    # A token that was issued a moment ago and is still refused is not "expired": logging in again
    # right away gives the same answer and only burns rate limit. Keep it, the caller tries other servers.
    if force:
        with _session_lock:
            hit = _session_cache.get(region)
        if hit and time.time() - hit[2] < 90:
            return hit[0], hit[1], None

    if not force:
        with _session_lock:
            hit = _session_cache.get(region)
            if hit and time.time() - hit[2] < SESSION_TTL:
                return hit[0], hit[1], None

    cd_left, _ = _cooldown_state(region)
    if cd_left > 0:
        with _session_lock:
            hit = _session_cache.get(region)
            if hit: return hit[0], hit[1], None
        return None, None, f"Login cooldown for {region} ({int(cd_left)}s)"

    with _auth_lock(region):
        if not force:
            with _session_lock:
                hit = _session_cache.get(region)
                if hit and time.time() - hit[2] < SESSION_TTL:
                    return hit[0], hit[1], None

        cd_left, gap_left = _cooldown_state(region)
        if cd_left > 0:
            with _session_lock:
                hit = _session_cache.get(region)
                if hit: return hit[0], hit[1], None
            return None, None, f"Login cooldown for {region} ({int(cd_left)}s)"

        left = _throttle_left()
        if left > 0:
            return None, None, f"Garena rate limit (429) - retry in {int(left)}s"

        if gap_left > 0:
            time.sleep(gap_left)

        acc = next_account(region)
        if not acc:
            return None, None, f"No account for region {region}"

        release_v, game_v, login_url, gop_url, app_ver, _ = version_config(region)
        log.info("Login: %s uid=%s release=%s game=%s pid=%d",
                 region, acc["uid"], release_v, game_v, os.getpid())
        _mark_login(region)

        res = None
        token_ok = False
        for attempt in range(1, LOGIN_ATTEMPTS + 1):
            _global_login_gate()
            tg = get_access_token(acc["uid"], acc["password"], region=region)
            if not tg:
                log.warning("get_access_token FAILED for %s uid=%s (try %d/%d)",
                            region, acc["uid"], attempt, LOGIN_ATTEMPTS)
            else:
                token_ok = True
                open_id, access_token, platform = tg
                res = major_login(
                    get_payload(access_token, open_id, platform, game_v, region=region),
                    login_url, release_v, region=region
                )
                if res and "8" in res:
                    break
                log.warning("MajorLogin FAILED for %s uid=%s (try %d/%d)",
                            region, acc["uid"], attempt, LOGIN_ATTEMPTS)
            if _throttle_left() > 0:
                break          # Garena said 429: stop at once, every extra request prolongs the block
            if token_ok and sum(1 for a in load_accounts()
                                if str(a.get("region", "")).upper() == region) < 2:
                break          # Garena answered, just not with a JWT: repeating the same request only adds load
            if attempt < LOGIN_ATTEMPTS:
                time.sleep(3 * attempt)
                # try the next account of this region, if there is one
                acc = next_account(region) or acc
        if not res or "8" not in res:
            _set_cooldown(region)
            if _throttle_left() > 0:
                return None, None, f"Garena rate limit (429) - retry in {int(_throttle_left())}s"
            return None, None, "MajorLogin failed" if token_ok else "Auth failed"

        jwt = res["8"]["data"] if isinstance(res["8"], dict) else res["8"]
        game_server = _extract_game_server(res, region)

        _clear_fail_streak(region)
        _token_block["streak"] = 0
        with _session_lock:
            _session_cache[region] = (jwt, game_server, time.time())
        log.info("✅ Session: %s uid=%s game_server=%s field10=%s jwt=%s",
                 region, acc["uid"], game_server,
                 (res.get("10") or {}).get("data") if isinstance(res.get("10"), dict) else None,
                 _jwt_claims(jwt))
        return jwt, game_server, None

# ==================== PLAYER INFO (GetPlayerPersonalShow) ====================
# Layout taken from the FreeFire-Api project's PlayerPersonalShow.proto, written out by hand so no
# protobuf library is needed. Each entry is: field number -> (name, type).
#   int / bool / str     plain values
#   rep_int              list of numbers (packed or not)
#   msg:<Name>           nested message      rep_msg:<Name>   list of nested messages
_PS = {
    "Response": {
        1: ("basic", "msg:Basic"), 2: ("profile", "msg:Profile"), 3: ("leaderboard_pos", "int"),
        6: ("clan", "msg:Clan"), 7: ("captain", "msg:Basic"), 8: ("pet", "msg:Pet"),
        9: ("social", "msg:Social"), 10: ("diamond", "msg:Diamond"), 11: ("credit", "msg:Credit"),
    },
    "Basic": {
        1: ("account_id", "int"), 3: ("nickname", "str"), 5: ("region", "str"),
        6: ("level", "int"), 7: ("exp", "int"),
        11: ("banner_id", "int"), 12: ("head_pic", "int"), 13: ("clan_name", "str"),
        14: ("rank", "int"), 15: ("ranking_points", "int"), 17: ("has_elite_pass", "bool"),
        18: ("badge_count", "int"), 19: ("badge_id", "int"), 20: ("season_id", "int"),
        21: ("liked", "int"), 24: ("last_login_at", "int"),
        30: ("cs_rank", "int"), 31: ("cs_ranking_points", "int"), 32: ("weapon_skins", "rep_int"),
        35: ("max_rank", "int"), 36: ("cs_max_rank", "int"), 37: ("max_ranking_points", "int"),
        39: ("peak_rank_pos", "int"), 40: ("cs_peak_rank_pos", "int"),
        44: ("created_at", "int"), 46: ("selected_item_slots", "rep_int"),
        48: ("title", "int"), 50: ("release_version", "str"),
        54: ("clan_id", "int"), 55: ("clan_badge_id", "int"),
        74: ("prime", "msg:Prime"), 75: ("cs_peak_points", "int"), 78: ("avatar_frame", "int"),
        82: ("social", "msg:Social"),
    },
    "Prime": {2: ("prime_level", "int")},
    "Profile": {
        1: ("avatar_id", "int"), 3: ("clothes", "rep_int"), 4: ("equipped_skills", "rep_int"),
        6: ("pve_primary_weapon", "int"),
    },
    "Clan": {
        1: ("id", "int"), 2: ("name", "str"), 3: ("captain_id", "int"), 4: ("level", "int"),
        5: ("capacity", "int"), 6: ("members", "int"), 7: ("honor_point", "int"),
    },
    "Pet": {
        1: ("id", "int"), 2: ("name", "str"), 3: ("level", "int"), 4: ("exp", "int"),
        6: ("skin_id", "int"), 9: ("selected_skill_id", "int"),
    },
    "Social": {
        2: ("gender", "int"), 3: ("language", "int"), 4: ("time_online", "int"), 5: ("time_active", "int"),
        6: ("battle_tags", "rep_int"), 7: ("social_tags", "rep_int"), 8: ("mode_prefer", "int"),
        9: ("signature", "str"), 10: ("rank_show", "int"),
    },
    "SpecialFriend": {1: ("duo_info", "msg:Duo")},
    "Duo": {1: ("partner_uid", "int"), 3: ("score", "int"), 4: ("creation_timestamp", "int"),
            5: ("days_active", "int"), 6: ("status", "int")},
    "Diamond": {1: ("cost", "int")},
    "Credit": {1: ("score", "int"), 2: ("is_init", "bool")},
}

_GENDER = {1: "Male", 2: "Female"}
_LANGUAGE = {1: "English", 2: "Chinese (Simplified)", 3: "Chinese (Traditional)", 4: "Thai", 5: "Vietnamese",
             6: "Indonesian", 7: "Portuguese", 8: "Spanish", 9: "Russian", 10: "Korean", 11: "French",
             12: "German", 13: "Turkish", 14: "Hindi", 15: "Japanese", 16: "Romanian", 17: "Arabic",
             18: "Burmese", 19: "Urdu", 20: "Bengali", 21: "Malay"}
_TIME_ONLINE = {1: "Online on weekdays", 2: "Online on weekends"}
_TIME_ACTIVE = {1: "Active in the morning", 2: "Active in the afternoon", 3: "Active at night"}
_MODE_PREFER = {1: "Battle Royale", 2: "Clash Squad", 3: "Entertainment"}
_BATTLE_TAGS = {1101: "Domination", 1102: "Uncrown", 1103: "Best partner", 1104: "Sniper", 1105: "Melee",
                1106: "Peacemaker", 1107: "Ambush", 1108: "Shortstop", 1109: "Rampage", 1110: "Leader"}
_SOCIAL_TAGS = {2101: "Fashion", 2102: "Social", 2103: "Veteran", 2104: "Newbie", 2105: "Plays for the win",
                2106: "Plays for fun", 2107: "Voice on", 2108: "Voice off"}

def _walk_fields(data):
    """Yield (field_number, wire_type, value) from raw protobuf bytes."""
    offset = 0
    while offset < len(data):
        header, offset = decode_varint(data, offset)
        if header is None: return
        fn, wt = header >> 3, header & 0x7
        if wt == 0:
            val, offset = decode_varint(data, offset)
            if val is None: return
            yield fn, wt, val
        elif wt == 2:
            length, offset = decode_varint(data, offset)
            if length is None or offset + length > len(data): return
            yield fn, wt, data[offset:offset + length]
            offset += length
        elif wt == 1: offset += 8
        elif wt == 5: offset += 4
        else: return

def _pb_to_dict(data, msg_name):
    """Decode bytes into a dict using the _PS schema. Unknown fields are ignored."""
    schema = _PS[msg_name]
    out = {}
    for fn, wt, val in _walk_fields(data):
        spec = schema.get(fn)
        if not spec: continue
        name, kind = spec
        if kind == "int" and wt == 0:
            out[name] = val - (1 << 64) if val >= (1 << 63) else val
        elif kind == "bool" and wt == 0:
            out[name] = bool(val)
        elif kind == "str" and wt == 2:
            out[name] = val.decode("utf-8", "replace")
        elif kind == "rep_int":
            lst = out.setdefault(name, [])
            if wt == 0:
                lst.append(val)
            elif wt == 2:                      # packed list
                pos = 0
                while pos < len(val):
                    num, pos = decode_varint(val, pos)
                    if num is None: break
                    lst.append(num)
        elif kind.startswith("msg:") and wt == 2:
            out[name] = _pb_to_dict(val, kind[4:])
    return out

def _fmt_ts(ts, with_time=False):
    try:
        ts = int(ts or 0)
        if ts <= 0: return ""
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M" if with_time else "%Y-%m-%d")
    except (ValueError, OSError, OverflowError):
        return ""

def _clean_item_ids(ids):
    out = []
    for i in ids or []:
        if 100000000 <= i <= 999999999 and i not in out:
            out.append(i)
    return out

def parse_player_info(raw):
    """Raw GetPlayerPersonalShow bytes -> readable dict (None if the response is not a player)."""
    info = _pb_to_dict(raw, "Response")
    basic = info.get("basic") or {}
    if not basic.get("nickname") and not basic.get("account_id"):
        return None
    return info

def build_profile(info, target_uid, region):
    b = info.get("basic", {})
    prof = info.get("profile", {})
    clan = info.get("clan", {})
    social = info.get("social") or b.get("social") or {}
    pet = info.get("pet", {})
    credit = info.get("credit", {})

    # Same avatar/banner handling as before, so pictures look exactly as they did.
    # Real avatar lives in Profile.avatar_id (field 2 -> 1). Basic.head_pic is just the default.
    avatar_id = prof.get("avatar_id") or b.get("head_pic") or 102000007
    banner_id = b.get("banner_id") or 902000172
    if str(avatar_id).startswith("902"):  # safety: if the two ever come swapped
        avatar_id, banner_id = banner_id, avatar_id

    clan_name = clan.get("name") or b.get("clan_name") or "No Clan"
    out = {
        "nickname": b.get("nickname", "Unknown"), "uid": target_uid,
        "region": region.upper(), "server_region": b.get("region", ""),
        "level": b.get("level", 0), "exp": b.get("exp", 0),
        "br_rank": b.get("rank", 0), "br_points": b.get("ranking_points", 0),
        "cs_rank": b.get("cs_rank", 0), "cs_points": b.get("cs_ranking_points", 0),
        "max_rank": b.get("max_rank", 0), "cs_max_rank": b.get("cs_max_rank", 0),
        "max_points": b.get("max_ranking_points", 0), "cs_peak_points": b.get("cs_peak_points", 0),
        "likes": b.get("liked", 0),
        "created_at": _fmt_ts(b.get("created_at")) or "Unknown",
        "last_login": _fmt_ts(b.get("last_login_at"), with_time=True),
        "avatar_id": avatar_id, "banner_id": banner_id,
        "clan_name": clan_name, "clan_id": clan.get("id") or b.get("clan_id") or "",
        "title": b.get("title", 0), "avatar_frame": b.get("avatar_frame", 0),
        "badge_count": b.get("badge_count", 0), "has_elite_pass": bool(b.get("has_elite_pass")),
        "prime_level": (b.get("prime") or {}).get("prime_level", 0),
        "release_version": b.get("release_version", ""),
        "leaderboard_pos": info.get("leaderboard_pos", 0),
        "credit_score": credit.get("score", 0),
        "diamond_cost": (info.get("diamond") or {}).get("cost", 0),
        "signature": social.get("signature", ""),
        "gender": _GENDER.get(social.get("gender"), ""),
        "language": _LANGUAGE.get(social.get("language"), ""),
        "mode_prefer": _MODE_PREFER.get(social.get("mode_prefer"), ""),
        "time_online": _TIME_ONLINE.get(social.get("time_online"), ""),
        "time_active": _TIME_ACTIVE.get(social.get("time_active"), ""),
        "battle_tags": [_BATTLE_TAGS[t] for t in social.get("battle_tags", []) if t in _BATTLE_TAGS],
        "social_tags": [_SOCIAL_TAGS[t] for t in social.get("social_tags", []) if t in _SOCIAL_TAGS],
        "outfit_ids": _clean_item_ids(prof.get("clothes")),
        "weapon_skin_ids": _clean_item_ids(b.get("weapon_skins")),
        "skill_ids": prof.get("equipped_skills", []),
    }
    if clan:
        out["clan"] = {"level": clan.get("level", 0), "members": clan.get("members", 0),
                       "capacity": clan.get("capacity", 0), "honor": clan.get("honor_point", 0),
                       "captain_id": clan.get("captain_id", "")}
    if pet.get("name") or pet.get("id"):
        out["pet"] = {"name": pet.get("name", ""), "level": pet.get("level", 0), "exp": pet.get("exp", 0)}
    return out

def search_player_profile(target_uid, region, jwt_token, game_server):
    if not game_server:
        game_server = FALLBACK_GAME_SERVER
    url = f"{game_server.rstrip('/')}/GetPlayerPersonalShow"
    release_v = version_config(region)[0]
    headers = {
        "User-Agent": f"UnityPlayer/{INFO_UNITY_VERSION} (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {jwt_token}",
        "X-GA": "v1 1", "ReleaseVersion": release_v,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": INFO_UNITY_VERSION,
    }
    bodies = []
    if INFO_CALLSIGN:
        bodies.append({"1": int(target_uid), "2": INFO_CALLSIGN})
    bodies.append({"1": int(target_uid)})          # old style request, used if the new one is refused
    try:
        r = None
        for fields in bodies:
            payload = bytes.fromhex(encrypt_aes(create_proto(fields).hex()))
            r = _http.post(url, headers=headers, data=payload, timeout=TIMEOUT_PROFILE)
            if r.status_code == 200:
                break
        if r.status_code != 200:
            return {"error": f"API error: HTTP {r.status_code}"}
        info = parse_player_info(r.content)
        if not info:
            return {"error": "Player not found in this region"}
        return build_profile(info, target_uid, region)
    except Exception as e:
        return {"error": str(e)}

# ==================== PROFILE CACHE ====================
_profile_cache = {}
_profile_cache_lock = threading.Lock()

def lookup_profile(uid, region):
    uid = str(uid).strip()
    if not uid.isdigit(): return {"error": "UID must be numeric"}
    jwt, game_server, err = get_session(region)
    if err: return {"error": err}
    details = search_player_profile(uid, region, jwt, game_server)
    if "error" in details and any(c in details["error"] for c in ("401", "403")):
        jwt, game_server, err = get_session(region, force=True)
        if err: return {"error": err}
        details = search_player_profile(uid, region, jwt, game_server)
    return details

def lookup_profile_cached(uid, region):
    key = (str(uid), str(region).upper())
    now = time.time()
    with _profile_cache_lock:
        hit = _profile_cache.get(key)
        if hit and now - hit[1] < PROFILE_TTL:
            return hit[0]
    result = lookup_profile(uid, region)
    if "error" not in result:
        with _profile_cache_lock:
            _profile_cache[key] = (result, time.time())
    return result


# ==================== REGION AUTO-DETECT ====================
REGION_RE = re.compile(r"^[A-Za-z]{2,4}$")
REGION_HINT_TTL = 60 * 60
SEARCH_BUDGET = float(os.environ.get("FF_SEARCH_BUDGET", "24"))   # seconds, stays below the function limit
_region_hint = {}            # uid -> (region, saved_at)
_region_hint_lock = threading.Lock()

def _account_regions():
    return sorted({str(a.get("region", "PK")).upper() for a in load_accounts()})

def _profile_ok(d):
    return isinstance(d, dict) and "error" not in d and bool(d.get("nickname"))

def _has_session(region):
    with _session_lock:
        hit = _session_cache.get(region)
    return bool(hit and time.time() - hit[2] < SESSION_TTL)

def _finish_auto(d, found_region):
    reported = str(d.get("server_region") or "").upper()
    d["searched_via"] = found_region
    d["region"] = reported if REGION_RE.match(reported) else found_region
    with _region_hint_lock:
        _region_hint[str(d.get("uid"))] = (
            d["region"] if d["region"] in _account_regions() else found_region, time.time())
    return d

def lookup_profile_auto(uid, hint=None):
    """Find a player without knowing the region.
    Order: remembered region, requested region, regions that already have a live login (free),
    then the remaining regions one at a time (each needs a login, so never in a burst)."""
    uid = str(uid).strip()
    regions = _account_regions()
    if not regions:
        return {"error": "No game accounts configured (FF_ACCOUNTS_JSON)", "code": 503}

    pref = []
    with _region_hint_lock:
        hit = _region_hint.get(uid)
    if hit and time.time() - hit[1] < REGION_HINT_TTL:
        pref.append(hit[0])
    if hint:
        pref.append(str(hint).upper())
    order = pref + [default_region()] + regions
    order = [r for i, r in enumerate(order) if r in regions and r not in order[:i]]

    deadline = time.time() + SEARCH_BUDGET
    errors = {}

    def try_region(r):
        d = lookup_profile_cached(uid, r)
        return d if isinstance(d, dict) else {"error": "Unknown error"}

    # 1) the most likely region, on its own
    d = try_region(order[0])
    if _profile_ok(d):
        return _finish_auto(dict(d), order[0])
    errors[order[0]] = d.get("error", "Unknown error")

    def stop_now():
        return any("rate limit" in e.lower() for e in errors.values())

    # 2) regions that are already logged in: parallel, costs no login
    warm = [r for r in order[1:] if _has_session(r)]
    if warm and not stop_now():
        with ThreadPoolExecutor(max_workers=min(4, len(warm))) as pool:
            futs = {pool.submit(try_region, r): r for r in warm}
            for f in as_completed(futs):
                r = futs[f]
                try: d = f.result()
                except Exception as e: d = {"error": str(e)}
                if _profile_ok(d):
                    for g in futs: g.cancel()
                    return _finish_auto(dict(d), r)
                errors[r] = d.get("error", "Unknown error")

    # 3) cold regions: one at a time, until the time budget is used
    for r in order[1:]:
        if r in errors or stop_now() or time.time() > deadline:
            continue
        d = try_region(r)
        if _profile_ok(d):
            return _finish_auto(dict(d), r)
        errors[r] = d.get("error", "Unknown error")

    unchecked = [r for r in order if r not in errors]
    for e in errors.values():
        if "rate limit" in e.lower():
            return {"error": e, "code": 429, "checked": sorted(errors)}
    not_found = [r for r, e in errors.items() if "not found" in e.lower()]
    if not_found:
        msg = f"Player {uid} was not found in: {', '.join(sorted(not_found))}."
        if unchecked:
            msg += f" Not checked (time ran out): {', '.join(unchecked)}."
        return {"error": msg, "code": 404, "checked": sorted(errors), "unchecked": unchecked}
    first_err = next(iter(errors.values()), "Unknown error")
    return {"error": f"Could not look up any region ({first_err}).", "code": 503, "checked": sorted(errors)}

# ==================== ITEM IMAGES (avatar / banner / outfit) ====================
ITEM_API = os.environ.get("FF_ITEM_API", "https://getitems.thug4ff.xyz/item").strip()
_item_http = requests.Session()        # separate session, normal TLS checking
_IMG_EXT = re.compile(r"\.(png|jpe?g|webp|gif)(\?|$)", re.I)

def item_url(item_id):
    return f"{ITEM_API}?id={int(item_id)}" if item_id else ""

def _public_https(url):
    """Only follow plain public https URLs (no IP literals / localhost) when an API answers with a link."""
    try:
        u = urlparse(url)
        if u.scheme != "https" or not u.hostname or u.hostname == "localhost":
            return False
        try:
            ipaddress.ip_address(u.hostname); return False
        except ValueError:
            return True
    except Exception:
        return False

def _find_image_ref(obj, depth=0):
    """Look through a JSON answer for an image link or a base64 image."""
    if depth > 4: return None
    if isinstance(obj, str):
        if obj.startswith("data:image/"): return obj
        if obj.startswith("http") and (_IMG_EXT.search(obj) or "icon" in obj.lower() or "image" in obj.lower()):
            return obj
    elif isinstance(obj, dict):
        for k in ("icon", "image", "img", "url", "icon_url", "image_url", "icon_path", "path"):
            if k in obj:
                r = _find_image_ref(obj[k], depth + 1)
                if r: return r
        for v in obj.values():
            r = _find_image_ref(v, depth + 1)
            if r: return r
    elif isinstance(obj, list):
        for v in obj[:6]:
            r = _find_image_ref(v, depth + 1)
            if r: return r
    return None

def _image_from(url, timeout=6):
    r = _item_http.get(url, timeout=timeout)
    ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if r.status_code == 200 and ct.startswith("image/") and r.content:
        return r.content, ct
    if r.status_code == 200 and "json" in ct:
        ref = _find_image_ref(r.json())
        if ref and ref.startswith("data:image/"):
            head, b64 = ref.split(",", 1)
            return base64.b64decode(b64), head[5:].split(";")[0]
        if ref and _public_https(ref):
            r2 = _item_http.get(ref, timeout=timeout)
            ct2 = (r2.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if r2.status_code == 200 and ct2.startswith("image/") and r2.content:
                return r2.content, ct2
    return None

_item_cache = {}          # id -> (bytes, content_type, saved_at)
_item_lock = threading.Lock()

def get_item_image(item_id):
    with _item_lock:
        hit = _item_cache.get(item_id)
    if hit and time.time() - hit[2] < 6 * 3600:
        return hit[0], hit[1]
    for url in (f"{ITEM_API}?id={item_id}", CDN_BASE.format(item_id)):
        try:
            got = _image_from(url)
            if got:
                with _item_lock:
                    if len(_item_cache) > 300: _item_cache.clear()
                    _item_cache[item_id] = (got[0], got[1], time.time())
                return got
        except Exception as e:
            log.info("item %s via %s failed: %s", item_id, url.split("?")[0], str(e)[:80])
    return None

# ==================== SMALL PER-IP RATE LIMIT ====================
RATE_PER_MIN = int(os.environ.get("FF_RATE_PER_MIN", "20"))
_rate = {}
_rate_lock = threading.Lock()

def _client_ip():
    xf = request.headers.get("X-Forwarded-For", "")
    return (xf.split(",")[0].strip() if xf else request.remote_addr) or "?"

def _rate_ok():
    now = time.time(); ip = _client_ip()
    with _rate_lock:
        if len(_rate) > 2000:
            for k in [k for k, v in _rate.items() if not v or now - v[-1] > 60]: _rate.pop(k, None)
        q = [t for t in _rate.get(ip, []) if now - t < 60]
        if len(q) >= RATE_PER_MIN:
            _rate[ip] = q; return False
        q.append(now); _rate[ip] = q
    return True

# ==================== WEB ====================
app = Flask(__name__)

class _RestorePath:
    """If the platform passes the rewrite target (/api/index) instead of the URL the visitor opened,
    take the original path from the forwarding headers."""
    def __init__(self, wsgi): self.wsgi = wsgi
    def __call__(self, environ, start_response):
        if environ.get("PATH_INFO") in ("/api/index", "/api/index.py"):
            for k in ("HTTP_X_VERCEL_ORIGINAL_PATH", "HTTP_X_ORIGINAL_PATH", "HTTP_X_FORWARDED_PATH", "HTTP_X_INVOKE_PATH"):
                v = (environ.get(k) or "").split("?")[0]
                if v.startswith("/") and v not in ("/api/index", "/api/index.py"):
                    environ["PATH_INFO"] = v
                    break
        return self.wsgi(environ, start_response)
app.wsgi_app = _RestorePath(app.wsgi_app)

@app.after_request
def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "X-API-Key, Content-Type"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

def _public_profile(d):
    """Profile + ready-to-use image links."""
    out = dict(d)
    out["avatar_url"] = item_url(d.get("avatar_id"))
    out["banner_url"] = item_url(d.get("banner_id"))
    out["outfits"] = [{"id": i, "url": item_url(i)} for i in d.get("outfit_ids", [])]
    out["weapon_skins"] = [{"id": i, "url": item_url(i)} for i in d.get("weapon_skin_ids", [])]
    for k in ("searched_via",):
        out.pop(k, None)
    return out

def _authorized():
    given = request.args.get("secret") or request.headers.get("X-API-Key") or ""
    return hmac.compare_digest(given.encode("utf-8"), API_SECRET.encode("utf-8"))

def _error(msg, code):
    r = jsonify({"status": "error", "error": msg}); r.status_code = code
    r.headers["Cache-Control"] = "no-store"
    return r

@app.route("/info", methods=["GET"])
@app.route("/api/info", methods=["GET"])
def api_info():
    if not _rate_ok():
        return _error("Too many requests. Try again in a minute.", 429)
    if not _authorized():
        return _error("Missing or wrong secret. Add &secret=YOUR_KEY (or send header X-API-Key).", 401)
    uid = (request.args.get("uid") or request.args.get("infouid") or "").strip()
    if not uid.isdigit() or not (5 <= len(uid) <= 14):
        return _error("uid must be a number with 5 to 14 digits, e.g. /info?uid=123456789&secret=YOUR_KEY", 400)
    d = lookup_profile_auto(uid, hint=ONLY_REGION)
    if "error" in d:
        return _error(d["error"], int(d.get("code") or 502))
    resp = jsonify({"status": "success", **_public_profile(d)})
    resp.headers["Cache-Control"] = "private, no-store"
    return resp

@app.route("/api/item", methods=["GET"])
def api_item():
    iid = (request.args.get("id") or "").strip()
    if not iid.isdigit() or len(iid) > 12:
        return Response("bad id", 400)
    got = get_item_image(int(iid))
    if not got:
        return Response("not found", 404, headers={"Cache-Control": "public, s-maxage=600"})
    return Response(got[0], mimetype=got[1],
                    headers={"Cache-Control": "public, max-age=86400, s-maxage=604800, immutable"})

_INDEX_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "public", "index.html")

@app.route("/", methods=["GET"])
def home():
    """Vercel normally serves public/index.html itself; this is the safety net."""
    try:
        with open(_INDEX_FILE, "rb") as f:
            body = f.read()
        return Response(body, mimetype="text/html", headers={"Cache-Control": "public, max-age=300"})
    except Exception:
        return jsonify({"status": "ok", "use": "/info?uid=<UID>&secret=<KEY>"})

@app.route("/api/index", methods=["GET"])
@app.route("/api/index.py", methods=["GET"])
def rewrite_target():
    """Some Vercel setups hand every request to the function as /api/index and lose the real path.
    Pick the right handler from the query string instead."""
    if request.args.get("uid") or request.args.get("infouid"):
        return api_info()
    if request.args.get("id"):
        return api_item()
    if request.args.get("secret") or request.headers.get("X-API-Key"):
        return api_health()
    return home()

@app.errorhandler(404)
def not_found(_e):
    r = jsonify({"status": "error", "error": "Not found", "path": request.path,
                 "try": ["/", "/info?uid=<UID>&secret=<KEY>", "/api/health?secret=<KEY>"]})
    r.status_code = 404
    return r

@app.route("/health", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def api_health():
    if not _authorized():
        return _error("Missing or wrong secret.", 401)
    return jsonify({"ok": True, "accounts_per_region": _accounts_per_region(),
                    "login_errors": dict(_login_errors),
                    "garena_rate_limit_seconds_left": int(_throttle_left())})

def _accounts_per_region():
    out = {}
    for a in load_accounts():
        r = str(a.get("region", "")).upper()
        out[r] = out.get(r, 0) + 1
    return out