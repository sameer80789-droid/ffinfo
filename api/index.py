# -*- coding: utf-8 -*-
"""
Free Fire player info API - one file, made for Vercel (Python runtime + Flask).

    GET /info?uid=123456789        (also /api/info?uid=...)

The region is detected automatically. Game accounts come from FF_ACCOUNTS_JSON
when set; otherwise DEFAULT_ACCOUNTS is used. Keep this repository private and
never publish real account credentials.
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
from urllib.parse import urlparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, jsonify, request, Response

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ff")

# ==================== CONFIG ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

# Built-in fallback account retained as supplied. Prefer FF_ACCOUNTS_JSON for deployments.
# Keep the repository private; rotate this credential if it is a real usable account.
DEFAULT_ACCOUNTS = [
    {
        "uid": "8388541595",
        "password": "8480008F238A133455A6B6C5E983B6B00E112B7A0C0D7F320785CDCBB24ABC84",
        "region": "PK",
    },
]

ONLY_REGION = os.environ.get("FF_REGION", "PK").strip().upper()
API_SECRET = os.environ.get("FF_API_SECRET", "ncs")

LOGIN_HOST = "loginbp.ppmainecoonghj.com"
CLIENT_HOST = "clientbp.ppmainecoonghj.com"
FALLBACK_LOGIN_URL = f"https://{LOGIN_HOST}"
FALLBACK_GAME_SERVER = f"https://{CLIENT_HOST}"

FALLBACK_RELEASE = "OB55"
FALLBACK_GAME_VERSION = "1.132.17"

INFO_CALLSIGN = int(os.environ.get("FF_INFO_CALLSIGN", "7"))
INFO_UNITY_VERSION = os.environ.get("FF_INFO_UNITY_VERSION", "2018.4.12f1")

TIMEOUT_AUTH = 6
TIMEOUT_MAJOR = 8
TIMEOUT_PROFILE = 10
TIMEOUT_VERCONFIG = 6

SESSION_TTL = 20 * 60
PROFILE_TTL = 120
VERSION_TTL = 60 * 60
LOGIN_COOLDOWN = 30
LOGIN_COOLDOWN_MAX = 600
MIN_LOGIN_GAP = 2
GLOBAL_LOGIN_GAP = float(os.environ.get("FF_LOGIN_GAP", "1.5"))
LOGIN_ATTEMPTS = 2

CDN_BASE = "https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{}.png"

REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th", "BD": "bn",
    "PK": "ur", "TW": "zh", "RU": "ru", "SAC": "es", "BR": "pt", "NA": "pt",
    "SG": "pt", "US": "pt", "EU": "en", "CIS": "ru",
}

REGION_PAYLOAD_MAP = {"EU": "SG", "CIS": "SG"}
REGION_ALT_PAYLOAD_CODES = {"IND": ["IND", "IN"]}

REGION_GAME_SERVER_CANDIDATES = {
    "IND": [
        "https://client.ind.freefiremobile.com",
        "https://clientbp.ppmainecoonghj.com",
    ],
    "NA": [
        "https://client.us.freefiremobile.com",
        "https://clientbp.ppmainecoonghj.com",
    ],
    "SAC": [
        "https://client.us.freefiremobile.com",
        "https://clientbp.ppmainecoonghj.com",
    ],
    "US": [
        "https://client.us.freefiremobile.com",
        "https://clientbp.ppmainecoonghj.com",
    ],
    "BR": [
        "https://client.us.freefiremobile.com",
        "https://clientbp.ppmainecoonghj.com",
    ],
    "DEFAULT": ["https://clientbp.ppmainecoonghj.com"],
}

REQUIRES_SPECIAL_ACCOUNT = {
    "IND": "India-cluster guest account (Free Fire India app) required",
}

app = Flask(__name__)

# ==================== HTTP SESSION ====================
_http = requests.Session()
_http.verify = False
_http.headers.update({"Connection": "keep-alive"})
_adapter = HTTPAdapter(
    pool_connections=30,
    pool_maxsize=80,
    max_retries=Retry(
        total=1,
        backoff_factor=0.4,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    ),
)
_http.mount("https://", _adapter)
_http.mount("http://", _adapter)

# ==================== PROTOBUF ====================
def encode_varint(n: int) -> bytes:
    out = bytearray()
    if n < 0:
        n &= 0xFFFFFFFFFFFFFFFF
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            break
    return bytes(out)


def _pb_varint(fn, val):
    return encode_varint((fn << 3) | 0) + encode_varint(val)


def _pb_length(fn, val):
    enc = val.encode("utf-8") if isinstance(val, str) else val
    return encode_varint((fn << 3) | 2) + encode_varint(len(enc)) + enc


def create_proto(fields) -> bytes:
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(field, str):
            field = int(field)
        if isinstance(value, dict):
            packet.extend(_pb_length(field, bytes(create_proto(value))))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    packet.extend(_pb_length(field, bytes(create_proto(item))))
                elif isinstance(item, str):
                    packet.extend(_pb_length(field, item))
                elif isinstance(item, (bytes, bytearray)):
                    packet.extend(_pb_length(field, bytes(item)))
                elif isinstance(item, bool):
                    packet.extend(_pb_varint(field, 1 if item else 0))
                elif isinstance(item, int):
                    packet.extend(_pb_varint(field, item))
        elif isinstance(value, bool):
            packet.extend(_pb_varint(field, 1 if value else 0))
        elif isinstance(value, int):
            packet.extend(_pb_varint(field, value))
        elif isinstance(value, str):
            packet.extend(_pb_length(field, value))
        elif isinstance(value, (bytes, bytearray)):
            packet.extend(_pb_length(field, bytes(value)))
    return bytes(packet)


def encrypt_aes(hex_data: str, key=AES_KEY, iv=AES_IV) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(hex_data), AES.block_size)).hex()


def decode_varint(data, offset):
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80):
            return result, offset
        shift += 7
        if shift >= 70:
            return None, offset
    return None, offset


def decode_protobuf(data):
    result = {}
    offset = 0
    while offset < len(data):
        header, offset = decode_varint(data, offset)
        if header is None:
            break
        fn = header >> 3
        wt = header & 0x7
        key = str(fn)
        if wt == 0:
            value, offset = decode_varint(data, offset)
            if value is not None:
                if key in result:
                    if not isinstance(result[key], list):
                        result[key] = [result[key]]
                    result[key].append(value)
                else:
                    result[key] = value
        elif wt == 2:
            length, offset = decode_varint(data, offset)
            if length is None or offset + length > len(data):
                break
            value = data[offset:offset + length]
            offset += length
            try:
                decoded = value.decode("utf-8")
                parsed = decoded if decoded else value.hex()
            except UnicodeDecodeError:
                nested = decode_protobuf(value)
                parsed = nested if nested else value.hex()
            if key in result:
                if not isinstance(result[key], list):
                    result[key] = [result[key]]
                result[key].append(parsed)
            else:
                result[key] = parsed
        elif wt == 1:
            offset += 8
        elif wt == 5:
            offset += 4
        else:
            break
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
    url = (
        f"https://version.ggwhitehawk.com/live/ver.php?version={app_version}"
        f"&lang={lang}&device=android&channel=android&appstore=googleplay"
        f"&region={region}&whitelist_version=1.3.0&whitelist_sp_version=1.0.0"
    )
    try:
        response = _http.get(url, timeout=TIMEOUT_VERCONFIG)
        response.raise_for_status()
        data = response.json()
        server_url = (data.get("server_url") or FALLBACK_LOGIN_URL).replace(
            "ggpolarbear.com", "ppmainecoonghj.com"
        )
        remote_version = data.get("remote_version") or app_version
        release_version = data.get("latest_release_version") or FALLBACK_RELEASE
        gops = [u.strip() for u in (data.get("gop_url") or "").split(";") if u.strip()]
        gop_url = gops[0] if gops else "https://ffmconnect.ppmainecoonghj.com"
        result = (release_version, remote_version, server_url, gop_url, app_version, now)
        with _version_lock:
            _version_cache[region] = result
        log.info("[VER:%s] release=%s game=%s login=%s", region, release_version, remote_version, server_url)
        return result
    except Exception as exc:
        log.warning("[VER:%s] failed (%s) - fallback", region, exc)
        result = (
            FALLBACK_RELEASE,
            FALLBACK_GAME_VERSION,
            FALLBACK_LOGIN_URL,
            "https://ffmconnect.ppmainecoonghj.com",
            app_version,
            now,
        )
        with _version_lock:
            _version_cache[region] = result
        return result

# ==================== AUTH ====================
_token_block = {"until": 0.0, "streak": 0}
THROTTLE_BASE = 300


def _throttle_left():
    return max(0, _token_block["until"] - time.time())


def _note_throttle():
    n = _token_block["streak"]
    _token_block["streak"] = n + 1
    _token_block["until"] = time.time() + min(THROTTLE_BASE * (2 ** n), 1800)
    log.warning("Garena rate limit (429) on token grant -> all logins paused for %ds", _throttle_left())


_login_errors = {}


def get_access_token(uid, password, region=""):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "GarenaMSDK/4.0.44(SM-E135F ;Android 14;en;GB;)",
        "Connection": "Keep-Alive",
    }
    data = {
        "uid": str(uid),
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": HEX_KEY,
        "client_id": "100067",
    }
    why = ""
    for attempt in range(3):
        try:
            response = _http.post(url, headers=headers, data=data, timeout=TIMEOUT_AUTH)
            if response.status_code == 200:
                payload = response.json()
                if payload.get("open_id") and payload.get("access_token"):
                    return payload["open_id"], payload["access_token"], payload.get("platform", 4)
                why = (
                    "HTTP 200 without token: "
                    f"keys={sorted(payload)[:8]} "
                    f"error={str(payload.get('error') or payload.get('error_description') or '')[:80]}"
                )
            else:
                why = f"HTTP {response.status_code} {response.text[:120]!r}"
                if response.status_code == 429:
                    _note_throttle()
                    break
        except Exception as exc:
            why = f"exception {type(exc).__name__}: {str(exc)[:100]}"
            log.warning("get_access_token attempt %d: %s", attempt + 1, exc)
        time.sleep(0.5 * (attempt + 1))
    log.warning("Token grant %s: %s", region, why)
    _login_errors[region] = f"guest token grant failed: {why}"
    return None


_egress = {"ip": None, "t": 0}
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _egress_ip():
    env_ip = os.environ.get("FF_EGRESS_IP", "").strip()
    if _IP_RE.match(env_ip):
        try:
            return str(ipaddress.ip_address(env_ip))
        except ValueError:
            pass
    if _egress["ip"] and time.time() - _egress["t"] < 3600:
        return _egress["ip"]
    try:
        ip = requests.get("https://api.ipify.org", timeout=3).text.strip()
        if _IP_RE.match(ip):
            ip = str(ipaddress.ip_address(ip))
            _egress.update(ip=ip, t=time.time())
            log.info("Egress IP = %s", ip)
            return ip
    except Exception as exc:
        log.warning("egress ip lookup failed: %s", exc)
    _egress.update(ip="104.28.197.151", t=time.time() - 3000)
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


def _describe_resp(content):
    """Short, secret-free description of a server reply for logs."""
    try:
        data = decode_protobuf(content) or {}
    except Exception:
        data = {}
    parts = []
    for key, value in list(data.items())[:12]:
        if isinstance(value, int):
            parts.append(f"{key}={value}")
        elif isinstance(value, str) and len(value) <= 60 and not value.startswith("eyJ"):
            parts.append(f"{key}={value!r}")
        else:
            parts.append(f"{key}=<{type(value).__name__}>")
    head = content[:80]
    text_head = ""
    if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head):
        text_head = f" text={head.decode('ascii')!r}"
    return f"len={len(content)} head={content[:20].hex()} fields[{', '.join(parts)}]{text_head}"


def major_login(payload, login_url, release_version, region=""):
    url = f"{login_url.rstrip('/')}/MajorLogin"
    headers = {
        "Accept": "*/*", "Authorization": "Bearer ",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": f"{release_version}",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1", "X-GA-SV": str(int(time.time())),
        "X-Unity-Version": "2018.4.12f1",
    }
    try:
        response = _http.post(url, headers=headers, data=payload, timeout=TIMEOUT_MAJOR)
        if response.status_code != 200:
            why = f"HTTP {response.status_code} {_describe_resp(response.content)}"
            log.warning("MajorLogin %s: %s", region, why)
            _login_errors[region] = why
            return None
        content = response.content
        best = None
        best_score = -1
        for offset in [0, 64, 48, 32, 80, 16, 128, 8, 96, 60, 56, 40, 24, 20, 12, 4]:
            if offset >= len(content):
                continue
            candidate = decode_protobuf(content[offset:])
            if not candidate:
                continue
            has_jwt = "8" in candidate
            has_url = "10" in candidate
            score = len(candidate) + (100 if has_jwt else 0) + (50 if has_url else 0)
            if score > best_score:
                best = candidate
                best_score = score
            if has_jwt and has_url:
                break
        if best and "8" in best:
            _login_errors.pop(region, None)
            return {str(k): {"data": v} for k, v in best.items()}
        why = f"HTTP 200 but no JWT in reply: {_describe_resp(content)}"
        log.warning("MajorLogin %s: %s", region, why)
        _login_errors[region] = why
        return None
    except Exception as exc:
        why = f"exception {type(exc).__name__}: {str(exc)[:150]}"
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
            if not isinstance(data, list):
                data = [data]
            data = [
                account for account in data
                if str(account.get("region", ONLY_REGION)).upper() == ONLY_REGION
            ]
            _accounts_cache["data"] = data
            _accounts_cache["t"] = time.time()
            log.info("Loaded %d accounts (pid %d)", len(data), os.getpid())
            return data
        except Exception as exc:
            log.error("accounts.json / FF_ACCOUNTS_JSON load failed: %s", exc)
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
        index = _account_rotor.get(region, 0) % len(pool)
        _account_rotor[region] = index + 1
    return pool[index]


def default_region():
    accounts = load_accounts()
    if not accounts:
        return "PK"
    for account in accounts:
        if str(account.get("region", "")).upper() == "PK":
            return "PK"
    return str(accounts[0].get("region", "PK")).upper()

# ==================== SESSION CACHE ====================
_session_cache = {}
_session_lock = threading.Lock()
_auth_locks = {}
_auth_locks_guard = threading.Lock()
_login_cooldown = {}
_last_login_at = {}
_cooldown_lock = threading.Lock()
_login_fail_streak = {}
_global_login_lock = threading.Lock()
_global_last_login = [0.0]


def _auth_lock(region):
    with _auth_locks_guard:
        return _auth_locks.setdefault(region, threading.Lock())


def _cooldown_state(region):
    with _cooldown_lock:
        now = time.time()
        cooldown_left = max(0, _login_cooldown.get(region, 0) - now)
        gap_left = max(0, MIN_LOGIN_GAP - (now - _last_login_at.get(region, 0)))
        return cooldown_left, gap_left


def _set_cooldown(region):
    with _cooldown_lock:
        n = _login_fail_streak.get(region, 0)
        _login_fail_streak[region] = n + 1
        _login_cooldown[region] = time.time() + min(LOGIN_COOLDOWN * (2 ** n), LOGIN_COOLDOWN_MAX)


def _clear_fail_streak(region):
    with _cooldown_lock:
        _login_fail_streak.pop(region, None)
        _login_cooldown.pop(region, None)


def _global_login_gate():
    with _global_login_lock:
        wait = GLOBAL_LOGIN_GAP - (time.time() - _global_last_login[0])
        if wait > 0:
            time.sleep(wait)
        _global_last_login[0] = time.time()


def _mark_login(region):
    with _cooldown_lock:
        _last_login_at[region] = time.time()


def _extract_game_server(result, region=""):
    value = result.get("10")
    if isinstance(value, dict) and "data" in value:
        url = value["data"]
        if isinstance(url, str) and url.startswith("http"):
            url = url.replace("ggpolarbear.com", "ppmainecoonghj.com").rstrip("/")
            if url == FALLBACK_GAME_SERVER and region in REGION_GAME_SERVER_CANDIDATES:
                return None
            return url
    if region in REGION_GAME_SERVER_CANDIDATES:
        return None
    return FALLBACK_GAME_SERVER


def _jwt_claims(jwt):
    try:
        part = str(jwt).split(".")[1]
        data = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        return {key: data[key] for key in ("lock_region", "noti_region", "country_code", "exp") if key in data}
    except Exception:
        return {}


def get_session(region, force=False):
    region = str(region).upper()
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

    cooldown_left, _ = _cooldown_state(region)
    if cooldown_left > 0:
        with _session_lock:
            hit = _session_cache.get(region)
            if hit:
                return hit[0], hit[1], None
        return None, None, f"Login cooldown for {region} ({int(cooldown_left)}s)"

    with _auth_lock(region):
        if not force:
            with _session_lock:
                hit = _session_cache.get(region)
                if hit and time.time() - hit[2] < SESSION_TTL:
                    return hit[0], hit[1], None

        cooldown_left, gap_left = _cooldown_state(region)
        if cooldown_left > 0:
            with _session_lock:
                hit = _session_cache.get(region)
                if hit:
                    return hit[0], hit[1], None
            return None, None, f"Login cooldown for {region} ({int(cooldown_left)}s)"

        throttle_left = _throttle_left()
        if throttle_left > 0:
            return None, None, f"Garena rate limit (429) - retry in {int(throttle_left)}s"

        if gap_left > 0:
            time.sleep(gap_left)

        account = next_account(region)
        if not account:
            return None, None, f"No account for region {region}"

        release_version, game_version, login_url, _gop_url, _app_ver, _ = version_config(region)
        log.info(
            "Login: %s uid=%s release=%s game=%s pid=%d",
            region, account["uid"], release_version, game_version, os.getpid()
        )
        _mark_login(region)

        result = None
        token_ok = False
        for attempt in range(1, LOGIN_ATTEMPTS + 1):
            _global_login_gate()
            token_grant = get_access_token(account["uid"], account["password"], region=region)
            if not token_grant:
                log.warning(
                    "get_access_token FAILED for %s uid=%s (try %d/%d)",
                    region, account["uid"], attempt, LOGIN_ATTEMPTS
                )
            else:
                token_ok = True
                open_id, access_token, platform = token_grant
                result = major_login(
                    get_payload(access_token, open_id, platform, game_version, region=region),
                    login_url,
                    release_version,
                    region=region,
                )
                if result and "8" in result:
                    break
                log.warning(
                    "MajorLogin FAILED for %s uid=%s (try %d/%d)",
                    region, account["uid"], attempt, LOGIN_ATTEMPTS
                )

            if _throttle_left() > 0:
                break
            if token_ok and sum(
                1 for a in load_accounts() if str(a.get("region", "")).upper() == region
            ) < 2:
                break
            if attempt < LOGIN_ATTEMPTS:
                time.sleep(3 * attempt)
                account = next_account(region) or account

        if not result or "8" not in result:
            _set_cooldown(region)
            if _throttle_left() > 0:
                return None, None, f"Garena rate limit (429) - retry in {int(_throttle_left())}s"
            return None, None, "MajorLogin failed" if token_ok else "Auth failed"

        jwt = result["8"]["data"] if isinstance(result["8"], dict) else result["8"]
        game_server = _extract_game_server(result, region)
        _clear_fail_streak(region)
        _token_block["streak"] = 0
        with _session_lock:
            _session_cache[region] = (jwt, game_server, time.time())
        log.info(
            "Session: %s uid=%s game_server=%s field10=%s jwt_claims=%s",
            region,
            account["uid"],
            game_server,
            (result.get("10") or {}).get("data") if isinstance(result.get("10"), dict) else None,
            _jwt_claims(jwt),
        )
        return jwt, game_server, None

# ==================== PLAYER INFO (GetPlayerPersonalShow) ====================
# Field numbers follow PlayerPersonalShow.proto. In Basic:
# field 11 = bannerid (901...); field 12 = headpic (902...).
# Profile.avatarid (normally 102...) is a separate profile field.
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
    "Duo": {
        1: ("partner_uid", "int"), 3: ("score", "int"), 4: ("creation_timestamp", "int"),
        5: ("days_active", "int"), 6: ("status", "int"),
    },
    "Diamond": {1: ("cost", "int")},
    "Credit": {1: ("score", "int"), 2: ("is_init", "bool")},
}

_GENDER = {1: "Male", 2: "Female"}
_LANGUAGE = {
    1: "English", 2: "Chinese (Simplified)", 3: "Chinese (Traditional)", 4: "Thai", 5: "Vietnamese",
    6: "Indonesian", 7: "Portuguese", 8: "Spanish", 9: "Russian", 10: "Korean", 11: "French",
    12: "German", 13: "Turkish", 14: "Hindi", 15: "Japanese", 16: "Romanian", 17: "Arabic",
    18: "Burmese", 19: "Urdu", 20: "Bengali", 21: "Malay",
}
_TIME_ONLINE = {1: "Online on weekdays", 2: "Online on weekends"}
_TIME_ACTIVE = {1: "Active in the morning", 2: "Active in the afternoon", 3: "Active at night"}
_MODE_PREFER = {1: "Battle Royale", 2: "Clash Squad", 3: "Entertainment"}
_BATTLE_TAGS = {
    1101: "Domination", 1102: "Uncrown", 1103: "Best partner", 1104: "Sniper", 1105: "Melee",
    1106: "Peacemaker", 1107: "Ambush", 1108: "Shortstop", 1109: "Rampage", 1110: "Leader",
}
_SOCIAL_TAGS = {
    2101: "Fashion", 2102: "Social", 2103: "Veteran", 2104: "Newbie", 2105: "Plays for the win",
    2106: "Plays for fun", 2107: "Voice on", 2108: "Voice off",
}


def _walk_fields(data):
    """Yield (field_number, wire_type, value) from raw protobuf bytes."""
    offset = 0
    while offset < len(data):
        header, offset = decode_varint(data, offset)
        if header is None:
            return
        field_number, wire_type = header >> 3, header & 0x7
        if wire_type == 0:
            value, offset = decode_varint(data, offset)
            if value is None:
                return
            yield field_number, wire_type, value
        elif wire_type == 2:
            length, offset = decode_varint(data, offset)
            if length is None or offset + length > len(data):
                return
            yield field_number, wire_type, data[offset:offset + length]
            offset += length
        elif wire_type == 1:
            offset += 8
        elif wire_type == 5:
            offset += 4
        else:
            return


def _pb_to_dict(data, msg_name):
    """Decode bytes into a dict using the _PS schema. Unknown fields are ignored."""
    schema = _PS[msg_name]
    out = {}
    for field_number, wire_type, value in _walk_fields(data):
        spec = schema.get(field_number)
        if not spec:
            continue
        name, kind = spec
        if kind == "int" and wire_type == 0:
            out[name] = value - (1 << 64) if value >= (1 << 63) else value
        elif kind == "bool" and wire_type == 0:
            out[name] = bool(value)
        elif kind == "str" and wire_type == 2:
            out[name] = value.decode("utf-8", "replace")
        elif kind == "rep_int":
            values = out.setdefault(name, [])
            if wire_type == 0:
                values.append(value)
            elif wire_type == 2:
                pos = 0
                while pos < len(value):
                    number, pos = decode_varint(value, pos)
                    if number is None:
                        break
                    values.append(number)
        elif kind.startswith("msg:") and wire_type == 2:
            out[name] = _pb_to_dict(value, kind[4:])
    return out


def _fmt_ts(ts, with_time=False):
    try:
        ts = int(ts or 0)
        if ts <= 0:
            return ""
        fmt = "%Y-%m-%d %H:%M" if with_time else "%Y-%m-%d"
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(fmt)
    except (ValueError, OSError, OverflowError, TypeError):
        return ""


def _clean_item_ids(ids):
    out = []
    for item_id in ids or []:
        if isinstance(item_id, int) and 100000000 <= item_id <= 999999999 and item_id not in out:
            out.append(item_id)
    return out


def parse_player_info(raw):
    """Raw GetPlayerPersonalShow bytes -> readable dict (None if not a player)."""
    info = _pb_to_dict(raw, "Response")
    basic = info.get("basic") or {}
    if not basic.get("nickname") and not basic.get("account_id"):
        return None
    return info


def build_profile(info, target_uid, region):
    basic = info.get("basic", {})
    profile = info.get("profile", {})
    clan = info.get("clan", {})
    social = info.get("social") or basic.get("social") or {}
    pet = info.get("pet", {})
    credit = info.get("credit", {})

    # Correct mapping from BasicInfo:
    #   head_pic  (field 12, normally 902...) -> displayed profile avatar
    #   banner_id (field 11, normally 901...) -> profile banner
    # Profile.avatar_id (usually 102...) is a separate field and is exposed separately.
    avatar_id = basic.get("head_pic") or 0
    banner_id = basic.get("banner_id") or 0
    profile_avatar_id = profile.get("avatar_id") or 0

    clan_name = clan.get("name") or basic.get("clan_name") or "No Clan"
    out = {
        "nickname": basic.get("nickname", "Unknown"),
        "uid": target_uid,
        "region": region.upper(),
        "server_region": basic.get("region", ""),
        "level": basic.get("level", 0),
        "exp": basic.get("exp", 0),
        "br_rank": basic.get("rank", 0),
        "br_points": basic.get("ranking_points", 0),
        "cs_rank": basic.get("cs_rank", 0),
        "cs_points": basic.get("cs_ranking_points", 0),
        "max_rank": basic.get("max_rank", 0),
        "cs_max_rank": basic.get("cs_max_rank", 0),
        "max_points": basic.get("max_ranking_points", 0),
        "cs_peak_points": basic.get("cs_peak_points", 0),
        "likes": basic.get("liked", 0),
        "created_at": _fmt_ts(basic.get("created_at")) or "Unknown",
        "last_login": _fmt_ts(basic.get("last_login_at"), with_time=True),
        "avatar_id": avatar_id,
        "banner_id": banner_id,
        "profile_avatar_id": profile_avatar_id,
        "clan_name": clan_name,
        "clan_id": clan.get("id") or basic.get("clan_id") or "",
        "title": basic.get("title", 0),
        "avatar_frame": basic.get("avatar_frame", 0),
        "badge_count": basic.get("badge_count", 0),
        "has_elite_pass": bool(basic.get("has_elite_pass")),
        "prime_level": (basic.get("prime") or {}).get("prime_level", 0),
        "release_version": basic.get("release_version", ""),
        "leaderboard_pos": info.get("leaderboard_pos", 0),
        "credit_score": credit.get("score", 0),
        "diamond_cost": (info.get("diamond") or {}).get("cost", 0),
        "signature": social.get("signature", ""),
        "gender": _GENDER.get(social.get("gender"), ""),
        "language": _LANGUAGE.get(social.get("language"), ""),
        "mode_prefer": _MODE_PREFER.get(social.get("mode_prefer"), ""),
        "time_online": _TIME_ONLINE.get(social.get("time_online"), ""),
        "time_active": _TIME_ACTIVE.get(social.get("time_active"), ""),
        "battle_tags": [_BATTLE_TAGS[tag] for tag in social.get("battle_tags", []) if tag in _BATTLE_TAGS],
        "social_tags": [_SOCIAL_TAGS[tag] for tag in social.get("social_tags", []) if tag in _SOCIAL_TAGS],
        "outfit_ids": _clean_item_ids(profile.get("clothes")),
        "weapon_skin_ids": _clean_item_ids(basic.get("weapon_skins")),
        "skill_ids": profile.get("equipped_skills", []),
    }
    if clan:
        out["clan"] = {
            "level": clan.get("level", 0),
            "members": clan.get("members", 0),
            "capacity": clan.get("capacity", 0),
            "honor": clan.get("honor_point", 0),
            "captain_id": clan.get("captain_id", ""),
        }
    if pet.get("name") or pet.get("id"):
        out["pet"] = {
            "name": pet.get("name", ""),
            "level": pet.get("level", 0),
            "exp": pet.get("exp", 0),
        }
    return out


def search_player_profile(target_uid, region, jwt_token, game_server):
    if not game_server:
        game_server = FALLBACK_GAME_SERVER
    url = f"{game_server.rstrip('/')}/GetPlayerPersonalShow"
    release_version = version_config(region)[0]
    headers = {
        "User-Agent": f"UnityPlayer/{INFO_UNITY_VERSION} (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {jwt_token}",
        "X-GA": "v1 1",
        "ReleaseVersion": release_version,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": INFO_UNITY_VERSION,
    }
    bodies = []
    if INFO_CALLSIGN:
        bodies.append({"1": int(target_uid), "2": INFO_CALLSIGN})
    bodies.append({"1": int(target_uid)})
    try:
        response = None
        for fields in bodies:
            payload = bytes.fromhex(encrypt_aes(create_proto(fields).hex()))
            response = _http.post(url, headers=headers, data=payload, timeout=TIMEOUT_PROFILE)
            if response.status_code == 200:
                break
        if response is None or response.status_code != 200:
            status = response.status_code if response is not None else "no response"
            return {"error": f"API error: HTTP {status}"}
        info = parse_player_info(response.content)
        if not info:
            return {"error": "Player not found in this region"}
        return build_profile(info, target_uid, region)
    except Exception as exc:
        log.exception("Player profile request failed")
        return {"error": str(exc)}

# ==================== PROFILE CACHE ====================
_profile_cache = {}
_profile_cache_lock = threading.Lock()


def lookup_profile(uid, region):
    uid = str(uid).strip()
    if not uid.isdigit():
        return {"error": "UID must be numeric"}
    jwt, game_server, error = get_session(region)
    if error:
        return {"error": error}
    details = search_player_profile(uid, region, jwt, game_server)
    if "error" in details and any(code in details["error"] for code in ("401", "403")):
        jwt, game_server, error = get_session(region, force=True)
        if error:
            return {"error": error}
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
SEARCH_BUDGET = float(os.environ.get("FF_SEARCH_BUDGET", "24"))
_region_hint = {}
_region_hint_lock = threading.Lock()


def _account_regions():
    return sorted({str(account.get("region", "PK")).upper() for account in load_accounts()})


def _profile_ok(data):
    return isinstance(data, dict) and "error" not in data and bool(data.get("nickname"))


def _has_session(region):
    with _session_lock:
        hit = _session_cache.get(region)
    return bool(hit and time.time() - hit[2] < SESSION_TTL)


def _finish_auto(data, found_region):
    reported = str(data.get("server_region") or "").upper()
    data["searched_via"] = found_region
    data["region"] = reported if REGION_RE.match(reported) else found_region
    with _region_hint_lock:
        _region_hint[str(data.get("uid"))] = (
            data["region"] if data["region"] in _account_regions() else found_region,
            time.time(),
        )
    return data


def lookup_profile_auto(uid, hint=None):
    """Try the remembered/default region first, then warm and remaining regions."""
    uid = str(uid).strip()
    regions = _account_regions()
    if not regions:
        return {"error": "No game accounts configured (FF_ACCOUNTS_JSON)", "code": 503}

    preferred = []
    with _region_hint_lock:
        hit = _region_hint.get(uid)
    if hit and time.time() - hit[1] < REGION_HINT_TTL:
        preferred.append(hit[0])
    if hint:
        preferred.append(str(hint).upper())
    order = preferred + [default_region()] + regions
    order = [region for index, region in enumerate(order) if region in regions and region not in order[:index]]

    deadline = time.time() + SEARCH_BUDGET
    errors = {}

    def try_region(region):
        result = lookup_profile_cached(uid, region)
        return result if isinstance(result, dict) else {"error": "Unknown error"}

    data = try_region(order[0])
    if _profile_ok(data):
        return _finish_auto(dict(data), order[0])
    errors[order[0]] = data.get("error", "Unknown error")

    def stop_now():
        return any("rate limit" in error.lower() for error in errors.values())

    warm = [region for region in order[1:] if _has_session(region)]
    if warm and not stop_now():
        with ThreadPoolExecutor(max_workers=min(4, len(warm))) as pool:
            futures = {pool.submit(try_region, region): region for region in warm}
            for future in as_completed(futures):
                region = futures[future]
                try:
                    data = future.result()
                except Exception as exc:
                    data = {"error": str(exc)}
                if _profile_ok(data):
                    for pending in futures:
                        pending.cancel()
                    return _finish_auto(dict(data), region)
                errors[region] = data.get("error", "Unknown error")

    for region in order[1:]:
        if region in errors or stop_now() or time.time() > deadline:
            continue
        data = try_region(region)
        if _profile_ok(data):
            return _finish_auto(dict(data), region)
        errors[region] = data.get("error", "Unknown error")

    unchecked = [region for region in order if region not in errors]
    for error in errors.values():
        if "rate limit" in error.lower():
            return {"error": error, "code": 429, "checked": sorted(errors)}
    not_found = [region for region, error in errors.items() if "not found" in error.lower()]
    if not_found:
        message = f"Player {uid} was not found in: {', '.join(sorted(not_found))}."
        if unchecked:
            message += f" Not checked (time ran out): {', '.join(unchecked)}."
        return {"error": message, "code": 404, "checked": sorted(errors), "unchecked": unchecked}
    first_error = next(iter(errors.values()), "Unknown error")
    return {"error": f"Could not look up any region ({first_error}).", "code": 503, "checked": sorted(errors)}

# ==================== ITEM IMAGES (avatar / banner / outfit) ====================
ITEM_API = os.environ.get("FF_ITEM_API", "https://getitems.thug4ff.xyz/item").strip()
_item_http = requests.Session()
_IMG_EXT = re.compile(r"\.(png|jpe?g|webp|gif)(\?|$)", re.I)


def item_url(item_id):
    try:
        item_id = int(item_id or 0)
    except (TypeError, ValueError):
        return ""
    return f"{ITEM_API}?id={item_id}" if item_id > 0 else ""


def _public_https(url):
    """Accept only HTTPS hostnames (no literal IP or localhost) from the item service."""
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.hostname.lower() == "localhost":
            return False
        try:
            ipaddress.ip_address(parsed.hostname)
            return False
        except ValueError:
            return True
    except Exception:
        return False


def _find_image_ref(obj, depth=0):
    if depth > 4:
        return None
    if isinstance(obj, str):
        if obj.startswith("data:image/"):
            return obj
        if obj.startswith("https://") and (_IMG_EXT.search(obj) or "icon" in obj.lower() or "image" in obj.lower()):
            return obj
    elif isinstance(obj, dict):
        for key in ("icon", "image", "img", "url", "icon_url", "image_url", "icon_path", "path"):
            if key in obj:
                found = _find_image_ref(obj[key], depth + 1)
                if found:
                    return found
        for value in obj.values():
            found = _find_image_ref(value, depth + 1)
            if found:
                return found
    elif isinstance(obj, list):
        for value in obj[:6]:
            found = _find_image_ref(value, depth + 1)
            if found:
                return found
    return None


def _image_from(url, timeout=6):
    response = _item_http.get(url, timeout=timeout)
    content_type = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if response.status_code == 200 and content_type.startswith("image/") and response.content:
        return response.content, content_type
    if response.status_code == 200 and "json" in content_type:
        reference = _find_image_ref(response.json())
        if reference and reference.startswith("data:image/"):
            header, b64_data = reference.split(",", 1)
            return base64.b64decode(b64_data), header[5:].split(";")[0]
        if reference and _public_https(reference):
            second = _item_http.get(reference, timeout=timeout)
            second_type = (second.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if second.status_code == 200 and second_type.startswith("image/") and second.content:
                return second.content, second_type
    return None


_item_cache = {}
_item_lock = threading.Lock()


def get_item_image(item_id):
    with _item_lock:
        hit = _item_cache.get(item_id)
    if hit and time.time() - hit[2] < 6 * 3600:
        return hit[0], hit[1]
    for url in (f"{ITEM_API}?id={item_id}", CDN_BASE.format(item_id)):
        try:
            found = _image_from(url)
            if found:
                with _item_lock:
                    if len(_item_cache) > 300:
                        _item_cache.clear()
                    _item_cache[item_id] = (found[0], found[1], time.time())
                return found
        except Exception as exc:
            log.info("item %s via %s failed: %s", item_id, url.split("?")[0], str(exc)[:80])
    return None

# ==================== SMALL PER-IP RATE LIMIT ====================
RATE_PER_MIN = int(os.environ.get("FF_RATE_PER_MIN", "20"))
_rate = {}
_rate_lock = threading.Lock()


def _client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return (forwarded.split(",")[0].strip() if forwarded else request.remote_addr) or "?"


def _rate_ok():
    now = time.time()
    ip = _client_ip()
    with _rate_lock:
        if len(_rate) > 2000:
            stale = [key for key, values in _rate.items() if not values or now - values[-1] > 60]
            for key in stale:
                _rate.pop(key, None)
        queue = [stamp for stamp in _rate.get(ip, []) if now - stamp < 60]
        if len(queue) >= RATE_PER_MIN:
            _rate[ip] = queue
            return False
        queue.append(now)
        _rate[ip] = queue
    return True

# ==================== WEB ====================
@app.after_request
def _cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "X-API-Key, Content-Type"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _public_profile(data):
    """Player profile plus image links. The IDs are kept separate by asset type."""
    out = dict(data)
    out["avatar_url"] = item_url(data.get("avatar_id"))
    out["banner_url"] = item_url(data.get("banner_id"))
    out["outfits"] = [{"id": item_id, "url": item_url(item_id)} for item_id in data.get("outfit_ids", [])]
    out["weapon_skins"] = [
        {"id": item_id, "url": item_url(item_id)} for item_id in data.get("weapon_skin_ids", [])
    ]
    out.pop("searched_via", None)
    return out


def _authorized():
    given = request.args.get("secret") or request.headers.get("X-API-Key") or ""
    return hmac.compare_digest(given.encode("utf-8"), API_SECRET.encode("utf-8"))


def _error(message, code):
    response = jsonify({"status": "error", "error": message})
    response.status_code = code
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/info", methods=["GET"])
@app.route("/api/info", methods=["GET"])
def api_info():
    if not _rate_ok():
        return _error("Too many requests. Try again in a minute.", 429)
    if not _authorized():
        return _error("Missing or wrong secret. Add &secret=YOUR_KEY (or send header X-API-Key).", 401)
    uid = (request.args.get("uid") or request.args.get("infouid") or "").strip()
    if not uid.isdigit() or not (5 <= len(uid) <= 14):
        return _error(
            "uid must be a number with 5 to 14 digits, e.g. /info?uid=123456789&secret=YOUR_KEY",
            400,
        )
    data = lookup_profile_auto(uid, hint=ONLY_REGION)
    if "error" in data:
        return _error(data["error"], int(data.get("code") or 502))
    response = jsonify({"status": "success", **_public_profile(data)})
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.route("/api/item", methods=["GET"])
def api_item():
    raw_id = (request.args.get("id") or "").strip()
    if not raw_id.isdigit() or len(raw_id) > 12:
        return Response("bad id", 400)
    item_id = int(raw_id)
    found = get_item_image(item_id)
    if not found:
        return Response("not found", 404, headers={"Cache-Control": "public, s-maxage=600"})
    return Response(
        found[0],
        mimetype=found[1],
        headers={"Cache-Control": "public, max-age=86400, s-maxage=604800, immutable"},
    )


@app.route("/api/health", methods=["GET"])
def api_health():
    if not _authorized():
        return _error("Missing or wrong secret.", 401)
    return jsonify({
        "ok": True,
        "accounts_per_region": _accounts_per_region(),
        "login_errors": dict(_login_errors),
        "garena_rate_limit_seconds_left": int(_throttle_left()),
    })


def _accounts_per_region():
    counts = {}
    for account in load_accounts():
        region = str(account.get("region", "")).upper()
        counts[region] = counts.get(region, 0) + 1
    return counts


# Vercel imports `app` as the WSGI application. For local testing, run this file directly.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
