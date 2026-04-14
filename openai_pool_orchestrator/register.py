import json
import os
import re
import sys
import time
import uuid
import math
import random
import string
import secrets
import socket
import hashlib
import base64
import threading
import argparse
import queue
import tempfile
import contextvars
from http.cookies import SimpleCookie
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass
from typing import Any, Dict, Optional, Callable
import urllib.parse
import urllib.request
import urllib.error

from curl_cffi import requests

try:
    from .fingerprint_profile import (
        FingerprintProfile,
        build_default_fingerprint_profile,
        build_sec_ch_headers,
        describe_fingerprint,
        generate_fingerprint_profile,
    )
except ImportError:
    from fingerprint_profile import (  # type: ignore
        FingerprintProfile,
        build_default_fingerprint_profile,
        build_sec_ch_headers,
        describe_fingerprint,
        generate_fingerprint_profile,
    )
try:
    from .token_compat import AUTH_CLAIM_KEY, decode_jwt_payload, normalize_token_data
except ImportError:
    from token_compat import AUTH_CLAIM_KEY, decode_jwt_payload, normalize_token_data  # type: ignore

# ==========================================
# 日志事件发射器
# ==========================================


class EventEmitter:
    """
    将注册流程中的日志事件发射到队列，供 SSE 消费。
    同时支持 CLI 模式（直接 print）。
    """

    def __init__(
        self,
        q: Optional[queue.Queue] = None,
        cli_mode: bool = False,
        defaults: Optional[Dict[str, Any]] = None,
    ):
        self._q = q
        self._cli_mode = cli_mode
        self._defaults = dict(defaults or {})

    def emit(self, level: str, message: str, step: str = "", **extra: Any) -> None:
        """
        level: "info" | "success" | "error" | "warn"
        step:  可选的流程阶段标识，如 "check_proxy" / "create_email" 等
        """
        ts = datetime.now().strftime("%H:%M:%S")
        event = {
            "ts": ts,
            "level": level,
            "message": message,
            "step": step,
        }
        if self._defaults:
            event.update(self._defaults)
        if extra:
            event.update({k: v for k, v in extra.items() if v is not None})
        if self._cli_mode:
            prefix_map = {
                "info": "[*]",
                "success": "[+]",
                "error": "[Error]",
                "warn": "[!]",
            }
            prefix = prefix_map.get(level, "[*]")
            print(f"{prefix} {message}")
        if self._q is not None:
            try:
                self._q.put_nowait(event)
            except queue.Full:
                pass

    def bind(self, **defaults: Any) -> "EventEmitter":
        merged = dict(self._defaults)
        merged.update({k: v for k, v in defaults.items() if v is not None})
        return EventEmitter(q=self._q, cli_mode=self._cli_mode, defaults=merged)

    def info(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("info", msg, step, **extra)

    def success(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("success", msg, step, **extra)

    def error(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("error", msg, step, **extra)

    def warn(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("warn", msg, step, **extra)


# 默认 CLI 发射器（兼容直接运行）
_cli_emitter = EventEmitter(cli_mode=True)


def _interruptible_sleep(seconds: float, stop_event: Optional[threading.Event] = None) -> bool:
    duration = max(0.0, float(seconds or 0))
    if duration <= 0:
        return bool(stop_event and stop_event.is_set())
    if stop_event is None:
        time.sleep(duration)
        return False
    return stop_event.wait(duration)


# ==========================================
# Mail.tm 临时邮箱 API
# ==========================================

MAILTM_BASE = "https://api.mail.tm"
DEFAULT_PROXY_POOL_URL = "https://zenproxy.top/api/fetch"
DEFAULT_PROXY_POOL_AUTH_MODE = "query"
DEFAULT_PROXY_POOL_API_KEY = "19c0ec43-8f76-4c97-81bc-bcda059eeba4"
DEFAULT_PROXY_POOL_COUNT = 1
DEFAULT_PROXY_POOL_COUNTRY = "US"
DEFAULT_HTTP_VERSION = "v2"
H3_PROXY_ERROR_HINT = "HTTP/3 is not supported over an HTTP proxy"
TRANSIENT_TLS_ERROR_HINTS = (
    "curl: (35)",
    "TLS connect error",
    "OPENSSL_internal:invalid library",
    "SSL_ERROR_SYSCALL",
)
TRANSIENT_TLS_RETRY_COUNT = 2
POOL_RELAY_RETRIES = 2
POOL_PROXY_FETCH_RETRIES = 3
POOL_RELAY_REQUEST_RETRIES = 2
OPENAI_AUTH_BASE = "https://auth.openai.com"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
COMMON_HEADERS = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "origin": OPENAI_AUTH_BASE,
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}
NAVIGATE_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}

DEFAULT_FINGERPRINT_PROFILE = build_default_fingerprint_profile()
_ACTIVE_FINGERPRINT_PROFILE = contextvars.ContextVar(
    "active_fingerprint_profile",
    default=None,
)


def _get_active_fingerprint_profile() -> FingerprintProfile:
    return _ACTIVE_FINGERPRINT_PROFILE.get() or DEFAULT_FINGERPRINT_PROFILE


def _current_user_agent() -> str:
    return _get_active_fingerprint_profile().user_agent


def _current_impersonate() -> str:
    return _get_active_fingerprint_profile().curl_impersonate


def _build_common_headers() -> Dict[str, str]:
    profile = _get_active_fingerprint_profile()
    headers = {
        "accept": "application/json",
        "accept-language": profile.accept_language,
        "origin": OPENAI_AUTH_BASE,
        "user-agent": profile.user_agent,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }
    headers.update(build_sec_ch_headers(profile))
    return headers


def _build_navigate_headers() -> Dict[str, str]:
    profile = _get_active_fingerprint_profile()
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept-language": profile.accept_language,
        "user-agent": profile.user_agent,
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    }
    headers.update(build_sec_ch_headers(profile))
    return headers


def _generate_datadog_trace() -> Dict[str, str]:
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), "016x")
    parent_hex = format(int(parent_id), "016x")
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def _random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    pwd = list(
        secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.digits)
        + secrets.choice("!@#$%")
        + "".join(secrets.choice(chars) for _ in range(max(4, length) - 4))
    )
    random.shuffle(pwd)
    return "".join(pwd)


def _random_profile_name() -> str:
    first_names = [
        "James", "Emma", "Liam", "Olivia", "Noah", "Ava", "Ethan", "Sophia",
        "Lucas", "Mia", "Mason", "Isabella", "Logan", "Charlotte", "Alexander",
        "Amelia", "Benjamin", "Harper", "William", "Evelyn", "Henry", "Abigail",
        "Sebastian", "Emily", "Jack", "Elizabeth",
    ]
    last_names = [
        "Smith", "Johnson", "Brown", "Davis", "Wilson", "Moore", "Taylor",
        "Clark", "Hall", "Young", "Anderson", "Thomas", "Jackson", "White",
        "Harris", "Martin", "Thompson", "Garcia", "Robinson", "Lewis",
        "Walker", "Allen", "King", "Wright", "Scott", "Green",
    ]
    return f"{random.choice(first_names)} {random.choice(last_names)}"


def _random_profile_birthdate() -> str:
    year = random.randint(1985, 2002)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year}-{month:02d}-{day:02d}"


def _build_openai_headers(
    referer: str,
    device_id: str,
    *,
    sentinel_token: str = "",
    accept: str = "application/json",
    content_type: Optional[str] = "application/json",
) -> Dict[str, str]:
    headers = _build_common_headers()
    headers["referer"] = referer
    headers["oai-device-id"] = device_id
    headers.update(_generate_datadog_trace())
    if accept:
        headers["accept"] = accept
    if content_type:
        headers["content-type"] = content_type
    if sentinel_token:
        headers["openai-sentinel-token"] = sentinel_token
    return headers


class _SentinelTokenGenerator:
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id: Optional[str] = None):
        self.device_id = device_id or str(uuid.uuid4())
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        h &= 0xFFFFFFFF
        return format(h, "08x")

    @staticmethod
    def _base64_encode(data: Any) -> str:
        js = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        return base64.b64encode(js.encode("utf-8")).decode("ascii")

    def _get_config(self) -> list[Any]:
        profile = _get_active_fingerprint_profile()
        now = datetime.now(timezone.utc).strftime(
            "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)"
        )
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        return [
            f"{profile.screen_width}x{profile.screen_height}",
            now,
            4294705152,
            random.random(),
            profile.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None,
            None,
            profile.language,
            profile.languages_header,
            random.random(),
            "vendorSub−undefined",
            "location",
            "Object",
            perf_now,
            self.sid,
            "",
            profile.hardware_concurrency,
            time_origin,
        ]

    def _run_check(
        self,
        start_time: float,
        seed: str,
        difficulty: str,
        config: list[Any],
        nonce: int,
    ) -> Optional[str]:
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        if hash_hex[: len(difficulty)] <= difficulty:
            return data + "~S"
        return None

    def generate_requirements_token(self) -> str:
        cfg = self._get_config()
        cfg[3] = 1
        cfg[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._base64_encode(cfg)

    def generate_token(
        self,
        seed: Optional[str] = None,
        difficulty: Optional[str] = None,
    ) -> str:
        if seed is None:
            seed = self.requirements_seed
            difficulty = difficulty or "0"
        cfg = self._get_config()
        start = time.time()
        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start, seed, difficulty or "0", cfg, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))


def _build_sentinel_token(
    device_id: str,
    flow: str = "authorize_continue",
    emitter: Optional[EventEmitter] = None,
    post_func: Optional[Callable[..., Any]] = None,
) -> Optional[str]:
    profile = _get_active_fingerprint_profile()
    gen = _SentinelTokenGenerator(device_id=device_id)
    body = {"p": gen.generate_requirements_token(), "id": device_id, "flow": flow}
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "User-Agent": profile.user_agent,
        "Origin": "https://sentinel.openai.com",
    }
    headers.update(build_sec_ch_headers(profile))
    sender = post_func or requests.post
    try:
        resp = sender(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers=headers,
            data=json.dumps(body),
        )
    except Exception as exc:
        if emitter:
            emitter.error(f"Sentinel 请求异常: {exc}", step="sentinel")
        return None
    if resp.status_code != 200:
        if emitter:
            body_preview = str(resp.text or "")[:200].replace("\n", " ")
            emitter.error(
                f"Sentinel 返回异常: {resp.status_code}, body={body_preview}",
                step="sentinel",
            )
        return None
    try:
        data = resp.json()
    except Exception:
        if emitter:
            body_preview = str(resp.text or "")[:200].replace("\n", " ")
            emitter.error(f"Sentinel 响应解析失败: {body_preview}", step="sentinel")
        return None
    if not isinstance(data, dict):
        return None
    c_value = str(data.get("token") or "")
    pow_data = data.get("proofofwork", {}) or {}
    if isinstance(pow_data, dict) and pow_data.get("required") and pow_data.get("seed"):
        p_value = gen.generate_token(
            seed=str(pow_data.get("seed")),
            difficulty=str(pow_data.get("difficulty", "0")),
        )
    else:
        p_value = gen.generate_requirements_token()
    return json.dumps(
        {"p": p_value, "t": "", "c": c_value, "id": device_id, "flow": flow}
    )


def _is_transient_tls_error(exc: Exception | str) -> bool:
    message = str(exc or "")
    return any(hint in message for hint in TRANSIENT_TLS_ERROR_HINTS)


def _call_with_http_fallback(request_func, url: str, **kwargs: Any):
    """
    curl_cffi 在某些站点可能优先尝试 H3，遇到 HTTP 代理不支持时自动降级到 HTTP/1.1 重试。
    对 curl TLS 握手异常（如 curl: (35)）也进行有限重试，并优先降级到 HTTP/1.1。
    """
    try:
        return request_func(url, **kwargs)
    except Exception as exc:
        message = str(exc)
        if H3_PROXY_ERROR_HINT in message:
            retry_kwargs = dict(kwargs)
            retry_kwargs["http_version"] = "v1"
            return request_func(url, **retry_kwargs)
        if not _is_transient_tls_error(message):
            raise

        last_exc: Exception = exc
        candidate_kwargs_list = [dict(kwargs)]
        if str(kwargs.get("http_version") or "").strip().lower() != "v1":
            retry_kwargs = dict(kwargs)
            retry_kwargs["http_version"] = "v1"
            candidate_kwargs_list.append(retry_kwargs)

        for candidate_kwargs in candidate_kwargs_list:
            for attempt in range(TRANSIENT_TLS_RETRY_COUNT):
                time.sleep(min(0.35 * (attempt + 1), 1.0))
                try:
                    return request_func(url, **candidate_kwargs)
                except Exception as retry_exc:
                    last_exc = retry_exc
                    retry_message = str(retry_exc)
                    if H3_PROXY_ERROR_HINT in retry_message and str(candidate_kwargs.get("http_version") or "").strip().lower() != "v1":
                        candidate_kwargs = dict(candidate_kwargs)
                        candidate_kwargs["http_version"] = "v1"
                        continue
                    if not _is_transient_tls_error(retry_message):
                        raise
        raise last_exc

def _normalize_proxy_value(proxy_value: Any) -> str:
    value = str(proxy_value or "").strip().strip('"').strip("'")
    if not value:
        return ""
    if value.startswith("{") or value.startswith("[") or value.startswith("<"):
        return ""
    if "://" in value:
        return value
    if ":" not in value:
        return ""
    return f"http://{value}"


def _to_proxies_dict(proxy_value: str) -> Optional[Dict[str, str]]:
    normalized = _normalize_proxy_value(proxy_value)
    if not normalized:
        return None
    return {"http": normalized, "https": normalized}


def _build_proxy_from_host_port(host: Any, port: Any, proxy_type: Any = "") -> str:
    host_value = str(host or "").strip()
    port_value = str(port or "").strip()
    if not host_value or not port_value:
        return ""
    proxy_type_value = str(proxy_type or "").strip().lower()
    if proxy_type_value in ("socks5", "socks", "shadowsocks"):
        return _normalize_proxy_value(f"socks5://{host_value}:{port_value}")
    return _normalize_proxy_value(f"http://{host_value}:{port_value}")


def _pool_host_from_api_url(api_url: str) -> str:
    raw = str(api_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        return str(parsed.hostname or "").strip()
    except Exception:
        return ""


def _pool_relay_url_from_fetch_url(api_url: str) -> str:
    raw = str(api_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc
        if not netloc:
            return ""
        return f"{scheme}://{netloc}/api/relay"
    except Exception:
        return ""


def _trace_via_pool_relay(pool_cfg: Dict[str, Any]) -> str:
    relay_url = _pool_relay_url_from_fetch_url(str(pool_cfg.get("api_url") or ""))
    if not relay_url:
        raise RuntimeError("代理池 relay 地址解析失败")

    api_key = str(pool_cfg.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY
    country = str(pool_cfg.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY
    timeout = int(pool_cfg.get("timeout_seconds") or 10)
    timeout = max(8, min(timeout, 30))

    params = {
        "api_key": api_key,
        "url": "https://cloudflare.com/cdn-cgi/trace",
        "country": country,
    }
    retry_count = max(1, int(pool_cfg.get("relay_retries") or POOL_RELAY_RETRIES))
    last_error = ""
    for i in range(retry_count):
        try:
            resp = _call_with_http_fallback(
                requests.get,
                relay_url,
                params=params,
                impersonate=_current_impersonate(),
                timeout=timeout,
            )
            if resp.status_code == 200:
                return str(resp.text or "")
            last_error = f"HTTP {resp.status_code}"
        except Exception as exc:
            last_error = str(exc)
        if i < retry_count - 1:
            time.sleep(min(0.3 * (i + 1), 1.0))
    raise RuntimeError(f"代理池 relay 请求失败: {last_error or 'unknown error'}")
def _extract_proxy_from_obj(obj: Any, relay_host: str = "") -> str:
    if isinstance(obj, str):
        return _normalize_proxy_value(obj)
    if isinstance(obj, (list, tuple)):
        for item in obj:
            proxy = _extract_proxy_from_obj(item, relay_host)
            if proxy:
                return proxy
        return ""
    if isinstance(obj, dict):
        local_port = obj.get("local_port")
        if local_port in (None, ""):
            local_port = obj.get("localPort")
        if local_port not in (None, ""):
            # ZenProxy 文档中的 local_port 是代理绑定端口，优先使用 api_url 主机名。
            if relay_host:
                proxy = _normalize_proxy_value(f"http://{relay_host}:{local_port}")
                if proxy:
                    return proxy
            proxy = _normalize_proxy_value(f"http://127.0.0.1:{local_port}")
            if proxy:
                return proxy

        host = str(obj.get("ip") or obj.get("host") or obj.get("server") or "").strip()
        port = str(obj.get("port") or "").strip()
        proxy_type = obj.get("type") or obj.get("protocol") or obj.get("scheme") or ""
        if host and port:
            proxy = _build_proxy_from_host_port(host, port, proxy_type)
            if proxy:
                return proxy

        for key in ("proxy", "proxy_url", "url", "value", "result", "data", "proxy_list", "list", "proxies"):
            if key in obj:
                proxy = _extract_proxy_from_obj(obj.get(key), relay_host)
                if proxy:
                    return proxy

        for value in obj.values():
            proxy = _extract_proxy_from_obj(value, relay_host)
            if proxy:
                return proxy
    return ""


def _proxy_tcp_reachable(proxy_url: str, timeout_seconds: float = 1.2) -> bool:
    value = str(proxy_url or "").strip()
    if not value:
        return False
    if "://" not in value:
        value = "http://" + value
    try:
        parsed = urlparse(value)
        host = str(parsed.hostname or "").strip()
        port = int(parsed.port or 0)
    except Exception:
        return False
    if not host or port <= 0:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except Exception:
        return False


def _fetch_proxy_from_pool(pool_cfg: Dict[str, Any]) -> str:
    enabled = bool(pool_cfg.get("enabled"))
    if not enabled:
        return ""

    api_url = str(pool_cfg.get("api_url") or DEFAULT_PROXY_POOL_URL).strip() or DEFAULT_PROXY_POOL_URL
    auth_mode = str(pool_cfg.get("auth_mode") or DEFAULT_PROXY_POOL_AUTH_MODE).strip().lower()
    if auth_mode not in ("header", "query"):
        auth_mode = DEFAULT_PROXY_POOL_AUTH_MODE
    api_key = str(pool_cfg.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY
    relay_host = str(pool_cfg.get("relay_host") or "").strip()
    if not relay_host:
        relay_host = _pool_host_from_api_url(api_url)
    try:
        count = int(pool_cfg.get("count") or DEFAULT_PROXY_POOL_COUNT)
    except (TypeError, ValueError):
        count = DEFAULT_PROXY_POOL_COUNT
    count = max(1, min(count, 20))
    country = str(pool_cfg.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY
    timeout = int(pool_cfg.get("timeout_seconds") or 10)
    timeout = max(3, min(timeout, 30))

    headers: Dict[str, str] = {}
    params: Dict[str, str] = {"count": str(count), "country": country}
    if auth_mode == "query":
        params["api_key"] = api_key
    else:
        headers["Authorization"] = f"Bearer {api_key}"

    resp = _call_with_http_fallback(
        requests.get,
        api_url,
        headers=headers or None,
        params=params or None,
        http_version=DEFAULT_HTTP_VERSION,
        impersonate=_current_impersonate(),
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"代理池请求失败: HTTP {resp.status_code}")

    proxy = ""
    try:
        payload = resp.json()
        if isinstance(payload, dict):
            proxies = payload.get("proxies")
            if isinstance(proxies, list):
                for item in proxies:
                    proxy = _extract_proxy_from_obj(item, relay_host)
                    if proxy:
                        break
        if not proxy:
            proxy = _extract_proxy_from_obj(payload, relay_host)
    except Exception:
        proxy = ""

    if not proxy:
        proxy = _normalize_proxy_value(resp.text)
    if not proxy:
        raise RuntimeError("代理池响应中未找到可用代理")
    return proxy


def _resolve_request_proxies(
    default_proxies: Any = None,
    proxy_selector: Optional[Callable[[], Any]] = None,
) -> Any:
    if not proxy_selector:
        return default_proxies
    try:
        selected = proxy_selector()
        if selected is not None:
            return selected
    except Exception:
        pass
    return default_proxies


def _mailtm_headers(*, token: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _mailtm_domains(proxies: Any = None) -> list[str]:
    resp = _call_with_http_fallback(
        requests.get,
        f"{MAILTM_BASE}/domains",
        headers=_mailtm_headers(),
        proxies=proxies,
        http_version=DEFAULT_HTTP_VERSION,
        impersonate=_current_impersonate(),
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"获取 Mail.tm 域名失败，状态码: {resp.status_code}")

    data = resp.json()
    domains = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("hydra:member") or data.get("items") or []
    else:
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip()
        is_active = item.get("isActive", True)
        is_private = item.get("isPrivate", False)
        if domain and is_active and not is_private:
            domains.append(domain)

    return domains


def get_email_and_token(
    proxies: Any = None,
    emitter: EventEmitter = _cli_emitter,
    proxy_selector: Optional[Callable[[], Any]] = None,
) -> tuple[str, str]:
    """创建 Mail.tm 邮箱并获取 Bearer Token"""
    try:
        domains = _mailtm_domains(_resolve_request_proxies(proxies, proxy_selector))
        if not domains:
            emitter.error("Mail.tm 没有可用域名", step="create_email")
            return "", ""
        domain = random.choice(domains)

        for _ in range(5):
            local = f"oc{secrets.token_hex(5)}"
            email = f"{local}@{domain}"
            password = secrets.token_urlsafe(18)

            create_resp = _call_with_http_fallback(
                requests.post,
                f"{MAILTM_BASE}/accounts",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=_resolve_request_proxies(proxies, proxy_selector),
                http_version=DEFAULT_HTTP_VERSION,
                impersonate=_current_impersonate(),
                timeout=15,
            )

            if create_resp.status_code not in (200, 201):
                continue

            token_resp = _call_with_http_fallback(
                requests.post,
                f"{MAILTM_BASE}/token",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=_resolve_request_proxies(proxies, proxy_selector),
                http_version=DEFAULT_HTTP_VERSION,
                impersonate=_current_impersonate(),
                timeout=15,
            )

            if token_resp.status_code == 200:
                token = str(token_resp.json().get("token") or "").strip()
                if token:
                    return email, token

        emitter.error("Mail.tm 邮箱创建成功但获取 Token 失败", step="create_email")
        return "", ""
    except Exception as e:
        emitter.error(f"请求 Mail.tm API 出错: {e}", step="create_email")
        return "", ""


def _get_mailtm_seen_message_ids(mailbox_key: str) -> set[str]:
    tls = getattr(get_oai_code, "_tls", None)
    if tls is None:
        tls = threading.local()
        setattr(get_oai_code, "_tls", tls)
    store = getattr(tls, "seen_message_ids_store", None)
    if store is None:
        store = {}
        setattr(tls, "seen_message_ids_store", store)
    key = str(mailbox_key or "_default")
    seen_ids = store.get(key)
    if seen_ids is None:
        seen_ids = set()
        store[key] = seen_ids
    return seen_ids


def get_oai_code(
    token: str, email: str, proxies: Any = None, emitter: EventEmitter = _cli_emitter,
    stop_event: Optional[threading.Event] = None,
    proxy_selector: Optional[Callable[[], Any]] = None,
    timeout_seconds: Optional[int] = None,
) -> str:
    """使用 Mail.tm Token 轮询获取 OpenAI 验证码"""
    url_list = f"{MAILTM_BASE}/messages"
    regex = r"(?<!\d)(\d{6})(?!\d)"
    seen_ids = _get_mailtm_seen_message_ids(f"{email}|{token}")
    wait_timeout = max(3, int(timeout_seconds or 120))
    deadline = time.time() + wait_timeout
    poll_round = 0

    emitter.info(f"正在等待邮箱 {email} 的验证码...", step="wait_otp")

    while time.time() < deadline:
        poll_round += 1
        if stop_event and stop_event.is_set():
            return ""
        try:
            resp = _call_with_http_fallback(
                requests.get,
                url_list,
                headers=_mailtm_headers(token=token),
                proxies=_resolve_request_proxies(proxies, proxy_selector),
                http_version=DEFAULT_HTTP_VERSION,
                impersonate=_current_impersonate(),
                timeout=15,
            )
            if resp.status_code != 200:
                sleep_seconds = min(3.0, max(0.0, deadline - time.time()))
                if sleep_seconds <= 0:
                    break
                if _interruptible_sleep(sleep_seconds, stop_event):
                    return ""
                continue

            data = resp.json()
            if isinstance(data, list):
                messages = data
            elif isinstance(data, dict):
                messages = data.get("hydra:member") or data.get("messages") or []
            else:
                messages = []

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue

                read_resp = _call_with_http_fallback(
                    requests.get,
                    f"{MAILTM_BASE}/messages/{msg_id}",
                    headers=_mailtm_headers(token=token),
                    proxies=_resolve_request_proxies(proxies, proxy_selector),
                    http_version=DEFAULT_HTTP_VERSION,
                    impersonate=_current_impersonate(),
                    timeout=15,
                )
                if read_resp.status_code != 200:
                    continue
                seen_ids.add(msg_id)

                mail_data = read_resp.json()
                sender = str(
                    ((mail_data.get("from") or {}).get("address") or "")
                ).lower()
                subject = str(mail_data.get("subject") or "")
                intro = str(mail_data.get("intro") or "")
                text = str(mail_data.get("text") or "")
                html = mail_data.get("html") or ""
                if isinstance(html, list):
                    html = "\n".join(str(x) for x in html)
                content = "\n".join([subject, intro, text, str(html)])

                if "openai" not in sender and "openai" not in content.lower():
                    continue

                m = re.search(regex, content)
                if m:
                    emitter.info(
                        "验证码邮件命中: "
                        + f"message_id={_mask_secret(msg_id, head=10, tail=4)}, "
                        + f"sender={_mask_secret(sender, head=18, tail=8)}, "
                        + f"subject={_preview_text(subject, 80)}",
                        step="wait_otp",
                    )
                    emitter.success(f"验证码已到达: {m.group(1)}", step="wait_otp")
                    return m.group(1)
        except Exception:
            pass

        # 每轮等待时输出进度
        if poll_round % 5 == 0:
            waited_seconds = min(wait_timeout, max(0, int(wait_timeout - max(0.0, deadline - time.time()))))
            emitter.info(f"已等待 {waited_seconds} 秒，继续轮询...", step="wait_otp")
        sleep_seconds = min(3.0, max(0.0, deadline - time.time()))
        if sleep_seconds <= 0:
            break
        if _interruptible_sleep(sleep_seconds, stop_event):
            return ""

    emitter.error(f"超时，未收到验证码（{wait_timeout}s）", step="wait_otp")
    return ""


# ==========================================
# OAuth 授权与辅助函数
# ==========================================

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

DEFAULT_REDIRECT_URI = f"http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _mask_secret(value: Any, head: int = 16, tail: int = 10) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if len(raw) <= head:
        return raw
    if len(raw) <= head + tail:
        return f"{raw[:head]}..."
    return f"{raw[:head]}...{raw[-tail:]}"


def _preview_text(value: Any, limit: int = 200) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


INTERESTING_AUTH_KEYS = {
    "workspace",
    "workspaces",
    "workspace_id",
    "org",
    "orgs",
    "org_id",
    "organization",
    "organizations",
    "project",
    "projects",
    "project_id",
    "continue_url",
    "redirect_url",
    "url",
    "page",
}


def _safe_dict_keys(data: Any, limit: int = 8) -> list[str]:
    if not isinstance(data, dict):
        return []
    return [str(k) for k in list(data.keys())[:limit]]


def _cookie_candidate_values(raw_cookie: str) -> list[tuple[str, str]]:
    variants: list[tuple[str, str]] = []
    raw = str(raw_cookie or "").strip()
    if not raw:
        return variants

    def _append(label: str, value: str) -> None:
        normalized = str(value or "").strip()
        if not normalized:
            return
        if (normalized.startswith('"') and normalized.endswith('"')) or (
            normalized.startswith("'") and normalized.endswith("'")
        ):
            normalized = normalized[1:-1].strip()
        if not normalized:
            return
        for existing_label, existing_value in variants:
            if existing_value == normalized:
                return
        variants.append((label, normalized))

    _append("raw", raw)
    try:
        decoded = urllib.parse.unquote(raw)
        if decoded != raw:
            _append("unquote", decoded)
    except Exception:
        pass
    return variants


def _try_parse_json_text(raw_text: str) -> Dict[str, Any]:
    text = str(raw_text or "").strip()
    if not text:
        return {}
    if not ((text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]"))):
        return {}
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _try_decode_b64_json(raw_text: str) -> Dict[str, Any]:
    text = str(raw_text or "").strip()
    if not text or "." in text:
        return {}
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((text + pad).encode("ascii"))
        data = json.loads(decoded.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _summarize_interesting_value(value: Any) -> str:
    if isinstance(value, dict):
        keys = ",".join(_safe_dict_keys(value, 6)) or "-"
        return f"dict(keys={keys})"
    if isinstance(value, list):
        sample_ids: list[str] = []
        for item in value[:3]:
            if isinstance(item, dict):
                candidate_id = str(
                    item.get("id")
                    or item.get("workspace_id")
                    or item.get("org_id")
                    or item.get("project_id")
                    or ""
                ).strip()
                if candidate_id:
                    sample_ids.append(_mask_secret(candidate_id, head=12, tail=6))
        suffix = f", ids={','.join(sample_ids)}" if sample_ids else ""
        return f"list(len={len(value)}{suffix})"
    if isinstance(value, str):
        return _mask_secret(value, head=18, tail=8)
    return str(value)


def _collect_interesting_paths(value: Any, limit: int = 8) -> list[Dict[str, str]]:
    results: list[Dict[str, str]] = []

    def _walk(node: Any, path: str = "") -> None:
        if len(results) >= limit:
            return
        if isinstance(node, dict):
            for key, child in node.items():
                key_text = str(key or "").strip()
                child_path = f"{path}.{key_text}" if path else key_text
                if key_text.lower() in INTERESTING_AUTH_KEYS:
                    results.append(
                        {
                            "path": child_path,
                            "summary": _summarize_interesting_value(child),
                        }
                    )
                    if len(results) >= limit:
                        return
                if isinstance(child, (dict, list)):
                    _walk(child, child_path)
                    if len(results) >= limit:
                        return
        elif isinstance(node, list):
            for index, child in enumerate(node[:3]):
                if isinstance(child, (dict, list)):
                    child_path = f"{path}[{index}]" if path else f"[{index}]"
                    _walk(child, child_path)
                    if len(results) >= limit:
                        return

    _walk(value)
    return results


def _format_interesting_paths(paths: list[Dict[str, str]]) -> str:
    if not paths:
        return "-"
    return " | ".join(f"{item['path']}={item['summary']}" for item in paths[:8])


def _collect_workspace_ids(value: Any, limit: int = 5) -> list[str]:
    workspace_ids: list[str] = []

    def _append(candidate: Any) -> None:
        wid = str(candidate or "").strip()
        if wid and wid not in workspace_ids and len(workspace_ids) < limit:
            workspace_ids.append(wid)

    def _walk(node: Any) -> None:
        if len(workspace_ids) >= limit:
            return
        if isinstance(node, dict):
            for key, child in node.items():
                key_text = str(key or "").strip().lower()
                if key_text == "workspace_id":
                    _append(child)
                elif key_text == "workspaces" and isinstance(child, list):
                    for item in child[:limit]:
                        if isinstance(item, dict):
                            _append(item.get("id") or item.get("workspace_id"))
                if isinstance(child, (dict, list)):
                    _walk(child)
                    if len(workspace_ids) >= limit:
                        return
        elif isinstance(node, list):
            for child in node[:limit]:
                if isinstance(child, (dict, list)):
                    _walk(child)
                    if len(workspace_ids) >= limit:
                        return

    _walk(value)
    return workspace_ids


def _response_cookie_names(resp: Any) -> list[str]:
    names: list[str] = []
    try:
        for key in (resp.cookies or {}).keys():
            name = str(key or "").strip()
            if name and name not in names:
                names.append(name)
    except Exception:
        pass

    set_cookie_values: list[str] = []
    try:
        values = resp.headers.get_list("set-cookie")  # type: ignore[attr-defined]
        if values:
            set_cookie_values.extend(str(v or "") for v in values if str(v or "").strip())
    except Exception:
        pass
    if not set_cookie_values:
        try:
            set_cookie_raw = str(resp.headers.get("set-cookie") or "")
            if set_cookie_raw.strip():
                set_cookie_values.append(set_cookie_raw)
        except Exception:
            pass

    for set_cookie_raw in set_cookie_values:
        try:
            parsed_cookie = SimpleCookie()
            parsed_cookie.load(set_cookie_raw)
            for key in parsed_cookie.keys():
                name = str(key or "").strip()
                if name and name not in names:
                    names.append(name)
        except Exception:
            pass
    return names


def _extract_error_summary(data: Any) -> str:
    if not isinstance(data, dict):
        return ""

    items: list[str] = []

    def _append(label: str, value: Any) -> None:
        if value in (None, "", [], {}):
            return
        if isinstance(value, str):
            normalized = _preview_text(value, 120)
        else:
            normalized = _summarize_interesting_value(value)
        if not normalized:
            return
        rendered = f"{label}={normalized}"
        if rendered not in items:
            items.append(rendered)

    for key in ("status", "statusCode", "code", "type", "message", "detail", "reason", "error_description"):
        if key in data:
            _append(key, data.get(key))

    err_value = data.get("error")
    if isinstance(err_value, dict):
        for key in ("status", "statusCode", "code", "type", "message", "detail", "reason", "error_description"):
            if key in err_value:
                _append(f"error.{key}", err_value.get(key))
    elif err_value not in (None, "", [], {}):
        _append("error", err_value)

    return "; ".join(items[:8])


def _response_debug_summary(resp: Any, *, text_limit: int = 220) -> str:
    parts: list[str] = []
    final_url = str(getattr(resp, "url", "") or "").strip()
    if final_url:
        parts.append(f"final_url={_mask_secret(final_url, head=48, tail=12)}")
        error_payload_summary = _error_payload_summary_from_url(final_url)
        if error_payload_summary:
            parts.append(f"error_payload={error_payload_summary}")

    cookie_names = _response_cookie_names(resp)
    if cookie_names:
        parts.append("cookies=" + ",".join(cookie_names[:8]))

    body_text = str(getattr(resp, "text", "") or "")
    parsed = _try_parse_json_text(body_text)
    if parsed:
        keys = ",".join(_safe_dict_keys(parsed)) or "-"
        parts.append(f"json_keys={keys}")
        error_summary = _extract_error_summary(parsed)
        if error_summary:
            parts.append(error_summary)
        interesting_paths = _collect_interesting_paths(parsed)
        if interesting_paths:
            parts.append("interesting=" + _format_interesting_paths(interesting_paths))
    elif body_text.strip():
        parts.append("body=" + _preview_text(body_text, text_limit))

    return " | ".join(parts) if parts else "-"


def _decode_error_payload_from_url(url: str) -> Dict[str, Any]:
    raw_url = str(url or "").strip()
    if not raw_url or "/error?" not in raw_url or "payload=" not in raw_url:
        return {}
    try:
        parsed = urllib.parse.urlparse(raw_url)
        payload = str((urllib.parse.parse_qs(parsed.query).get("payload") or [""])[0] or "").strip()
    except Exception:
        return {}
    if not payload:
        return {}
    decoded = _try_decode_b64_json(payload)
    if decoded:
        return decoded
    payload = urllib.parse.unquote(payload)
    decoded = _try_decode_b64_json(payload)
    if decoded:
        return decoded
    return _try_parse_json_text(payload)


def _error_payload_summary_from_url(url: str) -> str:
    payload_json = _decode_error_payload_from_url(url)
    if not payload_json:
        return ""
    parts: list[str] = []
    keys = ",".join(_safe_dict_keys(payload_json)) or "-"
    parts.append(f"keys={keys}")
    kind = str(payload_json.get("kind") or "").strip()
    if kind:
        parts.append(f"kind={kind}")
    message = str(
        payload_json.get("message")
        or payload_json.get("title")
        or payload_json.get("detail")
        or ""
    ).strip()
    if message:
        parts.append("message=" + _preview_text(message, 120))
    error_summary = _extract_error_summary(payload_json)
    if error_summary:
        parts.append(error_summary)
    interesting_paths = _collect_interesting_paths(payload_json)
    if interesting_paths:
        parts.append("interesting=" + _format_interesting_paths(interesting_paths))
    return " | ".join(parts)


def _looks_like_phone_gate_error(url: str) -> bool:
    payload_json = _decode_error_payload_from_url(url)
    if not payload_json:
        return False
    try:
        payload_text = json.dumps(payload_json, ensure_ascii=False).lower()
    except Exception:
        payload_text = str(payload_json).lower()
    return any(
        hint in payload_text
        for hint in (
            "phone",
            "add_phone",
            "add-phone",
            "verify your phone",
            "phone_verification",
            "required_action",
        )
    )


def _cookie_segment_debug(auth_cookie: str) -> list[Dict[str, Any]]:
    parts = str(auth_cookie or "").split(".")
    debug_items: list[Dict[str, Any]] = []
    for index, seg in enumerate(parts[:3]):
        decoded = _decode_jwt_segment(seg)
        workspaces = decoded.get("workspaces") if isinstance(decoded, dict) else []
        workspace_count = len(workspaces) if isinstance(workspaces, list) else 0
        workspace_id = ""
        if workspace_count and isinstance(workspaces[0], dict):
            workspace_id = str(workspaces[0].get("id") or "").strip()
        interesting_paths = _collect_interesting_paths(decoded) if isinstance(decoded, dict) else []
        workspace_ids = _collect_workspace_ids(decoded) if isinstance(decoded, dict) else []
        debug_items.append(
            {
                "index": index,
                "raw_len": len(seg or ""),
                "decoded": bool(decoded),
                "keys": list(decoded.keys())[:8] if isinstance(decoded, dict) else [],
                "workspace_count": workspace_count,
                "workspace_id": workspace_id,
                "interesting_paths": interesting_paths,
                "workspace_ids": workspace_ids,
            }
        )
    return debug_items


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _post_form(
    url: str,
    data: Dict[str, str],
    timeout: int = 30,
    proxy: str = "",
) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    handlers = []
    normalized_proxy = _normalize_proxy_value(proxy)
    if normalized_proxy:
        handlers.append(urllib.request.ProxyHandler({"http": normalized_proxy, "https": normalized_proxy}))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.status != 200:
                raise RuntimeError(
                    f"token exchange failed: {resp.status}: {raw.decode('utf-8', 'replace')}"
                )
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(
            f"token exchange failed: {exc.code}: {raw.decode('utf-8', 'replace')}"
        ) from exc


CHATGPT_ACCOUNTS_CHECK_URL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"


def _first_non_empty_str(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _auth_claims(payload: Dict[str, Any]) -> Dict[str, Any]:
    auth = payload.get(AUTH_CLAIM_KEY) if isinstance(payload, dict) else {}
    return auth if isinstance(auth, dict) else {}


def _extract_default_org_id(organizations: Any) -> str:
    if not isinstance(organizations, list):
        return ""
    first_id = ""
    for item in organizations:
        if not isinstance(item, dict):
            continue
        org_id = str(item.get("id") or "").strip()
        if not first_id and org_id:
            first_id = org_id
        if org_id and bool(item.get("is_default")):
            return org_id
    return first_id


def _extract_org_id_from_token_payload(token_payload: Dict[str, Any]) -> str:
    normalized = normalize_token_data(token_payload, default_type="codex")
    access_payload = decode_jwt_payload(normalized.get("access_token"))
    id_payload = decode_jwt_payload(normalized.get("id_token"))
    access_auth = _auth_claims(access_payload)
    id_auth = _auth_claims(id_payload)
    return _first_non_empty_str(
        normalized.get("organization_id"),
        token_payload.get("organization_id"),
        access_auth.get("poid"),
        access_auth.get("organization_id"),
        id_auth.get("organization_id"),
        _extract_default_org_id(id_auth.get("organizations")),
        _extract_default_org_id(access_auth.get("organizations")),
    )


def _build_accounts_check_candidate(raw: Any, *, org_hint: str = "") -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    account_payload = raw.get("account") if isinstance(raw.get("account"), dict) else {}
    user_payload = raw.get("user") if isinstance(raw.get("user"), dict) else {}
    owner_payload = raw.get("owner") if isinstance(raw.get("owner"), dict) else {}
    entitlement_payload = raw.get("entitlement") if isinstance(raw.get("entitlement"), dict) else {}
    organization_payload = raw.get("organization") if isinstance(raw.get("organization"), dict) else {}
    organization_id = _first_non_empty_str(
        raw.get("organization_id"),
        raw.get("org_id"),
        organization_payload.get("id"),
        account_payload.get("organization_id"),
        account_payload.get("org_id"),
        org_hint,
    )
    account_id = _first_non_empty_str(
        raw.get("chatgpt_account_id"),
        raw.get("account_id"),
        account_payload.get("chatgpt_account_id"),
        account_payload.get("account_id"),
        account_payload.get("id"),
    )
    email = _first_non_empty_str(
        raw.get("email"),
        user_payload.get("email"),
        owner_payload.get("email"),
        account_payload.get("email"),
    ).lower()
    plan_type = _first_non_empty_str(
        raw.get("plan_type"),
        account_payload.get("plan_type"),
        entitlement_payload.get("subscription_plan"),
    )
    subscription_expires_at = _first_non_empty_str(
        raw.get("subscription_expires_at"),
        entitlement_payload.get("expires_at"),
    )
    is_default = bool(
        raw.get("is_default")
        or account_payload.get("is_default")
        or organization_payload.get("is_default")
    )
    return {
        "organization_id": organization_id,
        "account_id": account_id,
        "email": email,
        "plan_type": plan_type,
        "subscription_expires_at": subscription_expires_at,
        "is_default": is_default,
    }


def _extract_accounts_check_payload(
    response_payload: Dict[str, Any],
    *,
    preferred_org_id: str = "",
    fallback_email: str = "",
) -> Dict[str, Any]:
    if not isinstance(response_payload, dict) or not response_payload:
        return {}

    preferred_org = str(preferred_org_id or "").strip()
    fallback_email_value = str(fallback_email or "").strip().lower()
    candidates: list[Dict[str, Any]] = []
    root_candidate = _build_accounts_check_candidate(response_payload)
    if any(root_candidate.get(key) for key in ("account_id", "email", "plan_type", "organization_id")):
        candidates.append(root_candidate)

    accounts_payload = response_payload.get("accounts")
    if isinstance(accounts_payload, dict):
        for org_key, acct_raw in accounts_payload.items():
            candidate = _build_accounts_check_candidate(acct_raw, org_hint=str(org_key or "").strip())
            if candidate:
                candidates.append(candidate)
    elif isinstance(accounts_payload, list):
        for acct_raw in accounts_payload:
            candidate = _build_accounts_check_candidate(acct_raw)
            if candidate:
                candidates.append(candidate)

    selected: Dict[str, Any] = {}
    if preferred_org:
        for candidate in candidates:
            if str(candidate.get("organization_id") or "").strip() == preferred_org:
                selected = candidate
                break
    if not selected:
        for candidate in candidates:
            if bool(candidate.get("is_default")):
                selected = candidate
                break
    if not selected:
        for candidate in candidates:
            if str(candidate.get("account_id") or "").strip():
                selected = candidate
                break
    if not selected and candidates:
        selected = candidates[0]

    result: Dict[str, Any] = {}
    account_id = _first_non_empty_str(
        selected.get("account_id"),
        root_candidate.get("account_id"),
    )
    email = _first_non_empty_str(
        selected.get("email"),
        root_candidate.get("email"),
        fallback_email_value,
    ).lower()
    plan_type = _first_non_empty_str(
        selected.get("plan_type"),
        root_candidate.get("plan_type"),
    )
    organization_id = _first_non_empty_str(
        selected.get("organization_id"),
        root_candidate.get("organization_id"),
        preferred_org,
    )
    subscription_expires_at = _first_non_empty_str(
        selected.get("subscription_expires_at"),
        root_candidate.get("subscription_expires_at"),
    )
    if account_id:
        result["account_id"] = account_id
        result["chatgpt_account_id"] = account_id
    if email:
        result["email"] = email
    if plan_type:
        result["plan_type"] = plan_type
    if organization_id:
        result["organization_id"] = organization_id
    if subscription_expires_at:
        result["subscription_expires_at"] = subscription_expires_at
    result["_accounts_check_meta"] = {
        "accounts_count": len(candidates),
        "preferred_org_id": preferred_org,
        "selected_org_id": organization_id,
        "selected_account_id": account_id,
        "selected_email": email,
    }
    return result


def _fetch_chatgpt_account_payload_by_access_token(
    *,
    access_token: str,
    proxy: str = "",
    fallback_email: str = "",
    emitter: Any = None,
) -> Dict[str, Any]:
    token_value = str(access_token or "").strip()
    if not token_value:
        return {}
    normalized_proxy = _normalize_proxy_value(proxy)
    proxies = _to_proxies_dict(normalized_proxy)
    access_payload = decode_jwt_payload(token_value)
    access_auth = _auth_claims(access_payload)
    preferred_org_id = _first_non_empty_str(
        access_auth.get("poid"),
        access_auth.get("organization_id"),
        _extract_default_org_id(access_auth.get("organizations")),
    )
    headers = {
        "Authorization": f"Bearer {token_value}",
        "Accept": "application/json",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "User-Agent": _current_user_agent(),
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-fetch-dest": "empty",
    }
    try:
        resp = _call_with_http_fallback(
            requests.get,
            CHATGPT_ACCOUNTS_CHECK_URL,
            headers=headers,
            proxies=proxies,
            http_version=DEFAULT_HTTP_VERSION,
            impersonate=_current_impersonate(),
            timeout=20,
        )
    except Exception as exc:
        if emitter is not None:
            try:
                emitter.warn(
                    f"access_token 直连 accounts/check 失败: {exc}",
                    step="get_token",
                )
            except Exception:
                pass
        return {}
    body_text = str(getattr(resp, "text", "") or "")
    if int(getattr(resp, "status_code", 0) or 0) != 200:
        if emitter is not None:
            try:
                emitter.warn(
                    "access_token 直连 accounts/check 非 200: "
                    + f"status={getattr(resp, 'status_code', 0)}, body={_preview_text(body_text, 220) or '-'}",
                    step="get_token",
                )
            except Exception:
                pass
        return {}
    try:
        response_payload = resp.json() or {}
    except Exception as exc:
        if emitter is not None:
            try:
                emitter.warn(
                    f"access_token 直连 accounts/check JSON 解析失败: {exc}",
                    step="get_token",
                )
            except Exception:
                pass
        return {}
    if not isinstance(response_payload, dict) or not response_payload:
        return {}
    extracted = _extract_accounts_check_payload(
        response_payload,
        preferred_org_id=preferred_org_id,
        fallback_email=fallback_email,
    )
    meta = extracted.get("_accounts_check_meta") if isinstance(extracted.get("_accounts_check_meta"), dict) else {}
    if emitter is not None:
        try:
            emitter.info(
                "access_token accounts/check 诊断: "
                + f"top_keys={','.join(sorted(str(k) for k in response_payload.keys())[:12]) or '-'}, "
                + f"preferred_org_id={_mask_secret(preferred_org_id, head=12, tail=6) or '-'}, "
                + f"accounts_count={meta.get('accounts_count') or 0}, "
                + f"selected_org_id={_mask_secret(meta.get('selected_org_id') or '', head=12, tail=6) or '-'}, "
                + f"account_id={_mask_secret(meta.get('selected_account_id') or '', head=12, tail=6) or '-'}, "
                + f"email={str(meta.get('selected_email') or '').strip() or '-'}",
                step="get_token",
            )
        except Exception:
            pass
    extracted.pop("_accounts_check_meta", None)
    return extracted


def _build_token_result(token_payload: Dict[str, Any]) -> str:
    normalized = normalize_token_data(token_payload, default_type="codex")
    access_token = str(normalized.get("access_token") or "").strip()
    refresh_token = str(normalized.get("refresh_token") or "").strip()
    id_token = str(normalized.get("id_token") or "").strip()
    session_token = str(normalized.get("session_token") or "").strip()
    email = str(normalized.get("email") or "").strip()
    account_id = str(
        normalized.get("chatgpt_account_id")
        or normalized.get("account_id")
        or ""
    ).strip()

    if not access_token:
        raise ValueError("token result missing access_token")
    if not id_token:
        raise ValueError("token result missing id_token")
    if not email or not account_id:
        raise ValueError("token result missing email/account_id")

    expires_in = _to_int(token_payload.get("expires_in"))
    now = int(time.time())
    expired_rfc3339 = str(normalized.get("expires_at") or normalized.get("expired") or "").strip()
    if not expired_rfc3339:
        expired_rfc3339 = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
        )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_token": session_token,
        "account_id": account_id,
        "chatgpt_account_id": account_id,
        "chatgpt_user_id": str(normalized.get("chatgpt_user_id") or "").strip(),
        "plan_type": str(normalized.get("plan_type") or "").strip(),
        "last_refresh": now_rfc3339,
        "expires_at": expired_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }
    normalized_config = normalize_token_data(config, default_type="codex")
    return json.dumps(normalized_config, ensure_ascii=False, separators=(",", ":"))


def _write_text_atomic(file_path: str, content: str) -> None:
    directory = os.path.dirname(file_path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, file_path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_url(
    *,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    scope: str = DEFAULT_SCOPE,
    prompt: str = "login",
    screen_hint: str = "signup",
    login_hint: str = "",
) -> OAuthStart:
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    if prompt:
        params["prompt"] = prompt
    if screen_hint:
        params["screen_hint"] = screen_hint
    if login_hint:
        params["login_hint"] = login_hint
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )


def submit_callback_url(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    proxy: str = "",
) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())

    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        proxy=proxy,
    )

    return _build_token_result(token_resp)


def exchange_callback_to_token_payload(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    proxy: str = "",
) -> Dict[str, Any]:
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())
    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    return _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        proxy=proxy,
    )


def build_token_result_from_payloads(
    *payloads: Dict[str, Any],
    proxy: str = "",
    emitter: Any = None,
    fallback_email: str = "",
) -> str:
    merged: Dict[str, Any] = {}
    payload_key_parts: list[str] = []
    for index, item in enumerate(payloads, start=1):
        if not isinstance(item, dict) or not item:
            continue
        payload_key_parts.append(
            f"p{index}={','.join(sorted(str(key) for key in item.keys())[:10]) or '-'}"
        )
        for key, value in item.items():
            if key not in merged:
                merged[key] = value
                continue
            existing = merged.get(key)
            if isinstance(existing, dict) and isinstance(value, dict):
                combined = dict(existing)
                for sub_key, sub_value in value.items():
                    if sub_key not in combined or str(combined.get(sub_key) or "").strip() == "":
                        combined[sub_key] = sub_value
                merged[key] = combined
                continue
            if str(existing or "").strip() == "" and str(value or "").strip() != "":
                merged[key] = value
    if not str(merged.get("email") or "").strip() and str(fallback_email or "").strip():
        merged["email"] = str(fallback_email or "").strip().lower()
    normalized_preview = normalize_token_data(merged, default_type="codex")
    access_payload = decode_jwt_payload(normalized_preview.get("access_token"))
    access_auth = _auth_claims(access_payload)
    id_payload = decode_jwt_payload(normalized_preview.get("id_token"))
    id_auth = _auth_claims(id_payload)
    if emitter is not None:
        try:
            emitter.info(
                "token 组装前诊断: "
                + f"{' | '.join(payload_key_parts) or 'payloads=-'}, "
                + f"email={str(normalized_preview.get('email') or '').strip() or '-'}, "
                + f"account_id={_mask_secret(normalized_preview.get('account_id') or normalized_preview.get('chatgpt_account_id') or '', head=12, tail=6) or '-'}, "
                + f"refresh_token={'有' if str(normalized_preview.get('refresh_token') or '').strip() else '无'}, "
                + f"id_token={'有' if str(normalized_preview.get('id_token') or '').strip() else '无'}, "
                + f"session_token={'有' if str(normalized_preview.get('session_token') or '').strip() else '无'}, "
                + f"access.auth.account_id={_mask_secret(access_auth.get('chatgpt_account_id') or '', head=12, tail=6) or '-'}, "
                + f"access.auth.poid={_mask_secret(access_auth.get('poid') or '', head=12, tail=6) or '-'}, "
                + f"id.email={str(id_payload.get('email') or '').strip() or '-'}, "
                + f"id.account_id={_mask_secret(id_auth.get('chatgpt_account_id') or '', head=12, tail=6) or '-'}",
                step="get_token",
            )
        except Exception:
            pass
    if (
        str(normalized_preview.get("access_token") or "").strip()
        and (
            not str(normalized_preview.get("email") or "").strip()
            or not str(normalized_preview.get("account_id") or normalized_preview.get("chatgpt_account_id") or "").strip()
        )
    ):
        accounts_check_payload = _fetch_chatgpt_account_payload_by_access_token(
            access_token=str(normalized_preview.get("access_token") or "").strip(),
            proxy=proxy,
            fallback_email=str(
                normalized_preview.get("email")
                or fallback_email
                or ""
            ).strip(),
            emitter=emitter,
        )
        if accounts_check_payload:
            for key, value in accounts_check_payload.items():
                if key not in merged or str(merged.get(key) or "").strip() == "":
                    merged[key] = value
            normalized_preview = normalize_token_data(merged, default_type="codex")
            if emitter is not None:
                try:
                    emitter.info(
                        "token 组装后诊断: "
                        + f"email={str(normalized_preview.get('email') or '').strip() or '-'}, "
                        + f"account_id={_mask_secret(normalized_preview.get('account_id') or normalized_preview.get('chatgpt_account_id') or '', head=12, tail=6) or '-'}, "
                        + f"plan_type={str(normalized_preview.get('plan_type') or '').strip() or '-'}, "
                        + f"organization_id={_mask_secret(_extract_org_id_from_token_payload(merged), head=12, tail=6) or '-'}",
                        step="get_token",
                    )
                except Exception:
                    pass
    return _build_token_result(merged)


# ==========================================
# 核心注册逻辑
# ==========================================

from . import TOKENS_DIR as _PKG_TOKENS_DIR

TOKENS_DIR = str(_PKG_TOKENS_DIR)


class PhoneVerificationRequiredError(RuntimeError):
    """账号已创建，但当前流程被手机号验证拦截。"""

    def __init__(
        self,
        message: str,
        *,
        page_type: str = "",
        continue_url: str = "",
        final_url: str = "",
    ) -> None:
        super().__init__(message)
        self.page_type = page_type
        self.continue_url = continue_url
        self.final_url = final_url


def run(
    proxy: Optional[str],
    emitter: EventEmitter = _cli_emitter,
    stop_event: Optional[threading.Event] = None,
    mail_provider=None,
    proxy_pool_config: Optional[Dict[str, Any]] = None,
    browser_config: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    try:
        from .sentinel_runtime import SentinelRuntime
    except ImportError:
        from sentinel_runtime import SentinelRuntime  # type: ignore
    try:
        from .browser_register import (
            BrowserPhoneVerificationRequiredError,
            normalize_browser_config,
            run_browser_registration,
        )
    except ImportError:
        from browser_register import (  # type: ignore
            BrowserPhoneVerificationRequiredError,
            normalize_browser_config,
            run_browser_registration,
        )

    normalized_browser_config = normalize_browser_config(browser_config or {})
    raw_locale = str(normalized_browser_config.get("browser_locale") or "").strip()
    raw_timezone = str(normalized_browser_config.get("browser_timezone") or "").strip()
    locale_override = "" if raw_locale in {"", "en-US", "random", "RANDOM"} else raw_locale
    timezone_override = (
        ""
        if raw_timezone in {"", "America/New_York", "random", "RANDOM"}
        else raw_timezone
    )
    register_mode_value = str(normalized_browser_config.get("register_mode") or "browser").strip().lower()
    fingerprint_profile = generate_fingerprint_profile(
        locale_override=locale_override,
        timezone_override=timezone_override,
        browser_executable_path=str(normalized_browser_config.get("browser_executable_path") or "").strip(),
    )
    _ACTIVE_FINGERPRINT_PROFILE.set(fingerprint_profile)
    normalized_browser_config["browser_locale"] = fingerprint_profile.locale
    normalized_browser_config["browser_timezone"] = fingerprint_profile.timezone_id
    emitter.info(f"本次请求指纹: {describe_fingerprint(fingerprint_profile)}", step="oauth_init")
    browser_mode = register_mode_value in ("browser", "browser_manual", "browser_manual_v2")
    verbose_auth_logs = str(os.getenv("OPENAI_POOL_VERBOSE_AUTH_LOGS") or "").strip().lower() in ("1", "true", "yes", "on")

    static_proxy = _normalize_proxy_value(proxy)
    static_proxies: Any = _to_proxies_dict(static_proxy)

    pool_cfg_raw = proxy_pool_config or {}
    pool_cfg = {
        "enabled": bool(pool_cfg_raw.get("enabled", False)),
        "api_url": str(pool_cfg_raw.get("api_url") or DEFAULT_PROXY_POOL_URL).strip() or DEFAULT_PROXY_POOL_URL,
        "auth_mode": str(pool_cfg_raw.get("auth_mode") or DEFAULT_PROXY_POOL_AUTH_MODE).strip().lower() or DEFAULT_PROXY_POOL_AUTH_MODE,
        "api_key": str(pool_cfg_raw.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY,
        "count": pool_cfg_raw.get("count", DEFAULT_PROXY_POOL_COUNT),
        "country": str(pool_cfg_raw.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY,
        "timeout_seconds": int(pool_cfg_raw.get("timeout_seconds") or 10),
    }
    if pool_cfg["auth_mode"] not in ("header", "query"):
        pool_cfg["auth_mode"] = DEFAULT_PROXY_POOL_AUTH_MODE
    try:
        pool_cfg["count"] = max(1, min(int(pool_cfg.get("count") or DEFAULT_PROXY_POOL_COUNT), 20))
    except (TypeError, ValueError):
        pool_cfg["count"] = DEFAULT_PROXY_POOL_COUNT

    last_pool_proxy = ""
    pool_fail_streak = 0
    warned_fallback = False

    def _next_proxy_value() -> str:
        nonlocal last_pool_proxy, pool_fail_streak, warned_fallback
        if pool_cfg["enabled"]:
            max_fetch_retries = max(1, int(pool_cfg.get("fetch_retries") or POOL_PROXY_FETCH_RETRIES))
            last_error = ""
            for _ in range(max_fetch_retries):
                try:
                    fetched = _fetch_proxy_from_pool(pool_cfg)
                    if fetched and not _proxy_tcp_reachable(fetched):
                        last_error = f"代理池代理不可达: {fetched}"
                        continue
                    last_pool_proxy = fetched
                    pool_fail_streak = 0
                    warned_fallback = False
                    return fetched
                except Exception as e:
                    last_error = str(e)

            pool_fail_streak += 1
            if static_proxy:
                if not warned_fallback:
                    emitter.warn(f"代理池不可用，回退固定代理: {last_error or 'unknown error'}", step="check_proxy")
                    warned_fallback = True
                return static_proxy
            if pool_fail_streak <= 3:
                emitter.warn(f"代理池不可用: {last_error or 'unknown error'}", step="check_proxy")
            return ""
        return static_proxy
    def _next_proxies() -> Any:
        proxy_value = _next_proxy_value()
        return _to_proxies_dict(proxy_value)

    s = requests.Session(impersonate=_current_impersonate())
    pool_relay_url = _pool_relay_url_from_fetch_url(str(pool_cfg.get("api_url") or ""))
    pool_relay_enabled = bool(pool_cfg["enabled"] and pool_relay_url)
    relay_cookie_jar: Dict[str, str] = {}
    pool_relay_api_key = str(pool_cfg.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY
    pool_relay_country = str(pool_cfg.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY
    relay_fallback_warned = False
    relay_bypass_openai_hosts = False
    openai_relay_probe_done = False
    mail_proxy_selector = None if pool_relay_enabled else _next_proxy_value
    mail_proxies_selector = None if pool_relay_enabled else _next_proxies

    def _fallback_proxies_for_relay_failure() -> Any:
        if static_proxy:
            return _to_proxies_dict(static_proxy)
        return None

    def _target_host(target_url: str) -> str:
        return str(urlparse(str(target_url or "")).hostname or "").strip().lower()

    def _is_openai_like_host(host: str) -> bool:
        return bool(host) and (host.endswith("openai.com") or host.endswith("chatgpt.com"))

    def _should_bypass_relay_for_target(target_url: str) -> bool:
        host = _target_host(target_url)
        return relay_bypass_openai_hosts and _is_openai_like_host(host)

    def _warn_relay_fallback(reason: str, target_url: str) -> None:
        nonlocal relay_fallback_warned, relay_bypass_openai_hosts
        host = _target_host(target_url) or str(target_url or "?")
        if _is_openai_like_host(host):
            relay_bypass_openai_hosts = True
        if relay_fallback_warned:
            return
        if static_proxy:
            emitter.warn(f"代理池 relay 对 {host} 不可用，回退固定代理: {reason}", step="check_proxy")
        else:
            emitter.warn(f"代理池 relay 对 {host} 不可用，回退直连: {reason}", step="check_proxy")
        relay_fallback_warned = True

    def _auth_cookie_presence_summary() -> str:
        cookie_names = (
            "login_session",
            "login_session_state",
            "auth_provider",
            "oai-client-auth-session",
            "oai-client-auth-info",
            "unified_session_manifest",
            "auth-session-minimized",
        )
        parts: list[str] = []
        for cookie_name in cookie_names:
            session_cookie = str(s.cookies.get(cookie_name) or "").strip()
            relay_cookie = str(relay_cookie_jar.get(cookie_name) or "").strip()
            source = "session" if session_cookie else ("relay" if relay_cookie else "none")
            raw_cookie = session_cookie or relay_cookie
            parts.append(f"{cookie_name}:{source}/{len(raw_cookie)}")
        return ", ".join(parts)

    def _build_email_otp_headers(referer: str) -> Dict[str, str]:
        headers = _build_navigate_headers()
        headers["referer"] = str(referer or "").strip() or "https://auth.openai.com/create-account/password"
        headers["origin"] = OPENAI_AUTH_BASE
        headers["oai-device-id"] = did
        headers.update(_generate_datadog_trace())
        return headers

    def _update_relay_cookie_jar(resp: Any) -> None:
        try:
            for k, v in (resp.cookies or {}).items():
                key = str(k or "").strip()
                if key:
                    relay_cookie_jar[key] = str(v or "")
        except Exception:
            pass
        set_cookie_values: list[str] = []
        try:
            values = resp.headers.get_list("set-cookie")  # type: ignore[attr-defined]
            if values:
                set_cookie_values.extend(str(v or "") for v in values if str(v or "").strip())
        except Exception:
            pass
        if not set_cookie_values:
            try:
                set_cookie_raw = str(resp.headers.get("set-cookie") or "")
                if set_cookie_raw.strip():
                    set_cookie_values.append(set_cookie_raw)
            except Exception:
                pass
        for set_cookie_raw in set_cookie_values:
            try:
                parsed_cookie = SimpleCookie()
                parsed_cookie.load(set_cookie_raw)
                for k, morsel in parsed_cookie.items():
                    key = str(k or "").strip()
                    if key:
                        relay_cookie_jar[key] = str(morsel.value or "")
            except Exception:
                pass
        try:
            for k, v in relay_cookie_jar.items():
                s.cookies.set(k, v)
        except Exception:
            pass

    def _request_via_pool_relay(method: str, target_url: str, **kwargs: Any):
        if not pool_relay_enabled:
            raise RuntimeError("代理池 relay 未启用")
        relay_retries_override = kwargs.pop("_relay_retries", None)
        relay_params = {
            "api_key": pool_relay_api_key,
            "url": str(target_url),
            "method": str(method or "GET").upper(),
            "country": pool_relay_country,
        }
        target_params = kwargs.pop("params", None)
        if target_params:
            query_text = urlencode(target_params, doseq=True)
            if query_text:
                separator = "&" if "?" in relay_params["url"] else "?"
                relay_params["url"] = f"{relay_params['url']}{separator}{query_text}"

        headers = dict(kwargs.pop("headers", {}) or {})
        if relay_cookie_jar and not any(str(k).lower() == "cookie" for k in headers.keys()):
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in relay_cookie_jar.items())
        kwargs.pop("proxies", None)
        kwargs.setdefault("impersonate", _current_impersonate())
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 20)

        method_upper = relay_params["method"]
        retry_count = max(
            1,
            int(
                relay_retries_override
                if relay_retries_override is not None
                else (pool_cfg.get("relay_request_retries") or POOL_RELAY_REQUEST_RETRIES)
            ),
        )
        last_error = ""
        for i in range(retry_count):
            try:
                resp = _call_with_http_fallback(
                    lambda relay_endpoint, **call_kwargs: requests.request(method_upper, relay_endpoint, **call_kwargs),
                    pool_relay_url,
                    params=relay_params,
                    headers=headers or None,
                    **kwargs,
                )
                _update_relay_cookie_jar(resp)
                if resp.status_code >= 500 or resp.status_code == 429:
                    last_error = f"HTTP {resp.status_code}"
                    if i < retry_count - 1:
                        time.sleep(min(0.4 * (i + 1), 1.2))
                        continue
                return resp
            except Exception as exc:
                last_error = str(exc)
                if i < retry_count - 1:
                    time.sleep(min(0.4 * (i + 1), 1.2))
        raise RuntimeError(f"代理池 relay 请求失败: {last_error or 'unknown error'}")

    def _ensure_openai_relay_ready() -> None:
        nonlocal openai_relay_probe_done
        if not pool_relay_enabled or relay_bypass_openai_hosts or openai_relay_probe_done:
            return
        openai_relay_probe_done = True
        probe_url = "https://auth.openai.com/"
        try:
            probe_resp = _request_via_pool_relay(
                "GET",
                probe_url,
                timeout=5,
                allow_redirects=False,
                _relay_retries=1,
            )
            status = int(probe_resp.status_code or 0)
            if status < 200 or status >= 400:
                raise RuntimeError(f"HTTP {status}")
            emitter.info("代理池 relay OpenAI 预检通过", step="check_proxy")
        except Exception as exc:
            _warn_relay_fallback(f"{exc} (OpenAI 预检)", probe_url)

    def _session_get(url: str, **kwargs: Any):
        relay_retries = kwargs.pop("_relay_retries", None)
        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("GET", url, _relay_retries=relay_retries, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(s.get, url, **kwargs)
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(s.get, url, **kwargs)
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(s.get, url, **kwargs)

    def _session_post(url: str, **kwargs: Any):
        relay_retries = kwargs.pop("_relay_retries", None)
        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("POST", url, _relay_retries=relay_retries, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(s.post, url, **kwargs)
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(s.post, url, **kwargs)
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(s.post, url, **kwargs)

    def _raw_get(url: str, **kwargs: Any):
        relay_retries = kwargs.pop("_relay_retries", None)
        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("GET", url, _relay_retries=relay_retries, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("impersonate", _current_impersonate())
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(requests.get, url, **kwargs)
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("impersonate", _current_impersonate())
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(requests.get, url, **kwargs)
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("impersonate", _current_impersonate())
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(requests.get, url, **kwargs)

    def _raw_post(url: str, **kwargs: Any):
        relay_retries = kwargs.pop("_relay_retries", None)
        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("POST", url, _relay_retries=relay_retries, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("impersonate", _current_impersonate())
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(requests.post, url, **kwargs)
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("impersonate", _current_impersonate())
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(requests.post, url, **kwargs)
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("impersonate", _current_impersonate())
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(requests.post, url, **kwargs)

    def _build_protocol_sentinel_token(*, flow: str, page_url: str) -> str:
        return SentinelRuntime(
            device_id=did,
            user_agent=fingerprint_profile.user_agent,
            fingerprint_profile=fingerprint_profile,
            get_func=_session_get,
            post_func=_raw_post,
            emitter=emitter,
        ).build_token(
            flow=flow,
            page_url=page_url,
        )

    def _submit_callback_url_via_pool_relay(
        *,
        callback_url: str,
        expected_state: str,
        code_verifier: str,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
    ) -> str:
        cb = _parse_callback_url(callback_url)
        if cb["error"]:
            desc = cb["error_description"]
            raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())
        if not cb["code"]:
            raise ValueError("callback url missing ?code=")
        if not cb["state"]:
            raise ValueError("callback url missing ?state=")
        if cb["state"] != expected_state:
            raise ValueError("state mismatch")

        token_resp = _request_via_pool_relay(
            "POST",
            TOKEN_URL,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data=urllib.parse.urlencode(
                {
                    "grant_type": "authorization_code",
                    "client_id": CLIENT_ID,
                    "code": cb["code"],
                    "redirect_uri": redirect_uri,
                    "code_verifier": code_verifier,
                }
            ),
            timeout=30,
        )
        if token_resp.status_code != 200:
            raise RuntimeError(
                f"token exchange failed: {token_resp.status_code}: {str(token_resp.text or '')[:240]}"
            )
        try:
            token_json = token_resp.json()
        except Exception:
            token_json = json.loads(str(token_resp.text or "{}"))

        return _build_token_result(token_json)

    def _extract_code_from_url(candidate_url: str) -> str:
        return str((_parse_callback_url(candidate_url) or {}).get("code") or "").strip()

    def _decode_oauth_session_cookie() -> Dict[str, Any]:
        raw_cookie = str(
            s.cookies.get("oai-client-auth-session")
            or relay_cookie_jar.get("oai-client-auth-session")
            or ""
        ).strip()
        if not raw_cookie:
            return {}
        for _, variant_value in _cookie_candidate_values(raw_cookie):
            if not variant_value:
                continue
            direct_json = _try_parse_json_text(variant_value)
            if isinstance(direct_json, dict) and direct_json:
                return direct_json
            parts = str(variant_value).split(".")
            for part in parts[:2]:
                decoded = _decode_jwt_segment(part)
                if isinstance(decoded, dict) and decoded:
                    if decoded.get("workspaces") or decoded.get("session_id"):
                        return decoded
        return {}

    def _extract_chatgpt_session_token() -> str:
        for cookie_name in (
            "__Secure-next-auth.session-token",
            "next-auth.session-token",
            "__Secure-authjs.session-token",
            "authjs.session-token",
        ):
            session_cookie = str(s.cookies.get(cookie_name) or "").strip()
            if session_cookie:
                return session_cookie
            relay_cookie = str(relay_cookie_jar.get(cookie_name) or "").strip()
            if relay_cookie:
                return relay_cookie
        return ""

    def _build_chatgpt_session_headers(referer_url: str = "") -> Dict[str, str]:
        profile = _get_active_fingerprint_profile()
        headers = {
            "accept": "application/json",
            "accept-language": profile.accept_language,
            "origin": "https://chatgpt.com",
            "referer": str(referer_url or "https://chatgpt.com/").strip() or "https://chatgpt.com/",
            "user-agent": profile.user_agent,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        headers.update(build_sec_ch_headers(profile))
        return headers

    def _try_build_token_from_chatgpt_session(referer_url: str = "") -> Optional[str]:
        session_headers = _build_chatgpt_session_headers(referer_url)
        try:
            session_resp = _session_get(
                "https://chatgpt.com/api/auth/session",
                headers=session_headers,
                allow_redirects=True,
                timeout=15,
                _relay_retries=1,
            )
        except Exception as exc:
            if verbose_auth_logs:
                emitter.warn(f"ChatGPT session fast path 请求失败: {exc}", step="get_token")
            return None

        if verbose_auth_logs:
            emitter.info(
                "ChatGPT session fast path 响应: "
                + f"status={session_resp.status_code}, {_response_debug_summary(session_resp, text_limit=220)}",
                step="get_token",
            )
        if session_resp.status_code != 200:
            return None

        try:
            session_json = session_resp.json() or {}
        except Exception:
            session_json = {}
        if not isinstance(session_json, dict) or not session_json:
            return None

        session_token = _extract_chatgpt_session_token()
        return _build_token_from_chatgpt_session_payload(
            session_json,
            source_label="ChatGPT session fast path",
            session_token_override=session_token,
        )

    def _build_token_from_chatgpt_session_payload(
        session_json: Dict[str, Any],
        *,
        source_label: str = "ChatGPT session payload",
        session_token_override: str = "",
    ) -> Optional[str]:
        if not isinstance(session_json, dict) or not session_json:
            return None

        access_token = str(
            session_json.get("accessToken")
            or session_json.get("access_token")
            or ((session_json.get("data") or {}).get("accessToken") if isinstance(session_json.get("data"), dict) else "")
            or ((session_json.get("data") or {}).get("access_token") if isinstance(session_json.get("data"), dict) else "")
            or ""
        ).strip()
        if not access_token:
            return None

        session_payload = dict(session_json)
        session_payload["access_token"] = access_token
        refresh_token = str(
            session_json.get("refreshToken")
            or session_json.get("refresh_token")
            or ""
        ).strip()
        if refresh_token:
            session_payload["refresh_token"] = refresh_token
        session_token = str(
            session_token_override
            or session_json.get("sessionToken")
            or session_json.get("session_token")
            or ""
        ).strip()
        if session_token:
            session_payload["session_token"] = session_token
        user_payload = session_json.get("user") if isinstance(session_json.get("user"), dict) else {}
        account_payload = session_json.get("account") if isinstance(session_json.get("account"), dict) else {}
        if user_payload and not session_payload.get("email"):
            session_payload["email"] = str(user_payload.get("email") or "").strip()
        account_id = str(
            session_json.get("account_id")
            or session_json.get("chatgpt_account_id")
            or account_payload.get("id")
            or ""
        ).strip()
        if account_id:
            session_payload["account_id"] = account_id
            session_payload["chatgpt_account_id"] = account_id
        expires_value = str(session_json.get("expires") or session_json.get("expires_at") or "").strip()
        if expires_value:
            session_payload["expires_at"] = expires_value
            session_payload["expired"] = expires_value

        try:
            result = _build_token_result(session_payload)
        except Exception as exc:
            if verbose_auth_logs:
                normalized_preview = normalize_token_data(session_payload, default_type="codex")
                emitter.warn(
                    f"{source_label} 组装 Token 失败: {exc}; "
                    + f"top_keys={','.join(sorted(str(k) for k in session_json.keys())[:12]) or '-'}, "
                    + f"user.email={str(user_payload.get('email') or '').strip() or '-'}, "
                    + f"account.id={str(account_payload.get('id') or '').strip() or '-'}, "
                    + f"normalized.email={str(normalized_preview.get('email') or '').strip() or '-'}, "
                    + f"normalized.account_id={_mask_secret(normalized_preview.get('account_id') or normalized_preview.get('chatgpt_account_id') or '', head=12, tail=6) or '-'}, "
                    + f"id_token={'有' if str(session_payload.get('id_token') or '').strip() else '无'}, "
                    + f"access_token={'有' if access_token else '无'}, "
                    + f"session_token={'有' if session_token else '无'}",
                    step="get_token",
                )
            return None

        try:
            normalized = json.loads(result)
        except Exception:
            normalized = {}
        if verbose_auth_logs and isinstance(normalized, dict):
            emitter.info(
                f"{source_label} 命中: "
                + f"email={str(normalized.get('email') or '-').strip() or '-'}, "
                + f"account_id={_mask_secret(normalized.get('account_id') or normalized.get('chatgpt_account_id') or '', head=12, tail=6) or '-'}, "
                + f"session_token={'有' if session_token else '无'}",
                step="get_token",
            )
        return result

    def _oauth_follow_for_callback(
        start_url: str,
        *,
        referer: str = "",
        max_hops: int = 16,
        timeout: int = 8,
        relay_retries: int = 1,
    ) -> tuple[str, str]:
        current_url = str(start_url or "").strip()
        if not current_url:
            return "", ""
        headers = _build_navigate_headers()
        if referer:
            headers["referer"] = referer
        last_url = current_url
        for _ in range(max_hops):
            try:
                resp = _session_get(
                    current_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=timeout,
                    _relay_retries=relay_retries,
                )
            except Exception as exc:
                maybe_localhost = re.search(r"(https?://localhost[^\s'\"<>]+)", str(exc))
                if maybe_localhost:
                    callback_url = maybe_localhost.group(1)
                    if _extract_code_from_url(callback_url):
                        return callback_url, callback_url
                return "", last_url
            last_url = str(getattr(resp, "url", "") or current_url).strip()
            if _extract_code_from_url(last_url):
                return last_url, last_url
            if getattr(resp, "status_code", 0) not in (301, 302, 303, 307, 308):
                return "", last_url
            location = str((resp.headers or {}).get("Location") or "").strip()
            if not location:
                return "", last_url
            next_url = urllib.parse.urljoin(current_url, location)
            if _extract_code_from_url(next_url):
                return next_url, next_url
            headers["referer"] = last_url
            current_url = next_url
        return "", last_url

    def _oauth_allow_redirect_extract_callback(
        start_url: str,
        *,
        referer: str = "",
        timeout: int = 8,
        relay_retries: int = 1,
    ) -> str:
        current_url = str(start_url or "").strip()
        if not current_url:
            return ""
        headers = _build_navigate_headers()
        if referer:
            headers["referer"] = referer
        try:
            resp = _session_get(
                current_url,
                headers=headers,
                allow_redirects=True,
                timeout=timeout,
                _relay_retries=relay_retries,
            )
        except Exception as exc:
            maybe_localhost = re.search(r"(https?://localhost[^\s'\"<>]+)", str(exc))
            if maybe_localhost:
                callback_url = maybe_localhost.group(1)
                if _extract_code_from_url(callback_url):
                    return callback_url
            return ""

        candidate_urls: list[str] = []

        def _append_candidate(candidate_url: str, *, base_url: str = "") -> None:
            value = str(candidate_url or "").strip()
            if not value:
                return
            normalized = urllib.parse.urljoin(base_url or current_url, value)
            if normalized and normalized not in candidate_urls:
                candidate_urls.append(normalized)

        _append_candidate(str(getattr(resp, "url", "") or current_url).strip())
        for hist_resp in getattr(resp, "history", []) or []:
            hist_url = str(getattr(hist_resp, "url", "") or "").strip()
            _append_candidate(hist_url)
            location = str((getattr(hist_resp, "headers", {}) or {}).get("Location") or "").strip()
            if location:
                _append_candidate(location, base_url=hist_url or current_url)

        for candidate_url in candidate_urls:
            if _extract_code_from_url(candidate_url):
                return candidate_url
        return ""

    def _extract_oauth_progress_urls(resp: Any, *, base_url: str = "") -> tuple[str, str, str]:
        current_base = str(base_url or getattr(resp, "url", "") or "").strip()
        candidate_urls: list[str] = []

        def _append_candidate(candidate_url: str, *, candidate_base: str = "") -> None:
            value = str(candidate_url or "").strip()
            if not value:
                return
            normalized = urllib.parse.urljoin(candidate_base or current_base, value)
            if normalized and normalized not in candidate_urls:
                candidate_urls.append(normalized)

        final_url = str(getattr(resp, "url", "") or current_base).strip()
        _append_candidate(final_url)
        for hist_resp in getattr(resp, "history", []) or []:
            hist_url = str(getattr(hist_resp, "url", "") or "").strip()
            _append_candidate(hist_url)
            location = str((getattr(hist_resp, "headers", {}) or {}).get("Location") or "").strip()
            if location:
                _append_candidate(location, candidate_base=hist_url or current_base)

        body_text = str(getattr(resp, "text", "") or "")
        if body_text:
            body_variants: list[str] = []
            for candidate_text in (
                body_text,
                body_text.replace("\\/", "/"),
                body_text.replace("\\u002F", "/"),
            ):
                normalized_text = str(candidate_text or "")
                if normalized_text and normalized_text not in body_variants:
                    body_variants.append(normalized_text)

            absolute_url_pattern = re.compile(r"https?://[^\s'\"<>\\]+")
            relative_url_patterns = (
                re.compile(r"/api/accounts/consent[^\s'\"<>\\]*"),
                re.compile(r"/sign-in-with-chatgpt/[^\s'\"<>\\]*"),
                re.compile(r"/api/oauth/oauth2/auth[^\s'\"<>\\]*"),
                re.compile(r"/workspace[^\s'\"<>\\]*"),
                re.compile(r"/organization[^\s'\"<>\\]*"),
                re.compile(r"/about-you[^\s'\"<>\\]*"),
                re.compile(r"/log-in/password[^\s'\"<>\\]*"),
                re.compile(r"/create-account/password[^\s'\"<>\\]*"),
                re.compile(r"/email-verification[^\s'\"<>\\]*"),
                re.compile(r"https?://localhost[^\s'\"<>\\]*"),
            )
            for body_variant in body_variants:
                for match in absolute_url_pattern.findall(body_variant):
                    _append_candidate(match)
                for pattern in relative_url_patterns:
                    for match in pattern.findall(body_variant):
                        _append_candidate(match)

        callback_url = ""
        consent_url = ""
        for candidate_url in candidate_urls:
            if not callback_url and _extract_code_from_url(candidate_url):
                callback_url = candidate_url
                continue
            normalized_lower = candidate_url.lower()
            if not consent_url and (
                "consent_challenge=" in normalized_lower
                or "/api/accounts/consent" in normalized_lower
                or "sign-in-with-chatgpt" in normalized_lower
                or "/workspace" in normalized_lower
                or "/organization" in normalized_lower
                or "/api/oauth/oauth2/auth" in normalized_lower
            ):
                consent_url = candidate_url

        return callback_url, consent_url, final_url

    def _exchange_callback_to_token(callback_url: str, oauth_start: OAuthStart) -> str:
        if pool_relay_enabled and not _should_bypass_relay_for_target(TOKEN_URL):
            return _submit_callback_url_via_pool_relay(
                callback_url=callback_url,
                code_verifier=oauth_start.code_verifier,
                redirect_uri=oauth_start.redirect_uri,
                expected_state=oauth_start.state,
            )
        return submit_callback_url(
            callback_url=callback_url,
            code_verifier=oauth_start.code_verifier,
            redirect_uri=oauth_start.redirect_uri,
            expected_state=oauth_start.state,
            proxy=(static_proxy if pool_relay_enabled else _next_proxy_value()),
        )

    def _discover_workspace_id_from_auth_cookies(log_prefix: str = "") -> str:
        candidate_cookie_names = (
            "oai-client-auth-session",
            "oai-client-auth-info",
            "unified_session_manifest",
            "auth-session-minimized",
        )
        candidate_workspace_hints: Dict[str, list[str]] = {}
        auth_cookie_source = "none"

        for cookie_name in candidate_cookie_names:
            session_cookie = s.cookies.get(cookie_name) or ""
            relay_cookie = relay_cookie_jar.get(cookie_name) or ""
            cookie_source = "session" if session_cookie else ("relay" if relay_cookie else "none")
            raw_cookie = session_cookie or relay_cookie or ""
            if cookie_name == "oai-client-auth-session":
                auth_cookie_source = cookie_source
            if verbose_auth_logs:
                emitter.info(
                    f"{log_prefix}候选 Cookie[{cookie_name}] 来源: {cookie_source}, 长度: {len(raw_cookie)}, 片段数: {len(raw_cookie.split('.')) if raw_cookie else 0}",
                    step="workspace",
                )
            if not raw_cookie:
                continue
            if verbose_auth_logs:
                emitter.info(
                    f"{log_prefix}候选 Cookie[{cookie_name}] 预览: {_mask_secret(raw_cookie)}",
                    step="workspace",
                )

            discovered_workspace_ids: list[str] = []
            for variant_label, variant_value in _cookie_candidate_values(raw_cookie):
                direct_json = _try_parse_json_text(variant_value)
                if direct_json:
                    direct_workspace_ids = _collect_workspace_ids(direct_json)
                    discovered_workspace_ids.extend(
                        item for item in direct_workspace_ids if item not in discovered_workspace_ids
                    )
                    if verbose_auth_logs:
                        emitter.info(
                            f"{log_prefix}Cookie[{cookie_name}] 变体={variant_label} 直解析 keys={','.join(_safe_dict_keys(direct_json)) or '-'}, workspace_ids={','.join(_mask_secret(item, 12, 6) for item in direct_workspace_ids) or '-'}, hits={_format_interesting_paths(_collect_interesting_paths(direct_json))}",
                            step="workspace",
                        )

                whole_b64_json = _try_decode_b64_json(variant_value)
                if whole_b64_json:
                    whole_workspace_ids = _collect_workspace_ids(whole_b64_json)
                    discovered_workspace_ids.extend(
                        item for item in whole_workspace_ids if item not in discovered_workspace_ids
                    )
                    if verbose_auth_logs:
                        emitter.info(
                            f"{log_prefix}Cookie[{cookie_name}] 变体={variant_label} base64-json keys={','.join(_safe_dict_keys(whole_b64_json)) or '-'}, workspace_ids={','.join(_mask_secret(item, 12, 6) for item in whole_workspace_ids) or '-'}, hits={_format_interesting_paths(_collect_interesting_paths(whole_b64_json))}",
                            step="workspace",
                        )

                for item in _cookie_segment_debug(variant_value):
                    key_text = ",".join(item["keys"]) if item["keys"] else "-"
                    workspace_preview = _mask_secret(item["workspace_id"], head=12, tail=6) if item["workspace_id"] else "-"
                    workspace_ids_text = (
                        ",".join(_mask_secret(v, head=12, tail=6) for v in item["workspace_ids"][:3])
                        if item["workspace_ids"]
                        else "-"
                    )
                    discovered_workspace_ids.extend(
                        wid for wid in item["workspace_ids"] if wid not in discovered_workspace_ids
                    )
                    if verbose_auth_logs:
                        emitter.info(
                            f"{log_prefix}Cookie[{cookie_name}] 变体={variant_label} 段[{item['index']}] len={item['raw_len']}, decoded={item['decoded']}, keys={key_text}, workspaces={item['workspace_count']}, workspace_id={workspace_preview}, workspace_ids={workspace_ids_text}, hits={_format_interesting_paths(item['interesting_paths'])}",
                            step="workspace",
                        )

            if discovered_workspace_ids:
                candidate_workspace_hints[cookie_name] = discovered_workspace_ids[:5]

        if candidate_workspace_hints and verbose_auth_logs:
            emitter.info(
                f"{log_prefix}候选 Cookie workspace_id 汇总: "
                + " | ".join(
                    f"{cookie_name}={','.join(_mask_secret(item, 12, 6) for item in workspace_ids[:3])}"
                    for cookie_name, workspace_ids in candidate_workspace_hints.items()
                ),
                step="workspace",
            )

        if verbose_auth_logs:
            emitter.info(
                f"{log_prefix}二段 OAuth 授权 Cookie 来源: {auth_cookie_source}",
                step="workspace",
            )
        for cookie_name in candidate_cookie_names:
            workspace_ids = candidate_workspace_hints.get(cookie_name) or []
            if workspace_ids:
                return str(workspace_ids[0] or "").strip()
        return ""

    def _oauth_submit_workspace_and_org(consent_url: str) -> str:
        workspace_id = _discover_workspace_id_from_auth_cookies(log_prefix="二段 OAuth ")
        if not workspace_id:
            if verbose_auth_logs:
                emitter.info("二段 OAuth 未直接拿到 workspace，先跟随 consent 预热授权上下文...", step="workspace")
            callback_url = _oauth_allow_redirect_extract_callback(
                consent_url,
                referer="https://auth.openai.com/log-in/password",
                timeout=8,
                relay_retries=1,
            )
            if callback_url:
                if verbose_auth_logs:
                    emitter.info("二段 OAuth consent 预热已直接拿到 callback", step="workspace")
                return callback_url
            if verbose_auth_logs:
                emitter.info("二段 OAuth consent 预热未直接拿到 callback，重新扫描 workspace 线索...", step="workspace")
            workspace_id = _discover_workspace_id_from_auth_cookies(log_prefix="二段 OAuth ")
        if not workspace_id:
            emitter.warn("二段 OAuth 会话里没有 workspace 信息", step="workspace")
            return ""

        if verbose_auth_logs:
            emitter.info(
                f"二段 OAuth 准备选择 Workspace: {_mask_secret(workspace_id, head=12, tail=6)}",
                step="workspace",
            )
        headers = _build_openai_headers(
            consent_url,
            did,
            accept="application/json",
            content_type="application/json",
        )
        select_resp = _session_post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers=headers,
            json={"workspace_id": workspace_id},
            allow_redirects=False,
            timeout=8,
            _relay_retries=1,
        )
        if verbose_auth_logs:
            emitter.info(
                f"二段 OAuth workspace/select 状态: {select_resp.status_code}",
                step="workspace",
            )
        if select_resp.status_code in (301, 302, 303, 307, 308):
            redirect_url = urllib.parse.urljoin(
                consent_url,
                str((select_resp.headers or {}).get("Location") or "").strip(),
            )
            if _extract_code_from_url(redirect_url):
                return redirect_url
            callback_url, _ = _oauth_follow_for_callback(redirect_url, referer=consent_url)
            if not callback_url:
                if verbose_auth_logs:
                    emitter.info("二段 OAuth workspace/select 普通跟随未拿到 callback，改用自动重定向兜底...", step="workspace")
                callback_url = _oauth_allow_redirect_extract_callback(redirect_url, referer=consent_url)
            return callback_url
        if select_resp.status_code != 200:
            return ""

        try:
            select_json = select_resp.json() or {}
        except Exception:
            return ""

        next_url = str(select_json.get("continue_url") or "").strip()
        orgs = ((select_json.get("data") or {}).get("orgs") or []) if isinstance(select_json, dict) else []
        org_id = ""
        project_id = ""
        if isinstance(orgs, list) and orgs:
            org_id = str((orgs[0] or {}).get("id") or "").strip()
            projects = (orgs[0] or {}).get("projects") or []
            if isinstance(projects, list) and projects:
                project_id = str((projects[0] or {}).get("id") or "").strip()

        if org_id:
            org_body: Dict[str, str] = {"org_id": org_id}
            if project_id:
                org_body["project_id"] = project_id
            org_referer = urllib.parse.urljoin(consent_url, next_url) if next_url else consent_url
            org_headers = _build_openai_headers(
                org_referer,
                did,
                accept="application/json",
                content_type="application/json",
            )
            org_resp = _session_post(
                "https://auth.openai.com/api/accounts/organization/select",
                headers=org_headers,
                json=org_body,
                allow_redirects=False,
                timeout=8,
                _relay_retries=1,
            )
            if verbose_auth_logs:
                emitter.info(
                    f"二段 OAuth organization/select 状态: {org_resp.status_code}",
                    step="workspace",
                )
            if org_resp.status_code in (301, 302, 303, 307, 308):
                redirect_url = urllib.parse.urljoin(
                    org_referer,
                    str((org_resp.headers or {}).get("Location") or "").strip(),
                )
                if _extract_code_from_url(redirect_url):
                    return redirect_url
                callback_url, _ = _oauth_follow_for_callback(redirect_url, referer=org_referer)
                if not callback_url:
                    if verbose_auth_logs:
                        emitter.info("二段 OAuth organization/select 普通跟随未拿到 callback，改用自动重定向兜底...", step="workspace")
                    callback_url = _oauth_allow_redirect_extract_callback(redirect_url, referer=org_referer)
                return callback_url
            if org_resp.status_code == 200:
                try:
                    org_json = org_resp.json() or {}
                except Exception:
                    org_json = {}
                org_next_url = str(org_json.get("continue_url") or "").strip()
                if org_next_url:
                    org_next_url = urllib.parse.urljoin(org_referer, org_next_url)
                    callback_url, _ = _oauth_follow_for_callback(org_next_url, referer=org_referer)
                    if not callback_url:
                        if verbose_auth_logs:
                            emitter.info("二段 OAuth organization continue_url 普通跟随未拿到 callback，改用自动重定向兜底...", step="workspace")
                        callback_url = _oauth_allow_redirect_extract_callback(org_next_url, referer=org_referer)
                    return callback_url

        if next_url:
            next_url = urllib.parse.urljoin(consent_url, next_url)
            callback_url, _ = _oauth_follow_for_callback(next_url, referer=consent_url)
            if not callback_url:
                if verbose_auth_logs:
                    emitter.info("二段 OAuth workspace continue_url 普通跟随未拿到 callback，改用自动重定向兜底...", step="workspace")
                callback_url = _oauth_allow_redirect_extract_callback(next_url, referer=consent_url)
            return callback_url
        return ""

    def _fresh_oauth_login_after_signup() -> Optional[str]:
        if verbose_auth_logs:
            emitter.info("检测到 add_phone，切换到二段 OAuth 登录链路...", step="oauth_init")
        fast_timeout = 8
        oauth_retry_state = secrets.token_urlsafe(24)
        oauth_retry_code_verifier = _pkce_verifier()
        oauth_retry_code_challenge = _sha256_b64url_no_pad(oauth_retry_code_verifier)
        oauth_retry_params = {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": DEFAULT_REDIRECT_URI,
            "scope": DEFAULT_SCOPE,
            "state": oauth_retry_state,
            "code_challenge": oauth_retry_code_challenge,
            "code_challenge_method": "S256",
            "prompt": "login",
            "login_hint": email,
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
        }
        oauth_resume_params = dict(oauth_retry_params)
        oauth_resume_params.pop("prompt", None)
        oauth_resume_auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(oauth_resume_params)}"
        oauth_retry = OAuthStart(
            auth_url=f"{AUTH_URL}?{urllib.parse.urlencode(oauth_retry_params)}",
            state=oauth_retry_state,
            code_verifier=oauth_retry_code_verifier,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        oauth_token_context = oauth_retry

        def _post_oauth_authorize_continue(referer_url: str, *, screen_hint: str = ""):
            try:
                continue_sentinel = SentinelRuntime(
                    device_id=did,
                    user_agent=fingerprint_profile.user_agent,
                    fingerprint_profile=fingerprint_profile,
                    get_func=_session_get,
                    post_func=_raw_post,
                    emitter=emitter,
                ).build_token(
                    flow="authorize_continue",
                    page_url=referer_url,
                )
            except Exception as exc:
                emitter.warn(f"二段 OAuth authorize/continue Sentinel 生成失败: {exc}", step="oauth_init")
                return None

            payload: Dict[str, Any] = {"username": {"kind": "email", "value": email}}
            if screen_hint:
                payload["screen_hint"] = screen_hint
            return _session_post(
                "https://auth.openai.com/api/accounts/authorize/continue",
                headers=_build_openai_headers(
                    referer_url,
                    did,
                    sentinel_token=continue_sentinel,
                ),
                json=payload,
                allow_redirects=False,
                timeout=fast_timeout,
                _relay_retries=1,
            )

        def _resume_authorization_context(after_url: str) -> tuple[str, str, str]:
            start_referer = str(after_url or "").strip() or "https://auth.openai.com/about-you"
            headers = _build_navigate_headers()
            headers["referer"] = start_referer
            auth_resp = _session_get(
                oauth_resume_auth_url,
                headers=headers,
                allow_redirects=True,
                timeout=fast_timeout,
                _relay_retries=1,
            )
            emitter.info(
                "二段 OAuth 恢复态 auth_url 跟随: "
                + f"status={auth_resp.status_code}, {_response_debug_summary(auth_resp, text_limit=260)}",
                step="create_account",
            )
            callback_url, consent_url, final_url = _extract_oauth_progress_urls(
                auth_resp,
                base_url=oauth_resume_auth_url,
            )
            if callback_url or consent_url:
                return callback_url, consent_url, final_url

            headers["referer"] = oauth_resume_auth_url
            oauth2_resp = _session_get(
                "https://auth.openai.com/api/oauth/oauth2/auth",
                headers=headers,
                params=oauth_resume_params,
                allow_redirects=True,
                timeout=fast_timeout,
                _relay_retries=1,
            )
            emitter.info(
                "二段 OAuth 恢复态 oauth2/auth 跟随: "
                + f"status={oauth2_resp.status_code}, {_response_debug_summary(oauth2_resp, text_limit=260)}",
                step="create_account",
            )
            callback_url, consent_url, final_url = _extract_oauth_progress_urls(
                oauth2_resp,
                base_url="https://auth.openai.com/api/oauth/oauth2/auth",
            )
            if callback_url or consent_url:
                return callback_url, consent_url, final_url

            continue_referer = (
                final_url
                if final_url.startswith("https://auth.openai.com")
                else "https://auth.openai.com/log-in"
            )
            continue_resp = None
            continue_json: Dict[str, Any] = {}
            resumed_continue_url = ""
            resumed_page_type = ""
            retry_delays = (1.5, 2.5)
            for attempt_index in range(len(retry_delays) + 1):
                continue_resp = _post_oauth_authorize_continue(continue_referer)
                if continue_resp is None:
                    return "", "", final_url
                try:
                    continue_json = continue_resp.json() or {}
                except Exception:
                    continue_json = {}
                resumed_continue_url = str(continue_json.get("continue_url") or "").strip()
                resumed_page_type = str(((continue_json.get("page") or {}).get("type")) or "").strip()
                emitter.info(
                    "二段 OAuth 恢复态 authorize/continue 返回: "
                    + f"status={continue_resp.status_code}, page.type={resumed_page_type or '-'}, "
                    + f"continue_url={_mask_secret(resumed_continue_url, head=48, tail=12) if resumed_continue_url else '-'}, "
                    + f"detail={_response_debug_summary(continue_resp, text_limit=260)}",
                    step="create_account",
                )
                if continue_resp.status_code != 429:
                    break
                if attempt_index >= len(retry_delays):
                    break
                retry_after_value = str((continue_resp.headers or {}).get("Retry-After") or "").strip()
                try:
                    retry_after_seconds = max(0.0, float(retry_after_value))
                except (TypeError, ValueError):
                    retry_after_seconds = 0.0
                wait_seconds = retry_after_seconds if retry_after_seconds > 0 else retry_delays[attempt_index]
                emitter.warn(
                    f"二段 OAuth 恢复态 authorize/continue 命中 429，等待 {wait_seconds:.1f}s 后重试...",
                    step="create_account",
                )
                if _interruptible_sleep(wait_seconds, stop_event):
                    return "", "", resumed_continue_url or final_url
            if continue_resp is None:
                return "", "", final_url
            if resumed_continue_url.startswith("/"):
                resumed_continue_url = urllib.parse.urljoin("https://auth.openai.com", resumed_continue_url)
            if _extract_code_from_url(resumed_continue_url):
                return resumed_continue_url, "", resumed_continue_url
            if resumed_continue_url:
                resumed_lower = resumed_continue_url.lower()
                if (
                    "consent_challenge=" in resumed_lower
                    or "/api/accounts/consent" in resumed_lower
                    or "sign-in-with-chatgpt" in resumed_lower
                    or "workspace" in resumed_lower
                    or "organization" in resumed_lower
                    or "/api/oauth/oauth2/auth" in resumed_lower
                ):
                    return "", resumed_continue_url, resumed_continue_url
            if resumed_page_type in {"consent", "workspace", "organization"} and resumed_continue_url:
                return "", resumed_continue_url, resumed_continue_url
            return "", "", resumed_continue_url or final_url

        def _restart_authorization_context(after_url: str) -> tuple[str, str, str, OAuthStart]:
            fresh_state = secrets.token_urlsafe(24)
            fresh_code_verifier = _pkce_verifier()
            fresh_code_challenge = _sha256_b64url_no_pad(fresh_code_verifier)
            fresh_params = {
                "client_id": CLIENT_ID,
                "response_type": "code",
                "redirect_uri": DEFAULT_REDIRECT_URI,
                "scope": DEFAULT_SCOPE,
                "state": fresh_state,
                "code_challenge": fresh_code_challenge,
                "code_challenge_method": "S256",
                "login_hint": email,
                "id_token_add_organizations": "true",
                "codex_cli_simplified_flow": "true",
            }
            oauth_fresh = OAuthStart(
                auth_url=f"{AUTH_URL}?{urllib.parse.urlencode(fresh_params)}",
                state=fresh_state,
                code_verifier=fresh_code_verifier,
                redirect_uri=DEFAULT_REDIRECT_URI,
            )

            def _extract_callback_from_exception(exc: Exception) -> str:
                maybe_localhost = re.search(r"(https?://localhost[^\s'\"<>]+)", str(exc))
                if maybe_localhost:
                    callback_candidate = maybe_localhost.group(1)
                    if _extract_code_from_url(callback_candidate):
                        return callback_candidate
                return ""

            referer_url = str(after_url or "").strip() or "https://auth.openai.com/about-you"
            headers = _build_navigate_headers()
            headers["referer"] = referer_url
            final_url = oauth_fresh.auth_url

            try:
                fresh_auth_resp = _session_get(
                    oauth_fresh.auth_url,
                    headers=headers,
                    allow_redirects=True,
                    timeout=fast_timeout,
                    _relay_retries=1,
                )
            except Exception as exc:
                callback_url = _extract_callback_from_exception(exc)
                if callback_url:
                    emitter.info(
                        "二段 OAuth 新事务 auth_url 直接捕获 callback，准备交换 Token...",
                        step="create_account",
                    )
                    return callback_url, "", callback_url, oauth_fresh
                emitter.warn(f"二段 OAuth 新事务 auth_url 跟随失败: {exc}", step="create_account")
            else:
                emitter.info(
                    "二段 OAuth 新事务 auth_url 跟随: "
                    + f"status={fresh_auth_resp.status_code}, {_response_debug_summary(fresh_auth_resp, text_limit=260)}",
                    step="create_account",
                )
                callback_url, consent_url, final_url = _extract_oauth_progress_urls(
                    fresh_auth_resp,
                    base_url=oauth_fresh.auth_url,
                )
                if callback_url or consent_url:
                    return callback_url, consent_url, final_url, oauth_fresh
                final_url = str(getattr(fresh_auth_resp, "url", "") or final_url).strip() or final_url

            headers["referer"] = oauth_fresh.auth_url
            try:
                fresh_oauth2_resp = _session_get(
                    "https://auth.openai.com/api/oauth/oauth2/auth",
                    headers=headers,
                    params=fresh_params,
                    allow_redirects=True,
                    timeout=fast_timeout,
                    _relay_retries=1,
                )
            except Exception as exc:
                callback_url = _extract_callback_from_exception(exc)
                if callback_url:
                    emitter.info(
                        "二段 OAuth 新事务 oauth2/auth 直接捕获 callback，准备交换 Token...",
                        step="create_account",
                    )
                    return callback_url, "", callback_url, oauth_fresh
                emitter.warn(f"二段 OAuth 新事务 oauth2/auth 跟随失败: {exc}", step="create_account")
                return "", "", final_url, oauth_fresh

            emitter.info(
                "二段 OAuth 新事务 oauth2/auth 跟随: "
                + f"status={fresh_oauth2_resp.status_code}, {_response_debug_summary(fresh_oauth2_resp, text_limit=260)}",
                step="create_account",
            )
            callback_url, consent_url, final_url = _extract_oauth_progress_urls(
                fresh_oauth2_resp,
                base_url="https://auth.openai.com/api/oauth/oauth2/auth",
            )
            final_url = str(getattr(fresh_oauth2_resp, "url", "") or final_url).strip() or final_url
            return callback_url, consent_url, final_url, oauth_fresh

        def _apply_resumed_authorization_state(
            resumed_callback_url: str,
            resumed_consent_url: str,
            resumed_final_url: str,
            current_continue_url: str,
            current_page_type: str,
        ) -> tuple[str, str]:
            next_continue_url = str(current_continue_url or "").strip()
            next_page_type = str(current_page_type or "").strip()

            if resumed_callback_url:
                return resumed_callback_url, "callback"

            def _infer_page_type_from_url(candidate_url: str, fallback_page_type: str = "") -> str:
                candidate_lower = str(candidate_url or "").lower()
                if not candidate_lower:
                    return fallback_page_type
                if _extract_code_from_url(candidate_url):
                    return "callback"
                if "consent" in candidate_lower or "oauth2/auth" in candidate_lower:
                    return "consent"
                if "workspace" in candidate_lower:
                    return "workspace"
                if "organization" in candidate_lower:
                    return "organization"
                if "about-you" in candidate_lower:
                    return "about_you"
                if "log-in/password" in candidate_lower:
                    return "login_password"
                if "create-account/password" in candidate_lower:
                    return "create_account_password"
                if "email-verification" in candidate_lower or "email-otp" in candidate_lower:
                    return "email_otp_verification"
                return fallback_page_type

            if resumed_consent_url:
                next_continue_url = resumed_consent_url
                next_page_type = _infer_page_type_from_url(resumed_consent_url, next_page_type)
                return next_continue_url, next_page_type

            if resumed_final_url:
                next_continue_url = resumed_final_url
                next_page_type = _infer_page_type_from_url(resumed_final_url, next_page_type)
                return next_continue_url, next_page_type

            return next_continue_url, next_page_type

        def _bootstrap_session() -> str:
            headers = _build_navigate_headers()
            headers["referer"] = "https://chatgpt.com/"
            resp = _session_get(
                oauth_retry.auth_url,
                headers=headers,
                allow_redirects=True,
                timeout=fast_timeout,
                _relay_retries=1,
            )
            final_url = str(getattr(resp, "url", "") or oauth_retry.auth_url).strip()
            has_login_session = bool(s.cookies.get("login_session") or relay_cookie_jar.get("login_session"))
            if has_login_session:
                return final_url
            headers["referer"] = oauth_retry.auth_url
            resp = _session_get(
                "https://auth.openai.com/api/oauth/oauth2/auth",
                headers=headers,
                params=oauth_retry_params,
                allow_redirects=True,
                timeout=fast_timeout,
                _relay_retries=1,
            )
            return str(getattr(resp, "url", "") or final_url).strip()

        try:
            authorize_final_url = _bootstrap_session()
        except Exception as exc:
            emitter.error(f"二段 OAuth 初始化失败: {exc}", step="oauth_init")
            return None
        if verbose_auth_logs:
            emitter.info(
                f"二段 OAuth 初始化落点: {_mask_secret(authorize_final_url, head=48, tail=12)}",
                step="oauth_init",
            )
        if verbose_auth_logs:
            emitter.info(
                f"二段 OAuth 初始化 Cookie 概览: {_auth_cookie_presence_summary()}",
                step="oauth_init",
            )

        continue_referer = (
            authorize_final_url
            if authorize_final_url.startswith("https://auth.openai.com")
            else "https://auth.openai.com/log-in"
        )
        if verbose_auth_logs:
            emitter.info("二段 OAuth 正在提交 authorize/continue...", step="oauth_init")
        continue_resp = _post_oauth_authorize_continue(continue_referer)
        if continue_resp is None:
            emitter.error("二段 OAuth Sentinel 生成失败", step="oauth_init")
            return None
        if continue_resp.status_code == 400 and "invalid_auth_step" in str(continue_resp.text or ""):
            try:
                authorize_final_url = _bootstrap_session()
                continue_referer = (
                    authorize_final_url
                    if authorize_final_url.startswith("https://auth.openai.com")
                    else "https://auth.openai.com/log-in"
                )
                continue_resp = _post_oauth_authorize_continue(continue_referer)
                if continue_resp is None:
                    emitter.error("二段 OAuth 重试 Sentinel 生成失败", step="oauth_init")
                    return None
            except Exception as exc:
                emitter.error(f"二段 OAuth 重试初始化失败: {exc}", step="oauth_init")
                return None
        if continue_resp.status_code != 200:
            emitter.error(
                f"二段 OAuth authorize/continue 失败（状态码 {continue_resp.status_code}）: {str(continue_resp.text or '')[:220]}",
                step="oauth_init",
            )
            return None
        try:
            continue_json = continue_resp.json() or {}
        except Exception:
            continue_json = {}
        continue_url = str(continue_json.get("continue_url") or "").strip()
        page_type = str(((continue_json.get("page") or {}).get("type")) or "").strip()
        if verbose_auth_logs:
            emitter.info(
                "二段 OAuth authorize/continue 返回: "
                + f"page.type={page_type or '-'}, continue_url={_mask_secret(continue_url, head=48, tail=12) if continue_url else '-'}",
                step="oauth_init",
            )
        resolution_round = 0
        max_resolution_rounds = 6
        while resolution_round < max_resolution_rounds:
            resolution_round += 1
            continue_url = str(continue_url or "").strip()
            page_type = str(page_type or "").strip()
            continue_url_lower = continue_url.lower()

            if page_type == "create_account_password" or "create-account/password" in continue_url_lower:
                emitter.warn(
                    "二段 OAuth 落到 create_account_password，判定为恢复链路被推回注册密码页，改走授权上下文恢复...",
                    step="create_account",
                )
                oauth_create_password_url = continue_url
                if oauth_create_password_url.startswith("/"):
                    oauth_create_password_url = urllib.parse.urljoin("https://auth.openai.com", oauth_create_password_url)
                if not oauth_create_password_url:
                    oauth_create_password_url = "https://auth.openai.com/create-account/password"
                try:
                    resumed_callback_url, resumed_consent_url, resumed_final_url = _resume_authorization_context(
                        oauth_create_password_url
                    )
                except Exception as exc:
                    emitter.warn(f"二段 OAuth create_account_password 恢复授权上下文失败: {exc}", step="create_account")
                    resumed_callback_url, resumed_consent_url, resumed_final_url = "", "", ""
                else:
                    emitter.info(
                        "二段 OAuth 注册密码页恢复结果: "
                        + f"callback={_mask_secret(resumed_callback_url, head=48, tail=12) if resumed_callback_url else '-'}, "
                        + f"consent={_mask_secret(resumed_consent_url, head=48, tail=12) if resumed_consent_url else '-'}, "
                        + f"final={_mask_secret(resumed_final_url, head=48, tail=12) if resumed_final_url else '-'}",
                        step="create_account",
                    )
                previous_continue_url = continue_url
                previous_page_type = page_type
                continue_url, page_type = _apply_resumed_authorization_state(
                    resumed_callback_url,
                    resumed_consent_url,
                    resumed_final_url,
                    continue_url,
                    page_type,
                )
                if continue_url == previous_continue_url and page_type == previous_page_type:
                    emitter.error(
                        "二段 OAuth 仍停留在 create_account_password，已停止错误的 password/verify 调用，请等待人工处理",
                        step="create_account",
                    )
                    return None
                emitter.info(
                    "二段 OAuth create_account_password 恢复后上下文: "
                    + f"page.type={page_type or '-'}, continue_url={_mask_secret(continue_url, head=48, tail=12) if continue_url else '-'}",
                    step="create_account",
                )
                continue

            if page_type == "login_password" or "log-in/password" in continue_url_lower:
                if verbose_auth_logs:
                    emitter.info("二段 OAuth 正在校验密码...", step="verify_otp")
                try:
                    password_sentinel = SentinelRuntime(
                        device_id=did,
                        user_agent=fingerprint_profile.user_agent,
                        fingerprint_profile=fingerprint_profile,
                        get_func=_session_get,
                        post_func=_raw_post,
                        emitter=emitter,
                    ).build_token(
                        flow="password_verify",
                        page_url="https://auth.openai.com/log-in/password",
                    )
                except Exception as exc:
                    emitter.error(f"二段 OAuth password_verify Sentinel 生成失败: {exc}", step="verify_otp")
                    return None
                verify_resp = _session_post(
                    "https://auth.openai.com/api/accounts/password/verify",
                    headers=_build_openai_headers(
                        "https://auth.openai.com/log-in/password",
                        did,
                        sentinel_token=password_sentinel,
                    ),
                    json={"password": account_password},
                    allow_redirects=False,
                    timeout=fast_timeout,
                    _relay_retries=1,
                )
                if verify_resp.status_code != 200:
                    emitter.error(
                        f"二段 OAuth 密码校验失败（状态码 {verify_resp.status_code}）: {str(verify_resp.text or '')[:220]}",
                        step="verify_otp",
                    )
                    return None
                try:
                    verify_json = verify_resp.json() or {}
                except Exception:
                    verify_json = {}
                continue_url = str(verify_json.get("continue_url") or continue_url or "").strip()
                page_type = str(((verify_json.get("page") or {}).get("type")) or page_type or "").strip()
                if verbose_auth_logs:
                    emitter.info(
                        "二段 OAuth password/verify 返回: "
                        + f"page.type={page_type or '-'}, continue_url={_mask_secret(continue_url, head=48, tail=12) if continue_url else '-'}",
                        step="verify_otp",
                    )
                continue

            need_oauth_otp = (
                page_type == "email_otp_verification"
                or "email-verification" in continue_url_lower
                or "email-otp" in continue_url_lower
            )
            if need_oauth_otp:
                oauth_otp_wait_seconds = 45
                emitter.info(
                    "二段 OAuth 等待邮箱新验证码...",
                    step="wait_otp",
                )
                if verbose_auth_logs:
                    emitter.info(
                        "二段 OAuth OTP 上下文: "
                        + f"page.type={page_type or '-'}, "
                        + f"continue_url={_mask_secret(continue_url, head=48, tail=12) if continue_url else '-'}",
                        step="send_otp",
                    )
                    emitter.info(
                        f"二段 OAuth OTP 阶段 Cookie 概览: {_auth_cookie_presence_summary()}",
                        step="send_otp",
                    )
                otp_deadline = time.time() + oauth_otp_wait_seconds
                tried_codes: set[str] = set()
                initial_signup_code = str(code or "").strip()
                if verbose_auth_logs:
                    emitter.info(
                        "二段 OAuth OTP 拉取上下文: "
                        + f"provider={type(mail_provider).__name__ if mail_provider is not None else 'Mail.tm'}, "
                        + f"signup_code={initial_signup_code or '-'}, "
                        + f"max_wait={oauth_otp_wait_seconds}s",
                        step="wait_otp",
                    )
                otp_success = False
                otp_wait_round = 0

                def _submit_oauth_otp(candidate_code: str, source: str = "mailbox") -> bool:
                    otp_code_local = str(candidate_code or "").strip()
                    if not otp_code_local:
                        return False
                    if initial_signup_code and otp_code_local == initial_signup_code:
                        if verbose_auth_logs:
                            emitter.info(
                                f"二段 OAuth 忽略首段注册旧 OTP: {otp_code_local}",
                                step="wait_otp",
                            )
                        return False
                    if otp_code_local in tried_codes:
                        if verbose_auth_logs:
                            emitter.info(
                                f"二段 OAuth 收到已尝试过的旧 OTP: {otp_code_local}，继续等待新验证码",
                                step="wait_otp",
                            )
                        return False
                    tried_codes.add(otp_code_local)
                    if verbose_auth_logs:
                        emitter.info(
                            "二段 OAuth 正在验证邮箱 OTP: "
                            + f"{otp_code_local} | attempt={len(tried_codes)} | source={source}",
                            step="verify_otp",
                        )
                    otp_resp = _session_post(
                        "https://auth.openai.com/api/accounts/email-otp/validate",
                        headers=_build_openai_headers(
                            "https://auth.openai.com/email-verification",
                            did,
                        ),
                        json={"code": otp_code_local},
                        allow_redirects=False,
                        timeout=fast_timeout,
                        _relay_retries=1,
                    )
                    if verbose_auth_logs:
                        emitter.info(
                            f"二段 OAuth OTP 校验状态: {otp_resp.status_code}",
                            step="verify_otp",
                        )
                    if otp_resp.status_code != 200:
                        failure_summary = _response_debug_summary(otp_resp, text_limit=320)
                        response_text = str(getattr(otp_resp, "text", "") or "")
                        response_text_lower = response_text.lower()
                        reason_hint = "未识别到明确错误字段"
                        if (
                            "invalid_otp" in response_text_lower
                            or "invalid code" in response_text_lower
                            or "incorrect code" in response_text_lower
                            or "wrong code" in response_text_lower
                            or "wrong_email_otp_code" in response_text_lower
                            or "expired code" in response_text_lower
                            or "otp_expired" in response_text_lower
                        ):
                            reason_hint = "更像是验证码错误、过期，或拿到了旧验证码"
                        elif (
                            "invalid_auth_step" in response_text_lower
                            or "unauthorized" in response_text_lower
                            or otp_resp.status_code == 401
                        ):
                            reason_hint = "更像是认证会话或流程步骤失效，不像单纯验证码错误"
                        elif "phone" in response_text_lower or "add-phone" in response_text_lower:
                            reason_hint = "当前会话可能仍然被手机号验证流程拦截"
                        if verbose_auth_logs:
                            emitter.warn(
                                f"二段 OAuth OTP 失败详情: {failure_summary}",
                                step="verify_otp",
                            )
                            emitter.warn(
                                "二段 OAuth OTP 失败上下文: "
                                + f"page.type={page_type or '-'}, "
                                + f"continue_url={_mask_secret(continue_url, head=48, tail=12) if continue_url else '-'}, "
                                + f"cookies={_auth_cookie_presence_summary()}",
                                step="verify_otp",
                            )
                            emitter.warn(
                                f"二段 OAuth OTP 失败原因猜测: {reason_hint}",
                                step="verify_otp",
                            )
                        return False
                    try:
                        otp_json = otp_resp.json() or {}
                    except Exception:
                        otp_json = {}
                    nonlocal_continue_url = str(otp_json.get("continue_url") or continue_url or "").strip()
                    nonlocal_page_type = str(((otp_json.get("page") or {}).get("type")) or page_type or "").strip()
                    if verbose_auth_logs:
                        emitter.info(
                            "二段 OAuth OTP 校验通过后上下文: "
                            + f"page.type={nonlocal_page_type or '-'}, continue_url={_mask_secret(nonlocal_continue_url, head=48, tail=12) if nonlocal_continue_url else '-'}",
                            step="verify_otp",
                        )
                    nonlocal_vars["continue_url"] = nonlocal_continue_url
                    nonlocal_vars["page_type"] = nonlocal_page_type
                    return True

                nonlocal_vars = {"continue_url": continue_url, "page_type": page_type}
                while not otp_success and time.time() < otp_deadline and not _stopped():
                    otp_wait_round += 1
                    remaining_seconds = max(1, int(max(0.0, otp_deadline - time.time())))
                    fetch_timeout = min(6, remaining_seconds)
                    if mail_provider is not None:
                        try:
                            otp_code = mail_provider.wait_for_otp(
                                dev_token,
                                email,
                                proxy=static_proxy,
                                proxy_selector=mail_proxy_selector,
                                stop_event=stop_event,
                                timeout=fetch_timeout,
                            )
                        except TypeError:
                            otp_code = mail_provider.wait_for_otp(
                                dev_token,
                                email,
                                proxy=static_proxy,
                                stop_event=stop_event,
                                timeout=fetch_timeout,
                            )
                    else:
                        otp_code = get_oai_code(
                            dev_token,
                            email,
                            static_proxies,
                            emitter,
                            stop_event,
                            proxy_selector=mail_proxies_selector,
                        )
                    otp_code = str(otp_code or "").strip()
                    if not otp_code:
                        if verbose_auth_logs and otp_wait_round % 2 == 0:
                            waited_seconds = max(0, int(oauth_otp_wait_seconds - max(0.0, otp_deadline - time.time())))
                            emitter.info(
                                f"二段 OAuth 仍在等待新邮箱 OTP... ({waited_seconds}s/{oauth_otp_wait_seconds}s)",
                                step="wait_otp",
                            )
                        if _interruptible_sleep(1.5, stop_event):
                            return None
                        continue

                    otp_success = _submit_oauth_otp(otp_code, source="mailbox")
                    continue_url = str(nonlocal_vars.get("continue_url") or continue_url or "").strip()
                    page_type = str(nonlocal_vars.get("page_type") or page_type or "").strip()

                if not otp_success:
                    emitter.warn(
                        "二段 OAuth 在短等待窗口内未拿到可用新 OTP，准备结束回退流程",
                        step="verify_otp",
                    )
                if not otp_success:
                    emitter.error("二段 OAuth 邮箱 OTP 验证失败", step="verify_otp")
                    return None
                continue

            need_oauth_profile = (
                page_type == "about_you"
                or "about-you" in continue_url_lower
            )
            if need_oauth_profile:
                emitter.info("二段 OAuth 落到 about_you，当前事务判定不可继续，改为重新拉起一轮新的授权事务...", step="create_account")
                oauth_about_you_url = str(continue_url or "").strip()
                if oauth_about_you_url.startswith("/"):
                    oauth_about_you_url = urllib.parse.urljoin("https://auth.openai.com", oauth_about_you_url)
                if not oauth_about_you_url:
                    oauth_about_you_url = "https://auth.openai.com/about-you"
                try:
                    resumed_callback_url, resumed_consent_url, resumed_final_url, oauth_fresh = _restart_authorization_context(
                        oauth_about_you_url
                    )
                except Exception as exc:
                    emitter.warn(f"二段 OAuth about_you 新建授权事务失败: {exc}", step="create_account")
                    resumed_callback_url, resumed_consent_url, resumed_final_url = "", "", ""
                else:
                    oauth_token_context = oauth_fresh
                    emitter.info(
                        "二段 OAuth 新事务结果: "
                        + f"callback={_mask_secret(resumed_callback_url, head=48, tail=12) if resumed_callback_url else '-'}, "
                        + f"consent={_mask_secret(resumed_consent_url, head=48, tail=12) if resumed_consent_url else '-'}, "
                        + f"final={_mask_secret(resumed_final_url, head=48, tail=12) if resumed_final_url else '-'}",
                        step="create_account",
                    )
                    error_payload_summary = _error_payload_summary_from_url(resumed_final_url)
                    if error_payload_summary:
                        emitter.warn(
                            f"二段 OAuth 新事务 error payload: {error_payload_summary}",
                            step="create_account",
                        )

                if (
                    not resumed_callback_url
                    and not resumed_consent_url
                    and resumed_final_url
                    and "/error?" in resumed_final_url
                ):
                    blocked_by_phone_gate = _looks_like_phone_gate_error(resumed_final_url)
                    try:
                        s.close()
                    except Exception:
                        pass
                    raise PhoneVerificationRequiredError(
                        (
                            "账号创建成功，但账号当前仍被手机号验证拦截，无法自动进入 workspace 授权阶段"
                            if blocked_by_phone_gate
                            else "账号创建成功，但账号当前仍被后置风控/错误页拦截，无法自动进入 workspace 授权阶段"
                        ),
                        page_type="add_phone",
                        continue_url=oauth_about_you_url,
                        final_url=resumed_final_url,
                    )

                continue_url, page_type = _apply_resumed_authorization_state(
                    resumed_callback_url,
                    resumed_consent_url,
                    resumed_final_url,
                    continue_url,
                    page_type,
                )
                if page_type == "about_you" or "about-you" in str(continue_url or "").lower():
                    emitter.warn(
                        "二段 OAuth 仍停留在 about_you，后续将直接走 consent/workspace 回退，不再重复提交 create_account",
                        step="create_account",
                    )
                    break
                emitter.info(
                    "二段 OAuth 跳过重复 create_account 后当前上下文: "
                    + f"page.type={page_type or '-'}, continue_url={_mask_secret(continue_url, head=48, tail=12) if continue_url else '-'}",
                    step="create_account",
                )
                continue

            break

        callback_url = ""
        consent_url = str(continue_url or "").strip()
        if consent_url.startswith("/"):
            consent_url = urllib.parse.urljoin("https://auth.openai.com", consent_url)
        if consent_url and _extract_code_from_url(consent_url):
            callback_url = consent_url
        if not callback_url and consent_url:
            if verbose_auth_logs:
                emitter.info("二段 OAuth 正在跟随 continue_url 提取 callback...", step="get_token")
            callback_url, _ = _oauth_follow_for_callback(
                consent_url,
                referer="https://auth.openai.com/log-in/password",
                timeout=fast_timeout,
                relay_retries=1,
            )
            if not callback_url:
                if verbose_auth_logs:
                    emitter.info("二段 OAuth continue_url 普通跟随未拿到 callback，改用自动重定向兜底...", step="get_token")
                callback_url = _oauth_allow_redirect_extract_callback(
                    consent_url,
                    referer="https://auth.openai.com/log-in/password",
                    timeout=fast_timeout,
                    relay_retries=1,
                )
        consent_hint = (
            ("consent" in consent_url)
            or ("sign-in-with-chatgpt" in consent_url)
            or ("workspace" in consent_url)
            or ("organization" in consent_url)
            or ("consent" in page_type)
            or ("workspace" in page_type)
            or ("organization" in page_type)
        )
        if not callback_url and consent_hint:
            if not consent_url:
                consent_url = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
            if verbose_auth_logs:
                emitter.info("二段 OAuth 正在自动选择 workspace/org...", step="workspace")
            callback_url = _oauth_submit_workspace_and_org(consent_url)
        if not callback_url:
            fallback_consent = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
            if verbose_auth_logs:
                emitter.info("二段 OAuth 正在回退 consent 路径重试...", step="workspace")
            callback_url = _oauth_submit_workspace_and_org(fallback_consent)
            if not callback_url:
                callback_url, _ = _oauth_follow_for_callback(
                    fallback_consent,
                    referer="https://auth.openai.com/log-in/password",
                    timeout=fast_timeout,
                    relay_retries=1,
                )
            if not callback_url:
                if verbose_auth_logs:
                    emitter.info("二段 OAuth fallback consent 普通跟随未拿到 callback，改用自动重定向兜底...", step="workspace")
                callback_url = _oauth_allow_redirect_extract_callback(
                    fallback_consent,
                    referer="https://auth.openai.com/log-in/password",
                    timeout=fast_timeout,
                    relay_retries=1,
                )
        if not callback_url:
            emitter.error("二段 OAuth 未获取到 callback URL", step="get_token")
            return None

        try:
            return _exchange_callback_to_token(callback_url, oauth_token_context)
        except Exception as exc:
            emitter.error(f"二段 OAuth token 交换失败: {exc}", step="get_token")
            return None

    def _stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    try:
        selected_browser_proxy = ""
        selected_browser_proxies: Any = None
        # ------- 步骤1：网络环境检查 -------
        emitter.info("正在检查网络环境...", step="check_proxy")
        try:
            trace_text = ""
            relay_error = ""
            relay_used = False
            if browser_mode:
                selected_browser_proxy = _next_proxy_value()
                selected_browser_proxies = _to_proxies_dict(selected_browser_proxy)
                trace_resp = _call_with_http_fallback(
                    requests.get,
                    "https://cloudflare.com/cdn-cgi/trace",
                    proxies=selected_browser_proxies,
                    http_version=DEFAULT_HTTP_VERSION,
                    impersonate=_current_impersonate(),
                    timeout=10,
                )
                trace_text = str(trace_resp.text or "")
                emitter.info(
                    "浏览器模式网络出口: "
                    + (
                        _mask_secret(selected_browser_proxy, head=24, tail=10)
                        if selected_browser_proxy
                        else "直连"
                    ),
                    step="check_proxy",
                )
            elif pool_cfg["enabled"]:
                try:
                    trace_text = _trace_via_pool_relay(pool_cfg)
                    relay_used = True
                except Exception as e:
                    relay_error = str(e)
                    if static_proxy:
                        emitter.warn(f"代理池 relay 检查失败，回退固定代理: {relay_error}", step="check_proxy")
                    else:
                        emitter.warn(f"代理池 relay 检查失败，尝试直连代理: {relay_error}", step="check_proxy")
            if not trace_text:
                trace_resp = _session_get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
                trace_text = trace_resp.text
            trace = trace_text
            loc_re = re.search(r"^loc=(.+)$", trace, re.MULTILINE)
            loc = loc_re.group(1) if loc_re else None
            ip_re = re.search(r"^ip=(.+)$", trace, re.MULTILINE)
            current_ip = ip_re.group(1).strip() if ip_re else ""
            if relay_used:
                emitter.info("代理池 relay 连通检查成功", step="check_proxy")
            emitter.info(f"当前 IP 所在地: {loc}", step="check_proxy")
            if current_ip:
                emitter.info(f"当前出口 IP: {current_ip}", step="check_proxy")
            if loc == "CN" or loc == "HK":
                emitter.error("检查代理哦 — 所在地不支持 (CN/HK)", step="check_proxy")
                return None
            emitter.success("网络环境检查通过", step="check_proxy")
            if not browser_mode:
                _ensure_openai_relay_ready()
        except Exception as e:
            emitter.error(f"网络连接检查失败: {e}", step="check_proxy")
            return None

        if _stopped():
            return None

        # ------- 步骤2：创建临时邮箱 -------
        if mail_provider is not None:
            emitter.info("正在创建临时邮箱...", step="create_email")
            try:
                if browser_mode:
                    email, dev_token = mail_provider.create_mailbox(
                        proxy=selected_browser_proxy,
                        proxy_selector=None,
                    )
                else:
                    email, dev_token = mail_provider.create_mailbox(
                        proxy=static_proxy,
                        proxy_selector=mail_proxy_selector,
                    )
            except TypeError:
                email, dev_token = mail_provider.create_mailbox(
                    proxy=selected_browser_proxy if browser_mode else static_proxy
                )
        else:
            emitter.info("正在创建 Mail.tm 临时邮箱...", step="create_email")
            email, dev_token = get_email_and_token(
                selected_browser_proxies if browser_mode else static_proxies,
                emitter,
                proxy_selector=None if browser_mode else mail_proxies_selector,
            )
        if not email or not dev_token:
            emitter.error("临时邮箱创建失败", step="create_email")
            return None
        emitter.success(f"临时邮箱创建成功: {email}", step="create_email")

        if _stopped():
            return None

        if browser_mode:
            emitter.info("当前为浏览器注册模式，准备切换浏览器流程...", step="oauth_init")
            try:
                token_json = run_browser_registration(
                    email=email,
                    dev_token=dev_token,
                    emitter=emitter,
                    stop_event=stop_event,
                    mail_provider=mail_provider,
                    proxy=selected_browser_proxy,
                    browser_config=normalized_browser_config,
                    user_agent=fingerprint_profile.user_agent,
                    fingerprint_profile=fingerprint_profile,
                    generate_oauth_url_func=lambda: generate_oauth_url(screen_hint="signup"),
                    generate_login_oauth_url_func=(
                        (lambda: generate_oauth_url(screen_hint="", prompt="", login_hint=""))
                        if str(normalized_browser_config.get("register_mode") or "").strip().lower() == "browser_manual_v2"
                        else (lambda: generate_oauth_url(
                            screen_hint="",
                            login_hint=email,
                        ))
                    ),
                    submit_callback_func=submit_callback_url,
                    exchange_callback_payload_func=exchange_callback_to_token_payload,
                    build_token_result_func=build_token_result_from_payloads,
                    build_browser_session_token_func=lambda session_payload: _build_token_from_chatgpt_session_payload(
                        session_payload,
                        source_label="浏览器 session fast path",
                    ),
                    fallback_wait_for_otp_func=get_oai_code,
                    random_password_func=_random_password,
                    random_profile_name_func=_random_profile_name,
                    random_profile_birthdate_func=_random_profile_birthdate,
                )
            except BrowserPhoneVerificationRequiredError as exc:
                try:
                    s.close()
                except Exception:
                    pass
                raise PhoneVerificationRequiredError(
                    str(exc),
                    page_type=getattr(exc, "page_type", ""),
                    continue_url=getattr(exc, "continue_url", ""),
                    final_url=getattr(exc, "final_url", ""),
                )
            except Exception as exc:
                emitter.error(f"浏览器注册流程失败: {exc}", step="runtime")
                try:
                    s.close()
                except Exception:
                    pass
                return None

            try:
                s.close()
            except Exception:
                pass
            return token_json

        # ------- 步骤3：生成 OAuth URL，获取 Device ID -------
        emitter.info("正在生成 OAuth 授权链接...", step="oauth_init")
        oauth = generate_oauth_url()
        url = oauth.auth_url

        did = s.cookies.get("oai-did") or relay_cookie_jar.get("oai-did") or ""
        if not did:
            did = str(uuid.uuid4())
            relay_cookie_jar["oai-did"] = did
            try:
                s.cookies.set("oai-did", did)
                s.cookies.set("oai-did", did, domain=".auth.openai.com")
                s.cookies.set("oai-did", did, domain="auth.openai.com")
            except Exception:
                pass

        resp = _session_get(url, timeout=20, headers=_build_navigate_headers(), allow_redirects=True)
        emitter.info(f"OAuth 初始化状态: {resp.status_code}", step="oauth_init")
        if resp.status_code >= 400:
            emitter.error(f"OAuth 初始化失败，状态码: {resp.status_code}", step="oauth_init")
            return None
        did = s.cookies.get("oai-did") or relay_cookie_jar.get("oai-did") or did
        if not did:
            did_m = re.search(r"oai-did=([0-9a-fA-F-]{20,})", str(resp.text or ""))
            if did_m:
                did = did_m.group(1)
        if not did:
            emitter.warn(f"未从响应提取到 oai-did，已使用临时 Device ID: {did}", step="oauth_init")
        else:
            emitter.info(f"Device ID: {did}", step="oauth_init")

        has_login_session = bool(getattr(s.cookies, "get", None) and s.cookies.get("login_session"))
        if not has_login_session:
            has_login_session = "login_session" in relay_cookie_jar
        if not has_login_session:
            emitter.warn("OAuth 初始化未获取 login_session cookie，继续沿用当前会话尝试注册", step="oauth_init")

        if _stopped():
            return None

        # ------- 步骤4：获取 Sentinel Token -------
        emitter.info("正在生成注册初始化 Sentinel Token...", step="sentinel")
        try:
            sentinel = _build_protocol_sentinel_token(
                flow="authorize_continue",
                page_url="https://auth.openai.com/create-account",
            )
        except Exception as exc:
            emitter.error(f"注册初始化 Sentinel Token 生成失败: {exc}", step="sentinel")
            return None
        emitter.success("注册初始化 Sentinel Token 生成成功", step="sentinel")

        if _stopped():
            return None

        # ------- 步骤5：初始化注册会话 -------
        emitter.info("正在初始化注册会话...", step="signup")
        continue_resp = _session_post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=_build_openai_headers(
                "https://auth.openai.com/create-account",
                did,
                sentinel_token=sentinel,
            ),
            json={"username": {"kind": "email", "value": email}, "screen_hint": "signup"},
        )
        if continue_resp.status_code != 200:
            emitter.error(
                f"注册会话初始化失败（状态码 {continue_resp.status_code}）: {str(continue_resp.text or '')[:220]}",
                step="signup",
            )
            return None

        # ------- 步骤6：提交注册 -------
        emitter.info("正在提交注册表单...", step="signup")
        account_password = _random_password(16)
        emitter.info("正在生成注册提交 Sentinel Token...", step="signup")
        try:
            signup_sentinel = _build_protocol_sentinel_token(
                flow="authorize_continue",
                page_url="https://auth.openai.com/create-account/password",
            )
        except Exception as exc:
            emitter.error(f"注册提交 Sentinel Token 生成失败: {exc}", step="signup")
            return None
        emitter.success("注册提交 Sentinel Token 生成成功", step="signup")
        signup_resp = _session_post(
            "https://auth.openai.com/api/accounts/user/register",
            headers=_build_openai_headers(
                "https://auth.openai.com/create-account/password",
                did,
                sentinel_token=signup_sentinel,
            ),
            json={"username": email, "password": account_password},
        )
        emitter.info(f"注册表单提交状态: {signup_resp.status_code}", step="signup")
        if signup_resp.status_code not in (200, 201, 302):
            emitter.error(
                f"注册表单提交失败（状态码 {signup_resp.status_code}）: {str(signup_resp.text or '')[:220]}",
                step="signup",
            )
            return None

        if _stopped():
            return None

        # ------- 步骤7：发送邮箱验证码 -------
        emitter.info("正在发送邮箱验证码...", step="send_otp")
        otp_headers = _build_email_otp_headers("https://auth.openai.com/create-account/password")
        otp_resp = _session_get(
            "https://auth.openai.com/api/accounts/email-otp/send",
            headers=otp_headers,
            allow_redirects=True,
        )
        page_resp = _session_get(
            "https://auth.openai.com/email-verification",
            headers=otp_headers,
            allow_redirects=True,
        )
        emitter.info(
            f"验证码发送状态: send={otp_resp.status_code}, page={page_resp.status_code}",
            step="send_otp",
        )
        if otp_resp.status_code >= 400 or page_resp.status_code >= 400:
            body_preview = str(otp_resp.text or "")[:200].replace("\n", " ")
            emitter.warn(
                f"send_otp 异常: send={otp_resp.status_code}, page={page_resp.status_code}, body={body_preview}",
                step="send_otp",
            )
        if otp_resp.status_code >= 400:
            emitter.error(
                f"验证码发送失败（状态码 {otp_resp.status_code}）: {str(otp_resp.text or '')[:220]}",
                step="send_otp",
            )
            return None

        if _stopped():
            return None

        # ------- 步骤8：轮询邮箱拿验证码 -------
        if mail_provider is not None:
            try:
                code = mail_provider.wait_for_otp(
                    dev_token,
                    email,
                    proxy=static_proxy,
                    proxy_selector=mail_proxy_selector,
                    stop_event=stop_event,
                )
            except TypeError:
                code = mail_provider.wait_for_otp(
                    dev_token,
                    email,
                    proxy=static_proxy,
                    stop_event=stop_event,
                )
        else:
            code = get_oai_code(
                dev_token,
                email,
                static_proxies,
                emitter,
                stop_event,
                proxy_selector=mail_proxies_selector,
            )
        if not code:
            return None

        if _stopped():
            return None

        # ------- 步骤9：提交验证码 -------
        emitter.info("正在验证 OTP...", step="verify_otp")
        code_body = json.dumps({"code": code}, ensure_ascii=False, separators=(",", ":"))
        code_resp = _session_post(
            "https://auth.openai.com/api/accounts/email-otp/validate",
            headers=_build_openai_headers(
                "https://auth.openai.com/email-verification",
                did,
            ),
            data=code_body,
        )
        emitter.info(f"验证码校验状态: {code_resp.status_code}", step="verify_otp")
        if code_resp.status_code != 200:
            emitter.error(
                f"验证码校验失败（状态码 {code_resp.status_code}）: {str(code_resp.text or '')[:220]}",
                step="verify_otp",
            )
            return None

        if _stopped():
            return None

        # ------- 步骤10：完善资料并创建账户 -------
        emitter.info("正在提交账户资料...", step="create_account")
        emitter.info("正在生成 create_account Sentinel Token...", step="create_account")
        try:
            create_account_sentinel = SentinelRuntime(
                device_id=did,
                user_agent=fingerprint_profile.user_agent,
                fingerprint_profile=fingerprint_profile,
                get_func=_session_get,
                post_func=_raw_post,
                emitter=emitter,
            ).build_token(
                flow="authorize_continue",
                page_url="https://auth.openai.com/about-you",
            )
        except Exception as exc:
            emitter.error(f"create_account Sentinel Token 生成失败: {exc}", step="create_account")
            return None
        emitter.success("create_account Sentinel Token 生成成功", step="create_account")
        profile_name = _random_profile_name()
        profile_birthdate = _random_profile_birthdate()
        emitter.info(
            f"本次资料: name={profile_name}, birthdate={profile_birthdate}",
            step="create_account",
        )
        create_account_body = json.dumps(
            {"name": profile_name, "birthdate": profile_birthdate},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        create_account_resp = _session_post(
            "https://auth.openai.com/api/accounts/create_account",
            headers=_build_openai_headers(
                "https://auth.openai.com/about-you",
                did,
                sentinel_token=create_account_sentinel,
            ),
            data=create_account_body,
        )
        create_account_status = create_account_resp.status_code
        emitter.info(f"资料提交状态: {create_account_status}", step="create_account")

        if create_account_status != 200:
            emitter.error(
                f"账户资料提交失败（状态码 {create_account_status}）: {str(create_account_resp.text or '')[:220]}",
                step="create_account",
            )
            return None

        emitter.success("账户创建成功！", step="create_account")
        create_account_cookie_names = _response_cookie_names(create_account_resp)
        if verbose_auth_logs:
            emitter.info(
                "create_account 响应 Cookie: "
                + (", ".join(create_account_cookie_names[:8]) if create_account_cookie_names else "无"),
                step="workspace",
            )
        create_account_json: Dict[str, Any] = {}
        create_account_continue_url = ""
        create_account_page_type = ""
        create_account_page_backstack = ""
        normalized_create_account_continue_url = ""
        follow_final_url = ""
        session_fast_path_token: Optional[str] = None
        try:
            parsed_create_account_json = create_account_resp.json() or {}
            if isinstance(parsed_create_account_json, dict):
                create_account_json = parsed_create_account_json
        except Exception:
            create_account_json = {}
        if create_account_json:
            if verbose_auth_logs:
                emitter.info(
                    "create_account 响应字段: "
                    + (", ".join(_safe_dict_keys(create_account_json)) or "无"),
                    step="workspace",
                )
            create_account_hits = _collect_interesting_paths(create_account_json)
            if create_account_hits and verbose_auth_logs:
                emitter.info(
                    f"create_account 关键信息: {_format_interesting_paths(create_account_hits)}",
                    step="workspace",
                )
            create_account_workspace_ids = _collect_workspace_ids(create_account_json)
            if create_account_workspace_ids and verbose_auth_logs:
                emitter.info(
                    "create_account workspace_id 线索: "
                    + ", ".join(_mask_secret(item, head=12, tail=6) for item in create_account_workspace_ids[:3]),
                    step="workspace",
                )
            create_account_page = create_account_json.get("page") or {}
            create_account_page_type = str((create_account_page or {}).get("type") or "").strip()
            create_account_page_backstack = str((create_account_page or {}).get("backstack_behavior") or "").strip()
            if (create_account_page_type or create_account_page_backstack) and verbose_auth_logs:
                emitter.info(
                    f"create_account page.type={create_account_page_type or '-'}, backstack={create_account_page_backstack or '-'}",
                    step="workspace",
                )
            create_account_continue_url = str(
                create_account_json.get("continue_url")
                or create_account_json.get("url")
                or create_account_json.get("redirect_url")
                or ""
            ).strip()
            if create_account_continue_url and verbose_auth_logs:
                emitter.info(
                    f"create_account continue_url 预览: {_mask_secret(create_account_continue_url, head=48, tail=12)}",
                    step="workspace",
                )
        else:
            if verbose_auth_logs:
                emitter.info(
                    f"create_account 响应体预览: {_preview_text(create_account_resp.text, 260)}",
                    step="workspace",
                )

        if create_account_continue_url:
            normalized_create_account_continue_url = urllib.parse.urljoin(
                "https://auth.openai.com",
                create_account_continue_url,
            )
            if verbose_auth_logs:
                emitter.info("正在跟进 create_account continue_url...", step="workspace")
            follow_headers = _build_navigate_headers()
            follow_headers["referer"] = "https://auth.openai.com/about-you"
            follow_resp = _session_get(
                normalized_create_account_continue_url,
                headers=follow_headers,
                allow_redirects=True,
                timeout=20,
            )
            follow_final_url = str(getattr(follow_resp, "url", "") or normalized_create_account_continue_url).strip()
            if verbose_auth_logs:
                emitter.info(
                    f"continue_url 跟进状态: {follow_resp.status_code}, final_url={_mask_secret(follow_final_url, head=48, tail=12)}",
                    step="workspace",
                )
            follow_cookie_names = _response_cookie_names(follow_resp)
            if verbose_auth_logs:
                emitter.info(
                    "continue_url 跟进响应 Cookie: "
                    + (", ".join(follow_cookie_names[:8]) if follow_cookie_names else "无"),
                    step="workspace",
                )
            follow_history = getattr(follow_resp, "history", []) or []
            if follow_history and verbose_auth_logs:
                for index, history_resp in enumerate(follow_history[:5], start=1):
                    history_url = str(getattr(history_resp, "url", "") or "").strip()
                    history_location = str((history_resp.headers or {}).get("Location") or "").strip()
                    emitter.info(
                        f"continue_url 历史[{index}] 状态={getattr(history_resp, 'status_code', '?')}, url={_mask_secret(history_url, head=44, tail=10)}, location={_mask_secret(history_location, head=44, tail=10) if history_location else '-'}",
                        step="workspace",
                    )
            if verbose_auth_logs:
                emitter.info(
                    f"continue_url 跟进响应体预览: {_preview_text(follow_resp.text, 220)}",
                    step="workspace",
                )
            session_fast_path_token = _try_build_token_from_chatgpt_session(
                referer_url=follow_final_url or normalized_create_account_continue_url
            )

        if session_fast_path_token:
            emitter.success("create_account 已直接完成 ChatGPT 会话建立，跳过重复登录链路", step="get_token")
            try:
                s.close()
            except Exception:
                pass
            return session_fast_path_token

        phone_verification_required = (
            create_account_page_type.lower() == "add_phone"
            or "add-phone" in normalized_create_account_continue_url.lower()
            or "add-phone" in follow_final_url.lower()
        )
        if phone_verification_required:
            emitter.warn(
                "账号创建成功，但当前进入 add_phone，需要手机号验证",
                step="phone_verification",
                reason="phone_verification_required",
                page_type=create_account_page_type or "",
                continue_url=create_account_continue_url or "",
                final_url=follow_final_url or normalized_create_account_continue_url or "",
            )
            try:
                s.close()
            except Exception:
                pass
            raise PhoneVerificationRequiredError(
                "账号创建成功，但当前进入 add_phone，需要手机号验证",
                page_type=create_account_page_type,
                continue_url=create_account_continue_url,
                final_url=follow_final_url or normalized_create_account_continue_url,
            )

        if _stopped():
            return None

        # ------- 步骤11：解析 Workspace -------
        emitter.info("正在解析 Workspace 信息...", step="workspace")
        candidate_cookie_names = (
            "oai-client-auth-session",
            "oai-client-auth-info",
            "unified_session_manifest",
            "auth-session-minimized",
        )
        candidate_workspace_hints: Dict[str, list[str]] = {}
        auth_cookie = ""
        auth_cookie_source = "none"
        for cookie_name in candidate_cookie_names:
            session_cookie = s.cookies.get(cookie_name) or ""
            relay_cookie = relay_cookie_jar.get(cookie_name) or ""
            cookie_source = "session" if session_cookie else ("relay" if relay_cookie else "none")
            raw_cookie = session_cookie or relay_cookie or ""
            if cookie_name == "oai-client-auth-session":
                auth_cookie = raw_cookie
                auth_cookie_source = cookie_source
            if verbose_auth_logs:
                emitter.info(
                    f"候选 Cookie[{cookie_name}] 来源: {cookie_source}, 长度: {len(raw_cookie)}, 片段数: {len(raw_cookie.split('.')) if raw_cookie else 0}",
                    step="workspace",
                )
            if not raw_cookie:
                continue
            if verbose_auth_logs:
                emitter.info(
                    f"候选 Cookie[{cookie_name}] 预览: {_mask_secret(raw_cookie)}",
                    step="workspace",
                )

            discovered_workspace_ids: list[str] = []
            for variant_label, variant_value in _cookie_candidate_values(raw_cookie):
                direct_json = _try_parse_json_text(variant_value)
                if direct_json:
                    direct_workspace_ids = _collect_workspace_ids(direct_json)
                    discovered_workspace_ids.extend(
                        item for item in direct_workspace_ids if item not in discovered_workspace_ids
                    )
                    if verbose_auth_logs:
                        emitter.info(
                            f"Cookie[{cookie_name}] 变体={variant_label} 直解析 keys={','.join(_safe_dict_keys(direct_json)) or '-'}, workspace_ids={','.join(_mask_secret(item, 12, 6) for item in direct_workspace_ids) or '-'}, hits={_format_interesting_paths(_collect_interesting_paths(direct_json))}",
                            step="workspace",
                        )

                whole_b64_json = _try_decode_b64_json(variant_value)
                if whole_b64_json:
                    whole_workspace_ids = _collect_workspace_ids(whole_b64_json)
                    discovered_workspace_ids.extend(
                        item for item in whole_workspace_ids if item not in discovered_workspace_ids
                    )
                    if verbose_auth_logs:
                        emitter.info(
                            f"Cookie[{cookie_name}] 变体={variant_label} base64-json keys={','.join(_safe_dict_keys(whole_b64_json)) or '-'}, workspace_ids={','.join(_mask_secret(item, 12, 6) for item in whole_workspace_ids) or '-'}, hits={_format_interesting_paths(_collect_interesting_paths(whole_b64_json))}",
                            step="workspace",
                        )

                for item in _cookie_segment_debug(variant_value):
                    key_text = ",".join(item["keys"]) if item["keys"] else "-"
                    workspace_preview = _mask_secret(item["workspace_id"], head=12, tail=6) if item["workspace_id"] else "-"
                    workspace_ids_text = (
                        ",".join(_mask_secret(v, head=12, tail=6) for v in item["workspace_ids"][:3])
                        if item["workspace_ids"]
                        else "-"
                    )
                    discovered_workspace_ids.extend(
                        wid for wid in item["workspace_ids"] if wid not in discovered_workspace_ids
                    )
                    if verbose_auth_logs:
                        emitter.info(
                            f"Cookie[{cookie_name}] 变体={variant_label} 段[{item['index']}] len={item['raw_len']}, decoded={item['decoded']}, keys={key_text}, workspaces={item['workspace_count']}, workspace_id={workspace_preview}, workspace_ids={workspace_ids_text}, hits={_format_interesting_paths(item['interesting_paths'])}",
                            step="workspace",
                        )

            if discovered_workspace_ids:
                candidate_workspace_hints[cookie_name] = discovered_workspace_ids[:5]

        if candidate_workspace_hints and verbose_auth_logs:
            emitter.info(
                "候选 Cookie workspace_id 汇总: "
                + " | ".join(
                    f"{cookie_name}={','.join(_mask_secret(item, 12, 6) for item in workspace_ids[:3])}"
                    for cookie_name, workspace_ids in candidate_workspace_hints.items()
                ),
                step="workspace",
            )

        if verbose_auth_logs:
            emitter.info(
                f"授权 Cookie 来源: {auth_cookie_source}, 长度: {len(auth_cookie)}, 片段数: {len(auth_cookie.split('.')) if auth_cookie else 0}",
                step="workspace",
            )
        if not auth_cookie:
            emitter.error("未能获取到授权 Cookie", step="workspace")
            return None

        if verbose_auth_logs:
            emitter.info(f"授权 Cookie 预览: {_mask_secret(auth_cookie)}", step="workspace")
        cookie_parts = auth_cookie.split(".")
        if verbose_auth_logs:
            for item in _cookie_segment_debug(auth_cookie):
                key_text = ",".join(item["keys"]) if item["keys"] else "-"
                workspace_preview = _mask_secret(item["workspace_id"], head=12, tail=6) if item["workspace_id"] else "-"
                workspace_ids_text = (
                    ",".join(_mask_secret(v, head=12, tail=6) for v in item["workspace_ids"][:3])
                    if item["workspace_ids"]
                    else "-"
                )
                emitter.info(
                    f"Cookie 段[{item['index']}] len={item['raw_len']}, decoded={item['decoded']}, keys={key_text}, workspaces={item['workspace_count']}, workspace_id={workspace_preview}, workspace_ids={workspace_ids_text}, hits={_format_interesting_paths(item['interesting_paths'])}",
                    step="workspace",
                )

        auth_json = _decode_jwt_segment(cookie_parts[0] if cookie_parts else "")
        workspaces = auth_json.get("workspaces") or []
        if not workspaces:
            payload_json = _decode_jwt_segment(cookie_parts[1] if len(cookie_parts) > 1 else "")
            payload_workspaces = payload_json.get("workspaces") or []
            emitter.error(
                f"授权 Cookie 里没有 workspace 信息（当前解析段=0，候选 payload workspaces={len(payload_workspaces) if isinstance(payload_workspaces, list) else 0}）",
                step="workspace",
            )
            emitter.error(
                f"当前解析段 keys={','.join(list(auth_json.keys())[:8]) if auth_json else '-'}；payload 段 keys={','.join(list(payload_json.keys())[:8]) if payload_json else '-'}",
                step="workspace",
            )
            if candidate_workspace_hints:
                emitter.error(
                    "其他候选 Cookie 的 workspace 线索: "
                    + " | ".join(
                        f"{cookie_name}={','.join(_mask_secret(item, 12, 6) for item in workspace_ids[:3])}"
                        for cookie_name, workspace_ids in candidate_workspace_hints.items()
                    ),
                    step="workspace",
                )
            return None
        workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
        if not workspace_id:
            emitter.error("无法解析 workspace_id", step="workspace")
            return None

        emitter.info(f"准备选择 Workspace: {_mask_secret(workspace_id, head=12, tail=6)}", step="workspace")

        select_body = f'{{"workspace_id":"{workspace_id}"}}'
        select_resp = _session_post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers={
                "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                "content-type": "application/json",
            },
            data=select_body,
        )
        if verbose_auth_logs:
            emitter.info(
                "workspace/select 响应 Cookie: "
                + (", ".join(_response_cookie_names(select_resp)[:8]) or "无"),
                step="workspace",
            )

        if select_resp.status_code != 200:
            emitter.error(f"选择 workspace 失败，状态码: {select_resp.status_code}", step="workspace")
            emitter.error(_preview_text(select_resp.text, 260), step="workspace")
            return None

        emitter.success(f"Workspace 选择成功: {workspace_id}", step="workspace")

        # ------- 步骤12：跟踪重定向，获取 Token -------
        emitter.info("正在获取最终 OAuth Token...", step="get_token")
        try:
            select_json = select_resp.json() or {}
        except Exception as exc:
            emitter.error(f"workspace/select 响应 JSON 解析失败: {exc}", step="get_token")
            emitter.error(_preview_text(select_resp.text, 260), step="get_token")
            return None
        if verbose_auth_logs:
            emitter.info(
                "workspace/select 响应字段: "
                + (", ".join(list(select_json.keys())[:8]) if isinstance(select_json, dict) and select_json else "无"),
                step="get_token",
            )
        continue_url = str((select_json or {}).get("continue_url") or "").strip()
        if not continue_url:
            emitter.error("workspace/select 响应里缺少 continue_url", step="get_token")
            emitter.error(_preview_text(select_resp.text, 260), step="get_token")
            return None

        current_url = continue_url
        if verbose_auth_logs:
            emitter.info(f"continue_url 预览: {_mask_secret(continue_url, head=48, tail=12)}", step="get_token")
        for redirect_index in range(6):
            if _stopped():
                return None
            final_resp = _session_get(current_url, allow_redirects=False, timeout=15)
            location = final_resp.headers.get("Location") or ""
            emitter.info(
                f"重定向[{redirect_index + 1}] 状态={final_resp.status_code}, location={'有' if location else '无'}, url={_mask_secret(current_url, head=48, tail=12)}",
                step="get_token",
            )

            if final_resp.status_code not in [301, 302, 303, 307, 308]:
                break
            if not location:
                break

            next_url = urllib.parse.urljoin(current_url, location)
            if "code=" in next_url and "state=" in next_url:
                if pool_relay_enabled and not _should_bypass_relay_for_target(TOKEN_URL):
                    try:
                        result = _submit_callback_url_via_pool_relay(
                            callback_url=next_url,
                            code_verifier=oauth.code_verifier,
                            redirect_uri=oauth.redirect_uri,
                            expected_state=oauth.state,
                        )
                    except Exception as exc:
                        _warn_relay_fallback(str(exc), TOKEN_URL)
                        result = submit_callback_url(
                            callback_url=next_url,
                            code_verifier=oauth.code_verifier,
                            redirect_uri=oauth.redirect_uri,
                            expected_state=oauth.state,
                            proxy=static_proxy,
                        )
                else:
                    result = submit_callback_url(
                        callback_url=next_url,
                        code_verifier=oauth.code_verifier,
                        redirect_uri=oauth.redirect_uri,
                        expected_state=oauth.state,
                        proxy=(static_proxy if pool_relay_enabled else _next_proxy_value()),
                    )
                emitter.success("Token 获取成功！", step="get_token")
                try: s.close()
                except: pass
                return result
            current_url = next_url

        emitter.error("未能在重定向链中捕获到最终 Callback URL", step="get_token")
        try: s.close()
        except: pass
        return None

    except PhoneVerificationRequiredError:
        raise
    except Exception as e:
        emitter.error(f"运行时发生错误: {e}", step="runtime")
        try: s.close()
        except: pass
        return None

# ==========================================
# CLI 入口（兼容直接运行）
# ==========================================


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAI 账号池编排器脚本")
    parser.add_argument(
        "--proxy", default=None, help="代理地址，如 http://127.0.0.1:7897"
    )
    parser.add_argument("--once", action="store_true", help="只运行一次")
    parser.add_argument("--sleep-min", type=int, default=5, help="循环模式最短等待秒数")
    parser.add_argument(
        "--sleep-max", type=int, default=30, help="循环模式最长等待秒数"
    )
    args = parser.parse_args()

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)

    os.makedirs(TOKENS_DIR, exist_ok=True)

    try:
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "sync_config.json")
        with open(config_path, "r", encoding="utf-8") as f:
            sync_cfg = json.load(f)
    except Exception:
        sync_cfg = {}

    cpa_base_url = str(sync_cfg.get("cpa_base_url") or "").strip()
    cpa_token = str(sync_cfg.get("cpa_token") or "").strip()
    
    pool_maintainer = None
    if cpa_base_url and cpa_token:
        try:
            from .pool_maintainer import PoolMaintainer
            pool_maintainer = PoolMaintainer(
                cpa_base_url=cpa_base_url,
                cpa_token=cpa_token,
            )
        except Exception as e:
            print(f"[-] 初始化 PoolMaintainer 失败: {e}")

    count = 0
    print("[Info] OpenAI 账号池编排器 - CLI 模式")

    while True:
        count += 1
        print(
            f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 开始第 {count} 次注册流程 <<<"
        )

        try:
            token_json = run(args.proxy)

            if token_json:
                try:
                    t_data = json.loads(token_json)
                    fname_email = t_data.get("email", "unknown").replace("@", "_")
                except Exception:
                    fname_email = "unknown"
                    t_data = {}

                file_name = f"token_{fname_email}_{time.time_ns()}.json"
                file_path = os.path.join(TOKENS_DIR, file_name)

                _write_text_atomic(file_path, token_json)

                print(f"[*] 成功! Token 已保存至: {file_path}")

                if pool_maintainer and t_data:
                    print(f"[*] 正在尝试上传到 CPA...")
                    try:
                        cpa_ok = pool_maintainer.upload_token(file_name, t_data, proxy=args.proxy or "")
                        upload_email = t_data.get('email', fname_email)
                        if cpa_ok:
                            print(f"[+] CPA 上传成功: {upload_email}")
                        else:
                            print(f"[-] CPA 上传失败: {upload_email}")
                    except Exception as e:
                        print(f"[-] CPA 上传抛出异常: {e}")
            else:
                print("[-] 本次注册失败。")

        except PhoneVerificationRequiredError as e:
            print(f"[!] {e}，本轮流程已停止，等待人工处理。")
        except Exception as e:
            print(f"[Error] 发生未捕获异常: {e}")

        if args.once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        print(f"[*] 休息 {wait_time} 秒...")
        time.sleep(wait_time)


if __name__ == "__main__":
    main()
