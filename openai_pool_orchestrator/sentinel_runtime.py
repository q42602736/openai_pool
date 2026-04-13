import base64
import json
import random
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qsl, urlparse

from curl_cffi import requests

try:
    from .fingerprint_profile import FingerprintProfile, build_default_fingerprint_profile, build_sec_ch_headers
except ImportError:
    from fingerprint_profile import FingerprintProfile, build_default_fingerprint_profile, build_sec_ch_headers  # type: ignore

SENTINEL_FRAME_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html"
SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
DEFAULT_SDK_URL = "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js"
DEFAULT_BUILD_HINT = "c/runtime/_"
DEFAULT_JS_HEAP_LIMIT = 4294705152
MAX_POW_ATTEMPTS = 500000
POW_ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
NODE_SCRIPT_PATH = Path(__file__).with_name("sentinel_vm.js")

DOCUMENT_KEYS = [
    "location",
    "implementation",
    "URL",
    "documentURI",
    "compatMode",
    "forms",
    "images",
    "scripts",
]
WINDOW_KEYS = [
    "window",
    "self",
    "document",
    "location",
    "navigator",
    "screen",
    "performance",
    "console",
]
NAVIGATOR_PROBE_KEYS = [
    "vendor",
    "userAgent",
    "language",
    "languages",
    "hardwareConcurrency",
    "platform",
]


@dataclass
class SentinelFrameContext:
    frame_url: str
    sdk_url: str
    build_hint: str = DEFAULT_BUILD_HINT


class SentinelRuntime:
    def __init__(
        self,
        *,
        device_id: str,
        user_agent: str,
        fingerprint_profile: Optional[FingerprintProfile] = None,
        get_func: Optional[Callable[..., Any]] = None,
        post_func: Optional[Callable[..., Any]] = None,
        emitter: Optional[Any] = None,
    ):
        self.fingerprint_profile = fingerprint_profile or build_default_fingerprint_profile()
        self.device_id = device_id
        self.user_agent = str(user_agent or self.fingerprint_profile.user_agent)
        self._get_func = get_func
        self._post_func = post_func
        self._emitter = emitter
        self._frame_context: Optional[SentinelFrameContext] = None

    def build_token(self, *, flow: str, page_url: str) -> str:
        frame_ctx = self._resolve_frame_context()
        requirements_proof = self._build_requirements_proof(
            sdk_url=frame_ctx.sdk_url,
            build_hint=frame_ctx.build_hint,
            page_url=page_url,
        )
        challenge = self._request_challenge(
            flow=flow,
            requirements_proof=requirements_proof,
            frame_ctx=frame_ctx,
        )
        challenge_token = str((challenge or {}).get("token") or "").strip()
        if not challenge_token:
            raise RuntimeError("Sentinel 响应里缺少 token")

        enforcement_proof = self._build_enforcement_proof(
            challenge=challenge,
            sdk_url=frame_ctx.sdk_url,
            build_hint=frame_ctx.build_hint,
            page_url=page_url,
        )
        dx_values = self._solve_dx(
            challenge=challenge,
            proof=requirements_proof,
            page_url=page_url,
            frame_ctx=frame_ctx,
            flow=flow,
        )

        token_payload: Dict[str, Any] = {
            "p": enforcement_proof,
            "t": dx_values.get("t"),
            "c": challenge_token,
            "id": self.device_id,
            "flow": flow,
        }
        session_observer = dx_values.get("so")
        if session_observer:
            token_payload["so"] = session_observer
        return json.dumps(token_payload, ensure_ascii=False, separators=(",", ":"))

    def _resolve_frame_context(self) -> SentinelFrameContext:
        if self._frame_context is not None:
            return self._frame_context

        sdk_url = DEFAULT_SDK_URL
        frame_html = ""
        try:
            response = self._http_get(
                SENTINEL_FRAME_URL,
                headers={
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "user-agent": self.user_agent,
                },
            )
            frame_html = str(getattr(response, "text", "") or "")
        except Exception as exc:
            self._warn(f"拉取 Sentinel frame 失败，回退默认 SDK: {exc}")

        if frame_html:
            match = re.search(r"<script\s+src=['\"]([^'\"]+/sdk\.js)['\"]", frame_html, re.IGNORECASE)
            if match:
                sdk_url = match.group(1).strip() or sdk_url

        self._frame_context = SentinelFrameContext(
            frame_url=SENTINEL_FRAME_URL,
            sdk_url=sdk_url,
            build_hint=DEFAULT_BUILD_HINT,
        )
        return self._frame_context

    def _build_requirements_proof(self, *, sdk_url: str, build_hint: str, page_url: str) -> str:
        config = self._build_browser_config(
            sdk_url=sdk_url,
            build_hint=build_hint,
            page_url=page_url,
        )
        start = time.perf_counter() * 1000.0
        config[3] = 1
        config[9] = round(max(0.0, time.perf_counter() * 1000.0 - start), 3)
        return "gAAAAAC" + self._base64_encode(config)

    def _build_enforcement_proof(
        self,
        *,
        challenge: Dict[str, Any],
        sdk_url: str,
        build_hint: str,
        page_url: str,
    ) -> Optional[str]:
        pow_data = (challenge or {}).get("proofofwork") or {}
        required = bool(pow_data.get("required"))
        seed = str(pow_data.get("seed") or "").strip()
        difficulty = str(pow_data.get("difficulty") or "").strip()
        if not required or not seed:
            return None

        config = self._build_browser_config(
            sdk_url=sdk_url,
            build_hint=build_hint,
            page_url=page_url,
        )
        start = time.perf_counter() * 1000.0
        difficulty_value = difficulty or "0"
        for nonce in range(MAX_POW_ATTEMPTS):
            config[3] = nonce
            config[9] = round(max(0.0, time.perf_counter() * 1000.0 - start))
            encoded = self._base64_encode(config)
            digest = self._fnv1a_32(seed + encoded)
            if digest[: len(difficulty_value)] <= difficulty_value:
                return "gAAAAAB" + encoded + "~S"
        return "gAAAAAB" + POW_ERROR_PREFIX + self._base64_encode(str(None))

    def _build_browser_config(self, *, sdk_url: str, build_hint: str, page_url: str) -> list[Any]:
        profile = self.fingerprint_profile
        script_candidates = [
            sdk_url,
            "https://auth.openai.com/c/runtime/_app.js",
            "https://auth.openai.com/c/runtime/_vendor.js",
        ]
        page_query_keys = ",".join(key for key, _ in parse_qsl(urlparse(page_url).query, keep_blank_values=True))
        perf_now = round(random.uniform(1000.0, 50000.0), 3)
        time_origin = round(time.time() * 1000.0 - perf_now, 3)
        now = datetime.now().astimezone().strftime("%a %b %d %Y %H:%M:%S GMT%z (%Z)")
        navigator_probe_key = random.choice(NAVIGATOR_PROBE_KEYS)
        navigator_probe_value = self._navigator_probe_value(navigator_probe_key)
        return [
            profile.screen_width + profile.screen_height,
            now,
            DEFAULT_JS_HEAP_LIMIT,
            random.random(),
            self.user_agent,
            random.choice(script_candidates),
            build_hint,
            profile.language,
            profile.languages_header,
            random.random(),
            f"{navigator_probe_key}\u2212{navigator_probe_value}",
            random.choice(DOCUMENT_KEYS),
            random.choice(WINDOW_KEYS),
            perf_now,
            str(uuid.uuid4()),
            page_query_keys,
            profile.hardware_concurrency,
            time_origin,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
        ]

    def _navigator_probe_value(self, key: str) -> str:
        profile = self.fingerprint_profile
        values = {
            "vendor": profile.vendor,
            "userAgent": self.user_agent,
            "language": profile.language,
            "languages": profile.languages_header,
            "hardwareConcurrency": str(profile.hardware_concurrency),
            "platform": profile.platform,
        }
        return str(values.get(key) or "undefined")

    def _request_challenge(
        self,
        *,
        flow: str,
        requirements_proof: str,
        frame_ctx: SentinelFrameContext,
    ) -> Dict[str, Any]:
        payload = json.dumps(
            {"p": requirements_proof, "id": self.device_id, "flow": flow},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        response = self._http_post(
            SENTINEL_REQ_URL,
            headers={
                "origin": "https://sentinel.openai.com",
                "referer": frame_ctx.frame_url,
                "content-type": "text/plain;charset=UTF-8",
                "user-agent": self.user_agent,
                **build_sec_ch_headers(self.fingerprint_profile),
            },
            data=payload,
        )
        status_code = int(getattr(response, "status_code", 0) or 0)
        if status_code != 200:
            body_preview = str(getattr(response, "text", "") or "")[:240].replace("\n", " ")
            raise RuntimeError(f"Sentinel 异常拦截，状态码: {status_code}, body={body_preview}")
        try:
            data = response.json() or {}
        except Exception as exc:
            body_preview = str(getattr(response, "text", "") or "")[:240].replace("\n", " ")
            raise RuntimeError(f"Sentinel 响应解析失败: {exc}, body={body_preview}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Sentinel 响应不是对象")
        return data

    def _solve_dx(
        self,
        *,
        challenge: Dict[str, Any],
        proof: str,
        page_url: str,
        frame_ctx: SentinelFrameContext,
        flow: str,
    ) -> Dict[str, Any]:
        node_path = shutil.which("node")
        if not node_path:
            raise RuntimeError("未找到 node，无法执行官方 Sentinel dx 挑战")
        if not NODE_SCRIPT_PATH.is_file():
            raise RuntimeError(f"缺少 Sentinel VM 脚本: {NODE_SCRIPT_PATH}")

        payload = {
            "challenge": challenge,
            "proof": proof,
            "device_id": self.device_id,
            "flow": flow,
            "page_url": page_url,
            "frame_url": frame_ctx.frame_url,
            "sdk_url": frame_ctx.sdk_url,
            "user_agent": self.user_agent,
            "language": self.fingerprint_profile.language,
            "languages": list(self.fingerprint_profile.languages),
            "hardware_concurrency": self.fingerprint_profile.hardware_concurrency,
            "platform": self.fingerprint_profile.platform,
            "vendor": self.fingerprint_profile.vendor,
            "device_memory": self.fingerprint_profile.device_memory,
            "screen_width": self.fingerprint_profile.screen_width,
            "screen_height": self.fingerprint_profile.screen_height,
            "timezone_id": self.fingerprint_profile.timezone_id,
        }
        proc = subprocess.run(
            [node_path, str(NODE_SCRIPT_PATH)],
            input=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if proc.returncode != 0:
            stderr = str(proc.stderr or "").strip()
            raise RuntimeError(f"Sentinel dx 执行失败: {stderr or f'node exit {proc.returncode}'}")
        try:
            result = json.loads(str(proc.stdout or "{}"))
        except Exception as exc:
            stdout_preview = str(proc.stdout or "")[:240].replace("\n", " ")
            raise RuntimeError(f"Sentinel dx 输出解析失败: {exc}, stdout={stdout_preview}") from exc
        if not isinstance(result, dict):
            raise RuntimeError("Sentinel dx 输出不是对象")
        return result

    def _http_get(self, url: str, **kwargs: Any):
        getter = self._get_func or requests.get
        request_kwargs = dict(kwargs)
        request_kwargs.setdefault("timeout", 15)
        if getter is requests.get:
            request_kwargs.setdefault("impersonate", self.fingerprint_profile.curl_impersonate)
        return getter(url, **request_kwargs)

    def _http_post(self, url: str, **kwargs: Any):
        poster = self._post_func or requests.post
        request_kwargs = dict(kwargs)
        request_kwargs.setdefault("timeout", 20)
        if poster is requests.post:
            request_kwargs.setdefault("impersonate", self.fingerprint_profile.curl_impersonate)
        return poster(url, **request_kwargs)

    @staticmethod
    def _base64_encode(data: Any) -> str:
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        value = 2166136261
        for char in text:
            value ^= ord(char)
            value = (value * 16777619) & 0xFFFFFFFF
        value ^= (value >> 16)
        value = (value * 2246822507) & 0xFFFFFFFF
        value ^= (value >> 13)
        value = (value * 3266489909) & 0xFFFFFFFF
        value ^= (value >> 16)
        value &= 0xFFFFFFFF
        return format(value, "08x")

    def _warn(self, message: str) -> None:
        if self._emitter is not None and hasattr(self._emitter, "warn"):
            try:
                self._emitter.warn(message, step="sentinel")
            except Exception:
                pass
