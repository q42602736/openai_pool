from __future__ import annotations

import importlib
import gc
import json
import os
import random
import re
import resource
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional

try:
    from .fingerprint_profile import FingerprintProfile, describe_fingerprint
except ImportError:
    from fingerprint_profile import FingerprintProfile, describe_fingerprint  # type: ignore
try:
    from .sms_providers import (
        DEFAULT_PHONE_COUNTRIES,
        HANDLER_API_PROVIDER_LABELS,
        HERO_SMS_CANCEL_MIN_WAIT_SECONDS,
        HeroSMSAcquireRetryableError,
        HeroSMSAcquireStoppedError,
        SMS_PROVIDER_PROFILE_DEFAULTS,
        active_sms_provider_fields,
        normalize_handler_api_country,
        normalize_sms_provider_profiles,
        schedule_hero_sms_delayed_cancel,
    )
except ImportError:
    from sms_providers import (  # type: ignore
        DEFAULT_PHONE_COUNTRIES,
        HANDLER_API_PROVIDER_LABELS,
        HERO_SMS_CANCEL_MIN_WAIT_SECONDS,
        HeroSMSAcquireRetryableError,
        HeroSMSAcquireStoppedError,
        SMS_PROVIDER_PROFILE_DEFAULTS,
        active_sms_provider_fields,
        normalize_handler_api_country,
        normalize_sms_provider_profiles,
        schedule_hero_sms_delayed_cancel,
    )


DEFAULT_BROWSER_CONFIG: Dict[str, Any] = {
    "register_mode": "browser",
    "browser_engine": "uc",
    "roxy_api_base": "http://127.0.0.1:50000",
    "roxy_api_key": "",
    "roxy_workspace_id": "",
    "roxy_profile_id": "",
    "roxy_api_timeout_sec": 20,
    "roxy_apply_proxy": True,
    "roxy_clear_cache": True,
    "roxy_random_fingerprint": True,
    "browser_headless": True,
    "browser_timeout_ms": 90000,
    "browser_slow_mo_ms": 0,
    "browser_executable_path": "",
    "browser_locale": "en-US",
    "browser_timezone": "America/New_York",
    "browser_block_media": False,
    "browser_realistic_profile": True,
    "browser_clear_runtime_state": True,
    "browser_manual_v2_phone_mode": "manual",
    "browser_manual_v2_email_mode": "auto",
    "browser_manual_v2_manual_restart_on_enter_password": False,
    "hero_sms_api_key": "",
    "hero_sms_service": "",
    "hero_sms_country": 16,
    "hero_sms_operator": "",
    "hero_sms_target_price": "",
    "hero_sms_fixed_price": True,
    "hero_sms_max_acquire_retries": 5,
    # 两档接码平台各存一份凭据，切换 browser_manual_v2_phone_mode 即切换生效档
    "sms_provider_profiles": {
        "hero_sms": dict(SMS_PROVIDER_PROFILE_DEFAULTS),
        "smsbower": dict(SMS_PROVIDER_PROFILE_DEFAULTS),
    },
}

MANUAL_V2_RESTART_PHONE_SENTINEL = "__manual_v2_restart_phone__"


def _normalize_manual_v2_email_mode(value: Any) -> str:
    mode = str(value or "auto").strip().lower()
    if mode not in {"auto", "manual"}:
        mode = "auto"
    return mode


_PRESERVED_BROWSER_RESOURCES: list[BrowserLaunchResources] = []
_PRESERVED_BROWSER_RESOURCES_LOCK = threading.Lock()
_ACTIVE_TEMP_USER_DATA_DIRS: set[str] = set()
_ACTIVE_TEMP_USER_DATA_DIRS_LOCK = threading.Lock()
_UC_TEMP_DIR_PREFIX = "opo_uc_"
_UC_STALE_DIR_TTL_SECONDS = 6 * 60 * 60
_LOOPBACK_CALLBACK_TTL_SECONDS = 30 * 60
_LOOPBACK_CALLBACK_HUB_LOCK = threading.Lock()
_LOOPBACK_CALLBACK_HUB: Optional["_LoopbackCallbackHub"] = None
_PAGE_SNAPSHOT_CACHE_TTL_SECONDS = 0.45
_PAGE_SNAPSHOT_CACHE_MAX_ENTRIES = 64
_PAGE_SNAPSHOT_MAX_BODY_CHARS = 65536
_PAGE_SNAPSHOT_CACHE_LOCK = threading.Lock()
_PAGE_SNAPSHOT_CACHE: dict[int, tuple[float, str, str]] = {}
_BROWSER_MEMORY_CHECK_INTERVAL_SECONDS = 15.0
_BROWSER_MEMORY_SOFT_RATIO = 0.78
_BROWSER_MEMORY_HARD_RATIO = 0.90
# Chrome for Testing + Playwright 进程树可占用数 GB，默认与 PM2 4G 限额对齐。
_DEFAULT_MEMORY_LIMIT_MB = 4096
_UC_PROCESS_SHUTDOWN_WAIT_SECONDS = 3.0
_BROWSER_STALL_WATCHDOG_SECONDS = 120.0


def _read_process_table() -> tuple[dict[int, tuple[int, int, str]], dict[int, list[int]]]:
    """读取进程父子关系、RSS 和命令行；命令行只用于识别本项目临时浏览器。"""
    output = subprocess.check_output(
        ["ps", "-axo", "pid=,ppid=,rss=,command="],
        text=True,
        stderr=subprocess.DEVNULL,
        timeout=1.5,
    )
    rows: dict[int, tuple[int, int, str]] = {}
    children: dict[int, list[int]] = {}
    for line in output.splitlines():
        parts = line.strip().split(maxsplit=3)
        if len(parts) < 3:
            continue
        try:
            pid, ppid, rss_kb = int(parts[0]), int(parts[1]), int(parts[2])
        except (TypeError, ValueError):
            continue
        command = str(parts[3] if len(parts) > 3 else "").strip()
        rows[pid] = (ppid, max(0, rss_kb), command)
        children.setdefault(ppid, []).append(pid)
    return rows, children


def _process_descendants(
    root_pid: int,
    children: dict[int, list[int]],
) -> set[int]:
    descendants = {int(root_pid)}
    pending = [int(root_pid)]
    while pending:
        parent = pending.pop()
        for child in children.get(parent, []):
            if child not in descendants:
                descendants.add(child)
                pending.append(child)
    return descendants


def _browser_memory_thresholds() -> tuple[int, int, int]:
    """返回总进程树内存上限、软阈值、硬阈值；默认与 PM2 2G 限额对齐。"""
    try:
        configured_mb = int(float(os.environ.get("OPO_MEMORY_LIMIT_MB", _DEFAULT_MEMORY_LIMIT_MB)))
    except (TypeError, ValueError):
        configured_mb = _DEFAULT_MEMORY_LIMIT_MB
    configured_mb = max(256, min(configured_mb, 32768))
    limit_bytes = configured_mb * 1024 * 1024
    return (
        limit_bytes,
        int(limit_bytes * _BROWSER_MEMORY_SOFT_RATIO),
        int(limit_bytes * _BROWSER_MEMORY_HARD_RATIO),
    )


def _process_tree_rss_bytes() -> int:
    """读取当前 Python 进程及其浏览器子进程 RSS，失败时退回当前进程峰值。"""
    root_pid = os.getpid()
    try:
        rows, children = _read_process_table()
        descendants = _process_descendants(root_pid, children)
        total_kb = sum(rows.get(pid, (0, 0, ""))[1] for pid in descendants)
        if total_kb > 0:
            return total_kb * 1024
    except Exception:
        pass

    try:
        peak = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        # macOS reports bytes, Linux reports KiB.
        return int(peak if sys.platform == "darwin" else peak * 1024)
    except Exception:
        return 0


def _process_tree_rss_report(limit: int = 8) -> str:
    """返回当前进程树的高占用进程，便于判断 RSS 是否来自 Chrome 原生进程。"""
    root_pid = os.getpid()
    try:
        rows, children = _read_process_table()
        descendants = _process_descendants(root_pid, children)
        top_rows = sorted(
            (
                (pid, rows.get(pid, (0, 0, ""))[1], rows.get(pid, (0, 0, ""))[2])
                for pid in descendants
                if pid in rows
            ),
            key=lambda item: item[1],
            reverse=True,
        )[: max(1, int(limit or 1))]
        if not top_rows:
            return "count=0"
        report_rows = []
        for pid, rss_kb, command in top_rows:
            safe_command = re.sub(r"(--proxy-server=)\S+", r"\1***", str(command or ""))
            safe_command = " ".join(safe_command.split())[:180]
            report_rows.append(f"pid={pid},rss={rss_kb / 1024:.0f}MB,cmd={safe_command or '-'}")
        return f"count={len(descendants)}; " + "; ".join(report_rows)
    except Exception as exc:
        return f"unavailable={type(exc).__name__}"


def _prune_page_snapshot_cache(
    *,
    page_ids: Optional[set[int]] = None,
    force: bool = False,
) -> int:
    """清理快照缓存，避免页面句柄或超大 body 文本跨轮残留。"""
    now = time.time()
    removed = 0
    with _PAGE_SNAPSHOT_CACHE_LOCK:
        if page_ids:
            for page_id in page_ids:
                if _PAGE_SNAPSHOT_CACHE.pop(page_id, None) is not None:
                    removed += 1
        if force:
            removed += len(_PAGE_SNAPSHOT_CACHE)
            _PAGE_SNAPSHOT_CACHE.clear()
        else:
            stale_keys = [
                key
                for key, (created_at, _, _) in _PAGE_SNAPSHOT_CACHE.items()
                if now - float(created_at or 0.0) > _PAGE_SNAPSHOT_CACHE_TTL_SECONDS * 4
            ]
            for key in stale_keys:
                if _PAGE_SNAPSHOT_CACHE.pop(key, None) is not None:
                    removed += 1
            overflow = len(_PAGE_SNAPSHOT_CACHE) - _PAGE_SNAPSHOT_CACHE_MAX_ENTRIES
            if overflow > 0:
                oldest = sorted(
                    _PAGE_SNAPSHOT_CACHE.items(),
                    key=lambda item: float(item[1][0] or 0.0),
                )[:overflow]
                for key, _ in oldest:
                    if _PAGE_SNAPSHOT_CACHE.pop(key, None) is not None:
                        removed += 1
    return removed


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off", ""):
        return False
    return default


class BrowserPhoneVerificationRequiredError(RuntimeError):
    """浏览器流程进入手机号验证页。"""

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


@dataclass
class BrowserRunContext:
    email: str
    dev_token: str
    account_password: str
    profile_name: str
    profile_birthdate: str
    proxy: str
    browser_config: Dict[str, Any]
    mail_provider: Any
    emitter: Any
    stop_event: Any
    user_agent: str
    fingerprint_profile: FingerprintProfile
    fallback_wait_for_otp_func: Optional[Callable[..., str]]


@dataclass
class BrowserLaunchResources:
    browser: Any
    context: Any
    page: Any
    playwright: Any = None
    cdp_driver: Any = None
    temp_user_data_dir: str = ""
    persistent_user_data_dir: bool = False
    launch_mode: str = "uc-bridge"
    owner_thread_id: int = 0
    roxy_client: Any = None
    roxy_profile_id: str = ""


class _IPv4LoopbackServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET


class _IPv6LoopbackServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET6

    def server_bind(self) -> None:  # pragma: no cover - 平台相关兜底
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except Exception:
            pass
        super().server_bind()


class _LoopbackCallbackHub:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._callbacks: Dict[str, tuple[str, float]] = {}
        self._servers: list[ThreadingHTTPServer] = []
        self._threads: list[threading.Thread] = []
        self._redirect_path = "/auth/callback"
        self._redirect_port = 1455
        self._started_hosts: list[str] = []

    def ensure_started(self, redirect_uri: str) -> bool:
        parsed = urllib.parse.urlparse(str(redirect_uri or "").strip())
        port = int(parsed.port or 1455)
        path = str(parsed.path or "/auth/callback").strip() or "/auth/callback"
        with self._lock:
            self._prune_locked()
            if self._servers:
                return True

            self._redirect_port = port
            self._redirect_path = path
            self._started_hosts = []
            handler_cls = self._build_handler()
            bind_specs = [
                ("127.0.0.1", _IPv4LoopbackServer),
                ("::1", _IPv6LoopbackServer),
            ]
            for host, server_cls in bind_specs:
                try:
                    server = server_cls((host, port), handler_cls)
                except OSError:
                    continue
                thread = threading.Thread(
                    target=server.serve_forever,
                    name=f"opo-loopback-{host}-{port}",
                    daemon=True,
                )
                thread.start()
                self._servers.append(server)
                self._threads.append(thread)
                self._started_hosts.append(host)
            return bool(self._servers)

    def pop_callback(self, expected_state: str) -> str:
        state = str(expected_state or "").strip()
        if not state:
            return ""
        with self._lock:
            self._prune_locked()
            record = self._callbacks.pop(state, None)
        return str(record[0] if record else "").strip()

    def describe_listener(self) -> str:
        with self._lock:
            hosts = ", ".join(self._started_hosts) if self._started_hosts else "-"
            return f"localhost:{self._redirect_port}{self._redirect_path} ({hosts})"

    def _store_callback(self, callback_url: str) -> None:
        value = str(callback_url or "").strip()
        if not value:
            return
        parsed = urllib.parse.urlparse(value)
        state = str((urllib.parse.parse_qs(parsed.query).get("state", [""])[0] or "")).strip()
        code = str((urllib.parse.parse_qs(parsed.query).get("code", [""])[0] or "")).strip()
        if not state or not code:
            return
        with self._lock:
            self._callbacks[state] = (value, time.time())
            self._prune_locked()

    def _prune_locked(self) -> None:
        now = time.time()
        stale_states = [
            state
            for state, (_, created_at) in self._callbacks.items()
            if now - float(created_at or 0.0) > _LOOPBACK_CALLBACK_TTL_SECONDS
        ]
        for state in stale_states:
            self._callbacks.pop(state, None)

    def _build_handler(self) -> type[BaseHTTPRequestHandler]:
        hub = self

        class LoopbackCallbackHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(str(self.path or "").strip())
                if parsed.path != hub._redirect_path:
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b"not found")
                    return

                callback_url = f"http://localhost:{hub._redirect_port}{parsed.path}"
                if parsed.query:
                    callback_url += f"?{parsed.query}"
                hub._store_callback(callback_url)

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h3>OAuth callback captured</h3><p>You can close this page now.</p></body></html>"
                )

        return LoopbackCallbackHandler


def _ensure_loopback_callback_hub(redirect_uri: str, emitter: Any) -> Optional[_LoopbackCallbackHub]:
    global _LOOPBACK_CALLBACK_HUB
    with _LOOPBACK_CALLBACK_HUB_LOCK:
        if _LOOPBACK_CALLBACK_HUB is None:
            _LOOPBACK_CALLBACK_HUB = _LoopbackCallbackHub()
        hub = _LOOPBACK_CALLBACK_HUB
    if hub.ensure_started(redirect_uri):
        try:
            emitter.info(f"已启动本地 OAuth 回调监听: {hub.describe_listener()}", step="oauth_init")
        except Exception:
            pass
        return hub
    try:
        emitter.warn(
            "本地 OAuth 回调监听启动失败，仍将继续依赖浏览器拦截和页面提取兜底。",
            step="oauth_init",
        )
    except Exception:
        pass
    return None


def normalize_browser_config(raw: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    source = dict(DEFAULT_BROWSER_CONFIG)
    if isinstance(raw, dict):
        source.update(raw)

    register_mode = str(source.get("register_mode") or "browser").strip().lower()
    if register_mode not in {"browser", "browser_manual", "browser_manual_v2", "protocol"}:
        register_mode = "browser"

    browser_engine = str(source.get("browser_engine") or "uc").strip().lower()
    if browser_engine not in {"uc", "roxy"}:
        browser_engine = "uc"
    try:
        roxy_api_timeout_sec = max(3, min(int(source.get("roxy_api_timeout_sec") or 20), 120))
    except (TypeError, ValueError):
        roxy_api_timeout_sec = 20

    executable_path = str(source.get("browser_executable_path") or "").strip()
    locale = str(source.get("browser_locale") or "en-US").strip() or "en-US"
    timezone_id = str(source.get("browser_timezone") or "America/New_York").strip() or "America/New_York"
    try:
        timeout_ms = max(15000, min(int(source.get("browser_timeout_ms") or 90000), 300000))
    except (TypeError, ValueError):
        timeout_ms = 90000
    try:
        slow_mo_ms = max(0, min(int(source.get("browser_slow_mo_ms") or 0), 5000))
    except (TypeError, ValueError):
        slow_mo_ms = 0
    phone_mode = str(source.get("browser_manual_v2_phone_mode") or "manual").strip().lower() or "manual"
    if phone_mode not in {"manual", "hero_sms", "smsbower"}:
        phone_mode = "manual"
    email_mode = _normalize_manual_v2_email_mode(source.get("browser_manual_v2_email_mode") or "auto")
    manual_restart_on_enter_password = _as_bool(source.get("browser_manual_v2_manual_restart_on_enter_password", False), default=False)
    # 两档接码平台配置各存各的，生效值按当前 phone_mode 投影出来。
    # profiles 只认调用方真正传进来的那份，否则默认值里的空档会遮蔽老配置迁移。
    sms_provider_profiles = normalize_sms_provider_profiles(
        {
            **source,
            "browser_manual_v2_phone_mode": phone_mode,
            "sms_provider_profiles": raw.get("sms_provider_profiles") if isinstance(raw, dict) else None,
        }
    )
    active_sms_fields = active_sms_provider_fields(sms_provider_profiles, phone_mode)

    raw_keep_open = None
    if isinstance(raw, dict) and "browser_keep_open_on_error" in raw:
        raw_keep_open = raw.get("browser_keep_open_on_error")

    return {
        "register_mode": register_mode,
        "browser_engine": browser_engine,
        "roxy_api_base": str(source.get("roxy_api_base") or "http://127.0.0.1:50000").strip(),
        "roxy_api_key": str(source.get("roxy_api_key") or "").strip(),
        "roxy_workspace_id": str(source.get("roxy_workspace_id") or "").strip(),
        "roxy_profile_id": str(
            source.get("roxy_profile_id") or source.get("roxy_profile_ids") or ""
        ).strip(),
        "roxy_api_timeout_sec": roxy_api_timeout_sec,
        "roxy_apply_proxy": _as_bool(source.get("roxy_apply_proxy", True), default=True),
        "roxy_clear_cache": _as_bool(source.get("roxy_clear_cache", True), default=True),
        "roxy_random_fingerprint": _as_bool(source.get("roxy_random_fingerprint", True), default=True),
        "browser_headless": False
        if register_mode == "browser_manual"
        else _as_bool(source.get("browser_headless", True), default=True),
        "browser_timeout_ms": timeout_ms,
        "browser_slow_mo_ms": slow_mo_ms,
        "browser_executable_path": executable_path,
        "browser_locale": locale,
        "browser_timezone": timezone_id,
        "browser_block_media": _as_bool(source.get("browser_block_media", True), default=True),
        "browser_realistic_profile": _as_bool(source.get("browser_realistic_profile", False), default=False),
        "browser_clear_runtime_state": _as_bool(source.get("browser_clear_runtime_state", True), default=True),
        "browser_manual_v2_phone_mode": phone_mode,
        "browser_manual_v2_email_mode": email_mode,
        "browser_manual_v2_manual_restart_on_enter_password": manual_restart_on_enter_password,
        "sms_provider_profiles": sms_provider_profiles,
        **active_sms_fields,
        "browser_keep_open_on_error": _as_bool(
            raw_keep_open if raw_keep_open is not None else (not _as_bool(source.get("browser_headless", True), default=True)),
            default=False,
        ),
    }


def _close_launch_resources(
    resources: Optional[BrowserLaunchResources],
    *,
    skip_browser_protocol: bool = False,
) -> None:
    if resources is None:
        return
    page_cache_keys: set[int] = set()
    if not skip_browser_protocol:
        try:
            if resources.page is not None:
                page_cache_keys.add(id(resources.page))
        except Exception:
            pass
        try:
            context_pages = list(getattr(resources.context, "pages", []) or [])
        except Exception:
            context_pages = []
        for candidate_page in context_pages:
            try:
                page_cache_keys.add(id(candidate_page))
            except Exception:
                continue
        try:
            if resources.context is not None:
                resources.context.close()
        except Exception:
            pass
        try:
            if resources.browser is not None:
                resources.browser.close()
        except Exception:
            pass
        try:
            if resources.cdp_driver is not None:
                resources.cdp_driver.quit()
        except Exception:
            pass
    # Roxy 的窗口由客户端托管，必须走 API 关闭，否则窗口会一直挂着占用资料
    try:
        if resources.roxy_client is not None and resources.roxy_profile_id:
            resources.roxy_client.close_browser(resources.roxy_profile_id)
    except Exception:
        pass
    temp_user_data_dir = str(resources.temp_user_data_dir or "").strip()
    process_profile = _canonical_uc_temp_profile(temp_user_data_dir)
    if temp_user_data_dir:
        _unregister_active_temp_user_data_dir(temp_user_data_dir)
        if not bool(getattr(resources, "persistent_user_data_dir", False)):
            shutil.rmtree(temp_user_data_dir, ignore_errors=True)
    if process_profile:
        _cleanup_orphan_uc_processes(profile_dirs={process_profile})
    try:
        if resources.playwright is not None:
            resources.playwright.stop()
    except Exception:
        pass
    if page_cache_keys:
        _prune_page_snapshot_cache(page_ids=page_cache_keys)


def _cleanup_preserved_browser_resources(
    emitter: Any,
    *,
    owner_thread_id: Optional[int] = None,
) -> int:
    with _PRESERVED_BROWSER_RESOURCES_LOCK:
        remaining: list[BrowserLaunchResources] = []
        stale_resources: list[BrowserLaunchResources] = []
        for resources in _PRESERVED_BROWSER_RESOURCES:
            if owner_thread_id is not None and int(resources.owner_thread_id or 0) != int(owner_thread_id):
                remaining.append(resources)
                continue
            stale_resources.append(resources)
        _PRESERVED_BROWSER_RESOURCES[:] = remaining
    for resources in stale_resources:
        _close_launch_resources(resources)
    if stale_resources:
        try:
            emitter.info(
                f"启动前已关闭 {len(stale_resources)} 个历史保留浏览器现场",
                step="oauth_init",
            )
        except Exception:
            pass
    return len(stale_resources)


def _release_memory_pressure(emitter: Any = None) -> tuple[int, int, int]:
    """关闭历史保留现场、清空快照缓存并触发 GC，返回回收前后 RSS 与对象数。"""
    before = _process_tree_rss_bytes()
    _cleanup_preserved_browser_resources(emitter)
    _prune_page_snapshot_cache(force=True)
    collected = gc.collect()
    after = _process_tree_rss_bytes()
    return before, after, collected


def _purge_active_browser_memory(context: Any, page: Any) -> int:
    """通过 CDP 停止当前页面加载并请求 Chromium 回收 JavaScript 内存。"""
    if context is None or page is None:
        return 0
    completed = 0
    try:
        cdp_session = context.new_cdp_session(page)
        for method in ("Page.stopLoading", "Memory.forciblyPurgeJavaScriptMemory"):
            try:
                cdp_session.send(method)
                completed += 1
            except Exception:
                continue
        try:
            cdp_session.send("Network.clearBrowserCache")
            completed += 1
        except Exception:
            pass
        try:
            cdp_session.detach()
        except Exception:
            pass
    except Exception:
        return completed
    return completed


def _stopped(stop_event: Any) -> bool:
    return bool(stop_event is not None and getattr(stop_event, "is_set", lambda: False)())


def _mask_secret(value: Any, head: int = 18, tail: int = 10) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if len(raw) <= head:
        return raw
    if len(raw) <= head + tail:
        return raw[:head] + "..."
    return f"{raw[:head]}...{raw[-tail:]}"


def _preview_text(value: Any, limit: int = 200) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _sleep_with_page(page: Any, milliseconds: int) -> None:
    wait_seconds = max(0.0, float(milliseconds or 0) / 1000.0)
    if wait_seconds <= 0:
        return
    # 不经 Playwright/CDP 做纯等待：渲染器失联时 wait_for_timeout 可能永久阻塞，
    # Python 等待同样给页面留下墙钟时间，但不会把自动化线程锁死。
    time.sleep(wait_seconds)


def _sleep_with_page_until(page: Any, milliseconds: int, stop_event: Any) -> bool:
    wait_seconds = max(0.0, float(milliseconds or 0) / 1000.0)
    if wait_seconds <= 0:
        return _stopped(stop_event)
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        if _stopped(stop_event):
            return True
        remaining_ms = int(max(0.0, min(0.2, deadline - time.time())) * 1000)
        if remaining_ms <= 0:
            break
        _sleep_with_page(page, remaining_ms)
    return _stopped(stop_event)


def _safe_page_title(page: Any) -> str:
    if page is None:
        return ""
    try:
        # Page.title 没有 timeout；title 元素读取可受 Playwright timeout 约束。
        return str(page.locator("title").text_content(timeout=300) or "").strip()
    except Exception:
        return ""


def _detect_cloudflare_blocker(page: Any, url_text: str, body_value: str) -> str:
    title = _safe_page_title(page)
    title_lower = title.lower()
    body_lower = str(body_value or "").lower()
    if any(token in title_lower for token in ("just a moment", "checking your browser", "checking if the site connection is secure", "稍候")):
        return title or "Cloudflare 校验页"
    if any(
        token in body_lower
        for token in (
            "checking if the site connection is secure",
            "verify you are human",
            "enable javascript and cookies to continue",
            "cf-browser-verification",
            "cf-chl",
            "cloudflare",
            "ray id",
            "captcha",
            "just a moment",
        )
    ):
        return title or "Cloudflare 校验页"
    return ""


def _simulate_human_idle(page: Any) -> None:
    """在 CF 校验等待期间模拟更保守的人类空闲行为。"""
    try:
        vw = page.viewport_size.get("width", 1440) if page.viewport_size else 1440
        vh = page.viewport_size.get("height", 900) if page.viewport_size else 900
        x = random.randint(int(vw * 0.2), int(vw * 0.8))
        y = random.randint(int(vh * 0.2), int(vh * 0.6))
        page.mouse.move(x, y, steps=random.randint(12, 28))
        time.sleep(random.uniform(0.6, 1.4))
        if random.random() < 0.25:
            page.mouse.wheel(0, random.choice([-40, -20, 20, 40]))
            time.sleep(random.uniform(0.3, 0.8))
        if random.random() < 0.2:
            x2 = x + random.randint(-80, 80)
            y2 = y + random.randint(-40, 40)
            page.mouse.move(max(10, x2), max(10, y2), steps=random.randint(8, 18))
    except Exception:
        pass


def _wait_for_load(page: Any, timeout_ms: int = 2500) -> None:
    try:
        page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
    except Exception:
        pass
    try:
        page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 1200))
    except Exception:
        pass
    _sleep_with_page(page, 180)


def _page_snapshot_signature(url: str, body_text: str) -> str:
    url_text = str(url or "").strip().lower()
    body_norm = re.sub(r"\s+", " ", str(body_text or "").strip().lower())
    return f"{url_text}|{body_norm[:240]}"


def _iter_page_targets(page: Any) -> list[Any]:
    """主文档 + 全部 frame，便于识别 auth.openai.com iframe 内的真实注册页。"""
    targets: list[Any] = []
    if page is None:
        return targets
    targets.append(page)
    try:
        frames = list(getattr(page, "frames", []) or [])
    except Exception:
        frames = []
    for frame in frames:
        if frame is None:
            continue
        try:
            if hasattr(page, "main_frame") and frame is getattr(page, "main_frame", None):
                continue
        except Exception:
            pass
        targets.append(frame)
    return targets


def _frame_url(target: Any) -> str:
    if target is None:
        return ""
    try:
        return str(getattr(target, "url", "") or "").strip()
    except Exception:
        return ""


def _first_visible_locator(page: Any, selectors: list[str]) -> Any:
    for target in _iter_page_targets(page):
        for selector in selectors:
            try:
                # CSS :visible 在浏览器侧过滤掉隐藏占位元素，避免逐个 nth 候选跨 CDP 往返。
                # text/xpath 等非 CSS selector 保留首元素兜底，避免改变 Playwright selector 语义。
                if not str(selector).lstrip().startswith(("text=", "xpath=", "id=")):
                    visible_locator = target.locator(f"{selector}:visible").first
                    if visible_locator.is_visible(timeout=250):
                        return visible_locator
                    continue
                locator = target.locator(selector).first
                if locator.is_visible(timeout=250):
                    return locator
            except Exception:
                continue
    return None


# 参照 grok注册机 human_input：记录每页最后鼠标位置，轨迹从真实落点续走。
_PAGE_MOUSE_POS: Dict[int, tuple[float, float]] = {}


def _resolve_mouse_page(page: Any, locator: Any = None) -> Any:
    if locator is not None:
        try:
            owner = getattr(locator, "page", None)
            if owner is not None:
                return owner
        except Exception:
            pass
    return page


def _get_page_mouse_pos(page: Any) -> tuple[float, float]:
    if page is None:
        return 0.0, 0.0
    try:
        return _PAGE_MOUSE_POS.get(id(page), (0.0, 0.0))
    except Exception:
        return 0.0, 0.0


def _set_page_mouse_pos(page: Any, x: float, y: float) -> None:
    if page is None:
        return
    try:
        _PAGE_MOUSE_POS[id(page)] = (float(x), float(y))
    except Exception:
        pass


def _page_viewport_size(page: Any) -> tuple[float, float]:
    try:
        size = getattr(page, "viewport_size", None) or {}
        vw = float(size.get("width") or 0)
        vh = float(size.get("height") or 0)
        if vw > 1 and vh > 1:
            return vw, vh
    except Exception:
        pass
    # page.evaluate 没有 timeout；没有 viewport 信息时使用稳定默认值。
    return 1280.0, 800.0


def _bezier_mouse_move(
    page: Any,
    start: tuple[float, float],
    end: tuple[float, float],
    *,
    duration_ms: Optional[int] = None,
) -> None:
    """二次贝塞尔轨迹移动（对齐 grok注册机 human_input._move_cursor_path）。"""
    if page is None:
        return
    sx, sy = float(start[0]), float(start[1])
    ex, ey = float(end[0]), float(end[1])
    if duration_ms is None:
        duration_ms = int(random.uniform(120, 320))
    duration_ms = max(60, int(duration_ms))
    steps = max(8, min(36, int(duration_ms / 16)))
    mx = (sx + ex) / 2.0 + random.uniform(-40.0, 40.0)
    my = (sy + ey) / 2.0 + random.uniform(-30.0, 30.0)
    for i in range(1, steps + 1):
        t = i / steps
        u = 1.0 - t
        x = u * u * sx + 2 * u * t * mx + t * t * ex
        y = u * u * sy + 2 * u * t * my + t * t * ey
        if i < steps:
            x += random.uniform(-1.2, 1.2)
            y += random.uniform(-1.0, 1.0)
        try:
            page.mouse.move(x, y)
        except Exception:
            return
        _set_page_mouse_pos(page, x, y)
        try:
            page.wait_for_timeout(max(4, int(duration_ms / steps)))
        except Exception:
            time.sleep(max(0.004, duration_ms / steps / 1000.0))


def _click_at_point_human_like(
    page: Any,
    x: float,
    y: float,
    *,
    hold_ms_lo: int = 45,
    hold_ms_hi: int = 130,
) -> bool:
    """
    视口坐标真人点击：轨迹移入 → 短停 → press/hold/release。
    对齐 grok注册机 CF Turnstile 的 CDP 真点思路（Playwright mouse 事件）。
    """
    if page is None:
        return False
    tx, ty = float(x), float(y)
    sx, sy = _get_page_mouse_pos(page)
    vw, vh = _page_viewport_size(page)
    if sx < 2 or sy < 2:
        sx = vw * random.uniform(0.18, 0.42)
        sy = vh * random.uniform(0.22, 0.55)
    try:
        # 点击前轻微“思考”
        if random.random() < 0.28:
            _sleep_with_page(page, random.randint(40, 120))
        _bezier_mouse_move(
            page,
            (sx, sy),
            (tx, ty),
            duration_ms=int(random.uniform(100, 280)),
        )
        # 轻微过冲再回正（更像真人；概率略降以提速）
        if random.random() < 0.22:
            overshoot = (
                tx + random.uniform(-6.0, 6.0),
                ty + random.uniform(-4.0, 4.0),
            )
            _bezier_mouse_move(
                page,
                (tx, ty),
                overshoot,
                duration_ms=int(random.uniform(50, 120)),
            )
            _bezier_mouse_move(
                page,
                overshoot,
                (tx, ty),
                duration_ms=int(random.uniform(40, 100)),
            )
        _sleep_with_page(page, random.randint(20, 80))
        page.mouse.down()
        _sleep_with_page(page, random.randint(int(hold_ms_lo), int(hold_ms_hi)))
        page.mouse.up()
        _set_page_mouse_pos(page, tx, ty)
        _sleep_with_page(page, random.randint(40, 140))
        return True
    except Exception:
        return False


def _click_locator_human_like(page: Any, locator: Any, *, timeout_ms: int = 1200) -> bool:
    """
    元素真人点击（主路径）。
    参照 grok注册机 human_click：
    scrollIntoView → 中心附近随机落点 → 贝塞尔轨迹 → press/hold/release。
    禁止一上来就 JS click / 瞬时 locator.click。
    """
    if locator is None:
        return False
    mouse_page = _resolve_mouse_page(page, locator)
    try:
        locator.scroll_into_view_if_needed(timeout=min(1200, int(timeout_ms or 1200)))
    except Exception:
        # scroll 失败时继续尝试 bounding_box/click；不使用无 timeout 的 locator.evaluate。
        pass
    _sleep_with_page(mouse_page, random.randint(50, 140))
    box = None
    try:
        box = locator.bounding_box()
    except Exception:
        box = None
    if box and float(box.get("width") or 0) >= 4 and float(box.get("height") or 0) >= 4:
        width = float(box["width"])
        height = float(box["height"])
        # 中心附近高斯偏移，限制在按钮内部（对齐 click_offset_ratio≈0.28）
        ox = random.gauss(0.0, width * 0.12)
        oy = random.gauss(0.0, height * 0.12)
        ox = max(-width * 0.35, min(width * 0.35, ox))
        oy = max(-height * 0.35, min(height * 0.35, oy))
        target_x = float(box["x"]) + width * 0.5 + ox
        target_y = float(box["y"]) + height * 0.5 + oy
        if _click_at_point_human_like(mouse_page, target_x, target_y):
            return True
    # 次选：Playwright 自带 delay 点击（仍带按压时长，不是瞬时 JS）
    try:
        locator.click(timeout=timeout_ms, delay=random.randint(60, 160))
        try:
            box2 = locator.bounding_box()
            if box2:
                _set_page_mouse_pos(
                    mouse_page,
                    float(box2["x"]) + float(box2["width"]) * 0.5,
                    float(box2["y"]) + float(box2["height"]) * 0.5,
                )
        except Exception:
            pass
        _sleep_with_page(mouse_page, random.randint(80, 220))
        return True
    except Exception:
        return False


def _click_first(page: Any, selectors: list[str], *, timeout_ms: int = 800) -> bool:
    locator = _first_visible_locator(page, selectors)
    if locator is None:
        return False
    if _click_locator_human_like(page, locator, timeout_ms=timeout_ms):
        return True
    # 真人点击失败才退回原生 click
    try:
        locator.click(timeout=timeout_ms, delay=random.randint(40, 120))
        return True
    except Exception:
        try:
            locator.first.click(timeout=timeout_ms, delay=random.randint(40, 120))
            return True
        except Exception:
            return False


def _click_text_ancestor(page: Any, texts: list[str], *, timeout_ms: int = 1200) -> bool:
    if page is None:
        return False
    for text in texts:
        needle = str(text or "").strip()
        if not needle:
            continue
        try:
            candidate = page.locator(f"text={needle}").first
            if not candidate.is_visible(timeout=300):
                continue
        except Exception:
            continue
        for selector in (
            "xpath=ancestor::button[1]",
            'xpath=ancestor::*[@role="button"][1]',
            "xpath=ancestor::a[1]",
            "xpath=ancestor::label[1]",
        ):
            try:
                ancestor = candidate.locator(selector).first
                if not ancestor.is_visible(timeout=300):
                    continue
                if _click_locator_human_like(page, ancestor, timeout_ms=timeout_ms):
                    return True
            except Exception:
                continue
        try:
            if _click_locator_human_like(page, candidate, timeout_ms=timeout_ms):
                return True
        except Exception:
            continue
    return False


def _wait_for_choose_account_transition(page: Any, previous_url: str, *, timeout_ms: int = 2500) -> bool:
    deadline = time.time() + max(0.8, float(timeout_ms or 0) / 1000.0)
    previous_url_lower = str(previous_url or "").strip().lower()
    while time.time() < deadline:
        _wait_for_load(page, timeout_ms=800)
        current_url, current_body = _describe_page(page, force_refresh=True)
        current_url_lower = str(current_url or "").strip().lower()
        if current_url_lower and current_url_lower != previous_url_lower:
            return True
        if not _is_choose_account_page(current_url, current_body, page):
            return True
        _sleep_with_page(page, 180)
    return False


def _activate_choose_account_candidate(page: Any, candidate: Any, previous_url: str, *, timeout_ms: int = 3200) -> bool:
    if page is None or candidate is None:
        return False
    try:
        candidate.scroll_into_view_if_needed(timeout=1200)
    except Exception:
        pass
    if _click_locator_human_like(page, candidate, timeout_ms=1500) and _wait_for_choose_account_transition(page, previous_url, timeout_ms=timeout_ms):
        return True
    try:
        candidate.click(timeout=1200)
        if _wait_for_choose_account_transition(page, previous_url, timeout_ms=timeout_ms):
            return True
    except Exception:
        pass
    try:
        candidate.focus()
    except Exception:
        pass
    for key_name in ("Enter", "Space"):
        try:
            candidate.press(key_name, timeout=1200)
            if _wait_for_choose_account_transition(page, previous_url, timeout_ms=timeout_ms):
                return True
        except Exception:
            continue
    try:
        js_clicked = bool(
            candidate.evaluate(
                """(el) => {
                    if (!el) return false;
                    const tryClick = (node) => {
                        if (!node) return false;
                        try { node.focus?.(); } catch (e) {}
                        try { node.click?.(); } catch (e) {}
                        try {
                            node.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
                        } catch (e) {}
                        return true;
                    };
                    if (tryClick(el)) return true;
                    const parent = el.closest?.('button, [role="button"], [role="listitem"], a, li, div');
                    return tryClick(parent);
                }"""
            )
        )
        if js_clicked and _wait_for_choose_account_transition(page, previous_url, timeout_ms=timeout_ms):
            return True
    except Exception:
        pass
    return False


def _fill_first(page: Any, selectors: list[str], value: str, *, timeout_ms: int = 1200) -> bool:
    locator = _first_visible_locator(page, selectors)
    if locator is None:
        return False
    try:
        locator.click(timeout=timeout_ms)
    except Exception:
        pass
    try:
        locator.fill(value, timeout=timeout_ms)
        return True
    except Exception:
        try:
            locator.press("Control+A")
            locator.type(value, timeout=timeout_ms)
            return True
        except Exception:
            return False


def _fill_input_by_label(page: Any, label_hints: list[str], value: str, *, timeout_ms: int = 1200) -> bool:
    normalized_hints = [str(item or "").strip().lower() for item in label_hints if str(item or "").strip()]
    if not normalized_hints:
        return False
    try:
        labels = page.locator("label")
    except Exception:
        return False

    for index in range(24):
        try:
            label = labels.nth(index)
            if not label.is_visible(timeout=300):
                if index == 0:
                    break
                continue
            label_text = str(label.inner_text(timeout=timeout_ms) or "").strip().lower()
            if not label_text or not any(hint in label_text for hint in normalized_hints):
                continue

            target = None
            label_for = str(label.get_attribute("for") or "").strip()
            if label_for:
                target = _first_visible_locator(
                    page,
                    [
                        f'[id="{label_for}"]',
                        f'input[id="{label_for}"]',
                        f'textarea[id="{label_for}"]',
                        f'[aria-labelledby*="{label_for}"]',
                    ],
                )
            if target is None:
                label_id = str(label.get_attribute("id") or "").strip()
                if label_id:
                    target = _first_visible_locator(
                        page,
                        [
                            f'input[aria-labelledby*="{label_id}"]',
                            f'textarea[aria-labelledby*="{label_id}"]',
                            f'[role="textbox"][aria-labelledby*="{label_id}"]',
                        ],
                    )
            if target is None:
                try:
                    nested = label.locator('input, textarea, [role="textbox"], [contenteditable="true"]')
                    for nested_index in range(4):
                        candidate = nested.nth(nested_index)
                        if candidate.is_visible(timeout=300):
                            target = candidate
                            break
                        if nested_index == 0:
                            break
                except Exception:
                    target = None

            if target is not None and _write_text_to_locator(target, value, timeout_ms=timeout_ms):
                return True
        except Exception:
            continue
    return False


def _extract_input_value_by_hints(page: Any, hints: list[str], *, limit: int = 16) -> str:
    normalized_hints = [str(item or "").strip().lower() for item in hints if str(item or "").strip()]
    if not normalized_hints:
        return ""
    for locator in _collect_visible_locators(page, ['input', 'textarea', '[role="textbox"]'], limit=limit):
        meta = _locator_metadata(locator)
        if not meta:
            continue
        haystack = " ".join(
            meta.get(key, "")
            for key in ("type", "name", "id", "aria_label", "placeholder", "autocomplete", "labels", "parent_text")
        )
        if not any(hint in haystack for hint in normalized_hints):
            continue
        value = ""
        try:
            value = str(locator.input_value(timeout=300) or "").strip()
        except Exception:
            try:
                value = str(locator.get_attribute("value") or "").strip()
            except Exception:
                value = ""
        if value:
            return value
    return ""


def _collect_visible_locators(page: Any, selectors: list[str], *, limit: int = 8) -> list[Any]:
    results: list[Any] = []
    for selector in selectors:
        try:
            locator = page.locator(selector)
            for index in range(max(1, int(limit or 1))):
                item = locator.nth(index)
                try:
                    if item.is_visible(timeout=300):
                        results.append(item)
                        if len(results) >= limit:
                            return results
                    elif index == 0:
                        break
                except Exception:
                    if index == 0:
                        break
                    continue
        except Exception:
            continue
    return results


def _locator_metadata(locator: Any) -> Dict[str, str]:
    """批量读取控件元数据；失败时返回空结果交给调用方跳过。"""

    # 健康页面走一次浏览器内读取，避免每个属性都跨 Playwright 同步桥接往返。
    # 活动页选择不走此函数；若渲染器失联，由看门狗终止当前 driver 并让外层重试。
    try:
        data = locator.evaluate(
            """(el) => {
                const labels = [];
                try {
                    if (el.labels && el.labels.length) {
                        for (const item of Array.from(el.labels)) {
                            labels.push((item.innerText || item.textContent || '').trim());
                        }
                    }
                } catch {}
                const closestLabel = el.closest && el.closest('label');
                if (closestLabel) {
                    labels.push((closestLabel.innerText || closestLabel.textContent || '').trim());
                }
                const nestedEditable = el.querySelector && el.querySelector('input, textarea, [contenteditable="true"]');
                const parent = el.parentElement;
                const attr = (name) => String(el.getAttribute?.(name) || '').toLowerCase();
                return {
                    tag: (el.tagName || '').toLowerCase(),
                    type: attr('type'),
                    role: attr('role'),
                    name: attr('name'),
                    id: attr('id'),
                    aria_label: attr('aria-label'),
                    placeholder: attr('placeholder'),
                    autocomplete: attr('autocomplete'),
                    aria_haspopup: attr('aria-haspopup'),
                    aria_valuemin: attr('aria-valuemin'),
                    aria_valuemax: attr('aria-valuemax'),
                    aria_valuenow: attr('aria-valuenow'),
                    aria_valuetext: attr('aria-valuetext'),
                    data_type: attr('data-type'),
                    contenteditable: attr('contenteditable'),
                    value: (typeof el.value === 'string' ? el.value : '').trim().toLowerCase(),
                    nested_value: nestedEditable
                        ? (((typeof nestedEditable.value === 'string' ? nestedEditable.value : '') || nestedEditable.textContent || '')).trim().toLowerCase()
                        : '',
                    text: ((el.innerText || el.textContent || '')).trim().toLowerCase(),
                    parent_text: parent ? ((parent.innerText || parent.textContent || '')).trim().toLowerCase() : '',
                    labels: labels.filter(Boolean).join(' ').toLowerCase(),
                };
            }""",
            timeout=500,
        )
        if isinstance(data, dict):
            return {str(key): str(value or '') for key, value in data.items()}
    except Exception:
        pass

    # 仅在批量读取失败时保留少量属性兜底；正常路径不会执行这里。
    def _attr(name: str) -> str:
        try:
            return str(locator.get_attribute(name, timeout=300) or "").strip().lower()
        except Exception:
            return ""

    attrs = {
        "type": _attr("type"),
        "role": _attr("role"),
        "name": _attr("name"),
        "id": _attr("id"),
        "aria_label": _attr("aria-label"),
        "placeholder": _attr("placeholder"),
        "autocomplete": _attr("autocomplete"),
        "aria_haspopup": _attr("aria-haspopup"),
        "aria_valuemin": _attr("aria-valuemin"),
        "aria_valuemax": _attr("aria-valuemax"),
        "aria_valuenow": _attr("aria-valuenow"),
        "aria_valuetext": _attr("aria-valuetext"),
        "data_type": _attr("data-type"),
        "contenteditable": _attr("contenteditable"),
    }
    value = ""
    try:
        value = str(locator.input_value(timeout=300) or "").strip().lower()
    except Exception:
        value = _attr("value")
    text = ""
    try:
        text = str(locator.inner_text(timeout=300) or "").strip().lower()
    except Exception:
        try:
            text = str(locator.text_content(timeout=300) or "").strip().lower()
        except Exception:
            text = ""
    parent_text = ""
    try:
        parent_text = str(locator.locator("xpath=..").inner_text(timeout=300) or "").strip().lower()
    except Exception:
        parent_text = ""
    if attrs["role"] == "combobox" or attrs["aria_haspopup"] == "listbox":
        tag = "select"
    elif attrs["role"] == "button" or attrs["type"] in {"submit", "button"}:
        tag = "button"
    elif attrs["type"]:
        tag = "input"
    else:
        tag = ""
    attrs.update(
        {
            "tag": tag,
            "value": value,
            "nested_value": value,
            "text": text,
            "parent_text": parent_text,
            "labels": "",
        }
    )
    return attrs


def _locator_matches_hints(locator: Any, hints: list[str]) -> bool:
    meta = _locator_metadata(locator)
    if not meta:
        return False
    haystack = " ".join(
        meta.get(key, "")
        for key in (
            "tag",
            "type",
            "role",
            "name",
            "id",
            "aria_label",
            "placeholder",
            "autocomplete",
            "data_type",
            "contenteditable",
            "text",
            "parent_text",
            "labels",
        )
    )
    return any(str(hint or "").strip().lower() in haystack for hint in hints if str(hint or "").strip())


def _apply_candidates_to_locator(page: Any, locator: Any, candidates: list[str]) -> bool:
    meta = _locator_metadata(locator)
    tag = meta.get("tag", "")
    role = meta.get("role", "")
    aria_haspopup = meta.get("aria_haspopup", "")
    if tag == "select" or tag == "button" or role == "combobox" or aria_haspopup == "listbox":
        return _choose_first_supported_option(page, locator, candidates)
    for value in candidates:
        if _write_text_to_locator(locator, value):
            return True
    return False


def _identify_birthdate_segment(locator: Any) -> str:
    meta = _locator_metadata(locator)
    if not meta:
        return ""
    data_type = meta.get("data_type", "")
    if data_type in {"year", "month", "day"}:
        return data_type

    aria_valuemax = str(meta.get("aria_valuemax", "")).strip()
    if aria_valuemax == "12":
        return "month"
    if aria_valuemax == "31":
        return "day"
    if aria_valuemax == "9999":
        return "year"

    haystack = " ".join(
        meta.get(key, "")
        for key in (
            "aria_label",
            "placeholder",
            "labels",
            "text",
            "name",
            "id",
        )
    )
    if any(token in haystack for token in ("year", "yyyy", "yy", "年")):
        return "year"
    if any(token in haystack for token in ("month", "mm", "月")):
        return "month"
    if any(token in haystack for token in ("day", "dd", "日")):
        return "day"
    return ""


def _birthdate_segment_contains(locator: Any, expected: str) -> bool:
    meta = _locator_metadata(locator)
    want = str(expected or "").strip().lower()
    if not meta or not want:
        return False
    want_digits = "".join(ch for ch in want if ch.isdigit())
    want_digits_norm = want_digits.lstrip("0") or ("0" if want_digits else "")
    observed_values = [
        str(meta.get(key, "") or "").strip().lower()
        for key in ("text", "value", "nested_value", "aria_valuetext", "aria_valuenow")
    ]
    for current in observed_values:
        if not current:
            continue
        if current == want or want in current:
            return True
        current_digits = "".join(ch for ch in current if ch.isdigit())
        current_digits_norm = current_digits.lstrip("0") or ("0" if current_digits else "")
        if want_digits and current_digits == want_digits:
            return True
        if want_digits_norm and current_digits_norm == want_digits_norm:
            return True
    return False


def _focus_birthdate_segment(locator: Any) -> None:
    try:
        locator.click(timeout=1200)
    except Exception:
        pass


def _birthdate_segment_numeric_value(locator: Any) -> Optional[int]:
    meta = _locator_metadata(locator)
    if not meta:
        return None
    for key in ("aria_valuenow", "text", "value", "nested_value", "aria_valuetext"):
        raw = str(meta.get(key, "") or "").strip().lower()
        if not raw:
            continue
        match = re.search(r"\d{1,4}", raw)
        if not match:
            continue
        try:
            return int(match.group(0))
        except Exception:
            continue
    return None


def _press_birthdate_digits(locator: Any, text: str) -> bool:
    digits = "".join(ch for ch in str(text or "") if ch.isdigit())
    if not digits:
        return False
    pressed = False
    for ch in digits:
        key_name = f"Digit{ch}"
        try:
            locator.press(key_name, timeout=1200)
            pressed = True
            continue
        except Exception:
            pass
        try:
            locator.press(ch, timeout=1200)
            pressed = True
        except Exception:
            return False
    return pressed


def _press_birthdate_digits_with_page_keyboard(page: Any, locator: Any, text: str) -> bool:
    digits = "".join(ch for ch in str(text or "") if ch.isdigit())
    if not digits or page is None:
        return False
    try:
        _focus_birthdate_segment(locator)
    except Exception:
        pass
    _sleep_with_page(page, 80)
    try:
        page.keyboard.type(digits, delay=55)
        return True
    except Exception:
        pass
    try:
        page.keyboard.insert_text(digits)
        return True
    except Exception:
        return False


def _adjust_birthdate_spinbutton_by_arrows(locator: Any, expected: str) -> bool:
    target_text = str(expected or "").strip()
    if not target_text:
        return False
    try:
        target_num = int(target_text)
    except Exception:
        return False
    current_num = _birthdate_segment_numeric_value(locator)
    if current_num is None:
        return False
    if current_num == target_num:
        return _birthdate_segment_contains(locator, target_text)
    press_key = "ArrowUp" if target_num > current_num else "ArrowDown"
    remaining = abs(target_num - current_num)
    if remaining > 120:
        return False
    _focus_birthdate_segment(locator)
    for step_idx in range(remaining):
        try:
            locator.press(press_key, timeout=1200)
        except Exception:
            return False
        if step_idx == remaining - 1 or (step_idx + 1) % 4 == 0:
            time.sleep(0.05)
            if _birthdate_segment_contains(locator, target_text):
                return True
    try:
        locator.press("Tab", timeout=1200)
    except Exception:
        pass
    time.sleep(0.08)
    return _birthdate_segment_contains(locator, target_text)


def _write_birthdate_segment(page: Any, locator: Any, value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    meta = _locator_metadata(locator)
    if meta.get("role", "") == "spinbutton":
        def _commit_and_check() -> bool:
            for _ in range(3):
                time.sleep(0.1)
                if _birthdate_segment_contains(locator, text):
                    return True
            try:
                locator.press("Tab", timeout=1200)
            except Exception:
                pass
            for _ in range(3):
                time.sleep(0.1)
                if _birthdate_segment_contains(locator, text):
                    return True
            return False

        for writer in (
            lambda: _press_birthdate_digits(locator, text),
            lambda: (locator.type(text, delay=55, timeout=1200), True)[1],
            lambda: (locator.press_sequentially(text, timeout=1200), True)[1],
            lambda: _press_birthdate_digits_with_page_keyboard(page, locator, text),
            lambda: _write_text_to_locator(locator, text, timeout_ms=1200),
        ):
            _focus_birthdate_segment(locator)
            for hotkey in ("Meta+A", "Control+A", "Backspace", "Delete"):
                try:
                    locator.press(hotkey, timeout=1200)
                except Exception:
                    pass
            try:
                if not writer():
                    continue
            except Exception:
                continue
            if _commit_and_check():
                return True
        if _adjust_birthdate_spinbutton_by_arrows(locator, text):
            return True
        return False
    if not _write_text_to_locator(locator, text):
        return False
    return _birthdate_segment_contains(locator, text)


def _write_birthdate_segment_candidates(page: Any, locator: Any, candidates: list[str]) -> bool:
    seen: set[str] = set()
    for value in candidates:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        if _write_birthdate_segment(page, locator, text):
            return True
    return False


def _fill_birthdate_spinbutton_triplet(
    page: Any,
    *,
    month_locator: Any,
    day_locator: Any,
    year_locator: Any,
    year: str,
    month: str,
    day: str,
) -> bool:
    month_candidates = [month.zfill(2), str(int(month))]
    day_candidates = [day.zfill(2), str(int(day))]
    return (
        _write_birthdate_segment_candidates(page, month_locator, month_candidates)
        and _write_birthdate_segment_candidates(page, day_locator, day_candidates)
        and _write_birthdate_segment_candidates(page, year_locator, [year])
    )


def _infer_birthdate_spinbutton_order(spinbuttons: list[Any]) -> list[str]:
    if len(spinbuttons) < 3:
        return []
    samples: list[str] = []
    for item in spinbuttons[:3]:
        meta = _locator_metadata(item)
        if not meta:
            continue
        samples.extend(
            [
                str(meta.get("parent_text", "") or "").strip().lower(),
                str(meta.get("text", "") or "").strip().lower(),
                str(meta.get("aria_label", "") or "").strip().lower(),
            ]
        )
    combined = " ".join(part for part in samples if part)
    combined = re.sub(r"\s+", " ", combined)
    patterns = [
        (("mm / dd / yyyy", "mm/dd/yyyy", "mm dd yyyy"), ["month", "day", "year"]),
        (("dd / mm / yyyy", "dd/mm/yyyy", "dd mm yyyy"), ["day", "month", "year"]),
        (("yyyy / mm / dd", "yyyy/mm/dd", "yyyy mm dd"), ["year", "month", "day"]),
    ]
    for hints, order in patterns:
        if any(hint in combined for hint in hints):
            return order
    return []


def _fill_birthdate_spinbuttons(page: Any, year: str, month: str, day: str) -> bool:
    spinbuttons = _collect_visible_locators(
        page,
        [
            '[role="spinbutton"][contenteditable="true"]',
            '[role="spinbutton"]',
            '[contenteditable="true"][data-type]',
        ],
        limit=8,
    )
    if len(spinbuttons) < 3:
        return False

    segment_map: Dict[str, Any] = {}
    for item in spinbuttons:
        segment_name = _identify_birthdate_segment(item)
        if segment_name and segment_name not in segment_map:
            segment_map[segment_name] = item

    year_locator = segment_map.get("year")
    month_locator = segment_map.get("month")
    day_locator = segment_map.get("day")
    if year_locator is not None and month_locator is not None and day_locator is not None:
        if _fill_birthdate_spinbutton_triplet(
            page,
            month_locator=month_locator,
            day_locator=day_locator,
            year_locator=year_locator,
            year=year,
            month=month,
            day=day,
        ):
            return True

    inferred_order = _infer_birthdate_spinbutton_order(spinbuttons)
    if len(inferred_order) == 3:
        fallback_map = {segment_name: spinbuttons[index] for index, segment_name in enumerate(inferred_order)}
        year_locator = fallback_map.get("year")
        month_locator = fallback_map.get("month")
        day_locator = fallback_map.get("day")
        if year_locator is not None and month_locator is not None and day_locator is not None:
            if _fill_birthdate_spinbutton_triplet(
                page,
                month_locator=month_locator,
                day_locator=day_locator,
                year_locator=year_locator,
                year=year,
                month=month,
                day=day,
            ):
                return True

    return False


def _choose_first_supported_option(page: Any, locator: Any, candidates: list[str], *, timeout_ms: int = 1200) -> bool:
    for value in candidates:
        if not str(value or "").strip():
            continue
        try:
            locator.select_option(value=value)
            return True
        except Exception:
            pass
        try:
            locator.select_option(label=value)
            return True
        except Exception:
            pass

    try:
        locator.click(timeout=timeout_ms)
    except Exception:
        pass

    for value in candidates:
        safe_value = str(value or "").replace('"', '\\"').strip()
        if not safe_value:
            continue
        option = _first_visible_locator(
            page,
            [
                f'[role="option"]:has-text("{safe_value}")',
                f'[role="listbox"] *:has-text("{safe_value}")',
                f'[data-radix-select-viewport] *:has-text("{safe_value}")',
                f'[data-headlessui-state] *:has-text("{safe_value}")',
                f'li:has-text("{safe_value}")',
            ],
        )
        if option is None:
            continue
        try:
            option.click(timeout=timeout_ms)
            return True
        except Exception:
            continue
    return False


def _is_oauth_provider_action_text(text: Any) -> bool:
    """识别第三方登录按钮文案，避免 Continue 误点到 Continue with Google。"""
    lower = re.sub(r"\s+", " ", str(text or "").strip().lower())
    if not lower:
        return False
    provider_tokens = (
        "google",
        "apple",
        "microsoft",
        "github",
        "facebook",
        "邮箱",
        "email",
        "sso",
    )
    if any(token in lower for token in provider_tokens):
        # 纯 “Continue / 继续” 不含 provider 词；带 provider 的一律拒绝。
        return True
    return False


def _is_social_login_choice_page(url: str, body_text: str, page: Any = None) -> bool:
    """
    登录方式选择页（Continue with Google/Apple/Phone...）。
    这种页绝不能当 workspace/consent 授权页去点 Continue，否则会误进 Google 登录。
    """
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    # 已进入第三方域名则由第三方分支处理。
    if any(
        domain in url_lower
        for domain in (
            "accounts.google.com",
            "login.microsoftonline.com",
            "appleid.apple.com",
            "login.live.com",
        )
    ):
        return False
    social_signals = 0
    for token in (
        "continue with google",
        "continue with apple",
        "continue with microsoft",
        "继续使用 google",
        "继续使用 apple",
        "继续使用 microsoft",
    ):
        if token in body_lower:
            social_signals += 1
    phone_signal = any(
        token in body_lower
        for token in (
            "continue with phone",
            "use phone instead",
            "继续使用手机",
            "手机登录",
        )
    )
    if social_signals >= 1 and phone_signal:
        return True
    if social_signals >= 2:
        return True
    if page is None:
        return False
    # 页面动作诊断级确认：可见的第三方登录按钮。
    try:
        actions = str(_summarize_primary_actions(page) or "").lower()
    except Exception:
        actions = ""
    if not actions:
        return False
    provider_hits = sum(
        1
        for token in ("continue with google", "continue with apple", "continue with microsoft")
        if token in actions
    )
    return provider_hits >= 1 and (
        "continue with phone" in actions or phone_signal or provider_hits >= 2
    )


def _click_exact_action_texts(
    page: Any,
    preferred_texts: list[str],
    *,
    allow_generic_submit: bool = False,
    timeout_ms: int = 1500,
) -> bool:
    """按完整文案批量查找按钮，再交给真人轨迹点击。"""
    if page is None:
        return False
    wanted = [str(item or "").strip() for item in (preferred_texts or []) if str(item or "").strip()]
    if not wanted and not allow_generic_submit:
        return False

    marker = f"data-human-click-{int(time.time() * 1000) % 10_000_000}"
    wanted_lower = [re.sub(r"\s+", " ", item).strip().lower() for item in wanted]
    reject_tokens = [
        "google", "apple", "microsoft", "github", "facebook", "email", "邮箱",
        "sso", "with phone", "使用手机", "手机登录",
    ]
    scan_script = """
        ({ wanted, allowGenericSubmit, rejectTokens, marker }) => {
            const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim().toLowerCase();
            const readText = (node) => normalize(
                node?.innerText || node?.value || node?.getAttribute?.('aria-label') || node?.getAttribute?.('title') || ''
            );
            const rejected = (text) => rejectTokens.some((token) => text.includes(String(token || '').toLowerCase()));
            const visible = (node) => {
                if (!node || node.disabled || String(node.getAttribute?.('aria-disabled') || '').toLowerCase() === 'true') return false;
                const rect = node.getBoundingClientRect?.();
                const style = window.getComputedStyle?.(node);
                return !!rect && rect.width >= 8 && rect.height >= 8
                    && style?.display !== 'none' && style?.visibility !== 'hidden'
                    && style?.opacity !== '0' && style?.pointerEvents !== 'none';
            };
            const nodes = Array.from(document.querySelectorAll(
                'button, [role="button"], input[type="submit"], input[type="button"], a[href]'
            ));
            const mark = (node) => {
                try { node.setAttribute(marker, '1'); return true; } catch (_) { return false; }
            };
            for (const want of wanted) {
                for (const node of nodes) {
                    if (!visible(node)) continue;
                    const text = readText(node);
                    if (text === want && mark(node)) return true;
                }
            }
            if (!allowGenericSubmit) return false;
            for (const node of nodes) {
                if (!visible(node)) continue;
                const text = readText(node);
                const tag = String(node.tagName || '').toLowerCase();
                const type = String(node.getAttribute?.('type') || '').toLowerCase();
                const isSubmit = type === 'submit' || (tag === 'button' && (!type || type === 'submit'));
                if (isSubmit && (!text || (!rejected(text) && wanted.includes(text))) && mark(node)) return true;
            }
            return false;
        }
    """
    clear_script = """(marker) => {
        try { document.querySelectorAll('[' + marker + ']').forEach((node) => node.removeAttribute(marker)); } catch (_) {}
    }"""
    for target in _iter_page_targets(page):
        marked = False
        try:
            marked = bool(
                target.evaluate(
                    scan_script,
                    {
                        "wanted": wanted_lower,
                        "allowGenericSubmit": bool(allow_generic_submit),
                        "rejectTokens": reject_tokens,
                        "marker": marker,
                    },
                )
            )
        except Exception:
            continue
        if not marked:
            continue
        try:
            locator = target.locator(f'[{marker}="1"]').first
            if locator.is_visible() and _click_locator_human_like(page, locator, timeout_ms=timeout_ms):
                return True
        except Exception:
            pass
        finally:
            try:
                target.evaluate(clear_script, marker)
            except Exception:
                pass
    return False


def _click_primary_action(page: Any, preferred_texts: list[str], *, allow_generic_fallback: bool = True) -> bool:
    # 先精确点目标文案，绝不用 :has-text("Continue") 去匹配 Continue with Google。
    if _click_exact_action_texts(
        page,
        preferred_texts,
        allow_generic_submit=False,
        timeout_ms=1500,
    ):
        return True
    if allow_generic_fallback and _click_exact_action_texts(
        page,
        preferred_texts,
        allow_generic_submit=True,
        timeout_ms=1200,
    ):
        return True
    # 最后才按 Enter；若当前焦点在第三方登录按钮上仍可能误触，因此仅在没有社交登录选择页时使用。
    try:
        current_url = str(getattr(page, "url", "") or "")
    except Exception:
        current_url = ""
    body_text = ""
    try:
        body_text = _get_body_text(page)
    except Exception:
        body_text = ""
    if _is_social_login_choice_page(current_url, body_text, page):
        return False
    try:
        page.keyboard.press("Enter")
        return True
    except Exception:
        return False


def _request_submit_with_button(locator: Any) -> bool:
    if locator is None:
        return False
    try:
        locator.press("Enter", timeout=1200)
        return True
    except Exception:
        return False


def _click_otp_resend(page: Any) -> bool:
    selectors = [
        'button:has-text("Resend")',
        '[role="button"]:has-text("Resend")',
        'a:has-text("Resend")',
        'button:has-text("Resend code")',
        '[role="button"]:has-text("Resend code")',
        'a:has-text("Resend code")',
        'button:has-text("Send again")',
        '[role="button"]:has-text("Send again")',
        'a:has-text("Send again")',
        'button:has-text("Send code again")',
        '[role="button"]:has-text("Send code again")',
        'a:has-text("Send code again")',
        'button:has-text("Try again")',
        '[role="button"]:has-text("Try again")',
        'a:has-text("Try again")',
        'button:has-text("重新发送")',
        '[role="button"]:has-text("重新发送")',
        'a:has-text("重新发送")',
        'button:has-text("再次发送")',
        '[role="button"]:has-text("再次发送")',
        'a:has-text("再次发送")',
        'button:has-text("重发验证码")',
        '[role="button"]:has-text("重发验证码")',
        'a:has-text("重发验证码")',
        'button:has-text("获取新验证码")',
        '[role="button"]:has-text("获取新验证码")',
        'a:has-text("获取新验证码")',
    ]
    return _click_first(page, selectors, timeout_ms=1500)


def _click_retryable_error_action(page: Any) -> bool:
    selectors = [
        'button:has-text("Try again")',
        '[role="button"]:has-text("Try again")',
        'a:has-text("Try again")',
        'button:has-text("Retry")',
        '[role="button"]:has-text("Retry")',
        'a:has-text("Retry")',
        'button:has-text("重试")',
        '[role="button"]:has-text("重试")',
        'a:has-text("重试")',
        'button:has-text("Continue")',
        '[role="button"]:has-text("Continue")',
    ]
    if _click_first(page, selectors, timeout_ms=1500):
        return True
    if _click_first(page, selectors, timeout_ms=1200):
        return True
    try:
        frames = list(getattr(page, "frames", []) or [])
    except Exception:
        frames = []
    for frame in frames:
        if frame is None:
            continue
        if _click_first(frame, selectors, timeout_ms=1200):
            return True
    return False


def _get_body_text(page: Any) -> str:
    try:
        return str(page.locator("body").inner_text(timeout=1500) or "")
    except Exception:
        return ""


def _get_body_raw_text(page: Any) -> str:
    try:
        text = page.locator("body").text_content(timeout=1500)
        if str(text or "").strip():
            return str(text or "")
    except Exception:
        pass
    # page.evaluate 没有 timeout；渲染器失联时会把同步 Playwright 线程永久挂住。
    # text_content 已经覆盖页面正文，失败时返回空串交给 URL/已有快照继续判断。
    return ""


def _get_alert_text(page: Any, *, max_items: int = 12) -> str:
    """读取常见错误提示节点；每个节点有短 timeout，不调用 evaluate。"""
    parts: list[str] = []
    selectors = (
        '[role="alert"]',
        '[aria-live="assertive"]',
        '[aria-live="polite"]',
        '[role="heading"]',
        "h1",
        "h2",
    )
    item_limit = max(1, int(max_items or 1))
    for target in _iter_page_targets(page):
        for selector in selectors:
            try:
                locator = target.locator(selector)
            except Exception:
                continue
            for index in range(item_limit):
                try:
                    text = str(locator.nth(index).inner_text(timeout=300) or "").strip()
                except Exception:
                    break
                if text and text not in parts:
                    parts.append(text)
                    if len(parts) >= item_limit:
                        return "\n".join(parts)
    return "\n".join(parts)


def _get_page_deep_text(page: Any) -> str:
    parts: list[str] = []
    seen: set[str] = set()
    total_chars = 0

    def _push(text: str) -> None:
        nonlocal total_chars
        normalized = str(text or "").strip()
        if not normalized:
            return
        remaining = _PAGE_SNAPSHOT_MAX_BODY_CHARS - total_chars
        if remaining <= 0:
            return
        normalized = normalized[:remaining]
        key = re.sub(r"\s+", " ", normalized)[:2000]
        if key in seen:
            return
        seen.add(key)
        parts.append(normalized)
        total_chars += len(normalized) + 1

    _push(_get_body_raw_text(page))
    try:
        frames = list(getattr(page, "frames", []) or [])
    except Exception:
        frames = []
    for frame in frames:
        if total_chars >= _PAGE_SNAPSHOT_MAX_BODY_CHARS:
            break
        if frame is None:
            continue
        try:
            text = str(frame.locator("body").text_content(timeout=1500) or "")
            if not text.strip():
                text = str(frame.locator("body").inner_text(timeout=1000) or "")
        except Exception:
            text = ""
        _push(text)
    return "\n".join(parts).strip()


def _is_session_ended_page(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    # 注册主路径页面上即使残留文案，也不按会话结束处理，避免短信后误重拉 OAuth。
    if any(
        token in url_lower
        for token in (
            "contact-verification",
            "verify-phone",
            "phone-verification",
            "about-you",
            "create-account/password",
            "email-verification",
            "add-email",
            "auth_challenge/passkey",
        )
    ):
        return False
    return bool(
        "your session has ended" in body_lower
        or "session has ended" in body_lower
        or "你的会话已结束" in body_text
        or ("chatgpt.com" in url_lower and "sign up" in body_lower and "session" in body_lower and "ended" in body_lower)
    )


def _is_timeout_error_page(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    return bool(
        "operation timed out" in body_lower
        or ("oops, an error occurred" in body_lower and "timed out" in body_lower)
        or ("chatgpt.com" in url_lower and "timed out" in body_lower and "oops" in body_lower)
    )


def _is_rate_limit_error_page(url: str, body_text: str) -> bool:
    """OpenAI 限流页：Too many requests / rate_limit_exceeded。"""
    body_lower = str(body_text or "").lower()
    url_lower = str(url or "").lower()
    if not body_lower and "rate" not in url_lower:
        return False
    return bool(
        "rate_limit_exceeded" in body_lower
        or "rate limit exceeded" in body_lower
        or "too many requests" in body_lower
        or ("rate_limit" in body_lower and ("exceeded" in body_lower or "try again later" in body_lower))
        or ("请求过多" in str(body_text or "") or "请求太频繁" in str(body_text or ""))
    )


def _is_retryable_error_page(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if _is_timeout_error_page(url, body_text):
        return True
    if _is_rate_limit_error_page(url, body_text):
        return True
    return bool(
        "something went wrong" in body_lower
        or "oops" in body_lower
        or "an error occurred" in body_lower
        or "please try again" in body_lower
        or ("error" in url_lower and "auth.openai.com" in url_lower)
        or "出错了" in body_text
        or "请重试" in body_text
    )


def _is_phone_sms_send_failed_error(url: str, body_text: str, page: Any = None) -> bool:
    url_lower = str(url or "").lower()
    text = str(body_text or "")
    text_lower = text.lower()
    english_hints = (
        "unable to send a text message to this phone number",
        "unable to send a text message",
        "unable to send text message to this phone number",
        "we couldn't send a text message to this phone number",
        "we couldn't send a text to this phone number",
        "couldn't send a text message to this phone number",
        "could not send a text message to this phone number",
        "cannot send a text message to this phone number",
        "this phone number is not supported",
    )
    chinese_hints = (
        "无法向此电话号码发送短信",
        "无法向该手机号发送短信",
        "无法向这个手机号发送短信",
        "不能向此电话号码发送短信",
        "不能向该手机号发送短信",
        "无法发送短信到此号码",
    )
    if any(hint in text_lower for hint in english_hints):
        return True
    if any(hint in text for hint in chinese_hints):
        return True
    if page is None:
        return False
    raw_text = _get_body_raw_text(page)
    raw_lower = str(raw_text or "").lower()
    if any(hint in raw_lower for hint in english_hints):
        return True
    if any(hint in str(raw_text or "") for hint in chinese_hints):
        return True
    if "auth.openai.com" not in url_lower and "/reset-password" not in url_lower:
        return False
    alert_text = _get_alert_text(page)
    alert_lower = alert_text.lower()
    if any(hint in alert_lower for hint in english_hints):
        return True
    if any(hint in alert_text for hint in chinese_hints):
        return True
    return False


def _is_virtual_phone_number_error(url: str, body_text: str, page: Any = None) -> bool:
    text = str(body_text or "")
    text_lower = text.lower()
    english_hints = (
        "virtual phone number",
        "non-virtual phone number",
        "non virtual phone number",
        "valid, non-virtual phone number",
        "valid non-virtual phone number",
        "also known as voip",
        "also known as a voip",
        "voip phone number",
        "this is a virtual phone number",
    )
    chinese_hints = (
        "虚拟号码",
        "虚拟手机号",
        "虚拟电话号码",
        "网络电话",
        "voip 号码",
        "非虚拟手机号",
        "非虚拟电话号码",
    )
    if any(hint in text_lower for hint in english_hints):
        return True
    if any(hint in text for hint in chinese_hints):
        return True
    if page is None:
        return False
    raw_text = _get_body_raw_text(page)
    raw_lower = str(raw_text or "").lower()
    if any(hint in raw_lower for hint in english_hints):
        return True
    if any(hint in str(raw_text or "") for hint in chinese_hints):
        return True
    return False


def _is_phone_number_existing_account_error(url: str, body_text: str, page: Any = None) -> bool:
    """
    手机号已绑定既有账号：应废弃当前号并重新取号。
    常见文案：
    - An account for this phone number already exists
    - To continue, sign in to h****1@o****k.com using that account's usual sign-in method.
    """
    url_lower = str(url or "").lower()
    text = str(body_text or "")
    text_lower = text.lower()
    english_hints = (
        "an account for this phone number already exists",
        "account for this phone number already exists",
        "this phone number already exists",
        "phone number already exists",
        "already have an account",
        "already associated with an account",
        # 已绑邮箱，要求用原账号登录方式（号码已被注册）
        "using that account's usual sign-in method",
        "using that account's usual sign in method",
        "using this account's usual sign-in method",
        "usual sign-in method",
        "usual sign in method",
        "to continue, sign in to",
        "to continue sign in to",
        "sign in to that account",
        "sign in with the email associated",
        "an account already exists for this phone",
        "this phone number is already associated",
        "phone number is already linked",
        "phone number is already registered",
        # 不能用此手机号登录/注册：已存在账号或号码被封禁
        "you can't log in or sign up with this phone number",
        "can't log in or sign up with this phone number",
        "this phone number cannot be used",
        "phone number cannot be used for registration",
        "phone number is blocked",
        "phone number is not allowed",
        "use your email address or another method",
        "you can't use this phone number",
    )
    chinese_hints = (
        "此电话号码已存在账号",
        "这个手机号已存在账号",
        "该手机号已存在账号",
        "此号码已存在账号",
        "该号码已存在账号",
        "该手机号已注册",
        "此手机号已注册",
        "手机号已绑定账号",
        "使用该账户的常用登录方式",
        "使用该账号的常用登录方式",
        "使用此账户的常用登录方式",
        "请使用该账户常用的登录方式",
        "请使用该账号常用的登录方式",
        "要继续，请登录",
        "要继续请登录",
    )

    def _match_existing(blob: str, blob_lower: str) -> bool:
        if any(hint in blob_lower for hint in english_hints):
            return True
        if any(hint in blob for hint in chinese_hints):
            return True
        # To continue, sign in to h****1@o****k.com ...
        # 遮罩邮箱 + sign in to / 登录到
        if (
            ("sign in to" in blob_lower or "sign-in to" in blob_lower or "登录到" in blob or "登录 " in blob)
            and re.search(r"[a-z0-9*]{1,64}@[a-z0-9*.\-]{2,}\.[a-z*]{2,}", blob_lower)
            and (
                "usual" in blob_lower
                or "continue" in blob_lower
                or "that account" in blob_lower
                or "this account" in blob_lower
                or "常用" in blob
                or "继续" in blob
            )
        ):
            return True
        return False

    if _match_existing(text, text_lower):
        return True
    if page is None:
        return False
    raw_text = _get_body_raw_text(page)
    raw_lower = str(raw_text or "").lower()
    if _match_existing(str(raw_text or ""), raw_lower):
        return True
    try:
        deep = _get_page_deep_text(page)
    except Exception:
        deep = ""
    if deep and _match_existing(str(deep), str(deep).lower()):
        return True
    alert_text = _get_alert_text(page)
    if alert_text and _match_existing(alert_text, alert_text.lower()):
        return True
    return False


def _is_create_account_failed_error(url: str, body_text: str, page: Any = None) -> bool:
    url_lower = str(url or "").lower()
    text = str(body_text or "")
    text_lower = text.lower()
    english_hints = (
        "failed to create account",
        "failed to create your account",
        "unable to create account",
        "unable to create your account",
    )
    chinese_hints = (
        "创建账户失败",
        "创建账号失败",
        "无法创建账户",
        "无法创建账号",
    )
    if any(hint in text_lower for hint in english_hints):
        return True
    if any(hint in text for hint in chinese_hints):
        return True
    if page is None:
        return False
    raw_text = _get_body_raw_text(page)
    raw_lower = str(raw_text or "").lower()
    if any(hint in raw_lower for hint in english_hints):
        return True
    if any(hint in str(raw_text or "") for hint in chinese_hints):
        return True
    if "auth.openai.com" not in url_lower and "/create-account" not in url_lower:
        return False
    alert_text = _get_alert_text(page)
    alert_lower = alert_text.lower()
    if any(hint in alert_lower for hint in english_hints):
        return True
    if any(hint in alert_text for hint in chinese_hints):
        return True
    return False


def _extract_browser_context_session_token(context: Any) -> str:
    cookie_names = (
        "__Secure-next-auth.session-token",
        "next-auth.session-token",
        "__Secure-authjs.session-token",
        "authjs.session-token",
    )
    try:
        cookies = context.cookies(["https://chatgpt.com", "https://chatgpt.com/api/auth/session"])
    except Exception:
        try:
            cookies = context.cookies()
        except Exception:
            cookies = []
    for item in cookies or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name not in cookie_names:
            continue
        value = str(item.get("value") or "").strip()
        if value:
            return value
    return ""


def _browser_cookie_presence_summary(context: Any) -> str:
    cookie_names = (
        "oai-client-auth-session",
        "__Secure-next-auth.session-token",
        "next-auth.session-token",
        "__Secure-authjs.session-token",
        "authjs.session-token",
        "login_session",
        "oai-did",
    )
    try:
        cookies = context.cookies(["https://chatgpt.com", "https://auth.openai.com"])
    except Exception:
        try:
            cookies = context.cookies()
        except Exception:
            cookies = []
    cookie_map: dict[str, str] = {}
    for item in cookies or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "").strip()
        if name and value:
            cookie_map[name] = value
    parts: list[str] = []
    for cookie_name in cookie_names:
        value = str(cookie_map.get(cookie_name) or "").strip()
        parts.append(f"{cookie_name}:{len(value) if value else 0}")
    return ", ".join(parts) if parts else "-"


def _has_manual_v2_login_session(context: Any) -> bool:
    try:
        cookies = context.cookies(["https://chatgpt.com", "https://auth.openai.com"])
    except Exception:
        try:
            cookies = context.cookies()
        except Exception:
            cookies = []
    cookie_map: dict[str, str] = {}
    for item in cookies or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "").strip()
        if name and value:
            cookie_map[name] = value
    has_auth_session = bool(str(cookie_map.get("oai-client-auth-session") or "").strip())
    has_chatgpt_session = bool(
        str(cookie_map.get("__Secure-next-auth.session-token") or "").strip()
        or str(cookie_map.get("next-auth.session-token") or "").strip()
        or str(cookie_map.get("__Secure-authjs.session-token") or "").strip()
        or str(cookie_map.get("authjs.session-token") or "").strip()
    )
    return has_auth_session and has_chatgpt_session


def _try_build_token_from_browser_session(
    *,
    context: Any,
    emitter: Any,
    build_browser_session_token_func: Optional[Callable[[Dict[str, Any]], Optional[str]]],
    referer_url: str = "",
    fallback_email: str = "",
    timeout_ms: int = 15000,
    page: Any = None,
    proxy: str = "",
) -> Optional[str]:
    """通过临时标签读取 /api/auth/session 并组装 Token（恢复原逻辑）。"""
    if not callable(build_browser_session_token_func):
        return None
    session_page = None
    try:
        session_page = context.new_page()
        try:
            session_page.goto(
                "https://chatgpt.com/api/auth/session",
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
        except Exception as exc:
            try:
                emitter.warn(f"浏览器 session fast path 打开会话接口失败: {exc}", step="get_token")
            except Exception:
                pass
            return None
        try:
            _wait_for_load(session_page, timeout_ms=min(timeout_ms, 2500))
        except Exception:
            pass

        raw_text = _get_body_raw_text(session_page).strip()
        if not raw_text or "{" not in raw_text:
            try:
                emitter.warn(
                    f"浏览器 session fast path 未拿到有效 JSON: {_preview_text(raw_text, 180) or '-'}",
                    step="get_token",
                )
            except Exception:
                pass
            return None
        try:
            session_json = json.loads(raw_text)
        except Exception as exc:
            try:
                emitter.warn(f"浏览器 session fast path JSON 解析失败: {exc}", step="get_token")
            except Exception:
                pass
            return None
        if not isinstance(session_json, dict) or not session_json:
            return None

        session_payload = dict(session_json)
        access_token = str(
            session_json.get("accessToken")
            or session_json.get("access_token")
            or ((session_json.get("data") or {}).get("accessToken") if isinstance(session_json.get("data"), dict) else "")
            or ((session_json.get("data") or {}).get("access_token") if isinstance(session_json.get("data"), dict) else "")
            or ""
        ).strip()
        if not access_token:
            return None
        session_payload["access_token"] = access_token
        refresh_token = str(
            session_json.get("refreshToken")
            or session_json.get("refresh_token")
            or ""
        ).strip()
        if refresh_token:
            session_payload["refresh_token"] = refresh_token
        session_token = _extract_browser_context_session_token(context)
        if session_token:
            session_payload["session_token"] = session_token
        user_payload = session_json.get("user") if isinstance(session_json.get("user"), dict) else {}
        account_payload = session_json.get("account") if isinstance(session_json.get("account"), dict) else {}
        if user_payload and not session_payload.get("email"):
            session_payload["email"] = str(user_payload.get("email") or "").strip()
        if not str(session_payload.get("email") or "").strip() and str(fallback_email or "").strip():
            session_payload["email"] = str(fallback_email or "").strip()
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
            emitter.info(
                "浏览器 session fast path 诊断: "
                + f"top_keys={','.join(sorted(str(k) for k in session_json.keys())[:12]) or '-'}, "
                + f"user.email={str(user_payload.get('email') or '').strip() or '-'}, "
                + f"fallback_email={str(fallback_email or '').strip() or '-'}, "
                + f"account.id={str(account_payload.get('id') or '').strip() or '-'}, "
                + f"access_token={'有' if access_token else '无'}, "
                + f"refresh_token={'有' if refresh_token else '无'}, "
                + f"session_token={'有' if session_token else '无'}",
                step="get_token",
            )
        except Exception:
            pass

        result = build_browser_session_token_func(session_payload)
        if result:
            try:
                emitter.success(
                    "浏览器 session fast path 命中：页面会话已建立，直接组装 Token 成功",
                    step="get_token",
                )
            except Exception:
                pass
        else:
            try:
                emitter.warn("浏览器 session fast path 未能组装出完整 Token，请查看上一条 session 诊断日志。", step="get_token")
            except Exception:
                pass
        return result
    finally:
        if session_page is not None:
            try:
                session_page.close()
            except Exception:
                pass


def _fetch_browser_session_payload(
    *,
    context: Any,
    emitter: Any,
    referer_url: str = "",
    fallback_email: str = "",
    timeout_ms: int = 15000,
    page: Any = None,
    proxy: str = "",
) -> Optional[Dict[str, Any]]:
    """通过临时标签读取 /api/auth/session（恢复原逻辑）。"""
    session_page = None
    try:
        session_page = context.new_page()
        try:
            session_page.goto(
                "https://chatgpt.com/api/auth/session",
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
        except Exception as exc:
            try:
                emitter.warn(f"浏览器 session payload 打开会话接口失败: {exc}", step="get_token")
            except Exception:
                pass
            return None
        try:
            _wait_for_load(session_page, timeout_ms=min(timeout_ms, 2500))
        except Exception:
            pass
        raw_text = _get_body_raw_text(session_page).strip()
        if not raw_text or "{" not in raw_text:
            try:
                emitter.warn(
                    f"浏览器 session payload 未拿到有效 JSON: {_preview_text(raw_text, 180) or '-'}",
                    step="get_token",
                )
            except Exception:
                pass
            return None
        try:
            session_json = json.loads(raw_text)
        except Exception as exc:
            try:
                emitter.warn(f"浏览器 session payload JSON 解析失败: {exc}", step="get_token")
            except Exception:
                pass
            return None
        if not isinstance(session_json, dict) or not session_json:
            return None
        session_payload = dict(session_json)
        access_token = str(
            session_json.get("accessToken")
            or session_json.get("access_token")
            or ((session_json.get("data") or {}).get("accessToken") if isinstance(session_json.get("data"), dict) else "")
            or ((session_json.get("data") or {}).get("access_token") if isinstance(session_json.get("data"), dict) else "")
            or ""
        ).strip()
        if access_token:
            session_payload["access_token"] = access_token
        refresh_token = str(
            session_json.get("refreshToken")
            or session_json.get("refresh_token")
            or ""
        ).strip()
        if refresh_token:
            session_payload["refresh_token"] = refresh_token
        session_token = _extract_browser_context_session_token(context)
        if session_token:
            session_payload["session_token"] = session_token
        user_payload = session_json.get("user") if isinstance(session_json.get("user"), dict) else {}
        account_payload = session_json.get("account") if isinstance(session_json.get("account"), dict) else {}
        if user_payload and not session_payload.get("email"):
            session_payload["email"] = str(user_payload.get("email") or "").strip()
        if not str(session_payload.get("email") or "").strip() and str(fallback_email or "").strip():
            session_payload["email"] = str(fallback_email or "").strip()
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
            emitter.info(
                "浏览器 session payload 诊断: "
                + f"top_keys={','.join(sorted(str(k) for k in session_json.keys())[:12]) or '-'}, "
                + f"user.email={str(user_payload.get('email') or '').strip() or '-'}, "
                + f"fallback_email={str(fallback_email or '').strip() or '-'}, "
                + f"account.id={str(account_payload.get('id') or '').strip() or '-'}, "
                + f"access_token={'有' if access_token else '无'}, "
                + f"refresh_token={'有' if refresh_token else '无'}, "
                + f"session_token={'有' if session_token else '无'}",
                step="get_token",
            )
        except Exception:
            pass
        return session_payload
    finally:
        if session_page is not None:
            try:
                session_page.close()
            except Exception:
                pass


def _has_visible_password_input(page: Any) -> bool:
    if page is None:
        return False
    return _first_visible_locator(
        page,
        [
            'input[type="password"]',
            'input[name="password"]',
            'input[name="new-password"]',
            'input[autocomplete="new-password"]',
            'input[autocomplete="current-password"]',
            'input[id*="password" i]',
        ],
    ) is not None


def _has_visible_about_you_controls(page: Any) -> bool:
    if page is None:
        return False
    return _first_visible_locator(
        page,
        [
            'input[name="name"][autocomplete="name"]',
            'input[name="name"][placeholder*="Full name" i]',
            'input[name="name"]',
            'input[name="age"]',
            'input[placeholder="Age"]',
            'input[placeholder*="Age" i]',
            'button:has-text("Finish creating account")',
            '[type="submit"]:has-text("Finish creating account")',
        ],
    ) is not None


def _is_profile_page(url: str, body_text: str, page: Any = None) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    body_text_value = str(body_text or "")

    # 密码创建/登录页绝不能当 about-you；否则会跳过短信并误填资料。
    if any(
        token in url_lower
        for token in (
            "/create-account/password",
            "/log-in/password",
            "/reset-password/new-password",
            "/reset-password",
        )
    ):
        return False

    # 可见密码框 + 创建密码文案：明确是密码页，不是资料页。
    # 深文案/脚本里可能误含 birthday/full name 等词，不能仅靠正文关键词。
    if page is not None and _has_visible_password_input(page):
        if (
            "create a password" in body_lower
            or "create password" in body_lower
            or "创建密码" in body_text_value
            or "you'll use this password" in body_lower
            or "you will use this password" in body_lower
            or "/create-account/" in url_lower
        ):
            return False
        # 密码框仍在且没有明确 about-you 控件时，也不当资料页。
        if "about-you" not in url_lower and not _has_visible_about_you_controls(page):
            return False

    if "about-you" in url_lower:
        return True

    # 正文关键词仅作弱信号：若有 page，必须同时看到 name/age 控件，避免脚本/隐藏文案误触发。
    body_looks_like_profile = any(
        token in body_lower
        for token in (
            "let's confirm your age",
            "how old are you",
            "whats your name",
            "what's your name",
            "full name",
            "finish creating account",
            "please enter name to continue",
            "enter a valid age",
            "birthday",
            "date of birth",
            "confirm your age",
        )
    ) or any(
        token in body_text_value
        for token in (
            "确认你的年龄",
            "你的名字",
            "全名",
            "生日",
            "出生日期",
            "完成帐户创建",
            "完成账户创建",
        )
    )
    if body_looks_like_profile:
        if page is None:
            return True
        if _has_visible_about_you_controls(page):
            return True
        # 无可见资料控件时，不因深文案/脚本关键词误判。
        return False

    if page is not None and _has_visible_about_you_controls(page):
        # 排除密码页残留 DOM 误命中。
        if _has_visible_password_input(page) and "about-you" not in url_lower:
            return False
        return True
    return False


def _normalize_youre_all_set_text(text: str) -> str:
    """统一弯引号/空白，便于匹配 You're all set 文案。"""
    value = str(text or "").lower()
    for src_ch, dst in (
        ("\u2019", "'"),
        ("\u2018", "'"),
        ("\u201c", '"'),
        ("\u201d", '"'),
        ("\u00a0", " "),
    ):
        value = value.replace(src_ch, dst)
    return re.sub(r"\s+", " ", value).strip()


def _body_has_youre_all_set_title(body_text: str) -> bool:
    body_norm = _normalize_youre_all_set_text(body_text)
    body_raw = str(body_text or "")
    if any(
        token in body_norm
        for token in (
            "you're all set",
            "you are all set",
            "youre all set",
            "you are ready",
            "you're ready",
        )
    ):
        return True
    return any(
        token in body_raw
        for token in (
            "你已准备就绪",
            "一切就绪",
            "全部就绪",
            "准备就绪",
        )
    )


def _body_has_youre_all_set_disclaimer(body_text: str) -> bool:
    body_norm = _normalize_youre_all_set_text(body_text)
    return any(
        token in body_norm
        for token in (
            "chatgpt can make mistakes",
            "don't share sensitive",
            "dont share sensitive",
            "by continuing, you agree",
            "by continuing you agree",
            "chatgpts may make mistakes",
            "chatgpt 可能会出错",
            "chatgpt可能会出错",
            "继续即表示你同意",
            "继续即表示您同意",
        )
    )


def _find_youre_all_set_continue_locator(page: Any) -> Any:
    """定位 You're all set 页的 Continue 黑按钮。"""
    if page is None:
        return None
    return _first_visible_locator(
        page,
        [
            'button:text-is("Continue")',
            '[role="button"]:text-is("Continue")',
            'button:text-is("继续")',
            '[role="button"]:text-is("继续")',
            'button:has-text("Continue")',
            '[role="button"]:has-text("Continue")',
            'button[type="submit"]:has-text("Continue")',
            'button:has-text("继续")',
            '[role="button"]:has-text("继续")',
            'button:text-is("Got it")',
            'button:has-text("Got it")',
            'button:text-is("Done")',
            'button:text-is("完成")',
        ],
    )


def _is_youre_all_set_page(url: str, body_text: str, page: Any = None) -> bool:
    """
    about-you 完成后的引导完成页：
    "You're all set" + Continue。
    必须点 Continue，否则会卡死在完成页。
    """
    if page is not None and _has_visible_about_you_controls(page):
        # 资料表单还在时，绝不当完成页。
        return False
    if _body_has_youre_all_set_title(body_text):
        return True
    # 弱信号：免责声明 + 可见 Continue 大按钮（SPA 标题偶发读不到）
    if _body_has_youre_all_set_disclaimer(body_text):
        if page is None:
            body_norm = _normalize_youre_all_set_text(body_text)
            return "continue" in body_norm or "继续" in str(body_text or "")
        if _find_youre_all_set_continue_locator(page) is not None:
            return True
    # DOM 直读标题（_describe_page 有时拿不全 SPA 文案）
    if page is not None:
        try:
            has_title = bool(
                page.evaluate(
                    """() => {
                        const raw = String(
                            (document.body && (document.body.innerText || document.body.textContent)) || ''
                        );
                        const t = raw.toLowerCase()
                            .replace(/[\\u2018\\u2019]/g, "'")
                            .replace(/\\s+/g, ' ');
                        if (
                            t.includes("you're all set")
                            || t.includes('you are all set')
                            || t.includes('youre all set')
                            || t.includes('you are ready')
                        ) {
                            return true;
                        }
                        if (
                            raw.includes('你已准备就绪')
                            || raw.includes('一切就绪')
                            || raw.includes('全部就绪')
                            || raw.includes('准备就绪')
                        ) {
                            return true;
                        }
                        const h = Array.from(document.querySelectorAll('h1,h2,[role="heading"]'))
                            .map((n) => String(n.innerText || n.textContent || '').trim().toLowerCase())
                            .join(' | ');
                        return h.includes("you're all set")
                            || h.includes('you are all set')
                            || h.includes('youre all set')
                            || h.includes('准备就绪');
                    }"""
                )
            )
            if has_title:
                return True
        except Exception:
            pass
        # 最弱信号：无 about-you 表单 + 免责声明 + Continue 主按钮
        try:
            weak = bool(
                page.evaluate(
                    """() => {
                        const raw = String(
                            (document.body && (document.body.innerText || document.body.textContent)) || ''
                        ).toLowerCase();
                        const hasDisclaimer = raw.includes('chatgpt can make mistakes')
                            || raw.includes('by continuing, you agree')
                            || raw.includes('by continuing you agree')
                            || raw.includes("don't share sensitive")
                            || raw.includes('chatgpt 可能会出错')
                            || raw.includes('继续即表示');
                        if (!hasDisclaimer) return false;
                        const nodes = Array.from(document.querySelectorAll('button, [role="button"]'));
                        const isVisible = (el) => {
                            if (!el || el.disabled) return false;
                            const r = el.getBoundingClientRect();
                            const s = window.getComputedStyle(el);
                            return r.width > 40 && r.height > 20
                                && s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0';
                        };
                        return nodes.some((el) => {
                            if (!isVisible(el)) return false;
                            const t = String(el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim().toLowerCase();
                            return t === 'continue' || t === '继续' || t === 'got it' || t === 'done' || t === '完成';
                        });
                    }"""
                )
            )
            if weak:
                return True
        except Exception:
            pass
    return False


def _click_youre_all_set_continue(page: Any) -> bool:
    """点 You're all set 页的 Continue；多策略重试，避免点不到黑按钮。"""
    if page is None:
        return False
    # 0) 按钮可能刚渲染：短暂等可见
    for _ in range(4):
        if _find_youre_all_set_continue_locator(page) is not None:
            break
        _sleep_with_page(page, 250)
    # 1) 精确文案 + 真人轨迹
    if _click_exact_action_texts(
        page,
        ["Continue", "继续", "Got it", "Done", "完成"],
        allow_generic_submit=False,
        timeout_ms=2000,
    ):
        return True
    # 2) 常见选择器 + 真人 / force / JS
    loc = _find_youre_all_set_continue_locator(page)
    if loc is not None and _click_locator_human_like(page, loc, timeout_ms=2000):
        return True
    if loc is not None:
        try:
            loc.click(timeout=1800, force=True, delay=random.randint(40, 120))
            return True
        except Exception:
            pass
        try:
            ok = bool(
                loc.evaluate(
                    """(el) => {
                        try { el.focus(); } catch (e) {}
                        try { el.click(); return true; } catch (e) {}
                        try {
                            el.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true, view: window}));
                            return true;
                        } catch (e2) {}
                        return false;
                    }"""
                )
            )
            if ok:
                return True
        except Exception:
            pass
    # 3) 坐标兜底：找含 Continue 的大黑按钮中心
    try:
        pos = page.evaluate(
            """() => {
                const nodes = Array.from(document.querySelectorAll('button, [role="button"], a, div[role="button"]'));
                const isVisible = (el) => {
                    if (!el) return false;
                    const r = el.getBoundingClientRect();
                    const s = window.getComputedStyle(el);
                    return r.width > 40 && r.height > 20
                        && s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0';
                };
                const wanted = new Set(['continue', '继续', 'got it', 'done', '完成']);
                let best = null;
                for (const el of nodes) {
                    if (!isVisible(el) || el.disabled) continue;
                    const t = String(el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim().toLowerCase();
                    if (!wanted.has(t)) continue;
                    const r = el.getBoundingClientRect();
                    const area = r.width * r.height;
                    if (!best || area > best.area) {
                        best = { x: r.x + r.width / 2, y: r.y + r.height / 2, w: r.width, h: r.height, area };
                    }
                }
                return best;
            }"""
        )
        if isinstance(pos, dict) and pos.get("x") is not None:
            if _click_at_point_human_like(page, float(pos["x"]), float(pos["y"])):
                return True
            try:
                page.mouse.click(float(pos["x"]), float(pos["y"]), delay=random.randint(40, 100))
                return True
            except Exception:
                pass
    except Exception:
        pass
    # 4) 键盘兜底：焦点在 Continue 时按 Enter / Space
    try:
        focused = bool(
            page.evaluate(
                """() => {
                    const wanted = new Set(['continue', '继续', 'got it', 'done', '完成']);
                    const nodes = Array.from(document.querySelectorAll('button, [role="button"]'));
                    for (const el of nodes) {
                        const t = String(el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim().toLowerCase();
                        if (!wanted.has(t)) continue;
                        try { el.focus(); return true; } catch (e) {}
                    }
                    return false;
                }"""
            )
        )
        if focused:
            try:
                page.keyboard.press("Enter")
                return True
            except Exception:
                pass
            try:
                page.keyboard.press(" ")
                return True
            except Exception:
                pass
    except Exception:
        pass
    return _click_first(
        page,
        [
            'button:text-is("Continue")',
            'button:has-text("Continue")',
            '[role="button"]:has-text("Continue")',
            'button[type="submit"]:has-text("Continue")',
            'button:has-text("继续")',
            '[role="button"]:has-text("继续")',
        ],
        timeout_ms=1500,
    )


def _read_page_url_body(page: Any) -> tuple[str, str]:
    """刷新读取当前 url + 深文案，供 You're all set / about-you 判定。"""
    url, body = "", ""
    try:
        url, body = _describe_page(page, force_refresh=True)
    except Exception:
        url, body = "", ""
    try:
        deep = _get_page_deep_text(page)
        if str(deep or "").strip():
            body = deep
    except Exception:
        pass
    return str(url or ""), str(body or "")


def _looks_like_chatgpt_composer_home(page: Any, body_text: str) -> bool:
    """真正对话首页信号（有输入框），区别于 You're all set 引导页。"""
    body_norm = _normalize_youre_all_set_text(body_text)
    if any(
        token in body_norm
        for token in (
            "message chatgpt",
            "ask anything",
            "ask chatgpt",
            "向 chatgpt 提问",
            "询问任何问题",
            "发送消息",
        )
    ):
        return True
    if page is None:
        return False
    try:
        loc = _first_visible_locator(
            page,
            [
                '#prompt-textarea',
                'textarea[placeholder*="Message"]',
                'textarea[placeholder*="Ask"]',
                'div[contenteditable="true"]#prompt-textarea',
                '[data-testid="composer"]',
                'textarea[name="prompt-textarea"]',
            ],
        )
        return loc is not None
    except Exception:
        return False


def _wait_for_post_about_you_page(
    page: Any,
    *,
    emitter: Any = None,
    step: str = "create_account",
    timeout_ms: int = 12000,
) -> Dict[str, Any]:
    """
    about-you 提交后等待下一状态。
    注意：You're all set 本身就在 chatgpt.com（无 about-you），
    绝不能把“到了 chatgpt.com”当成已离开完成页。
    返回: {url, body, kind}  kind in youre_all_set|missing_email|still_form|home|auth|other
    """
    result: Dict[str, Any] = {"url": "", "body": "", "kind": "other"}
    if page is None:
        return result
    started = time.time()
    deadline = started + max(1.0, float(timeout_ms or 0) / 1000.0)
    # 给 SPA 渲染 You're all set 的最短观察窗，避免空页被误判成首页
    min_observe_s = min(1.6, max(0.8, (deadline - started) * 0.25))
    # 表单已离开且始终没有完成页：最多再观察这么久（避免无 You're all set 时空耗满 timeout）
    no_all_set_grace_s = min(2.2, max(1.2, (deadline - started) * 0.35))
    logged_all_set = False
    form_left_at = 0.0
    while time.time() < deadline:
        url, body = _read_page_url_body(page)
        result["url"], result["body"] = url, body
        if _is_youre_all_set_page(url, body, page):
            result["kind"] = "youre_all_set"
            if not logged_all_set and emitter is not None:
                logged_all_set = True
                try:
                    emitter.info(
                        "浏览器模式2 about-you 提交后已出现 You're all set 完成页，准备点 Continue...",
                        step=step,
                    )
                except Exception:
                    pass
            return result
        # 无完整文案时，仅凭 Continue 黑按钮也先按完成页处理（标题晚渲染）
        if (
            not _has_visible_about_you_controls(page)
            and _find_youre_all_set_continue_locator(page) is not None
            and (
                _body_has_youre_all_set_disclaimer(body)
                or _body_has_youre_all_set_title(body)
                or len(str(body or "").strip()) < 40
            )
        ):
            # 正文极短 + 只有 Continue：多半是完成页正在渲染
            if _find_youre_all_set_continue_locator(page) is not None and not _looks_like_chatgpt_composer_home(page, body):
                result["kind"] = "youre_all_set"
                if not logged_all_set and emitter is not None:
                    logged_all_set = True
                    try:
                        emitter.info(
                            "浏览器模式2 about-you 提交后检测到 Continue 引导按钮（疑似 You're all set），准备点击...",
                            step=step,
                        )
                    except Exception:
                        pass
                return result
        if _is_about_you_missing_email_error(url, body):
            result["kind"] = "missing_email"
            return result
        if _about_you_form_still_visible(url, body, page):
            result["kind"] = "still_form"
            form_left_at = 0.0
            # 表单还在可能是短暂过渡；接近超时再返回
            if time.time() + 1.0 >= deadline:
                return result
            _sleep_with_page(page, 280)
            continue
        # 表单已离开
        if form_left_at <= 0:
            form_left_at = time.time()
        url_l = str(url or "").lower()
        elapsed = time.time() - started
        form_left_for = time.time() - form_left_at
        # 明确进入登录/OAuth/验证码页，可结束等待
        if any(
            token in url_l
            for token in (
                "auth.openai.com",
                "email-verification",
                "contact-verification",
                "add-phone",
                "choose-an-account",
                "add-email",
            )
        ) and "about-you" not in url_l:
            result["kind"] = "auth"
            return result
        # oauth/login 也要避开过早误判；最短观察窗后再认
        if elapsed >= min_observe_s and any(
            token in url_l for token in ("/api/auth", "oauth", "authorize")
        ) and "about-you" not in url_l:
            result["kind"] = "auth"
            return result
        # 真正的 ChatGPT 主站对话页：必须看到输入框，且没有 Continue 引导
        if (
            elapsed >= min_observe_s
            and _is_logged_in_chatgpt_home(url, body)
            and not _body_has_youre_all_set_title(body)
            and not _body_has_youre_all_set_disclaimer(body)
            and _find_youre_all_set_continue_locator(page) is None
            and _looks_like_chatgpt_composer_home(page, body)
        ):
            result["kind"] = "home"
            return result
        # 有 Continue 但主站 URL：按完成页
        if (
            _find_youre_all_set_continue_locator(page) is not None
            and not _looks_like_chatgpt_composer_home(page, body)
            and not _has_visible_about_you_controls(page)
        ):
            result["kind"] = "youre_all_set"
            return result
        # 关键加速：表单已离开、始终无完成页信号 → 短观察后放行，不再空耗满 timeout
        # （本轮日志常见：about-you 后直接进步骤2，没有 You're all set）
        if form_left_for >= no_all_set_grace_s and elapsed >= min_observe_s:
            has_continue = _find_youre_all_set_continue_locator(page) is not None
            if (
                not has_continue
                and not _body_has_youre_all_set_title(body)
                and not _body_has_youre_all_set_disclaimer(body)
            ):
                if _looks_like_chatgpt_composer_home(page, body):
                    result["kind"] = "home"
                else:
                    result["kind"] = "other"
                return result
        _sleep_with_page(page, 280)
    # 超时前最后一次判定
    url, body = _read_page_url_body(page)
    result["url"], result["body"] = url, body
    if _is_youre_all_set_page(url, body, page):
        result["kind"] = "youre_all_set"
    elif _is_about_you_missing_email_error(url, body):
        result["kind"] = "missing_email"
    elif _about_you_form_still_visible(url, body, page):
        result["kind"] = "still_form"
    elif _find_youre_all_set_continue_locator(page) is not None and not _has_visible_about_you_controls(page):
        # 超时仍见 Continue 且无资料表单：按完成页处理，避免漏点
        result["kind"] = "youre_all_set"
        if emitter is not None:
            try:
                emitter.warn(
                    "浏览器模式2 about-you 提交后超时，仍看到 Continue 按钮，按 You're all set 处理...",
                    step=step,
                )
            except Exception:
                pass
    else:
        result["kind"] = "other"
    return result


def _pass_youre_all_set_page(
    page: Any,
    *,
    emitter: Any = None,
    step: str = "create_account",
    max_attempts: int = 8,
    settle_ms: int = 1800,
    wait_appear_ms: int = 0,
) -> Dict[str, Any]:
    """
    若当前在 You're all set，持续点 Continue 直到离开该页。
    wait_appear_ms>0 时先等完成页出现（about-you 提交后 SPA 渲染有延迟）。
    返回: {was_page, clicked, left, attempts, url, body}
    """
    result: Dict[str, Any] = {
        "was_page": False,
        "clicked": False,
        "left": False,
        "attempts": 0,
        "url": "",
        "body": "",
    }
    if page is None:
        return result

    # 提交后可能还没渲染出完成页：先等一会儿
    if int(wait_appear_ms or 0) > 0:
        appear = _wait_for_post_about_you_page(
            page,
            emitter=emitter,
            step=step,
            timeout_ms=int(wait_appear_ms),
        )
        result["url"] = str(appear.get("url") or "")
        result["body"] = str(appear.get("body") or "")
        kind = str(appear.get("kind") or "")
        if kind == "youre_all_set":
            result["was_page"] = True
        elif kind in {"missing_email", "home", "auth", "other"}:
            # 没有完成页（含 about-you 后直接跳过 You're all set 的常见路径），视为已通过
            result["left"] = True
            return result
        elif kind == "still_form":
            result["left"] = False
            return result

    url, body = _read_page_url_body(page)
    result["url"], result["body"] = url, body
    if not result["was_page"]:
        if _is_youre_all_set_page(url, body, page):
            result["was_page"] = True
        elif (
            _find_youre_all_set_continue_locator(page) is not None
            and not _has_visible_about_you_controls(page)
            and (
                _body_has_youre_all_set_disclaimer(body)
                or _body_has_youre_all_set_title(body)
            )
        ):
            result["was_page"] = True

    if not result["was_page"]:
        # 当前确实不是完成页
        result["left"] = True
        return result

    attempts = max(1, int(max_attempts or 1))
    for i in range(1, attempts + 1):
        result["attempts"] = i
        if emitter is not None:
            try:
                emitter.info(
                    f"浏览器模式2 检测到 You're all set，准备点击 Continue（第 {i}/{attempts} 次）...",
                    step=step,
                )
            except Exception:
                pass
        clicked = _click_youre_all_set_continue(page)
        if clicked:
            result["clicked"] = True
            if emitter is not None:
                try:
                    emitter.info(
                        f"浏览器模式2 You're all set 已点击 Continue（第 {i} 次），等待离开完成页...",
                        step=step,
                    )
                except Exception:
                    pass
        else:
            if emitter is not None:
                try:
                    emitter.warn(
                        f"浏览器模式2 You're all set 第 {i} 次未点到 Continue，稍后重试..."
                        + f" actions={_summarize_primary_actions(page)}",
                        step=step,
                    )
                except Exception:
                    pass
        _wait_for_load(page, timeout_ms=min(1800, int(settle_ms or 1800) + 600))
        _sleep_with_page(page, max(400, int(settle_ms or 0)))
        url, body = _read_page_url_body(page)
        result["url"], result["body"] = url, body
        if not _is_youre_all_set_page(url, body, page):
            # 离开完成页：也可能短暂空白，再确认 Continue 引导是否消失
            still_has_continue = False
            try:
                still_has_continue = (
                    _find_youre_all_set_continue_locator(page) is not None
                    and _body_has_youre_all_set_disclaimer(body)
                )
            except Exception:
                still_has_continue = False
            if not still_has_continue:
                result["left"] = True
                if emitter is not None:
                    try:
                        emitter.success(
                            "浏览器模式2 已离开 You're all set 完成页，继续后续流程...",
                            step=step,
                        )
                    except Exception:
                        pass
                return result
        # 点过但仍在页上：下轮换策略前稍等
        if clicked:
            _sleep_with_page(page, 400 + i * 120)
    # 最后仍未离开
    result["left"] = not _is_youre_all_set_page(result.get("url") or "", result.get("body") or "", page)
    return result


def _is_logged_in_chatgpt_home(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "chatgpt.com" not in url_lower:
        return False
    if "auth.openai.com" in url_lower or "chatgpt.com/auth/login_with" in url_lower:
        return False
    if _is_profile_page(url, body_text):
        return False
    if _is_session_ended_page(url, body_text):
        return False
    # You're all set 引导页也在 chatgpt.com，绝不能当已登录首页。
    if _body_has_youre_all_set_title(body_text) or _body_has_youre_all_set_disclaimer(body_text):
        return False
    if any(
        token in body_lower
        for token in (
            "continue with phone",
            "continue with email",
            "log in",
            "sign up",
            "login or sign up",
            "continue with google",
            "continue with apple",
            "继续使用手机登录",
            "继续使用邮箱",
            "登录或注册",
        )
    ):
        return False
    return True


def _is_birthdate_segment(locator: Any) -> bool:
    meta = _locator_metadata(locator)
    if not meta:
        return False
    data_type = meta.get("data_type", "")
    aria_label = meta.get("aria_label", "")
    haystack = " ".join(
        meta.get(key, "")
        for key in ("aria_label", "placeholder", "text", "parent_text", "labels")
    )
    if data_type in {"year", "month", "day"}:
        return True
    if any(token in aria_label for token in ("year", "month", "day", "年", "月", "日")):
        return True
    return any(token in haystack for token in ("birthday", "date of birth", "生日", "出生日期"))


def _is_profile_form_field(locator: Any) -> bool:
    """about-you 的 name/age 等资料字段，绝不能当 OTP 验证码输入。"""
    if locator is None:
        return False
    try:
        meta = _locator_metadata(locator) or {}
    except Exception:
        meta = {}
    joined = " ".join(str(v or "") for v in meta.values()).lower()
    name = str(meta.get("name") or "").strip().lower()
    placeholder = str(meta.get("placeholder") or "").strip().lower()
    autocomplete = str(meta.get("autocomplete") or "").strip().lower()
    input_type = str(meta.get("type") or "").strip().lower()
    if name in {"name", "age", "full_name", "fullname"}:
        return True
    if autocomplete in {"name", "given-name", "family-name"}:
        return True
    if placeholder in {"full name", "age", "name"} or "full name" in placeholder:
        return True
    if "age" in joined and "code" not in joined and "otp" not in joined:
        return True
    if input_type == "text" and name == "name":
        return True
    if input_type == "number" and ("age" in joined or name == "age"):
        return True
    return False


def _detect_otp_inputs(page: Any) -> Dict[str, Any]:
    # about-you 资料页绝不当 OTP 页。
    try:
        current_url = str(getattr(page, "url", "") or "")
    except Exception:
        current_url = ""
    if "about-you" in current_url.lower():
        return {"mode": "", "input": None}

    single_input = _first_visible_locator(
        page,
        [
            'input[autocomplete="one-time-code"]',
            'input[name*="otp" i]',
            'input[name*="code" i]',
            'input[aria-label*="code" i]',
            'input[placeholder*="code" i]',
            'input[placeholder*="digit" i]',
            'input[pattern*="[0-9]"]',
            'input[type="tel"]',
            'input[inputmode="numeric"]',
            '[contenteditable="true"][inputmode="numeric"]',
            '[role="textbox"][contenteditable="true"]',
            '[role="spinbutton"][contenteditable="true"]',
            '[role="textbox"][aria-label*="code" i]',
            '[role="spinbutton"][aria-label*="code" i]',
        ],
    )
    if single_input is not None and (_is_birthdate_segment(single_input) or _is_profile_form_field(single_input)):
        single_input = None

    segmented = []
    try:
        inputs = page.locator('input, [contenteditable="true"], [role="spinbutton"], [role="textbox"]')
        for index in range(16):
            item = inputs.nth(index)
            try:
                if not item.is_visible(timeout=300):
                    if index == 0:
                        break
                    continue
                maxlength = str(item.get_attribute("maxlength") or "").strip()
                inputmode = str(item.get_attribute("inputmode") or "").strip().lower()
                item_type = str(item.get_attribute("type") or "").strip().lower()
                autocomplete = str(item.get_attribute("autocomplete") or "").strip().lower()
                role = str(item.get_attribute("role") or "").strip().lower()
                aria_label = str(item.get_attribute("aria-label") or "").strip().lower()
                data_type = str(item.get_attribute("data-type") or "").strip().lower()
                if data_type in {"year", "month", "day"} or aria_label in {"年, ", "月, ", "日, "}:
                    continue
                text_value = ""
                try:
                    text_value = str(item.inner_text(timeout=300) or "").strip().lower()
                except Exception:
                    text_value = ""
                if _is_profile_form_field(item) or _is_birthdate_segment(item):
                    continue
                item_name = str(item.get_attribute("name") or "").strip().lower()
                if item_name in {"name", "age"}:
                    continue
                if (
                    maxlength == "1"
                    or (inputmode == "numeric" and item_name not in {"age"} and "age" not in aria_label)
                    or autocomplete == "one-time-code"
                    or item_type == "tel"
                    or (role in {"spinbutton", "textbox"} and ("code" in aria_label or "digit" in aria_label or data_type in {"otp", "code"}))
                    or (role in {"spinbutton", "textbox"} and text_value in {"", "•", "-", "_"} and "age" not in aria_label and item_name not in {"age", "name"})
                ):
                    segmented.append(item)
            except Exception:
                continue
    except Exception:
        pass

    if len(segmented) >= 6:
        return {"mode": "segmented", "inputs": segmented[:6]}
    if single_input is not None:
        return {"mode": "single", "input": single_input}
    return {"mode": "", "input": None}


def _summarize_otp_controls(page: Any) -> str:
    controls = _collect_visible_locators(
        page,
        [
            'input',
            '[contenteditable="true"]',
            '[role="spinbutton"]',
            '[role="textbox"]',
            'button',
        ],
        limit=8,
    )
    snippets: list[str] = []
    for item in controls:
        meta = _locator_metadata(item)
        if not meta:
            continue
        joined = " ".join(meta.values())
        if not any(token in joined for token in ("code", "otp", "digit", "verification", "verify")):
            continue
        snippets.append(
            "|".join(
                part
                for part in (
                    f"tag={meta.get('tag', '-')}",
                    f"role={meta.get('role', '-')}",
                    f"type={meta.get('type', '-')}",
                    f"name={meta.get('name', '-')}",
                    f"id={meta.get('id', '-')}",
                    f"data_type={meta.get('data_type', '-')}",
                    f"aria={_preview_text(meta.get('aria_label', ''), 40)}",
                    f"placeholder={_preview_text(meta.get('placeholder', ''), 40)}",
                    f"text={_preview_text(meta.get('text', ''), 40)}",
                    f"parent={_preview_text(meta.get('parent_text', ''), 40)}",
                )
                if part
            )
        )
        if len(snippets) >= 8:
            break
    return " || ".join(snippets) if snippets else "未识别到明显的 OTP 控件元数据"


def _summarize_primary_actions(page: Any) -> str:
    controls = _collect_visible_locators(
        page,
        [
            'button',
            '[role="button"]',
            'input[type="submit"]',
            'a',
        ],
        limit=8,
    )
    snippets: list[str] = []
    for item in controls:
        meta = _locator_metadata(item)
        if not meta:
            continue
        joined = " ".join(meta.values()).lower()
        if not any(token in joined for token in ("continue", "verify", "submit", "next", "confirm", "继续", "下一步", "验证")):
            continue
        snippets.append(
            "|".join(
                part
                for part in (
                    f"tag={meta.get('tag', '-')}",
                    f"role={meta.get('role', '-')}",
                    f"type={meta.get('type', '-')}",
                    f"text={_preview_text(meta.get('text', ''), 50)}",
                    f"aria={_preview_text(meta.get('aria_label', ''), 50)}",
                    f"id={meta.get('id', '-')}",
                    f"name={meta.get('name', '-')}",
                )
                if part
            )
        )
        if len(snippets) >= 8:
            break
    return " || ".join(snippets) if snippets else "未识别到明显的主提交按钮"


def _summarize_recent_network_events(events: Any, *, limit: int = 10) -> str:
    if not events:
        return "无"
    picked = list(events)[-max(1, int(limit or 1)) :]
    parts: list[str] = []
    for item in picked:
        if not isinstance(item, dict):
            continue
        method = str(item.get("method") or "-").strip()
        status = str(item.get("status") or item.get("event") or "-").strip()
        url = _mask_secret(str(item.get("url") or "").strip(), head=64, tail=18)
        parts.append(f"{method} {status} {url}".strip())
    return " || ".join(parts) if parts else "无"


def _has_recent_network_url(events: Any, token: str, *, within_seconds: float = 8.0) -> bool:
    token_lower = str(token or "").strip().lower()
    if not token_lower or not events:
        return False
    now = time.time()
    max_age = max(0.2, float(within_seconds or 0.0))
    for item in reversed(list(events)):
        if not isinstance(item, dict):
            continue
        url_lower = str(item.get("url") or "").strip().lower()
        if token_lower not in url_lower:
            continue
        try:
            event_ts = float(item.get("ts"))
        except Exception:
            continue
        if now - event_ts <= max_age:
            return True
    return False


def _has_recent_challenge_network(events: Any, *, within_seconds: float = 8.0) -> bool:
    return (
        _has_recent_network_url(events, "cdn-cgi/challenge-platform", within_seconds=within_seconds)
        or _has_recent_network_url(events, "cf-chl", within_seconds=within_seconds)
        or _has_recent_network_url(events, "/jsd/oneshot", within_seconds=within_seconds)
    )


def _write_text_to_locator(locator: Any, value: str, *, timeout_ms: int = 1200) -> bool:
    text = str(value or "")
    if not text:
        return False
    try:
        locator.click(timeout=timeout_ms)
    except Exception:
        pass
    try:
        locator.fill(text, timeout=timeout_ms)
        return True
    except Exception:
        pass
    try:
        locator.press("Control+A", timeout=timeout_ms)
    except Exception:
        pass
    try:
        locator.press("Meta+A", timeout=timeout_ms)
    except Exception:
        pass
    try:
        locator.press("Backspace", timeout=timeout_ms)
    except Exception:
        pass
    try:
        locator.type(text, timeout=timeout_ms)
        return True
    except Exception:
        pass
    try:
        locator.press_sequentially(text, timeout=timeout_ms)
        return True
    except Exception:
        pass
    # 不使用无 timeout 的 locator.evaluate；前面的 fill/type/press 已覆盖可编辑控件。
    return False


def _write_password_to_locator(
    locator: Any,
    value: str,
    *,
    timeout_ms: int = 1200,
) -> tuple[bool, str]:
    """只对目标密码 Locator 写入并确认值，禁止依赖页面全局焦点。"""
    text = str(value or "")
    if locator is None or not text:
        return False, "missing_locator_or_value"
    timeout = max(400, int(timeout_ms or 1200))
    last_reason = "not_attempted"

    try:
        locator.click(timeout=min(timeout, 900))
    except Exception as exc:
        last_reason = f"click:{type(exc).__name__}"

    try:
        locator.fill(text, timeout=timeout)
        if _locator_value(locator, timeout_ms=min(500, timeout)) == text:
            return True, "fill"
        last_reason = "fill_value_mismatch"
    except Exception as exc:
        last_reason = f"fill:{type(exc).__name__}"

    try:
        locator.fill(text, timeout=min(timeout, 900), force=True)
        if _locator_value(locator, timeout_ms=min(500, timeout)) == text:
            return True, "fill_force"
        last_reason = "fill_force_value_mismatch"
    except Exception as exc:
        last_reason = f"fill_force:{type(exc).__name__}"

    # 某些受控密码组件拦截 fill；仍在同一 Locator 上清空并逐字触发输入事件。
    try:
        locator.fill("", timeout=min(timeout, 700))
    except Exception:
        pass
    for method_name in ("press_sequentially", "type"):
        try:
            writer = getattr(locator, method_name)
            writer(text, timeout=timeout)
            if _locator_value(locator, timeout_ms=min(500, timeout)) == text:
                return True, method_name
            last_reason = f"{method_name}_value_mismatch"
        except Exception as exc:
            last_reason = f"{method_name}:{type(exc).__name__}"
        try:
            locator.fill("", timeout=min(timeout, 700))
        except Exception:
            pass
    return False, last_reason


def _find_visible_submit_locator(
    page: Any,
    preferred_texts: tuple[str, ...],
    *,
    max_candidates: int = 8,
) -> Any:
    """在主文档和 frame 内找可点击提交控件，避免无 timeout 的 page.evaluate。"""
    preferred = tuple(
        str(item or "").strip().lower()
        for item in preferred_texts
        if str(item or "").strip()
    )
    fallback = None
    selectors = ('button[type="submit"]', "button", 'input[type="submit"]', '[role="button"]')
    # OpenAI create-account/password 当前 Continue 控件具有稳定属性；先走精确路径，
    # 避免在页面和 frame 中逐个扫描候选按钮。
    fast_selectors = (
        'button[type="submit"][name="intent"][value="validate"]',
        'button[type="submit"][value="validate"]',
        'button[type="submit"][data-dd-action-name="Continue"]',
        'button[type="submit"]:has-text("Continue")',
        'button[type="submit"]:has-text("继续")',
    )
    for target in _iter_page_targets(page):
        for selector in fast_selectors:
            try:
                item = target.locator(selector).first
                if not item.is_visible(timeout=180) or not item.is_enabled(timeout=180):
                    continue
                aria_disabled = str(item.get_attribute("aria-disabled", timeout=180) or "").strip().lower()
                if aria_disabled == "true":
                    continue
                return item
            except Exception:
                continue
    for target in _iter_page_targets(page):
        for selector in selectors:
            try:
                locator = target.locator(selector)
            except Exception:
                continue
            for index in range(max(1, int(max_candidates or 1))):
                item = locator.nth(index)
                try:
                    if not item.is_visible(timeout=250):
                        if index == 0:
                            break
                        continue
                    if not item.is_enabled(timeout=250):
                        continue
                except Exception:
                    if index == 0:
                        break
                    continue
                text = ""
                try:
                    text = str(item.inner_text(timeout=250) or "").strip()
                except Exception:
                    pass
                if not text:
                    for attr_name in ("value", "aria-label"):
                        try:
                            text = str(item.get_attribute(attr_name, timeout=250) or "").strip()
                        except Exception:
                            text = ""
                        if text:
                            break
                normalized = text.lower()
                if "continue with" in normalized:
                    continue
                if fallback is None:
                    fallback = item
                if normalized and any(
                    token == normalized or token in normalized for token in preferred
                ):
                    return item
    return fallback


def _submit_create_account_password_like_codex_registrar(
    page: Any,
    password: str,
    *,
    emitter: Any = None,
    step: str = "create_password",
    check_page_ready: bool = True,
) -> Dict[str, str]:
    pwd = str(password or "").strip()
    if page is None or not pwd:
        return {"ok": "", "submitted": "", "reason": "missing_page_or_password"}
    if check_page_ready and not _is_create_account_password_ready_for_submit(page):
        if emitter is not None:
            try:
                emitter.warn(
                    "浏览器模式2 create-account/password 当前页面并非可安全提交的真实密码页，"
                    + "已跳过本轮专用提交，交回外层继续按错误页/过渡页诊断。",
                    step=step,
                )
                emitter.info(
                    "create-account/password 提交前页面诊断: "
                    + _summarize_create_account_password_probe(page)
                    + ", actions="
                    + _summarize_primary_actions(page),
                    step=step,
                )
            except Exception:
                pass
        return {"ok": "true", "submitted": "", "reason": "page_not_ready"}
    password_input = _first_visible_locator(
        page,
        [
            'input[type="password"]',
            'input[name="password"]',
            'input[name="new-password"]',
            'input[autocomplete="new-password"]',
            'input[id*="password" i]',
        ],
    )
    if password_input is None:
        if emitter is not None:
            try:
                emitter.warn(
                    "浏览器模式2 create-account/password 未找到可见密码输入框，"
                    + "本轮不提交并交由外层重试。",
                    step=step,
                )
            except Exception:
                pass
        return {"ok": "", "submitted": "", "reason": "password_input_missing"}
    if emitter is not None:
        try:
            emitter.info(
                "浏览器模式2 create-account/password 已定位密码输入框，开始使用同一元素填写并校验...",
                step=step,
            )
        except Exception:
            pass
    password_write_started_at = time.monotonic()
    typed, write_method = _write_password_to_locator(password_input, pwd, timeout_ms=1200)
    typed_value = _locator_value(password_input, timeout_ms=450)
    if not typed or typed_value != pwd:
        if emitter is not None:
            try:
                emitter.warn(
                    "浏览器模式2 create-account/password 密码未成功写入，当前页不会继续提交。"
                    + f" method={write_method}, elapsed_ms={int((time.monotonic() - password_write_started_at) * 1000)}, "
                    + f"actual={_mask_secret(typed_value, head=2, tail=2)}",
                    step=step,
                )
            except Exception:
                pass
        return {"ok": "", "submitted": "", "reason": "password_value_mismatch"}
    if emitter is not None:
        try:
            emitter.info(
                "浏览器模式2 create-account/password 密码已写入并通过值校验，准备点击继续按钮。"
                + f" method={write_method}, elapsed_ms={int((time.monotonic() - password_write_started_at) * 1000)}",
                step=step,
            )
        except Exception:
            pass
    _sleep_with_page(page, 80)
    submit_locator = _find_visible_submit_locator(
        page,
        ("继续", "Continue", "Next", "Verify", "Submit", "Create account", "Sign up"),
    )
    if submit_locator is None:
        if emitter is not None:
            try:
                emitter.warn(
                    "浏览器模式2 create-account/password 密码已填入，但未找到可点击的继续按钮。",
                    step=step,
                )
            except Exception:
                pass
        return {"ok": "", "submitted": "", "reason": "submit_button_missing"}
    clicked = False
    try:
        submit_locator.click(
            timeout=1500,
            delay=random.randint(30, 80),
            no_wait_after=True,
        )
        clicked = True
    except Exception:
        try:
            submit_locator.press("Enter", timeout=1000)
            clicked = True
        except Exception:
            clicked = False
    if emitter is not None:
        try:
            emitter.info(
                "浏览器模式2 create-account/password 已执行继续按钮提交。"
                + ("" if clicked else " 点击失败。"),
                step=step,
            )
        except Exception:
            pass
    if not clicked:
        return {"ok": "", "submitted": "", "reason": "submit_click_failed"}
    # 跳转、错误页和短信页由外层过渡观察器统一处理；这里不再重复读正文/扫描 frame。
    # 这样点击成功后立即把控制权交回主循环，避免密码页收尾额外等待数秒。
    return {"ok": "true", "submitted": "true", "reason": "submitted"}


def _fill_otp(page: Any, code: str) -> bool:
    otp = str(code or "").strip()
    if not otp:
        return False
    detected = {"mode": "", "input": None}
    for _ in range(10):
        detected = _detect_otp_inputs(page)
        if detected.get("mode"):
            break
        _sleep_with_page(page, 300)
    mode = detected.get("mode")
    if mode == "segmented":
        inputs = detected.get("inputs") or []
        if len(inputs) < 6:
            return False
        try:
            for index, digit in enumerate(otp[:6]):
                if not _write_text_to_locator(inputs[index], digit):
                    raise RuntimeError(f"otp segmented input[{index}] write failed")
            return True
        except Exception:
            try:
                first_input = inputs[0]
                first_input.click(timeout=1200)
                page.keyboard.type(otp[:6], delay=60)
                return True
            except Exception:
                return False
    if mode == "single":
        item = detected.get("input")
        if item is None:
            return False
        if _write_text_to_locator(item, otp):
            return True
        try:
            item.click(timeout=1200)
            page.keyboard.type(otp, delay=60)
            return True
        except Exception:
            return False
    return False


def _wait_and_fill_otp(page: Any, code: str, *, timeout_seconds: float = 8.0) -> bool:
    if page is not None:
        try:
            url_now = str(getattr(page, "url", "") or "")
        except Exception:
            url_now = ""
        if "about-you" in url_now.lower() or _is_profile_page(url_now, _get_body_text(page), page):
            return False
    deadline = time.time() + max(1.0, float(timeout_seconds or 0))
    tried_without_controls = False
    while time.time() < deadline:
        detected = _detect_otp_inputs(page)
        if detected.get("mode"):
            if _fill_otp(page, code):
                return True
        else:
            tried_without_controls = True
        try:
            _wait_for_load(page, timeout_ms=800)
        except Exception:
            pass
        _sleep_with_page(page, 350)

    if tried_without_controls:
        try:
            page.keyboard.press("Tab")
        except Exception:
            pass
        _sleep_with_page(page, 250)
        if _fill_otp(page, code):
            return True
    return False


def _otp_controls_match_code(page: Any, code: str) -> bool:
    otp = str(code or "").strip()
    if not otp:
        return False
    detected = _detect_otp_inputs(page)
    mode = str(detected.get("mode") or "").strip()
    if mode == "single":
        value = _locator_value(detected.get("input"))
        digits = "".join(ch for ch in value if ch.isdigit())
        return digits == "".join(ch for ch in otp if ch.isdigit())
    if mode == "segmented":
        inputs = detected.get("inputs") or []
        if len(inputs) < 6:
            return False
        digits = "".join(_locator_value(item)[:1] for item in inputs[:6])
        return digits == otp[:6]
    return False


def _submit_email_otp_via_page_api(page: Any, code: str) -> Dict[str, Any]:
    otp = str(code or "").strip()
    if not otp:
        return {"ok": False, "status": 0, "text": "", "json": {}}
    try:
        result = page.evaluate(
            """async (payload) => {
                const resp = await fetch("/api/accounts/email-otp/validate", {
                    method: "POST",
                    credentials: "include",
                    headers: {
                        "content-type": "application/json",
                        "accept": "application/json, text/plain, */*"
                    },
                    body: JSON.stringify({ code: payload.code }),
                });
                const text = await resp.text();
                let parsed = {};
                try { parsed = JSON.parse(text || "{}"); } catch (_err) {}
                return {
                    ok: !!resp.ok,
                    status: Number(resp.status || 0),
                    text: String(text || ""),
                    json: parsed || {},
                };
            }""",
            {"code": otp},
        )
    except Exception as exc:
        return {"ok": False, "status": 0, "text": str(exc), "json": {}}
    if isinstance(result, dict):
        return result
    return {"ok": False, "status": 0, "text": str(result or ""), "json": {}}


def _manual_v2_authorize_continue_via_page_api(page: Any, email: str) -> Dict[str, Any]:
    username = str(email or "").strip()
    if not username:
        return {"ok": False, "status": 0, "text": "missing email", "json": {}}
    try:
        result = page.evaluate(
            """async (payload) => {
                const resp = await fetch("/api/accounts/authorize/continue", {
                    method: "POST",
                    credentials: "include",
                    headers: {
                        "content-type": "application/json",
                        "accept": "application/json, text/plain, */*"
                    },
                    body: JSON.stringify({
                        username: {
                            kind: "email",
                            value: payload.email
                        }
                    }),
                });
                const text = await resp.text();
                let parsed = {};
                try { parsed = JSON.parse(text || "{}"); } catch (_err) {}
                return {
                    ok: !!resp.ok,
                    status: Number(resp.status || 0),
                    text: String(text || ""),
                    json: parsed || {},
                };
            }""",
            {"email": username},
        )
    except Exception as exc:
        return {"ok": False, "status": 0, "text": str(exc), "json": {}}
    if isinstance(result, dict):
        return result
    return {"ok": False, "status": 0, "text": str(result or ""), "json": {}}


def _manual_v2_password_verify_via_page_api(page: Any, password: str) -> Dict[str, Any]:
    pwd = str(password or "").strip()
    if not pwd:
        return {"ok": False, "status": 0, "text": "missing password", "json": {}}
    try:
        result = page.evaluate(
            """async (payload) => {
                const resp = await fetch("/api/accounts/password/verify", {
                    method: "POST",
                    credentials: "include",
                    headers: {
                        "content-type": "application/json",
                        "accept": "application/json, text/plain, */*"
                    },
                    body: JSON.stringify({ password: payload.password }),
                });
                const text = await resp.text();
                let parsed = {};
                try { parsed = JSON.parse(text || "{}"); } catch (_err) {}
                return {
                    ok: !!resp.ok,
                    status: Number(resp.status || 0),
                    text: String(text || ""),
                    json: parsed || {},
                };
            }""",
            {"password": pwd},
        )
    except Exception as exc:
        return {"ok": False, "status": 0, "text": str(exc), "json": {}}
    if isinstance(result, dict):
        return result
    return {"ok": False, "status": 0, "text": str(result or ""), "json": {}}


def _fill_birthdate(page: Any, birthdate: str) -> bool:
    birth = str(birthdate or "").strip()
    if not birth or len(birth.split("-")) != 3:
        return False
    year, month, day = birth.split("-")

    if _fill_first(
        page,
        [
            'input[type="date"]',
            'input[name*="birth" i]',
            'input[placeholder*="YYYY" i]',
        ],
        birth,
    ):
        return True

    month_values = []
    for value in [str(int(month)), month, _month_name(int(month)), _month_name(int(month), short=True)]:
        if value and value not in month_values:
            month_values.append(value)
    day_values = [str(int(day)), day]
    year_values = [year]
    _sleep_with_page(page, 200)

    birthdate_controls = _collect_visible_locators(
        page,
        [
            'select',
            '[role="combobox"]',
            '[role="spinbutton"][contenteditable="true"]',
            '[role="spinbutton"]',
            'button[aria-haspopup="listbox"]',
            'button[aria-label*="month" i]',
            'button[aria-label*="day" i]',
            'button[aria-label*="year" i]',
            'button:has-text("Month")',
            'button:has-text("Day")',
            'button:has-text("Year")',
            'input[name*="birth" i]',
            'input[name*="date" i]',
            'input[name*="month" i]',
            'input[name*="day" i]',
            'input[name*="year" i]',
            'input[aria-label*="birth" i]',
            'input[aria-label*="month" i]',
            'input[aria-label*="day" i]',
            'input[aria-label*="year" i]',
            'input[placeholder*="month" i]',
            'input[placeholder*="day" i]',
            'input[placeholder*="year" i]',
        ],
        limit=12,
    )

    if _fill_birthdate_spinbuttons(page, year, month, day):
        return True

    explicit_month = next((item for item in birthdate_controls if _locator_matches_hints(item, ["month", "mm", "jan", "feb", "月"])), None)
    explicit_day = next((item for item in birthdate_controls if _locator_matches_hints(item, ["day", "dd", "日"])), None)
    explicit_year = next((item for item in birthdate_controls if _locator_matches_hints(item, ["year", "yyyy", "yy", "年"])), None)
    if explicit_month is not None and explicit_day is not None and explicit_year is not None:
        if (
            _apply_candidates_to_locator(page, explicit_month, month_values)
            and _apply_candidates_to_locator(page, explicit_day, day_values)
            and _apply_candidates_to_locator(page, explicit_year, year_values)
        ):
            return True

    visible_dropdowns = _collect_visible_locators(
        page,
        [
            'select',
            '[role="combobox"]',
            '[role="spinbutton"][contenteditable="true"]',
            'button[aria-haspopup="listbox"]',
        ],
        limit=6,
    )
    dropdown_orders = [
        (0, 1, 2),
        (1, 0, 2),
        (0, 2, 1),
        (2, 0, 1),
    ]
    if len(visible_dropdowns) >= 3:
        for month_idx, day_idx, year_idx in dropdown_orders:
            if max(month_idx, day_idx, year_idx) >= len(visible_dropdowns):
                continue
            if (
                _choose_first_supported_option(page, visible_dropdowns[month_idx], month_values)
                and _choose_first_supported_option(page, visible_dropdowns[day_idx], day_values)
                and _choose_first_supported_option(page, visible_dropdowns[year_idx], year_values)
            ):
                return True

    filled = 0
    if _fill_first(page, ['input[name*="month" i]', 'input[placeholder*="MM" i]'], month):
        filled += 1
    if _fill_first(page, ['input[name*="day" i]', 'input[placeholder*="DD" i]'], day):
        filled += 1
    if _fill_first(page, ['input[name*="year" i]', 'input[placeholder*="YYYY" i]'], year):
        filled += 1
    return filled >= 2


def _derive_profile_age(birthdate: str) -> str:
    birth = str(birthdate or "").strip()
    try:
        year, month, day = [int(part) for part in birth.split("-")]
        today = datetime.now()
        age = int(today.year) - year
        if (today.month, today.day) < (month, day):
            age -= 1
    except Exception:
        age = 26
    age = max(18, min(age, 60))
    return str(age)


def _fill_age(page: Any, birthdate: str) -> bool:
    age_value = _derive_profile_age(birthdate)
    if _fill_input_by_label(page, ["年龄", "age", "your age"], age_value):
        return True
    if _fill_first(
        page,
        [
            'input[name="age"]',
            'input[placeholder="Age"]',
            'input[type="number"][name="age"]',
            'input[inputmode="numeric"][name="age"]',
            'input[name*="age" i]',
            'input[id*="-age" i]',
            'input[id*="age" i]',
            'input[placeholder*="age" i]',
            'input[aria-label*="age" i]',
            'input[placeholder*="年龄"]',
            'input[aria-label*="年龄"]',
            'input[name*="年龄"]',
            'input[type="number"]',
        ],
        age_value,
    ):
        return True

    candidates = _collect_visible_locators(
        page,
        [
            'input[type="number"]',
            'input[inputmode="numeric"]',
            'input[type="text"]',
            '[role="spinbutton"]',
            '[role="textbox"]',
        ],
        limit=12,
    )
    for locator in candidates:
        if _locator_matches_hints(locator, ["age", "年龄", "your age", "confirm your age"]):
            if _write_text_to_locator(locator, age_value):
                return True
    return False


def _has_about_you_birthdate_controls(page: Any) -> bool:
    controls = _collect_visible_locators(
        page,
        [
            'input[type="date"]',
            'input[name*="birth" i]',
            'input[name*="date" i]',
            'input[name*="month" i]',
            'input[name*="day" i]',
            'input[name*="year" i]',
            'input[aria-label*="birth" i]',
            'input[aria-label*="month" i]',
            'input[aria-label*="day" i]',
            'input[aria-label*="year" i]',
            'select',
            '[role="combobox"]',
            '[role="spinbutton"][contenteditable="true"]',
            '[role="spinbutton"]',
            'button[aria-haspopup="listbox"]',
        ],
        limit=12,
    )
    if not controls:
        return False
    segments: set[str] = set()
    for item in controls:
        segment = _identify_birthdate_segment(item)
        if segment:
            segments.add(segment)
    if len(segments) >= 3:
        return True
    month_like = any(_locator_matches_hints(item, ["month", "mm", "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec", "月"]) for item in controls)
    day_like = any(_locator_matches_hints(item, ["day", "dd", "日"]) for item in controls)
    year_like = any(_locator_matches_hints(item, ["year", "yyyy", "yy", "年"]) for item in controls)
    return month_like and day_like and year_like


def _is_locator_checked(locator: Any) -> bool:
    if locator is None:
        return False
    try:
        return bool(
            locator.evaluate(
                """(el) => {
                    if ('checked' in el) return !!el.checked;
                    return el.getAttribute('aria-checked') === 'true';
                }"""
            )
        )
    except Exception:
        return False


def _ensure_about_you_checkbox(page: Any) -> bool:
    checkbox = _first_visible_locator(
        page,
        [
            'input[type="checkbox"][name="allCheckboxes"]',
            'input[type="checkbox"][id*="allcheckboxes" i]',
            'input[type="checkbox"][name*="agree" i]',
            'input[type="checkbox"][id*="agree" i]',
        ],
    )
    if checkbox is None:
        candidates = _collect_visible_locators(page, ['input[type="checkbox"]'], limit=4)
        if len(candidates) == 1:
            checkbox = candidates[0]
    if checkbox is None:
        return True
    if _is_locator_checked(checkbox):
        return True

    try:
        checkbox.check(timeout=1200)
    except Exception:
        pass
    if _is_locator_checked(checkbox):
        return True

    checkbox_id = ""
    try:
        checkbox_id = str(checkbox.get_attribute("id") or "").strip()
    except Exception:
        checkbox_id = ""
    if checkbox_id and _click_first(page, [f'label[for="{checkbox_id}"]'], timeout_ms=1200):
        return _is_locator_checked(checkbox)

    if _click_locator_human_like(page, checkbox, timeout_ms=1200):
        return _is_locator_checked(checkbox)
    return False


def _summarize_about_you_controls(page: Any) -> str:
    controls = _collect_visible_locators(
        page,
        [
            'input',
            'select',
            '[role="textbox"]',
            '[role="spinbutton"]',
            'button',
            'label',
        ],
        limit=16,
    )
    snippets: list[str] = []
    for item in controls:
        meta = _locator_metadata(item)
        if not meta:
            continue
        haystack = " ".join(meta.values())
        if not any(
            token in haystack
            for token in ("month", "day", "year", "birth", "date", "dob", "age", "年龄", "checkbox", "agree", "同意")
        ):
            continue
        checked = ""
        try:
            checked = "checked=true" if _is_locator_checked(item) else "checked=false"
        except Exception:
            checked = ""
        snippets.append(
            "|".join(
                part
                for part in (
                    f"tag={meta.get('tag', '-')}",
                    f"type={meta.get('type', '-')}",
                    f"role={meta.get('role', '-')}",
                    f"name={meta.get('name', '-')}",
                    f"id={meta.get('id', '-')}",
                    checked,
                    f"label={_preview_text(meta.get('labels', ''), 40)}",
                    f"aria={_preview_text(meta.get('aria_label', ''), 40)}",
                    f"aria_value={_preview_text(meta.get('aria_valuetext', '') or meta.get('aria_valuenow', ''), 40)}",
                    f"value={_preview_text(meta.get('value', '') or meta.get('nested_value', ''), 40)}",
                    f"text={_preview_text(meta.get('text', ''), 40)}",
                    f"parent={_preview_text(meta.get('parent_text', ''), 40)}",
                )
                if part
            )
        )
        if len(snippets) >= 8:
            break
    return " || ".join(snippets) if snippets else "未识别到明显的 about-you 控件元数据"


def _fill_about_you_profile(page: Any, ctx: Any) -> tuple[bool, str]:
    # 先清掉可能被 OTP 误填进 age 的脏值。
    age_locator = _first_visible_locator(
        page,
        [
            'input[name="age"]',
            'input[placeholder="Age"]',
            'input[placeholder*="Age" i]',
            'input[id*="-age" i]',
            'input[type="number"]',
        ],
    )
    if age_locator is not None:
        try:
            age_locator.fill("", timeout=800)
        except Exception:
            try:
                _write_text_to_locator(age_locator, "")
            except Exception:
                pass

    name_ok = (
        _fill_input_by_label(page, ["全名", "姓名", "full name", "name"], ctx.profile_name)
        or _fill_first(
            page,
            [
                'input[name="name"]',
                'input[autocomplete="name"]',
                'input[placeholder*="Full name" i]',
                'input[placeholder*="name" i]',
                'input[id*="-name" i]',
                'input[id*="name" i]',
                'input[type="text"]',
            ],
            ctx.profile_name,
        )
    )
    if not name_ok:
        return False, "name"
    # 回读姓名，避免“看起来点了但没写上”
    name_locator = _first_visible_locator(
        page,
        [
            'input[name="name"]',
            'input[autocomplete="name"]',
            'input[placeholder*="Full name" i]',
        ],
    )
    if name_locator is not None:
        typed_name = str(_locator_value(name_locator, timeout_ms=500) or "").strip()
        if not typed_name:
            if not _write_text_to_locator(name_locator, ctx.profile_name):
                return False, "name"

    body_text = _get_body_text(page)
    body_lower = str(body_text or "").lower()
    has_age_input = _first_visible_locator(
        page,
        [
            'input[name="age"]',
            'input[placeholder="Age"]',
            'input[placeholder*="Age" i]',
            'input[id*="-age" i]',
            'input[id*="age" i]',
            'input[inputmode="numeric"][name="age"]',
        ],
    ) is not None
    has_birthdate_controls = _has_about_you_birthdate_controls(page)
    prefers_age = (
        has_age_input
        or "confirm your age" in body_lower
        or "your age" in body_lower
        or " age " in f" {body_lower} "
        or "年龄" in body_text
    )
    # 同时有明确 age 输入框时，优先年龄，不强制生日下拉。
    if has_birthdate_controls and not has_age_input:
        prefers_age = False
    if prefers_age:
        if not _fill_age(page, ctx.profile_birthdate):
            if not _fill_birthdate(page, ctx.profile_birthdate):
                return False, "age"
    else:
        if not _fill_birthdate(page, ctx.profile_birthdate):
            if not _fill_age(page, ctx.profile_birthdate):
                return False, "birthdate"

    # 校验 age 是否是合理年龄，避免短信码被误填进去。
    if prefers_age:
        age_check = _first_visible_locator(
            page,
            [
                'input[name="age"]',
                'input[placeholder="Age"]',
                'input[placeholder*="Age" i]',
                'input[id*="-age" i]',
                'input[type="number"]',
            ],
        )
        if age_check is not None:
            age_value = str(_locator_value(age_check, timeout_ms=500) or "").strip()
            expected_age = _derive_profile_age(ctx.profile_birthdate)
            invalid_age = (not age_value.isdigit()) or int(age_value) < 5 or int(age_value) > 130 or len(age_value) >= 4
            if invalid_age or age_value != expected_age:
                if not _write_text_to_locator(age_check, expected_age):
                    if not _fill_age(page, ctx.profile_birthdate):
                        return False, "age"
                age_value = str(_locator_value(age_check, timeout_ms=500) or "").strip()
                if (not age_value.isdigit()) or int(age_value) < 5 or int(age_value) > 130:
                    return False, "age"

    # 新版 about-you 可能没有同意勾选；勾选失败不硬失败。
    if not _ensure_about_you_checkbox(page):
        # 若页面明确要求勾选再失败；否则放行提交按钮。
        if any(token in body_lower for token in ("i agree", "agree to", "terms", "同意", "勾选")):
            return False, "checkbox"
    return True, ("age" if prefers_age else "birthdate")


def _is_about_you_terms_soft_error(url: str, body_text: str, page: Any = None) -> bool:
    """
    about-you 红色提示：
    “We can't create your account due to our Terms of Use”
    实测直接再点一次 Finish creating account 经常就能过（无需重填），不当硬失败。
    """
    text = str(body_text or "")
    text_lower = text.lower()
    english_hints = (
        "we can't create your account due to our terms of use",
        "we cannot create your account due to our terms of use",
        "can't create your account due to our terms of use",
        "cannot create your account due to our terms of use",
        "due to our terms of use",
        "can't create your account due to our terms",
    )
    chinese_hints = (
        "由于我们的服务条款无法创建",
        "因服务条款无法创建",
        "根据服务条款无法创建你的账户",
        "根据服务条款无法创建您的账户",
    )
    if any(hint in text_lower for hint in english_hints):
        return True
    if any(hint in text for hint in chinese_hints):
        return True
    if page is None:
        return False
    raw_text = _get_body_raw_text(page)
    raw_lower = str(raw_text or "").lower()
    if any(hint in raw_lower for hint in english_hints):
        return True
    if any(hint in str(raw_text or "") for hint in chinese_hints):
        return True
    alert_text = _get_alert_text(page)
    alert_lower = alert_text.lower()
    if any(hint in alert_lower for hint in english_hints):
        return True
    if any(hint in alert_text for hint in chinese_hints):
        return True
    return False


def _click_about_you_finish_button(page: Any) -> bool:
    if page is None:
        return False
    if _click_exact_action_texts(
        page,
        [
            "Finish creating account",
            "完成帐户创建",
            "完成账户创建",
            "Create account",
            "Continue",
            "Next",
            "完成",
            "继续",
        ],
        allow_generic_submit=False,
        timeout_ms=1500,
    ):
        return True
    if _click_primary_action(
        page,
        [
            "Finish creating account",
            "完成帐户创建",
            "完成账户创建",
            "Create account",
            "Continue",
            "Next",
            "完成",
            "继续",
        ],
        allow_generic_fallback=True,
    ):
        return True
    return _click_first(
        page,
        [
            'button[data-dd-action-name="Continue"]',
            'button[data-dd-action-name="Finish creating account"]',
            'button[type="submit"]:has-text("Finish creating account")',
            'button:has-text("Finish creating account")',
            '[role="button"]:has-text("Finish creating account")',
            'button[type="submit"]',
        ],
        timeout_ms=1500,
    )


def _about_you_form_still_visible(url: str, body_text: str, page: Any = None) -> bool:
    if _is_youre_all_set_page(url, body_text, page):
        return False
    if _is_about_you_missing_email_error(url, body_text):
        return False
    url_lower = str(url or "").lower()
    if "about-you" in url_lower:
        return True
    if _is_profile_page(url, body_text, page):
        return True
    return bool(page is not None and _has_visible_about_you_controls(page))


def _submit_about_you_finish_with_terms_retry(
    page: Any,
    ctx: Any = None,
    *,
    max_attempts: int = 3,
    settle_ms: int = 1600,
) -> Dict[str, Any]:
    """
    提交 about-you。
    若出现 Terms of Use 红色软错误，只再点 Finish，不重填资料（字段本来就在，重点即可）。
    返回:
      ok: 是否已离开表单页（或进入 You're all set / missing_email）
      url/body: 最新页面
      attempts: 实际点击次数
      terms_retried: 是否因 Terms 软错误重试过
    """
    result: Dict[str, Any] = {
        "ok": False,
        "url": "",
        "body": "",
        "attempts": 0,
        "terms_retried": False,
        "clicked": False,
    }
    if page is None:
        return result
    last_url, last_body = _describe_page(page, force_refresh=True)
    deep_body = _get_page_deep_text(page)
    if str(deep_body or "").strip():
        last_body = deep_body
    result["url"] = last_url
    result["body"] = last_body
    attempts = max(1, int(max_attempts or 1))
    for attempt in range(1, attempts + 1):
        result["attempts"] = attempt
        # 重试只点按钮，绝不重填姓名/年龄。
        if attempt > 1:
            _sleep_with_page(page, 250)
        if not _click_about_you_finish_button(page):
            continue
        result["clicked"] = True
        _wait_for_load(page, timeout_ms=1500)
        _sleep_with_page(page, max(300, int(settle_ms or 0)))
        last_url, last_body = _describe_page(page, force_refresh=True)
        deep_body = _get_page_deep_text(page)
        if str(deep_body or "").strip():
            last_body = deep_body
        result["url"] = last_url
        result["body"] = last_body
        if _is_youre_all_set_page(last_url, last_body, page) or _is_about_you_missing_email_error(last_url, last_body):
            result["ok"] = True
            return result
        if not _about_you_form_still_visible(last_url, last_body, page):
            result["ok"] = True
            return result
        if _is_about_you_terms_soft_error(last_url, last_body, page):
            result["terms_retried"] = True
            # 红色 Terms：资料已在，直接再点 Finish。
            continue
        # 仍停在 about-you 但没有明确 Terms 文案，也再点一次（偶发提交未生效）。
        if attempt < attempts:
            continue
    result["ok"] = not _about_you_form_still_visible(result["url"], result["body"], page)
    if _is_youre_all_set_page(result["url"], result["body"], page) or _is_about_you_missing_email_error(result["url"], result["body"]):
        result["ok"] = True
    return result


def _summarize_birthdate_controls(page: Any) -> str:
    controls = _collect_visible_locators(
        page,
        [
            'select',
            '[role="combobox"]',
            '[role="spinbutton"]',
            'button',
            'input',
        ],
        limit=12,
    )
    snippets: list[str] = []
    for item in controls:
        meta = _locator_metadata(item)
        if not meta:
            continue
        if not any(
            token in " ".join(meta.values())
            for token in ("month", "day", "year", "birth", "date", "dob")
        ):
            continue
        snippets.append(
            "|".join(
                part
                for part in (
                    f"tag={meta.get('tag', '-')}",
                    f"role={meta.get('role', '-')}",
                    f"name={meta.get('name', '-')}",
                    f"id={meta.get('id', '-')}",
                    f"label={_preview_text(meta.get('labels', ''), 40)}",
                    f"aria={_preview_text(meta.get('aria_label', ''), 40)}",
                    f"aria_value={_preview_text(meta.get('aria_valuetext', '') or meta.get('aria_valuenow', ''), 40)}",
                    f"value={_preview_text(meta.get('value', '') or meta.get('nested_value', ''), 40)}",
                    f"text={_preview_text(meta.get('text', ''), 40)}",
                    f"parent={_preview_text(meta.get('parent_text', ''), 40)}",
                )
                if part
            )
        )
        if len(snippets) >= 6:
            break
    return " || ".join(snippets) if snippets else _summarize_about_you_controls(page)


def _month_name(month: int, short: bool = False) -> str:
    names = [
        "",
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    if month < 1 or month > 12:
        return ""
    if short:
        return names[month][:3]
    return names[month]
def _wait_for_mail_otp(
    ctx: BrowserRunContext,
    *,
    timeout_seconds: int,
) -> str:
    if ctx.mail_provider is not None:
        try:
            return str(
                ctx.mail_provider.wait_for_otp(
                    ctx.dev_token,
                    ctx.email,
                    proxy=ctx.proxy,
                    stop_event=ctx.stop_event,
                    timeout=timeout_seconds,
                )
                or ""
            ).strip()
        except TypeError:
            return str(
                ctx.mail_provider.wait_for_otp(
                    ctx.dev_token,
                    ctx.email,
                    proxy=ctx.proxy,
                    timeout=timeout_seconds,
                    stop_event=ctx.stop_event,
                    proxy_selector=None,
                )
                or ""
            ).strip()

    if ctx.fallback_wait_for_otp_func is None:
        return ""

    proxy_dict = {"http": ctx.proxy, "https": ctx.proxy} if ctx.proxy else None
    try:
        return str(
            ctx.fallback_wait_for_otp_func(
                ctx.dev_token,
                ctx.email,
                proxy_dict,
                ctx.emitter,
                ctx.stop_event,
                proxy_selector=None,
                timeout_seconds=timeout_seconds,
            )
            or ""
        ).strip()
    except TypeError:
        return str(
            ctx.fallback_wait_for_otp_func(
                ctx.dev_token,
                ctx.email,
                proxy_dict,
                ctx.emitter,
                ctx.stop_event,
                None,
            )
            or ""
        ).strip()


def _describe_page(page: Any, *, force_refresh: bool = False) -> tuple[str, str]:
    current_url = ""
    body_text = ""
    try:
        current_url = str(page.url or "").strip()
    except Exception:
        current_url = ""
    cache_key = id(page)
    now = time.time()
    if not force_refresh:
        with _PAGE_SNAPSHOT_CACHE_LOCK:
            cached_snapshot = _PAGE_SNAPSHOT_CACHE.get(cache_key)
        if cached_snapshot is not None:
            cached_at, cached_url, cached_body = cached_snapshot
            if cached_url == current_url and now - cached_at <= _PAGE_SNAPSHOT_CACHE_TTL_SECONDS:
                return cached_url, cached_body
    try:
        body_text = _get_body_text(page)
    except Exception:
        body_text = ""
    if len(body_text) > _PAGE_SNAPSHOT_MAX_BODY_CHARS:
        body_text = body_text[:_PAGE_SNAPSHOT_MAX_BODY_CHARS] + "\n[页面文本已截断]"
    with _PAGE_SNAPSHOT_CACHE_LOCK:
        _PAGE_SNAPSHOT_CACHE[cache_key] = (now, current_url, body_text)
    _prune_page_snapshot_cache()
    return current_url, body_text


def _collect_auth_frame_urls(page: Any) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for target in _iter_page_targets(page):
        url = _frame_url(target)
        if not url:
            continue
        key = url.lower()
        if key in seen:
            continue
        seen.add(key)
        urls.append(url)
    return urls


def _best_auth_target_url(page: Any) -> str:
    """在主文档与 iframe 中挑出优先级最高的 auth 业务 URL。"""
    best_url = ""
    best_score = -1
    for url in _collect_auth_frame_urls(page):
        score = _page_priority_from_url(url)
        if score > best_score:
            best_score = score
            best_url = url
    return best_url


def _promote_auth_target_if_needed(page: Any, *, timeout_ms: int = 12000) -> tuple[Any, str, str]:
    """若顶层仍是 chatgpt 壳，但 iframe/子 frame 已进入 auth 业务页，则提升到真实 URL。"""
    if page is None:
        return page, "", ""
    top_url = ""
    try:
        top_url = str(page.url or "").strip()
    except Exception:
        top_url = ""
    top_lower = top_url.lower()
    best_url = _best_auth_target_url(page)
    best_lower = str(best_url or "").lower()
    should_promote = bool(
        best_url
        and "auth.openai.com" in best_lower
        and (
            "chatgpt.com" in top_lower
            or not top_lower
            or top_lower.startswith("about:blank")
            or (
                "auth.openai.com" in top_lower
                and _page_priority_from_url(best_url) > _page_priority_from_url(top_url)
            )
        )
        and best_lower != top_lower
    )
    # 密码页/短信页通常仍在 auth iframe 中。此时所有控件探测都会遍历
    # _iter_page_targets，强制 page.goto() 只会同步等待同一页面再次加载。
    # 返回 iframe 的逻辑 URL 即可继续处理；资料页、OAuth 页仍保留顶层提升。
    iframe_fast_route = any(
        token in best_lower
        for token in (
            "/create-account/password",
            "/log-in/password",
            "contact-verification",
            "verify-phone",
            "phone-verification",
        )
    )
    top_fast_route = any(
        token in top_lower
        for token in (
            "/create-account/password",
            "/log-in/password",
            "contact-verification",
            "verify-phone",
            "phone-verification",
        )
    )
    if should_promote and not iframe_fast_route and any(
        token in best_lower
        for token in (
            "create-account/password",
            "auth_challenge",
            "log-in/password",
            "contact-verification",
            "email-verification",
            "about-you",
            "reset-password",
            "add-phone",
            "add-email",
        )
    ):
        try:
            page.goto(best_url, wait_until="domcontentloaded", timeout=max(3000, int(timeout_ms or 0)))
        except Exception:
            try:
                page.goto(best_url, wait_until="commit", timeout=max(3000, int(timeout_ms or 0)))
            except Exception:
                pass
        try:
            page.wait_for_timeout(500)
        except Exception:
            pass
    # about-you 已提升到顶层时不再深读全文：控件探测走 frame 遍历即可，省去每次深读的几秒。
    about_you_promoted = (
        "about-you" in best_lower
        and "about-you" in top_lower
    )
    if (iframe_fast_route and (should_promote or top_fast_route)) or (top_fast_route and not best_url) or about_you_promoted:
        # URL 已足够判定密码/短信阶段；调用方会从 frame 查控件，正文留给需要时再读。
        return page, (best_url if iframe_fast_route else top_url), ""
    current_url, body_text = _describe_page(page, force_refresh=True)
    deep_body = _get_page_deep_text(page)
    if str(deep_body or "").strip():
        body_text = str(deep_body or "")
    # 若仍在 chatgpt 壳，但 deep text / frame 已能确认密码页，用 best auth URL 作为逻辑 URL。
    current_lower = str(current_url or "").lower()
    if "chatgpt.com" in current_lower and best_url and "auth.openai.com" in best_lower:
        if any(
            token in best_lower
            for token in (
                "create-account/password",
                "auth_challenge",
                "log-in/password",
                "contact-verification",
                "about-you",
            )
        ) or _first_visible_locator(
            page,
            [
                'input[type="password"]',
                'input[name="password"]',
                'input[name="new-password"]',
                'input[autocomplete="new-password"]',
            ],
        ) is not None:
            current_url = best_url
    return page, current_url, body_text


def _page_priority_from_url(url: str) -> int:
    url_lower = str(url or "").strip().lower()
    if not url_lower:
        return 0
    if "code=" in url_lower and "state=" in url_lower:
        return 200
    if "auth.openai.com" in url_lower:
        if any(token in url_lower for token in ("consent", "workspace", "organization")):
            return 190
        if "email-verification" in url_lower:
            return 185
        if "add-email" in url_lower:
            return 180
        if "contact-verification" in url_lower:
            return 178
        if "/log-in/password" in url_lower:
            return 175
        if "/reset-password/new-password" in url_lower:
            return 174
        if "about-you" in url_lower:
            return 173
        if "/create-account/password" in url_lower:
            return 172
        if "/reset-password" in url_lower:
            return 166
        if "auth_challenge" in url_lower or "passkey" in url_lower:
            return 176
        if "/log-in" in url_lower:
            return 162
        if "/create-account" in url_lower:
            return 160
        return 150
    if "chatgpt.com/auth/login_with" in url_lower:
        return 120
    if "chatgpt.com" in url_lower:
        return 40
    return 10


def _has_phone_input(page: Any) -> bool:
    return _first_visible_locator(
        page,
        [
            'input[id="phoneNumberInput"]',
            'input[name="phoneNumberInput"]',
            'input[type="tel"]',
            'input[inputmode="tel"]',
            'input[name*="phone" i]',
            'input[autocomplete="tel"]',
            'input[placeholder*="phone" i]',
            'input[aria-label*="phone" i]',
            'input[placeholder*="手机号"]',
            'input[aria-label*="手机号"]',
        ],
    ) is not None


def _is_phone_verification_page(url: str, body_text: str, page: Any = None) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "/create-account/password" in url_lower:
        return False
    if "contact-verification" in url_lower:
        return False
    has_phone_input = _has_phone_input(page) if page is not None else False
    return bool(
        "add-phone" in url_lower
        or (has_phone_input and "phone number" in body_lower)
        or (has_phone_input and "enter your phone number" in body_lower)
        or (has_phone_input and "use phone instead" in body_lower)
    )


def _is_phone_flow_page(url: str, body_text: str) -> bool:
    """检测整个手机验证流程（手机号输入页 + 手机验证码页）"""
    if _is_phone_verification_page(url, body_text):
        return True
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    return bool(
        "verify-phone" in url_lower
        or "phone-verification" in url_lower
        or "phone_verification" in url_lower
        or "contact-verification" in url_lower
        or "sent to your phone" in body_lower
        or "sent a code to" in body_lower
        or ("enter the code" in body_lower and "phone" in body_lower)
        or ("verification code" in body_lower and "phone" in body_lower)
        or ("verify" in body_lower and "sms" in body_lower)
        or "whatsapp" in body_lower
        or "resend whatsapp message" in body_lower
    )


def _is_contact_verification_page(url: str, body_text: str, page: Any) -> bool:
    """仅识别“已发短信后的手机验证码页”，避免 ChatGPT 首页营销文案误判。"""
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    body_text_value = str(body_text or "")

    # URL 已明确是手机 contact-verification，直接认定（优先级最高，避免被后续邮箱文案误杀）。
    if (
        "contact-verification" in url_lower
        or "verify-phone" in url_lower
        or "phone-verification" in url_lower
        or "phone_verification" in url_lower
    ):
        return True

    # 邮箱验证码页/补邮箱页绝不能当成手机短信验证码页。
    if "email-verification" in url_lower or "add-email" in url_lower or "email-otp" in url_lower:
        return False
    if any(
        token in body_lower
        for token in (
            "check your inbox",
            "resend email",
            "verify your email",
            "email address",
            "verification code we just sent to",
            "we just sent to",
        )
    ) and ("@" in body_text_value or "email" in body_lower) and not any(
        token in body_lower
        for token in (
            "verify your phone",
            "sent to your phone",
            "resend whatsapp",
            "短信验证码",
            "验证你的手机",
        )
    ):
        return False

    # about-you 资料页优先，绝不回流到短信验证码处理。
    if "about-you" in url_lower:
        return False
    if any(
        token in body_lower
        for token in (
            "how old are you",
            "finish creating account",
            "please enter name to continue",
            "enter a valid age",
            "full name",
        )
    ) and "verification code" not in body_lower:
        return False
    if page is not None and _first_visible_locator(
        page,
        [
            'input[name="name"]',
            'input[name="age"]',
            'input[placeholder="Age"]',
            'input[placeholder*="Full name" i]',
            'button:has-text("Finish creating account")',
        ],
    ) is not None:
        return False

    # 首页/桥接壳绝不算短信验证码页。
    if "chatgpt.com" in url_lower and "auth.openai.com" not in url_lower:
        if "contact-verification" not in url_lower and "verify-phone" not in url_lower:
            return False
    if "chatgpt.com/auth/login_with" in url_lower:
        return False
    # 密码/passkey 明确页不算短信验证码页（避免与其他判定互相递归）。
    if "/create-account/password" in url_lower or "/log-in/password" in url_lower:
        return False
    if "auth_challenge/passkey" in url_lower:
        return False
    if _has_phone_input(page) and "contact-verification" not in url_lower and "verify-phone" not in url_lower:
        # 还在输入手机号阶段，不算验证码页。
        # 但 contact-verification URL 可能同时有残留 phone 输入，故 URL 命中时放行。
        body_suggests_otp = any(
            token in body_lower
            for token in (
                "verify your phone",
                "sent a code",
                "enter the code",
                "verification code",
                "短信验证码",
            )
        )
        if not body_suggests_otp:
            return False

    url_hit = bool(
        "contact-verification" in url_lower
        or "verify-phone" in url_lower
        or "phone-verification" in url_lower
        or "phone_verification" in url_lower
    )
    # 注意：不要用“sent a code / we sent a code”这类邮箱页也会出现的泛化文案。
    strong_text_hit = bool(
        "verify your phone" in body_lower
        or "contact verification" in body_lower
        or "resend whatsapp message" in body_lower
        or "sent to your phone" in body_lower
        or "sent a code to your phone" in body_lower
        or ("sent a code to" in body_lower and ("phone" in body_lower or "sms" in body_lower or "whatsapp" in body_lower))
        or ("we sent a code" in body_lower and ("phone" in body_lower or "sms" in body_lower or "whatsapp" in body_lower))
        or ("enter the code" in body_lower and ("phone" in body_lower or "sms" in body_lower or "whatsapp" in body_lower))
        or "验证你的手机" in body_text_value
        or "短信验证码" in body_text_value
    )
    # 单独出现 whatsapp / phone 等营销词不够。
    if (
        "whatsapp" in body_lower
        and not strong_text_hit
        and not url_hit
        and "verify" not in body_lower
        and "code" not in body_lower
    ):
        return False

    phone_otp_input = _first_visible_locator(
        page,
        [
            'input[name="code"]',
            'input[id*="-code" i]',
            'input[placeholder="Code"]',
            'input[placeholder*="code" i]',
            'input[inputmode="numeric"]',
            'input[autocomplete="one-time-code"]',
            'input[name*="otp" i]',
        ],
    )
    if url_hit:
        return True
    if strong_text_hit and phone_otp_input is not None:
        return True
    if strong_text_hit and "auth.openai.com" in url_lower:
        return True
    return bool(
        phone_otp_input is not None
        and ("phone" in body_lower or "sms" in body_lower or "whatsapp" in body_lower)
        and ("code" in body_lower or "verification" in body_lower or "验证" in body_text_value)
        and "auth.openai.com" in url_lower
    )



def _is_phone_login_entry_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "auth.openai.com/log-in" not in url_lower:
        return False
    if "continue with phone" in body_lower or "继续使用手机登录" in body_text:
        return True
    return _first_visible_locator(
        page,
        [
            'button:has-text("Continue with phone")',
            '[role="button"]:has-text("Continue with phone")',
            'button:has-text("继续使用手机登录")',
            '[role="button"]:has-text("继续使用手机登录")',
        ],
    ) is not None


def _is_choose_account_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "choose-an-account" in url_lower:
        return True
    if "choose an account" not in body_lower:
        return False
    return _first_visible_locator(
        page,
        [
            'button:has-text("Use another account")',
            '[role="button"]:has-text("Use another account")',
            'button:has-text("使用其他账号")',
            '[role="button"]:has-text("使用其他账号")',
            '[role="listitem"]',
            '[data-testid*="account" i]',
        ],
    ) is not None


def _click_choose_account_phone_card(page: Any, phone_number: str) -> Dict[str, str]:
    phone_text = str(phone_number or "").strip()
    if page is None or not phone_text:
        return {"clicked": "", "matched_text": "", "reason": "missing_phone"}
    digits = "".join(ch for ch in phone_text if ch.isdigit())
    tail_digits = digits[-8:] if len(digits) >= 8 else digits
    if not tail_digits:
        return {"clicked": "", "matched_text": "", "reason": "missing_digits"}

    previous_url = ""
    try:
        previous_url = str(page.url or "").strip()
    except Exception:
        previous_url = ""

    try:
        text_nodes = page.locator("span, div, p, button, a, [role=\"button\"], [role=\"listitem\"]")
    except Exception:
        text_nodes = None

    matched_text = ""
    found_candidate = False
    for index in range(60):
        try:
            item = text_nodes.nth(index)
            if not item.is_visible(timeout=300):
                if index == 0:
                    break
                continue
            raw_text = str(item.inner_text(timeout=300) or "").strip()
        except Exception:
            continue
        node_digits = "".join(ch for ch in raw_text if ch.isdigit())
        if not node_digits or not node_digits.endswith(tail_digits):
            continue
        found_candidate = True
        matched_text = raw_text
        candidate_selectors = [
            "xpath=ancestor-or-self::*[@role='listitem'][1]",
            "xpath=ancestor-or-self::button[1]",
            "xpath=ancestor-or-self::*[@role='button'][1]",
            "xpath=ancestor-or-self::a[1]",
            "xpath=ancestor-or-self::li[1]",
            "xpath=ancestor-or-self::div[@data-testid][1]",
            "xpath=ancestor-or-self::div[1]",
        ]
        for selector in candidate_selectors:
            try:
                candidate = item.locator(selector).first
                if not candidate.is_visible(timeout=300):
                    continue
            except Exception:
                continue
            if _activate_choose_account_candidate(page, candidate, previous_url, timeout_ms=1800):
                return {"clicked": "true", "matched_text": matched_text, "reason": "matched_phone_card"}
        break

    if found_candidate:
        return {"clicked": "", "matched_text": matched_text, "reason": "candidate_not_clickable"}
    return {"clicked": "", "matched_text": "", "reason": "no_candidate"}


def _is_create_account_password_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    # 绝不能把 Google/Microsoft/Apple 登录密码页当成 create-account/password。
    if any(
        domain in url_lower
        for domain in (
            "accounts.google.com",
            "login.microsoftonline.com",
            "appleid.apple.com",
            "login.live.com",
        )
    ):
        return False
    if page is not None:
        for frame_url in _collect_auth_frame_urls(page):
            frame_lower = str(frame_url or "").lower()
            if "/create-account/password" in frame_lower:
                url_lower = frame_lower
                break
    if _is_retryable_error_page(url, body_text) or _is_create_account_failed_error(url, body_text, page):
        return False
    if "/reset-password/new-password" in url_lower:
        return False
    if _is_contact_verification_page(url, body_text, page):
        return False
    if "/create-account/password" in url_lower:
        body_lower = str(body_text or "").lower()
        if (
            "verify your phone" in body_lower
            or "contact verification" in body_lower
            or "sent to your phone" in body_lower
            or "sent a code to" in body_lower
            or ("verification code" in body_lower and "phone" in body_lower)
            or ("enter the code" in body_lower and "phone" in body_lower)
            or ("verify" in body_lower and "sms" in body_lower)
            or "whatsapp" in body_lower
            or "resend whatsapp message" in body_lower
        ):
            return False
        if _first_visible_locator(
            page,
            [
                'input[name="code"]',
                'input[id*="-code" i]',
                'input[placeholder="Code"]',
                'input[placeholder*="code" i]',
                'input[inputmode="numeric"]',
                'input[autocomplete="one-time-code"]',
                'input[name*="code" i]',
                'input[name*="otp" i]',
            ],
        ) is not None:
            return False
        return True
    if "new-password" in url_lower and "reset-password" not in url_lower:
        return True
    password_input = _first_visible_locator(
        page,
        [
            'input[name="new-password"]',
            'input[autocomplete="new-password"]',
            'input[id*="new-password" i]',
        ],
    )
    confirm_password_input = _first_visible_locator(
        page,
        [
            'input[name="confirm-password"]',
            'input[id*="confirm-password" i]',
            'input[placeholder*="Re-enter new password" i]',
        ],
    )
    if password_input is not None and confirm_password_input is not None:
        return False
    if password_input is not None:
        return True
    body_lower = str(body_text or "").lower()
    return "create password" in body_lower or "创建密码" in body_text


def _probe_submit_button_state(page: Any, preferred_texts: tuple[str, ...]) -> Dict[str, str]:
    """读取提交按钮状态；避免用无 timeout 的 DOM evaluate。"""
    candidates = _collect_visible_locators(
        page,
        ['button[type="submit"]', "button", 'input[type="submit"]', '[role="button"]'],
        limit=12,
    )
    preferred = tuple(str(item or "").strip().lower() for item in preferred_texts if str(item or "").strip())
    selected = None
    selected_text = ""
    for locator in candidates:
        try:
            text = str(locator.inner_text(timeout=300) or "").strip()
        except Exception:
            text = ""
        if not text:
            for attr_name in ("value", "aria-label"):
                try:
                    text = str(locator.get_attribute(attr_name, timeout=300) or "").strip()
                except Exception:
                    text = ""
                if text:
                    break
        normalized = text.lower()
        if selected is None:
            selected = locator
            selected_text = text
        if normalized and any(item == normalized or item in normalized for item in preferred):
            selected = locator
            selected_text = text
            break
    if selected is None:
        return {}

    def _attr(name: str) -> str:
        try:
            return str(selected.get_attribute(name, timeout=300) or "").strip().lower()
        except Exception:
            return ""

    disabled_attr = _attr("disabled")
    try:
        disabled = not bool(selected.is_enabled(timeout=300))
    except Exception:
        disabled = disabled_attr in {"disabled", "true"}
    return {
        "submit_found": "true",
        "submit_text": selected_text,
        "submit_disabled": "true" if disabled else "false",
        "submit_aria_disabled": _attr("aria-disabled"),
        "submit_busy": _attr("aria-busy"),
        "submit_state": _attr("data-state"),
    }


def _probe_create_account_password_page_state(
    page: Any,
    *,
    include_deep_text: bool = True,
    include_submit: bool = True,
) -> Dict[str, str]:
    current_url, body_text = _describe_page(page, force_refresh=True)
    if include_deep_text:
        deep_body_text = _get_page_deep_text(page)
        if str(deep_body_text or "").strip():
            body_text = deep_body_text
    info: Dict[str, str] = {
        "url": str(current_url or "").strip(),
        "state": _classify_page_state(current_url, body_text, page),
        "password_visible": "false",
        "password_disabled": "",
        "password_readonly": "",
        "submit_found": "false",
        "submit_text": "",
        "submit_disabled": "",
        "submit_aria_disabled": "",
        "submit_busy": "",
        "submit_state": "",
    }
    password_input = _first_visible_locator(
        page,
        [
            'input[type="password"]',
            'input[name="password"]',
            'input[name="new-password"]',
            'input[autocomplete="new-password"]',
            'input[id*="password" i]',
        ],
    )
    if password_input is not None:
        info["password_visible"] = "true"
        try:
            info["password_disabled"] = str(password_input.get_attribute("disabled") or "").strip().lower()
        except Exception:
            info["password_disabled"] = ""
        try:
            info["password_readonly"] = str(password_input.get_attribute("readonly") or "").strip().lower()
        except Exception:
            info["password_readonly"] = ""
    if include_submit:
        submit_info = _probe_submit_button_state(
            page,
            ("继续", "Continue", "Next", "Verify", "Submit", "Create account", "Sign up", "下一步", "创建账户", "注册"),
        )
        for key, value in submit_info.items():
            info[str(key)] = str(value or "").strip().lower() if key != "submit_text" else str(value or "").strip()
    return info


def _summarize_create_account_password_probe(page: Any) -> str:
    info = _probe_create_account_password_page_state(page)
    parts = [
        f"url={_mask_secret(info.get('url', ''), head=56, tail=12) if info.get('url') else '-'}",
        f"page_state={info.get('state') or '-'}",
        f"password_visible={info.get('password_visible') or '-'}",
        f"password_disabled={info.get('password_disabled') or '-'}",
        f"password_readonly={info.get('password_readonly') or '-'}",
        f"submit_found={info.get('submit_found') or '-'}",
        f"submit_text={_preview_text(info.get('submit_text', ''), 40) or '-'}",
        f"submit_disabled={info.get('submit_disabled') or '-'}",
        f"aria_disabled={info.get('submit_aria_disabled') or '-'}",
        f"submit_busy={info.get('submit_busy') or '-'}",
        f"submit_state={info.get('submit_state') or '-'}",
    ]
    return ", ".join(parts)


def _is_create_account_password_ready_for_submit(page: Any) -> bool:
    info = _probe_create_account_password_page_state(page)
    state = str(info.get("state") or "").strip().lower()
    password_visible = str(info.get("password_visible") or "").strip().lower() == "true"
    submit_found = str(info.get("submit_found") or "").strip().lower() == "true"
    if state not in {"password", "workspace"} and not (password_visible and submit_found):
        return False
    if not password_visible:
        return False
    if not submit_found:
        return False
    if str(info.get("submit_disabled") or "").strip().lower() in {"true", "disabled"}:
        return False
    if str(info.get("submit_aria_disabled") or "").strip().lower() == "true":
        return False
    if str(info.get("password_disabled") or "").strip().lower() in {"true", "disabled"}:
        return False
    if str(info.get("password_readonly") or "").strip().lower() in {"true", "readonly"}:
        return False
    return True


def _probe_add_email_page_state(page: Any) -> Dict[str, str]:
    info: Dict[str, str] = {"url": "", "state": "", "body": ""}
    try:
        current_url, body_text = _describe_page(page, force_refresh=True)
        info["url"] = current_url
        info["body"] = body_text
        info["state"] = _classify_page_state(current_url, body_text, page)
    except Exception:
        pass
    input_locator = _first_visible_locator(
        page,
        [
            'input[type="email"]',
            'input[name="email"]',
            'input[autocomplete="email"]',
            'input[id*="-email" i]',
            'input[placeholder*="email" i]',
            'input[placeholder*="mail" i]',
            'input[aria-label*="email" i]',
            'input[aria-label*="mail" i]',
        ],
    )
    if input_locator is not None:
        info["input_found"] = "true"
        info["input_meta"] = _summarize_locator_compact(input_locator)
        info["input_value"] = _locator_value(input_locator, timeout_ms=250)
        try:
            info["input_disabled"] = str(input_locator.get_attribute("disabled") or "").strip().lower()
        except Exception:
            info["input_disabled"] = ""
        try:
            info["input_readonly"] = str(input_locator.get_attribute("readonly") or "").strip().lower()
        except Exception:
            info["input_readonly"] = ""
        try:
            info["input_aria_disabled"] = str(input_locator.get_attribute("aria-disabled") or "").strip().lower()
        except Exception:
            info["input_aria_disabled"] = ""
    else:
        info["input_found"] = "false"
        info["input_meta"] = ""
        info["input_value"] = ""
        info["input_disabled"] = ""
        info["input_readonly"] = ""
        info["input_aria_disabled"] = ""

    submit_info = _probe_submit_button_state(
        page,
        ("continue", "next", "verify", "submit", "继续", "下一步", "验证"),
    )
    for key, value in submit_info.items():
        info[str(key)] = str(value or "").strip().lower() if key != "submit_text" else str(value or "").strip()
    return info


def _summarize_locator_compact(locator: Any) -> str:
    meta = _locator_metadata(locator)
    if not meta:
        return "-"
    return "|".join(
        part
        for part in (
            f"tag={meta.get('tag', '-')}",
            f"role={meta.get('role', '-')}",
            f"type={meta.get('type', '-')}",
            f"name={meta.get('name', '-')}",
            f"id={meta.get('id', '-')}",
            f"aria={_preview_text(meta.get('aria_label', ''), 36)}",
            f"placeholder={_preview_text(meta.get('placeholder', ''), 36)}",
            f"autocomplete={_preview_text(meta.get('autocomplete', ''), 24)}",
            f"labels={_preview_text(meta.get('labels', ''), 36)}",
            f"parent={_preview_text(meta.get('parent_text', ''), 48)}",
        )
        if part
    )


def _summarize_add_email_probe(page: Any) -> str:
    info = _probe_add_email_page_state(page)
    parts = [
        f"url={_mask_secret(info.get('url', ''), head=56, tail=12) if info.get('url') else '-'}",
        f"page_state={info.get('state') or '-'}",
        f"input_found={info.get('input_found') or '-'}",
        f"input_meta={info.get('input_meta') or '-'}",
        f"input_value={_preview_text(info.get('input_value', ''), 60) or '-'}",
        f"input_disabled={info.get('input_disabled') or '-'}",
        f"input_readonly={info.get('input_readonly') or '-'}",
        f"aria_disabled={info.get('input_aria_disabled') or '-'}",
        f"submit_found={info.get('submit_found') or '-'}",
        f"submit_text={_preview_text(info.get('submit_text', ''), 40) or '-'}",
        f"submit_disabled={info.get('submit_disabled') or '-'}",
        f"submit_busy={info.get('submit_busy') or '-'}",
        f"submit_state={info.get('submit_state') or '-'}",
    ]
    return ", ".join(parts)


def _fill_add_email_input(page: Any, email: str) -> tuple[bool, str]:
    label_filled = _fill_input_by_label(page, ["email", "mail", "邮箱", "电子邮件"], email, timeout_ms=1400)
    if label_filled:
        confirmed = _extract_input_value_by_hints(page, ["email", "mail", "邮箱", "电子邮件"], limit=16)
        return bool(confirmed and confirmed.strip().lower() == str(email or "").strip().lower()), confirmed

    selectors = [
        'input[name="email"]',
        'input[type="email"]',
        'input[autocomplete="email"]',
        'input[id*="-email" i]',
        'input[placeholder*="email" i]',
        'input[placeholder*="mail" i]',
        'input[placeholder*="电子邮件" i]',
        'input[aria-label*="email" i]',
        'input[aria-label*="mail" i]',
        'input[name*="mail" i]',
    ]
    locator = _first_visible_locator(page, selectors)
    if locator is None:
        return False, ""
    if not _write_text_to_locator(locator, email, timeout_ms=1400):
        return False, _locator_value(locator, timeout_ms=250)
    confirmed = _locator_value(locator, timeout_ms=250)
    if not confirmed:
        confirmed = _extract_input_value_by_hints(page, ["email", "mail", "邮箱", "电子邮件"], limit=16)
    return bool(confirmed and confirmed.strip().lower() == str(email or "").strip().lower()), confirmed


def _submit_add_email_continue(page: Any) -> bool:
    preferred = [
        'button:has-text("Continue")',
        '[role="button"]:has-text("Continue")',
        'button:has-text("Next")',
        '[role="button"]:has-text("Next")',
        'button:has-text("Verify")',
        '[role="button"]:has-text("Verify")',
        'button:has-text("继续")',
        '[role="button"]:has-text("继续")',
        'button:has-text("下一步")',
        '[role="button"]:has-text("下一步")',
        'button[type="submit"]',
        'input[type="submit"]',
    ]
    locator = _first_visible_locator(page, preferred)
    if locator is not None:
        if _click_locator_human_like(page, locator, timeout_ms=1400):
            return True
        if _request_submit_with_button(locator):
            return True
    return _click_primary_action(
        page,
        ["Continue", "Next", "Verify", "继续", "下一步"],
        allow_generic_fallback=True,
    )


def _wait_for_create_account_password_ready(page: Any, *, timeout_ms: int = 8000) -> bool:
    deadline = time.time() + max(1.5, float(timeout_ms or 0) / 1000.0)
    first_round = True
    while time.time() < deadline:
        # 这里由主循环刚确认过密码页；不再等待 networkidle，避免站点后台长连接
        # 把“输入框已经出现”人为拖成数秒。
        if first_round:
            _sleep_with_page(page, 80)
            first_round = False
        try:
            current_url = str(page.url or "").strip()
        except Exception:
            current_url = ""
        frame_url = _best_auth_target_url(page)
        frame_url_lower = frame_url.lower()
        current_url_lower = current_url.lower()
        is_password_url = (
            "/create-account/password" in current_url_lower
            or "/create-account/password" in frame_url_lower
            or "/log-in/password" in current_url_lower
            or "/log-in/password" in frame_url_lower
        )
        # 密码路由已经由 URL 确认，正文只会增加一次同步 CDP 读取；离开密码路由后
        # 再读取正文用于错误页/资料页判定。
        body_text = "" if is_password_url else _describe_page(page)[1]
        if not is_password_url and not _is_create_account_password_page(current_url, body_text, page):
            if (
                _is_contact_verification_page(current_url, body_text, page)
                or _is_phone_sms_send_failed_error(current_url, body_text, page)
                or _is_timeout_error_page(current_url, body_text)
                or _is_profile_page(current_url, body_text)
                or _is_login_password_page(current_url, body_text, page)
            ):
                return True
            _sleep_with_page(page, 160)
            continue
        password_input = _first_visible_locator(
            page,
            [
                'input[type="password"]',
                'input[name="password"]',
                'input[name="new-password"]',
                'input[autocomplete="new-password"]',
                'input[id*="password" i]',
            ],
        )
        if password_input is None:
            _sleep_with_page(page, 160)
            continue
        try:
            disabled = str(password_input.get_attribute("disabled", timeout=250) or "").strip().lower()
        except Exception:
            disabled = ""
        try:
            readonly = str(password_input.get_attribute("readonly", timeout=250) or "").strip().lower()
        except Exception:
            readonly = ""
        # Continue 在密码为空时可能被站点主动置灰；密码框可编辑即可立即填入，
        # 填值后再重新定位/点击提交按钮，不在这里空等按钮解锁。
        if disabled in {"", "false"} and readonly in {"", "false"}:
            return True
        _sleep_with_page(page, 140)
    current_url, body_text = _describe_page(page, force_refresh=True)
    if (
        _is_contact_verification_page(current_url, body_text, page)
        or _is_phone_sms_send_failed_error(current_url, body_text, page)
        or _is_timeout_error_page(current_url, body_text)
        or _is_profile_page(current_url, body_text)
        or _is_login_password_page(current_url, body_text, page)
    ):
        return True
    return False


def _is_login_password_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    if any(
        domain in url_lower
        for domain in (
            "accounts.google.com",
            "login.microsoftonline.com",
            "appleid.apple.com",
            "login.live.com",
        )
    ):
        return False
    if "/log-in/password" not in url_lower:
        return False
    if _is_create_account_password_page(url, body_text, page):
        return False
    body_lower = str(body_text or "").lower()
    if (
        "forgot password" in body_lower
        or "enter your password" in body_lower
        or "password" in body_lower
    ):
        return True
    return _first_visible_locator(
        page,
        [
            'input[type="password"]',
            'input[name="password"]',
            'button:has-text("Forgot password")',
            'a:has-text("Forgot password")',
        ],
    ) is not None



def _is_passkey_challenge_page(url: str, body_text: str, page: Any = None) -> bool:
    """Passkey / security key 挑战页：通常表示当前手机号已绑定既有账号。"""
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    body_text_value = str(body_text or "")
    if "auth_challenge/passkey" in url_lower:
        return True
    if "auth_challenge" in url_lower and "passkey" in url_lower:
        return True
    if any(
        hint in body_lower
        for hint in (
            "continue with passkey",
            "verifying it's you",
            "we've found a passkey",
            "security key for your account",
            "use a passkey",
            "use passkey",
        )
    ):
        return True
    if "passkey" in body_lower and (
        "try another way" in body_lower
        or "继续使用通行密钥" in body_text_value
        or "验证是你本人" in body_text_value
    ):
        return True
    if page is not None:
        has_passkey_action = _first_visible_locator(
            page,
            [
                'button:has-text("Continue with passkey")',
                '[role="button"]:has-text("Continue with passkey")',
                'button:has-text("Try another way")',
                '[role="button"]:has-text("Try another way")',
                'button:has-text("继续使用通行密钥")',
                '[role="button"]:has-text("继续使用通行密钥")',
                'button:has-text("换个方式")',
                '[role="button"]:has-text("换个方式")',
            ],
        ) is not None
        if has_passkey_action and (
            "passkey" in body_lower
            or "security key" in body_lower
            or "auth_challenge" in url_lower
            or "通行密钥" in body_text_value
        ):
            return True
    return False


def _is_reset_password_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "/reset-password/new-password" in url_lower:
        return False
    if "/reset-password" in url_lower:
        return True
    return bool(
        "reset password" in body_lower
        and _first_visible_locator(
            page,
            [
                'button:has-text("Continue")',
                '[role="button"]:has-text("Continue")',
                'button:has-text("继续")',
                '[role="button"]:has-text("继续")',
            ],
        )
        is not None
    )


def _is_reset_password_new_password_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    if "/reset-password/new-password" in url_lower:
        return True
    new_password = _first_visible_locator(
        page,
        [
            'input[name="new-password"]',
            'input[autocomplete="new-password"]',
        ],
    )
    confirm_password = _first_visible_locator(
        page,
        [
            'input[name="confirm-password"]',
            'input[id*="confirm-password" i]',
            'input[placeholder*="Re-enter new password" i]',
        ],
    )
    return new_password is not None and confirm_password is not None


def _wait_for_reset_password_new_password_ready(page: Any, *, timeout_ms: int = 12000) -> bool:
    deadline = time.time() + max(2.0, float(timeout_ms or 0) / 1000.0)
    stable_rounds = 0
    last_signature = ""
    while time.time() < deadline:
        _wait_for_load(page, timeout_ms=1200)
        current_url, body_text = _describe_page(page)
        if not _is_reset_password_new_password_page(current_url, body_text, page):
            _sleep_with_page(page, 350)
            continue
        new_password = _first_visible_locator(
            page,
            [
                'input[name="new-password"]',
                'input[autocomplete="new-password"]',
                'input[id*="new-password" i]',
            ],
        )
        confirm_password = _first_visible_locator(
            page,
            [
                'input[name="confirm-password"]',
                'input[id*="confirm-password" i]',
                'input[placeholder*="Re-enter new password" i]',
            ],
        )
        if new_password is None or confirm_password is None:
            _sleep_with_page(page, 350)
            continue
        try:
            new_disabled = str(new_password.get_attribute("disabled") or "").strip().lower()
        except Exception:
            new_disabled = ""
        try:
            confirm_disabled = str(confirm_password.get_attribute("disabled") or "").strip().lower()
        except Exception:
            confirm_disabled = ""
        try:
            new_readonly = str(new_password.get_attribute("readonly") or "").strip().lower()
        except Exception:
            new_readonly = ""
        try:
            confirm_readonly = str(confirm_password.get_attribute("readonly") or "").strip().lower()
        except Exception:
            confirm_readonly = ""
        if new_disabled or confirm_disabled or new_readonly or confirm_readonly:
            _sleep_with_page(page, 350)
            continue
        signature = _page_snapshot_signature(current_url, body_text)
        if signature == last_signature:
            stable_rounds += 1
        else:
            stable_rounds = 1
            last_signature = signature
        if stable_rounds >= 3:
            _sleep_with_page(page, random.randint(300, 700))
            return True
        _sleep_with_page(page, 350)
    return False


def _is_reset_password_success_page(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    return bool(
        "/reset-password/success" in url_lower
        or ("password reset" in body_lower and "successful" in body_lower)
        or ("reset password" in body_lower and "success" in body_lower)
    )


def _locator_value(locator: Any, *, timeout_ms: int = 300) -> str:
    if locator is None:
        return ""
    timeout = max(100, int(timeout_ms or 300))
    try:
        return str(locator.input_value(timeout=timeout) or "").strip()
    except Exception:
        try:
            return str(locator.get_attribute("value", timeout=timeout) or "").strip()
        except Exception:
            return ""


def _digits_only(value: Any) -> str:
    return "".join(ch for ch in str(value or "") if ch.isdigit())


def _clear_locator_text(locator: Any, *, timeout_ms: int = 1200) -> None:
    if locator is None:
        return
    try:
        locator.click(timeout=timeout_ms)
    except Exception:
        pass
    try:
        locator.fill("", timeout=timeout_ms)
        return
    except Exception:
        pass
    for key in ("Control+A", "Meta+A"):
        try:
            locator.press(key, timeout=timeout_ms)
        except Exception:
            pass
    try:
        locator.press("Backspace", timeout=timeout_ms)
    except Exception:
        pass


def _write_phone_text_to_locator(locator: Any, value: str, *, timeout_ms: int = 1400) -> bool:
    text = str(value or "").strip()
    expected_digits = _digits_only(text)
    if locator is None or not text or not expected_digits:
        return False

    def _confirm_written() -> bool:
        for _ in range(3):
            current_digits = _digits_only(_locator_value(locator, timeout_ms=500))
            if current_digits == expected_digits:
                return True
            time.sleep(0.12)
        return False

    if _write_text_to_locator(locator, text, timeout_ms=timeout_ms) and _confirm_written():
        return True

    _clear_locator_text(locator, timeout_ms=timeout_ms)
    try:
        locator.press_sequentially(text, timeout=timeout_ms)
    except Exception:
        pass
    if _confirm_written():
        return True

    _clear_locator_text(locator, timeout_ms=timeout_ms)
    try:
        locator.evaluate(
            """(el, newValue) => {
                el.focus?.();
                if ('value' in el) {
                    el.value = '';
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.value = newValue;
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                    return true;
                }
                return false;
            }""",
            text,
        )
    except Exception:
        pass
    return _confirm_written()


def _manual_phone_input_ready(page: Any) -> bool:
    locator = _first_visible_locator(
        page,
        [
            'input[id="phoneNumberInput"]',
            'input[name="phoneNumberInput"]',
            'input[type="tel"]',
            'input[inputmode="tel"]',
            'input[name*="phone" i]',
            'input[autocomplete="tel"]',
            'input[placeholder*="phone" i]',
            'input[aria-label*="phone" i]',
            'input[placeholder*="手机号"]',
            'input[aria-label*="手机号"]',
        ],
    )
    value = _locator_value(locator)
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) < 7:
        return False
    continue_button = _first_visible_locator(
        page,
        [
            'button:has-text("Continue")',
            '[role="button"]:has-text("Continue")',
            'button:has-text("Next")',
            '[role="button"]:has-text("Next")',
            'button:has-text("继续")',
            '[role="button"]:has-text("继续")',
            'button:has-text("下一步")',
            '[role="button"]:has-text("下一步")',
            'button[type="submit"]',
        ],
    )
    if continue_button is None:
        return False
    try:
        disabled_attr = str(continue_button.get_attribute("disabled") or "").strip().lower()
    except Exception:
        disabled_attr = ""
    try:
        aria_disabled = str(continue_button.get_attribute("aria-disabled") or "").strip().lower()
    except Exception:
        aria_disabled = ""
    return disabled_attr not in {"true", "disabled"} and aria_disabled != "true"


def _manual_contact_verification_ready(page: Any) -> bool:
    otp_meta = _detect_otp_inputs(page)
    mode = str(otp_meta.get("mode") or "")
    if mode == "single":
        value = _locator_value(otp_meta.get("input"))
        digits = "".join(ch for ch in value if ch.isdigit())
        return len(digits) >= 6
    if mode == "segmented":
        inputs = otp_meta.get("inputs") or []
        if not inputs:
            return False
        filled_count = 0
        for item in inputs[:6]:
            if _locator_value(item):
                filled_count += 1
        return filled_count >= min(6, len(inputs[:6]))
    return False


def _match_manual_v2_phone_country(digits: str) -> Dict[str, str]:
    normalized_digits = str(digits or "").strip()
    if not normalized_digits:
        return {}
    matches: list[Dict[str, str]] = []
    for item in DEFAULT_PHONE_COUNTRIES:
        dial_code = str(item.get("dialCode") or "").strip().lstrip("+")
        if not dial_code or not normalized_digits.startswith(dial_code):
            continue
        matches.append(
            {
                "country_dial_code": dial_code,
                "country_iso": str(item.get("isoCode") or "").strip().upper(),
                "country_hint": str((item.get("aliases") or [""])[0] or item.get("name") or "").strip(),
            }
        )
    if not matches:
        return {}
    matches.sort(key=lambda row: len(str(row.get("country_dial_code") or "")), reverse=True)
    return matches[0]


def _normalize_manual_v2_phone_number(raw_phone: str) -> Dict[str, str]:
    text = str(raw_phone or "").strip()
    digits = "".join(ch for ch in text if ch.isdigit())
    info: Dict[str, str] = {
        "raw": text,
        "digits": digits,
        "canonical_phone": text,
        "country_dial_code": "",
        "country_iso": "",
        "country_hint": "",
        "local_number": text,
    }
    if not digits:
        return info
    country_match = _match_manual_v2_phone_country(digits) if text.startswith("+") else {}
    if country_match:
        dial_code = str(country_match.get("country_dial_code") or "").strip()
        local_number = digits[len(dial_code):] if dial_code else digits
        info.update(
            {
                "canonical_phone": f"+{digits}" if digits else text,
                **country_match,
                "local_number": local_number or text,
            }
        )
        return info
    if text.startswith("+44") or (digits.startswith("44") and len(digits) >= 11):
        local_number = digits[2:]
        info.update(
            {
                "canonical_phone": f"+{digits}" if digits else text,
                "country_dial_code": "44",
                "country_iso": "GB",
                "country_hint": "United Kingdom",
                "local_number": local_number or text,
            }
        )
        return info
    if digits.startswith("07") and len(digits) >= 10:
        info.update(
            {
                "canonical_phone": digits,
                "country_dial_code": "44",
                "country_iso": "GB",
                "country_hint": "United Kingdom",
                "local_number": digits,
            }
        )
        return info
    if text.startswith("+"):
        info["canonical_phone"] = "+" + digits if digits else text
        return info
    if digits and not digits.startswith("0"):
        info["canonical_phone"] = f"+{digits}"
    return info


def _ensure_manual_v2_phone_country(
    page: Any,
    *,
    dial_code: str,
    country_iso: str = "",
    country_hint: str = "",
) -> bool:
    if page is None or not str(dial_code or "").strip():
        return False
    dial = str(dial_code or "").strip().lstrip("+")
    iso = str(country_iso or "").strip().upper()
    hint = str(country_hint or "").strip()
    hint_candidates = [item for item in [hint, "United Kingdom" if iso == "GB" else "", "英国" if iso == "GB" else "", f"+{dial}", f"({dial})"] if item]
    try:
        result = page.evaluate(
            """({ dialCode, isoCode, hintCandidates }) => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim().toLowerCase();
                const hints = (hintCandidates || []).map(normalize).filter(Boolean);
                const visible = (node) => {
                    if (!node) return false;
                    const rect = node.getBoundingClientRect();
                    const style = window.getComputedStyle(node);
                    return rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden';
                };
                const textOf = (node) => normalize(
                    node?.innerText
                    || node?.textContent
                    || node?.value
                    || node?.getAttribute?.('aria-label')
                    || ''
                );
                const matches = (value) => {
                    const text = normalize(value);
                    if (!text) return false;
                    return hints.some((hint) => text.includes(hint));
                };
                const currentMatches = () => {
                    for (const select of Array.from(document.querySelectorAll('select'))) {
                        try {
                            if (isoCode && normalize(select.value) === normalize(isoCode)) return true;
                        } catch (e) {}
                        const selected = select.options?.[select.selectedIndex];
                        if (selected && matches(selected.text || selected.label || selected.value || '')) return true;
                    }
                    for (const node of Array.from(document.querySelectorAll('button, [role="button"], [role="combobox"]'))) {
                        if (!visible(node)) continue;
                        if (matches(textOf(node))) return true;
                    }
                    return false;
                };
                if (currentMatches()) return 'already';
                for (const select of Array.from(document.querySelectorAll('select'))) {
                    const options = Array.from(select.options || []);
                    const matched = options.find((option) => {
                        const optionValue = normalize(option.value || '');
                        const optionText = option.text || option.label || option.value || '';
                        return (isoCode && optionValue === normalize(isoCode)) || matches(optionText);
                    });
                    if (!matched) continue;
                    try {
                        select.value = matched.value;
                        select.dispatchEvent(new Event('input', { bubbles: true }));
                        select.dispatchEvent(new Event('change', { bubbles: true }));
                    } catch (e) {}
                    if (currentMatches()) return 'select';
                }
                const clickNode = (node) => {
                    try { node.focus?.(); } catch (e) {}
                    ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'].forEach((type) => {
                        try {
                            node.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
                        } catch (e) {}
                    });
                };
                const openers = Array.from(document.querySelectorAll('button[aria-haspopup="listbox"], [role="combobox"], button, [role="button"]'));
                for (const opener of openers) {
                    if (!visible(opener)) continue;
                    const text = textOf(opener);
                    if (!(text.includes('+') || text.includes('country') || text.includes('region') || text.includes('国家') || text.includes('区号') || matches(text))) continue;
                    clickNode(opener);
                    break;
                }
                const options = Array.from(document.querySelectorAll('[role="option"], [role="listbox"] *, [data-key], li, button, [role="button"]'));
                for (const option of options) {
                    if (!visible(option)) continue;
                    const optionText = textOf(option);
                    const dataKey = normalize(option.getAttribute?.('data-key') || '');
                    if ((isoCode && dataKey === normalize(isoCode)) || matches(optionText)) {
                        clickNode(option);
                        if (currentMatches()) return 'option';
                    }
                }
                return currentMatches() ? 'matched' : '';
            }""",
            {"dialCode": dial, "isoCode": iso, "hintCandidates": hint_candidates},
        )
        return bool(str(result or "").strip())
    except Exception:
        pass

    visible_selects = _collect_visible_locators(
        page,
        [
            'select',
            '[role="combobox"]',
            'button[aria-haspopup="listbox"]',
        ],
        limit=6,
    )
    candidates = [item for item in [iso, hint, "英国" if iso == "GB" else "", f"+{dial}", f"({dial})"] if item]
    for locator in visible_selects:
        if _choose_first_supported_option(page, locator, candidates, timeout_ms=1200):
            return True
    option_selectors = [f'[role="option"]:has-text("+{dial}")', f'[role="listbox"] *:has-text("+{dial}")', f'li:has-text("+{dial}")']
    if iso:
        option_selectors.insert(0, f'[data-key="{iso}"]')
    if hint:
        option_selectors.insert(1, f'[role="option"]:has-text("{hint}")')
    if iso == "GB":
        option_selectors.insert(2, '[role="option"]:has-text("英国")')
    option = _first_visible_locator(page, option_selectors)
    if option is not None:
        try:
            option.click(timeout=1200)
            return True
        except Exception:
            return False
    return False


def _click_phone_form_continue_human(page: Any) -> bool:
    """手机号页 Continue：优先真人轨迹点击，避免 JS 假点。"""
    return _click_exact_action_texts(
        page,
        ["Continue", "Next", "继续", "下一步"],
        allow_generic_submit=True,
        timeout_ms=1500,
    ) or _click_first(
        page,
        [
            'button[type="submit"]:text-is("Continue")',
            'button:text-is("Continue")',
            'button[type="submit"]:text-is("继续")',
            'button:text-is("继续")',
            'button[type="submit"]',
        ],
        timeout_ms=1200,
    )


def _submit_manual_v2_phone_input(page: Any, phone_number: str, *, step: str = "add_phone") -> bool:
    phone_text = str(phone_number or "").strip()
    if page is None or not phone_text:
        return False
    phone_meta = _normalize_manual_v2_phone_number(phone_text)
    normalized_phone_text = str(phone_meta.get("canonical_phone") or phone_text).strip()
    local_phone_text = str(phone_meta.get("local_number") or "").strip()
    dial_code = str(phone_meta.get("country_dial_code") or "").strip()
    phone_input = _first_visible_locator(
        page,
        [
            'input[name="phoneNumberInput"]',
            'input[type="tel"]',
            'input[inputmode="tel"]',
            'input[name*="phone" i]',
            'input[autocomplete="tel"]',
            'input[placeholder*="phone" i]',
            'input[aria-label*="phone" i]',
            'input[placeholder*="手机号"]',
            'input[aria-label*="手机号"]',
        ],
    )
    if phone_input is None:
        return False
    # 先直接写完整国际号码，让站点自己识别区号；只有失败时才回退到手动切国家+本地号。
    if normalized_phone_text.startswith("+") and _write_phone_text_to_locator(phone_input, normalized_phone_text):
        try:
            _click_locator_human_like(page, phone_input, timeout_ms=1200)
        except Exception:
            try:
                phone_input.click(timeout=1200)
            except Exception:
                pass
        # 优先真人点 Continue（参照 grok 注册机 CF 真点），JS 假点仅兜底。
        if _click_phone_form_continue_human(page):
            _sleep_with_page(page, 800)
            return True
        phone_form_result = ""
        try:
            phone_form_result = str(
                phone_input.evaluate(
                    """(el) => {
                        const isVisible = (node) => {
                            if (!node) return false;
                            const rect = node.getBoundingClientRect();
                            const style = window.getComputedStyle(node);
                            return rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden';
                        };
                        const safeTexts = new Set(['继续', 'Continue', 'Next', '下一步']);
                        const rejectTokens = ['google', 'apple', 'microsoft', 'email', '邮箱'];
                        const normalizedText = (node) => String(
                            node?.innerText
                            || node?.textContent
                            || node?.value
                            || node?.getAttribute?.('aria-label')
                            || ''
                        ).replace(/\\s+/g, ' ').trim();
                        const isSafeSubmitButton = (button) => {
                            const text = normalizedText(button);
                            if (!text || !safeTexts.has(text)) return false;
                            const lower = text.toLowerCase();
                            if (rejectTokens.some(token => lower.includes(token))) return false;
                            if (!isVisible(button) || button.disabled) return false;
                            const ariaDisabled = String(button.getAttribute?.('aria-disabled') || '').trim().toLowerCase();
                            return ariaDisabled !== 'true';
                        };
                        const scopes = [];
                        const seen = new Set();
                        const pushScope = (node) => {
                            if (!node || seen.has(node)) return;
                            seen.add(node);
                            scopes.push(node);
                        };
                        pushScope(el.closest('form'));
                        pushScope(el.closest('[role="dialog"]'));
                        let current = el.parentElement;
                        let depth = 0;
                        while (current && depth < 8) {
                            pushScope(current);
                            current = current.parentElement;
                            depth += 1;
                        }
                        // 仅打标，不在 JS 里 click；外层用真人轨迹点。
                        const marker = 'data-phone-continue-human';
                        document.querySelectorAll('[' + marker + ']').forEach((n) => n.removeAttribute(marker));
                        for (const scope of scopes) {
                            const strictButtons = Array.from(scope.querySelectorAll('button[type="submit"], input[type="submit"]'));
                            for (const button of strictButtons) {
                                if (!isSafeSubmitButton(button)) continue;
                                button.setAttribute(marker, '1');
                                return 'marked';
                            }
                            const fallbackButtons = Array.from(scope.querySelectorAll('button, [role="button"]'));
                            for (const button of fallbackButtons) {
                                if (!isSafeSubmitButton(button)) continue;
                                button.setAttribute(marker, '1');
                                return 'marked';
                            }
                        }
                        const form = el.closest('form');
                        if (form && typeof form.requestSubmit === 'function') {
                            form.requestSubmit();
                            return 'form';
                        }
                        if (form && typeof form.submit === 'function') {
                            form.submit();
                            return 'form';
                        }
                        return '';
                    }"""
                )
                or ""
            )
        except Exception:
            phone_form_result = ""
        if phone_form_result == "marked":
            marked_btn = _first_visible_locator(page, ['[data-phone-continue-human="1"]'])
            if marked_btn is not None and _click_locator_human_like(page, marked_btn, timeout_ms=1500):
                _sleep_with_page(page, 800)
                return True
        if phone_form_result == "form":
            _sleep_with_page(page, 800)
            return True
        if _request_submit_with_button(phone_input):
            return True

    country_selected = False
    if dial_code:
        country_selected = _ensure_manual_v2_phone_country(
            page,
            dial_code=dial_code,
            country_iso=str(phone_meta.get("country_iso") or "").strip(),
            country_hint=str(phone_meta.get("country_hint") or "").strip(),
        )
        if country_selected:
            _sleep_with_page(page, 250)

    input_candidates: list[str] = []
    if country_selected and local_phone_text:
        input_candidates.append(local_phone_text)
    if normalized_phone_text and normalized_phone_text not in input_candidates:
        input_candidates.append(normalized_phone_text)
    if (
        country_selected
        and local_phone_text
        and not local_phone_text.startswith("0")
        and str(phone_meta.get("country_iso") or "").strip().upper() not in {"GB"}
    ):
        trunk_candidate = "0" + local_phone_text
        if trunk_candidate not in input_candidates:
            input_candidates.append(trunk_candidate)

    write_ok = False
    for candidate_text in input_candidates:
        if _write_phone_text_to_locator(phone_input, candidate_text):
            write_ok = True
            break
    if not write_ok:
        return False
    try:
        _click_locator_human_like(page, phone_input, timeout_ms=1200)
    except Exception:
        try:
            phone_input.click(timeout=1200)
        except Exception:
            pass
    if _click_phone_form_continue_human(page):
        _sleep_with_page(page, 800)
        return True
    phone_form_result = ""
    try:
        phone_form_result = str(
            phone_input.evaluate(
                """(el) => {
                    const isVisible = (node) => {
                        if (!node) return false;
                        const rect = node.getBoundingClientRect();
                        const style = window.getComputedStyle(node);
                        return rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden';
                    };
                    const safeTexts = new Set(['继续', 'Continue', 'Next', '下一步']);
                    const rejectTokens = ['google', 'apple', 'microsoft', 'email', '邮箱'];
                    const normalizedText = (node) => String(
                        node?.innerText
                        || node?.textContent
                        || node?.value
                        || node?.getAttribute?.('aria-label')
                        || ''
                    ).replace(/\\s+/g, ' ').trim();
                    const isSafeSubmitButton = (button) => {
                        const text = normalizedText(button);
                        if (!text || !safeTexts.has(text)) return false;
                        const lower = text.toLowerCase();
                        if (rejectTokens.some(token => lower.includes(token))) return false;
                        if (!isVisible(button) || button.disabled) return false;
                        const ariaDisabled = String(button.getAttribute?.('aria-disabled') || '').trim().toLowerCase();
                        return ariaDisabled !== 'true';
                    };
                    const scopes = [];
                    const seen = new Set();
                    const pushScope = (node) => {
                        if (!node || seen.has(node)) return;
                        seen.add(node);
                        scopes.push(node);
                    };
                    pushScope(el.closest('form'));
                    pushScope(el.closest('[role="dialog"]'));
                    let current = el.parentElement;
                    let depth = 0;
                    while (current && depth < 8) {
                        pushScope(current);
                        current = current.parentElement;
                        depth += 1;
                    }
                    const marker = 'data-phone-continue-human';
                    document.querySelectorAll('[' + marker + ']').forEach((n) => n.removeAttribute(marker));
                    for (const scope of scopes) {
                        const strictButtons = Array.from(scope.querySelectorAll('button[type="submit"], input[type="submit"]'));
                        for (const button of strictButtons) {
                            if (!isSafeSubmitButton(button)) continue;
                            button.setAttribute(marker, '1');
                            return 'marked';
                        }
                        const fallbackButtons = Array.from(scope.querySelectorAll('button, [role="button"]'));
                        for (const button of fallbackButtons) {
                            if (!isSafeSubmitButton(button)) continue;
                            button.setAttribute(marker, '1');
                            return 'marked';
                        }
                    }
                    const form = el.closest('form');
                    if (form && typeof form.requestSubmit === 'function') {
                        form.requestSubmit();
                        return 'form';
                    }
                    if (form && typeof form.submit === 'function') {
                        form.submit();
                        return 'form';
                    }
                    return '';
                }"""
            )
            or ""
        )
    except Exception:
        phone_form_result = ""
    if phone_form_result == "marked":
        marked_btn = _first_visible_locator(page, ['[data-phone-continue-human="1"]'])
        if marked_btn is not None and _click_locator_human_like(page, marked_btn, timeout_ms=1500):
            _sleep_with_page(page, 800)
            return True
    if phone_form_result == "form":
        _sleep_with_page(page, 800)
        return True
    if _request_submit_with_button(phone_input):
        return True
    return False


def _is_phone_input_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "/create-account/password" in url_lower:
        return False
    if "/reset-password/new-password" in url_lower:
        return False
    if _is_create_account_password_page(url, body_text, page):
        return False
    phone_input = _first_visible_locator(
        page,
        [
            'input[id="phoneNumberInput"]',
            'input[name="phoneNumberInput"]',
            'input[type="tel"]',
            'input[inputmode="tel"]',
            'input[name*="phone" i]',
            'input[autocomplete="tel"]',
            'input[placeholder*="phone" i]',
            'input[aria-label*="phone" i]',
            'input[placeholder*="手机号"]',
            'input[aria-label*="手机号"]',
        ],
    )
    if phone_input is not None:
        return True
    return False


def _is_add_email_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "/add-email" in url_lower:
        return True
    if "log-in" in url_lower or "login" in url_lower:
        return False
    email_input = _first_visible_locator(
        page,
        [
            'input[name="email"]',
            'input[autocomplete="email"]',
            'input[id*="-email" i]',
            'input[placeholder*="email" i]',
            'input[placeholder*="电子邮件" i]',
        ],
    )
    if email_input is None:
        return False
    return bool(
        "add email" in body_lower
        or "add your email" in body_lower
        or "verify your email" in body_lower
        or "电子邮件地址" in body_text
        or "绑定邮箱" in body_text
    )


def _wait_for_add_email_ready(page: Any, *, timeout_ms: int = 8000) -> bool:
    deadline = time.time() + max(1.5, float(timeout_ms or 0) / 1000.0)
    stable_rounds = 0
    last_signature = ""
    first_round = True
    while time.time() < deadline:
        # 仅首轮做较长 load 等待；后续快轮询，避免每轮 +1.2s
        if first_round:
            _wait_for_load(page, timeout_ms=800)
            first_round = False
        current_url, body_text = _describe_page(page)
        if not _is_add_email_page(current_url, body_text, page):
            if (
                _is_otp_page(current_url, body_text, page)
                or _is_profile_page(current_url, body_text)
                or _is_timeout_error_page(current_url, body_text)
                or _is_login_password_page(current_url, body_text, page)
                or _is_logged_in_chatgpt_home(current_url, body_text)
            ):
                return True
            _sleep_with_page(page, 180)
            continue
        probe_locator = _first_visible_locator(
            page,
            [
                'input[type="email"]',
                'input[name="email"]',
                'input[autocomplete="email"]',
                'input[id*="-email" i]',
                'input[placeholder*="email" i]',
                'input[placeholder*="mail" i]',
                'input[placeholder*="电子邮件" i]',
                'input[aria-label*="email" i]',
                'input[aria-label*="mail" i]',
                'input[name*="mail" i]',
            ],
        )
        if probe_locator is None:
            _sleep_with_page(page, 180)
            continue
        try:
            disabled = str(probe_locator.get_attribute("aria-disabled") or "").strip().lower()
        except Exception:
            disabled = ""
        readonly = "false"
        try:
            readonly = str(probe_locator.get_attribute("readonly") or "").strip().lower() or "false"
        except Exception:
            readonly = "false"
        try:
            native_disabled = str(probe_locator.get_attribute("disabled") or "").strip().lower()
        except Exception:
            native_disabled = ""
        signature = _page_snapshot_signature(current_url, body_text) + "|" + native_disabled + "|" + readonly + "|" + disabled
        if native_disabled in {"", "false"} and readonly in {"", "false"} and disabled in {"", "false"}:
            if signature == last_signature:
                stable_rounds += 1
            else:
                last_signature = signature
                stable_rounds = 1
            # 输入框已可用且签名稳定 1 轮即可（原 2 轮偏慢）
            if stable_rounds >= 1:
                return True
        _sleep_with_page(page, 160)
    return False


def _is_login_with_bridge_page(url: str, body_text: str, page: Any = None) -> bool:
    """仅识别 ChatGPT 首页登录桥接弹层，避免 create-password / passkey 等页面被误判。"""
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    # 已进入 OpenAI 认证域的真实业务页，一律不算桥接页。
    if "auth.openai.com" in url_lower:
        if any(
            token in url_lower
            for token in (
                "auth_challenge",
                "create-account",
                "log-in/password",
                "reset-password",
                "contact-verification",
                "email-verification",
                "about-you",
                "add-email",
                "add-phone",
            )
        ):
            return False
    url_is_bridge = bool(
        "chatgpt.com/auth/login_with" in url_lower
        or ("login_with" in url_lower and "chatgpt.com" in url_lower)
    )
    if not url_is_bridge:
        # 正文启发式只在仍停留在 chatgpt 域、且没有密码/OTP 主流程控件时启用。
        if "chatgpt.com" not in url_lower:
            return False
        if any(
            token in body_lower
            for token in (
                "create a password",
                "create password",
                "enter your password",
                "continue with passkey",
                "verifying it's you",
                "verification code",
                "verify your phone",
            )
        ):
            return False
        if page is not None and _first_visible_locator(
            page,
            [
                'input[type="password"]',
                'input[name="password"]',
                'input[name="new-password"]',
                'input[autocomplete="new-password"]',
                'input[name="code"]',
                'input[autocomplete="one-time-code"]',
            ],
        ) is not None:
            return False
        # 纯 chatgpt.com 首页即便有 Continue with Google/Email 文案，也优先视为首页壳，
        # 只有 login_with URL 或明确登录弹层路径才算桥接；否则会挡住 Sign up 点击。
        if "chatgpt.com" in url_lower and "login_with" not in url_lower and "/auth/login" not in url_lower:
            return False
        return bool(
            (
                "continue with phone" in body_lower
                or "continue with email" in body_lower
                or "continue with google" in body_lower
                or "continue with apple" in body_lower
                or "use phone instead" in body_lower
            )
            and ("login_with" in url_lower or "/auth/login" in url_lower)
        )
    # URL 已是 login_with，再排除已切入下一阶段控件的情况。
    if any(
        token in body_lower
        for token in (
            "create a password",
            "create password",
            "enter your password",
            "continue with passkey",
            "verifying it's you",
        )
    ):
        return False
    if page is not None and _first_visible_locator(
        page,
        [
            'input[type="password"]',
            'input[name="password"]',
            'input[name="new-password"]',
            'input[autocomplete="new-password"]',
        ],
    ) is not None:
        return False
    return True


def _is_session_ended_login_shell_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "auth.openai.com/log-in" not in url_lower:
        return False
    if not (
        "your session has ended" in body_lower
        or "session has ended" in body_lower
        or "你的会话已结束" in body_text
    ):
        return False
    return _first_visible_locator(
        page,
        [
            'a:has-text("Log in")',
            'button:has-text("Log in")',
            '[role="button"]:has-text("Log in")',
            'a:has-text("登录")',
            'button:has-text("登录")',
            '[role="button"]:has-text("登录")',
        ],
    ) is not None


def _is_manual_v2_phone_stage_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if (
        "email-verification" in url_lower
        or "add-email" in url_lower
        or "callback" in url_lower
        or "consent" in url_lower
        or "workspace" in url_lower
    ):
        return False
    if url_lower.startswith("about:blank"):
        return True
    if "chatgpt.com" in url_lower:
        return True
    if "check your inbox" in body_lower or "验证码" in body_text or "verification code" in body_lower:
        return False
    if "chatgpt.com/auth/login_with" in url_lower:
        return True
    if _is_phone_verification_page(url, body_text, page):
        return True
    if _is_phone_flow_page(url, body_text):
        return True
    if _is_create_account_password_page(url, body_text, page):
        return True
    if _is_phone_input_page(url, body_text, page):
        return True
    return False


def _is_manual_v2_login_phone_input_stage(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    if (
        "email-verification" in url_lower
        or "add-email" in url_lower
        or "callback" in url_lower
        or _is_contact_verification_page(url, body_text, page)
        or _is_create_account_password_page(url, body_text, page)
    ):
        return False
    return _is_phone_input_page(url, body_text, page)


def _is_otp_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if _is_profile_page(url, body_text):
        return False
    if _is_phone_verification_page(url, body_text, page):
        return False
    if _is_contact_verification_page(url, body_text, page):
        return False
    if "chatgpt.com" in url_lower and "email-verification" not in url_lower and "login_with" not in url_lower:
        return False
    return bool(
        "email-verification" in url_lower
        or "email otp" in body_lower
        or "verification code" in body_lower
        or (("auth.openai.com" in url_lower or "localhost:" in url_lower) and _detect_otp_inputs(page).get("mode"))
    )


def _is_email_verification_invalid_state_page(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "email-verification" not in url_lower:
        return False
    return bool(
        "invalid_state" in body_lower
        or "an error occurred during verification" in body_lower
        or "something went wrong" in body_lower
        or "验证过程中出错" in body_text
        or "请重试" in body_text
    )


def _is_about_you_missing_email_error(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "missing_email" not in body_lower:
        return False
    return bool(
        "about-you" in url_lower
        or "an error occurred during authentication" in body_lower
        or "please try again" in body_lower
    )


def _is_codex_consent_page(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    return bool(
        "sign-in-with-chatgpt/codex/consent" in url_lower
        or ("codex" in url_lower and "consent" in url_lower)
        or ("chatgpt codex" in body_lower and ("continue" in body_lower or "authorize" in body_lower or "allow" in body_lower))
    )


def _is_otp_page_ready(url: str, body_text: str, page: Any) -> bool:
    if not _is_otp_page(url, body_text, page):
        return False
    body_lower = str(body_text or "").lower()
    if any(
        hint in body_lower
        for hint in (
            "verification code",
            "enter code",
            "check your email",
            "resend",
            "send again",
            "verify email",
            "验证码",
            "验证代码",
            "重新发送",
            "再次发送",
        )
    ):
        return True
    if _detect_otp_inputs(page).get("mode"):
        return True
    resend_selectors = [
        'button:has-text("Resend")',
        '[role="button"]:has-text("Resend")',
        'a:has-text("Resend")',
        'button:has-text("Send again")',
        '[role="button"]:has-text("Send again")',
        'a:has-text("Send again")',
        'button:has-text("重新发送")',
        '[role="button"]:has-text("重新发送")',
        'a:has-text("重新发送")',
    ]
    return _first_visible_locator(page, resend_selectors) is not None


def _classify_page_state(url: str, body_text: str, page: Any) -> str:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()

    if "code=" in url_lower and "state=" in url_lower:
        return "callback"
    # 手机短信验证码路由优先于邮箱 OTP 分类，避免 contact-verification 被标成 otp_ready。
    if (
        "contact-verification" in url_lower
        or "verify-phone" in url_lower
        or "phone-verification" in url_lower
        or "phone_verification" in url_lower
    ):
        return "contact_verification"
    if "email-verification" in url_lower or "email-otp" in url_lower:
        return "otp_ready" if _is_otp_page_ready(url, body_text, page) else "otp_loading"
    if _is_login_with_bridge_page(url, body_text):
        return "login_with_bridge"
    if _is_session_ended_page(url, body_text):
        return "session_ended"
    if _is_passkey_challenge_page(url, body_text, page):
        return "passkey_challenge"
    if _is_timeout_error_page(url, body_text):
        return "timeout_error"
    if _is_phone_verification_page(url, body_text, page):
        return "add_phone"
    if _is_contact_verification_page(url, body_text, page):
        return "contact_verification"
    if "chatgpt.com" in url_lower:
        return "chatgpt"
    if url_lower.startswith("about:blank"):
        return "blank"
    if any(keyword in url_lower for keyword in ("consent", "workspace", "organization")):
        return "workspace"
    # 密码页优先于 profile：create-account/password 停留时绝不能被标成 profile。
    if (
        "/create-account/password" in url_lower
        or "/log-in/password" in url_lower
        or _is_create_account_password_page(url, body_text, page)
        or (
            _has_visible_password_input(page)
            and (
                "create a password" in body_lower
                or "create password" in body_lower
                or "创建密码" in str(body_text or "")
            )
        )
    ):
        return "password"
    if _is_profile_page(url, body_text, page):
        return "profile"
    if _is_otp_page(url, body_text, page):
        return "otp_ready" if _is_otp_page_ready(url, body_text, page) else "otp_loading"
    if _has_visible_password_input(page):
        return "password"
    if _first_visible_locator(
        page,
        [
            'input[type="email"]',
            'input[name="email"]',
            'input[name*="username" i]',
        ],
    ) is not None:
        return "email"
    if any(keyword in body_lower for keyword in ("authorize", "workspace", "organization", "allow access")):
        return "workspace"
    if "auth.openai.com" in url_lower:
        return "auth"
    return "other"


def _candidate_uc_paths() -> list[Path]:
    current_file = Path(__file__).resolve()
    repo_root = current_file.parents[1]
    workspace_root = current_file.parents[2]
    env_value = str((os.environ.get("OPENAI_POOL_UC_PATH") or "")).strip()
    candidates = [
        Path(env_value).expanduser() if env_value else None,
        repo_root / "undetected-chromedriver-master",
        workspace_root / "droid_Auto_Registration" / "undetected-chromedriver-master",
    ]
    seen: set[str] = set()
    result: list[Path] = []
    for item in candidates:
        if item is None:
            continue
        try:
            resolved = item.resolve()
        except Exception:
            resolved = item
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        result.append(resolved)
    return result


def _load_local_uc() -> tuple[Any, str]:
    errors: list[str] = []
    for candidate in _candidate_uc_paths():
        if not candidate.exists():
            errors.append(f"{candidate} (不存在)")
            continue
        if not candidate.is_dir():
            errors.append(f"{candidate} (不是目录)")
            continue
        candidate_str = str(candidate)
        inserted = False
        try:
            if candidate_str not in sys.path:
                sys.path.insert(0, candidate_str)
                inserted = True
            cached = sys.modules.get("undetected_chromedriver")
            if cached is not None:
                cached_file = str(getattr(cached, "__file__", "") or "")
                if cached_file.startswith(candidate_str):
                    return cached, candidate_str
                sys.modules.pop("undetected_chromedriver", None)
            module = importlib.import_module("undetected_chromedriver")
            return module, candidate_str
        except Exception as exc:
            errors.append(f"{candidate}: {exc}")
            if inserted:
                try:
                    sys.path.remove(candidate_str)
                except ValueError:
                    pass
    raise RuntimeError("未找到可用的本地 undetected-chromedriver，候选路径: " + " | ".join(errors or ["<empty>"]))


def _resolve_cdp_endpoint(cdp_driver: Any) -> str:
    candidates = [
        getattr(getattr(cdp_driver, "options", None), "debugger_address", ""),
        ((getattr(cdp_driver, "capabilities", {}) or {}).get("goog:chromeOptions") or {}).get("debuggerAddress", ""),
    ]
    for item in candidates:
        value = str(item or "").strip()
        if not value:
            continue
        if value.startswith(("http://", "https://", "ws://", "wss://")):
            return value
        return f"http://{value}"
    raise RuntimeError("无法从 undetected-chromedriver 解析 CDP 调试地址")


def _register_active_temp_user_data_dir(path: str) -> None:
    value = str(path or "").strip()
    if not value:
        return
    with _ACTIVE_TEMP_USER_DATA_DIRS_LOCK:
        _ACTIVE_TEMP_USER_DATA_DIRS.add(value)


def _unregister_active_temp_user_data_dir(path: str) -> None:
    value = str(path or "").strip()
    if not value:
        return
    with _ACTIVE_TEMP_USER_DATA_DIRS_LOCK:
        _ACTIVE_TEMP_USER_DATA_DIRS.discard(value)


def _canonical_uc_temp_profile(path: Any) -> str:
    """只接受系统临时目录下的 opo_uc_* profile，避免误碰普通 Chrome。"""
    value = str(path or "").strip().strip("\"'")
    if not value:
        return ""
    try:
        resolved = Path(value).expanduser().resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
        relative = resolved.relative_to(temp_root)
    except (OSError, RuntimeError, ValueError):
        return ""
    if not relative.parts or not str(relative.parts[0]).startswith(_UC_TEMP_DIR_PREFIX):
        return ""
    return str(resolved)


def _uc_profile_from_command(command: Any) -> str:
    text = str(command or "")
    match = re.search(
        r"--user-data-dir(?:=|\s+)(\"[^\"]+\"|'[^']+'|[^\s]+)",
        text,
    )
    if not match:
        return ""
    return _canonical_uc_temp_profile(match.group(1))


def _has_project_process_ancestor(
    pid: int,
    rows: dict[int, tuple[int, int, str]],
) -> bool:
    """有项目服务祖先的浏览器视为仍在使用，不能在启动新任务时误杀。"""
    project_root = str(Path(__file__).resolve().parents[1])
    visited: set[int] = set()
    current_pid = int(pid)
    while current_pid not in visited:
        visited.add(current_pid)
        row = rows.get(current_pid)
        if row is None:
            return False
        parent_pid = int(row[0] or 0)
        if parent_pid <= 1:
            return False
        if parent_pid == os.getpid():
            return True
        parent_command = str(rows.get(parent_pid, (0, 0, ""))[2] or "")
        if project_root and project_root in parent_command:
            return True
        current_pid = parent_pid
    return False


def _process_depth(pid: int, rows: dict[int, tuple[int, int, str]]) -> int:
    depth = 0
    current_pid = int(pid)
    visited: set[int] = set()
    while current_pid not in visited:
        visited.add(current_pid)
        row = rows.get(current_pid)
        if row is None:
            break
        parent_pid = int(row[0] or 0)
        if parent_pid <= 1:
            break
        depth += 1
        current_pid = parent_pid
    return depth


def _terminate_processes(
    pids: set[int],
    rows: dict[int, tuple[int, int, str]],
    children: dict[int, list[int]],
) -> int:
    """先优雅终止，再强制终止指定进程集合；集合只来自已校验的 UC profile。"""
    if not pids:
        return 0
    ordered = sorted(
        (int(pid) for pid in pids if int(pid) != os.getpid()),
        key=lambda pid: _process_depth(pid, rows),
        reverse=True,
    )
    signaled = 0
    for pid in ordered:
        try:
            os.kill(pid, signal.SIGTERM)
            signaled += 1
        except (ProcessLookupError, PermissionError, OSError):
            continue

    deadline = time.monotonic() + _UC_PROCESS_SHUTDOWN_WAIT_SECONDS
    remaining = set(ordered)
    while remaining and time.monotonic() < deadline:
        try:
            current_rows, _ = _read_process_table()
            remaining = {pid for pid in remaining if pid in current_rows}
        except Exception:
            remaining = {pid for pid in remaining if _process_depth(pid, rows) >= 0}
        if not remaining:
            break
        time.sleep(0.2)

    hard_kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
    for pid in sorted(remaining, key=lambda item: _process_depth(item, rows), reverse=True):
        try:
            os.kill(pid, hard_kill_signal)
            signaled += 1
        except (ProcessLookupError, PermissionError, OSError):
            continue
    return signaled


def _cleanup_orphan_uc_processes(
    emitter: Any = None,
    *,
    profile_dirs: Optional[set[str]] = None,
    step: str = "memory",
) -> int:
    """清理无项目服务祖先的 UC Chrome；普通 Chrome 不满足 profile 条件，不会被触碰。"""
    try:
        rows, children = _read_process_table()
    except Exception:
        return 0

    forced_profiles = {
        canonical
        for canonical in (_canonical_uc_temp_profile(item) for item in (profile_dirs or set()))
        if canonical
    }
    with _ACTIVE_TEMP_USER_DATA_DIRS_LOCK:
        active_profiles = {
            canonical
            for canonical in (_canonical_uc_temp_profile(item) for item in _ACTIVE_TEMP_USER_DATA_DIRS)
            if canonical
        }

    roots: set[int] = set()
    for pid, row in rows.items():
        profile = _uc_profile_from_command(row[2])
        if not profile:
            continue
        if forced_profiles:
            if profile not in forced_profiles:
                continue
        else:
            if profile in active_profiles or _has_project_process_ancestor(pid, rows):
                continue
        roots.add(int(pid))

    if not roots:
        return 0
    process_ids: set[int] = set()
    for root_pid in roots:
        process_ids.update(_process_descendants(root_pid, children))
    killed = _terminate_processes(process_ids, rows, children)
    if killed and emitter is not None:
        try:
            emitter.info(
                f"已终止 {killed} 个无主 UC 浏览器进程，profile={', '.join(sorted(forced_profiles)) or '历史临时目录'}",
                step=step,
            )
        except Exception:
            pass
    return killed


def _shutdown_browser_for_memory_pressure(
    resources: Optional[BrowserLaunchResources],
    playwright: Any,
    emitter: Any,
    *,
    target_bytes: int,
) -> tuple[int, int, int, int]:
    """关闭当前浏览器、终止残留子进程并等待进程树 RSS 降到目标以下。"""
    before = _process_tree_rss_bytes()
    profile_dirs: set[str] = set()
    if resources is not None:
        profile = _canonical_uc_temp_profile(getattr(resources, "temp_user_data_dir", ""))
        if profile:
            profile_dirs.add(profile)
        try:
            resources.playwright = playwright
        except Exception:
            pass
        _close_launch_resources(resources)
    else:
        try:
            if playwright is not None:
                playwright.stop()
        except Exception:
            pass

    killed = _cleanup_orphan_uc_processes(
        emitter,
        profile_dirs=profile_dirs or None,
        step="memory",
    )
    deadline = time.monotonic() + _UC_PROCESS_SHUTDOWN_WAIT_SECONDS
    after = _process_tree_rss_bytes()
    while after >= int(target_bytes or 0) and time.monotonic() < deadline:
        if profile_dirs:
            killed += _cleanup_orphan_uc_processes(
                emitter,
                profile_dirs=profile_dirs,
                step="memory",
            )
        after = _process_tree_rss_bytes()
        if after < int(target_bytes or 0):
            break
        time.sleep(0.2)
    collected = gc.collect()
    after = _process_tree_rss_bytes()
    return before, after, collected, killed


def _cleanup_stale_temp_user_data_dirs(emitter: Any) -> None:
    _cleanup_orphan_uc_processes(emitter, step="oauth_init")
    now = time.time()
    temp_root = Path(tempfile.gettempdir())
    removed_count = 0
    for candidate in temp_root.glob(f"{_UC_TEMP_DIR_PREFIX}*"):
        try:
            if not candidate.is_dir():
                continue
            candidate_str = str(candidate)
            with _ACTIVE_TEMP_USER_DATA_DIRS_LOCK:
                if candidate_str in _ACTIVE_TEMP_USER_DATA_DIRS:
                    continue
            age_seconds = max(0.0, now - candidate.stat().st_mtime)
            if age_seconds < _UC_STALE_DIR_TTL_SECONDS:
                continue
            shutil.rmtree(candidate_str, ignore_errors=True)
            if not candidate.exists():
                removed_count += 1
        except Exception:
            continue
    if removed_count > 0:
        try:
            emitter.info(f"启动前已清理 {removed_count} 个历史浏览器临时目录", step="oauth_init")
        except Exception:
            pass


def _seed_user_data_dir_profile(user_data_dir: str) -> None:
    """在临时 user-data-dir 中预写 Chrome profile 文件，模拟有使用历史的老浏览器。"""
    default_dir = os.path.join(user_data_dir, "Default")
    os.makedirs(default_dir, exist_ok=True)
    now_ts = int(time.time())
    install_age_days = random.randint(30, 180)
    install_ts = now_ts - install_age_days * 86400
    last_session_ts = now_ts - random.randint(3600, 86400)
    preferences = {
        "profile": {
            "last_engagement_time": str(last_session_ts * 1000000),
            "exit_type": "Normal",
            "exited_cleanly": True,
            "default_content_setting_values": {
                "notifications": 2,
                "geolocation": 2,
            },
            "password_manager_enabled": False,
            "creation_time": str(install_ts * 1000000),
            "name": "Person 1",
            "avatar_index": 0,
        },
        "session": {
            "restore_on_startup": 1,
        },
        "browser": {
            "has_seen_welcome_page": True,
            "check_default_browser": False,
            "should_reset_check_default_browser": False,
        },
        "credentials_enable_service": False,
        "credentials_enable_autosign_in": False,
        "autofill": {
            "profile_enabled": False,
            "credit_card_enabled": False,
        },
        "translate": {
            "enabled": False,
        },
        "search": {
            "suggest_enabled": False,
        },
        "safebrowsing": {
            "enabled": True,
            "enhanced": False,
        },
    }
    local_state = {
        "profile": {
            "info_cache": {
                "Default": {
                    "active_time": last_session_ts,
                    "name": "Person 1",
                    "is_using_default_name": True,
                }
            },
            "profiles_created": 1,
        },
        "browser": {
            "enabled_labs_experiments": [],
            "has_seen_welcome_page": True,
        },
        "user_experience_metrics": {
            "reporting_enabled": False,
        },
    }
    try:
        with open(os.path.join(default_dir, "Preferences"), "w", encoding="utf-8") as f:
            json.dump(preferences, f, separators=(",", ":"))
        with open(os.path.join(user_data_dir, "Local State"), "w", encoding="utf-8") as f:
            json.dump(local_state, f, separators=(",", ":"))
        first_run_path = os.path.join(user_data_dir, "First Run")
        with open(first_run_path, "w") as f:
            pass
    except Exception:
        pass


def _resolve_uc_user_data_dir(cfg: Dict[str, Any], emitter: Any) -> tuple[str, bool]:
    register_mode = str(cfg.get("register_mode") or "").strip().lower()
    temp_user_data_dir = tempfile.mkdtemp(prefix="opo_uc_")
    _register_active_temp_user_data_dir(temp_user_data_dir)
    _seed_user_data_dir_profile(temp_user_data_dir)
    return temp_user_data_dir, False


def _clear_browser_runtime_state(context: Any, page: Any, emitter: Any, *, hard_reset: bool = True) -> None:
    if not hard_reset:
        try:
            emitter.info("当前保留浏览器 Cookie/存储，仅清理缓存以尽量贴近真实浏览器环境", step="oauth_init")
        except Exception:
            pass
        try:
            cdp_session = context.new_cdp_session(page)
            try:
                cdp_session.send("Network.enable")
            except Exception:
                pass
            try:
                cdp_session.send("Network.clearBrowserCache")
            except Exception:
                pass
            try:
                cdp_session.detach()
            except Exception:
                pass
        except Exception:
            pass
        return
    try:
        context.clear_cookies()
    except Exception:
        pass
    try:
        page.goto("about:blank", wait_until="domcontentloaded", timeout=5000)
    except Exception:
        pass
    try:
        page.evaluate(
            """() => {
                try { localStorage.clear(); } catch {}
                try { sessionStorage.clear(); } catch {}
                try {
                    if (window.indexedDB && typeof indexedDB.databases === 'function') {
                        indexedDB.databases().then((dbs) => {
                            for (const db of dbs || []) {
                                if (db && db.name) {
                                    try { indexedDB.deleteDatabase(db.name); } catch {}
                                }
                            }
                        }).catch(() => {});
                    }
                } catch {}
            }"""
        )
    except Exception:
        pass
    try:
        cdp_session = context.new_cdp_session(page)
        try:
            cdp_session.send("Network.enable")
        except Exception:
            pass
        try:
            cdp_session.send("Network.clearBrowserCookies")
        except Exception:
            pass
        try:
            cdp_session.send("Network.clearBrowserCache")
        except Exception:
            pass
        try:
            cdp_session.detach()
        except Exception:
            pass
    except Exception:
        pass
    try:
        emitter.info("已重置当前浏览器会话的 Cookie/缓存/存储", step="oauth_init")
    except Exception:
        pass


def _resolve_browser_executable_path(cfg: Dict[str, Any], finder: Optional[Callable[[], Any]] = None) -> str:
    configured_path = str(cfg.get("browser_executable_path") or "").strip()
    if configured_path:
        return configured_path
    managed_path = _resolve_managed_browser_executable_path()
    if managed_path:
        return managed_path
    preferred_candidates: list[str] = []
    if sys.platform == "darwin":
        preferred_candidates.extend(
            [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ]
        )
    elif sys.platform.startswith("win"):
        preferred_candidates.extend(
            [
                str(Path(os.environ.get("PROGRAMFILES", "")) / "Google/Chrome/Application/chrome.exe"),
                str(Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Google/Chrome/Application/chrome.exe"),
            ]
        )
    else:
        preferred_candidates.extend(
            [
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
            ]
        )
    for candidate in preferred_candidates:
        path = str(candidate or "").strip()
        if path and os.path.exists(path):
            return path
    if not callable(finder):
        return ""
    try:
        return str(finder() or "").strip()
    except Exception:
        return ""


def _detect_browser_major_version(executable_path: str) -> Optional[int]:
    path = str(executable_path or "").strip()
    if not path:
        return None
    try:
        completed = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return None

    version_text = " ".join(
        item.strip()
        for item in (completed.stdout, completed.stderr)
        if str(item or "").strip()
    )
    match = re.search(r"(\d+)\.\d+\.\d+\.\d+", version_text)
    if not match:
        return None
    try:
        major_version = int(match.group(1))
    except (TypeError, ValueError):
        return None
    return major_version if major_version > 0 else None


def _detect_browser_full_version(executable_path: str) -> str:
    path = str(executable_path or "").strip()
    if not path:
        return ""
    try:
        completed = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return ""
    version_text = " ".join(
        item.strip()
        for item in (completed.stdout, completed.stderr)
        if str(item or "").strip()
    )
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", version_text)
    return str(match.group(1) if match else "").strip()


def _managed_chrome_for_testing_root() -> Path:
    env_value = str(os.environ.get("OPENAI_POOL_CFT_ROOT") or "").strip()
    if env_value:
        return Path(env_value).expanduser()
    return Path.home() / "Library/Application Support/openai_pool_orchestrator/chrome-for-testing"


def _version_sort_key(value: str) -> tuple[int, ...]:
    match = re.findall(r"\d+", str(value or ""))
    if not match:
        return (0,)
    return tuple(int(item) for item in match)


def _resolve_managed_browser_executable_path() -> str:
    root = _managed_chrome_for_testing_root()
    if not root.exists():
        return ""
    patterns: list[str] = []
    if sys.platform == "darwin":
        patterns.extend(
            [
                "*/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
                "*/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            ]
        )
    elif sys.platform.startswith("win"):
        patterns.extend(
            [
                "*/chrome-win64/chrome.exe",
                "*/chrome-win32/chrome.exe",
            ]
        )
    else:
        patterns.extend(
            [
                "*/chrome-linux64/chrome",
            ]
        )
    candidates: list[Path] = []
    for pattern in patterns:
        try:
            candidates.extend(root.glob(pattern))
        except Exception:
            continue
    valid_candidates = [item for item in candidates if item.exists()]
    if not valid_candidates:
        return ""
    valid_candidates.sort(key=lambda item: _version_sort_key(item.parts[-6] if sys.platform == "darwin" else item.parts[-3]), reverse=True)
    return str(valid_candidates[0])


def _resolve_managed_driver_executable_path(
    browser_executable_path: str,
    browser_major_version: Optional[int],
) -> str:
    executable = str(browser_executable_path or "").strip()
    if not executable:
        return ""
    root = _managed_chrome_for_testing_root()
    if not root.exists():
        return ""
    candidate_base = None
    try:
        resolved = Path(executable).resolve()
    except Exception:
        resolved = Path(executable)
    for parent in resolved.parents:
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parent.name):
            candidate_base = parent
            break
    if candidate_base is None or root not in candidate_base.parents:
        return ""
    driver_candidates: list[Path] = []
    if sys.platform == "darwin":
        driver_candidates.extend(
            [
                candidate_base / "chromedriver-mac-arm64" / "chromedriver",
                candidate_base / "chromedriver-mac-x64" / "chromedriver",
            ]
        )
    elif sys.platform.startswith("win"):
        driver_candidates.extend(
            [
                candidate_base / "chromedriver-win64" / "chromedriver.exe",
                candidate_base / "chromedriver-win32" / "chromedriver.exe",
            ]
        )
    else:
        driver_candidates.extend(
            [
                candidate_base / "chromedriver-linux64" / "chromedriver",
            ]
        )
    for candidate in driver_candidates:
        if not candidate.exists():
            continue
        driver_version = _detect_browser_major_version(str(candidate))
        if browser_major_version is None or driver_version is None or driver_version == browser_major_version:
            return str(candidate)
    return ""


def _build_browser_context_kwargs(ctx: BrowserRunContext, cfg: Dict[str, Any]) -> Dict[str, Any]:
    profile = ctx.fingerprint_profile
    context_kwargs: Dict[str, Any] = {
        "ignore_https_errors": True,
        "user_agent": ctx.user_agent,
        "locale": str(profile.locale or cfg["browser_locale"] or "en-US"),
        "timezone_id": str(profile.timezone_id or cfg["browser_timezone"] or "America/New_York"),
    }
    if cfg["browser_headless"]:
        context_kwargs["viewport"] = {"width": profile.viewport_width, "height": profile.viewport_height}
    else:
        context_kwargs["no_viewport"] = True
    return context_kwargs


def _launch_via_local_uc_bridge(playwright: Any, ctx: BrowserRunContext, cfg: Dict[str, Any]) -> BrowserLaunchResources:
    uc, uc_path = _load_local_uc()
    profile = ctx.fingerprint_profile
    _cleanup_stale_temp_user_data_dirs(ctx.emitter)
    temp_user_data_dir, persistent_user_data_dir = _resolve_uc_user_data_dir(cfg, ctx.emitter)
    cdp_driver = None
    browser = None
    context = None
    try:
        options = uc.ChromeOptions()
        if cfg["browser_headless"]:
            options.add_argument("--headless=new")
        options.add_argument(f"--window-size={profile.screen_width},{profile.screen_height}")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--no-first-run")
        options.add_argument("--no-default-browser-check")
        options.add_argument("--ignore-certificate-errors")
        # 注册流程只需一个页面；关闭浏览器后台服务和过多 renderer，降低单轮原生内存。
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-background-networking")
        options.add_argument("--disable-component-update")
        options.add_argument("--disable-sync")
        options.add_argument("--no-pings")
        options.add_argument("--renderer-process-limit=4")
        if cfg["browser_headless"]:
            options.add_argument("--disable-gpu")
        if cfg.get("browser_realistic_profile", True):
            options.add_argument("--disable-features=ImprovedCookieControls,ThirdPartyStoragePartitioning,BlockThirdPartyCookies")
        options.add_argument("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
        options.add_argument("--webrtc-ip-handling-policy=disable_non_proxied_udp")
        options.add_argument("--enforce-webrtc-ip-permission-check")
        options.add_argument(f"--user-data-dir={temp_user_data_dir}")
        try:
            fake_engagement_time = int(time.time()) - random.randint(7, 30) * 24 * 60 * 60
            options.add_experimental_option(
                "prefs",
                {
                    "webrtc.ip_handling_policy": "disable_non_proxied_udp",
                    "webrtc.multiple_routes_enabled": False,
                    "webrtc.nonproxied_udp_enabled": False,
                    "profile.default_content_setting_values.cookies": 1,
                    "profile.block_third_party_cookies": False if cfg.get("browser_realistic_profile", True) else True,
                    "profile.cookie_controls_mode": 0 if cfg.get("browser_realistic_profile", True) else 1,
                    "profile.default_content_setting_values.popups": 1,
                    "profile.default_content_setting_values.notifications": 2,
                    "profile.default_content_setting_values.geolocation": 2,
                    "profile.password_manager_enabled": False,
                    "profile.last_engagement_time": fake_engagement_time,
                    "profile.exit_type": "Normal",
                    "profile.exited_cleanly": True,
                    "session.restore_on_startup": 1,
                    "intl.accept_languages": str(profile.accept_language or "en-US,en"),
                    "credentials_enable_service": False,
                    "credentials_enable_autosign_in": False,
                },
            )
        except Exception:
            pass
        if ctx.user_agent:
            options.add_argument(f"--user-agent={ctx.user_agent}")
        locale = str(profile.locale or cfg.get("browser_locale") or "").strip()
        if locale:
            options.add_argument(f"--lang={locale}")
        if ctx.proxy:
            options.add_argument(f"--proxy-server={ctx.proxy}")
        executable_path = _resolve_browser_executable_path(cfg, getattr(uc, "find_chrome_executable", None))
        if executable_path:
            options.binary_location = executable_path
            browser_full_version = _detect_browser_full_version(executable_path)
            try:
                ctx.emitter.info(
                    "浏览器可执行文件: "
                    + f"path={_mask_secret(executable_path, head=40, tail=24)}, "
                    + f"version={browser_full_version or '-'}",
                    step="oauth_init",
                )
            except Exception:
                pass
        browser_major_version = _detect_browser_major_version(executable_path)

        driver_kwargs: Dict[str, Any] = {
            "options": options,
            "use_subprocess": True,
        }
        if executable_path:
            driver_kwargs["browser_executable_path"] = executable_path
            managed_driver_path = _resolve_managed_driver_executable_path(executable_path, browser_major_version)
            if managed_driver_path:
                driver_kwargs["driver_executable_path"] = managed_driver_path
                try:
                    ctx.emitter.info(
                        "命中本地 Chrome for Testing 驱动缓存: "
                        + _mask_secret(managed_driver_path, head=40, tail=24),
                        step="oauth_init",
                    )
                except Exception:
                    pass
        if browser_major_version is not None:
            driver_kwargs["version_main"] = browser_major_version
            try:
                ctx.emitter.info(
                    f"检测到本机 Chrome 主版本 {browser_major_version}，将匹配对应 ChromeDriver",
                    step="oauth_init",
                )
            except Exception:
                pass
        driver_prepare_started_at = time.time()
        try:
            ctx.emitter.info("开始准备本地 Chromedriver（检查缓存/下载/补丁）...", step="oauth_init")
        except Exception:
            pass
        cdp_driver = uc.Chrome(**driver_kwargs)
        try:
            ctx.emitter.info(
                f"本地 Chromedriver 已就绪，耗时 {time.time() - driver_prepare_started_at:.1f}s",
                step="oauth_init",
            )
        except Exception:
            pass
        endpoint_url = _resolve_cdp_endpoint(cdp_driver)
        cdp_connect_started_at = time.time()
        try:
            ctx.emitter.info("正在连接浏览器 CDP 会话...", step="oauth_init")
        except Exception:
            pass
        browser = playwright.chromium.connect_over_cdp(
            endpoint_url,
            timeout=cfg["browser_timeout_ms"],
            slow_mo=int(cfg["browser_slow_mo_ms"]),
        )
        try:
            ctx.emitter.info(
                f"浏览器 CDP 连接完成，耗时 {time.time() - cdp_connect_started_at:.1f}s",
                step="oauth_init",
            )
        except Exception:
            pass
        contexts = list(getattr(browser, "contexts", []) or [])
        if contexts:
            context = contexts[0]
            launch_mode_detail = "temp-profile+primary-context"
        else:
            launch_mode_detail = "temp-profile+created-context"
            context_kwargs = _build_browser_context_kwargs(ctx, cfg)
            try:
                context = browser.new_context(**context_kwargs)
            except Exception as exc:
                raise RuntimeError(f"创建浏览器上下文失败: {exc}") from exc
        pages = list(getattr(context, "pages", []) or [])
        page = pages[0] if pages else context.new_page()
        _clear_browser_runtime_state(
            context,
            page,
            ctx.emitter,
            hard_reset=bool(cfg.get("browser_clear_runtime_state", False)),
        )
        return BrowserLaunchResources(
            browser=browser,
            context=context,
            page=page,
            cdp_driver=cdp_driver,
            temp_user_data_dir=temp_user_data_dir,
            persistent_user_data_dir=persistent_user_data_dir,
            launch_mode=f"uc-bridge:{uc_path}:{launch_mode_detail}",
            owner_thread_id=threading.get_ident(),
        )
    except Exception:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if cdp_driver is not None:
            try:
                cdp_driver.quit()
            except Exception:
                pass
        _unregister_active_temp_user_data_dir(temp_user_data_dir)
        if not persistent_user_data_dir:
            shutil.rmtree(temp_user_data_dir, ignore_errors=True)
        raise


def _launch_via_roxy(playwright: Any, ctx: BrowserRunContext, cfg: Dict[str, Any]) -> BrowserLaunchResources:
    """用 RoxyBrowser 打开指纹窗口，再让 Playwright 通过 CDP 附着。

    指纹与 UA 全部交给 Roxy，本项目不再注入自建指纹（两套叠加反而会露馅）。
    """
    try:
        from .roxy_browser import RoxyClient, RoxyBrowserError, wait_cdp_ready
    except ImportError:  # pragma: no cover - 兼容以脚本方式直接运行
        from roxy_browser import RoxyClient, RoxyBrowserError, wait_cdp_ready  # type: ignore

    client, settings = RoxyClient.from_config(cfg)
    profile_id = settings["profile_id"]
    workspace_id = settings["workspace_id"]
    browser = None

    try:
        # 复用同一个资料，先把上一轮可能残留的窗口关掉
        try:
            client.close_browser(profile_id)
            time.sleep(0.6)
        except RoxyBrowserError as exc:
            ctx.emitter.info(f"Roxy 关闭残留窗口失败（忽略）: {exc}", step="oauth_init")

        if cfg.get("roxy_apply_proxy", True):
            proxy_info = client.modify_proxy(workspace_id, profile_id, ctx.proxy)
            if proxy_info.get("proxyCategory") == "noproxy":
                ctx.emitter.info("Roxy 资料已设为直连（本次未分配代理）", step="oauth_init")
            else:
                ctx.emitter.info(
                    "Roxy 资料代理已更新: "
                    + f"{proxy_info.get('protocol')} {proxy_info.get('host')}:{proxy_info.get('port')}",
                    step="oauth_init",
                )

        if cfg.get("roxy_clear_cache", True):
            # 单窗口串行注册复用同一资料，不清缓存会带着上一个号的 cookie
            client.clear_local_cache(workspace_id, profile_id)
            ctx.emitter.info("Roxy 本地缓存已清理", step="oauth_init")

        if cfg.get("roxy_random_fingerprint", True):
            client.random_fingerprint(workspace_id, profile_id)
            ctx.emitter.info("Roxy 资料指纹已随机化", step="oauth_init")

        headless = bool(cfg.get("browser_headless", False))
        open_started_at = time.time()
        ctx.emitter.info(
            f"正在通过 Roxy 打开资料 {_mask_secret(profile_id, head=8, tail=4)} "
            + f"（{'无头' if headless else '有头'}）...",
            step="oauth_init",
        )
        if headless:
            ctx.emitter.info("Roxy 无头模式下 Turnstile 通过率偏低，失败偏多时建议改回有头", step="oauth_init")
        data = client.open_browser(profile_id=profile_id, headless=headless)
        ws_url = str(data.get("ws") or "").strip()
        http_address = str(data.get("http") or "").strip()
        ctx.emitter.info(
            f"Roxy 窗口已启动，耗时 {time.time() - open_started_at:.1f}s，"
            + f"内核 {data.get('coreVersion') or '-'}",
            step="oauth_init",
        )

        endpoint_source = ws_url or http_address
        # 无头启动比有头慢，version 接口就绪也更晚，等待下限相应放宽
        addr = wait_cdp_ready(
            endpoint_source,
            timeout_sec=max(25.0 if headless else 10.0, float(cfg["browser_timeout_ms"]) / 1000.0),
            log=lambda message: ctx.emitter.info(message, step="oauth_init"),
        )
        # ws 地址带 browser 级会话标识，比 http 更直接；拿不到再退回 http
        endpoint_url = ws_url if ws_url.startswith("ws") else f"http://{addr}"

        cdp_connect_started_at = time.time()
        browser = playwright.chromium.connect_over_cdp(
            endpoint_url,
            timeout=cfg["browser_timeout_ms"],
            slow_mo=int(cfg["browser_slow_mo_ms"]),
        )
        ctx.emitter.info(
            f"Roxy CDP 连接完成，耗时 {time.time() - cdp_connect_started_at:.1f}s",
            step="oauth_init",
        )

        contexts = list(getattr(browser, "contexts", []) or [])
        if not contexts:
            raise RuntimeError("Roxy 窗口未提供可用的浏览器上下文")
        context = contexts[0]
        pages = list(getattr(context, "pages", []) or [])
        page = pages[0] if pages else context.new_page()
        _clear_browser_runtime_state(
            context,
            page,
            ctx.emitter,
            hard_reset=bool(cfg.get("browser_clear_runtime_state", False)),
        )
        return BrowserLaunchResources(
            browser=browser,
            context=context,
            page=page,
            launch_mode=f"roxy:{profile_id}",
            owner_thread_id=threading.get_ident(),
            roxy_client=client,
            roxy_profile_id=profile_id,
        )
    except Exception:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        try:
            client.close_browser(profile_id)
        except Exception:
            pass
        raise


def run_browser_registration(
    *,
    email: str,
    dev_token: str,
    emitter: Any,
    stop_event: Any,
    mail_provider: Any,
    proxy: str,
    browser_config: Optional[Dict[str, Any]],
    user_agent: str,
    fingerprint_profile: FingerprintProfile,
    generate_oauth_url_func: Callable[[], Any],
    generate_login_oauth_url_func: Callable[[], Any],
    submit_callback_func: Callable[..., str],
    exchange_callback_payload_func: Optional[Callable[..., Dict[str, Any]]] = None,
    build_token_result_func: Optional[Callable[..., str]] = None,
    build_browser_session_token_func: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
    fallback_wait_for_otp_func: Optional[Callable[..., str]] = None,
    wait_manual_phone_input_func: Optional[Callable[..., str]] = None,
    wait_manual_sms_code_input_func: Optional[Callable[..., str]] = None,
    wait_manual_email_input_func: Optional[Callable[..., str]] = None,
    wait_manual_email_code_input_func: Optional[Callable[..., str]] = None,
    sms_provider: Optional[Any] = None,
    random_password_func: Optional[Callable[[int], str]] = None,
    random_profile_name_func: Optional[Callable[[], str]] = None,
    random_profile_birthdate_func: Optional[Callable[[], str]] = None,
) -> Optional[str]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(f"未安装 Playwright 或浏览器驱动不可用: {exc}") from exc

    _cleanup_preserved_browser_resources(
        emitter,
        owner_thread_id=threading.get_ident(),
    )
    _cleanup_stale_temp_user_data_dirs(emitter)

    cfg = normalize_browser_config(browser_config)
    _, memory_soft_limit, memory_hard_limit = _browser_memory_thresholds()
    startup_rss = _process_tree_rss_bytes()
    if startup_rss >= memory_soft_limit:
        before_rss, after_rss, collected = _release_memory_pressure(emitter)
        emitter.warn(
            "启动浏览器前检测到进程内存偏高，已清理历史浏览器现场/页面快照并执行垃圾回收："
            + f"before={before_rss / 1024 / 1024:.0f}MB, after={after_rss / 1024 / 1024:.0f}MB, gc={collected}",
            step="memory",
        )
        if after_rss >= memory_hard_limit:
            raise RuntimeError(
                "进程内存仍接近 PM2 上限，已阻止启动新的浏览器任务；"
                + f"rss={after_rss / 1024 / 1024:.0f}MB, hard_limit={memory_hard_limit / 1024 / 1024:.0f}MB"
            )
    current_oauth = generate_oauth_url_func()
    current_phase = "signup"
    account_password = (
        random_password_func(16)
        if callable(random_password_func)
        else f"Pwd!{random.randint(100000, 999999)}Aa"
    )
    profile_name = random_profile_name_func() if callable(random_profile_name_func) else "Emma White"
    profile_birthdate = (
        random_profile_birthdate_func() if callable(random_profile_birthdate_func) else "1998-08-18"
    )
    ctx = BrowserRunContext(
        email=email,
        dev_token=dev_token,
        account_password=account_password,
        profile_name=profile_name,
        profile_birthdate=profile_birthdate,
        proxy=str(proxy or "").strip(),
        browser_config=cfg,
        mail_provider=mail_provider,
        emitter=emitter,
        stop_event=stop_event,
        user_agent=user_agent,
        fingerprint_profile=fingerprint_profile,
        fallback_wait_for_otp_func=fallback_wait_for_otp_func,
    )
    callback_state: Dict[str, str] = {"url": ""}
    loopback_callback_hub = _ensure_loopback_callback_hub(
        str(getattr(current_oauth, "redirect_uri", "") or ""),
        emitter,
    )
    otp_wait_started = False
    otp_page_ready_logged = False
    otp_initial_send_triggered = False
    profile_submitted = False
    email_submitted = False
    password_submitted = False
    tried_otp_codes: set[str] = set()
    otp_code_submit_attempts: Dict[str, int] = {}
    browser_session_fast_path_attempts = 0
    session_recover_attempts = 0
    timeout_recover_attempts = 0
    rate_limit_recover_attempts = 0
    login_add_phone_retry_attempts = 0
    login_add_phone_retry_limit = 3
    register_mode = str(cfg.get("register_mode") or "browser").strip().lower()
    is_manual_mode = register_mode == "browser_manual"
    is_manual_v2_mode = register_mode == "browser_manual_v2"
    manual_v2_expected_auto_phone_mode = (
        is_manual_v2_mode
        and str(cfg.get("browser_manual_v2_phone_mode") or "").strip().lower() in {"hero_sms", "smsbower"}
    )
    manual_v2_auto_phone_mode_name = str(cfg.get("browser_manual_v2_phone_mode") or "").strip().lower()
    manual_v2_auto_phone_provider_label = HANDLER_API_PROVIDER_LABELS.get(manual_v2_auto_phone_mode_name, "短信平台")
    manual_v2_email_mode = (
        _normalize_manual_v2_email_mode(cfg.get("browser_manual_v2_email_mode", "auto"))
        if is_manual_v2_mode
        else "auto"
    )
    manual_v2_manual_restart_on_enter_password = (
        is_manual_v2_mode
        and not manual_v2_expected_auto_phone_mode
        and bool(cfg.get("browser_manual_v2_manual_restart_on_enter_password", False))
    )
    manual_v2_auto_phone_mode = (
        manual_v2_expected_auto_phone_mode
        and sms_provider is not None
    )
    manual_v2_hidden_input_mode = is_manual_v2_mode and bool(cfg.get("browser_headless", False))
    manual_v2_phone_panel_input_mode = (
        is_manual_v2_mode
        and not manual_v2_expected_auto_phone_mode
        and callable(wait_manual_phone_input_func)
    )
    manual_v2_sms_panel_input_mode = (
        is_manual_v2_mode
        and not manual_v2_expected_auto_phone_mode
        and callable(wait_manual_sms_code_input_func)
    )
    manual_v2_manual_email_mode = (
        is_manual_v2_mode
        and manual_v2_email_mode == "manual"
    )
    manual_v2_email_panel_input_mode = (
        manual_v2_manual_email_mode
        and callable(wait_manual_email_input_func)
    )
    manual_v2_email_code_panel_input_mode = (
        manual_v2_manual_email_mode
        and callable(wait_manual_email_code_input_func)
    )
    # Roxy 自带平台侧指纹，再叠加自建指纹会让 UA 与 navigator 对不上，反而更易被识别
    use_plain_browser_env = cfg.get("browser_engine") == "roxy"
    otp_wait_timeout_seconds = 20
    otp_max_resend_attempts = 20
    otp_same_code_retry_limit = 2
    otp_resend_attempts = 0
    wired_page_ids: set[int] = set()
    recent_network_events = deque(maxlen=40)
    manual_v2_login_oauth = None
    manual_v2_phone_number = ""
    manual_v2_sms_activation_id = ""
    manual_v2_sms_provider_done = False
    manual_v2_sms_purchased_at = 0.0
    manual_v2_sms_country_id: Any = None
    manual_v2_sms_country_iso = ""
    manual_v2_sms_country_name = ""
    manual_v2_sms_country_result_recorded = False
    manual_v2_cached_sms_code = ""
    manual_v2_contact_network_seen = False
    manual_v2_wait_phone_logged = False
    manual_v2_wait_contact_logged = False
    manual_v2_contact_transition_last_key = ""
    manual_v2_contact_seen = False
    manual_v2_sms_code_submitted = False
    manual_v2_login_flow_started = False
    manual_v2_phone_entry_clicked = False
    manual_v2_login_phone_prefilled = False
    manual_v2_login_phone_submitted = False
    manual_v2_login_password_prefilled = False
    manual_v2_post_login_pending_email = False
    manual_v2_bridge_entered_at = 0.0
    manual_v2_bridge_logged = False
    manual_v2_post_login_recover_attempts = 0
    manual_v2_post_login_retryable_error_attempts = 0
    manual_v2_post_login_oauth_retry_attempts = 0
    manual_v2_post_login_oauth_retry_limit = 2
    manual_v2_email_verification_recover_attempts = 0
    manual_v2_email_verification_logged = False
    manual_v2_email_otp_completed = False
    manual_v2_oauth_resumed = False
    manual_v2_workspace_logged = False
    manual_v2_profile_completion_mode = False
    manual_v2_waiting_phone_retry = False
    manual_v2_waiting_phone_retry_logged = False
    manual_v2_require_phone_resubmit = False
    manual_v2_password_page_logged = False
    manual_v2_create_password_submit_attempts = 0
    manual_v2_phone_submit_stall_attempts = 0
    manual_v2_wait_phone_last_url = ""
    manual_v2_entry_bootstrap_logged = False
    manual_v2_entry_unavailable_since = 0.0
    manual_v2_entry_fallback_attempts = 0
    manual_v2_reset_password_flow_started = False
    manual_v2_reset_password_continue_clicked = False

    def _record_callback(candidate_url: str) -> None:
        value = str(candidate_url or "").strip()
        if value and "code=" in value and "state=" in value:
            callback_state["url"] = value

    def _active_oauth_start() -> Any:
        if is_manual_v2_mode and manual_v2_login_flow_started and manual_v2_login_oauth is not None:
            return manual_v2_login_oauth
        return current_oauth

    def _consume_loopback_callback() -> str:
        if loopback_callback_hub is None:
            return ""
        oauth_start = _active_oauth_start()
        expected_state = str(getattr(oauth_start, "state", "") or "").strip()
        if not expected_state:
            return ""
        callback_url = loopback_callback_hub.pop_callback(expected_state)
        if callback_url:
            _record_callback(callback_url)
        return callback_url

    def _extract_callback_url_from_page(current_url: str, body_text: str) -> str:
        oauth_start = _active_oauth_start()
        redirect_base = str(getattr(oauth_start, "redirect_uri", "") or "").strip()
        if not redirect_base:
            return ""
        direct_url = str(current_url or "").strip()
        if direct_url.startswith(redirect_base) and "code=" in direct_url and "state=" in direct_url:
            return direct_url
        body = str(body_text or "").strip()
        if not body:
            return ""
        pattern = re.escape(redirect_base) + r'[^\s"\'<>)]+'
        match = re.search(pattern, body)
        if not match:
            return ""
        candidate = str(match.group(0) or "").strip()
        return candidate if ("code=" in candidate and "state=" in candidate) else ""

    def _handle_route(route: Any) -> None:
        request = route.request
        request_url = str(getattr(request, "url", "") or "").strip()
        oauth_start = _active_oauth_start()
        if request_url.startswith(str(getattr(oauth_start, "redirect_uri", "") or "").strip()):
            _record_callback(request_url)
            route.fulfill(
                status=200,
                content_type="text/html",
                body="<html><body>callback captured</body></html>",
            )
            return
        if cfg.get("browser_block_media", True):
            resource_type = str(getattr(request, "resource_type", "") or "").strip().lower()
            if resource_type in {"image", "font", "media"}:
                route.abort()
                return
        route.continue_()

    def _wire_page(page: Any) -> None:
        page.set_default_timeout(cfg["browser_timeout_ms"])
        page.on(
            "framenavigated",
            lambda frame: _record_callback(str(getattr(frame, "url", "") or "").strip()),
        )
        page.on(
            "request",
            lambda request: (
                _record_callback(str(getattr(request, "url", "") or "").strip()),
                recent_network_events.append(
                    {
                        "event": "request",
                        "method": str(getattr(request, "method", "") or "").strip(),
                        "ts": time.time(),
                        "url": str(getattr(request, "url", "") or "").strip(),
                    }
                )
                if any(
                    token in str(getattr(request, "url", "") or "").lower()
                    for token in ("auth.openai.com", "chatgpt.com/auth/login_with", "email-verification", "add-email", "verify")
                )
                else None
            ),
        )
        page.on(
            "requestfailed",
            lambda request: (
                _record_callback(str(getattr(request, "url", "") or "").strip()),
                recent_network_events.append(
                    {
                        "event": "requestfailed",
                        "method": str(getattr(request, "method", "") or "").strip(),
                        "ts": time.time(),
                        "url": str(getattr(request, "url", "") or "").strip(),
                    }
                )
                if any(
                    token in str(getattr(request, "url", "") or "").lower()
                    for token in ("auth.openai.com", "chatgpt.com/auth/login_with", "email-verification", "add-email", "verify")
                )
                else None
            ),
        )
        page.on(
            "response",
            lambda response: (
                _record_callback(str(getattr(response, "url", "") or "").strip()),
                recent_network_events.append(
                    {
                        "event": "response",
                        "method": str(getattr(getattr(response, "request", None), "method", lambda: "")() if callable(getattr(getattr(response, "request", None), "method", None)) else getattr(getattr(response, "request", None), "method", "") or "").strip(),
                        "status": str(getattr(response, "status", "") or "").strip(),
                        "ts": time.time(),
                        "url": str(getattr(response, "url", "") or "").strip(),
                    }
                )
                if any(
                    token in str(getattr(response, "url", "") or "").lower()
                    for token in ("auth.openai.com", "chatgpt.com/auth/login_with", "email-verification", "add-email", "verify")
                )
                else None
            ),
        )

    def _wire_page_once(candidate_page: Any) -> None:
        if candidate_page is None:
            return
        candidate_id = id(candidate_page)
        if candidate_id in wired_page_ids:
            return
        wired_page_ids.add(candidate_id)
        _wire_page(candidate_page)

    def _page_is_usable(candidate_page: Any) -> bool:
        if candidate_page is None:
            return False
        try:
            is_closed = getattr(candidate_page, "is_closed", None)
            if callable(is_closed):
                return not bool(is_closed())
        except Exception:
            return False
        return True

    def _scan_context_pages_for_callback() -> bool:
        try:
            context_pages = list(getattr(context, "pages", []) or [])
        except Exception:
            context_pages = []
        for candidate_page in context_pages:
            if not _page_is_usable(candidate_page):
                continue
            try:
                # 活动页选择阶段只读本地 URL；正文/控件探测可能触发 CDP 等待，交给主循环处理。
                candidate_url = str(candidate_page.url or "").strip()
            except Exception:
                continue
            if "code=" in str(candidate_url or "").lower() and "state=" in str(candidate_url or "").lower():
                _record_callback(candidate_url)
            if callback_state["url"]:
                return True
        return bool(callback_state["url"])

    def _resolve_active_page(
        preferred_page: Any = None,
        *,
        timeout_ms: int = 0,
    ) -> Any:
        nonlocal page
        deadline_local = time.time() + max(0.0, float(timeout_ms or 0) / 1000.0)
        while True:
            candidates: list[Any] = []
            if preferred_page is not None:
                candidates.append(preferred_page)
            _touch_browser_watchdog("活动页选择/枚举页面")
            try:
                context_pages = list(getattr(context, "pages", []) or [])
            except Exception:
                context_pages = []
            candidates.extend(reversed(context_pages))
            seen_ids: set[int] = set()
            selected_page = None
            selected_rank: tuple[int, int] | None = None
            for candidate_page in candidates:
                if candidate_page is None:
                    continue
                candidate_id = id(candidate_page)
                if candidate_id in seen_ids:
                    continue
                seen_ids.add(candidate_id)
                if not _page_is_usable(candidate_page):
                    continue
                _wire_page_once(candidate_page)
                _touch_browser_watchdog("活动页选择/读取页面状态")
                try:
                    candidate_url = str(candidate_page.url or "").strip()
                except Exception:
                    candidate_url = ""
                score = _page_priority_from_url(candidate_url)
                candidate_url_lower = candidate_url.lower()
                # 只按 URL/句柄选择活动页；正文和控件状态留给主循环一次性判断。
                if preferred_page is not None and candidate_page is preferred_page:
                    score += 3
                if page is not None and candidate_page is page:
                    score += 2
                if "auth.openai.com" in candidate_url_lower:
                    score += 2
                rank = (score, -len(seen_ids))
                if selected_page is None or selected_rank is None or rank > selected_rank:
                    selected_page = candidate_page
                    selected_rank = rank
            if selected_page is not None:
                page = selected_page
                _scan_context_pages_for_callback()
                return selected_page
            if _scan_context_pages_for_callback() or time.time() >= deadline_local:
                return None
            time.sleep(0.2)

    def _page_navigation_debug_summary(candidate_page: Any = None) -> str:
        target_page = candidate_page if candidate_page is not None else page
        try:
            context_pages = list(getattr(context, "pages", []) or [])
        except Exception:
            context_pages = []
        is_closed = False
        if target_page is None:
            is_closed = True
        else:
            try:
                is_closed_fn = getattr(target_page, "is_closed", None)
                if callable(is_closed_fn):
                    is_closed = bool(is_closed_fn())
            except Exception:
                is_closed = True
        try:
            current_url = str(getattr(target_page, "url", "") or "").strip()
        except Exception:
            current_url = ""
        return (
            f"is_closed={'是' if is_closed else '否'}, "
            + f"context_pages={len(context_pages)}, "
            + f"current_url={_mask_secret(current_url, head=64, tail=16) if current_url else '-'}"
        )

    def _ensure_navigable_page(*, step: str, reason: str, timeout_ms: int = 1500) -> Any:
        nonlocal page
        active_page = _resolve_active_page(page, timeout_ms=timeout_ms)
        if active_page is not None:
            page = active_page
            return active_page
        emitter.warn(
            f"{reason}；当前页面句柄不可用，准备创建新页面继续。{_page_navigation_debug_summary(page)}",
            step=step,
        )
        try:
            fresh_page = context.new_page()
        except Exception as exc:
            raise RuntimeError(f"{reason}；当前页面句柄不可用，且创建新页面失败: {exc}") from exc
        _wire_page_once(fresh_page)
        page = fresh_page
        return fresh_page

    def _goto_with_recovery(
        target_url: str,
        *,
        step: str,
        reason: str,
        wait_until: str = "domcontentloaded",
        timeout_ms: Optional[int] = None,
        max_attempts: int = 2,
    ) -> Any:
        nonlocal page
        url = str(target_url or "").strip()
        if not url:
            raise RuntimeError(f"{reason}；目标 URL 为空")
        last_exc: Optional[Exception] = None
        total_attempts = max(1, int(max_attempts or 1))
        for attempt in range(1, total_attempts + 1):
            _touch_browser_watchdog(f"{step}/导航第 {attempt} 次")
            nav_page = _ensure_navigable_page(step=step, reason=reason, timeout_ms=1500)
            try:
                nav_page.goto(
                    url,
                    wait_until=wait_until,
                    timeout=int(timeout_ms or cfg["browser_timeout_ms"]),
                )
                page = nav_page
                return nav_page
            except Exception as exc:
                last_exc = exc
                message = str(exc or "")
                tls_like_recoverable = (
                    "net::ERR_SSL_PROTOCOL_ERROR" in message
                    or "net::ERR_HTTP2_PROTOCOL_ERROR" in message
                    or "net::ERR_QUIC_PROTOCOL_ERROR" in message
                    or "net::ERR_CONNECTION_RESET" in message
                    or "net::ERR_CONNECTION_CLOSED" in message
                )
                recoverable = (
                    "Target page, context or browser has been closed" in message
                    or "net::ERR_ABORTED" in message
                    or tls_like_recoverable
                )
                if not recoverable or attempt >= total_attempts:
                    raise
                emitter.warn(
                    f"{reason}；第 {attempt}/{total_attempts} 次导航异常，准备自动恢复后重试: {message}. "
                    + _page_navigation_debug_summary(nav_page),
                    step=step,
                )
                if "Target page, context or browser has been closed" in message or tls_like_recoverable:
                    page = None
                _sleep_with_page(None, 700 if tls_like_recoverable else 350)
        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"{reason}；导航失败且未返回具体异常")

    def _start_oauth_flow(page: Any, oauth_start: Any, phase: str) -> None:
        if phase == "login":
            emitter.info("浏览器注册阶段已结束，正在当前浏览器窗口重新拉起登录流程获取 Token...", step="oauth_init")
        else:
            emitter.info("正在当前浏览器窗口启动注册流程...", step="oauth_init")
        page = _goto_with_recovery(
            str(oauth_start.auth_url),
            step="oauth_init",
            reason="浏览器 OAuth 导航失败",
            wait_until="domcontentloaded",
            timeout_ms=cfg["browser_timeout_ms"],
        )
        _wait_for_load(page, timeout_ms=2500)
        emitter.info(
            f"浏览器{('登录' if phase == 'login' else '注册')}流程落点: {_mask_secret(page.url, head=48, tail=12)}",
            step="oauth_init",
        )
        if not cfg["browser_headless"]:
            emitter.info("当前为可见浏览器模式，可直接观察页面流程用于排查", step="oauth_init")

    def _goto_manual_v2_phone_auth_entry(*, reason: str, prefer_login: bool = False) -> bool:
        """点击失败或点了没跳转时，直接走手机号登录/注册入口 URL（步骤1/补资料共用）。"""
        _touch_browser_watchdog("手机号入口直链兜底")
        candidates = []
        try:
            for frame in _iter_page_targets(page):
                try:
                    loc = frame.locator(
                        'a[data-auth-provider="phone"], a[href*="usernameKind=phone"], a._X60mza_providerButton'
                    )
                except Exception:
                    loc = None
                if loc is not None:
                    item = loc.first
                    try:
                        href = (
                            str(item.get_attribute("href", timeout=300) or "").strip()
                            if item.is_visible(timeout=300)
                            else ""
                        )
                    except Exception:
                        href = ""
                    if href:
                        candidates.append(href)
                if candidates:
                    break
        except Exception:
            pass
        if prefer_login:
            candidates.extend(
                [
                    "https://chatgpt.com/auth/login?usernameKind=phone_number",
                    "https://chatgpt.com/auth/login?next=%2F&usernameKind=phone_number",
                    "https://auth.openai.com/log-in",
                ]
            )
        else:
            candidates.extend(
                [
                    "https://chatgpt.com/auth/login?usernameKind=phone_number",
                    "https://chatgpt.com/auth/login?next=%2F&usernameKind=phone_number",
                    "https://chatgpt.com/auth/login?screen_hint=signup&usernameKind=phone_number",
                ]
            )
        seen = set()
        for url in candidates:
            target = str(url or "").strip()
            if not target or target in seen:
                continue
            seen.add(target)
            try:
                emitter.info(
                    f"浏览器模式2 {reason}，改用手机号入口直链: {_mask_secret(target, head=72, tail=24)}",
                    step="oauth_init",
                )
                _goto_with_recovery(
                    target,
                    step="oauth_init",
                    reason="浏览器模式2 打开手机号入口直链失败",
                    wait_until="domcontentloaded",
                    timeout_ms=min(20000, int(cfg.get("browser_timeout_ms") or 20000)),
                    max_attempts=2,
                )
                _wait_for_load(page, timeout_ms=2500)
                latest_url, latest_body = _describe_page(page, force_refresh=True)
                latest_lower = str(latest_url or "").lower()
                if (
                    _has_phone_input(page)
                    or "auth.openai.com" in latest_lower
                    or "chatgpt.com/auth/" in latest_lower
                    or _is_phone_input_page(latest_url, latest_body, page)
                    or _is_login_password_page(latest_url, latest_body, page)
                    or _is_create_account_password_page(latest_url, latest_body, page)
                ):
                    emitter.info("浏览器模式2 已通过手机号入口直链进入认证流程。", step="oauth_init")
                    return True
            except Exception as exc:
                _touch_browser_watchdog("手机号入口直链失败收口")
                emitter.warn(f"浏览器模式2 手机号入口直链失败: {exc}", step="oauth_init")
        return False

    def _bootstrap_manual_v2_phone_entry(current_url: str, body_text: str) -> bool:
        _touch_browser_watchdog("注册入口探测")
        nonlocal manual_v2_entry_bootstrap_signature, manual_v2_entry_bootstrap_seen_at
        nonlocal manual_v2_entry_bootstrap_wait_logged
        nonlocal manual_v2_entry_unavailable_since, manual_v2_entry_fallback_attempts
        signup_selectors = [
            'button[data-mobile-auth-entry-action="signup"]',
            'button.wm-app-signupButton',
            'button[commandfor="mobile-auth-dialog"]',
            'button[data-mobile-auth-entry-trigger="cta"]',
            'button:has-text("Sign up for free")',
            'a:has-text("Sign up for free")',
            '[role="button"]:has-text("Sign up for free")',
            'a:has-text("Sign up")',
            'button:has-text("Sign up")',
            '[role="button"]:has-text("Sign up")',
            'a:has-text("免费注册")',
            'button:has-text("免费注册")',
            '[role="button"]:has-text("免费注册")',
            'a:has-text("注册")',
            'button:has-text("注册")',
            '[role="button"]:has-text("注册")',
        ]
        phone_entry_selectors = [
            'a[data-auth-provider="phone"]',
            'a._X60mza_providerButton[data-auth-provider="phone"]',
            'a[href*="usernameKind=phone_number"]',
            'a[href*="usernameKind=phone"]',
            'a:has-text("Continue with phone")',
            'button:has-text("Continue with phone")',
            '[role="button"]:has-text("Continue with phone")',
            'div:has-text("Continue with phone")',
            'a:has-text("Use phone instead")',
            'button:has-text("Use phone instead")',
            '[role="button"]:has-text("Use phone instead")',
            'div:has-text("Use phone instead")',
            'a:has-text("Phone")',
            'button:has-text("Phone")',
            '[role="button"]:has-text("Phone")',
            'a:has-text("手机号")',
            'button:has-text("手机号")',
            '[role="button"]:has-text("手机号")',
            'button:has-text("使用手机")',
            '[role="button"]:has-text("使用手机")',
            'button:has-text("手机登录")',
            '[role="button"]:has-text("手机登录")',
            'a:has-text("继续使用手机登录")',
            'button:has-text("继续使用手机登录")',
            '[role="button"]:has-text("继续使用手机登录")',
            'div:has-text("继续使用手机登录")',
        ]
        more_menu_selectors = [
            'button:has-text("More")',
            '[role="button"]:has-text("More")',
            'button:has-text("更多")',
            '[role="button"]:has-text("更多")',
            'button[aria-label*="more" i]',
            '[role="button"][aria-label*="more" i]',
            'button[aria-label*="menu" i]',
            '[role="button"][aria-label*="menu" i]',
        ]

        def _detect_homepage_blocker(url_text: str, body_value: str) -> str:
            global_blocker = _detect_cloudflare_blocker(page, url_text, body_value)
            if global_blocker:
                return global_blocker
            body_lower = str(body_value or "").lower()
            if (
                "chatgpt.com" in str(url_text or "").lower()
                and "log in" in body_lower
                and "sign up" not in body_lower
                and not _has_phone_input(page)
            ):
                return "首页壳页尚未完成渲染"
            return ""

        def _entry_flow_ready(url_text: str, body_value: str) -> bool:
            if _has_phone_input(page):
                return True
            url_lower = str(url_text or "").lower()
            if "auth.openai.com" in url_lower:
                return True
            if "chatgpt.com/auth/login" in url_lower and "phone" in url_lower:
                return True
            if "chatgpt.com/auth/login_with" in url_lower:
                return True
            return bool(
                _is_phone_input_page(url_text, body_value, page)
                or _is_phone_verification_page(url_text, body_value, page)
                or _is_create_account_password_page(url_text, body_value, page)
                or _is_login_password_page(url_text, body_value, page)
                or _is_passkey_challenge_page(url_text, body_value, page)
            )

        def _wait_signup_transition(previous_url: str, previous_body: str, *, action_label: str) -> tuple[str, str]:
            quick_deadline = time.time() + 4.0
            latest_url = previous_url
            latest_body = previous_body
            previous_url_lower = str(previous_url or "").lower()
            while time.time() < quick_deadline:
                _touch_browser_watchdog("注册入口过渡等待")
                active_page = _resolve_active_page(page, timeout_ms=300)
                if active_page is not None:
                    # ensure outer page handle follows new tabs if any
                    pass
                latest_url, latest_body = _describe_page(page, force_refresh=True)
                _touch_browser_watchdog("注册入口过渡结果")
                latest_url_lower = str(latest_url or "").lower()
                if _entry_flow_ready(latest_url, latest_body):
                    return latest_url, latest_body
                if _first_visible_locator(page, phone_entry_selectors) is not None and "auth.openai.com" not in latest_url_lower:
                    # 弹层已出现，也算过渡成功的一环
                    if "continue with phone" in str(latest_body or "").lower() or _first_visible_locator(page, ['a[data-auth-provider="phone"]']) is not None:
                        return latest_url, latest_body
                if latest_url_lower and latest_url_lower != previous_url_lower and (
                    "auth.openai.com" in latest_url_lower
                    or "chatgpt.com/auth/" in latest_url_lower
                ):
                    return latest_url, latest_body
                _sleep_with_page(page, 180)
            latest_url, latest_body = _wait_for_page_stabilize(
                previous_url,
                previous_body,
                step="oauth_init",
                action_label=action_label,
                timeout_ms=9000,
            )
            settle_deadline = time.time() + 4.0
            while time.time() < settle_deadline:
                _wait_for_load(page, timeout_ms=1200)
                latest_url, latest_body = _describe_page(page, force_refresh=True)
                _touch_browser_watchdog("注册入口稳定结果")
                if _entry_flow_ready(latest_url, latest_body):
                    return latest_url, latest_body
                if "auth.openai.com" in str(latest_url or "").lower() or "chatgpt.com/auth/" in str(latest_url or "").lower():
                    return latest_url, latest_body
                if _first_visible_locator(page, phone_entry_selectors) is not None:
                    return latest_url, latest_body
                _sleep_with_page(page, 250)
            return latest_url, latest_body

        def _extract_phone_provider_href() -> str:
            selectors = (
                'a[data-auth-provider="phone"]',
                'a[href*="usernameKind=phone"]',
                'a._X60mza_providerButton',
                "a[href]",
            )
            for target in _iter_page_targets(page):
                for selector in selectors:
                    try:
                        locator = target.locator(selector)
                    except Exception:
                        continue
                    item = locator.first
                    try:
                        if not item.is_visible(timeout=300):
                            continue
                        href = str(item.get_attribute("href", timeout=300) or "").strip()
                        provider = str(item.get_attribute("data-auth-provider", timeout=300) or "").strip().lower()
                        text = str(item.inner_text(timeout=300) or "").strip().lower()
                    except Exception:
                        continue
                    if href and (
                        provider == "phone"
                        or "usernamekind=phone" in href.lower()
                        or "continue with phone" in text
                        or "use phone instead" in text
                        or "继续使用手机" in text
                    ):
                        return href
            return ""

        def _goto_phone_auth_entry(*, reason: str) -> bool:
            """兼容旧调用：统一复用外层手机号入口直链兜底。"""
            _touch_browser_watchdog("手机号入口直链兜底")
            extracted = _extract_phone_provider_href()
            if extracted:
                try:
                    emitter.info(
                        f"浏览器模式2 {reason}，改用页面提取的手机号入口直链: {_mask_secret(extracted, head=72, tail=24)}",
                        step="oauth_init",
                    )
                    _goto_with_recovery(
                        extracted,
                        step="oauth_init",
                        reason="浏览器模式2 打开页面提取手机号入口直链失败",
                        wait_until="domcontentloaded",
                        timeout_ms=min(20000, int(cfg.get("browser_timeout_ms") or 20000)),
                        max_attempts=2,
                    )
                    _wait_for_load(page, timeout_ms=2500)
                    latest_url, latest_body = _describe_page(page, force_refresh=True)
                    if _entry_flow_ready(latest_url, latest_body) or "auth.openai.com" in str(latest_url or "").lower() or "chatgpt.com/auth/" in str(latest_url or "").lower():
                        emitter.info("浏览器模式2 已通过手机号入口直链进入认证流程。", step="oauth_init")
                        return True
                except Exception as exc:
                    _touch_browser_watchdog("手机号入口直链失败收口")
                    emitter.warn(f"浏览器模式2 页面提取手机号入口直链失败: {exc}", step="oauth_init")
            return _goto_manual_v2_phone_auth_entry(reason=reason, prefer_login=False)

        url_lower = str(current_url or "").lower()
        if "chatgpt.com" not in url_lower and "auth.openai.com" not in url_lower:
            manual_v2_entry_unavailable_since = 0.0
            return False
        if _entry_flow_ready(current_url, body_text):
            manual_v2_entry_bootstrap_signature = ""
            manual_v2_entry_bootstrap_seen_at = 0.0
            manual_v2_entry_bootstrap_wait_logged = False
            manual_v2_entry_unavailable_since = 0.0
            manual_v2_entry_fallback_attempts = 0
            return True if _has_phone_input(page) or "auth.openai.com" in url_lower else False

        clicked = False
        signup_visible = _first_visible_locator(page, signup_selectors) is not None
        phone_entry_visible = _first_visible_locator(page, phone_entry_selectors) is not None
        _touch_browser_watchdog("注册入口控件探测结果")
        blocker_reason = _detect_homepage_blocker(current_url, body_text)
        _touch_browser_watchdog("首页状态探测结果")
        if blocker_reason:
            blocker_signature = f"blocker:{url_lower}:{blocker_reason}"
            now = time.time()
            if blocker_signature != manual_v2_entry_bootstrap_signature or now - manual_v2_entry_bootstrap_seen_at >= 15:
                manual_v2_entry_bootstrap_signature = blocker_signature
                manual_v2_entry_bootstrap_seen_at = now
                manual_v2_entry_bootstrap_wait_logged = False
                emitter.info(
                    "浏览器模式2 首页仍在等待前置状态完成，暂未出现注册入口: "
                    + _preview_text(blocker_reason, 120),
                    step="oauth_init",
                )
            return False
        if signup_visible or phone_entry_visible:
            manual_v2_entry_unavailable_since = 0.0
            # 不重置 fallback_attempts，便于累计后走直链
        if not signup_visible and not phone_entry_visible:
            if manual_v2_entry_unavailable_since <= 0:
                manual_v2_entry_unavailable_since = time.time()
            if _click_first(page, more_menu_selectors, timeout_ms=800):
                emitter.info("浏览器模式2 首页未直接看到注册入口，已尝试点击 More/菜单 展开更多入口...", step="oauth_init")
                _wait_for_load(page, timeout_ms=1200)
                current_url, body_text = _describe_page(page, force_refresh=True)
                url_lower = str(current_url or "").lower()
                signup_visible = _first_visible_locator(page, signup_selectors) is not None
                phone_entry_visible = _first_visible_locator(page, phone_entry_selectors) is not None
                if signup_visible or phone_entry_visible:
                    manual_v2_entry_unavailable_since = 0.0
        entry_signature = f"{url_lower}|signup:{1 if signup_visible else 0}|phone_entry:{1 if phone_entry_visible else 0}"
        if not signup_visible and not phone_entry_visible:
            _touch_browser_watchdog("注册入口等待收口")
            now = time.time()
            wait_signature = f"pending:{url_lower}"
            if wait_signature != manual_v2_entry_bootstrap_signature or now - manual_v2_entry_bootstrap_seen_at >= 15:
                manual_v2_entry_bootstrap_signature = wait_signature
                manual_v2_entry_bootstrap_seen_at = now
                manual_v2_entry_bootstrap_wait_logged = False
                actions_summary = _summarize_primary_actions(page)
                _touch_browser_watchdog("首页入口诊断结果")
                emitter.info(
                    "浏览器模式2 首页暂未识别到注册入口，继续等待页面渲染..."
                    + " actions="
                    + actions_summary,
                    step="oauth_init",
                )
            if (
                manual_v2_entry_unavailable_since > 0
                and now - manual_v2_entry_unavailable_since >= 8.0
                and manual_v2_entry_fallback_attempts < 3
            ):
                manual_v2_entry_fallback_attempts += 1
                manual_v2_entry_unavailable_since = now
                if _goto_phone_auth_entry(reason=f"首页入口持续未出现，准备第 {manual_v2_entry_fallback_attempts}/3 次手机号直链兜底"):
                    return True
                if manual_v2_entry_fallback_attempts >= 2:
                    emitter.warn(
                        "浏览器模式2 首页注册入口持续未出现，准备直接重开注册授权页兜底...",
                        step="oauth_init",
                    )
                    current_oauth = generate_oauth_url_func()
                    _start_oauth_flow(page, current_oauth, "signup")
                return False
            return False

        if signup_visible and not phone_entry_visible:
            if entry_signature != manual_v2_entry_bootstrap_signature:
                manual_v2_entry_bootstrap_signature = entry_signature
                manual_v2_entry_bootstrap_seen_at = time.time()
                manual_v2_entry_bootstrap_wait_logged = False
            if time.time() - manual_v2_entry_bootstrap_seen_at < 0.2:
                if not manual_v2_entry_bootstrap_wait_logged:
                    manual_v2_entry_bootstrap_wait_logged = True
                    emitter.info("浏览器模式2 首页注册入口已出现，先等待页面稳定再点击，避免误点空白弹层...", step="oauth_init")
                return False
        else:
            if not phone_entry_visible:
                manual_v2_entry_bootstrap_signature = ""
                manual_v2_entry_bootstrap_seen_at = 0.0
                manual_v2_entry_bootstrap_wait_logged = False

        def _js_click_mobile_auth_signup() -> bool:
            # 保留旧函数名，实际使用 locator 点击，避免无 timeout page.evaluate。
            return _click_first(
                page,
                [
                    'button[data-mobile-auth-entry-action="signup"]',
                    "button.wm-app-signupButton",
                    'button[commandfor="mobile-auth-dialog"]',
                    'button:has-text("Sign up for free")',
                    'button:has-text("Sign up")',
                    'a:has-text("Sign up for free")',
                    'a:has-text("Sign up")',
                    'button:has-text("免费注册")',
                    'button:has-text("注册")',
                ],
                timeout_ms=1000,
            )

        def _js_click_phone_provider() -> bool:
            return _click_first(
                page,
                [
                    'a[data-auth-provider="phone"]',
                    'a[href*="usernameKind=phone"]',
                    'a._X60mza_providerButton',
                    'a:has-text("Continue with phone")',
                    'button:has-text("Continue with phone")',
                    'button:has-text("Use phone instead")',
                    'button:has-text("继续使用手机")',
                    'button:has-text("手机登录")',
                ],
                timeout_ms=1000,
            )

        if not phone_entry_visible and signup_visible:
            signup_clicked = (
                _click_first(page, signup_selectors, timeout_ms=1500)
                or _click_text_ancestor(page, ["Sign up for free", "Sign up", "免费注册", "注册"], timeout_ms=1200)
                or _js_click_mobile_auth_signup()
            )
            if signup_clicked:
                emitter.info("浏览器模式2 已自动点击首页注册入口（Sign up for free / Sign up），准备拉起手机号注册界面...", step="oauth_init")
                clicked = True
                _sleep_with_page(page, 500)
                current_url, body_text = _wait_signup_transition(current_url, body_text, action_label="首页注册入口已点击")
                if _entry_flow_ready(current_url, body_text):
                    return True
                phone_entry_visible = _first_visible_locator(page, phone_entry_selectors) is not None
                if not phone_entry_visible:
                    for _ in range(12):
                        _sleep_with_page(page, 250)
                        phone_entry_visible = _first_visible_locator(page, phone_entry_selectors) is not None
                        if phone_entry_visible:
                            break

        phone_entry_clicked = False
        phone_href_before_click = _extract_phone_provider_href() if (phone_entry_visible or clicked) else ""
        if phone_entry_visible or clicked:
            phone_entry_clicked = (
                _click_first(page, phone_entry_selectors, timeout_ms=1500)
                or _click_text_ancestor(
                    page,
                    ["Continue with phone", "Use phone instead", "继续使用手机登录", "使用手机", "手机登录"],
                    timeout_ms=1200,
                )
                or _js_click_phone_provider()
            )
        if phone_entry_clicked:
            emitter.info("浏览器模式2 已点击手机号注册入口，等待站点真正渲染手机号输入框...", step="oauth_init")
            clicked = True
            current_url, body_text = _wait_signup_transition(current_url, body_text, action_label="手机号注册入口已点击")
            if _entry_flow_ready(current_url, body_text):
                emitter.info("浏览器模式2 已自动切换到手机号注册入口，已看到手机号输入控件或认证页。", step="oauth_init")
                return True
            # 点了但还在 chatgpt 首页：优先用链接 href 直跳
            if "chatgpt.com" in str(current_url or "").lower() and "auth.openai.com" not in str(current_url or "").lower():
                if _goto_phone_auth_entry(reason="点击 Continue with phone 后仍停在首页"):
                    latest_url, latest_body = _describe_page(page, force_refresh=True)
                    if _entry_flow_ready(latest_url, latest_body) or "auth.openai.com" in str(latest_url or "").lower() or "chatgpt.com/auth/" in str(latest_url or "").lower():
                        emitter.info("浏览器模式2 已通过手机号入口直链进入认证流程。", step="oauth_init")
                        return True

        if _entry_flow_ready(current_url, body_text):
            return True
        if clicked:
            if _is_login_with_bridge_page(current_url, body_text, page):
                emitter.info(
                    "浏览器模式2 首页入口点击后已进入登录弹层桥接页，正在等待站点真正渲染手机号输入控件...",
                    step="oauth_init",
                )
            # 累计失败后强制直链，避免无限“点了没进去”
            manual_v2_entry_fallback_attempts += 1
            if manual_v2_entry_fallback_attempts >= 2:
                if _goto_phone_auth_entry(reason=f"连续 {manual_v2_entry_fallback_attempts} 次点击后仍未进入手机号页"):
                    return True
            emitter.warn(
                "浏览器模式2 首页入口点击后尚未真正进入手机号页，本轮按未成功处理，下一轮继续等待页面稳定后再试。"
                + f" current_url={_mask_secret(current_url, head=56, tail=12)}"
                + f", state={_classify_page_state(current_url, body_text, page)}"
                + f", attempt={manual_v2_entry_fallback_attempts}",
                step="oauth_init",
            )
            emitter.info(
                "首页入口点击后诊断: actions=" + _summarize_primary_actions(page)
                + f", phone_href={_mask_secret(phone_href_before_click or _extract_phone_provider_href(), head=64, tail=24) or '-'}",
                step="oauth_init",
            )
        return False

    def _bootstrap_manual_v2_login_entry(current_url: str, body_text: str) -> bool:
        nonlocal manual_v2_entry_fallback_attempts
        url_lower = str(current_url or "").lower()
        body_lower = str(body_text or "").lower()
        if _is_phone_input_page(current_url, body_text, page) or _has_phone_input(page):
            return True
        # 首页/桥接页也允许走补资料登录入口（不仅 auth.openai.com/log-in）。
        on_login_shell = (
            "auth.openai.com/log-in" in url_lower
            or _is_login_with_bridge_page(current_url, body_text)
            or ("chatgpt.com" in url_lower and "auth.openai.com" not in url_lower)
        )
        if not on_login_shell:
            return False
        clicked = (
            _click_first(
                page,
                [
                    'a[data-auth-provider="phone"]',
                    'a[href*="usernameKind=phone_number"]',
                    'a[href*="usernameKind=phone"]',
                    'a:has-text("Continue with phone")',
                    'button:has-text("Continue with phone")',
                    '[role="button"]:has-text("Continue with phone")',
                    'div:has-text("Continue with phone")',
                    'button:has-text("Use phone instead")',
                    '[role="button"]:has-text("Use phone instead")',
                    'div:has-text("Use phone instead")',
                    'button:has-text("Phone")',
                    '[role="button"]:has-text("Phone")',
                    'button:has-text("手机号")',
                    '[role="button"]:has-text("手机号")',
                    'button:has-text("使用手机")',
                    '[role="button"]:has-text("使用手机")',
                    'button:has-text("手机登录")',
                    '[role="button"]:has-text("手机登录")',
                    'button:has-text("继续使用手机登录")',
                    '[role="button"]:has-text("继续使用手机登录")',
                    'div:has-text("继续使用手机登录")',
                ],
                timeout_ms=1200,
            )
            or _click_text_ancestor(
                page,
                ["Continue with phone", "Use phone instead", "继续使用手机登录", "使用手机", "手机登录"],
                timeout_ms=1200,
            )
        )
        if clicked:
            if manual_v2_profile_completion_mode and manual_v2_phone_number:
                emitter.info(
                    "浏览器模式2 已在登录入口点击手机号登录，等待手机号输入页就绪后自动复用已保存手机号...",
                    step="oauth_init",
                )
            else:
                emitter.info("浏览器模式2 已在登录入口点击手机号登录，等待站点渲染手机号输入框...", step="oauth_init")
            _wait_for_load(page, timeout_ms=2500)
            latest_url, latest_body = _describe_page(page, force_refresh=True)
            if _is_phone_input_page(latest_url, latest_body, page) or _has_phone_input(page):
                if manual_v2_profile_completion_mode and manual_v2_phone_number:
                    emitter.info(
                        "浏览器模式2 已切到手机号输入页，准备自动复用已保存手机号...",
                        step="oauth_init",
                    )
                else:
                    emitter.info("浏览器模式2 已切到手机号输入页。", step="oauth_init")
                return True
            # 点了 Continue with phone 仍停在首页/桥接：复用直链兜底
            latest_lower = str(latest_url or "").lower()
            if "chatgpt.com" in latest_lower and "auth.openai.com" not in latest_lower:
                if _goto_manual_v2_phone_auth_entry(reason="点击 Continue with phone 后仍停在首页", prefer_login=True):
                    return True
            if "auth.openai.com/log-in" in latest_lower or _is_login_with_bridge_page(latest_url, latest_body):
                manual_v2_entry_fallback_attempts += 1
                if manual_v2_entry_fallback_attempts >= 1:
                    if _goto_manual_v2_phone_auth_entry(
                        reason=f"登录入口连续 {manual_v2_entry_fallback_attempts} 次点击后仍未进入手机号页",
                        prefer_login=True,
                    ):
                        return True
            return False
        # 点不到 Continue with phone 时，首页/登录壳直接走直链
        if "chatgpt.com" in url_lower or "auth.openai.com/log-in" in url_lower or _is_login_with_bridge_page(current_url, body_text):
            manual_v2_entry_fallback_attempts += 1
            if manual_v2_entry_fallback_attempts >= 1:
                if _goto_manual_v2_phone_auth_entry(
                    reason=f"登录入口未点到 Continue with phone，准备第 {manual_v2_entry_fallback_attempts} 次手机号直链兜底",
                    prefer_login=True,
                ):
                    return True
        return bool("continue with phone" in body_lower or "use phone instead" in body_lower or "继续使用手机登录" in body_text)

    def _reset_browser_phase_state(*, clear_profile: bool = False) -> None:
        nonlocal otp_wait_started, otp_page_ready_logged, otp_initial_send_triggered
        nonlocal email_submitted, password_submitted, profile_submitted
        nonlocal otp_resend_attempts
        callback_state["url"] = ""
        otp_wait_started = False
        otp_page_ready_logged = False
        otp_initial_send_triggered = False
        email_submitted = False
        password_submitted = False
        tried_otp_codes.clear()
        otp_code_submit_attempts.clear()
        otp_resend_attempts = 0
        if clear_profile:
            profile_submitted = False

    def _schedule_otp_resend(reason: str, *, step: str) -> bool:
        nonlocal otp_resend_attempts
        reason_text = str(reason or "浏览器 OTP 阶段需要重发验证码").strip()
        if otp_resend_attempts < otp_max_resend_attempts and _click_otp_resend(page):
            otp_resend_attempts += 1
            emitter.info(
                f"{reason_text}，已触发第 {otp_resend_attempts}/{otp_max_resend_attempts} 次验证码重发，"
                + f"下一轮等待 {otp_wait_timeout_seconds}s",
                step="send_otp",
            )
            _wait_for_load(page, timeout_ms=1800)
            return True
        if otp_resend_attempts < otp_max_resend_attempts:
            otp_resend_attempts += 1
            emitter.warn(
                f"{reason_text}，当前页面未找到明确的重发入口，"
                + f"{otp_wait_timeout_seconds}s 后继续轮询（计入第 {otp_resend_attempts}/{otp_max_resend_attempts} 次重试）",
                step=step,
            )
            return True
        return False

    def _try_browser_session_fast_path(current_url: str) -> Optional[str]:
        nonlocal browser_session_fast_path_attempts
        if browser_session_fast_path_attempts >= 2:
            return None
        browser_session_fast_path_attempts += 1
        emitter.info(
            "浏览器已进入 ChatGPT 域，尝试执行浏览器 session fast path 兜底...",
            step="get_token",
        )
        return _try_build_token_from_browser_session(
            context=context,
            emitter=emitter,
            build_browser_session_token_func=build_browser_session_token_func,
            referer_url=current_url,
            fallback_email=ctx.email,
            page=page,
            proxy=str(ctx.proxy or ""),
        )

    def _restart_current_page_oauth_flow(*, target_phase: str, reason: str) -> None:
        nonlocal current_phase, current_oauth, deadline, manual_v2_login_oauth
        reason_text = str(reason or "").strip() or "浏览器流程需要重新拉起 OAuth"
        emitter.warn(reason_text, step="oauth_init")
        _reset_browser_phase_state(clear_profile=True)
        current_phase = "login" if str(target_phase or "").strip().lower() == "login" else "signup"
        if current_phase == "login":
            current_oauth = generate_login_oauth_url_func()
            manual_v2_login_oauth = current_oauth
        else:
            current_oauth = generate_oauth_url_func()
            manual_v2_login_oauth = None
        deadline = time.time() + max(90, int(cfg["browser_timeout_ms"] / 1000) + 60)
        _start_oauth_flow(page, current_oauth, current_phase)

    def _try_recover_timeout_error_page(
        current_url: str,
        body_text: str,
        *,
        step: str,
        action_label: str,
        timeout_ms: int = 15000,
    ) -> bool:
        nonlocal email_submitted, password_submitted, manual_v2_password_page_logged
        if not _is_retryable_error_page(current_url, body_text):
            return False
        active_page = _resolve_active_page(page, timeout_ms=1500)
        if active_page is None:
            emitter.warn("检测到超时错误页，但当前没有可用活动页面，改走后续兜底恢复...", step=step)
            return False
        is_rate_limited = _is_rate_limit_error_page(current_url, body_text)
        if is_rate_limited:
            # 限流页立刻狂点 Try again 只会更限；先冷却再点。
            emitter.warn(
                "检测到 OpenAI 限流页（rate_limit_exceeded / Too many requests），"
                + "先冷却约 20 秒再点 Try again，避免继续触发限流..."
                + f" detail={_preview_text(body_text, 160)}",
                step=step,
            )
            if _sleep_with_page_until(page, 20000, ctx.stop_event):
                return False
        elif _is_timeout_error_page(current_url, body_text):
            emitter.warn("检测到 Operation timed out，先在当前页面点击 Try again/Retry 原地恢复...", step=step)
        else:
            emitter.warn(
                "检测到可重试错误页（Oops / something went wrong / please try again），"
                + "先在当前页面点击 Try again/Retry 原地恢复...",
                step=step,
            )
        previous_url = current_url
        previous_body = body_text
        if not _click_retryable_error_action(page):
            emitter.warn(
                ("限流页" if is_rate_limited else "超时错误页")
                + "当前未找到 Try again/Retry/重试 按钮，改走后续兜底恢复...",
                step=step,
            )
            return False
        _wait_for_load(page, timeout_ms=2500)
        blocker_wait_deadline = time.time() + 30.0
        blocker_logged = False
        while time.time() < blocker_wait_deadline:
            latest_probe_url, latest_probe_body = _describe_page(page, force_refresh=True)
            latest_blocker = _detect_cloudflare_blocker(page, latest_probe_url, latest_probe_body)
            if not latest_blocker:
                break
            if not blocker_logged:
                blocker_logged = True
                emitter.info(
                    "Try again 后检测到 Cloudflare / Just a moment，先等待站点自行通过再继续恢复..."
                    + f" blocker={_preview_text(latest_blocker, 120) or '-'}",
                    step=step,
                )
            _wait_for_load(page, timeout_ms=1200)
            _simulate_human_idle(page)
            _sleep_with_page(page, 1200)
        latest_url, latest_body = _wait_for_page_stabilize(
            previous_url,
            previous_body,
            step=step,
            action_label=action_label,
            timeout_ms=timeout_ms,
        )
        latest_url_lower = str(latest_url or "").lower()
        if callback_state["url"] or ("code=" in latest_url_lower and "state=" in latest_url_lower):
            emitter.info("超时错误页已在当前页面恢复并命中回调线索，继续推进流程...", step=step)
            return True
        if (
            is_manual_v2_mode
            and not manual_v2_login_flow_started
            and not manual_v2_contact_seen
            and _is_create_account_password_page(latest_url, latest_body, page)
        ):
            password_submitted = False
            manual_v2_password_page_logged = False
            manual_v2_create_password_submit_attempts = 0
            manual_v2_wait_phone_logged = False
            manual_v2_wait_phone_last_url = ""
            emitter.info(
                "超时页 Try again 后已回到创建密码页，恢复自动填密码流程并继续输入密码...",
                step="create_password",
            )
            return True
        if (
            not is_manual_v2_mode
            and "/create-account" in latest_url_lower
            and "/create-account/password" not in latest_url_lower
        ):
            email_submitted = False
            password_submitted = False
            manual_v2_password_page_logged = False
            emitter.info(
                "超时页 Try again 后已回到注册邮箱页，重置邮箱提交状态并重新继续填写邮箱...",
                step="create_email",
            )
            return True
        if (
            is_manual_v2_mode
            and manual_v2_login_flow_started
            and current_phase == "login"
            and _is_login_password_page(latest_url, latest_body, page)
        ):
            password_submitted = False
            manual_v2_password_page_logged = False
            manual_v2_wait_phone_logged = False
            manual_v2_wait_phone_last_url = ""
            emitter.info(
                "可重试错误页恢复后已回到登录密码页，恢复自动填密码流程并继续输入密码...",
                step="create_password",
            )
            return True
        if (
            is_manual_v2_mode
            and manual_v2_login_flow_started
            and _is_manual_v2_login_phone_input_stage(previous_url, previous_body, page)
            and _is_login_password_page(latest_url, latest_body, page)
        ):
            password_submitted = False
            manual_v2_password_page_logged = False
            manual_v2_wait_phone_logged = False
            manual_v2_wait_phone_last_url = ""
            emitter.info(
                "可重试错误页恢复后已进入第二步登录密码页，恢复自动填密码流程并继续输入密码...",
                step="create_password",
            )
            return True
        if _is_timeout_error_page(latest_url, latest_body):
            emitter.warn("超时错误页当前页重试后仍未恢复，准备走 OAuth 重拉兜底...", step=step)
            return False
        if _is_retryable_error_page(latest_url, latest_body):
            emitter.warn("可重试错误页当前页重试后仍未恢复，准备走后续 OAuth 兜底恢复...", step=step)
            return False
        emitter.info(
            "可重试错误页已通过当前页面重试恢复，继续沿现有流程推进: "
            + _mask_secret(latest_url, head=56, tail=12),
            step=step,
        )
        return True

    def _wait_for_page_stabilize(
        previous_url: str,
        previous_body: str,
        *,
        step: str,
        action_label: str,
        timeout_ms: int = 15000,
    ) -> tuple[str, str]:
        previous_signature = _page_snapshot_signature(previous_url, previous_body)
        previous_url_lower = str(previous_url or "").lower()
        previous_state = _classify_page_state(previous_url, previous_body, page)
        deadline_local = time.time() + max(2.0, float(timeout_ms) / 1000.0)
        wait_logged = False
        latest_url = previous_url
        latest_body = previous_body
        changed_rounds = 0
        sticky_states = {"email", "password", "profile", "otp_loading", "otp_ready"}
        while time.time() < deadline_local:
            active_page = _resolve_active_page(page, timeout_ms=1200)
            if active_page is None:
                if callback_state["url"]:
                    return latest_url, latest_body
                _sleep_with_page(None, 300)
                continue
            if not callback_state["url"]:
                _consume_loopback_callback()
            _wait_for_load(page, timeout_ms=1200)
            latest_url, latest_body = _describe_page(page, force_refresh=True)
            latest_url_lower = latest_url.lower()
            latest_signature = _page_snapshot_signature(latest_url, latest_body)
            latest_state = _classify_page_state(latest_url, latest_body, page)
            if (
                callback_state["url"]
                or ("code=" in latest_url_lower and "state=" in latest_url_lower)
            ):
                return latest_url, latest_body
            if latest_state != previous_state:
                return latest_url, latest_body
            if latest_url_lower and latest_url_lower != previous_url_lower:
                return latest_url, latest_body
            if latest_signature != previous_signature:
                changed_rounds += 1
                if latest_state not in sticky_states and changed_rounds >= 2:
                    return latest_url, latest_body
            else:
                changed_rounds = 0
            if not wait_logged:
                wait_logged = True
                emitter.info(f"{action_label}，等待页面稳定并切换到下一阶段...", step=step)
            _sleep_with_page(page, 450)
        return _describe_page(page, force_refresh=True)

    def _wait_for_manual_v2_phone_submit_transition(
        previous_url: str,
        previous_body: str,
        *,
        step: str = "add_phone",
        timeout_ms: int = 18000,
    ) -> tuple[str, str]:
        nonlocal page
        previous_url_lower = str(previous_url or "").lower()
        previous_state = _classify_page_state(previous_url, previous_body, page)
        previous_signature = _page_snapshot_signature(previous_url, previous_body)
        deadline_local = time.time() + max(2.0, float(timeout_ms) / 1000.0)
        wait_logged = False
        latest_url = previous_url
        latest_body = previous_body
        same_signature_rounds = 0
        stalled_bridge_rounds = 0
        while time.time() < deadline_local:
            if stop_event is not None and stop_event.is_set():
                return latest_url, latest_body
            active_page = _resolve_active_page(page, timeout_ms=500)
            if active_page is None:
                if callback_state["url"]:
                    return latest_url, latest_body
                if not wait_logged:
                    wait_logged = True
                    emitter.info("步骤1手机号已提交，等待页面稳定并切换到下一阶段...", step=step)
                _sleep_with_page(None, 250)
                continue
            if not callback_state["url"]:
                _consume_loopback_callback()
            page, latest_url, latest_body = _promote_auth_target_if_needed(page, timeout_ms=2500)
            latest_url_lower = latest_url.lower()
            latest_state = _classify_page_state(latest_url, latest_body, page)
            latest_signature = _page_snapshot_signature(latest_url, latest_body)
            if callback_state["url"] or ("code=" in latest_url_lower and "state=" in latest_url_lower):
                return latest_url, latest_body
            if _has_recent_network_url(recent_network_events, "create-account/password", within_seconds=20.0):
                page, latest_url, latest_body = _promote_auth_target_if_needed(page, timeout_ms=2500)
                latest_url_lower = latest_url.lower()
            if _is_create_account_password_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_login_password_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_passkey_challenge_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_contact_verification_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_reset_password_page(latest_url, latest_body, page):
                return latest_url, latest_body
            # 只要出现密码框，即使 URL/壳层文本滞后，也视为已进入下一阶段。
            if _first_visible_locator(
                page,
                [
                    'input[type="password"]',
                    'input[name="password"]',
                    'input[name="new-password"]',
                    'input[autocomplete="new-password"]',
                ],
            ) is not None:
                return latest_url, latest_body
            if latest_state not in {"login_with_bridge", "add_phone", "blank"} and latest_state != previous_state:
                return latest_url, latest_body
            if latest_url_lower and latest_url_lower != previous_url_lower:
                # 真正发生了导航；若仍像桥接，继续观察，不要立刻当失败。
                if not _is_login_with_bridge_page(latest_url, latest_body, page) and not _is_phone_input_page(latest_url, latest_body, page):
                    return latest_url, latest_body
                previous_url_lower = latest_url_lower
                previous_state = latest_state
                previous_signature = latest_signature
                same_signature_rounds = 0
                stalled_bridge_rounds = 0
            if latest_signature == previous_signature:
                same_signature_rounds += 1
            else:
                previous_signature = latest_signature
                same_signature_rounds = 0
            still_on_origin = (
                _is_login_with_bridge_page(latest_url, latest_body, page)
                or _is_phone_input_page(latest_url, latest_body, page)
                or latest_state in {"login_with_bridge", "add_phone"}
            )
            if still_on_origin:
                stalled_bridge_rounds += 1
            else:
                stalled_bridge_rounds = 0
                return latest_url, latest_body
            # 约 3 秒一轮确认；至少连续观察更久，避免 SPA 跳转瞬间误判卡死。
            if still_on_origin and same_signature_rounds >= 18 and stalled_bridge_rounds >= 18:
                return latest_url, latest_body
            if not wait_logged:
                wait_logged = True
                emitter.info("步骤1手机号已提交，等待页面稳定并切换到下一阶段...", step=step)
            _sleep_with_page(page, 300)
        emitter.warn(
            "浏览器模式2 步骤1手机号提交后的短轮询观察超时，先返回当前页面继续主循环诊断..."
            + f" current_url={_mask_secret(latest_url, head=56, tail=12)}"
            + f", state={_classify_page_state(latest_url, latest_body, page)}"
            + f", pages={_page_navigation_debug_summary(page)}",
            step=step,
        )
        return _describe_page(page, force_refresh=True)

    def _wait_for_manual_v2_create_password_transition(
        previous_url: str,
        previous_body: str,
        *,
        step: str = "create_password",
        timeout_ms: int = 12000,
    ) -> tuple[str, str]:
        nonlocal page, manual_v2_contact_network_seen
        previous_url_lower = str(previous_url or "").lower()
        previous_state = _classify_page_state(previous_url, previous_body, page)
        deadline_local = time.time() + max(2.0, float(timeout_ms) / 1000.0)
        wait_logged = False
        latest_url = previous_url
        latest_body = previous_body
        register_send_wait_started_at = 0.0
        while time.time() < deadline_local:
            if stop_event is not None and stop_event.is_set():
                return latest_url, latest_body
            active_page = _resolve_active_page(page, timeout_ms=300)
            if active_page is None:
                if callback_state["url"]:
                    return latest_url, latest_body
                if not wait_logged:
                    wait_logged = True
                    emitter.info("create-account/password 已提交，等待页面稳定并切换到下一阶段...", step=step)
                _sleep_with_page(None, 200)
                continue
            page = active_page
            if not callback_state["url"]:
                _consume_loopback_callback()
            # 先读 frame URL/Continue 控件，再读整页正文。密码页按钮已出现时，
            # 交给外层精确提交路径处理，不能先被正文读取和网络轮询拖住。
            frame_target_url = _best_auth_target_url(page)
            frame_target_lower = str(frame_target_url or "").lower()
            if any(
                token in frame_target_lower
                for token in ("contact-verification", "verify-phone", "phone-verification")
            ):
                manual_v2_contact_network_seen = True
                return frame_target_url, ""
            if any(
                token in frame_target_lower
                for token in ("/create-account/password", "/log-in/password")
            ):
                continue_locator = _find_visible_submit_locator(
                    page,
                    ("继续", "Continue", "Next", "Verify", "Submit"),
                )
                if continue_locator is not None:
                    return frame_target_url, ""
            latest_url, latest_body = _describe_page(page, force_refresh=True)
            latest_url_lower = latest_url.lower()
            # 提交后 auth 业务页可能先在 iframe 内切换，顶层 URL 仍短暂停留在密码页。
            # 直接读取 frame URL，避免等网络事件或超时后才把控制权交回主循环。
            frame_target_url = _best_auth_target_url(page)
            frame_target_lower = str(frame_target_url or "").lower()
            if any(
                token in frame_target_lower
                for token in ("contact-verification", "verify-phone", "phone-verification")
            ):
                manual_v2_contact_network_seen = True
                return frame_target_url, latest_body
            # URL 已是 contact-verification：最快路径，跳过深文案/CF
            if "contact-verification" in latest_url_lower or "verify-phone" in latest_url_lower:
                manual_v2_contact_network_seen = True
                return latest_url, latest_body
            # 仅仍停在密码页时做深文案（每轮 deep text 很慢）
            if "/create-account/password" in latest_url_lower:
                raw_body_text = _get_page_deep_text(page)
                if str(raw_body_text or "").strip():
                    latest_body = str(raw_body_text or "")
            latest_state = _classify_page_state(latest_url, latest_body, page)
            if _is_create_account_failed_error(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_retryable_error_page(latest_url, latest_body):
                if _try_recover_timeout_error_page(
                    latest_url,
                    latest_body,
                    step=step,
                    action_label="create-account/password 提交后已直接检测到错误页文本，已立即触发当前页重试",
                    timeout_ms=12000,
                ):
                    latest_url, latest_body = _describe_page(page, force_refresh=True)
                return latest_url, latest_body
            cloudflare_blocker = _detect_cloudflare_blocker(page, latest_url, latest_body)
            if cloudflare_blocker:
                if not wait_logged:
                    wait_logged = True
                    emitter.info(
                        "create-account/password 提交后检测到 Cloudflare / Just a moment，先等待站点自行通过..."
                        + f" blocker={_preview_text(cloudflare_blocker, 120) or '-'}",
                        step=step,
                    )
                _wait_for_load(page, timeout_ms=800)
                # CF 等待期间只做轻量空闲，避免每次 +1.2s idle + 1.2s sleep
                if random.random() < 0.35:
                    _simulate_human_idle(page)
                _sleep_with_page(page, 450)
                continue
            if callback_state["url"] or ("code=" in latest_url_lower and "state=" in latest_url_lower):
                return latest_url, latest_body
            if _has_recent_network_url(recent_network_events, "contact-verification", within_seconds=12.0):
                manual_v2_contact_network_seen = True
                return latest_url, latest_body
            if _has_recent_network_url(recent_network_events, "phone-otp/send", within_seconds=12.0):
                manual_v2_contact_network_seen = True
                # 发码请求已出：再稍等 URL 切过去，最多 1.2s
                if register_send_wait_started_at <= 0.0:
                    register_send_wait_started_at = time.time()
                if time.time() - register_send_wait_started_at >= 1.2:
                    return latest_url, latest_body
            if _is_create_account_failed_error(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_phone_number_existing_account_error(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_phone_sms_send_failed_error(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_contact_verification_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_timeout_error_page(latest_url, latest_body):
                return latest_url, latest_body
            if _is_profile_page(latest_url, latest_body):
                return latest_url, latest_body
            if _is_create_account_password_page(latest_url, latest_body, page):
                recent_register_request = _has_recent_network_url(
                    recent_network_events,
                    "api/accounts/user/register",
                    within_seconds=20.0,
                )
                recent_phone_otp_send = _has_recent_network_url(
                    recent_network_events,
                    "api/accounts/phone-otp/send",
                    within_seconds=20.0,
                )
                if recent_phone_otp_send:
                    manual_v2_contact_network_seen = True
                    if register_send_wait_started_at <= 0.0:
                        register_send_wait_started_at = time.time()
                    # 发码已发出：1.2s 内 URL 仍未切就返回，交给主循环继续盯
                    if time.time() - register_send_wait_started_at >= 1.2:
                        return latest_url, latest_body
                if recent_register_request or recent_phone_otp_send:
                    if register_send_wait_started_at <= 0.0:
                        register_send_wait_started_at = time.time()
                    if time.time() - register_send_wait_started_at >= 1.8:
                        return latest_url, latest_body
                    if not wait_logged:
                        wait_logged = True
                        emitter.info(
                            "create-account/password 提交后已检测到注册/发码网络请求，页面仍停留在密码页时先继续等待站点完成切换...",
                            step=step,
                        )
                    _sleep_with_page(page, 180)
                    continue
            if latest_state != previous_state:
                return latest_url, latest_body
            if latest_url_lower and latest_url_lower != previous_url_lower:
                return latest_url, latest_body
            if not wait_logged:
                wait_logged = True
                emitter.info("create-account/password 已提交，等待页面稳定并切换到下一阶段...", step=step)
            _sleep_with_page(page, 150)
        emitter.warn(
            "浏览器模式2 create-account/password 提交后的短轮询观察超时，先返回当前页面继续主循环诊断..."
            + f" current_url={_mask_secret(latest_url, head=56, tail=12)}"
            + f", state={_classify_page_state(latest_url, latest_body, page)}",
            step=step,
        )
        # 最新快照已在本轮读取；把页面复查交给主循环，避免超时分支再同步读一次正文。
        return latest_url, latest_body

    def _wait_for_manual_v2_contact_submit_transition(
        previous_url: str,
        previous_body: str,
        *,
        step: str = "phone_verification",
        timeout_ms: int = 18000,
    ) -> tuple[str, str]:
        nonlocal page
        previous_url_lower = str(previous_url or "").lower()
        previous_state = _classify_page_state(previous_url, previous_body, page)
        deadline_local = time.time() + max(2.0, float(timeout_ms) / 1000.0)
        wait_logged = False
        latest_url = previous_url
        latest_body = previous_body
        invalid_code_hints = (
            "invalid code",
            "incorrect code",
            "expired code",
            "wrong code",
            "verification failed",
            "验证码无效",
            "验证码错误",
            "验证码已过期",
            "验证失败",
        )
        while time.time() < deadline_local:
            if stop_event is not None and stop_event.is_set():
                return latest_url, latest_body
            active_page = _resolve_active_page(page, timeout_ms=800)
            if active_page is None:
                if callback_state["url"]:
                    return latest_url, latest_body
                if not wait_logged:
                    wait_logged = True
                    emitter.info("短信验证码已提交，等待页面跳转并确认后续状态...", step=step)
                _sleep_with_page(None, 250)
                continue
            page = active_page
            if not callback_state["url"]:
                _consume_loopback_callback()
            page, latest_url, latest_body = _promote_auth_target_if_needed(page, timeout_ms=2500)
            latest_url_lower = latest_url.lower()
            latest_state = _classify_page_state(latest_url, latest_body, page)
            latest_body_lower = str(latest_body or "").lower()
            if callback_state["url"] or ("code=" in latest_url_lower and "state=" in latest_url_lower):
                return latest_url, latest_body
            if _is_profile_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_create_account_password_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_passkey_challenge_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if "about-you" in latest_url_lower:
                return latest_url, latest_body
            if latest_state != previous_state:
                return latest_url, latest_body
            if latest_url_lower and latest_url_lower != previous_url_lower:
                return latest_url, latest_body
            if any(hint in latest_body_lower for hint in invalid_code_hints):
                return latest_url, latest_body
            if not wait_logged:
                wait_logged = True
                emitter.info("短信验证码已提交，等待页面跳转并确认后续状态...", step=step)
            _sleep_with_page(page, 300)
        emitter.warn(
            "浏览器模式2 短信验证码提交后的短轮询观察超时，先返回当前页面继续主循环诊断..."
            + f" current_url={_mask_secret(latest_url, head=56, tail=12)}"
            + f", state={_classify_page_state(latest_url, latest_body, page)}"
            + f", pages={_page_navigation_debug_summary(page)}",
            step=step,
        )
        page, latest_url, latest_body = _promote_auth_target_if_needed(page, timeout_ms=2500)
        return latest_url, latest_body

    def _wait_for_manual_v2_reset_password_continue_transition(
        previous_url: str,
        previous_body: str,
        *,
        step: str = "create_password",
        timeout_ms: int = 10000,
    ) -> tuple[str, str]:
        previous_url_lower = str(previous_url or "").lower()
        previous_state = _classify_page_state(previous_url, previous_body, page)
        deadline_local = time.time() + max(2.0, float(timeout_ms) / 1000.0)
        wait_logged = False
        latest_url = previous_url
        latest_body = previous_body
        while time.time() < deadline_local:
            if stop_event is not None and stop_event.is_set():
                return latest_url, latest_body
            active_page = _resolve_active_page(page, timeout_ms=300)
            if active_page is None:
                if callback_state["url"]:
                    return latest_url, latest_body
                if not wait_logged:
                    wait_logged = True
                    emitter.info("reset-password 已点击继续，等待短信验证码页或发码结果...", step=step)
                _sleep_with_page(None, 200)
                continue
            if not callback_state["url"]:
                _consume_loopback_callback()
            latest_url, latest_body = _describe_page(page, force_refresh=True)
            latest_url_lower = latest_url.lower()
            latest_state = _classify_page_state(latest_url, latest_body, page)
            if callback_state["url"] or ("code=" in latest_url_lower and "state=" in latest_url_lower):
                return latest_url, latest_body
            if _is_phone_sms_send_failed_error(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_contact_verification_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_reset_password_new_password_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_timeout_error_page(latest_url, latest_body):
                return latest_url, latest_body
            if latest_state != previous_state:
                return latest_url, latest_body
            if latest_url_lower and latest_url_lower != previous_url_lower:
                return latest_url, latest_body
            if not wait_logged:
                wait_logged = True
                emitter.info("reset-password 已点击继续，等待短信验证码页或发码结果...", step=step)
            _sleep_with_page(page, 250)
        emitter.warn(
            "浏览器模式2 reset-password 点击继续后的短轮询观察超时，先返回当前页面继续主循环诊断..."
            + f" current_url={_mask_secret(latest_url, head=56, tail=12)}"
            + f", state={_classify_page_state(latest_url, latest_body, page)}",
            step=step,
        )
        return _describe_page(page, force_refresh=True)

    def _wait_for_manual_v2_login_phone_submit_transition(
        previous_url: str,
        previous_body: str,
        *,
        step: str = "create_email",
        timeout_ms: int = 12000,
    ) -> tuple[str, str]:
        previous_url_lower = str(previous_url or "").lower()
        previous_state = _classify_page_state(previous_url, previous_body, page)
        deadline_local = time.time() + max(2.0, float(timeout_ms) / 1000.0)
        wait_logged = False
        latest_url = previous_url
        latest_body = previous_body
        while time.time() < deadline_local:
            if stop_event is not None and stop_event.is_set():
                return latest_url, latest_body
            active_page = _resolve_active_page(page, timeout_ms=300)
            if active_page is None:
                if callback_state["url"]:
                    return latest_url, latest_body
                if not wait_logged:
                    wait_logged = True
                    emitter.info("第二步手机号已提交，等待页面稳定并切换到密码页/错误页...", step=step)
                _sleep_with_page(None, 200)
                continue
            if not callback_state["url"]:
                _consume_loopback_callback()
            latest_url, latest_body = _describe_page(page, force_refresh=True)
            latest_url_lower = latest_url.lower()
            latest_state = _classify_page_state(latest_url, latest_body, page)
            if callback_state["url"] or ("code=" in latest_url_lower and "state=" in latest_url_lower):
                return latest_url, latest_body
            if _is_login_password_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_retryable_error_page(latest_url, latest_body):
                return latest_url, latest_body
            if _is_timeout_error_page(latest_url, latest_body):
                return latest_url, latest_body
            if _is_add_email_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_otp_page(latest_url, latest_body, page):
                return latest_url, latest_body
            if _is_login_with_bridge_page(latest_url, latest_body):
                return latest_url, latest_body
            if latest_state != previous_state:
                return latest_url, latest_body
            if latest_url_lower and latest_url_lower != previous_url_lower:
                return latest_url, latest_body
            if not wait_logged:
                wait_logged = True
                emitter.info("第二步手机号已提交，等待页面稳定并切换到密码页/错误页...", step=step)
            _sleep_with_page(page, 250)
        emitter.warn(
            "浏览器模式2 第二步手机号提交后的短轮询观察超时，先返回当前页面继续主循环诊断..."
            + f" current_url={_mask_secret(latest_url, head=56, tail=12)}"
            + f", state={_classify_page_state(latest_url, latest_body, page)}",
            step=step,
        )
        return _describe_page(page, force_refresh=True)

    def _prepare_manual_v2_login_flow(reason: str, *, profile_completion_only: bool = False) -> None:
        nonlocal current_phase, email_submitted, password_submitted, profile_submitted
        nonlocal current_oauth, manual_v2_login_oauth
        nonlocal manual_v2_contact_seen, manual_v2_wait_contact_logged, manual_v2_contact_transition_last_key
        nonlocal manual_v2_contact_network_seen
        nonlocal manual_v2_sms_code_submitted
        nonlocal manual_v2_login_flow_started, manual_v2_phone_entry_clicked
        nonlocal manual_v2_login_phone_prefilled, manual_v2_login_password_prefilled
        nonlocal manual_v2_login_phone_submitted, manual_v2_post_login_pending_email
        nonlocal manual_v2_bridge_entered_at, manual_v2_bridge_logged
        nonlocal manual_v2_post_login_recover_attempts
        nonlocal manual_v2_post_login_retryable_error_attempts
        nonlocal manual_v2_email_verification_recover_attempts
        nonlocal manual_v2_email_verification_logged
        nonlocal manual_v2_email_otp_completed
        nonlocal manual_v2_oauth_resumed, manual_v2_workspace_logged, manual_v2_wait_phone_logged
        nonlocal manual_v2_profile_completion_mode
        nonlocal manual_v2_wait_phone_last_url, manual_v2_password_page_logged, manual_v2_phone_number
        nonlocal manual_v2_create_password_submit_attempts, manual_v2_phone_submit_stall_attempts
        nonlocal manual_v2_waiting_phone_retry, manual_v2_waiting_phone_retry_logged
        nonlocal manual_v2_require_phone_resubmit, manual_v2_reset_password_flow_started
        nonlocal manual_v2_reset_password_continue_clicked, manual_v2_post_login_oauth_retry_attempts
        nonlocal manual_v2_choose_account_click_failures, manual_v2_cached_sms_code
        nonlocal page
        callback_state["url"] = ""
        current_phase = "login"
        email_submitted = False
        password_submitted = False
        profile_submitted = False
        manual_v2_contact_seen = False
        manual_v2_wait_contact_logged = False
        manual_v2_contact_transition_last_key = ""
        manual_v2_contact_network_seen = False
        manual_v2_sms_code_submitted = False
        manual_v2_login_flow_started = True
        manual_v2_phone_entry_clicked = False
        manual_v2_login_phone_prefilled = False
        manual_v2_login_phone_submitted = False
        manual_v2_login_password_prefilled = False
        manual_v2_post_login_pending_email = False
        manual_v2_bridge_entered_at = 0.0
        manual_v2_bridge_logged = False
        manual_v2_post_login_recover_attempts = 0
        manual_v2_post_login_retryable_error_attempts = 0
        manual_v2_post_login_oauth_retry_attempts = 0
        manual_v2_email_verification_recover_attempts = 0
        manual_v2_email_verification_logged = False
        manual_v2_email_otp_completed = False
        manual_v2_oauth_resumed = False
        manual_v2_workspace_logged = False
        manual_v2_profile_completion_mode = bool(profile_completion_only)
        manual_v2_wait_phone_logged = False
        manual_v2_wait_phone_last_url = ""
        manual_v2_password_page_logged = False
        manual_v2_create_password_submit_attempts = 0
        manual_v2_phone_submit_stall_attempts = 0
        manual_v2_cached_sms_code = ""
        manual_v2_waiting_phone_retry = False
        manual_v2_waiting_phone_retry_logged = False
        manual_v2_require_phone_resubmit = False
        manual_v2_choose_account_click_failures = 0
        manual_v2_reset_password_flow_started = False
        manual_v2_reset_password_continue_clicked = False
        emitter.info(reason, step="oauth_init")
        if profile_completion_only:
            current_oauth = generate_oauth_url_func()
            manual_v2_login_oauth = None
            emitter.info(
                "浏览器模式2 正在打开 ChatGPT 首页登录流程，先使用已保存手机号与密码完成资料补充...",
                step="oauth_init",
            )
            _goto_with_recovery(
                "https://chatgpt.com/",
                step="oauth_init",
                reason="浏览器模式2 打开 ChatGPT 首页登录流程失败",
                wait_until="domcontentloaded",
                timeout_ms=cfg["browser_timeout_ms"],
                max_attempts=3,
            )
        else:
            current_oauth = generate_login_oauth_url_func()
            manual_v2_login_oauth = current_oauth
            emitter.info(
                "浏览器模式2 正在打开标准 OAuth 授权地址，进入第二步手机登录链路...",
                step="oauth_init",
            )
            try:
                emitter.info(
                    "浏览器模式2 第二步登录 OAuth 授权地址: "
                    + _mask_secret(str(getattr(current_oauth, "auth_url", "") or ""), head=160, tail=24),
                    step="oauth_init",
                )
            except Exception:
                pass
            _start_oauth_flow(page, current_oauth, "login")
        _wait_for_load(page, timeout_ms=2500)
        current_url, body_text = _describe_page(page)
        if _is_session_ended_login_shell_page(current_url, body_text, page):
            if _click_first(
                page,
                [
                    'a:has-text("Log in")',
                    'button:has-text("Log in")',
                    '[role="button"]:has-text("Log in")',
                    'a:has-text("登录")',
                    'button:has-text("登录")',
                    '[role="button"]:has-text("登录")',
                ],
                timeout_ms=1500,
            ):
                emitter.info("浏览器模式2 在第二步登录入口命中“你的会话已结束”壳页，已立即自动点击登录...", step="oauth_init")
                _wait_for_load(page, timeout_ms=2500)

    def _prepare_manual_v2_signup_flow(reason: str) -> None:
        nonlocal current_phase, email_submitted, password_submitted, profile_submitted
        nonlocal current_oauth, manual_v2_login_oauth
        nonlocal manual_v2_contact_seen, manual_v2_wait_contact_logged, manual_v2_contact_transition_last_key
        nonlocal manual_v2_contact_network_seen
        nonlocal manual_v2_sms_code_submitted
        nonlocal manual_v2_login_flow_started, manual_v2_phone_entry_clicked
        nonlocal manual_v2_login_phone_prefilled, manual_v2_login_password_prefilled
        nonlocal manual_v2_login_phone_submitted, manual_v2_post_login_pending_email
        nonlocal manual_v2_bridge_entered_at, manual_v2_bridge_logged
        nonlocal manual_v2_post_login_recover_attempts, manual_v2_post_login_oauth_retry_attempts
        nonlocal manual_v2_email_verification_recover_attempts, manual_v2_email_verification_logged
        nonlocal manual_v2_email_otp_completed, manual_v2_oauth_resumed, manual_v2_workspace_logged
        nonlocal manual_v2_wait_phone_logged, manual_v2_wait_phone_last_url
        nonlocal manual_v2_password_page_logged, manual_v2_phone_number
        nonlocal manual_v2_create_password_submit_attempts
        nonlocal manual_v2_waiting_phone_retry, manual_v2_waiting_phone_retry_logged
        nonlocal manual_v2_require_phone_resubmit, manual_v2_reset_password_flow_started
        nonlocal manual_v2_reset_password_continue_clicked, manual_v2_entry_bootstrap_logged
        nonlocal manual_v2_entry_bootstrap_signature, manual_v2_entry_bootstrap_seen_at
        nonlocal manual_v2_entry_bootstrap_wait_logged, manual_v2_entry_unavailable_since
        nonlocal manual_v2_entry_fallback_attempts
        nonlocal manual_v2_choose_account_click_failures, manual_v2_cached_sms_code
        nonlocal deadline, page
        callback_state["url"] = ""
        _reset_browser_phase_state(clear_profile=True)
        current_phase = "signup"
        current_oauth = generate_oauth_url_func()
        manual_v2_login_oauth = None
        email_submitted = False
        password_submitted = False
        profile_submitted = False
        manual_v2_contact_seen = False
        manual_v2_wait_contact_logged = False
        manual_v2_contact_transition_last_key = ""
        manual_v2_contact_network_seen = False
        manual_v2_sms_code_submitted = False
        manual_v2_login_flow_started = False
        manual_v2_phone_entry_clicked = False
        manual_v2_login_phone_prefilled = False
        manual_v2_login_phone_submitted = False
        manual_v2_login_password_prefilled = False
        manual_v2_post_login_pending_email = False
        manual_v2_bridge_entered_at = 0.0
        manual_v2_bridge_logged = False
        manual_v2_post_login_recover_attempts = 0
        manual_v2_post_login_oauth_retry_attempts = 0
        manual_v2_email_verification_recover_attempts = 0
        manual_v2_email_verification_logged = False
        manual_v2_email_otp_completed = False
        manual_v2_oauth_resumed = False
        manual_v2_workspace_logged = False
        manual_v2_wait_phone_logged = False
        manual_v2_wait_phone_last_url = ""
        manual_v2_password_page_logged = False
        manual_v2_create_password_submit_attempts = 0
        manual_v2_phone_number = ""
        manual_v2_sms_activation_id = ""
        manual_v2_sms_purchased_at = 0.0
        manual_v2_sms_provider_done = False
        manual_v2_cached_sms_code = ""
        manual_v2_waiting_phone_retry = False
        manual_v2_waiting_phone_retry_logged = False
        manual_v2_require_phone_resubmit = False
        manual_v2_choose_account_click_failures = 0
        manual_v2_reset_password_flow_started = False
        manual_v2_reset_password_continue_clicked = False
        manual_v2_entry_bootstrap_logged = False
        manual_v2_entry_bootstrap_signature = ""
        manual_v2_entry_bootstrap_seen_at = 0.0
        manual_v2_entry_bootstrap_wait_logged = False
        manual_v2_entry_unavailable_since = 0.0
        manual_v2_entry_fallback_attempts = 0
        deadline = time.time() + max(6 * 60 * 60, int(cfg["browser_timeout_ms"] / 1000) + 60)
        emitter.warn(reason, step="oauth_init")
        _goto_with_recovery(
            "https://chatgpt.com/",
            step="oauth_init",
            reason="浏览器模式2 返回 ChatGPT 首页失败",
            wait_until="domcontentloaded",
            timeout_ms=cfg["browser_timeout_ms"],
            max_attempts=3,
        )
        _wait_for_load(page, timeout_ms=2500)
        emitter.info(
            f"浏览器模式2 已回到步骤1首页落点: {_mask_secret(page.url, head=48, tail=12)}",
            step="oauth_init",
        )
        if not cfg["browser_headless"]:
            emitter.info("当前为可见浏览器模式，可直接观察 ChatGPT 首页到手机注册入口的切换过程", step="oauth_init")
        try:
            landing_url, landing_body = _describe_page(page, force_refresh=True)
            emitter.info("浏览器模式2 回到首页后，立即重试手机号注册入口...", step="oauth_init")
            for attempt in range(1, 4):
                if _bootstrap_manual_v2_phone_entry(landing_url, landing_body):
                    emitter.info(
                        f"浏览器模式2 回首页入口启动成功（第 {attempt}/3 次尝试）",
                        step="oauth_init",
                    )
                    break
                _wait_for_load(page, timeout_ms=1200)
                _sleep_with_page(page, 500)
                landing_url, landing_body = _describe_page(page, force_refresh=True)
        except Exception as exc:
            _touch_browser_watchdog("回首页入口预热失败收口")
            emitter.warn(f"浏览器模式2 回首页入口预热失败，将交由主循环继续重试: {exc}", step="oauth_init")
    manual_v2_require_phone_resubmit = False
    manual_v2_reset_password_flow_started = False
    manual_v2_reset_password_continue_clicked = False
    manual_v2_entry_bootstrap_logged = False
    manual_v2_entry_bootstrap_signature = ""
    manual_v2_entry_bootstrap_seen_at = 0.0
    manual_v2_entry_bootstrap_wait_logged = False

    def _wait_manual_v2_phone_input(*, step: str, prompt: str, timeout_seconds: int = 3600) -> str:
        if not callable(wait_manual_phone_input_func):
            raise RuntimeError("浏览器模式2 当前未配置手机号人工输入通道")
        return str(
            wait_manual_phone_input_func(
                prompt=prompt,
                step=step,
                timeout_seconds=timeout_seconds,
                placeholder="请输入手机号，支持 +44 或本地格式",
                button_text="提交手机号",
                helper_text="当前为无头模式2，浏览器窗口不会显示；提交后程序会自动继续。",
            )
            or ""
        ).strip()

    def _wait_manual_v2_sms_code(*, step: str, prompt: str, timeout_seconds: int = 3600) -> str:
        if not callable(wait_manual_sms_code_input_func):
            raise RuntimeError("浏览器模式2 当前未配置短信验证码人工输入通道")
        return str(
            wait_manual_sms_code_input_func(
                prompt=prompt,
                step=step,
                timeout_seconds=timeout_seconds,
                placeholder="请输入 6 位短信验证码",
                button_text="提交验证码",
                helper_text="当前为无头模式2，提交验证码后程序会自动填入并继续；如果一直收不到码，可点“换手机号重来”。",
            )
            or ""
        ).strip()

    def _wait_manual_v2_email_input(*, step: str, prompt: str, timeout_seconds: int = 3600) -> str:
        if not callable(wait_manual_email_input_func):
            raise RuntimeError("浏览器模式2 当前未配置邮箱人工输入通道")
        return str(
            wait_manual_email_input_func(
                prompt=prompt,
                step=step,
                timeout_seconds=timeout_seconds,
                placeholder="请输入要绑定的邮箱地址",
                button_text="提交邮箱",
                helper_text="其他流程保持自动，只有补邮箱和邮箱验证码改为手动输入。",
            )
            or ""
        ).strip()

    def _wait_manual_v2_email_code(*, step: str, prompt: str, timeout_seconds: int = 3600) -> str:
        if not callable(wait_manual_email_code_input_func):
            raise RuntimeError("浏览器模式2 当前未配置邮箱验证码人工输入通道")
        return str(
            wait_manual_email_code_input_func(
                prompt=prompt,
                step=step,
                timeout_seconds=timeout_seconds,
                placeholder="请输入邮箱收到的 6 位验证码",
                button_text="提交邮箱验证码",
                helper_text="提交后程序会自动填入当前页面并继续后续授权流程。",
            )
            or ""
        ).strip()

    def _ensure_manual_v2_auto_phone(*, step: str, prompt: str) -> str:
        nonlocal launch_resources
        nonlocal manual_v2_phone_number, manual_v2_sms_activation_id, manual_v2_sms_provider_done, manual_v2_sms_purchased_at
        nonlocal manual_v2_sms_country_id, manual_v2_sms_country_iso, manual_v2_sms_country_name, manual_v2_sms_country_result_recorded
        if manual_v2_phone_number:
            return manual_v2_phone_number
        if not manual_v2_auto_phone_mode or sms_provider is None:
            raise RuntimeError("浏览器模式2 当前未启用自动手机号模式")
        _touch_browser_watchdog("SMSBower 取号")
        # 短暂取号轮询也可能阻塞主循环；进入 API 前先做一次内存闸门检查。
        current_rss = _process_tree_rss_bytes()
        if current_rss >= memory_soft_limit:
            cdp_purged = _purge_active_browser_memory(context, page)
            before_rss, after_rss, collected = _release_memory_pressure(emitter)
            if after_rss >= memory_hard_limit:
                top_before = _process_tree_rss_report()
                _, closed_rss, close_gc, killed = _shutdown_browser_for_memory_pressure(
                    launch_resources,
                    playwright,
                    emitter,
                    target_bytes=memory_hard_limit,
                )
                launch_resources = None
                emitter.warn(
                    "短信取号前检测到进程内存偏高，已关闭当前浏览器并清理残留进程："
                    + f"rss={current_rss / 1024 / 1024:.0f}MB, before={before_rss / 1024 / 1024:.0f}MB, "
                    + f"after={closed_rss / 1024 / 1024:.0f}MB, gc={collected + close_gc}, killed={killed}, "
                    + f"cdp_purge={cdp_purged}, top_before={top_before}",
                    step="memory",
                )
                raise RuntimeError(
                    "短信取号前进程内存仍超过安全阈值，已停止当前浏览器流程并交由外层重试；"
                    + f"rss_before_close={after_rss / 1024 / 1024:.0f}MB, "
                    + f"rss_after_close={closed_rss / 1024 / 1024:.0f}MB, "
                    + f"hard_limit={memory_hard_limit / 1024 / 1024:.0f}MB"
                )
            emitter.warn(
                "短信取号前检测到进程内存偏高，已清理历史浏览器现场/页面快照并执行垃圾回收："
                + f"rss={current_rss / 1024 / 1024:.0f}MB, before={before_rss / 1024 / 1024:.0f}MB, "
                + f"after={after_rss / 1024 / 1024:.0f}MB, gc={collected}, cdp_purge={cdp_purged}",
                step="memory",
            )
        emitter.info(prompt, step=step)
        # 取号属于外部 HTTP 轮询，不访问浏览器；长时间无库存时暂停浏览器看门狗，避免误杀 Chrome。
        _pause_browser_watchdog(f"{manual_v2_auto_phone_provider_label} 取号轮询")
        try:
            sms_order = sms_provider.acquire_number(proxy=ctx.proxy, stop_event=ctx.stop_event)
        finally:
            _resume_browser_watchdog("短信取号完成，恢复浏览器流程")
        price_tier_options = sms_order.get("price_tier_options") if isinstance(sms_order.get("price_tier_options"), list) else []
        operator_options = sms_order.get("operator_options") if isinstance(sms_order.get("operator_options"), list) else []
        auto_country_mode = bool(sms_order.get("auto_country_mode"))
        candidate_country_total = int(sms_order.get("country_candidates_total") or 0)
        if price_tier_options:
            preview_rows = []
            for item in price_tier_options[:8]:
                display_stock = None
                try:
                    display_stock = sms_provider._format_price_tier_stock_for_display(item)  # type: ignore[attr-defined]
                except Exception:
                    display_stock = item.get("count") if item.get("count") is not None else None
                source_text = str(item.get("source") or "").strip()
                extra_flags = []
                if source_text:
                    extra_flags.append(source_text)
                if item.get("is_default_price"):
                    extra_flags.append("default")
                if item.get("is_min_price"):
                    extra_flags.append("min")
                preview_rows.append(
                    f"${item.get('price') if item.get('price') is not None else '-'}"
                    + f"/stock={display_stock if display_stock is not None else '-'}"
                    + (f"/{'/'.join(extra_flags)}" if extra_flags else "")
                )
            emitter.info(
                (
                    f"浏览器模式2 {manual_v2_auto_phone_provider_label} 自动国家候选首个国家价档："
                    if auto_country_mode
                    else f"浏览器模式2 {manual_v2_auto_phone_provider_label} 当前国家可选价格档："
                )
                + ", ".join(preview_rows),
                step=step,
            )
        elif operator_options:
            preview_rows = []
            for item in operator_options[:6]:
                preview_rows.append(
                    f"{str(item.get('operator') or '-').strip() or '-'}"
                    + f":${item.get('price') if item.get('price') is not None else '-'}"
                    + f"/stock={item.get('count') if item.get('count') is not None else '-'}"
                )
            emitter.info(
                f"浏览器模式2 {manual_v2_auto_phone_provider_label} 运营商报价（兼容接口）："
                + ", ".join(preview_rows),
                step=step,
            )
        else:
            emitter.info(
                (
                    f"浏览器模式2 {manual_v2_auto_phone_provider_label} 自动国家模式本轮没有拿到细分价格档，直接按候选国家聚合价取号；"
                    if auto_country_mode
                    else f"浏览器模式2 {manual_v2_auto_phone_provider_label} 本轮没有拿到细分价格档，直接按国家聚合池取号；"
                )
                + f"参考价 ${sms_order.get('aggregate_price') if sms_order.get('aggregate_price') is not None else '-'}"
                + f"，库存 {sms_order.get('aggregate_count') if sms_order.get('aggregate_count') is not None else '-'}。",
                step=step,
            )
        debug_events = sms_order.get("debug_events") if isinstance(sms_order.get("debug_events"), list) else []
        if debug_events:
            emitter.info(
                f"浏览器模式2 {manual_v2_auto_phone_provider_label} 取号过程："
                + " || ".join(str(item) for item in debug_events[:12]),
                step=step,
            )
        if sms_order.get("used_hidden_ceiling_fallback"):
            emitter.info(
                f"浏览器模式2 {manual_v2_auto_phone_provider_label} 当前页面展示的价档里，没有不超过你设置上限的低价档；"
                + f"本轮改为直接探测隐藏低价池（不超过 ${sms_order.get('max_price') if sms_order.get('max_price') is not None else sms_order.get('target_price')}）"
                + "，所以实际成交价可能低于当前页面展示的最低档。",
                step=step,
            )
        manual_v2_phone_number = str(sms_order.get("phone_number") or "").strip()
        manual_v2_sms_activation_id = str(sms_order.get("activation_id") or "").strip()
        manual_v2_sms_purchased_at = time.time()
        manual_v2_sms_provider_done = False
        manual_v2_sms_country_id = sms_order.get("country")
        manual_v2_sms_country_iso = str(sms_order.get("country_iso_code") or "").strip().upper()
        manual_v2_sms_country_name = str(sms_order.get("country_name") or "").strip()
        manual_v2_sms_country_result_recorded = False
        if not manual_v2_phone_number or not manual_v2_sms_activation_id:
            raise RuntimeError("浏览器模式2 自动取号失败：缺少手机号或 activation_id")
        sms_provider.mark_ready(manual_v2_sms_activation_id, proxy=ctx.proxy)
        price_mode_label = ""
        if str(sms_order.get("price_mode") or "") == "ceiling":
            price_mode_label = "按价格上限模式"
        elif str(sms_order.get("price_mode") or "") == "fixed":
            price_mode_label = "按固定价模式"
        elif str(sms_order.get("price_mode") or "") == "range":
            price_mode_label = "按价格区间模式"
        elif str(sms_order.get("price_mode") or "") == "auto":
            price_mode_label = "按自动最低价模式"
        emitter.info(
            f"浏览器模式2 已从 {manual_v2_auto_phone_provider_label} 成功取到手机号："
            + manual_v2_phone_number
            + f"（隐藏显示 {_mask_secret(manual_v2_phone_number, head=8, tail=4)}）"
            + f"，国家 {str(sms_order.get('country_name') or '').strip() or sms_order.get('country') or '-'}"
            + (
                f"，{price_mode_label}"
                if price_mode_label
                else ""
            )
            + (
                f"，价格区间 ${sms_order.get('min_price')}-${sms_order.get('max_price')}"
                if sms_order.get("price_mode") == "range" and sms_order.get("min_price") is not None and sms_order.get("max_price") is not None
                else ""
            )
            + (
                f"，价格上限 ${sms_order.get('max_price')}"
                if sms_order.get("price_mode") != "range" and sms_order.get("max_price") is not None
                else ""
            )
            + (
                "，本次来自隐藏低价池"
                if sms_order.get("used_hidden_ceiling_fallback")
                else ""
            )
            + (
                f"，目标价 ${sms_order.get('target_price')}"
                if sms_order.get("target_price") is not None and sms_order.get("max_price") is None
                else ""
            )
            + (
                f"，自动国家候选 {candidate_country_total} 个"
                if auto_country_mode and candidate_country_total > 0
                else ""
            )
            + (
                f"，参考聚合价 ${sms_order.get('aggregate_price')}"
                if sms_order.get("aggregate_price") is not None
                else ""
            )
            + f"，参考库存 {sms_order.get('aggregate_count') if sms_order.get('aggregate_count') is not None else '-'}"
            + f"，运营商 {str(sms_order.get('operator') or '').strip() or '任何运营商'}"
            + (
                "（已从运营商报价回退到国家聚合池）"
                if sms_order.get("operator_fallback_to_aggregate")
                else ""
            )
            + (
                f"，运营商报价 ${sms_order.get('selected_operator_price')}"
                if sms_order.get("selected_operator_price") is not None
                else ""
            )
            + (
                f"，实际成交价 ${sms_order.get('activation_cost')}"
                if sms_order.get("activation_cost") is not None
                else ""
            )
            + (
                f"，余额从 ${sms_order.get('balance_before')} 变为 ${sms_order.get('balance_after')}"
                if sms_order.get("balance_before") is not None and sms_order.get("balance_after") is not None
                else ""
            )
            + "，并已标记为可接收短信。",
            step=step,
        )
        emitter.info(
            f"浏览器模式2 {manual_v2_auto_phone_provider_label} 接口探测结果：余额接口可用，价格接口可用，运营商接口可用；"
            + "价格校验接口返回 BAD_ACTION（当前按兼容方式处理）。",
            step=step,
        )
        return manual_v2_phone_number

    def _normalize_manual_v2_sms_code(raw: Any) -> str:
        """只认 6 位短信码，其余一律当没收到。

        OpenAI 的验证码固定 6 位；接码平台偶尔会把短信里别的数字（如 STATUS_WAIT_RETRY
        带回的旧码）当成验证码返回，拿去填必然失败，不如直接弃号换下一个。
        """
        text = str(raw or "").strip()
        if not text:
            return ""
        matched = re.search(r"(?<!\d)\d{6}(?!\d)", text)
        return matched.group(0) if matched else ""

    def _wait_manual_v2_auto_sms_code(*, step: str, prompt: str, timeout_seconds: int = 60) -> str:
        nonlocal manual_v2_cached_sms_code
        if not manual_v2_auto_phone_mode or sms_provider is None:
            raise RuntimeError("浏览器模式2 当前未启用自动短信验证码模式")
        if not manual_v2_sms_activation_id:
            # 还没完成步骤1取号就误进验证码页时，返回空串让外层回退，而不是直接炸流程。
            emitter.warn(
                "浏览器模式2 当前尚未拿到 SMSBower/HeroSMS activation_id，"
                + "跳过短信验证码轮询并回到步骤1继续取号/提交手机号...",
                step=step,
            )
            return ""
        if manual_v2_cached_sms_code:
            code = manual_v2_cached_sms_code
            manual_v2_cached_sms_code = ""
            emitter.success(f"浏览器模式2 已直接复用此前收到的 {manual_v2_auto_phone_provider_label} 短信验证码: {code}", step=step)
            return code
        emitter.info(prompt, step=step)
        _pause_browser_watchdog(f"{manual_v2_auto_phone_provider_label} 等待短信")
        try:
            raw_code = str(
                sms_provider.wait_for_code(
                    manual_v2_sms_activation_id,
                    proxy=ctx.proxy,
                    timeout_seconds=timeout_seconds,
                    poll_interval_seconds=2.5,
                    stop_event=stop_event,
                )
                or ""
            ).strip()
        finally:
            _resume_browser_watchdog("短信等待完成，恢复浏览器流程")
        code = _normalize_manual_v2_sms_code(raw_code)
        if code:
            emitter.success(f"浏览器模式2 已从 {manual_v2_auto_phone_provider_label} 自动收到短信验证码: {code}", step=step)
        elif raw_code:
            emitter.warn(
                f"浏览器模式2 {manual_v2_auto_phone_provider_label} 返回的短信内容不含 6 位验证码: {raw_code}；"
                + "本地直接放弃当前号码并回到步骤1重新取号...",
                step=step,
            )
        return code

    def _probe_manual_v2_auto_sms_code() -> str:
        nonlocal manual_v2_cached_sms_code
        if not manual_v2_auto_phone_mode or sms_provider is None or not manual_v2_sms_activation_id:
            return ""
        if manual_v2_cached_sms_code:
            return manual_v2_cached_sms_code
        # 非 6 位的码不入缓存，避免上游据此误判"验证码已就绪"
        code = _normalize_manual_v2_sms_code(
            sms_provider.peek_code(manual_v2_sms_activation_id, proxy=ctx.proxy)
        )
        if code:
            manual_v2_cached_sms_code = code
        return manual_v2_cached_sms_code

    def _handle_manual_v2_phone_submit_stall(current_url: str, body_text: str) -> bool:
        nonlocal password_submitted, manual_v2_password_page_logged
        nonlocal manual_v2_create_password_submit_attempts, manual_v2_phone_submit_stall_attempts
        nonlocal manual_v2_contact_seen, manual_v2_wait_phone_logged, manual_v2_wait_phone_last_url
        nonlocal manual_v2_waiting_phone_retry, manual_v2_waiting_phone_retry_logged
        nonlocal manual_v2_require_phone_resubmit, manual_v2_reset_password_flow_started
        nonlocal manual_v2_reset_password_continue_clicked, manual_v2_sms_code_submitted
        nonlocal manual_v2_phone_number, manual_v2_sms_activation_id, manual_v2_sms_purchased_at
        nonlocal manual_v2_sms_provider_done
        nonlocal page
        # 再解析一次活动页，并尝试把 iframe 内的 auth 业务页提升到顶层。
        active_page = _resolve_active_page(page, timeout_ms=1800)
        if active_page is not None:
            page = active_page
        page, recheck_url, recheck_body = _promote_auth_target_if_needed(page, timeout_ms=2500)
        password_input_visible = _first_visible_locator(
            page,
            [
                'input[type="password"]',
                'input[name="password"]',
                'input[name="new-password"]',
                'input[autocomplete="new-password"]',
            ],
        ) is not None
        left_bridge = (
            _is_create_account_password_page(recheck_url, recheck_body, page)
            or _is_login_password_page(recheck_url, recheck_body, page)
            or _is_passkey_challenge_page(recheck_url, recheck_body, page)
            or _is_contact_verification_page(recheck_url, recheck_body, page)
            or password_input_visible
            or (
                "auth.openai.com" in str(recheck_url or "").lower()
                and any(
                    token in str(recheck_url or "").lower()
                    for token in (
                        "create-account/password",
                        "auth_challenge",
                        "log-in/password",
                        "contact-verification",
                        "about-you",
                    )
                )
            )
            or (
                _has_recent_network_url(recent_network_events, "create-account/password", within_seconds=20.0)
                and password_input_visible
            )
        )
        # 仍停在 chatgpt 首页壳且没有真实密码控件时，不算离开。
        if left_bridge and "chatgpt.com" in str(recheck_url or "").lower() and not password_input_visible:
            if not any(
                token in str(recheck_url or "").lower()
                for token in ("create-account/password", "auth_challenge", "log-in/password")
            ):
                left_bridge = False
        if left_bridge:
            manual_v2_phone_submit_stall_attempts = 0
            emitter.info(
                "浏览器模式2 步骤1手机号提交后二次确认已离开桥接/手机号页，"
                + f"继续后续流程... current_url={_mask_secret(recheck_url, head=72, tail=18)}"
                + f", state={_classify_page_state(recheck_url, recheck_body, page)}"
                + f", frames={_preview_text(' | '.join(_collect_auth_frame_urls(page)[:4]), 180)}",
                step="add_phone",
            )
            return False
        current_url = recheck_url or current_url
        body_text = recheck_body or body_text
        # 若其实已是限流/可重试错误页，不要当成“号码无效”反复重提手机号（会加速限流）。
        if _is_rate_limit_error_page(current_url, body_text) or _is_retryable_error_page(current_url, body_text):
            manual_v2_phone_submit_stall_attempts = 0
            emitter.warn(
                "浏览器模式2 步骤1手机号提交后命中错误/限流页，不再按号码无效重提："
                + f" rate_limit={_is_rate_limit_error_page(current_url, body_text)}"
                + f", detail={_preview_text(body_text, 160)}",
                step="add_phone",
            )
            if _try_recover_timeout_error_page(
                current_url,
                body_text,
                step="add_phone",
                action_label="步骤1手机号提交后错误/限流页已触发当前页重试",
                timeout_ms=20000,
            ):
                return True
            return True
        stall_state = _classify_page_state(current_url, body_text, page)
        manual_v2_phone_submit_stall_attempts += 1
        stall_limit = 3
        if manual_v2_phone_submit_stall_attempts < stall_limit:
            emitter.warn(
                "浏览器模式2 步骤1手机号提交后站点仍未真正离开当前桥接/手机号页，"
                + f"准备第 {manual_v2_phone_submit_stall_attempts}/{stall_limit} 次确认后再判定当前号码无效..."
                + f" state={stall_state}"
                + f", current_url={_mask_secret(current_url, head=56, tail=12)}"
                + f", pages={_page_navigation_debug_summary(page)}",
                step="add_phone",
            )
            # 给 SPA 跳转留观察窗口，避免立即废弃有效号码。
            _wait_for_load(page, timeout_ms=1800)
            _sleep_with_page(page, 1200)
            return False
        password_submitted = False
        manual_v2_password_page_logged = False
        manual_v2_create_password_submit_attempts = 0
        manual_v2_phone_submit_stall_attempts = 0
        manual_v2_contact_seen = False
        manual_v2_wait_phone_logged = False
        manual_v2_wait_phone_last_url = ""
        manual_v2_waiting_phone_retry = False
        manual_v2_waiting_phone_retry_logged = False
        manual_v2_require_phone_resubmit = False
        manual_v2_reset_password_flow_started = False
        manual_v2_reset_password_continue_clicked = False
        manual_v2_sms_code_submitted = False
        if manual_v2_auto_phone_mode:
            _finish_manual_v2_sms_provider(success=False)
            manual_v2_phone_number = ""
            manual_v2_sms_activation_id = ""
            manual_v2_sms_purchased_at = 0.0
            manual_v2_sms_provider_done = False
            _prepare_manual_v2_signup_flow(
                "浏览器模式2 步骤1手机号提交后连续 3 次确认仍卡在首页桥接弹层/手机号页；"
                + f"已废弃当前 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取号..."
            )
        else:
            manual_v2_phone_number = ""
            _prepare_manual_v2_signup_flow(
                "浏览器模式2 步骤1手机号提交后连续两次仍卡在首页桥接弹层/手机号页；"
                + "已判定当前手机号不可用，回到步骤1重新输入新的手机号..."
            )
        return True

    def _record_manual_v2_sms_country_result(*, success: bool) -> None:
        # 连败国家软禁已停用：不再记账、不禁取、不输出连败日志。
        nonlocal manual_v2_sms_country_result_recorded
        if manual_v2_sms_country_result_recorded:
            return
        manual_v2_sms_country_result_recorded = True
        return

    def _finish_manual_v2_sms_provider(*, success: bool) -> None:
        nonlocal manual_v2_sms_provider_done, manual_v2_sms_purchased_at
        if sms_provider is None or not manual_v2_sms_activation_id or manual_v2_sms_provider_done:
            if success or (manual_v2_sms_activation_id and not manual_v2_sms_country_result_recorded):
                _record_manual_v2_sms_country_result(success=success)
            return
        try:
            if success:
                sms_provider.complete(manual_v2_sms_activation_id, proxy=ctx.proxy)
                emitter.info(
                    f"浏览器模式2 已在 Token/流程成功后完成 {manual_v2_auto_phone_provider_label} 激活，避免号码继续占用。"
                    + f" activation_id={manual_v2_sms_activation_id}, phone={manual_v2_phone_number or '-'}",
                    step="get_token",
                )
            else:
                cancel_result = sms_provider.cancel(manual_v2_sms_activation_id, proxy=ctx.proxy)
                cancel_code = str((cancel_result or {}).get("code") or "").strip()
                if cancel_result and cancel_result.get("ok"):
                    emitter.info(
                        f"浏览器模式2 因流程失败/退出已取消 {manual_v2_auto_phone_provider_label} 激活，避免继续扣占资源。"
                        + f" activation_id={manual_v2_sms_activation_id}, phone={manual_v2_phone_number or '-'}"
                        + (f", code={cancel_code}" if cancel_code else ""),
                        step="runtime",
                    )
                elif cancel_code == "EARLY_CANCEL_DENIED":
                    waited_seconds = max(0, int(time.time() - float(manual_v2_sms_purchased_at or 0.0)))
                    retry_after_seconds = HERO_SMS_CANCEL_MIN_WAIT_SECONDS
                    try:
                        retry_after_seconds = max(
                            1,
                            int((cancel_result or {}).get("retry_after_seconds") or HERO_SMS_CANCEL_MIN_WAIT_SECONDS),
                        )
                    except (TypeError, ValueError):
                        retry_after_seconds = HERO_SMS_CANCEL_MIN_WAIT_SECONDS
                    schedule_hero_sms_delayed_cancel(
                        provider=sms_provider,
                        activation_id=manual_v2_sms_activation_id,
                        purchased_at=manual_v2_sms_purchased_at,
                        proxy=ctx.proxy,
                        min_wait_seconds=retry_after_seconds,
                        provider_label=manual_v2_auto_phone_provider_label,
                        logger=lambda message: emitter.info(message, step="runtime"),
                    )
                    emitter.warn(
                        f"浏览器模式2 当前流程已结束，但 {manual_v2_auto_phone_provider_label} 尚未到可取消窗口；已转后台延迟取消。"
                        + f" activation_id={manual_v2_sms_activation_id}, phone={manual_v2_phone_number or '-'}"
                        + f", waited={waited_seconds}s, min_wait={retry_after_seconds}s",
                        step="runtime",
                    )
                else:
                    emitter.warn(
                        f"浏览器模式2 {manual_v2_auto_phone_provider_label} 取消未成功，本地流程直接结束。"
                        + f" activation_id={manual_v2_sms_activation_id}, phone={manual_v2_phone_number or '-'}"
                        + f", code={cancel_code or '-'}"
                        + f", message={str((cancel_result or {}).get('message') or '-')}",
                        step="runtime",
                    )
        except Exception as exc:
            try:
                emitter.warn(
                    f"浏览器模式2 {manual_v2_auto_phone_provider_label} 激活收尾调用失败: "
                    + f"success={'是' if success else '否'}, "
                    + f"activation_id={manual_v2_sms_activation_id}, "
                    + f"phone={manual_v2_phone_number or '-'}, "
                    + f"error={exc}",
                    step="runtime",
                )
            except Exception:
                pass
        _record_manual_v2_sms_country_result(success=success)
        manual_v2_sms_provider_done = True

    def _restart_manual_v2_login_oauth(reason: str) -> bool:
        nonlocal current_phase, current_oauth, deadline, email_submitted, password_submitted
        nonlocal manual_v2_login_oauth, manual_v2_login_flow_started, manual_v2_phone_entry_clicked, manual_v2_login_phone_prefilled
        nonlocal manual_v2_login_phone_submitted, manual_v2_login_password_prefilled
        nonlocal manual_v2_post_login_pending_email, manual_v2_bridge_entered_at, manual_v2_bridge_logged
        nonlocal manual_v2_post_login_recover_attempts, manual_v2_post_login_retryable_error_attempts, manual_v2_email_verification_recover_attempts
        nonlocal manual_v2_email_verification_logged, manual_v2_email_otp_completed
        nonlocal manual_v2_oauth_resumed, manual_v2_workspace_logged, manual_v2_wait_phone_logged, manual_v2_wait_phone_last_url
        nonlocal manual_v2_password_page_logged, manual_v2_waiting_phone_retry
        nonlocal manual_v2_waiting_phone_retry_logged, manual_v2_require_phone_resubmit
        nonlocal manual_v2_post_login_oauth_retry_attempts, manual_v2_contact_transition_last_key
        nonlocal manual_v2_phone_submit_stall_attempts, manual_v2_cached_sms_code
        if manual_v2_post_login_oauth_retry_attempts >= manual_v2_post_login_oauth_retry_limit:
            return False
        manual_v2_post_login_oauth_retry_attempts += 1
        emitter.warn(
            f"{str(reason or '').strip() or '浏览器模式2 第二步登录后未进入绑定邮箱链路，重新拉起 OAuth'}"
            + f" 开始第 {manual_v2_post_login_oauth_retry_attempts}/{manual_v2_post_login_oauth_retry_limit} 次第二步 OAuth 重试。",
            step="oauth_init",
        )
        _reset_browser_phase_state(clear_profile=False)
        current_phase = "login"
        email_submitted = False
        password_submitted = False
        manual_v2_login_flow_started = True
        manual_v2_phone_entry_clicked = False
        manual_v2_login_phone_prefilled = False
        manual_v2_login_phone_submitted = False
        manual_v2_login_password_prefilled = False
        manual_v2_post_login_pending_email = False
        manual_v2_bridge_entered_at = 0.0
        manual_v2_bridge_logged = False
        manual_v2_contact_transition_last_key = ""
        manual_v2_post_login_recover_attempts = 0
        manual_v2_post_login_retryable_error_attempts = 0
        manual_v2_email_verification_recover_attempts = 0
        manual_v2_email_verification_logged = False
        manual_v2_email_otp_completed = False
        manual_v2_oauth_resumed = False
        manual_v2_workspace_logged = False
        manual_v2_wait_phone_logged = False
        manual_v2_wait_phone_last_url = ""
        manual_v2_password_page_logged = False
        manual_v2_phone_submit_stall_attempts = 0
        manual_v2_cached_sms_code = ""
        manual_v2_waiting_phone_retry = False
        manual_v2_waiting_phone_retry_logged = False
        manual_v2_require_phone_resubmit = False
        current_oauth = generate_login_oauth_url_func()
        manual_v2_login_oauth = current_oauth
        deadline = time.time() + max(90, int(cfg["browser_timeout_ms"] / 1000) + 60)
        try:
            emitter.info(
                "浏览器模式2 第二步重试 OAuth 授权地址: "
                + _mask_secret(str(getattr(current_oauth, "auth_url", "") or ""), head=160, tail=24),
                step="oauth_init",
            )
        except Exception:
            pass
        _start_oauth_flow(page, current_oauth, "login")
        _wait_for_load(page, timeout_ms=2500)
        current_url, body_text = _describe_page(page)
        if _is_session_ended_login_shell_page(current_url, body_text, page):
            if _click_first(
                page,
                [
                    'a:has-text("Log in")',
                    'button:has-text("Log in")',
                    '[role="button"]:has-text("Log in")',
                    'a:has-text("登录")',
                    'button:has-text("登录")',
                    '[role="button"]:has-text("登录")',
                ],
                timeout_ms=1500,
            ):
                emitter.info("浏览器模式2 第二步 OAuth 重试后命中“你的会话已结束”壳页，已自动点击登录继续...", step="oauth_init")
                _wait_for_load(page, timeout_ms=2500)
        return True

    def _restart_manual_v2_login_page(reason: str) -> bool:
        nonlocal current_phase, deadline, email_submitted, password_submitted
        nonlocal manual_v2_login_flow_started, manual_v2_phone_entry_clicked, manual_v2_login_phone_prefilled
        nonlocal manual_v2_login_phone_submitted, manual_v2_login_password_prefilled
        nonlocal manual_v2_post_login_pending_email, manual_v2_bridge_entered_at, manual_v2_bridge_logged
        nonlocal manual_v2_post_login_recover_attempts, manual_v2_post_login_retryable_error_attempts
        nonlocal manual_v2_email_verification_recover_attempts, manual_v2_email_verification_logged
        nonlocal manual_v2_email_otp_completed, manual_v2_oauth_resumed, manual_v2_workspace_logged
        nonlocal manual_v2_wait_phone_logged, manual_v2_wait_phone_last_url
        nonlocal manual_v2_password_page_logged, manual_v2_waiting_phone_retry
        nonlocal manual_v2_waiting_phone_retry_logged, manual_v2_require_phone_resubmit
        nonlocal manual_v2_contact_transition_last_key, manual_v2_phone_submit_stall_attempts, manual_v2_cached_sms_code
        emitter.warn(str(reason or "").strip() or "浏览器模式2 第二步登录链路准备重新打开 auth.openai.com/log-in 页面", step="oauth_init")
        _reset_browser_phase_state(clear_profile=False)
        current_phase = "login"
        email_submitted = False
        password_submitted = False
        manual_v2_login_flow_started = True
        manual_v2_phone_entry_clicked = False
        manual_v2_login_phone_prefilled = False
        manual_v2_login_phone_submitted = False
        manual_v2_login_password_prefilled = False
        manual_v2_post_login_pending_email = False
        manual_v2_bridge_entered_at = 0.0
        manual_v2_bridge_logged = False
        manual_v2_contact_transition_last_key = ""
        manual_v2_post_login_recover_attempts = 0
        manual_v2_post_login_retryable_error_attempts = 0
        manual_v2_email_verification_recover_attempts = 0
        manual_v2_email_verification_logged = False
        manual_v2_email_otp_completed = False
        manual_v2_oauth_resumed = False
        manual_v2_workspace_logged = False
        manual_v2_wait_phone_logged = False
        manual_v2_wait_phone_last_url = ""
        manual_v2_password_page_logged = False
        manual_v2_phone_submit_stall_attempts = 0
        manual_v2_cached_sms_code = ""
        manual_v2_waiting_phone_retry = False
        manual_v2_waiting_phone_retry_logged = False
        manual_v2_require_phone_resubmit = False
        deadline = time.time() + max(90, int(cfg["browser_timeout_ms"] / 1000) + 60)
        _goto_with_recovery(
            "https://auth.openai.com/log-in",
            step="oauth_init",
            reason="浏览器模式2 重新打开 auth.openai.com/log-in 页面失败",
            wait_until="domcontentloaded",
            timeout_ms=cfg["browser_timeout_ms"],
            max_attempts=2,
        )
        _wait_for_load(page, timeout_ms=2500)
        return True

    def _goto_manual_v2_add_email(reason: str) -> bool:
        try:
            page.goto(
                "https://auth.openai.com/add-email",
                wait_until="domcontentloaded",
                timeout=cfg["browser_timeout_ms"],
            )
        except Exception as exc:
            emitter.warn(f"{reason}；导航过程中被站点自身跳转打断: {exc}", step="create_email")
        _wait_for_load(page, timeout_ms=2500)
        latest_url, latest_body = _describe_page(page)
        if _is_add_email_page(latest_url, latest_body, page):
            return True
        if _is_email_verification_invalid_state_page(latest_url, latest_body):
            emitter.warn(
                "补跳 add-email 后页面直接进入 email-verification invalid_state，等待主循环恢复处理...",
                step="create_email",
            )
            return False
        if _is_login_password_page(latest_url, latest_body, page) or _is_phone_login_entry_page(latest_url, latest_body, page):
            emitter.warn(
                "补跳 add-email 后站点又回到了登录页，等待主循环继续恢复...",
                step="create_email",
            )
            return False
        return False

    def _extend_manual_v2_deadline(seconds: int = 1800) -> None:
        nonlocal deadline
        if not is_manual_v2_mode:
            return
        deadline = max(deadline, time.time() + max(60, int(seconds or 0)))

    emitter.info(
        "当前注册模式: "
        + (
            "浏览器模式2（手机注册）"
            if is_manual_v2_mode
            else ("浏览器手动验证" if is_manual_mode else "浏览器自动化")
        ),
        step="oauth_init",
    )
    emitter.info(
        "浏览器配置: "
        + f"mode={'无头' if cfg['browser_headless'] else '可见'}, "
        + f"timeout={cfg['browser_timeout_ms']}ms, "
        + f"proxy={_mask_secret(ctx.proxy, head=22, tail=10) if ctx.proxy else '直连'}, "
        + f"realistic={'是' if cfg.get('browser_realistic_profile', True) else '否'}, "
        + f"clear_state={'是' if cfg.get('browser_clear_runtime_state') else '否'}, "
        + f"error_keep_open={'是' if cfg.get('browser_keep_open_on_error') else '否'}",
        step="oauth_init",
    )
    if manual_v2_expected_auto_phone_mode and not manual_v2_auto_phone_mode:
        emitter.warn(
            f"浏览器模式2 配置为 {manual_v2_auto_phone_provider_label} 全自动，但运行时未成功初始化短信 provider；"
            + f"当前不会回退成人工输入，请优先检查 {manual_v2_auto_phone_provider_label} API Key / 业务代码 / 保存是否生效。",
            step="oauth_init",
        )
    if manual_v2_hidden_input_mode:
        if manual_v2_auto_phone_mode:
            emitter.info(
                f"浏览器模式2 当前启用无头全自动接码模式：手机号与短信验证码将通过 {manual_v2_auto_phone_provider_label} 自动获取；浏览器窗口不会显示。",
                step="oauth_init",
            )
        else:
            emitter.info(
                "浏览器模式2 当前启用无头人工输入模式：浏览器窗口不会显示；手机号与短信验证码将在 Worker 详情面板中提交。",
                step="oauth_init",
            )
    elif manual_v2_phone_panel_input_mode or manual_v2_sms_panel_input_mode:
        emitter.info(
            "浏览器模式2 当前启用页面运行面板人工输入模式：手机号与短信验证码优先在任务控制卡片中提交；可见浏览器仅用于观察流程。",
            step="oauth_init",
        )
    elif manual_v2_auto_phone_mode:
        emitter.info(
            f"浏览器模式2 当前启用可见全自动接码模式：手机号与短信验证码将通过 {manual_v2_auto_phone_provider_label} 自动获取；浏览器窗口仅用于观察流程。",
            step="oauth_init",
        )
    if manual_v2_manual_email_mode:
        emitter.info(
            "浏览器模式2 当前补邮箱阶段已切换为人工输入：第二步 add-email 与邮箱验证码都将在任务控制卡片中手动提交。",
            step="oauth_init",
        )
    emitter.info(f"本次浏览器指纹: {describe_fingerprint(ctx.fingerprint_profile)}", step="oauth_init")

    playwright = sync_playwright().start()
    launch_resources: Optional[BrowserLaunchResources] = None
    preserve_browser_on_error = False
    watchdog_stop = threading.Event()
    watchdog_triggered = threading.Event()
    watchdog_state_lock = threading.Lock()
    flow_thread_id = threading.get_ident()
    watchdog_state: dict[str, Any] = {
        "at": time.monotonic(),
        "label": "浏览器启动",
        "paused": False,
    }
    watchdog_thread: Optional[threading.Thread] = None

    def _touch_browser_watchdog(label: str) -> None:
        if watchdog_triggered.is_set():
            raise RuntimeError(
                "浏览器自动流程看门狗已终止当前 Chrome，当前流程立即退出并交由外层重试"
            )
        with watchdog_state_lock:
            watchdog_state["at"] = time.monotonic()
            watchdog_state["label"] = str(label or "浏览器流程")
            watchdog_state["paused"] = False

    def _pause_browser_watchdog(label: str) -> None:
        """暂停看门狗，仅用于明确不会访问浏览器的外部等待（如短信平台轮询）。"""
        if watchdog_triggered.is_set():
            raise RuntimeError(
                "浏览器自动流程看门狗已终止当前 Chrome，当前流程立即退出并交由外层重试"
            )
        with watchdog_state_lock:
            watchdog_state["paused"] = True
            watchdog_state["label"] = str(label or "外部等待")

    def _resume_browser_watchdog(label: str) -> None:
        with watchdog_state_lock:
            watchdog_state["paused"] = False
            watchdog_state["at"] = time.monotonic()
            watchdog_state["label"] = str(label or "浏览器流程")

    try:
        if cfg.get("browser_engine") == "roxy":
            try:
                launch_resources = _launch_via_roxy(playwright, ctx, cfg)
                emitter.info(f"浏览器已切换为 Roxy 指纹浏览器模式: {launch_resources.launch_mode}", step="oauth_init")
            except Exception as exc:
                raise RuntimeError(f"Roxy 启动失败，无法继续注册流程: {exc}") from exc
        else:
            try:
                launch_resources = _launch_via_local_uc_bridge(playwright, ctx, cfg)
                emitter.info(f"浏览器已切换为本地 uc 桥接模式: {launch_resources.launch_mode}", step="oauth_init")
            except Exception as exc:
                raise RuntimeError(f"本地 uc 启动失败，无法继续注册流程: {exc}") from exc

        browser = launch_resources.browser
        context = launch_resources.context
        page = launch_resources.page

        if manual_v2_auto_phone_mode and str(cfg.get("browser_engine") or "uc").strip().lower() == "uc":
            watchdog_profile = _canonical_uc_temp_profile(
                getattr(launch_resources, "temp_user_data_dir", "")
            )
            if watchdog_profile:
                def _browser_stall_watchdog() -> None:
                    while not watchdog_stop.wait(5.0):
                        if manual_v2_contact_seen:
                            continue
                        with watchdog_state_lock:
                            last_heartbeat = float(watchdog_state.get("at") or 0.0)
                            last_label = str(watchdog_state.get("label") or "浏览器流程")
                            is_paused = bool(watchdog_state.get("paused"))
                        if is_paused:
                            continue
                        stalled_seconds = max(0.0, time.monotonic() - last_heartbeat)
                        if stalled_seconds < _BROWSER_STALL_WATCHDOG_SECONDS:
                            continue
                        if watchdog_triggered.is_set():
                            return
                        watchdog_triggered.set()
                        # Chrome 被杀后，Playwright driver/chromedriver 仍可能保持 pipe/CDP
                        # 阻塞；精确终止本次任务自己的驱动进程，促使主线程收到连接关闭异常。
                        driver_pids: set[int] = set()
                        try:
                            transport = getattr(
                                getattr(
                                    getattr(playwright, "_impl_obj", None),
                                    "_connection",
                                    None,
                                ),
                                "_transport",
                                None,
                            )
                            driver_pid = int(getattr(getattr(transport, "_proc", None), "pid", 0) or 0)
                            if driver_pid > 0:
                                driver_pids.add(driver_pid)
                        except Exception:
                            pass
                        try:
                            cdp_process = getattr(
                                getattr(getattr(launch_resources, "cdp_driver", None), "service", None),
                                "process",
                                None,
                            )
                            cdp_pid = int(getattr(cdp_process, "pid", 0) or 0)
                            if cdp_pid > 0:
                                driver_pids.add(cdp_pid)
                        except Exception:
                            pass
                        driver_pids.discard(os.getpid())
                        killed_driver_pids = 0
                        try:
                            driver_rows, _ = _read_process_table()
                        except Exception:
                            driver_rows = {}
                        for driver_pid in sorted(driver_pids):
                            driver_command = str(driver_rows.get(driver_pid, (0, 0, ""))[2] or "").lower()
                            if driver_command and not (
                                "playwright/driver/node" in driver_command
                                or "chromedriver" in driver_command
                            ):
                                continue
                            try:
                                os.kill(driver_pid, signal.SIGTERM)
                                killed_driver_pids += 1
                            except (ProcessLookupError, PermissionError, OSError):
                                continue
                        if driver_pids:
                            driver_deadline = time.monotonic() + 1.0
                            pending_driver_pids = set(driver_pids)
                            current_driver_rows = driver_rows
                            while pending_driver_pids and time.monotonic() < driver_deadline:
                                try:
                                    current_driver_rows, _ = _read_process_table()
                                    pending_driver_pids &= set(current_driver_rows)
                                except Exception:
                                    break
                                if not pending_driver_pids:
                                    break
                                time.sleep(0.1)
                            for driver_pid in sorted(pending_driver_pids):
                                try:
                                    current_command = str(
                                        current_driver_rows.get(driver_pid, (0, 0, ""))[2] or ""
                                    ).lower()
                                except Exception:
                                    current_command = ""
                                if current_command and not (
                                    "playwright/driver/node" in current_command
                                    or "chromedriver" in current_command
                                ):
                                    continue
                                try:
                                    os.kill(driver_pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                                    killed_driver_pids += 1
                                except (ProcessLookupError, PermissionError, OSError):
                                    continue
                        current_rss = _process_tree_rss_bytes()
                        top_before = _process_tree_rss_report()
                        stack_text = ""
                        try:
                            flow_frame = sys._current_frames().get(flow_thread_id)
                            if flow_frame is not None:
                                stack_text = " ".join(traceback.format_stack(flow_frame)).strip()
                                stack_text = stack_text[-5000:]
                        except Exception as exc:
                            stack_text = f"stack_unavailable={type(exc).__name__}"
                        try:
                            emitter.error(
                                "浏览器自动流程超过看门狗等待时间没有进度，已终止当前 Chrome 并交由外层重试："
                                + f"stalled={stalled_seconds:.0f}s, last_step={last_label}, "
                                + f"rss={current_rss / 1024 / 1024:.0f}MB, top={top_before}, "
                                + f"driver_killed={killed_driver_pids}, "
                                + f"stack={stack_text or '-'}",
                                step="runtime",
                            )
                        except Exception:
                            pass
                        _cleanup_orphan_uc_processes(
                            emitter,
                            profile_dirs={watchdog_profile},
                            step="runtime",
                        )
                        return

                watchdog_thread = threading.Thread(
                    target=_browser_stall_watchdog,
                    name="opo-browser-stall-watchdog",
                    daemon=True,
                )
                watchdog_thread.start()

        def _trim_obsolete_browser_pages(active_page: Any) -> int:
            """多次 OAuth 重试时关闭不再参与认证的旧首页页签。"""
            try:
                pages = list(getattr(context, "pages", []) or [])
            except Exception:
                return 0
            if len(pages) <= 4:
                return 0
            closed = 0
            for candidate_page in pages:
                if len(pages) - closed <= 4 or candidate_page is active_page:
                    continue
                try:
                    url = str(candidate_page.url or "").strip().lower()
                except Exception:
                    url = ""
                if "code=" in url and "state=" in url:
                    continue
                if "auth.openai.com" in url:
                    continue
                try:
                    candidate_page.close()
                    closed += 1
                except Exception:
                    pass
            return closed

        if not use_plain_browser_env:
            try:
                # 只有用户明确要拦媒体，且未启用拟真档案时，才在无头模式下拦截资源。
                if cfg.get("browser_block_media", False) and cfg["browser_headless"] and not cfg.get("browser_realistic_profile", True):
                    context.route("**/*", _handle_route)
            except Exception:
                pass
            try:
                context.add_init_script(ctx.fingerprint_profile.to_init_script())
            except Exception:
                pass
        _wire_page_once(page)
        last_memory_check_at = 0.0
        try:
            context.on("page", _wire_page_once)
        except Exception:
            pass
        if not use_plain_browser_env:
            try:
                cdp_session = context.new_cdp_session(page)
                cdp_session.send(
                    "Network.setUserAgentOverride",
                    {
                        "userAgent": ctx.fingerprint_profile.user_agent,
                        "acceptLanguage": ctx.fingerprint_profile.accept_language,
                        "platform": ctx.fingerprint_profile.ch_platform,
                        "userAgentMetadata": ctx.fingerprint_profile.to_cdp_user_agent_metadata(),
                    },
                )
                cdp_session.send(
                    "Emulation.setTimezoneOverride",
                    {"timezoneId": ctx.fingerprint_profile.timezone_id},
                )
                cdp_session.send(
                    "Emulation.setLocaleOverride",
                    {"locale": ctx.fingerprint_profile.locale},
                )
            except Exception:
                pass

        try:
            if is_manual_v2_mode:
                emitter.info("浏览器模式2 已恢复为完整注册流程：先打开 ChatGPT 首页执行步骤1，再衔接步骤2手机登录与补邮箱流程...", step="oauth_init")
                _goto_with_recovery(
                    "https://chatgpt.com/",
                    step="oauth_init",
                    reason="浏览器模式2 打开 ChatGPT 首页失败",
                    wait_until="domcontentloaded",
                    timeout_ms=cfg["browser_timeout_ms"],
                    max_attempts=3,
                )
                _wait_for_load(page, timeout_ms=2500)
                emitter.info(
                    f"浏览器模式2 步骤1首页落点: {_mask_secret(page.url, head=48, tail=12)}",
                    step="oauth_init",
                )
                if not cfg["browser_headless"]:
                    emitter.info("当前为可见浏览器模式，可直接观察 ChatGPT 首页到手机注册入口的切换过程", step="oauth_init")
                # 首页落地后立刻尝试入口点击，避免主循环前置条件卡住导致“只停在观察提示”。
                try:
                    landing_url, landing_body = _describe_page(page, force_refresh=True)
                    emitter.info("浏览器模式2 检测到 ChatGPT 首页，正在尝试自动打开手机号注册入口...", step="oauth_init")
                    for attempt in range(1, 4):
                        if _bootstrap_manual_v2_phone_entry(landing_url, landing_body):
                            emitter.info(
                                f"浏览器模式2 首页入口启动成功（第 {attempt}/3 次尝试）",
                                step="oauth_init",
                            )
                            break
                        _wait_for_load(page, timeout_ms=1200)
                        _sleep_with_page(page, 500)
                        landing_url, landing_body = _describe_page(page, force_refresh=True)
                except Exception as exc:
                    _touch_browser_watchdog("首页入口预热失败收口")
                    emitter.warn(f"浏览器模式2 首页入口启动预热失败，将交由主循环继续重试: {exc}", step="oauth_init")
            else:
                _start_oauth_flow(page, current_oauth, current_phase)

            deadline = time.time() + (
                max(6 * 60 * 60, int(cfg["browser_timeout_ms"] / 1000) + 60)
                if is_manual_v2_mode
                else max(90, int(cfg["browser_timeout_ms"] / 1000) + 60)
            )
            while time.time() < deadline:
                if _stopped(ctx.stop_event):
                    return None
                _touch_browser_watchdog("浏览器主循环")

                now = time.time()
                if now - last_memory_check_at >= _BROWSER_MEMORY_CHECK_INTERVAL_SECONDS:
                    last_memory_check_at = now
                    _touch_browser_watchdog("内存检查/清理")
                    current_rss = _process_tree_rss_bytes()
                    if current_rss >= memory_soft_limit:
                        closed_pages = _trim_obsolete_browser_pages(page)
                        cdp_purged = _purge_active_browser_memory(context, page)
                        before_rss, after_rss, collected = _release_memory_pressure(emitter)
                        if after_rss >= memory_hard_limit:
                            top_before = _process_tree_rss_report()
                            _, closed_rss, close_gc, killed = _shutdown_browser_for_memory_pressure(
                                launch_resources,
                                playwright,
                                emitter,
                                target_bytes=memory_hard_limit,
                            )
                            launch_resources = None
                            emitter.warn(
                                "浏览器任务检测到进程内存偏高，已关闭当前浏览器并清理残留进程："
                                + f"rss={current_rss / 1024 / 1024:.0f}MB, before={before_rss / 1024 / 1024:.0f}MB, "
                                + f"after={closed_rss / 1024 / 1024:.0f}MB, closed_pages={closed_pages}, "
                                + f"gc={collected + close_gc}, killed={killed}, cdp_purge={cdp_purged}, "
                                + f"top_before={top_before}",
                                step="memory",
                            )
                            raise RuntimeError(
                                "进程内存超过浏览器任务安全阈值，已停止当前浏览器流程并交由外层重试；"
                                + f"rss_before_close={after_rss / 1024 / 1024:.0f}MB, "
                                + f"rss_after_close={closed_rss / 1024 / 1024:.0f}MB, "
                                + f"hard_limit={memory_hard_limit / 1024 / 1024:.0f}MB"
                            )
                        emitter.warn(
                            "浏览器任务检测到进程内存偏高，已主动清理缓存/历史保留现场并执行垃圾回收："
                            + f"rss={current_rss / 1024 / 1024:.0f}MB, before={before_rss / 1024 / 1024:.0f}MB, "
                            + f"after={after_rss / 1024 / 1024:.0f}MB, closed_pages={closed_pages}, "
                            + f"gc={collected}, cdp_purge={cdp_purged}",
                            step="memory",
                        )
                    _touch_browser_watchdog("内存检查完成")

                if not callback_state["url"]:
                    loopback_callback = _consume_loopback_callback()
                    if loopback_callback:
                        emitter.info("本地 OAuth 回调监听已收到 callback，准备交换 Token...", step="get_token")
                if callback_state["url"]:
                    callback_url_value = str(callback_state["url"] or "").strip()
                    callback_is_real = ("code=" in callback_url_value and "state=" in callback_url_value)
                    oauth_for_exchange = _active_oauth_start()
                    if is_manual_v2_mode and manual_v2_profile_completion_mode and callback_is_real:
                        emitter.info(
                            "浏览器模式2 当前仍处于 reset-password 后的登录后分流阶段；"
                            + "此时还在判定是否需要补资料，即使捕获到真实 callback 也先忽略，"
                            + "等待分流结束后再进入真正的步骤2 OAuth。",
                            step="get_token",
                        )
                        callback_state["url"] = ""
                    elif is_manual_v2_mode and not manual_v2_login_flow_started:
                        # 步骤1注册期（含 about-you 刚完成）出现的 callback 与步骤2 PKCE 不是一套，禁止直接兑换。
                        emitter.info(
                            "浏览器模式2 当前仍处于步骤1注册/补资料阶段，忽略提前出现的 OAuth callback；"
                            + ("资料已提交，准备进入步骤2登录 OAuth..." if profile_submitted else "等待注册前半段完成后再进入步骤2 OAuth..."),
                            step="get_token",
                        )
                        callback_state["url"] = ""
                        if profile_submitted and not manual_v2_login_flow_started:
                            _prepare_manual_v2_login_flow(
                                "浏览器模式2 步骤1已完成且捕获到注册期 callback，已丢弃该 callback，改为重新拉起步骤2 OAuth 登录链路获取 Token..."
                            )
                        continue
                    elif is_manual_v2_mode and not manual_v2_oauth_resumed and not callback_is_real:
                        emitter.info("浏览器模式2 当前仍处于注册前半段，忽略提前出现的 callback 线索，等待进入后续授权流程...", step="get_token")
                        callback_state["url"] = ""
                    else:
                        if is_manual_v2_mode and not manual_v2_oauth_resumed and callback_is_real:
                            # 仅步骤2登录链路启动后，才允许用当前 login OAuth 的 PKCE 兑换。
                            if not manual_v2_login_flow_started:
                                emitter.warn(
                                    "浏览器模式2 捕获到真实 callback，但步骤2登录链路尚未启动，已忽略并准备拉起步骤2 OAuth...",
                                    step="get_token",
                                )
                                callback_state["url"] = ""
                                _prepare_manual_v2_login_flow(
                                    "浏览器模式2 捕获到过早 callback，改为正式进入步骤2 OAuth 登录获取 Token..."
                                )
                                continue
                            emitter.info("浏览器模式2 已捕获真实 OAuth callback，直接使用当前登录链路的 PKCE 参数兑换 Token...", step="get_token")
                            manual_v2_oauth_resumed = True
                        else:
                            emitter.info("已在浏览器中捕获 OAuth callback，准备交换 Token...", step="get_token")
                        try:
                            if is_manual_v2_mode and callback_is_real and callable(exchange_callback_payload_func) and callable(build_token_result_func):
                                raw_token_payload = exchange_callback_payload_func(
                                    callback_url=callback_url_value,
                                    code_verifier=oauth_for_exchange.code_verifier,
                                    redirect_uri=oauth_for_exchange.redirect_uri,
                                    expected_state=oauth_for_exchange.state,
                                    proxy=ctx.proxy or None,
                                )
                                emitter.info(
                                    "浏览器模式2 已拿到 oauth/token 原始响应，优先使用 access_token 直连补齐账号信息，浏览器 session 仅作兜底...",
                                    step="get_token",
                                )
                                session_payload = _fetch_browser_session_payload(
                                    context=context,
                                    emitter=emitter,
                                    referer_url=current_url or callback_url_value,
                                    fallback_email=ctx.email,
                                    page=page,
                                    proxy=str(ctx.proxy or ""),
                                ) or {}
                                token_json = build_token_result_func(
                                    raw_token_payload,
                                    session_payload,
                                    proxy=ctx.proxy or None,
                                    emitter=emitter,
                                    fallback_email=ctx.email,
                                )
                            else:
                                token_json = submit_callback_func(
                                    callback_url=callback_url_value,
                                    code_verifier=oauth_for_exchange.code_verifier,
                                    redirect_uri=oauth_for_exchange.redirect_uri,
                                    expected_state=oauth_for_exchange.state,
                                    proxy=ctx.proxy or None,
                                )
                        except Exception as exc:
                            exc_text = str(exc or "")
                            if is_manual_v2_mode and "state mismatch" in exc_text.lower() and callback_is_real:
                                parsed_cb = urllib.parse.urlparse(callback_url_value)
                                callback_state_value = (
                                    urllib.parse.parse_qs(parsed_cb.query).get("state", [""])[0] or ""
                                ).strip()
                                emitter.warn(
                                    "浏览器模式2 callback 首次兑换触发 state mismatch，准备使用 callback 中的实际 state 再试一次。"
                                    + f" expected={_mask_secret(oauth_for_exchange.state, head=10, tail=8)},"
                                    + f" callback={_mask_secret(callback_state_value, head=10, tail=8)}",
                                    step="get_token",
                                )
                                try:
                                    if callable(exchange_callback_payload_func) and callable(build_token_result_func):
                                        raw_token_payload = exchange_callback_payload_func(
                                            callback_url=callback_url_value,
                                            code_verifier=oauth_for_exchange.code_verifier,
                                            redirect_uri=oauth_for_exchange.redirect_uri,
                                            expected_state=(callback_state_value or oauth_for_exchange.state),
                                            proxy=ctx.proxy or None,
                                        )
                                        emitter.info(
                                            "浏览器模式2 state 重试兑换成功，继续用 access_token 直连补齐账号信息...",
                                            step="get_token",
                                        )
                                        session_payload = _fetch_browser_session_payload(
                                            context=context,
                                            emitter=emitter,
                                            referer_url=current_url or callback_url_value,
                                            fallback_email=ctx.email,
                                            page=page,
                                            proxy=str(ctx.proxy or ""),
                                        ) or {}
                                        token_json = build_token_result_func(
                                            raw_token_payload,
                                            session_payload,
                                            proxy=ctx.proxy or None,
                                            emitter=emitter,
                                            fallback_email=ctx.email,
                                        )
                                    else:
                                        token_json = submit_callback_func(
                                            callback_url=callback_url_value,
                                            code_verifier=oauth_for_exchange.code_verifier,
                                            redirect_uri=oauth_for_exchange.redirect_uri,
                                            expected_state=(callback_state_value or oauth_for_exchange.state),
                                            proxy=ctx.proxy or None,
                                        )
                                except Exception as retry_exc:
                                    # 注册期 callback 与步骤2 PKCE 不匹配时，改走正式步骤2，而不是直接失败。
                                    emitter.warn(
                                        "浏览器模式2 state mismatch 重试仍失败，判定当前 callback 不属于步骤2 PKCE 会话；"
                                        + f" error={retry_exc}；丢弃该 callback 并重新拉起步骤2 OAuth 登录链路...",
                                        step="get_token",
                                    )
                                    callback_state["url"] = ""
                                    manual_v2_oauth_resumed = False
                                    if not manual_v2_login_flow_started or profile_submitted or True:
                                        _prepare_manual_v2_login_flow(
                                            "浏览器模式2 因 callback/PKCE 不匹配，已丢弃当前 callback，重新进入步骤2 OAuth 登录获取 Token..."
                                        )
                                    continue
                            elif is_manual_v2_mode and (
                                "token_exchange_user_error" in exc_text
                                or "token exchange failed" in exc_text.lower()
                                or "invalid_request_error" in exc_text.lower()
                            ):
                                emitter.warn(
                                    "浏览器模式2 Token 兑换失败，可能用了注册阶段 callback/PKCE；"
                                    + f" error={_preview_text(exc_text, 180)}；丢弃 callback 并改走步骤2 OAuth 登录链路...",
                                    step="get_token",
                                )
                                callback_state["url"] = ""
                                manual_v2_oauth_resumed = False
                                _prepare_manual_v2_login_flow(
                                    "浏览器模式2 Token 兑换失败后，重新拉起步骤2 OAuth 登录获取 Token..."
                                )
                                continue
                            elif "token result missing email/account_id" in exc_text.lower():
                                emitter.warn(
                                    "浏览器模式2 当前页 access_token + session 仍未补齐 email/account_id，准备再次读取一次浏览器 session payload 复核...",
                                    step="get_token",
                                )
                                _session_recovered = False
                                try:
                                    _sleep_with_page(page, 1200)
                                    session_payload_retry = _fetch_browser_session_payload(
                                        context=context,
                                        emitter=emitter,
                                        referer_url=current_url or callback_url_value,
                                        fallback_email=ctx.email,
                                        page=page,
                                        proxy=str(ctx.proxy or ""),
                                    ) or {}
                                    token_json = build_token_result_func(
                                        raw_token_payload,
                                        session_payload_retry,
                                        proxy=ctx.proxy or None,
                                        emitter=emitter,
                                        fallback_email=ctx.email,
                                    )
                                    _session_recovered = True
                                except Exception as retry_exc:
                                    emitter.warn(
                                        f"浏览器模式2 二次组装仍失败: {retry_exc}",
                                        step="get_token",
                                    )
                                if _session_recovered:
                                    _finish_manual_v2_sms_provider(success=True)
                                    emitter.success("浏览器模式2 二次组装恢复成功，Token 已获取", step="get_token")
                                    return token_json
                                emitter.warn(
                                    "浏览器模式2 token 交换已完成，但 access_token 直连补齐 + 浏览器 session 兜底后仍缺 email/account_id；请查看上方组装诊断日志继续排查。",
                                    step="get_token",
                                )
                                raise
                            else:
                                raise
                        emitter.success(
                            "浏览器" + ("二次登录" if current_phase == "login" else "注册") + "获取 Token 成功",
                            step="get_token",
                        )
                        _finish_manual_v2_sms_provider(success=True)
                        return token_json

                _touch_browser_watchdog("解析当前浏览器页面")
                _touch_browser_watchdog("活动页选择")
                active_page = _resolve_active_page(page, timeout_ms=1500)
                if active_page is None:
                    if callback_state["url"]:
                        continue
                    _sleep_with_page(None, 300)
                    continue

                _touch_browser_watchdog("页面正文读取")
                current_url, body_text = _describe_page(page)
                current_url_lower = current_url.lower()
                body_lower = body_text.lower()
                _touch_browser_watchdog("页面状态分类")
                cloudflare_blocker = _detect_cloudflare_blocker(page, current_url, body_text)
                if cloudflare_blocker:
                    blocker_key = f"cf:{current_url_lower}:{cloudflare_blocker}"
                    if blocker_key != manual_v2_entry_bootstrap_signature:
                        manual_v2_entry_bootstrap_signature = blocker_key
                        manual_v2_entry_bootstrap_seen_at = time.time()
                        emitter.info(
                            "浏览器当前命中 Cloudflare / Just a moment 校验，先暂停后续自动点击并等待页面自行通过: "
                            + _preview_text(cloudflare_blocker, 120),
                            step="oauth_init",
                        )
                    _wait_for_load(page, timeout_ms=2200)
                    _simulate_human_idle(page)
                    _sleep_with_page(page, random.randint(2600, 5200))
                    continue
                otp_route_locked = ("email-verification" in current_url_lower or "email-otp" in current_url_lower)
                callback_candidate = _extract_callback_url_from_page(current_url, body_text)
                if callback_candidate and not callback_state["url"]:
                    callback_is_real = ("code=" in callback_candidate and "state=" in callback_candidate)
                    if is_manual_v2_mode and manual_v2_profile_completion_mode and callback_is_real:
                        emitter.info(
                            "浏览器模式2 当前仍处于 reset-password 后的登录后分流阶段；"
                            + "页面里即使出现真实 callback 也先忽略，等待判定完是否需要补资料后再进入真正的步骤2 OAuth。",
                            step="get_token",
                        )
                    elif is_manual_v2_mode and not manual_v2_login_flow_started:
                        emitter.info(
                            "浏览器模式2 步骤1阶段从页面提取到 OAuth callback，先忽略；"
                            + ("资料已完成则转入步骤2 OAuth..." if profile_submitted else "等步骤1完成后再取 Token..."),
                            step="get_token",
                        )
                        if profile_submitted:
                            _prepare_manual_v2_login_flow(
                                "浏览器模式2 步骤1已完成，忽略注册期 callback，正式进入步骤2 OAuth 登录获取 Token..."
                            )
                        continue
                    elif is_manual_v2_mode and not manual_v2_oauth_resumed and not callback_is_real:
                        emitter.info("浏览器模式2 注册前半段检测到 callback 线索，暂不处理，等待后续授权流程重新拉起...", step="get_token")
                    else:
                        if is_manual_v2_mode and not manual_v2_oauth_resumed and callback_is_real:
                            if not manual_v2_login_flow_started:
                                continue
                            emitter.info("浏览器模式2 已从页面提取到真实 OAuth callback，准备直接兑换 Token...", step="get_token")
                        else:
                            emitter.info("已从页面跳转/错误页文本中提取到 OAuth callback，准备继续交换 Token...", step="get_token")
                        _record_callback(callback_candidate)
                        continue

                if _is_session_ended_page(current_url, body_text):
                    if (
                        is_manual_v2_mode
                        and manual_v2_login_flow_started
                        and manual_v2_post_login_pending_email
                    ):
                        emitter.warn(
                            "浏览器模式2 第二步登录后命中了会话结束提示页，先保留当前上下文，不立即重拉 OAuth，继续等待绑定邮箱链路...",
                            step="oauth_init",
                        )
                        _wait_for_load(page, timeout_ms=1800)
                        _sleep_with_page(page, 800)
                        continue
                    # 步骤1（手机注册）中途：短信/密码/资料已进行时，禁止重拉 signup OAuth，
                    # 否则会清掉 contact_seen 并跳到 create-account 邮箱页，把本轮注册冲掉。
                    if is_manual_v2_mode and not manual_v2_login_flow_started and (
                        manual_v2_contact_seen
                        or manual_v2_sms_code_submitted
                        or password_submitted
                        or bool(str(manual_v2_sms_activation_id or "").strip())
                    ):
                        emitter.warn(
                            "浏览器模式2 步骤1注册中途命中会话结束提示，保留本轮手机号/短信上下文，不重拉 OAuth；"
                            + "继续提升/观察 auth 页并等待 about-you 或后续自然跳转..."
                            + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                            step="phone_verification",
                        )
                        page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                        current_url_lower = str(current_url or "").lower()
                        # 若是可点的会话结束壳，只点 Log in / Continue，不要清注册状态。
                        _click_first(
                            page,
                            [
                                'a:has-text("Log in")',
                                'button:has-text("Log in")',
                                '[role="button"]:has-text("Log in")',
                                'a:has-text("Continue")',
                                'button:has-text("Continue")',
                                '[role="button"]:has-text("Continue")',
                                'a:has-text("登录")',
                                'button:has-text("登录")',
                                'a:has-text("继续")',
                                'button:has-text("继续")',
                            ],
                            timeout_ms=1200,
                        )
                        _wait_for_load(page, timeout_ms=1800)
                        _sleep_with_page(page, 800)
                        continue
                    session_recover_attempts += 1
                    if session_recover_attempts > 2:
                        raise RuntimeError("浏览器页面连续提示 session 已结束，无法继续推进注册流程")
                    recovered = _click_first(
                        page,
                        [
                            'a:has-text("Sign up")',
                            'button:has-text("Sign up")',
                            '[role="button"]:has-text("Sign up")',
                            'a:has-text("Log in")',
                            'button:has-text("Log in")',
                            '[role="button"]:has-text("Log in")',
                        ],
                        timeout_ms=1200,
                    )
                    if recovered:
                        emitter.warn("浏览器页面提示会话已结束，尝试在当前页面恢复流程...", step="oauth_init")
                        _reset_browser_phase_state(clear_profile=True)
                        _wait_for_load(page)
                    else:
                        _restart_current_page_oauth_flow(
                            target_phase=current_phase,
                            reason="浏览器页面提示会话已结束，准备在当前页面重新拉起 OAuth 流程...",
                        )
                    continue

                if (
                    "chatgpt.com" in current_url_lower
                    and "/api/auth/session" not in current_url_lower
                    and not callback_state["url"]
                    and not is_manual_v2_mode
                ):
                    session_fast_path_token = _try_browser_session_fast_path(current_url)
                    if session_fast_path_token:
                        return session_fast_path_token

                if is_manual_v2_mode:
                    _extend_manual_v2_deadline(1800)
                    _touch_browser_watchdog("认证页/frame 提升")
                    page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                    current_url_lower = str(current_url or "").lower()
                    body_lower = str(body_text or "").lower()
                    is_create_password_page = _is_create_account_password_page(current_url, body_text, page)
                    is_reset_new_password_page = _is_reset_password_new_password_page(current_url, body_text, page)
                    is_login_password_page = _is_login_password_page(current_url, body_text, page)
                    is_passkey_challenge_page = _is_passkey_challenge_page(current_url, body_text, page)
                    is_phone_stage_page = (
                        not is_create_password_page
                        and not is_reset_new_password_page
                        and not is_login_password_page
                        and not is_passkey_challenge_page
                        and (
                            _is_phone_input_page(current_url, body_text, page)
                            or _is_phone_verification_page(current_url, body_text, page)
                        )
                    )
                    _touch_browser_watchdog("手机输入值读取")
                    captured_phone = _extract_input_value_by_hints(
                        page,
                        ["phone", "mobile", "手机号", "电话", "tel"],
                    )
                    if captured_phone:
                        manual_v2_phone_number = captured_phone

                    # 步骤1任意阶段：号码已绑定旧账号（含 “sign in to h****@o****.com using usual sign-in method”）
                    # 立即废弃当前号并重新取号，不要卡在登录引导页。
                    _touch_browser_watchdog("手机号状态识别")
                    if (
                        not manual_v2_login_flow_started
                        and _is_phone_number_existing_account_error(current_url, body_text, page)
                    ):
                        password_submitted = False
                        profile_submitted = False
                        manual_v2_password_page_logged = False
                        manual_v2_create_password_submit_attempts = 0
                        manual_v2_contact_seen = False
                        manual_v2_phone_submit_stall_attempts = 0
                        if manual_v2_auto_phone_mode:
                            _finish_manual_v2_sms_provider(success=False)
                            manual_v2_phone_number = ""
                            manual_v2_sms_activation_id = ""
                            manual_v2_sms_purchased_at = 0.0
                            manual_v2_sms_provider_done = False
                            _prepare_manual_v2_signup_flow(
                                "浏览器模式2 步骤1检测到手机号已绑定既有账号"
                                + "（如 To continue, sign in to ***@***.com using that account's usual sign-in method）；"
                                + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                            )
                        else:
                            manual_v2_phone_number = ""
                            _prepare_manual_v2_signup_flow(
                                "浏览器模式2 步骤1检测到手机号已绑定既有账号"
                                + "（如要求使用原邮箱/常用登录方式登录）；"
                                + "已回到步骤1，请重新输入新的手机号..."
                            )
                        continue

                    if (
                        is_phone_stage_page
                        and not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                        and password_submitted
                    ):
                        password_submitted = False
                        profile_submitted = False
                        manual_v2_contact_seen = False
                        manual_v2_wait_contact_logged = False
                        manual_v2_password_page_logged = False
                        manual_v2_reset_password_flow_started = False
                        manual_v2_reset_password_continue_clicked = False
                        emitter.info(
                            "浏览器模式2 检测到已回到首页/手机号输入阶段，已清理上一轮密码提交状态，等待重新输入手机号。",
                            step="add_phone",
                        )

                    if (
                        not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                        and not is_create_password_page
                        and not is_reset_new_password_page
                        and not is_login_password_page
                        and not is_passkey_challenge_page
                        and "chatgpt.com" in current_url_lower
                        and not _has_phone_input(page)
                    ):
                        _touch_browser_watchdog("注册入口探测")
                        if not manual_v2_entry_bootstrap_logged:
                            manual_v2_entry_bootstrap_logged = True
                            emitter.info("浏览器模式2 检测到 ChatGPT 首页，正在尝试自动打开手机号注册入口...", step="oauth_init")
                        if _bootstrap_manual_v2_phone_entry(current_url, body_text):
                            current_url, body_text = _describe_page(page)
                            current_url_lower = current_url.lower()
                            body_lower = body_text.lower()
                            is_create_password_page = _is_create_account_password_page(current_url, body_text, page)
                            is_reset_new_password_page = _is_reset_password_new_password_page(current_url, body_text, page)
                            is_login_password_page = _is_login_password_page(current_url, body_text, page)
                            is_passkey_challenge_page = _is_passkey_challenge_page(current_url, body_text, page)
                    else:
                        manual_v2_entry_bootstrap_logged = False
                        manual_v2_entry_bootstrap_signature = ""
                        manual_v2_entry_bootstrap_seen_at = 0.0
                        manual_v2_entry_bootstrap_wait_logged = False

                    if is_create_password_page:
                        manual_v2_wait_phone_logged = False
                        manual_v2_wait_phone_last_url = ""
                        if not manual_v2_password_page_logged:
                            manual_v2_password_page_logged = True
                            emitter.info(
                                "浏览器模式2 已检测到创建密码页，准备自动填写密码: "
                                + ctx.account_password,
                                step="create_password",
                            )
                    else:
                        manual_v2_password_page_logged = False
                        manual_v2_create_password_submit_attempts = 0

                    if (
                        password_submitted
                        and not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                    ):
                        recent_contact_verification_network = _has_recent_network_url(
                            recent_network_events,
                            "contact-verification",
                            within_seconds=20.0,
                        )
                        recent_phone_otp_send = _has_recent_network_url(
                            recent_network_events,
                            "phone-otp/send",
                            within_seconds=30.0,
                        )
                        # 已有 contact/发码网络线索时直接进入验证码阶段；真正验证码由 wait_for_code 轮询，
                        # 这里不再同步调用 HeroSMS peek_code 阻塞主循环。
                        hero_sms_code_ready = bool(manual_v2_cached_sms_code)
                        if recent_contact_verification_network or recent_phone_otp_send or hero_sms_code_ready or _is_contact_verification_page(current_url, body_text, page):
                            manual_v2_contact_seen = True
                            manual_v2_contact_network_seen = True
                            manual_v2_contact_transition_last_key = ""
                            manual_v2_waiting_phone_retry = False
                            manual_v2_waiting_phone_retry_logged = False
                            manual_v2_require_phone_resubmit = False
                            emitter.info(
                                (
                                    f"浏览器模式2 检测到 {manual_v2_auto_phone_provider_label} 已收到短信验证码，页面即使尚未完成切换，也直接进入验证码处理阶段..."
                                    if hero_sms_code_ready
                                    else "浏览器模式2 检测到密码提交后已进入短信验证码链路，立即切换到验证码输入阶段..."
                                ),
                                step="phone_verification",
                            )
                            continue

                    if (
                        is_create_password_page
                        and not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                        and not password_submitted
                    ):
                        if _is_retryable_error_page(current_url, body_text):
                            if _try_recover_timeout_error_page(
                                current_url,
                                body_text,
                                step="create_password",
                                action_label="create-account/password 错误页已触发当前页重试",
                                timeout_ms=12000,
                            ):
                                current_url, body_text = _describe_page(page, force_refresh=True)
                                if _is_create_account_password_page(current_url, body_text, page):
                                    password_submitted = False
                                    manual_v2_password_page_logged = False
                                    emitter.info(
                                        "浏览器模式2 create-account/password 当前页重试后已恢复到可继续提交密码的状态，"
                                        + f"准备重新走密码提交流程: {ctx.account_password}",
                                        step="create_password",
                                    )
                                    continue
                                continue
                        manual_v2_create_password_submit_attempts += 1
                        previous_url = current_url
                        previous_body = body_text
                        emitter.info(
                            (
                                "浏览器模式2 首轮 create-account/password 命中专用提交流程，按 codex-registrar 方式提交密码..."
                                if manual_v2_create_password_submit_attempts == 1
                                else "浏览器模式2 create-account/password 仍停留在密码页，开始第 "
                                + str(manual_v2_create_password_submit_attempts)
                                + " 次提交流程重试..."
                            ),
                            step="create_password",
                        )
                        password_ready_started_at = time.monotonic()
                        password_ready = _wait_for_create_account_password_ready(page, timeout_ms=6000)
                        emitter.info(
                            "浏览器模式2 create-account/password 就绪探针完成："
                            + f"ready={str(password_ready).lower()}, elapsed_ms={int((time.monotonic() - password_ready_started_at) * 1000)}",
                            step="create_password",
                        )
                        if not password_ready:
                            emitter.warn(
                                "浏览器模式2 create-account/password ready 探针诊断: "
                                + _summarize_create_account_password_probe(page),
                                step="create_password",
                            )
                            raise RuntimeError("浏览器模式2 create-account/password 页面未稳定就绪")
                        submit_password_result = _submit_create_account_password_like_codex_registrar(
                            page,
                            ctx.account_password,
                            emitter=emitter,
                            step="create_password",
                            check_page_ready=False,
                        )
                        emitter.info(
                            "浏览器模式2 create-account/password 专用提交流程返回："
                            + f"ok={submit_password_result.get('ok') or '-'}, "
                            + f"submitted={submit_password_result.get('submitted') or '-'}, "
                            + f"reason={submit_password_result.get('reason') or '-'}",
                            step="create_password",
                        )
                        if str(submit_password_result.get("ok") or "").strip().lower() != "true":
                            raise RuntimeError(
                                "浏览器模式2 create-account/password 专用提交流程失败: "
                                + str(submit_password_result.get("reason") or "unknown")
                            )
                        if str(submit_password_result.get("submitted") or "").strip().lower() == "true":
                            password_submitted = True
                            emitter.info(
                                "浏览器模式2 首轮注册密码已提交，等待站点自然跳转后续页面...",
                                step="create_password",
                            )
                        else:
                            password_submitted = False
                            manual_v2_create_password_submit_attempts = max(0, manual_v2_create_password_submit_attempts - 1)
                        current_url, body_text = _wait_for_manual_v2_create_password_transition(
                            previous_url,
                            previous_body,
                            # frame URL/网络事件未立即出现时只短暂观察，随后交回主循环；
                            # 不让一次提交同步占住整个注册流程。
                            timeout_ms=2500,
                        )
                        recent_contact_verification_network = _has_recent_network_url(
                            recent_network_events,
                            "contact-verification",
                            within_seconds=8.0,
                        )
                        if recent_contact_verification_network:
                            manual_v2_contact_network_seen = True
                        transition_detected_contact_verification = bool(
                            "contact-verification" in str(current_url or "").lower()
                            or recent_contact_verification_network
                            or manual_v2_contact_network_seen
                        )
                        hero_sms_code_ready = bool(manual_v2_cached_sms_code)
                        if hero_sms_code_ready:
                            transition_detected_contact_verification = True
                            manual_v2_contact_network_seen = True
                        if _is_contact_verification_page(current_url, body_text, page):
                            manual_v2_contact_seen = True
                            manual_v2_contact_transition_last_key = ""
                            manual_v2_waiting_phone_retry = False
                            manual_v2_waiting_phone_retry_logged = False
                            manual_v2_require_phone_resubmit = False
                            emitter.info(
                                "浏览器模式2 create-account/password 提交后已进入短信验证码页，准备立即切换到验证码输入阶段...",
                                step="phone_verification",
                            )
                            continue

                        if transition_detected_contact_verification:
                            manual_v2_contact_seen = True
                            manual_v2_contact_transition_last_key = ""
                            manual_v2_waiting_phone_retry = False
                            manual_v2_waiting_phone_retry_logged = False
                            manual_v2_require_phone_resubmit = False
                            emitter.info(
                                (
                                    f"浏览器模式2 create-account/password 提交后，{manual_v2_auto_phone_provider_label} 已经收到验证码；"
                                    + "即使当前页面快照仍停留在密码页，也直接切换到验证码输入阶段..."
                                    if hero_sms_code_ready
                                    else "浏览器模式2 create-account/password 提交后已通过网络跳转检测到短信验证码页，"
                                    + "即使当前页面快照仍停留在密码页，也直接切换到验证码输入阶段..."
                                ),
                                step="phone_verification",
                            )
                            continue

                        if _is_phone_sms_send_failed_error(current_url, body_text, page):
                            password_submitted = False
                            manual_v2_password_page_logged = False
                            manual_v2_create_password_submit_attempts = 0
                            _prepare_manual_v2_signup_flow(
                                "浏览器模式2 create-account/password 提交后，站点提示当前手机号无法发送短信，"
                                + "回到步骤1重新输入手机号..."
                            )
                            continue
                        if _is_virtual_phone_number_error(current_url, body_text, page):
                            password_submitted = False
                            manual_v2_password_page_logged = False
                            manual_v2_create_password_submit_attempts = 0
                            if manual_v2_auto_phone_mode:
                                _finish_manual_v2_sms_provider(success=False)
                                manual_v2_phone_number = ""
                                manual_v2_sms_activation_id = ""
                                manual_v2_sms_purchased_at = 0.0
                                manual_v2_sms_provider_done = False
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 create-account/password 提交后，站点明确提示当前手机号属于虚拟号/VoIP；"
                                    + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                                )
                            else:
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 create-account/password 提交后，站点明确提示当前手机号属于虚拟号/VoIP；"
                                    + "回到步骤1重新输入新的非虚拟手机号..."
                                )
                            continue
                        if _is_phone_number_existing_account_error(current_url, body_text, page):
                            password_submitted = False
                            manual_v2_password_page_logged = False
                            manual_v2_create_password_submit_attempts = 0
                            if manual_v2_auto_phone_mode:
                                _finish_manual_v2_sms_provider(success=False)
                                manual_v2_phone_number = ""
                                manual_v2_sms_activation_id = ""
                                manual_v2_sms_purchased_at = 0.0
                                manual_v2_sms_provider_done = False
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 create-account/password 提交后，站点明确提示当前手机号已存在账号；"
                                    + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                                )
                            else:
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 create-account/password 提交后，站点明确提示当前手机号已存在账号；"
                                    + "回到步骤1重新输入新的手机号..."
                                )
                            continue
                        if _is_create_account_failed_error(current_url, body_text, page):
                            password_submitted = False
                            manual_v2_password_page_logged = False
                            manual_v2_create_password_submit_attempts = 0
                            if manual_v2_auto_phone_mode:
                                _finish_manual_v2_sms_provider(success=False)
                                manual_v2_phone_number = ""
                                manual_v2_sms_activation_id = ""
                                manual_v2_sms_purchased_at = 0.0
                                manual_v2_sms_provider_done = False
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 create-account/password 提交后，站点明确提示 Failed to create account；"
                                    + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取号..."
                                )
                            else:
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 create-account/password 提交后，站点明确提示 Failed to create account；"
                                    + "回到步骤1重新输入新的手机号..."
                                )
                            continue
                        if _is_create_account_password_page(current_url, body_text, page):
                            # 上一次点击后仍停在密码页时，先看精确的 Continue 是否仍可用。
                            # 可用说明提交事件未被消费，直接再次点击，不进入后面的多轮正文刷新。
                            recent_contact_or_send = (
                                _has_recent_network_url(recent_network_events, "contact-verification", within_seconds=4.0)
                                or _has_recent_network_url(recent_network_events, "phone-otp/send", within_seconds=4.0)
                            )
                            if not recent_contact_or_send and not _has_recent_challenge_network(
                                recent_network_events,
                                within_seconds=4.0,
                            ):
                                continue_locator = _find_visible_submit_locator(
                                    page,
                                    ("继续", "Continue", "Next", "Verify", "Submit"),
                                )
                                if continue_locator is not None:
                                    retry_clicked = False
                                    try:
                                        continue_locator.click(
                                            timeout=1200,
                                            delay=random.randint(30, 70),
                                            no_wait_after=True,
                                        )
                                        retry_clicked = True
                                    except Exception:
                                        try:
                                            continue_locator.press("Enter", timeout=800)
                                            retry_clicked = True
                                        except Exception:
                                            retry_clicked = False
                                    if retry_clicked:
                                        password_submitted = False
                                        manual_v2_password_page_logged = False
                                        emitter.info(
                                            "浏览器模式2 create-account/password 检测到仍可用的 Continue 按钮，"
                                            + "已直接再次提交，跳过多轮页面正文等待...",
                                            step="create_password",
                                        )
                                        continue
                            if _has_recent_challenge_network(recent_network_events, within_seconds=10.0):
                                manual_v2_create_password_submit_attempts = max(0, manual_v2_create_password_submit_attempts - 1)
                                emitter.info(
                                    "浏览器模式2 create-account/password 提交后仍检测到 Cloudflare challenge 网络活动，"
                                    + "先不判定为密码页提交失败，继续等待挑战流结束后再判断...",
                                    step="create_password",
                                )
                                _wait_for_load(page, timeout_ms=1800)
                                _sleep_with_page(page, 500)
                                continue
                            refreshed_retryable = False
                            # 网络事件判定是纯内存操作，最先检查：发码链路已触发就立即切换验证码阶段，
                            # 不必先做 4 轮全文刷新（每轮 _describe_page + _get_page_deep_text 可能耗时数秒）。
                            for _ in range(4):
                                recent_contact_verification_network = _has_recent_network_url(
                                    recent_network_events,
                                    "contact-verification",
                                    within_seconds=10.0,
                                )
                                recent_phone_otp_send = _has_recent_network_url(
                                    recent_network_events,
                                    "phone-otp/send",
                                    within_seconds=25.0,
                                )
                                hero_sms_code_ready = bool(manual_v2_cached_sms_code)
                                if recent_contact_verification_network or recent_phone_otp_send or hero_sms_code_ready:
                                    manual_v2_contact_network_seen = True
                                    break
                                current_url, refreshed_body = _describe_page(page, force_refresh=True)
                                deep_retry_body = _get_page_deep_text(page)
                                if str(deep_retry_body or "").strip():
                                    body_text = str(deep_retry_body or "")
                                else:
                                    body_text = refreshed_body
                                if _is_create_account_failed_error(current_url, body_text, page):
                                    break
                                if _is_retryable_error_page(current_url, body_text):
                                    refreshed_retryable = True
                                    break
                                _wait_for_load(page, timeout_ms=600)
                                _sleep_with_page(page, 180)
                            if _is_create_account_failed_error(current_url, body_text, page):
                                password_submitted = False
                                manual_v2_password_page_logged = False
                                manual_v2_create_password_submit_attempts = 0
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 create-account/password 页面已出现 Failed to create account 硬失败提示；"
                                    + "不再原地 Try again，直接回到步骤1重新注册..."
                                )
                                continue
                            if refreshed_retryable or _is_retryable_error_page(current_url, body_text):
                                if _try_recover_timeout_error_page(
                                    current_url,
                                    body_text,
                                    step="create_password",
                                    action_label="create-account/password 停留在密码页但实际已命中错误页，已触发当前页重试",
                                    timeout_ms=12000,
                                ):
                                    current_url, body_text = _describe_page(page, force_refresh=True)
                                    continue
                            recent_contact_verification_network = _has_recent_network_url(
                                recent_network_events,
                                "contact-verification",
                                within_seconds=10.0,
                            )
                            if recent_contact_verification_network:
                                manual_v2_contact_network_seen = True
                            recent_phone_otp_send = _has_recent_network_url(
                                recent_network_events,
                                "phone-otp/send",
                                within_seconds=25.0,
                            )
                            hero_sms_code_ready = bool(manual_v2_cached_sms_code)
                            if recent_contact_verification_network or manual_v2_contact_network_seen or recent_phone_otp_send or hero_sms_code_ready:
                                manual_v2_contact_seen = True
                                manual_v2_contact_network_seen = True
                                manual_v2_contact_transition_last_key = ""
                                manual_v2_waiting_phone_retry = False
                                manual_v2_waiting_phone_retry_logged = False
                                manual_v2_require_phone_resubmit = False
                                emitter.info(
                                    (
                                        f"浏览器模式2 当前页面快照仍显示密码页，但 {manual_v2_auto_phone_provider_label} 已经收到验证码，"
                                        + "直接按短信验证码阶段继续，跳过多余的密码重试..."
                                        if hero_sms_code_ready
                                        else "浏览器模式2 当前页面快照仍显示密码页，但最近网络已进入发码/短信验证码链路，"
                                        + "直接按短信验证码阶段继续，跳过多余的密码重试..."
                                    ),
                                    step="phone_verification",
                                )
                                continue
                            password_submitted = False
                            manual_v2_password_page_logged = False
                            emitter.warn(
                                "浏览器模式2 create-account/password 提交后仍停留在密码页，准备自动重试一次提交流程..."
                                + f" current_url={_mask_secret(current_url, head=56, tail=12)}",
                                step="create_password",
                            )
                            emitter.info(
                                "create-account/password 停留诊断: "
                                + _summarize_create_account_password_probe(page)
                                + ", body="
                                + (_preview_text(body_text, 220) or "-")
                                + ", actions="
                                + _summarize_primary_actions(page)
                                + ", network="
                                + _summarize_recent_network_events(recent_network_events, limit=10),
                                step="create_password",
                            )
                            if manual_v2_create_password_submit_attempts >= 2:
                                raise RuntimeError(
                                    "浏览器模式2 create-account/password 连续两次提交后仍停留在密码页，"
                                    + "已停止无限重试；请结合上面的 body/network 诊断排查站点真实报错"
                                )
                        else:
                            manual_v2_create_password_submit_attempts = 0
                        continue

                    if (
                        not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                        and is_passkey_challenge_page
                    ):
                        password_submitted = False
                        manual_v2_password_page_logged = False
                        manual_v2_create_password_submit_attempts = 0
                        manual_v2_phone_number = ""
                        if manual_v2_auto_phone_mode:
                            _finish_manual_v2_sms_provider(success=False)
                            manual_v2_sms_activation_id = ""
                            manual_v2_sms_purchased_at = 0.0
                            manual_v2_sms_provider_done = False
                            _prepare_manual_v2_signup_flow(
                                "浏览器模式2 自动接码模式在步骤1命中 passkey 挑战页，"
                                + f"判定当前手机号已是老号；已废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                            )
                        else:
                            _prepare_manual_v2_signup_flow(
                                "浏览器模式2 步骤1命中 passkey 挑战页，判定当前手机号已是老号；"
                                + "已回到步骤1，请重新输入新的手机号..."
                            )
                        continue

                    if (
                        not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                        and not is_create_password_page
                        and not is_login_password_page
                        and not is_passkey_challenge_page
                        and _is_phone_input_page(current_url, body_text, page)
                    ):
                        if manual_v2_reset_password_flow_started or manual_v2_reset_password_continue_clicked:
                            manual_v2_reset_password_flow_started = False
                            manual_v2_reset_password_continue_clicked = False
                            manual_v2_password_page_logged = False
                        if manual_v2_phone_panel_input_mode:
                            previous_url = current_url
                            previous_body = body_text
                            if not manual_v2_phone_number:
                                if not manual_v2_wait_phone_logged or manual_v2_wait_phone_last_url != current_url:
                                    manual_v2_wait_phone_logged = True
                                    manual_v2_wait_phone_last_url = current_url
                                    emitter.info(
                                        "浏览器模式2 已进入步骤1手机号页，请在任务控制卡片中输入手机号并提交；程序会自动继续注册...",
                                        step="add_phone",
                                    )
                                manual_v2_phone_number = _wait_manual_v2_phone_input(
                                    step="add_phone",
                                    prompt="模式2步骤1需要手机号，请输入本次注册使用的手机号。",
                                )
                            manual_v2_wait_phone_logged = False
                            manual_v2_wait_phone_last_url = current_url
                            if not _submit_manual_v2_phone_input(page, manual_v2_phone_number, step="add_phone"):
                                raise RuntimeError("浏览器模式2 无头模式提交步骤1手机号失败")
                            emitter.info("浏览器模式2 已自动提交步骤1手机号，等待进入创建密码页...", step="add_phone")
                            current_url, body_text = _wait_for_manual_v2_phone_submit_transition(
                                previous_url,
                                previous_body,
                                timeout_ms=18000,
                            )
                            page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                            if _is_login_with_bridge_page(current_url, body_text, page):
                                page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                                # 若其实已进入密码/passkey 页，不要按桥接失败处理。
                                if (
                                    _is_create_account_password_page(current_url, body_text, page)
                                    or _is_login_password_page(current_url, body_text, page)
                                    or _is_passkey_challenge_page(current_url, body_text, page)
                                    or _first_visible_locator(
                                        page,
                                        [
                                            'input[type="password"]',
                                            'input[name="password"]',
                                            'input[name="new-password"]',
                                            'input[autocomplete="new-password"]',
                                        ],
                                    ) is not None
                                ):
                                    manual_v2_phone_submit_stall_attempts = 0
                                    emitter.info(
                                        "浏览器模式2 步骤1手机号提交后已从桥接壳提升到认证业务页，"
                                        + f"继续后续流程... current_url={_mask_secret(current_url, head=72, tail=18)}"
                                        + f", state={_classify_page_state(current_url, body_text, page)}",
                                        step="add_phone",
                                    )
                                else:
                                    emitter.warn(
                                        "浏览器模式2 步骤1手机号提交后仍停留在首页登录弹层桥接页，当前号码可能未被站点接受..."
                                        + f" current_url={_mask_secret(current_url, head=56, tail=12)}"
                                        + f", state={_classify_page_state(current_url, body_text, page)}"
                                        + f", pages={_page_navigation_debug_summary(page)}"
                                        + f", frames={_preview_text(' | '.join(_collect_auth_frame_urls(page)[:4]), 180)}",
                                        step="add_phone",
                                    )
                                    emitter.info(
                                        "步骤1手机号桥接页停留诊断: actions=" + _summarize_primary_actions(page),
                                        step="add_phone",
                                    )
                                    if _handle_manual_v2_phone_submit_stall(current_url, body_text):
                                        continue
                                    # stall 返回 False 后，再提升一次页面再判定；真正进入密码页则落回主循环。
                                    page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                                    if (
                                        _is_create_account_password_page(current_url, body_text, page)
                                        or _is_login_password_page(current_url, body_text, page)
                                        or _is_passkey_challenge_page(current_url, body_text, page)
                                        or _first_visible_locator(
                                            page,
                                            [
                                                'input[type="password"]',
                                                'input[name="password"]',
                                                'input[name="new-password"]',
                                                'input[autocomplete="new-password"]',
                                            ],
                                        ) is not None
                                    ):
                                        manual_v2_phone_submit_stall_attempts = 0
                                    else:
                                        continue
                            if _is_login_password_page(current_url, body_text, page):
                                manual_v2_phone_submit_stall_attempts = 0
                                # 已判定老号：立刻废弃取号，不要只打日志再空等下一轮主循环（可白白多等十几秒）
                                password_submitted = False
                                manual_v2_password_page_logged = False
                                manual_v2_create_password_submit_attempts = 0
                                if manual_v2_auto_phone_mode:
                                    _finish_manual_v2_sms_provider(success=False)
                                    manual_v2_phone_number = ""
                                    manual_v2_sms_activation_id = ""
                                    manual_v2_sms_purchased_at = 0.0
                                    manual_v2_sms_provider_done = False
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 Enter your password（号码已是老号）；"
                                        + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                                    )
                                elif manual_v2_manual_restart_on_enter_password:
                                    manual_v2_phone_number = ""
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 Enter your password（号码已是老号）；"
                                        + "已立即回到步骤1，请重新输入新的手机号..."
                                    )
                                else:
                                    emitter.info(
                                        "浏览器模式2 步骤1手机号已被站点识别为已存在账号，已自动转入 Enter your password / Forgot password 流程...",
                                        step="create_password",
                                    )
                                continue
                            elif _is_create_account_password_page(current_url, body_text, page):
                                manual_v2_phone_submit_stall_attempts = 0
                                emitter.info(
                                    "浏览器模式2 步骤1手机号提交后已进入 create-account/password，下一轮将自动填写密码..."
                                    + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                    step="create_password",
                                )
                            elif _is_passkey_challenge_page(current_url, body_text, page):
                                manual_v2_phone_submit_stall_attempts = 0
                                password_submitted = False
                                manual_v2_password_page_logged = False
                                manual_v2_create_password_submit_attempts = 0
                                manual_v2_phone_number = ""
                                if manual_v2_auto_phone_mode:
                                    _finish_manual_v2_sms_provider(success=False)
                                    manual_v2_sms_activation_id = ""
                                    manual_v2_sms_purchased_at = 0.0
                                    manual_v2_sms_provider_done = False
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 passkey 挑战页（号码已是老号）；"
                                        + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                                    )
                                else:
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 passkey 挑战页（号码已是老号）；"
                                        + "已立即回到步骤1，请重新输入新的手机号..."
                                    )
                                continue
                            elif _is_phone_input_page(current_url, body_text, page):
                                emitter.warn(
                                    "浏览器模式2 步骤1手机号提交后仍停留在手机号页，当前号码可能未被站点接受..."
                                    + f" current_url={_mask_secret(current_url, head=56, tail=12)}"
                                    + f", state={_classify_page_state(current_url, body_text, page)}",
                                    step="add_phone",
                                )
                                emitter.info(
                                    "步骤1手机号页停留诊断: actions=" + _summarize_primary_actions(page),
                                    step="add_phone",
                                )
                                if _handle_manual_v2_phone_submit_stall(current_url, body_text):
                                    continue
                            else:
                                manual_v2_phone_submit_stall_attempts = 0
                            continue
                        if manual_v2_auto_phone_mode:
                            previous_url = current_url
                            previous_body = body_text
                            if not manual_v2_phone_number:
                                try:
                                    _ensure_manual_v2_auto_phone(
                                        step="add_phone",
                                        prompt=f"浏览器模式2 已进入步骤1手机号页，准备通过 {manual_v2_auto_phone_provider_label} 自动获取本轮注册手机号...",
                                    )
                                except HeroSMSAcquireStoppedError:
                                    emitter.info(
                                        f"浏览器模式2 {manual_v2_auto_phone_provider_label} 取号过程中收到停止请求，当前流程立即收尾退出...",
                                        step="add_phone",
                                    )
                                    return None
                                except HeroSMSAcquireRetryableError as exc:
                                    emitter.warn(str(exc), step="add_phone")
                                    emitter.info(
                                        f"浏览器模式2 {manual_v2_auto_phone_provider_label} 当前暂无可用号码/价档，"
                                        + "不结束本轮浏览器、不进外层休息；留在手机号页继续轮询取号...",
                                        step="add_phone",
                                    )
                                    _wait_for_load(page, timeout_ms=800)
                                    # 价档/库存空：短等后重试；比外层 5~30s 休息快得多
                                    retry_wait_ms = 2500
                                    exc_text = str(exc or "")
                                    if any(
                                        token in exc_text
                                        for token in ("价格区间", "价档", "没有国家", "无可用国家", "NO_NUMBERS")
                                    ):
                                        retry_wait_ms = 2000
                                    if _sleep_with_page_until(page, retry_wait_ms, ctx.stop_event):
                                        emitter.info(
                                            f"浏览器模式2 {manual_v2_auto_phone_provider_label} 重试等待期间收到停止请求，当前流程立即收尾退出...",
                                            step="add_phone",
                                        )
                                        return None
                                    continue
                            manual_v2_wait_phone_logged = False
                            manual_v2_wait_phone_last_url = current_url
                            if not _submit_manual_v2_phone_input(page, manual_v2_phone_number, step="add_phone"):
                                raise RuntimeError("浏览器模式2 自动模式提交步骤1手机号失败")
                            emitter.info(f"浏览器模式2 已自动提交 {manual_v2_auto_phone_provider_label} 手机号，等待进入创建密码页...", step="add_phone")
                            current_url, body_text = _wait_for_manual_v2_phone_submit_transition(
                                previous_url,
                                previous_body,
                                timeout_ms=18000,
                            )
                            page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                            if _is_login_with_bridge_page(current_url, body_text, page):
                                page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                                # 若其实已进入密码/passkey 页，不要按桥接失败处理。
                                if (
                                    _is_create_account_password_page(current_url, body_text, page)
                                    or _is_login_password_page(current_url, body_text, page)
                                    or _is_passkey_challenge_page(current_url, body_text, page)
                                    or _first_visible_locator(
                                        page,
                                        [
                                            'input[type="password"]',
                                            'input[name="password"]',
                                            'input[name="new-password"]',
                                            'input[autocomplete="new-password"]',
                                        ],
                                    ) is not None
                                ):
                                    manual_v2_phone_submit_stall_attempts = 0
                                    emitter.info(
                                        "浏览器模式2 步骤1手机号提交后已从桥接壳提升到认证业务页，"
                                        + f"继续后续流程... current_url={_mask_secret(current_url, head=72, tail=18)}"
                                        + f", state={_classify_page_state(current_url, body_text, page)}",
                                        step="add_phone",
                                    )
                                else:
                                    emitter.warn(
                                        "浏览器模式2 步骤1手机号提交后仍停留在首页登录弹层桥接页，当前号码可能未被站点接受..."
                                        + f" current_url={_mask_secret(current_url, head=56, tail=12)}"
                                        + f", state={_classify_page_state(current_url, body_text, page)}"
                                        + f", pages={_page_navigation_debug_summary(page)}"
                                        + f", frames={_preview_text(' | '.join(_collect_auth_frame_urls(page)[:4]), 180)}",
                                        step="add_phone",
                                    )
                                    emitter.info(
                                        "步骤1手机号桥接页停留诊断: actions=" + _summarize_primary_actions(page),
                                        step="add_phone",
                                    )
                                    if _handle_manual_v2_phone_submit_stall(current_url, body_text):
                                        continue
                                    # stall 返回 False 后，再提升一次页面再判定；真正进入密码页则落回主循环。
                                    page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                                    if (
                                        _is_create_account_password_page(current_url, body_text, page)
                                        or _is_login_password_page(current_url, body_text, page)
                                        or _is_passkey_challenge_page(current_url, body_text, page)
                                        or _first_visible_locator(
                                            page,
                                            [
                                                'input[type="password"]',
                                                'input[name="password"]',
                                                'input[name="new-password"]',
                                                'input[autocomplete="new-password"]',
                                            ],
                                        ) is not None
                                    ):
                                        manual_v2_phone_submit_stall_attempts = 0
                                    else:
                                        continue
                            if _is_login_password_page(current_url, body_text, page):
                                manual_v2_phone_submit_stall_attempts = 0
                                # 已判定老号：立刻废弃取号，不要只打日志再空等下一轮主循环（可白白多等十几秒）
                                password_submitted = False
                                manual_v2_password_page_logged = False
                                manual_v2_create_password_submit_attempts = 0
                                if manual_v2_auto_phone_mode:
                                    _finish_manual_v2_sms_provider(success=False)
                                    manual_v2_phone_number = ""
                                    manual_v2_sms_activation_id = ""
                                    manual_v2_sms_purchased_at = 0.0
                                    manual_v2_sms_provider_done = False
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 Enter your password（号码已是老号）；"
                                        + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                                    )
                                elif manual_v2_manual_restart_on_enter_password:
                                    manual_v2_phone_number = ""
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 Enter your password（号码已是老号）；"
                                        + "已立即回到步骤1，请重新输入新的手机号..."
                                    )
                                else:
                                    emitter.info(
                                        "浏览器模式2 步骤1手机号已被站点识别为已存在账号，已自动转入 Enter your password / Forgot password 流程...",
                                        step="create_password",
                                    )
                                continue
                            elif _is_create_account_password_page(current_url, body_text, page):
                                manual_v2_phone_submit_stall_attempts = 0
                                emitter.info(
                                    "浏览器模式2 步骤1手机号提交后已进入 create-account/password，下一轮将自动填写密码..."
                                    + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                    step="create_password",
                                )
                            elif _is_passkey_challenge_page(current_url, body_text, page):
                                manual_v2_phone_submit_stall_attempts = 0
                                password_submitted = False
                                manual_v2_password_page_logged = False
                                manual_v2_create_password_submit_attempts = 0
                                manual_v2_phone_number = ""
                                if manual_v2_auto_phone_mode:
                                    _finish_manual_v2_sms_provider(success=False)
                                    manual_v2_sms_activation_id = ""
                                    manual_v2_sms_purchased_at = 0.0
                                    manual_v2_sms_provider_done = False
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 passkey 挑战页（号码已是老号）；"
                                        + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                                    )
                                else:
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 passkey 挑战页（号码已是老号）；"
                                        + "已立即回到步骤1，请重新输入新的手机号..."
                                    )
                                continue
                            elif _is_phone_input_page(current_url, body_text, page):
                                emitter.warn(
                                    "浏览器模式2 步骤1手机号提交后仍停留在手机号页，当前号码可能未被站点接受..."
                                    + f" current_url={_mask_secret(current_url, head=56, tail=12)}"
                                    + f", state={_classify_page_state(current_url, body_text, page)}",
                                    step="add_phone",
                                )
                                emitter.info(
                                    "步骤1手机号页停留诊断: actions=" + _summarize_primary_actions(page),
                                    step="add_phone",
                                )
                                if _handle_manual_v2_phone_submit_stall(current_url, body_text):
                                    continue
                            else:
                                manual_v2_phone_submit_stall_attempts = 0
                            continue
                        if _manual_phone_input_ready(page):
                            previous_url = current_url
                            previous_body = body_text
                            manual_v2_phone_number = _extract_input_value_by_hints(
                                page,
                                ["phone", "mobile", "手机号", "电话", "tel"],
                            ) or manual_v2_phone_number
                            manual_v2_wait_phone_logged = False
                            manual_v2_wait_phone_last_url = current_url + "#ready"
                            emitter.info(
                                "浏览器模式2 已检测到你填好的手机号，准备自动提交并等待进入创建密码页...",
                                step="add_phone",
                            )
                            if not _submit_manual_v2_phone_input(page, manual_v2_phone_number, step="add_phone"):
                                raise RuntimeError("浏览器模式2 步骤1手机号自动提交失败")
                            current_url, body_text = _wait_for_manual_v2_phone_submit_transition(
                                previous_url,
                                previous_body,
                                timeout_ms=18000,
                            )
                            page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                            if _is_login_with_bridge_page(current_url, body_text, page):
                                page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                                # 若其实已进入密码/passkey 页，不要按桥接失败处理。
                                if (
                                    _is_create_account_password_page(current_url, body_text, page)
                                    or _is_login_password_page(current_url, body_text, page)
                                    or _is_passkey_challenge_page(current_url, body_text, page)
                                    or _first_visible_locator(
                                        page,
                                        [
                                            'input[type="password"]',
                                            'input[name="password"]',
                                            'input[name="new-password"]',
                                            'input[autocomplete="new-password"]',
                                        ],
                                    ) is not None
                                ):
                                    manual_v2_phone_submit_stall_attempts = 0
                                    emitter.info(
                                        "浏览器模式2 步骤1手机号提交后已从桥接壳提升到认证业务页，"
                                        + f"继续后续流程... current_url={_mask_secret(current_url, head=72, tail=18)}"
                                        + f", state={_classify_page_state(current_url, body_text, page)}",
                                        step="add_phone",
                                    )
                                else:
                                    emitter.warn(
                                        "浏览器模式2 步骤1手机号提交后仍停留在首页登录弹层桥接页，当前号码可能未被站点接受..."
                                        + f" current_url={_mask_secret(current_url, head=56, tail=12)}"
                                        + f", state={_classify_page_state(current_url, body_text, page)}"
                                        + f", pages={_page_navigation_debug_summary(page)}"
                                        + f", frames={_preview_text(' | '.join(_collect_auth_frame_urls(page)[:4]), 180)}",
                                        step="add_phone",
                                    )
                                    emitter.info(
                                        "步骤1手机号桥接页停留诊断: actions=" + _summarize_primary_actions(page),
                                        step="add_phone",
                                    )
                                    if _handle_manual_v2_phone_submit_stall(current_url, body_text):
                                        continue
                                    # stall 返回 False 后，再提升一次页面再判定；真正进入密码页则落回主循环。
                                    page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                                    if (
                                        _is_create_account_password_page(current_url, body_text, page)
                                        or _is_login_password_page(current_url, body_text, page)
                                        or _is_passkey_challenge_page(current_url, body_text, page)
                                        or _first_visible_locator(
                                            page,
                                            [
                                                'input[type="password"]',
                                                'input[name="password"]',
                                                'input[name="new-password"]',
                                                'input[autocomplete="new-password"]',
                                            ],
                                        ) is not None
                                    ):
                                        manual_v2_phone_submit_stall_attempts = 0
                                    else:
                                        continue
                            if _is_login_password_page(current_url, body_text, page):
                                manual_v2_phone_submit_stall_attempts = 0
                                # 已判定老号：立刻废弃取号，不要只打日志再空等下一轮主循环（可白白多等十几秒）
                                password_submitted = False
                                manual_v2_password_page_logged = False
                                manual_v2_create_password_submit_attempts = 0
                                if manual_v2_auto_phone_mode:
                                    _finish_manual_v2_sms_provider(success=False)
                                    manual_v2_phone_number = ""
                                    manual_v2_sms_activation_id = ""
                                    manual_v2_sms_purchased_at = 0.0
                                    manual_v2_sms_provider_done = False
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 Enter your password（号码已是老号）；"
                                        + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                                    )
                                elif manual_v2_manual_restart_on_enter_password:
                                    manual_v2_phone_number = ""
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 Enter your password（号码已是老号）；"
                                        + "已立即回到步骤1，请重新输入新的手机号..."
                                    )
                                else:
                                    emitter.info(
                                        "浏览器模式2 步骤1手机号已被站点识别为已存在账号，已自动转入 Enter your password / Forgot password 流程...",
                                        step="create_password",
                                    )
                                continue
                            elif _is_create_account_password_page(current_url, body_text, page):
                                manual_v2_phone_submit_stall_attempts = 0
                                emitter.info(
                                    "浏览器模式2 步骤1手机号提交后已进入 create-account/password，下一轮将自动填写密码..."
                                    + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                    step="create_password",
                                )
                            elif _is_passkey_challenge_page(current_url, body_text, page):
                                manual_v2_phone_submit_stall_attempts = 0
                                password_submitted = False
                                manual_v2_password_page_logged = False
                                manual_v2_create_password_submit_attempts = 0
                                manual_v2_phone_number = ""
                                if manual_v2_auto_phone_mode:
                                    _finish_manual_v2_sms_provider(success=False)
                                    manual_v2_sms_activation_id = ""
                                    manual_v2_sms_purchased_at = 0.0
                                    manual_v2_sms_provider_done = False
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 passkey 挑战页（号码已是老号）；"
                                        + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                                    )
                                else:
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 步骤1手机号提交后命中 passkey 挑战页（号码已是老号）；"
                                        + "已立即回到步骤1，请重新输入新的手机号..."
                                    )
                                continue
                            elif _is_phone_input_page(current_url, body_text, page):
                                emitter.warn(
                                    "浏览器模式2 步骤1手机号提交后仍停留在手机号页，当前号码可能未被站点接受..."
                                    + f" current_url={_mask_secret(current_url, head=56, tail=12)}"
                                    + f", state={_classify_page_state(current_url, body_text, page)}",
                                    step="add_phone",
                                )
                                emitter.info(
                                    "步骤1手机号页停留诊断: actions=" + _summarize_primary_actions(page),
                                    step="add_phone",
                                )
                                if _handle_manual_v2_phone_submit_stall(current_url, body_text):
                                    continue
                            else:
                                manual_v2_phone_submit_stall_attempts = 0
                            continue
                        if not manual_v2_wait_phone_logged or manual_v2_wait_phone_last_url != current_url:
                            manual_v2_wait_phone_logged = True
                            manual_v2_wait_phone_last_url = current_url
                            emitter.info(
                                "浏览器模式2 已进入步骤1手机号输入页，请先输入手机号；填好后程序会自动提交并继续...",
                                step="add_phone",
                            )
                        _sleep_with_page(page, 800)
                        continue

                        continue

                    if (
                        not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                        and is_login_password_page
                        and not manual_v2_reset_password_flow_started
                    ):
                        if manual_v2_manual_restart_on_enter_password:
                            password_submitted = False
                            manual_v2_password_page_logged = False
                            manual_v2_create_password_submit_attempts = 0
                            manual_v2_phone_number = ""
                            _prepare_manual_v2_signup_flow(
                                "浏览器模式2 人工输入模式在步骤1命中 Enter your password，"
                                + "当前已按配置直接回到步骤1重新输入新的手机号..."
                            )
                            continue
                        if manual_v2_auto_phone_mode:
                            _finish_manual_v2_sms_provider(success=False)
                            manual_v2_sms_activation_id = ""
                            manual_v2_sms_purchased_at = 0.0
                            manual_v2_sms_provider_done = False
                            _prepare_manual_v2_signup_flow(
                                "浏览器模式2 自动接码模式在步骤1命中 Enter your password，"
                                + f"判定当前手机号已是老号；已废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                            )
                            continue
                        if _click_first(
                            page,
                            [
                                'button:has-text("Forgot password")',
                                '[role="button"]:has-text("Forgot password")',
                                'a:has-text("Forgot password")',
                                'button:has-text("忘记密码")',
                                'a:has-text("忘记密码")',
                            ],
                            timeout_ms=1500,
                        ):
                            manual_v2_reset_password_flow_started = True
                            manual_v2_reset_password_continue_clicked = False
                            emitter.info("浏览器模式2 首次注册命中 Enter your password，已自动点击 Forgot password，切换到重置密码流程...", step="create_password")
                            _wait_for_load(page, timeout_ms=2500)
                            continue

                    if (
                        not manual_v2_login_flow_started
                        and manual_v2_reset_password_flow_started
                        and _is_reset_password_page(current_url, body_text, page)
                        and not manual_v2_reset_password_continue_clicked
                    ):
                        previous_url = current_url
                        previous_body = body_text
                        if _click_primary_action(page, ["Continue", "Next", "继续", "下一步"], allow_generic_fallback=True):
                            manual_v2_reset_password_continue_clicked = True
                            emitter.info("浏览器模式2 已进入 reset-password 页面，已自动点击继续，等待短信验证码页或发码结果...", step="create_password")
                            current_url, body_text = _wait_for_manual_v2_reset_password_continue_transition(
                                previous_url,
                                previous_body,
                                timeout_ms=10000,
                            )
                            if _is_phone_sms_send_failed_error(current_url, body_text, page):
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 reset-password 点击继续后，站点提示当前手机号无法发送短信，"
                                    + "回到步骤1重新输入手机号..."
                                )
                                continue
                            if _is_virtual_phone_number_error(current_url, body_text, page):
                                if manual_v2_auto_phone_mode:
                                    _finish_manual_v2_sms_provider(success=False)
                                    manual_v2_phone_number = ""
                                    manual_v2_sms_activation_id = ""
                                    manual_v2_sms_purchased_at = 0.0
                                    manual_v2_sms_provider_done = False
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 reset-password 点击继续后，站点明确提示当前手机号属于虚拟号/VoIP；"
                                        + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                                    )
                                else:
                                    _prepare_manual_v2_signup_flow(
                                        "浏览器模式2 reset-password 点击继续后，站点明确提示当前手机号属于虚拟号/VoIP；"
                                        + "回到步骤1重新输入新的非虚拟手机号..."
                                    )
                                continue
                            continue

                    if (
                        not manual_v2_login_flow_started
                        and manual_v2_reset_password_flow_started
                        and manual_v2_reset_password_continue_clicked
                        and _is_phone_sms_send_failed_error(current_url, body_text, page)
                    ):
                        _prepare_manual_v2_signup_flow(
                            "浏览器模式2 reset-password 当前手机号无法发送短信验证码，"
                            + "回到步骤1重新输入手机号..."
                        )
                        continue
                    if (
                        not manual_v2_login_flow_started
                        and manual_v2_reset_password_flow_started
                        and manual_v2_reset_password_continue_clicked
                        and _is_virtual_phone_number_error(current_url, body_text, page)
                    ):
                        if manual_v2_auto_phone_mode:
                            _finish_manual_v2_sms_provider(success=False)
                            manual_v2_phone_number = ""
                            manual_v2_sms_activation_id = ""
                            manual_v2_sms_purchased_at = 0.0
                            manual_v2_sms_provider_done = False
                            _prepare_manual_v2_signup_flow(
                                "浏览器模式2 reset-password 当前手机号被站点判定为虚拟号/VoIP；"
                                + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取新号..."
                            )
                        else:
                            _prepare_manual_v2_signup_flow(
                                "浏览器模式2 reset-password 当前手机号被站点判定为虚拟号/VoIP；"
                                + "回到步骤1重新输入新的非虚拟手机号..."
                            )
                        continue

                    # about-you 优先：一旦到资料页，立刻填写，禁止回流短信验证码循环。
                    # 仍停在 create-account/password 时绝不进资料分支，否则会跳过短信并误失败。
                    if (
                        not manual_v2_login_flow_started
                        and not profile_submitted
                        and not _is_create_account_password_page(current_url, body_text, page)
                        and not (
                            _has_visible_password_input(page)
                            and (
                                "create a password" in str(body_text or "").lower()
                                or "create password" in str(body_text or "").lower()
                                or "/create-account/password" in str(current_url or "").lower()
                            )
                        )
                        and (
                            "about-you" in str(current_url or "").lower()
                            or _is_profile_page(current_url, body_text, page)
                            or (
                                _has_visible_about_you_controls(page)
                                and not _has_visible_password_input(page)
                            )
                        )
                    ):
                        manual_v2_contact_seen = True
                        # 仅在真正进入资料页后才标记短信已完成；密码页误判时不能短路接码。
                        manual_v2_sms_code_submitted = True
                        _extend_manual_v2_deadline(1800)
                        page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=3000)
                        # promote 后若其实仍在密码页，立即退出本分支，交给密码/短信流程。
                        if (
                            _is_create_account_password_page(current_url, body_text, page)
                            or (
                                _has_visible_password_input(page)
                                and "about-you" not in str(current_url or "").lower()
                                and not _has_visible_about_you_controls(page)
                            )
                        ):
                            manual_v2_sms_code_submitted = False
                            emitter.warn(
                                "浏览器模式2 资料页判定后复核仍为密码页，取消 about-you 短路并继续密码/短信流程..."
                                + f" current_url={_mask_secret(current_url, head=72, tail=18)}"
                                + f", state={_classify_page_state(current_url, body_text, page)}",
                                step="create_password",
                            )
                            continue
                        emitter.info("浏览器模式2 已进入 about-you 页面，开始自动填写姓名/年龄并提交...", step="create_account")
                        emitter.info(
                            f"浏览器本次资料: name={ctx.profile_name}, birthdate={ctx.profile_birthdate}, age={_derive_profile_age(ctx.profile_birthdate)}",
                            step="create_account",
                        )
                        profile_ok, profile_mode = _fill_about_you_profile(page, ctx)
                        if not profile_ok and profile_mode == "name":
                            raise RuntimeError("浏览器模式2 在 about-you 页面填写姓名失败")
                        if not profile_ok and profile_mode in {"birthdate", "age"}:
                            emitter.warn(
                                "浏览器模式2 about-you 年龄/生日控件诊断: " + _summarize_about_you_controls(page),
                                step="create_account",
                            )
                            raise RuntimeError("浏览器模式2 在 about-you 页面填写年龄/生日失败")
                        if not profile_ok and profile_mode == "checkbox":
                            emitter.warn(
                                "浏览器模式2 about-you 勾选控件诊断: " + _summarize_about_you_controls(page),
                                step="create_account",
                            )
                            raise RuntimeError("浏览器模式2 在 about-you 页面勾选同意项失败")
                        previous_url = current_url
                        previous_body = body_text
                        finish_result = _submit_about_you_finish_with_terms_retry(
                            page,
                            ctx,
                            max_attempts=3,
                            settle_ms=800,
                        )
                        if finish_result.get("terms_retried"):
                            emitter.warn(
                                "浏览器模式2 about-you 出现 Terms of Use 红色提示，"
                                + f"未重填资料，已直接再点 Finish creating account（共 {finish_result.get('attempts') or 0} 次）...",
                                step="create_account",
                            )
                        if not finish_result.get("clicked"):
                            raise RuntimeError("浏览器模式2 提交 about-you 资料失败：未点到 Finish creating account")
                        current_url = str(finish_result.get("url") or current_url)
                        body_text = str(finish_result.get("body") or body_text)
                        # 仍停在 about-you 且还是 Terms 软错误：不标记已完成，下一轮只再点，不重填。
                        if _about_you_form_still_visible(current_url, body_text, page):
                            if _is_about_you_terms_soft_error(current_url, body_text, page):
                                emitter.warn(
                                    "浏览器模式2 about-you 多次直接点击 Finish 后仍显示 Terms 红字，"
                                    + "本轮不结束资料页；下一轮继续只点 Finish，不重填...",
                                    step="create_account",
                                )
                                _sleep_with_page(page, 800)
                                continue
                            current_url, body_text = _wait_for_page_stabilize(
                                previous_url,
                                previous_body,
                                step="create_account",
                                action_label="about-you 资料已提交",
                                timeout_ms=12000,
                            )
                            if _about_you_form_still_visible(current_url, body_text, page):
                                emitter.warn(
                                    "浏览器模式2 about-you 提交后仍停留在资料页，暂不进入步骤2，下一轮重试..."
                                    + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                    step="create_account",
                                )
                                continue
                        profile_submitted = True
                        # 注册前半段 callback 与步骤2 PKCE 不是同一套；资料完成后必须重新拉起登录 OAuth。
                        callback_state["url"] = ""
                        # about-you 提交后常见 You're all set（在 chatgpt.com 上）：
                        # 必须等完成页出现并点完 Continue，绝不能把“到了 chatgpt.com”当成已离开。
                        all_set = _pass_youre_all_set_page(
                            page,
                            emitter=emitter,
                            step="create_account",
                            max_attempts=6,
                            settle_ms=700,
                            wait_appear_ms=3500,
                        )
                        try:
                            current_url = str(all_set.get("url") or current_url)
                            body_text = str(all_set.get("body") or body_text)
                            if not current_url or not body_text:
                                current_url, body_text = _read_page_url_body(page)
                        except Exception:
                            try:
                                current_url, body_text = _read_page_url_body(page)
                            except Exception:
                                pass
                        if all_set.get("was_page") and not all_set.get("left"):
                            emitter.warn(
                                "浏览器模式2 about-you 后仍停在 You're all set，本轮不进步骤2，下一轮继续点 Continue..."
                                + f" attempts={all_set.get('attempts') or 0}"
                                + f" actions={_summarize_primary_actions(page)}",
                                step="create_account",
                            )
                            continue
                        if (not all_set.get("left")) and (not all_set.get("was_page")):
                            emitter.warn(
                                "浏览器模式2 about-you 提交后页面未离开资料/过渡态，本轮不进步骤2，下一轮重试...",
                                step="create_account",
                            )
                            continue
                        # 若其实还在完成页（检测漏了），下一轮主循环会再点
                        if _is_youre_all_set_page(current_url, body_text, page):
                            emitter.warn(
                                "浏览器模式2 仍检测到 You're all set，本轮不进步骤2，交给主循环继续点 Continue...",
                                step="create_account",
                            )
                            continue
                        if _is_about_you_missing_email_error(current_url, body_text):
                            emitter.warn(
                                "浏览器模式2 about-you 提交后命中 authentication missing_email，"
                                + "资料阶段结束，直接进入步骤2 OAuth 补邮箱/取 Token 流程...",
                                step="create_email",
                            )
                        else:
                            emitter.success(
                                "浏览器模式2 已提交 about-you 资料"
                                + ("并离开 You're all set" if all_set.get("was_page") else "")
                                + "，开始进入步骤2：使用已注册手机号走 OAuth 登录获取 Token...",
                                step="create_account",
                            )
                        _prepare_manual_v2_login_flow(
                            "浏览器模式2 步骤1（手机注册+资料）已完成，现在进入真正的步骤2 OAuth 登录/补邮箱获取 Token 流程..."
                        )
                        continue

                    if (
                        _is_contact_verification_page(current_url, body_text, page)
                        and manual_v2_auto_phone_mode
                        and not manual_v2_login_flow_started
                        and not str(manual_v2_sms_activation_id or "").strip()
                        and not password_submitted
                        and not manual_v2_contact_seen
                    ):
                        emitter.warn(
                            "浏览器模式2 当前页疑似短信验证码页，但步骤1尚未取号；忽略本次识别并继续首页/手机号流程。"
                            + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                            step="add_phone",
                        )
                    if (
                        not (
                            _is_profile_page(current_url, body_text, page)
                            or "about-you" in str(current_url or "").lower()
                            or "email-verification" in str(current_url or "").lower()
                            or "add-email" in str(current_url or "").lower()
                        )
                        and _is_contact_verification_page(current_url, body_text, page)
                        # 步骤2登录/补邮箱阶段禁止再走手机短信验证码分支，避免把邮箱 OTP 页当成短信页并复用旧 SMS 码。
                        and not manual_v2_login_flow_started
                        and not email_submitted
                        and not (
                            manual_v2_auto_phone_mode
                            and not manual_v2_login_flow_started
                            and not str(manual_v2_sms_activation_id or "").strip()
                            and not password_submitted
                            and not manual_v2_contact_seen
                        )
                        and not profile_submitted
                    ):
                        _extend_manual_v2_deadline(3600)
                        manual_v2_contact_seen = True
                        manual_v2_contact_transition_last_key = ""
                        manual_v2_waiting_phone_retry = False
                        manual_v2_waiting_phone_retry_logged = False
                        manual_v2_require_phone_resubmit = False
                        if manual_v2_sms_code_submitted:
                            current_url, body_text = _wait_for_manual_v2_contact_submit_transition(
                                current_url,
                                body_text,
                                timeout_ms=12000,
                            )
                            current_url_lower = current_url.lower()
                            body_lower = body_text.lower()
                            if _is_contact_verification_page(current_url, body_text, page):
                                manual_v2_sms_code_submitted = False
                            else:
                                manual_v2_wait_contact_logged = False
                                continue
                        if manual_v2_sms_panel_input_mode:
                            if not manual_v2_wait_contact_logged:
                                manual_v2_wait_contact_logged = True
                                emitter.info(
                                    "浏览器模式2 已进入短信验证码页，请在任务控制卡片中输入短信验证码并提交...",
                                    step="phone_verification",
                                )
                            sms_code = _wait_manual_v2_sms_code(
                                step="phone_verification",
                                prompt="模式2当前需要短信验证码，请输入本次收到的 6 位短信码。",
                            )
                            if sms_code == MANUAL_V2_RESTART_PHONE_SENTINEL:
                                manual_v2_wait_contact_logged = False
                                manual_v2_phone_number = ""
                                manual_v2_contact_seen = False
                                manual_v2_wait_phone_logged = False
                                manual_v2_wait_phone_last_url = ""
                                manual_v2_waiting_phone_retry = False
                                manual_v2_waiting_phone_retry_logged = False
                                manual_v2_require_phone_resubmit = False
                                manual_v2_reset_password_flow_started = False
                                manual_v2_reset_password_continue_clicked = False
                                manual_v2_sms_code_submitted = False
                                password_submitted = False
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 无头人工输入模式收到“换手机号重来”指令，"
                                    + "准备回到步骤1重新输入新的手机号..."
                                )
                                continue
                            if not _wait_and_fill_otp(page, sms_code, timeout_seconds=12.0):
                                raise RuntimeError("浏览器模式2 无头模式填写短信验证码失败")
                            if not _otp_controls_match_code(page, sms_code):
                                raise RuntimeError("浏览器模式2 无头模式短信验证码回填校验失败")
                            if not _click_primary_action(page, ["Continue", "Verify", "Submit", "继续", "下一步"], allow_generic_fallback=True):
                                raise RuntimeError("浏览器模式2 无头模式提交短信验证码失败")
                            manual_v2_wait_contact_logged = False
                            manual_v2_sms_code_submitted = True
                            emitter.info("浏览器模式2 已自动提交短信验证码，等待后续跳转...", step="phone_verification")
                            current_url, body_text = _wait_for_manual_v2_contact_submit_transition(
                                current_url,
                                body_text,
                                timeout_ms=18000,
                            )
                            page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                            if _is_profile_page(current_url, body_text, page) or "about-you" in str(current_url or "").lower():
                                emitter.info(
                                    "浏览器模式2 短信验证码通过后已进入 about-you 资料页，下一轮自动填写姓名/年龄并点击 Finish creating account..."
                                    + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                    step="create_account",
                                )
                            elif _is_contact_verification_page(current_url, body_text, page):
                                manual_v2_sms_code_submitted = False
                            continue
                        if manual_v2_auto_phone_mode:
                            if not str(manual_v2_sms_activation_id or "").strip():
                                manual_v2_contact_seen = False
                                manual_v2_wait_contact_logged = False
                                emitter.warn(
                                    "浏览器模式2 进入短信验证码处理前发现尚未取号（缺少 activation_id），"
                                    + "回退到步骤1继续手机号流程...",
                                    step="add_phone",
                                )
                                continue
                            if not manual_v2_wait_contact_logged:
                                manual_v2_wait_contact_logged = True
                                emitter.info(
                                    f"浏览器模式2 已进入短信验证码页，准备通过 {manual_v2_auto_phone_provider_label} 自动轮询短信验证码并提交...",
                                    step="phone_verification",
                                )
                            sms_code = _wait_manual_v2_auto_sms_code(
                                step="phone_verification",
                                prompt=f"浏览器模式2 当前需要短信验证码，开始通过 {manual_v2_auto_phone_provider_label} 轮询本轮号码的 6 位短信码；若 60 秒仍未收到，将结束本地流程，并在满足取消窗口后后台补发取消...",
                                timeout_seconds=60,
                            )
                            if not sms_code:
                                manual_v2_wait_contact_logged = False
                                _finish_manual_v2_sms_provider(success=False)
                                manual_v2_contact_seen = False
                                manual_v2_wait_phone_logged = False
                                manual_v2_wait_phone_last_url = ""
                                manual_v2_waiting_phone_retry = False
                                manual_v2_waiting_phone_retry_logged = False
                                manual_v2_require_phone_resubmit = False
                                manual_v2_reset_password_flow_started = False
                                manual_v2_reset_password_continue_clicked = False
                                manual_v2_sms_code_submitted = False
                                password_submitted = False
                                manual_v2_phone_number = ""
                                manual_v2_sms_activation_id = ""
                                manual_v2_sms_purchased_at = 0.0
                                manual_v2_sms_provider_done = False
                                _prepare_manual_v2_signup_flow(
                                    f"浏览器模式2 {manual_v2_auto_phone_provider_label} 在短信验证码阶段等待 60 秒仍未收到短信；"
                                    + "本地已放弃当前号码，若未到 2 分钟取消窗口将转后台延迟取消，然后回到步骤1重新取号..."
                                )
                                continue
                            if not _wait_and_fill_otp(page, sms_code, timeout_seconds=12.0):
                                raise RuntimeError("浏览器模式2 自动模式填写短信验证码失败")
                            if not _otp_controls_match_code(page, sms_code):
                                raise RuntimeError("浏览器模式2 自动模式短信验证码回填校验失败")
                            if not _click_primary_action(page, ["Continue", "Verify", "Submit", "继续", "下一步"], allow_generic_fallback=True):
                                raise RuntimeError("浏览器模式2 自动模式提交短信验证码失败")
                            manual_v2_wait_contact_logged = False
                            manual_v2_sms_code_submitted = True
                            emitter.info(f"浏览器模式2 已自动提交 {manual_v2_auto_phone_provider_label} 短信验证码，等待后续跳转...", step="phone_verification")
                            current_url, body_text = _wait_for_manual_v2_contact_submit_transition(
                                current_url,
                                body_text,
                                timeout_ms=18000,
                            )
                            page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=2500)
                            if _is_profile_page(current_url, body_text, page) or "about-you" in str(current_url or "").lower():
                                emitter.info(
                                    "浏览器模式2 短信验证码通过后已进入 about-you 资料页，下一轮自动填写姓名/年龄并点击 Finish creating account..."
                                    + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                    step="create_account",
                                )
                            elif _is_contact_verification_page(current_url, body_text, page):
                                manual_v2_sms_code_submitted = False
                            continue
                        if _manual_contact_verification_ready(page):
                            if _click_primary_action(page, ["Continue", "Verify", "Submit", "继续", "下一步"], allow_generic_fallback=True):
                                emitter.info("浏览器模式2 检测到你已填好手机验证码，已自动点击继续...", step="phone_verification")
                                manual_v2_sms_code_submitted = True
                                _wait_for_load(page, timeout_ms=2000)
                                continue
                        if not manual_v2_wait_contact_logged:
                            manual_v2_wait_contact_logged = True
                            emitter.info(
                                "浏览器模式2 已进入 contact-verification 页面，请人工输入短信验证码；完成后程序会自动继续...",
                                step="phone_verification",
                            )
                        _sleep_with_page(page, 1000)
                        continue

                    if (
                        manual_v2_contact_seen
                        and not manual_v2_login_flow_started
                        and manual_v2_reset_password_flow_started
                        and _is_reset_password_new_password_page(current_url, body_text, page)
                    ):
                        if not _wait_for_reset_password_new_password_ready(page, timeout_ms=12000):
                            raise RuntimeError("浏览器模式2 等待 reset-password/new-password 页面稳定超时")
                        emitter.info(
                            f"浏览器模式2 已进入 reset-password/new-password 页面，准备重新设置密码: {ctx.account_password}",
                            step="create_password",
                        )
                        if not _fill_first(
                            page,
                            [
                                'input[name="new-password"]',
                                'input[autocomplete="new-password"]',
                                'input[id*="new-password" i]',
                            ],
                            ctx.account_password,
                        ):
                            raise RuntimeError("浏览器模式2 在 reset-password/new-password 页面填写新密码失败")
                        if not _fill_first(
                            page,
                            [
                                'input[name="confirm-password"]',
                                'input[id*="confirm-password" i]',
                                'input[placeholder*="Re-enter new password" i]',
                            ],
                            ctx.account_password,
                        ):
                            raise RuntimeError("浏览器模式2 在 reset-password/new-password 页面填写确认密码失败")
                        previous_url = current_url
                        previous_body = body_text
                        if not _click_primary_action(page, ["Continue", "Next", "继续", "下一步"], allow_generic_fallback=True):
                            raise RuntimeError("浏览器模式2 在 reset-password/new-password 页面提交失败")
                        emitter.info("浏览器模式2 已完成 reset-password/new-password 提交，转入第二步手机登录流程...", step="create_password")
                        _wait_for_page_stabilize(
                            previous_url,
                            previous_body,
                            step="create_password",
                            action_label="reset-password/new-password 已提交",
                            timeout_ms=15000,
                        )
                        _prepare_manual_v2_login_flow(
                            "浏览器模式2 已完成首次重置密码，先使用已保存手机号与密码重新登录 ChatGPT 完成资料补充...",
                            profile_completion_only=True,
                        )
                        continue

                    if (
                        manual_v2_contact_seen
                        and not manual_v2_login_flow_started
                        and manual_v2_reset_password_flow_started
                        and _is_reset_password_success_page(current_url, body_text)
                    ):
                        emitter.info(
                            "浏览器模式2 已进入 reset-password/success 页面，直接转入第二步手机登录流程...",
                            step="create_password",
                        )
                        _prepare_manual_v2_login_flow(
                            "浏览器模式2 已完成首次重置密码成功页，先使用已保存手机号与密码重新登录 ChatGPT 完成资料补充...",
                            profile_completion_only=True,
                        )
                        continue

                    if (
                        not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                        and not is_create_password_page
                        and not _is_reset_password_new_password_page(current_url, body_text, page)
                        and not _is_login_password_page(current_url, body_text, page)
                        and not password_submitted
                        and _is_phone_input_page(current_url, body_text, page)
                    ):
                        if not manual_v2_wait_phone_logged:
                            manual_v2_wait_phone_logged = True
                            manual_v2_wait_phone_last_url = current_url
                            emitter.info(
                                "浏览器模式2 正等待人工完成手机号输入/提交；检测到跳转到创建密码页后将自动继续...",
                                step="add_phone",
                            )
                        elif current_url and current_url != manual_v2_wait_phone_last_url:
                            manual_v2_wait_phone_last_url = current_url
                            emitter.info(
                                "浏览器模式2 仍在等待手机号阶段，当前页面: "
                                + _mask_secret(current_url, head=56, tail=12),
                                step="add_phone",
                            )
                        _sleep_with_page(page, 1000)
                        continue

                    if (
                        manual_v2_login_flow_started
                        and manual_v2_profile_completion_mode
                        and _is_logged_in_chatgpt_home(current_url, body_text)
                    ):
                        _extend_manual_v2_deadline(1800)
                        emitter.success(
                            "浏览器模式2 reset-password 后复用手机号与密码登录时，站点直接进入已登录的 ChatGPT 主页；"
                            + "说明当前账号无需补资料，直接切入真正的步骤2 OAuth 获取 Token 流程...",
                            step="create_account",
                        )
                        manual_v2_profile_completion_mode = False
                        _prepare_manual_v2_login_flow(
                            "浏览器模式2 已确认 reset-password 后登录可直接进入 ChatGPT 主页，"
                            + "无需补资料，现进入真正的步骤2 OAuth 获取 Token 流程..."
                        )
                        continue

                    # about-you 已有 Terms 红字：只再点 Finish，绝不重填姓名/年龄。
                    if (
                        _about_you_form_still_visible(current_url, body_text, page)
                        and _is_about_you_terms_soft_error(current_url, body_text, page)
                    ):
                        profile_submitted = False
                        emitter.warn(
                            "浏览器模式2 about-you 已有 Terms of Use 红色提示；"
                            + "不重填资料，直接再点 Finish creating account...",
                            step="create_account",
                        )
                        finish_result = _submit_about_you_finish_with_terms_retry(
                            page,
                            ctx,
                            max_attempts=3,
                            settle_ms=800,
                        )
                        current_url = str(finish_result.get("url") or current_url)
                        body_text = str(finish_result.get("body") or body_text)
                        if finish_result.get("terms_retried") or int(finish_result.get("attempts") or 0) > 1:
                            emitter.info(
                                f"浏览器模式2 Terms 红字场景已连续点击 Finish {finish_result.get('attempts') or 0} 次"
                                + ("（仍未离开则下轮继续只点）" if _about_you_form_still_visible(current_url, body_text, page) else "，已离开资料页"),
                                step="create_account",
                            )
                        if _about_you_form_still_visible(current_url, body_text, page):
                            _sleep_with_page(page, 800)
                            continue
                        profile_submitted = True
                        callback_state["url"] = ""
                        all_set = _pass_youre_all_set_page(
                            page,
                            emitter=emitter,
                            step="create_account",
                            max_attempts=6,
                            settle_ms=700,
                            wait_appear_ms=3500,
                        )
                        try:
                            current_url = str(all_set.get("url") or current_url)
                            body_text = str(all_set.get("body") or body_text)
                        except Exception:
                            pass
                        if all_set.get("was_page") and not all_set.get("left"):
                            emitter.warn(
                                "浏览器模式2 Terms 重点后仍停在 You're all set，本轮不进步骤2，下一轮继续点 Continue...",
                                step="create_account",
                            )
                            continue
                        if (not all_set.get("left")) and (not all_set.get("was_page")):
                            emitter.warn(
                                "浏览器模式2 Terms 重点后页面未离开资料/过渡态，本轮不进步骤2，下一轮重试...",
                                step="create_account",
                            )
                            continue
                        if _is_youre_all_set_page(current_url, body_text, page):
                            emitter.warn(
                                "浏览器模式2 Terms 重点后仍检测到 You're all set，交给主循环继续点 Continue...",
                                step="create_account",
                            )
                            continue
                        if manual_v2_profile_completion_mode:
                            manual_v2_profile_completion_mode = False
                            manual_v2_post_login_pending_email = False
                            manual_v2_bridge_entered_at = 0.0
                            manual_v2_bridge_logged = False
                            _prepare_manual_v2_login_flow(
                                "浏览器模式2 Terms 红字重点 Finish 成功，结束补资料分流并进入真正的步骤2 OAuth..."
                            )
                        elif not manual_v2_login_flow_started:
                            _prepare_manual_v2_login_flow(
                                "浏览器模式2 Terms 红字重点 Finish 成功，进入真正的步骤2 OAuth 登录/补邮箱获取 Token 流程..."
                            )
                        else:
                            emitter.success(
                                "浏览器模式2 Terms 红字重点 Finish 成功，资料页已通过，继续后续流程...",
                                step="create_account",
                            )
                        continue

                    # about-you 完成后的 You're all set：必须点 Continue 离开，再进步骤2。
                    if is_manual_v2_mode and _is_youre_all_set_page(current_url, body_text, page):
                        _extend_manual_v2_deadline(1800)
                        all_set = _pass_youre_all_set_page(
                            page,
                            emitter=emitter,
                            step="create_account",
                            max_attempts=6,
                            settle_ms=900,
                            wait_appear_ms=0,
                        )
                        profile_submitted = True
                        if not all_set.get("left"):
                            # 仍在完成页：不拉 OAuth，下一轮继续点
                            continue
                        # 已离开完成页
                        if (
                            not manual_v2_login_flow_started
                            or manual_v2_profile_completion_mode
                            or (manual_v2_login_flow_started and not manual_v2_oauth_resumed)
                        ):
                            if manual_v2_profile_completion_mode:
                                emitter.success(
                                    "浏览器模式2 You're all set 已通过，结束补资料分流并进入真正的步骤2 OAuth...",
                                    step="create_account",
                                )
                            else:
                                emitter.success(
                                    "浏览器模式2 You're all set 已通过，进入真正的步骤2 OAuth 获取 Token...",
                                    step="create_account",
                                )
                            manual_v2_profile_completion_mode = False
                            manual_v2_post_login_pending_email = False
                            manual_v2_bridge_entered_at = 0.0
                            manual_v2_bridge_logged = False
                            callback_state["url"] = ""
                            _prepare_manual_v2_login_flow(
                                "浏览器模式2 You're all set 后进入真正的步骤2 OAuth 获取 Token / 绑定邮箱流程..."
                            )
                        continue

                    if (
                        manual_v2_login_flow_started
                        and manual_v2_profile_completion_mode
                        and not manual_v2_phone_entry_clicked
                        and "chatgpt.com" in current_url_lower
                        and "auth.openai.com" not in current_url_lower
                        and not _is_login_with_bridge_page(current_url, body_text)
                    ):
                        _extend_manual_v2_deadline(1800)
                        # 补资料登录流：首页 “Log in” → Continue with phone → 直链兜底（复用步骤1逻辑）
                        clicked_login = _click_first(
                            page,
                            [
                                'a:has-text("Log in")',
                                'button:has-text("Log in")',
                                '[role="button"]:has-text("Log in")',
                                'a:has-text("登录")',
                                'button:has-text("登录")',
                                '[role="button"]:has-text("登录")',
                            ],
                            timeout_ms=1500,
                        )
                        if clicked_login:
                            emitter.info(
                                "浏览器模式2 reset-password 后的补资料登录流已点击 ChatGPT 首页“登录”，准备进入手机登录...",
                                step="oauth_init",
                            )
                            _wait_for_load(page, timeout_ms=2500)
                        current_url, body_text = _describe_page(page, force_refresh=True)
                        current_url_lower = str(current_url or "").lower()
                        body_lower = str(body_text or "").lower()
                        # 若已出现手机入口/手机输入框，继续点 Continue with phone 或标记成功
                        if _is_phone_input_page(current_url, body_text, page) or _has_phone_input(page):
                            manual_v2_phone_entry_clicked = True
                            emitter.info(
                                "浏览器模式2 补资料登录流已进入手机号输入页，准备自动复用已保存手机号...",
                                step="oauth_init",
                            )
                            continue
                        if _bootstrap_manual_v2_login_entry(current_url, body_text):
                            current_url, body_text = _describe_page(page, force_refresh=True)
                            if _is_phone_input_page(current_url, body_text, page) or _has_phone_input(page) or "auth.openai.com" in str(current_url or "").lower() or "chatgpt.com/auth/" in str(current_url or "").lower():
                                manual_v2_phone_entry_clicked = True
                                emitter.info(
                                    "浏览器模式2 补资料登录流已通过手机号入口进入认证流程。",
                                    step="oauth_init",
                                )
                                continue
                        # 点击后仍停首页：直接走手机号入口直链（与步骤1一致）
                        if "chatgpt.com" in current_url_lower and "auth.openai.com" not in current_url_lower:
                            manual_v2_entry_fallback_attempts += 1
                            if _goto_manual_v2_phone_auth_entry(
                                reason=(
                                    "补资料登录流点击登录/手机入口后仍停在首页"
                                    if clicked_login
                                    else "补资料登录流未点到登录按钮，准备手机号入口直链"
                                ),
                                prefer_login=True,
                            ):
                                manual_v2_phone_entry_clicked = True
                                continue
                            if manual_v2_entry_fallback_attempts >= 3:
                                emitter.warn(
                                    "浏览器模式2 补资料登录流连续多次仍未进入手机号页，下一轮继续重试直链..."
                                    + f" attempt={manual_v2_entry_fallback_attempts}",
                                    step="oauth_init",
                                )
                        continue

                    if (
                        not manual_v2_login_flow_started
                        and not profile_submitted
                        and not _is_create_account_password_page(current_url, body_text, page)
                        and not (
                            _has_visible_password_input(page)
                            and "about-you" not in str(current_url or "").lower()
                            and not _has_visible_about_you_controls(page)
                        )
                        and (
                            _is_profile_page(current_url, body_text, page)
                            or "about-you" in str(current_url or "").lower()
                        )
                    ):
                        # 短信验证后即使 contact_seen 标志丢失，也要能进入资料页。
                        manual_v2_contact_seen = True
                        _extend_manual_v2_deadline(1800)
                        page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=3000)
                        if (
                            _is_create_account_password_page(current_url, body_text, page)
                            or (
                                _has_visible_password_input(page)
                                and "about-you" not in str(current_url or "").lower()
                                and not _has_visible_about_you_controls(page)
                            )
                        ):
                            emitter.warn(
                                "浏览器模式2 复用资料流程前复核仍为密码页，跳过 about-you 填写..."
                                + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                step="create_password",
                            )
                            continue
                        emitter.info("浏览器模式2 已进入 about-you 页面，复用资料填写流程...", step="create_account")
                        emitter.info(
                            f"浏览器本次资料: name={ctx.profile_name}, birthdate={ctx.profile_birthdate}, age={_derive_profile_age(ctx.profile_birthdate)}",
                            step="create_account",
                        )
                        profile_ok, profile_mode = _fill_about_you_profile(page, ctx)
                        if not profile_ok and profile_mode == "name":
                            raise RuntimeError("浏览器模式2 在 about-you 页面填写姓名失败")
                        if not profile_ok and profile_mode in {"birthdate", "age"}:
                            emitter.warn(
                                "浏览器模式2 about-you 年龄/生日控件诊断: " + _summarize_about_you_controls(page),
                                step="create_account",
                            )
                            raise RuntimeError("浏览器模式2 在 about-you 页面填写年龄/生日失败")
                        if not profile_ok and profile_mode == "checkbox":
                            emitter.warn(
                                "浏览器模式2 about-you 勾选控件诊断: " + _summarize_about_you_controls(page),
                                step="create_account",
                            )
                            raise RuntimeError("浏览器模式2 在 about-you 页面勾选同意项失败")
                        previous_url = current_url
                        previous_body = body_text
                        finish_result = _submit_about_you_finish_with_terms_retry(
                            page,
                            ctx,
                            max_attempts=3,
                            settle_ms=800,
                        )
                        if finish_result.get("terms_retried"):
                            emitter.warn(
                                "浏览器模式2 about-you 出现 Terms of Use 红色提示，"
                                + f"未重填资料，已直接再点 Finish creating account（共 {finish_result.get('attempts') or 0} 次）...",
                                step="create_account",
                            )
                        if not finish_result.get("clicked"):
                            raise RuntimeError("浏览器模式2 提交 about-you 资料失败：未点到 Finish creating account")
                        current_url = str(finish_result.get("url") or current_url)
                        body_text = str(finish_result.get("body") or body_text)
                        if _about_you_form_still_visible(current_url, body_text, page):
                            if _is_about_you_terms_soft_error(current_url, body_text, page):
                                emitter.warn(
                                    "浏览器模式2 about-you 多次直接点击 Finish 后仍显示 Terms 红字，"
                                    + "本轮不结束资料页；下一轮继续只点 Finish，不重填...",
                                    step="create_account",
                                )
                                _sleep_with_page(page, 800)
                                continue
                            current_url, body_text = _wait_for_page_stabilize(
                                previous_url,
                                previous_body,
                                step="create_account",
                                action_label="about-you 资料已提交",
                                timeout_ms=12000,
                            )
                            if _about_you_form_still_visible(current_url, body_text, page):
                                emitter.warn(
                                    "浏览器模式2 about-you 提交后仍停留在资料页，暂不进入下一步，下一轮重试..."
                                    + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                    step="create_account",
                                )
                                continue
                        profile_submitted = True
                        if _is_about_you_missing_email_error(current_url, body_text):
                            if manual_v2_profile_completion_mode:
                                emitter.warn(
                                    "浏览器模式2 reset-password 后的补资料流程在 about-you 提交后命中 authentication missing_email，"
                                    + "这说明资料补充阶段已结束，下一步直接切入真正的步骤2 OAuth 补邮箱链路...",
                                    step="create_email",
                                )
                                manual_v2_profile_completion_mode = False
                                manual_v2_post_login_pending_email = False
                                manual_v2_bridge_entered_at = 0.0
                                manual_v2_bridge_logged = False
                                manual_v2_post_login_recover_attempts = 0
                                manual_v2_post_login_retryable_error_attempts = 0
                                manual_v2_email_verification_logged = False
                                email_submitted = False
                                _prepare_manual_v2_login_flow(
                                    "浏览器模式2 reset-password 后的补资料阶段已结束，"
                                    + "现在进入真正的步骤2 OAuth 获取 Token / 绑定邮箱流程..."
                                )
                                continue
                            emitter.warn(
                                "浏览器模式2 about-you 提交后命中 authentication missing_email，"
                                + "改为回到 ChatGPT 首页复用已保存手机号与密码重新登录，继续补资料/补邮箱链路...",
                                step="create_email",
                            )
                            manual_v2_post_login_pending_email = False
                            manual_v2_bridge_entered_at = 0.0
                            manual_v2_bridge_logged = False
                            manual_v2_post_login_recover_attempts = 0
                            manual_v2_post_login_retryable_error_attempts = 0
                            manual_v2_email_verification_logged = False
                            email_submitted = False
                            _prepare_manual_v2_login_flow(
                                "浏览器模式2 about-you 提交后命中 authentication missing_email，"
                                + "现在回到 ChatGPT 首页，复用已保存手机号与密码重新登录并继续补资料/补邮箱...",
                                profile_completion_only=True,
                            )
                            continue
                        all_set = _pass_youre_all_set_page(
                            page,
                            emitter=emitter,
                            step="create_account",
                            max_attempts=6,
                            settle_ms=700,
                            wait_appear_ms=3500,
                        )
                        try:
                            current_url = str(all_set.get("url") or current_url)
                            body_text = str(all_set.get("body") or body_text)
                        except Exception:
                            pass
                        if all_set.get("was_page") and not all_set.get("left"):
                            emitter.warn(
                                "浏览器模式2 about-you 提交后仍停在 You're all set，本轮不进入下一步，下一轮继续点 Continue...",
                                step="create_account",
                            )
                            continue
                        if (not all_set.get("left")) and (not all_set.get("was_page")):
                            emitter.warn(
                                "浏览器模式2 about-you 提交后页面未离开资料/过渡态，本轮不进入下一步，下一轮重试...",
                                step="create_account",
                            )
                            continue
                        if _is_youre_all_set_page(current_url, body_text, page):
                            emitter.warn(
                                "浏览器模式2 about-you 后仍检测到 You're all set，交给主循环继续点 Continue...",
                                step="create_account",
                            )
                            continue
                        emitter.success(
                            "浏览器模式2 已完成 about-you"
                            + ("并离开 You're all set" if all_set.get("was_page") else "")
                            + "，转入手机登录补邮箱流程...",
                            step="create_account",
                        )
                        if manual_v2_profile_completion_mode:
                            manual_v2_profile_completion_mode = False
                            callback_state["url"] = ""
                            _prepare_manual_v2_login_flow(
                                "浏览器模式2 已完成 about-you 资料填写，"
                                + "现在进入真正的步骤2 OAuth 获取 Token 流程..."
                            )
                        else:
                            _prepare_manual_v2_login_flow("浏览器模式2 正在清理注册残留状态，并重新打开手机登录流程...")
                        continue

                    if (
                        manual_v2_contact_seen
                        and not manual_v2_login_flow_started
                        # 仍在手机短信验证码页且还没提交时，禁止进入“提交后过渡观察”，
                        # 否则会和上方真正的短信填码分支形成死循环空转。
                        and not (
                            not manual_v2_sms_code_submitted
                            and (
                                "contact-verification" in current_url_lower
                                or "verify-phone" in current_url_lower
                                or _is_contact_verification_page(current_url, body_text, page)
                            )
                        )
                    ):
                        if _is_retryable_error_page(current_url, body_text):
                            if _try_recover_timeout_error_page(
                                current_url,
                                body_text,
                                step="create_password",
                                action_label="短信验证码后的错误页已触发当前页重试",
                                timeout_ms=12000,
                            ):
                                current_url, body_text = _describe_page(page, force_refresh=True)
                                continue
                        if _is_create_account_password_page(current_url, body_text, page):
                            _extend_manual_v2_deadline(1800)
                            manual_v2_contact_seen = False
                            manual_v2_wait_contact_logged = False
                            manual_v2_contact_transition_last_key = ""
                            manual_v2_sms_code_submitted = False
                            manual_v2_waiting_phone_retry = False
                            manual_v2_waiting_phone_retry_logged = False
                            manual_v2_require_phone_resubmit = False
                            manual_v2_wait_phone_logged = False
                            manual_v2_password_page_logged = False
                            manual_v2_create_password_submit_attempts = 0
                            password_submitted = False
                            emitter.info(
                                "浏览器模式2 检测到流程从短信验证码页回到了设置密码页，已恢复自动填密码流程...",
                                step="create_password",
                            )
                            _sleep_with_page(page, 800)
                            continue
                        if _is_manual_v2_phone_stage_page(current_url, body_text, page):
                            _extend_manual_v2_deadline(1800)
                            manual_v2_contact_seen = False
                            manual_v2_wait_contact_logged = False
                            manual_v2_contact_transition_last_key = ""
                            manual_v2_sms_code_submitted = False
                            manual_v2_wait_phone_logged = False
                            manual_v2_waiting_phone_retry = False
                            manual_v2_waiting_phone_retry_logged = False
                            manual_v2_require_phone_resubmit = True
                            manual_v2_reset_password_flow_started = False
                            manual_v2_reset_password_continue_clicked = False
                            manual_v2_password_page_logged = False
                            password_submitted = False
                            emitter.warn(
                                "浏览器模式2 检测到你已从短信验证码页回退，已恢复到手机号录入阶段；你可以重新输入别的手机号继续注册。",
                                step="add_phone",
                            )
                            if "chatgpt.com" in current_url_lower and not _is_login_with_bridge_page(current_url, body_text):
                                emitter.info("浏览器模式2 检测到已回到 ChatGPT 首页，立即重新尝试打开手机号注册入口...", step="oauth_init")
                                _bootstrap_manual_v2_phone_entry(current_url, body_text)
                                _wait_for_load(page, timeout_ms=2000)
                            _sleep_with_page(page, 800)
                            continue
                        # 短信提交后已进入资料页：结束过渡观察，交给 about-you 分支。
                        if _is_profile_page(current_url, body_text, page) or "about-you" in current_url_lower:
                            manual_v2_sms_code_submitted = True
                            manual_v2_contact_transition_last_key = ""
                            emitter.info(
                                "浏览器模式2 短信验证码提交后已进入 about-you 资料页，结束过渡观察并进入资料填写..."
                                + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                step="create_account",
                            )
                            continue
                        # 若因误重拉 OAuth 落到 create-account 邮箱页，不要当正常过渡空转；
                        # 有 activation 说明本轮手机注册仍有效，优先尝试回到首页/auth 自然流而非卡死。
                        if (
                            manual_v2_sms_code_submitted
                            and "auth.openai.com/create-account" in current_url_lower
                            and "password" not in current_url_lower
                            and "about-you" not in current_url_lower
                        ):
                            emitter.warn(
                                "浏览器模式2 短信验证码提交后落到 create-account 邮箱页（通常由中途误重拉 OAuth 引起），"
                                + "保留手机号上下文并继续短等/提升页面，不再空转过渡观察..."
                                + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                step="phone_verification",
                            )
                            page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=3000)
                            if _is_profile_page(current_url, body_text, page) or "about-you" in str(current_url or "").lower():
                                continue
                            # 给站点一次自然恢复机会；若持续停留再由主循环其它分支处理。
                            _sleep_with_page(page, 1200)
                            continue

                        # 若其实还停在短信验证码页，说明要么码未提交成功，要么提交后仍需重填。
                        if (
                            "contact-verification" in current_url_lower
                            or "verify-phone" in current_url_lower
                            or _is_contact_verification_page(current_url, body_text, page)
                        ):
                            if manual_v2_sms_code_submitted:
                                emitter.info(
                                    "浏览器模式2 短信验证码提交后仍停留在 contact-verification，继续短等站点跳转..."
                                    + f" current_url={_mask_secret(current_url, head=56, tail=12)}"
                                    + f", state={_classify_page_state(current_url, body_text, page)}",
                                    step="phone_verification",
                                )
                                current_url, body_text = _wait_for_manual_v2_contact_submit_transition(
                                    current_url,
                                    body_text,
                                    timeout_ms=8000,
                                )
                                page, current_url, body_text = _promote_auth_target_if_needed(page, timeout_ms=3000)
                                if _is_contact_verification_page(current_url, body_text, page) or (
                                    "contact-verification" in str(current_url or "").lower()
                                ):
                                    manual_v2_sms_code_submitted = False
                                    manual_v2_wait_contact_logged = False
                                    emitter.warn(
                                        "浏览器模式2 短信验证码提交后仍在 contact-verification，准备重新填写/提交验证码...",
                                        step="phone_verification",
                                    )
                                continue
                            # 未提交却进了过渡分支：放行回主循环真正填码。
                            manual_v2_contact_transition_last_key = ""
                            continue

                        transition_state = _classify_page_state(current_url, body_text, page)
                        transition_key = f"{transition_state}|{str(current_url or '').strip().lower()}"
                        if transition_key != manual_v2_contact_transition_last_key:
                            manual_v2_contact_transition_last_key = transition_key
                            emitter.info(
                                "浏览器模式2 短信验证码提交后进入过渡页，继续观察后续跳转，不再仅凭离开 contact-verification 就判定完成。"
                                + f" current_url={_mask_secret(current_url, head=56, tail=12)}"
                                + f", state={transition_state}",
                                step="phone_verification",
                            )
                        _sleep_with_page(page, 800)
                        continue

                    if (
                        manual_v2_login_flow_started
                        and not manual_v2_profile_completion_mode
                        and _is_choose_account_page(current_url, body_text, page)
                    ):
                        _extend_manual_v2_deadline(1800)
                        choose_account_result = _click_choose_account_phone_card(page, manual_v2_phone_number)
                        choose_account_clicked = str(choose_account_result.get("clicked") or "").strip().lower() == "true"
                        if (
                            not choose_account_clicked
                            and not str(choose_account_result.get("matched_text") or "").strip()
                            and _click_first(
                                page,
                                [
                                    '[role="listitem"] button',
                                    '[role="listitem"] [role="button"]',
                                    '[data-testid*="account" i] button',
                                    '[data-testid*="account" i] [role="button"]',
                                    'button:has-text("Continue as")',
                                    '[role="button"]:has-text("Continue as")',
                                    'button:has-text("继续使用")',
                                    '[role="button"]:has-text("继续使用")',
                                ],
                                timeout_ms=1500,
                            )
                            and _wait_for_choose_account_transition(page, current_url, timeout_ms=2800)
                        ):
                            choose_account_clicked = True
                            choose_account_result = {
                                "clicked": "true",
                                "matched_text": "",
                                "reason": "fallback_account_button",
                            }
                        if choose_account_clicked:
                            manual_v2_choose_account_click_failures = 0
                            emitter.info(
                                "浏览器模式2 第二步命中 choose-an-account 页面，已自动点击当前已登录账号，等待站点跳到绑定邮箱链路..."
                                + (
                                    f" matched={_preview_text(choose_account_result.get('matched_text', ''), 48)}"
                                    if choose_account_result.get("matched_text")
                                    else ""
                                ),
                                step="oauth_init",
                            )
                            _wait_for_load(page, timeout_ms=1200)
                            continue
                        if str(choose_account_result.get("reason") or "").strip() == "candidate_not_clickable":
                            manual_v2_choose_account_click_failures += 1
                            if manual_v2_choose_account_click_failures >= 3 and _click_first(
                                page,
                                [
                                    'button:has-text("Use another account")',
                                    '[role="button"]:has-text("Use another account")',
                                    'button:has-text("使用其他账号")',
                                    '[role="button"]:has-text("使用其他账号")',
                                ],
                                timeout_ms=1200,
                            ):
                                manual_v2_choose_account_click_failures = 0
                                emitter.warn(
                                    "浏览器模式2 choose-an-account 页面连续多次命中账号卡片但点击未生效；"
                                    + "已主动切到“使用其他账号”，回退到手机号登录链路继续推进...",
                                    step="oauth_init",
                                )
                                _wait_for_load(page, timeout_ms=2000)
                                continue
                            emitter.warn(
                                "浏览器模式2 当前停留在 choose-an-account 页面，已识别到目标手机号账号卡片，但真实点击未生效；继续下一轮观察..."
                                + f" attempt={manual_v2_choose_account_click_failures}"
                                + (
                                    f" matched={_preview_text(choose_account_result.get('matched_text', ''), 48)}"
                                    if choose_account_result.get("matched_text")
                                    else ""
                                ),
                                step="oauth_init",
                            )
                            _sleep_with_page(page, 600)
                            continue
                        if _click_first(
                            page,
                            [
                                'button:has-text("Use another account")',
                                '[role="button"]:has-text("Use another account")',
                                'button:has-text("使用其他账号")',
                                '[role="button"]:has-text("使用其他账号")',
                            ],
                            timeout_ms=1200,
                        ):
                            manual_v2_choose_account_click_failures = 0
                            emitter.warn(
                                "浏览器模式2 choose-an-account 页面未找到可直接复用的账号卡片，已切到“使用其他账号”，回退到手机号登录链路...",
                                step="oauth_init",
                            )
                            _wait_for_load(page, timeout_ms=2000)
                            continue
                        manual_v2_choose_account_click_failures = 0
                        emitter.warn(
                            "浏览器模式2 当前停留在 choose-an-account 页面，但未识别到可点击的账号卡片或“使用其他账号”按钮；继续下一轮观察...",
                            step="oauth_init",
                        )
                        _sleep_with_page(page, 600)
                        continue

                    if manual_v2_login_flow_started and not manual_v2_phone_entry_clicked and _is_phone_login_entry_page(current_url, body_text, page):
                        _extend_manual_v2_deadline(1800)
                        if _click_first(
                            page,
                            [
                                'button:has-text("Continue with phone")',
                                '[role="button"]:has-text("Continue with phone")',
                                'button:has-text("继续使用手机登录")',
                                '[role="button"]:has-text("继续使用手机登录")',
                            ],
                            timeout_ms=1500,
                        ):
                            manual_v2_phone_entry_clicked = True
                            emitter.info("浏览器模式2 已点击“继续使用手机登录”，准备自动填写手机号...", step="oauth_init")
                            _wait_for_load(page, timeout_ms=2000)
                            continue

                    if manual_v2_login_flow_started and _is_session_ended_login_shell_page(current_url, body_text, page):
                        _extend_manual_v2_deadline(1800)
                        if _click_first(
                            page,
                            [
                                'a:has-text("Log in")',
                                'button:has-text("Log in")',
                                '[role="button"]:has-text("Log in")',
                                'a:has-text("登录")',
                                'button:has-text("登录")',
                                '[role="button"]:has-text("登录")',
                            ],
                            timeout_ms=1500,
                        ):
                            emitter.info("浏览器模式2 命中“你的会话已结束”登录壳页，已自动点击登录继续...", step="oauth_init")
                            _wait_for_load(page, timeout_ms=2000)
                            continue

                    if (
                        manual_v2_login_flow_started
                        and not manual_v2_phone_entry_clicked
                        and "auth.openai.com/log-in" in current_url_lower
                    ):
                        _extend_manual_v2_deadline(1800)
                        if _bootstrap_manual_v2_login_entry(current_url, body_text):
                            current_url, body_text = _describe_page(page)
                            current_url_lower = current_url.lower()
                            body_lower = body_text.lower()
                            if _is_phone_input_page(current_url, body_text, page):
                                manual_v2_phone_entry_clicked = True
                        if _is_phone_login_entry_page(current_url, body_text, page):
                            continue

                    if manual_v2_login_flow_started and _is_login_with_bridge_page(current_url, body_text):
                        _extend_manual_v2_deadline(1800)
                        if manual_v2_profile_completion_mode and not manual_v2_phone_entry_clicked:
                            if _bootstrap_manual_v2_login_entry(current_url, body_text):
                                current_url, body_text = _describe_page(page)
                                current_url_lower = current_url.lower()
                                body_lower = body_text.lower()
                                if _is_phone_input_page(current_url, body_text, page):
                                    manual_v2_phone_entry_clicked = True
                                    emitter.info(
                                        "浏览器模式2 reset-password 后的补资料登录流已在登录弹层切到手机登录入口，准备填写手机号...",
                                        step="oauth_init",
                                    )
                        if (
                            manual_v2_profile_completion_mode
                            and manual_v2_phone_entry_clicked
                            and not manual_v2_login_phone_submitted
                            and _is_manual_v2_login_phone_input_stage(current_url, body_text, page)
                        ):
                            if not manual_v2_phone_number:
                                manual_v2_phone_number = _extract_input_value_by_hints(
                                    page,
                                    ["phone", "mobile", "手机号", "电话", "tel"],
                                )
                            if not manual_v2_phone_number and manual_v2_auto_phone_mode:
                                manual_v2_phone_number = _ensure_manual_v2_auto_phone(
                                    step="create_email",
                                    prompt=f"浏览器模式2 reset-password 后的补资料登录流已到手机号输入页，准备复用本轮 {manual_v2_auto_phone_provider_label} 手机号自动继续...",
                                )
                            if manual_v2_phone_number:
                                if not _submit_manual_v2_phone_input(page, manual_v2_phone_number, step="create_email"):
                                    raise RuntimeError("浏览器模式2 reset-password 后的补资料登录流自动提交已保存手机号失败")
                                manual_v2_login_phone_submitted = True
                                manual_v2_post_login_pending_email = False
                                manual_v2_bridge_entered_at = 0.0
                                manual_v2_bridge_logged = False
                                manual_v2_post_login_recover_attempts = 0
                                manual_v2_post_login_retryable_error_attempts = 0
                                emitter.info(
                                    "浏览器模式2 reset-password 后的补资料登录流已自动复用保存的手机号并提交，等待密码页...",
                                    step="create_email",
                                )
                                _wait_for_load(page, timeout_ms=4000)
                                continue
                        if manual_v2_profile_completion_mode:
                            if not manual_v2_bridge_logged:
                                manual_v2_bridge_logged = True
                                manual_v2_bridge_entered_at = time.time()
                                emitter.info(
                                    "浏览器模式2 补资料登录流进入 chatgpt.com/auth/login_with 桥接页，当前仅等待站点继续跳到密码页或 about-you，"
                                    + "此阶段不进入绑定邮箱逻辑...",
                                    step="oauth_init",
                                )
                                emitter.info(
                                    "补资料桥接页会话诊断: cookies="
                                    + _browser_cookie_presence_summary(context),
                                    step="oauth_init",
                                )
                            _wait_for_load(page, timeout_ms=2000)
                            _sleep_with_page(page, 500)
                            continue
                        if not manual_v2_bridge_logged:
                            manual_v2_bridge_logged = True
                            manual_v2_bridge_entered_at = time.time()
                            emitter.info(
                                "浏览器模式2 第二步登录后进入 chatgpt.com/auth/login_with 桥接页，先等待站点自动跳转到绑定邮箱页...",
                                step="oauth_init",
                            )
                            emitter.info(
                                "桥接页会话诊断: cookies="
                                + _browser_cookie_presence_summary(context),
                                step="oauth_init",
                            )
                        _wait_for_load(page, timeout_ms=2000)
                        if manual_v2_post_login_pending_email and _has_manual_v2_login_session(context):
                            if not manual_v2_bridge_logged or manual_v2_bridge_entered_at <= 0:
                                manual_v2_bridge_entered_at = time.time()
                            emitter.info(
                                "浏览器模式2 检测到 login_with 桥接页上的登录态已建立，改为等待站点自然跳转到绑定邮箱页，不再强制打开 add-email...",
                                step="create_email",
                            )
                        if (
                            manual_v2_post_login_pending_email
                            and manual_v2_bridge_entered_at > 0
                            and _has_manual_v2_login_session(context)
                            and time.time() - manual_v2_bridge_entered_at >= 12
                        ):
                            if _restart_manual_v2_login_oauth(
                                "浏览器模式2 在 login_with 桥接页等待超过 12 秒仍未自然进入 add-email / email-verification / callback，"
                                + "重新生成授权链接并重试第二步手机登录。"
                            ):
                                continue
                            emitter.warn(
                                "浏览器模式2 第二步 OAuth 重试次数已用尽，改为执行安全补跳 add-email；"
                                + "若补跳后仍失败，再退回 session fast path 兜底。",
                                step="create_email",
                            )
                            if _goto_manual_v2_add_email("浏览器模式2 在 bridge 页重试耗尽后安全补跳 add-email"):
                                continue
                            session_fast_path_token = _try_browser_session_fast_path(current_url)
                            if session_fast_path_token:
                                return session_fast_path_token
                        _sleep_with_page(page, 800)
                        continue

                    if (
                        manual_v2_login_flow_started
                        and manual_v2_post_login_pending_email
                        and _is_retryable_error_page(current_url, body_text)
                    ):
                        manual_v2_post_login_retryable_error_attempts += 1
                        emitter.warn(
                            "浏览器模式2 第二步密码提交后命中可重试错误页，"
                            + f"先在当前页 Try again/Retry/重试，第 {manual_v2_post_login_retryable_error_attempts}/3 次原地恢复...",
                            step="oauth_init",
                        )
                        if _try_recover_timeout_error_page(
                            current_url,
                            body_text,
                            step="oauth_init",
                            action_label="第二步密码提交后的错误页已点击重试",
                            timeout_ms=12000,
                        ):
                            continue
                        if manual_v2_post_login_retryable_error_attempts < 3:
                            emitter.warn(
                                "浏览器模式2 当前页重试后仍未恢复，将继续保留在现有链路中等待下一轮页面更新，再尝试原地恢复...",
                                step="oauth_init",
                            )
                            _wait_for_load(page, timeout_ms=1800)
                            _sleep_with_page(page, 600)
                            continue
                        if _restart_manual_v2_login_page(
                            "浏览器模式2 第二步密码提交后连续 3 次原地 Try again/Retry/重试 仍未恢复，"
                            + "改为重新打开 auth.openai.com/log-in 页面并复用手机号+密码重新登录。"
                        ):
                            continue

                    if (
                        manual_v2_login_flow_started
                        and manual_v2_post_login_pending_email
                        and "auth.openai.com/log-in" in current_url_lower
                        and manual_v2_login_phone_submitted
                    ):
                        manual_v2_post_login_recover_attempts += 1
                        emitter.warn(
                            "浏览器模式2 第二步密码提交后又回到了 log-in 页面，判定为 login_with 桥接回跳；"
                            + f"当前第 {manual_v2_post_login_recover_attempts} 次观测到回跳。"
                            + " cookies="
                            + _browser_cookie_presence_summary(context),
                            step="oauth_init",
                        )
                        if _restart_manual_v2_login_page(
                            "浏览器模式2 第二步密码提交后未能继续进入绑定邮箱链路，"
                            + "直接重新打开 auth.openai.com/log-in 页面并复用手机号+密码重新登录。"
                        ):
                            continue
                        continue_probe = _manual_v2_authorize_continue_via_page_api(page, ctx.email)
                        continue_json = continue_probe.get("json") if isinstance(continue_probe.get("json"), dict) else {}
                        continue_url = str(continue_json.get("continue_url") or "").strip()
                        continue_page_type = str(((continue_json.get("page") or {}).get("type")) or "").strip()
                        emitter.info(
                            "浏览器模式2 回跳页 authorize/continue 直提结果: "
                            + f"status={int(continue_probe.get('status') or 0)}, "
                            + f"ok={'是' if continue_probe.get('ok') else '否'}, "
                            + f"page.type={continue_page_type or '-'}, "
                            + f"continue_url={_mask_secret(continue_url, head=56, tail=12) if continue_url else '-'}, "
                            + f"body={_preview_text(str(continue_probe.get('text') or ''), 220) or '-'}",
                            step="oauth_init",
                        )
                        if continue_probe.get("ok") and continue_page_type == "login_password":
                            verify_probe = _manual_v2_password_verify_via_page_api(page, ctx.account_password)
                            verify_json = verify_probe.get("json") if isinstance(verify_probe.get("json"), dict) else {}
                            verify_continue_url = str(verify_json.get("continue_url") or "").strip()
                            verify_page_type = str(((verify_json.get("page") or {}).get("type")) or "").strip()
                            emitter.info(
                                "浏览器模式2 回跳页 password/verify 直提结果: "
                                + f"status={int(verify_probe.get('status') or 0)}, "
                                + f"ok={'是' if verify_probe.get('ok') else '否'}, "
                                + f"page.type={verify_page_type or '-'}, "
                                + f"continue_url={_mask_secret(verify_continue_url, head=56, tail=12) if verify_continue_url else '-'}, "
                                + f"body={_preview_text(str(verify_probe.get('text') or ''), 220) or '-'}",
                                step="verify_otp",
                            )
                            if verify_probe.get("ok") and verify_continue_url:
                                try:
                                    page.goto(
                                        verify_continue_url,
                                        wait_until="domcontentloaded",
                                        timeout=cfg["browser_timeout_ms"],
                                    )
                                except Exception as exc:
                                    emitter.warn(f"浏览器模式2 回跳页 password/verify 后跳转 continue_url 失败: {exc}", step="verify_otp")
                                _wait_for_load(page, timeout_ms=2500)
                                continue
                        if continue_probe.get("ok") and continue_url:
                            try:
                                page.goto(
                                    continue_url,
                                    wait_until="domcontentloaded",
                                    timeout=cfg["browser_timeout_ms"],
                                )
                            except Exception as exc:
                                emitter.warn(f"浏览器模式2 回跳页 continue_url 跳转失败: {exc}", step="oauth_init")
                            _wait_for_load(page, timeout_ms=2500)
                            continue
                        if _has_manual_v2_login_session(context):
                            emitter.warn(
                                "浏览器模式2 第二步 OAuth 重试已用尽且当前确认登录态已建立，改为执行安全补跳 add-email...",
                                step="create_email",
                            )
                            if _goto_manual_v2_add_email("浏览器模式2 在自然桥接失败后安全补跳 add-email"):
                                continue
                        session_fast_path_token = _try_browser_session_fast_path(current_url)
                        if session_fast_path_token:
                            return session_fast_path_token
                        emitter.info(
                            "桥接回跳后已完成 OAuth 重试、continue 直提和 add-email 补跳，当前继续观察一次站点自然跳转。",
                            step="oauth_init",
                        )
                        _wait_for_load(page, timeout_ms=1800)
                        continue

                    if manual_v2_login_flow_started and manual_v2_phone_entry_clicked and not manual_v2_login_phone_submitted:
                        _extend_manual_v2_deadline(1800)
                        if not _is_manual_v2_login_phone_input_stage(current_url, body_text, page):
                            if (
                                _is_add_email_page(current_url, body_text, page)
                                or _is_otp_page(current_url, body_text, page)
                                or _is_login_with_bridge_page(current_url, body_text)
                            ):
                                manual_v2_wait_phone_logged = False
                            _sleep_with_page(page, 300)
                            continue
                        phone_input = _first_visible_locator(
                            page,
                            [
                                'input[id="phoneNumberInput"]',
                                'input[name="phoneNumberInput"]',
                                'input[type="tel"]',
                                'input[inputmode="tel"]',
                                'input[name*="phone" i]',
                                'input[autocomplete="tel"]',
                                'input[placeholder*="phone" i]',
                                'input[aria-label*="phone" i]',
                            ],
                        )
                        if phone_input is not None:
                            if not manual_v2_phone_number:
                                manual_v2_phone_number = _extract_input_value_by_hints(
                                    page,
                                    ["phone", "mobile", "手机号", "电话", "tel"],
                                )
                            if not manual_v2_phone_number:
                                if manual_v2_auto_phone_mode:
                                    manual_v2_phone_number = _ensure_manual_v2_auto_phone(
                                        step="create_email",
                                        prompt=f"浏览器模式2 当前位于第二步手机号输入页，准备复用本轮 {manual_v2_auto_phone_provider_label} 手机号自动继续登录...",
                                    )
                                if not manual_v2_wait_phone_logged or manual_v2_wait_phone_last_url != current_url:
                                    manual_v2_wait_phone_logged = True
                                    manual_v2_wait_phone_last_url = current_url
                                    emitter.info(
                                        (
                                            "浏览器模式2 当前位于第二步手机号输入页，请在任务控制卡片中提交手机号，程序会自动继续登录..."
                                            if manual_v2_phone_panel_input_mode
                                            else "浏览器模式2 当前位于手机号输入页，正等待读取你已输入的手机号，再自动提交登录..."
                                        ),
                                        step="create_email",
                                    )
                                if manual_v2_phone_panel_input_mode:
                                    manual_v2_phone_number = _wait_manual_v2_phone_input(
                                        step="create_email",
                                        prompt="模式2第二步登录需要手机号，请输入与注册相同的手机号。",
                                    )
                                elif manual_v2_auto_phone_mode and manual_v2_phone_number:
                                    pass
                                else:
                                    _sleep_with_page(page, 800)
                                    continue
                            manual_v2_wait_phone_logged = False
                            manual_v2_wait_phone_last_url = current_url
                            if not _submit_manual_v2_phone_input(page, manual_v2_phone_number, step="create_email"):
                                raise RuntimeError("浏览器模式2 提交手机号失败")
                            manual_v2_login_phone_submitted = True
                            manual_v2_post_login_pending_email = False
                            manual_v2_bridge_entered_at = 0.0
                            manual_v2_bridge_logged = False
                            manual_v2_post_login_recover_attempts = 0
                            manual_v2_post_login_retryable_error_attempts = 0
                            emitter.info("浏览器模式2 已提交手机号，等待密码页...", step="create_email")
                            _post_phone_url, _post_phone_body = _wait_for_manual_v2_login_phone_submit_transition(
                                previous_url,
                                previous_body,
                                timeout_ms=12000,
                            )
                            emitter.info(
                                f"浏览器模式2 提交手机号后落点: {_mask_secret(_post_phone_url, head=64, tail=12)}",
                                step="create_email",
                            )
                            continue

                    if manual_v2_login_flow_started and not email_submitted and _is_add_email_page(current_url, body_text, page):
                        _extend_manual_v2_deadline(1800)
                        manual_v2_post_login_pending_email = False
                        manual_v2_bridge_entered_at = 0.0
                        manual_v2_bridge_logged = False
                        manual_v2_email_verification_logged = False
                        if manual_v2_manual_email_mode:
                            emitter.info("浏览器模式2 已进入 add-email 页面，等待你手动提供本次要绑定的邮箱...", step="create_email")
                            manual_email = _wait_manual_v2_email_input(
                                step="create_email",
                                prompt="模式2第二步需要绑定邮箱，请输入你这次要补绑的邮箱地址。",
                            )
                            if not manual_email or "@" not in manual_email:
                                raise RuntimeError("浏览器模式2 手动邮箱输入为空或格式不正确")
                            ctx.email = manual_email.strip()
                        emitter.info(f"浏览器模式2 已进入 add-email 页面，准备绑定邮箱: {ctx.email}", step="create_email")
                        emitter.info(
                            "进入 add-email 前会话诊断: cookies="
                            + _browser_cookie_presence_summary(context),
                            step="create_email",
                        )
                        emitter.info(
                            "浏览器模式2 add-email 页面开始等待输入框稳定: "
                            + _summarize_add_email_probe(page),
                            step="create_email",
                        )
                        if not _wait_for_add_email_ready(page, timeout_ms=12000):
                            emitter.warn(
                                "浏览器模式2 add-email ready 探针诊断: "
                                + _summarize_add_email_probe(page)
                                + ", actions="
                                + _summarize_primary_actions(page)
                                + f", body={_preview_text(_describe_page(page, force_refresh=True)[1], 220) or '-'}",
                                step="create_email",
                            )
                            raise RuntimeError(
                                "浏览器模式2 add-email 页面未稳定就绪: "
                                + _summarize_primary_actions(page)
                            )
                        current_url, body_text = _describe_page(page, force_refresh=True)
                        if not _is_add_email_page(current_url, body_text, page):
                            emitter.info(
                                "浏览器模式2 add-email 等待期间页面已自然跳转，改由主循环接管后续阶段: "
                                + f"url={_mask_secret(current_url, head=56, tail=12)}, "
                                + f"page_state={_classify_page_state(current_url, body_text, page)}, "
                                + f"body={_preview_text(body_text, 220) or '-'}",
                                step="create_email",
                            )
                            continue
                        emitter.info(
                            "浏览器模式2 add-email 输入框已稳定，准备填写邮箱..."
                            + f" probe={_summarize_add_email_probe(page)}",
                            step="create_email",
                        )
                        fill_ok, filled_value = _fill_add_email_input(page, ctx.email)
                        emitter.info(
                            "浏览器模式2 add-email 邮箱写入结果: "
                            + ("成功" if fill_ok else "失败")
                            + f", expected={ctx.email}, actual={_preview_text(filled_value, 80) or '-'}",
                            step="create_email",
                        )
                        if not fill_ok:
                            emitter.warn(
                                "浏览器模式2 add-email 写入失败诊断: "
                                + _summarize_add_email_probe(page)
                                + ", actions="
                                + _summarize_primary_actions(page),
                                step="create_email",
                            )
                            raise RuntimeError("浏览器模式2 在 add-email 页面填写邮箱失败")
                        previous_url = current_url
                        previous_body = body_text
                        emitter.info(
                            "浏览器模式2 add-email 准备点击 Continue: actions="
                            + _summarize_primary_actions(page),
                            step="create_email",
                        )
                        submit_ok = _submit_add_email_continue(page)
                        emitter.info(
                            "浏览器模式2 add-email Continue 点击结果: "
                            + ("成功" if submit_ok else "失败"),
                            step="create_email",
                        )
                        if not submit_ok:
                            emitter.warn(
                                "浏览器模式2 add-email 提交失败诊断: "
                                + _summarize_add_email_probe(page)
                                + ", actions="
                                + _summarize_primary_actions(page),
                                step="create_email",
                            )
                            raise RuntimeError("浏览器模式2 在 add-email 页面提交邮箱失败")
                        email_submitted = True
                        current_url, body_text = _wait_for_page_stabilize(
                            previous_url,
                            previous_body,
                            step="create_email",
                            action_label="add-email 邮箱已提交",
                            timeout_ms=12000,
                        )
                        emitter.info(
                            "浏览器模式2 add-email 提交后落点: "
                            + f"url={_mask_secret(current_url, head=56, tail=12)}, "
                            + f"page_state={_classify_page_state(current_url, body_text, page)}, "
                            + f"body={_preview_text(body_text, 220) or '-'}",
                            step="create_email",
                        )
                        continue

                    if manual_v2_waiting_phone_retry:
                        _extend_manual_v2_deadline(1800)
                        if _is_phone_input_page(current_url, body_text, page) or _is_phone_verification_page(current_url, body_text, page):
                            manual_v2_waiting_phone_retry = False
                            manual_v2_waiting_phone_retry_logged = False
                            manual_v2_wait_phone_logged = False
                            manual_v2_phone_number = ""
                            manual_v2_require_phone_resubmit = True
                            emitter.info(
                                "浏览器模式2 已回到手机号输入阶段，你可以重新输入别的手机号；提交后程序会再次自动填写密码。",
                                step="add_phone",
                            )
                            _sleep_with_page(page, 600)
                            continue
                        if _is_create_account_password_page(current_url, body_text, page):
                            if not manual_v2_waiting_phone_retry_logged:
                                manual_v2_waiting_phone_retry_logged = True
                                emitter.info(
                                    "浏览器模式2 当前停留在设置密码页，等待你决定是否继续回退到手机号页...",
                                    step="add_phone",
                                )
                            _sleep_with_page(page, 800)
                            continue

                    if manual_v2_require_phone_resubmit:
                        _extend_manual_v2_deadline(1800)
                        if _is_create_account_password_page(current_url, body_text, page):
                            manual_v2_require_phone_resubmit = False
                            manual_v2_wait_phone_logged = False
                            password_submitted = False
                            emitter.info(
                                "浏览器模式2 已重新回到设置密码页，恢复自动填写密码流程...",
                                step="create_password",
                            )
                            continue
                        if _is_phone_input_page(current_url, body_text, page) or _is_phone_verification_page(current_url, body_text, page):
                            if not manual_v2_wait_phone_logged:
                                manual_v2_wait_phone_logged = True
                                emitter.info(
                                    "浏览器模式2 正等待你重新输入并提交手机号；只有重新回到设置密码页后，程序才会再次自动填写密码。",
                                    step="add_phone",
                                )
                            _sleep_with_page(page, 800)
                            continue

                    if (
                        password_submitted
                        and not manual_v2_login_flow_started
                        and not _is_contact_verification_page(current_url, body_text, page)
                    ):
                        refreshed_url, refreshed_body = _describe_page(page, force_refresh=True)
                        deep_wait_body = _get_page_deep_text(page)
                        current_url = refreshed_url
                        current_url_lower = str(current_url or "").lower()
                        if str(deep_wait_body or "").strip():
                            body_text = str(deep_wait_body or "")
                        else:
                            body_text = refreshed_body
                        if _is_create_account_failed_error(current_url, body_text, page):
                            password_submitted = False
                            manual_v2_password_page_logged = False
                            manual_v2_create_password_submit_attempts = 0
                            if manual_v2_auto_phone_mode:
                                _finish_manual_v2_sms_provider(success=False)
                                manual_v2_phone_number = ""
                                manual_v2_sms_activation_id = ""
                                manual_v2_sms_purchased_at = 0.0
                                manual_v2_sms_provider_done = False
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 密码提交后等待后续页面时，站点已出现 Failed to create account；"
                                    + f"已立即废弃本轮 {manual_v2_auto_phone_provider_label} 号码并回到步骤1重新取号..."
                                )
                            else:
                                _prepare_manual_v2_signup_flow(
                                    "浏览器模式2 密码提交后等待后续页面时，站点已出现 Failed to create account；"
                                    + "回到步骤1重新输入新的手机号..."
                                )
                            continue
                        if _is_retryable_error_page(current_url, body_text):
                            if _try_recover_timeout_error_page(
                                current_url,
                                body_text,
                                step="create_password",
                                action_label="密码提交后的等待阶段已命中错误页，已触发当前页重试",
                                timeout_ms=12000,
                            ):
                                current_url, body_text = _describe_page(page, force_refresh=True)
                                continue
                        if _is_create_account_password_page(current_url, body_text, page):
                            if _has_recent_challenge_network(recent_network_events, within_seconds=10.0):
                                wait_key = current_url + "#challenge-wait"
                                if not manual_v2_wait_phone_logged or manual_v2_wait_phone_last_url != wait_key:
                                    manual_v2_wait_phone_logged = True
                                    manual_v2_wait_phone_last_url = wait_key
                                    emitter.info(
                                        "浏览器模式2 密码提交后当前仍停留在 create-account/password，且 challenge 网络活动仍在继续；"
                                        + "先继续等待，不切到短信验证码阶段...",
                                        step="create_password",
                                    )
                                _wait_for_load(page, timeout_ms=1800)
                                _sleep_with_page(page, 500)
                                continue
                            recent_register_request = _has_recent_network_url(
                                recent_network_events,
                                "api/accounts/user/register",
                                within_seconds=20.0,
                            )
                            recent_phone_otp_send = _has_recent_network_url(
                                recent_network_events,
                                "api/accounts/phone-otp/send",
                                within_seconds=20.0,
                            )
                            hero_sms_code_ready = bool(manual_v2_cached_sms_code)
                            if recent_register_request or recent_phone_otp_send or hero_sms_code_ready:
                                if hero_sms_code_ready:
                                    manual_v2_contact_seen = True
                                    manual_v2_contact_network_seen = True
                                    manual_v2_contact_transition_last_key = ""
                                    manual_v2_waiting_phone_retry = False
                                    manual_v2_waiting_phone_retry_logged = False
                                    manual_v2_require_phone_resubmit = False
                                    manual_v2_wait_phone_logged = False
                                    manual_v2_wait_phone_last_url = ""
                                    emitter.info(
                                        f"浏览器模式2 密码提交后 {manual_v2_auto_phone_provider_label} 已提前收到验证码，"
                                        + "不再继续等待页面切换，直接进入短信验证码处理阶段...",
                                        step="phone_verification",
                                    )
                                    continue
                                wait_key = current_url + "#register-send-wait"
                                if not manual_v2_wait_phone_logged or manual_v2_wait_phone_last_url != wait_key:
                                    manual_v2_wait_phone_logged = True
                                    manual_v2_wait_phone_last_url = wait_key
                                    emitter.info(
                                        "浏览器模式2 密码提交后已检测到注册/发码网络请求，当前即使仍停留在 create-account/password，"
                                        + "也先继续等待站点完成短信验证码页切换...",
                                        step="create_password",
                                    )
                                _wait_for_load(page, timeout_ms=1200)
                                _sleep_with_page(page, 250)
                                continue
                            password_submitted = False
                            manual_v2_password_page_logged = False
                            manual_v2_wait_phone_logged = False
                            emitter.warn(
                                "浏览器模式2 密码提交后仍停留在 create-account/password，未进入短信验证码阶段；"
                                + "恢复到密码页诊断分支继续处理...",
                                step="create_password",
                            )
                            continue
                        _extend_manual_v2_deadline(1800)
                        if current_url:
                            wait_key = current_url + "#wait-phone-verification"
                            if not manual_v2_wait_phone_logged or manual_v2_wait_phone_last_url != wait_key:
                                manual_v2_wait_phone_logged = True
                                manual_v2_wait_phone_last_url = wait_key
                                emitter.info(
                                    "浏览器模式2 密码已提交，当前等待进入短信验证码页，当前页面: "
                                    + _mask_secret(current_url, head=56, tail=12),
                                    step="phone_verification",
                                )
                        _sleep_with_page(page, 250)
                        continue

                if (
                    not is_manual_v2_mode
                    and _is_phone_verification_page(current_url, body_text, page)
                ) or (
                    is_manual_mode and _is_phone_flow_page(current_url, body_text)
                ):
                    if is_manual_mode:
                        emitter.info(
                            "检测到手机验证页面，请在浏览器窗口手动完成手机号验证...",
                            step="add_phone",
                        )
                        deadline = max(deadline, time.time() + 600)
                        while not _stopped(ctx.stop_event) and time.time() < deadline:
                            active_page = _resolve_active_page(page, timeout_ms=2500)
                            if active_page is None:
                                if _scan_context_pages_for_callback():
                                    emitter.success("手机验证已完成，继续流程...", step="add_phone")
                                    break
                                _sleep_with_page(None, 1000)
                                continue
                            _wait_for_load(page, timeout_ms=2000)
                            new_url, new_body = _describe_page(page)
                            new_url_lower = str(new_url or "").lower()
                            callback_candidate = _extract_callback_url_from_page(new_url, new_body)
                            if callback_candidate and not callback_state["url"]:
                                _record_callback(callback_candidate)
                            if _is_retryable_error_page(new_url, new_body):
                                if _try_recover_timeout_error_page(
                                    new_url,
                                    new_body,
                                    step="phone_verification",
                                    action_label="手机验证码页错误已触发当前页重试",
                                    timeout_ms=12000,
                                ):
                                    _sleep_with_page(page, 800)
                                    continue
                            if _is_contact_verification_page(new_url, new_body, page):
                                if _manual_contact_verification_ready(page):
                                    if _click_primary_action(
                                        page,
                                        ["Continue", "Verify", "Submit", "Validate", "继续", "下一步"],
                                        allow_generic_fallback=True,
                                    ):
                                        emitter.info(
                                            "检测到你已填好手机验证码，已自动点击 Continue/Validate 继续...",
                                            step="phone_verification",
                                        )
                                        _wait_for_load(page, timeout_ms=2000)
                                        _sleep_with_page(page, 600)
                                        continue
                                _sleep_with_page(page, 800)
                                continue
                            phone_done = False
                            if callback_state["url"] or _scan_context_pages_for_callback():
                                phone_done = True
                            elif "chatgpt.com" in new_url_lower:
                                phone_done = True
                            elif "code=" in new_url_lower and "state=" in new_url_lower:
                                phone_done = True
                            elif any(kw in new_url_lower for kw in ("consent", "workspace", "organization")):
                                phone_done = True
                            elif _is_profile_page(new_url, new_body):
                                phone_done = True
                            elif _is_create_account_password_page(new_url, new_body, page):
                                phone_done = True
                            elif _is_add_email_page(new_url, new_body, page):
                                phone_done = True
                            elif _is_otp_page(new_url, new_body, page):
                                phone_done = True
                            if phone_done:
                                emitter.success("手机验证已完成，继续流程...", step="add_phone")
                                break
                            _sleep_with_page(page, 2000)
                        continue
                    if current_phase != "login":
                        login_add_phone_retry_attempts = 0
                        _restart_current_page_oauth_flow(
                            target_phase="login",
                            reason="浏览器注册流程进入手机号验证页面，改为在当前页面重新登录以继续获取 Token",
                        )
                        continue
                    if login_add_phone_retry_attempts < login_add_phone_retry_limit:
                        login_add_phone_retry_attempts += 1
                        _restart_current_page_oauth_flow(
                            target_phase="login",
                            reason=(
                                "浏览器二次登录后仍进入手机号验证页面，"
                                + f"准备第 {login_add_phone_retry_attempts}/{login_add_phone_retry_limit} 次重新登录重试..."
                            ),
                        )
                        continue
                    raise BrowserPhoneVerificationRequiredError(
                        "浏览器流程进入手机号验证页面，且二次登录重试仍未绕过",
                        page_type="add_phone",
                        continue_url=current_url,
                        final_url=current_url,
                    )

                if "code=" in current_url_lower and "state=" in current_url_lower:
                    _record_callback(current_url)
                    continue

                if (not otp_route_locked) and _click_first(
                    page,
                    [
                        'button:has-text("Continue with password")',
                        '[role="button"]:has-text("Continue with password")',
                        'text="Continue with password"',
                    ],
                    timeout_ms=1000,
                ):
                    emitter.info("检测到 Continue with password，优先切换到密码直通链路", step="create_password")
                    _wait_for_load(page)
                    continue

                if (
                    not otp_route_locked
                    and
                    not email_submitted
                    and not is_manual_v2_mode
                    and _first_visible_locator(
                        page,
                        [
                            'input[type="email"]',
                            'input[name="email"]',
                            'input[name*="username" i]',
                        ],
                    )
                    is not None
                ):
                    emitter.info(
                        f"浏览器正在填写{'登录' if current_phase == 'login' else '注册'}邮箱: {ctx.email}",
                        step="create_email",
                    )
                    if not _fill_first(
                        page,
                        [
                            'input[type="email"]',
                            'input[name="email"]',
                            'input[name*="username" i]',
                        ],
                        ctx.email,
                    ):
                        raise RuntimeError("浏览器模式填写邮箱失败")
                    previous_url = current_url
                    previous_body = body_text
                    if not _click_primary_action(
                        page,
                        ["Continue", "Next", "Log in", "Sign in", "继续", "下一步", "登录", "Sign up", "Create account"],
                    ):
                        raise RuntimeError("浏览器模式提交邮箱失败")
                    email_submitted = True
                    _wait_for_page_stabilize(
                        previous_url,
                        previous_body,
                        step="create_email",
                        action_label="邮箱提交完成",
                        timeout_ms=12000,
                    )
                    continue

                if (
                    not otp_route_locked
                    and
                    not password_submitted
                    and not (is_manual_v2_mode and manual_v2_waiting_phone_retry)
                    and not (
                        is_manual_v2_mode
                        and manual_v2_require_phone_resubmit
                        and not _is_create_account_password_page(current_url, body_text, page)
                    )
                    and (
                        not is_manual_v2_mode
                        or manual_v2_oauth_resumed
                        or manual_v2_login_phone_submitted
                        or "/create-account/password" in current_url_lower
                    )
                    and _first_visible_locator(
                        page,
                        [
                            'input[type="password"]',
                            'input[name="password"]',
                            'input[name="new-password"]',
                            'input[autocomplete="new-password"]',
                        ],
                    )
                    is not None
                ):
                    emitter.info(
                        "浏览器正在"
                        + ("输入登录密码..." if current_phase == "login" else "设置密码...")
                        + f" 本次密码: {ctx.account_password}",
                        step="create_password",
                    )
                    if not _fill_first(page, ['input[type="password"]', 'input[name="password"]'], ctx.account_password):
                        if not _fill_first(
                            page,
                            [
                                'input[type="password"]',
                                'input[name="password"]',
                                'input[name="new-password"]',
                                'input[autocomplete="new-password"]',
                                'input[id*="password" i]',
                            ],
                            ctx.account_password,
                        ):
                            raise RuntimeError("浏览器模式填写密码失败")
                    previous_url = current_url
                    previous_body = body_text
                    if not _click_primary_action(
                        page,
                        ["Continue", "Next", "Log in", "Sign in", "Create account", "Sign up", "继续", "登录", "完成"],
                    ):
                        raise RuntimeError("浏览器模式提交密码失败")
                    password_submitted = True
                    if (
                        is_manual_v2_mode
                        and manual_v2_login_flow_started
                        and current_phase == "login"
                        and not manual_v2_profile_completion_mode
                    ):
                        manual_v2_post_login_pending_email = True
                        manual_v2_bridge_entered_at = 0.0
                        manual_v2_bridge_logged = False
                        manual_v2_post_login_recover_attempts = 0
                        manual_v2_post_login_retryable_error_attempts = 0
                    emitter.info(
                        ("浏览器登录密码已提交，密码: " if current_phase == "login" else "浏览器注册密码已提交，密码: ")
                        + ctx.account_password,
                        step="create_password",
                    )
                    if (
                        is_manual_v2_mode
                        and manual_v2_login_flow_started
                        and current_phase == "login"
                        and manual_v2_profile_completion_mode
                    ):
                        emitter.info(
                            "浏览器模式2 补资料登录密码已提交，当前仅等待站点进入 about-you / ChatGPT 主页；"
                            + "此阶段不绑定邮箱，也不进入步骤2 OAuth。",
                            step="create_account",
                        )
                        emitter.info(
                            "补资料阶段密码提交后会话诊断: cookies="
                            + _browser_cookie_presence_summary(context)
                            + f", current_url={_mask_secret(current_url, head=56, tail=12)}",
                            step="create_account",
                        )
                    elif is_manual_v2_mode and manual_v2_login_flow_started and current_phase == "login":
                        emitter.info(
                            "浏览器模式2 第二步登录密码已提交，当前优先等待 add-email / email-verification，暂不重拉 OAuth...",
                            step="create_email",
                        )
                        emitter.info(
                            "当前阶段仅等待页面从密码页跳到 add-email / email-verification；邮箱验证码轮询会在进入 email-verification 页面后才启动。",
                            step="create_email",
                        )
                        emitter.info(
                            "第二步密码提交后会话诊断: cookies="
                            + _browser_cookie_presence_summary(context)
                            + f", current_url={_mask_secret(current_url, head=56, tail=12)}",
                            step="create_email",
                        )
                    _wait_for_page_stabilize(
                        previous_url,
                        previous_body,
                        step="create_password",
                        action_label=("登录密码已提交" if current_phase == "login" else "注册密码已提交"),
                        timeout_ms=20000,
                    )
                    continue

                need_profile = (
                    (not otp_route_locked)
                    and _is_profile_page(current_url, body_text)
                    and ((not is_manual_v2_mode) or manual_v2_login_flow_started)
                )
                if need_profile and not profile_submitted:
                    if is_manual_v2_mode and manual_v2_login_flow_started:
                        emitter.info(
                            "浏览器模式2 第二步登录后，站点再次进入 about-you 资料页；"
                            + "这说明当前账号在真正补邮箱前仍被要求补资料，程序继续复用资料填写流程。"
                            + f" url={_mask_secret(current_url, head=56, tail=12)}",
                            step="create_account",
                        )
                    else:
                        emitter.info("浏览器正在补充账户资料...", step="create_account")
                    emitter.info(
                        f"浏览器本次资料: name={ctx.profile_name}, birthdate={ctx.profile_birthdate}, age={_derive_profile_age(ctx.profile_birthdate)}",
                        step="create_account",
                    )
                    profile_ok, profile_mode = _fill_about_you_profile(page, ctx)
                    if not profile_ok and profile_mode == "name":
                        raise RuntimeError("浏览器模式填写姓名失败")
                    if not profile_ok and profile_mode in {"birthdate", "age"}:
                        emitter.warn(
                            "浏览器 about-you 年龄/生日控件诊断: " + _summarize_about_you_controls(page),
                            step="create_account",
                        )
                        raise RuntimeError("浏览器模式填写年龄/生日失败")
                    if not profile_ok and profile_mode == "checkbox":
                        emitter.warn(
                            "浏览器 about-you 勾选控件诊断: " + _summarize_about_you_controls(page),
                            step="create_account",
                        )
                        raise RuntimeError("浏览器模式勾选 about-you 同意项失败")
                    previous_url = current_url
                    previous_body = body_text
                    finish_result = _submit_about_you_finish_with_terms_retry(
                        page,
                        ctx,
                        max_attempts=3,
                        settle_ms=800,
                    )
                    if finish_result.get("terms_retried"):
                        emitter.warn(
                            "浏览器 about-you 出现 Terms of Use 红色提示，"
                            + f"未重填资料，已直接再点 Finish creating account（共 {finish_result.get('attempts') or 0} 次）...",
                            step="create_account",
                        )
                    if not finish_result.get("clicked"):
                        raise RuntimeError("浏览器模式提交账户资料失败：未点到 Finish creating account")
                    current_url = str(finish_result.get("url") or current_url)
                    body_text = str(finish_result.get("body") or body_text)
                    if _about_you_form_still_visible(current_url, body_text, page):
                        if _is_about_you_terms_soft_error(current_url, body_text, page):
                            emitter.warn(
                                "浏览器 about-you 多次直接点击 Finish 后仍显示 Terms 红字，"
                                + "本轮不结束资料页；下一轮继续只点 Finish，不重填...",
                                step="create_account",
                            )
                            _sleep_with_page(page, 800)
                            continue
                        current_url, body_text = _wait_for_page_stabilize(
                            previous_url,
                            previous_body,
                            step="create_account",
                            action_label="账户资料已提交",
                            timeout_ms=12000,
                        )
                        if _about_you_form_still_visible(current_url, body_text, page):
                            emitter.warn(
                                "浏览器 about-you 提交后仍停留在资料页，暂不标记完成，下一轮重试..."
                                + f" current_url={_mask_secret(current_url, head=72, tail=18)}",
                                step="create_account",
                            )
                            continue
                    profile_submitted = True
                    if is_manual_v2_mode and _is_about_you_missing_email_error(current_url, body_text):
                        if manual_v2_profile_completion_mode:
                            emitter.warn(
                                "浏览器模式2 reset-password 后的补资料流程在 about-you 提交后命中 authentication missing_email，"
                                + "不在此阶段绑定邮箱，直接切入真正的步骤2 OAuth 补邮箱链路...",
                                step="create_email",
                            )
                            manual_v2_profile_completion_mode = False
                            manual_v2_post_login_pending_email = False
                            manual_v2_bridge_entered_at = 0.0
                            manual_v2_bridge_logged = False
                            manual_v2_post_login_recover_attempts = 0
                            manual_v2_post_login_retryable_error_attempts = 0
                            manual_v2_email_verification_logged = False
                            email_submitted = False
                            _prepare_manual_v2_login_flow(
                                "浏览器模式2 reset-password 后的补资料阶段已结束，"
                                + "现在进入真正的步骤2 OAuth 获取 Token / 绑定邮箱流程..."
                            )
                            continue
                        emitter.warn(
                            "浏览器模式2 about-you 提交后命中 authentication missing_email，"
                            + "改为回到 ChatGPT 首页复用已保存手机号与密码重新登录，继续补资料/补邮箱链路...",
                            step="create_email",
                        )
                        manual_v2_post_login_pending_email = False
                        manual_v2_bridge_entered_at = 0.0
                        manual_v2_bridge_logged = False
                        manual_v2_post_login_recover_attempts = 0
                        manual_v2_post_login_retryable_error_attempts = 0
                        manual_v2_email_verification_logged = False
                        email_submitted = False
                        _prepare_manual_v2_login_flow(
                            "浏览器模式2 about-you 提交后命中 authentication missing_email，"
                            + "现在回到 ChatGPT 首页，复用已保存手机号与密码重新登录并继续补资料/补邮箱...",
                            profile_completion_only=True,
                        )
                        continue
                    # about-you 成功后常见 “You're all set”：必须点完 Continue 再结束补资料分流。
                    if is_manual_v2_mode:
                        all_set = _pass_youre_all_set_page(
                            page,
                            emitter=emitter,
                            step="create_account",
                            max_attempts=6,
                            settle_ms=700,
                            wait_appear_ms=3500,
                        )
                        try:
                            current_url = str(all_set.get("url") or current_url)
                            body_text = str(all_set.get("body") or body_text)
                        except Exception:
                            pass
                        if all_set.get("was_page") and not all_set.get("left"):
                            emitter.warn(
                                "浏览器模式2 about-you 提交后仍停在 You're all set，下一轮继续点 Continue...",
                                step="create_account",
                            )
                            continue
                        if (not all_set.get("left")) and (not all_set.get("was_page")):
                            emitter.warn(
                                "浏览器模式2 about-you 提交后页面未离开资料/过渡态，下一轮重试...",
                                step="create_account",
                            )
                            continue
                        if _is_youre_all_set_page(current_url, body_text, page):
                            emitter.warn(
                                "浏览器模式2 仍检测到 You're all set，交给主循环继续点 Continue...",
                                step="create_account",
                            )
                            continue
                    if is_manual_v2_mode and manual_v2_profile_completion_mode:
                        emitter.success(
                            "浏览器模式2 登录后补资料（about-you）已完成，结束分流并进入真正的步骤2 OAuth 获取 Token...",
                            step="create_account",
                        )
                        manual_v2_profile_completion_mode = False
                        manual_v2_post_login_pending_email = False
                        manual_v2_bridge_entered_at = 0.0
                        manual_v2_bridge_logged = False
                        callback_state["url"] = ""
                        _prepare_manual_v2_login_flow(
                            "浏览器模式2 补资料分流已结束，现在进入真正的步骤2 OAuth 获取 Token / 绑定邮箱流程..."
                        )
                    continue

                if (
                    is_manual_v2_mode
                    and manual_v2_login_flow_started
                    and not email_submitted
                    and "email-verification" in current_url_lower
                ):
                    # 检测页面上的目标邮箱是否是我们的临时邮箱
                    # 如果不是，检查其域名是否属于我们 mail_provider 配置的 custom_domains
                    # 属于 → 切换到旧邮箱继续取验证码；不属于 → 注册失败
                    _page_shown_email = ""
                    try:
                        _email_match = re.search(
                            r"sent\s+to\s+([a-zA-Z0-9_.+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})",
                            body_text,
                            re.IGNORECASE,
                        )
                        if _email_match:
                            _page_shown_email = _email_match.group(1).strip().lower()
                    except Exception:
                        pass
                    if manual_v2_manual_email_mode:
                        if _page_shown_email:
                            ctx.email = _page_shown_email
                        email_submitted = True
                        manual_v2_post_login_pending_email = False
                        manual_v2_bridge_entered_at = 0.0
                        manual_v2_bridge_logged = False
                        emitter.info(
                            "浏览器模式2 第二步登录后已直接进入 email-verification；当前为手动邮箱模式，"
                            + "直接接管页面显示的目标邮箱并等待你手动输入邮箱验证码...",
                            step="send_otp",
                        )
                        continue
                    _our_email = str(ctx.email or "").strip().lower()
                    if _page_shown_email and _our_email and _page_shown_email != _our_email:
                        # 收集 mail_provider 的所有 custom_domains
                        _managed_domains: set[str] = set()
                        try:
                            _mp = ctx.mail_provider
                            if _mp is not None:
                                # 直接是 MailTmForwardProvider
                                if hasattr(_mp, "custom_domains") and _mp.custom_domains:
                                    _managed_domains.update(str(d).strip().lower() for d in _mp.custom_domains if d)
                                # MultiMailRouter: 遍历内部 provider
                                if hasattr(_mp, "_providers") and isinstance(_mp._providers, dict):
                                    for _sub_p in _mp._providers.values():
                                        if hasattr(_sub_p, "custom_domains") and _sub_p.custom_domains:
                                            _managed_domains.update(str(d).strip().lower() for d in _sub_p.custom_domains if d)
                        except Exception:
                            pass
                        _shown_domain = _page_shown_email.split("@", 1)[-1] if "@" in _page_shown_email else ""
                        if _shown_domain and _shown_domain in _managed_domains:
                            # 旧邮箱域名是我们配置的自定义域名，切换到旧邮箱继续取验证码
                            emitter.info(
                                f"浏览器模式2 第二步登录后直接进入 email-verification，"
                                f"页面目标邮箱 ({_page_shown_email}) 不是本次临时邮箱但属于我们的自定义域名 ({_shown_domain})，"
                                f"切换为旧邮箱继续取验证码...",
                                step="send_otp",
                            )
                            ctx.email = _page_shown_email
                        else:
                            raise RuntimeError(
                                f"浏览器模式2 第二步登录后直接进入 email-verification，"
                                f"但页面显示的目标邮箱 ({_page_shown_email}) 不是本次临时邮箱 ({_our_email})，"
                                f"且域名不属于已配置的自定义域名，说明该手机号已绑定外部邮箱，无法继续注册"
                            )
                    email_submitted = True
                    manual_v2_post_login_pending_email = False
                    manual_v2_bridge_entered_at = 0.0
                    manual_v2_bridge_logged = False
                    emitter.info(
                        "浏览器模式2 检测到页面已直接进入 email-verification，自动同步为\u201c邮箱已提交\u201d状态，继续进入验证码阶段...",
                        step="send_otp",
                    )
                otp_visible = _is_otp_page(current_url, body_text, page)
                if is_manual_v2_mode and (not manual_v2_login_flow_started or not email_submitted):
                    otp_visible = False
                if (
                    not is_manual_v2_mode
                    and email_submitted
                    and "/create-account" in current_url_lower
                    and "/create-account/password" not in current_url_lower
                    and _first_visible_locator(
                        page,
                        [
                            'input[type="email"]',
                            'input[name="email"]',
                            'input[name*="username" i]',
                        ],
                    ) is not None
                ):
                    email_submitted = False
                    password_submitted = False
                    emitter.warn(
                        "浏览器流程检测到页面已回退到注册邮箱输入页，自动撤销“邮箱已提交”状态并重新继续填写邮箱...",
                        step="create_email",
                    )
                if (
                    is_manual_v2_mode
                    and manual_v2_login_flow_started
                    and email_submitted
                    and _is_add_email_page(current_url, body_text, page)
                ):
                    emitter.warn(
                        "浏览器模式2 add-email 已提交但页面仍停留在 add-email，继续观察下一轮页面变化..."
                        + f" url={_mask_secret(current_url, head=56, tail=12)}, "
                        + "probe="
                        + _summarize_add_email_probe(page)
                        + ", actions="
                        + _summarize_primary_actions(page),
                        step="create_email",
                    )
                    _wait_for_load(page, timeout_ms=1200)
                    _sleep_with_page(page, 600)
                    continue
                if (
                    is_manual_v2_mode
                    and manual_v2_login_flow_started
                    and email_submitted
                    and _is_email_verification_invalid_state_page(current_url, body_text)
                ):
                    if manual_v2_email_verification_recover_attempts >= 2:
                        raise RuntimeError(
                            "浏览器模式2 email-verification 页面连续命中 invalid_state，自动恢复仍失败"
                        )
                    manual_v2_email_verification_recover_attempts += 1
                    manual_v2_email_verification_logged = False
                    otp_wait_started = False
                    otp_page_ready_logged = False
                    otp_initial_send_triggered = False
                    email_submitted = False
                    emitter.warn(
                        "浏览器模式2 检测到 email-verification 页面进入 invalid_state 错误态，"
                        + f"开始第 {manual_v2_email_verification_recover_attempts}/2 次恢复：重新打开 add-email 刷新邮箱验证上下文。"
                        + " cookies="
                        + _browser_cookie_presence_summary(context)
                        + f", url={_mask_secret(current_url, head=56, tail=12)}"
                        + f", body={_preview_text(body_text, 220) or '-'}",
                        step="create_email",
                    )
                    page.goto(
                        "https://auth.openai.com/add-email",
                        wait_until="domcontentloaded",
                        timeout=cfg["browser_timeout_ms"],
                    )
                    _wait_for_load(page, timeout_ms=2500)
                    continue
                if otp_visible:
                    if is_manual_v2_mode and "email-verification" in current_url_lower:
                        manual_v2_post_login_pending_email = False
                        manual_v2_bridge_entered_at = 0.0
                        manual_v2_bridge_logged = False
                        if not manual_v2_email_verification_logged:
                            manual_v2_email_verification_logged = True
                            emitter.info(
                                "浏览器模式2 已进入 email-verification 页面，开始接管邮箱验证码流程..."
                                + f" body={_preview_text(body_text, 180) or '-'}",
                                step="send_otp",
                            )
                    if not _is_otp_page_ready(current_url, body_text, page):
                        if not otp_page_ready_logged:
                            emitter.info(
                                "浏览器已进入邮箱 OTP 路由，但页面仍在加载/渲染，等待验证码页面完全出现后再开始邮箱轮询...",
                                step="send_otp",
                            )
                            otp_page_ready_logged = True
                        _wait_for_load(page, timeout_ms=1200)
                        _sleep_with_page(page, 600)
                        continue
                    if not otp_wait_started:
                        if not otp_initial_send_triggered:
                            otp_initial_send_triggered = True
                            if (not is_manual_v2_mode) and _click_otp_resend(page):
                                emitter.info(
                                    "浏览器 OTP 页面已就绪，先主动触发一次验证码发送/重发，再开始邮箱轮询...",
                                    step="send_otp",
                                )
                                _wait_for_load(page, timeout_ms=1800)
                                _sleep_with_page(page, 900)
                                continue
                            if is_manual_v2_mode:
                                emitter.info(
                                    "浏览器模式2 在 email-verification 页面不再主动点击重发，先等待当前验证码邮件到达...",
                                    step="send_otp",
                                )
                        if manual_v2_manual_email_mode:
                            emitter.info("浏览器模式2 邮箱验证码页已就绪，等待你在任务控制卡片中手动提交邮箱验证码...", step="send_otp")
                        else:
                            emitter.info("浏览器流程进入邮箱 OTP 阶段，页面已就绪，开始轮询邮箱...", step="send_otp")
                        otp_wait_started = True
                    otp_page_ready_logged = False
                    current_wait_timeout = otp_wait_timeout_seconds
                    otp_code = ""
                    if manual_v2_manual_email_mode:
                        emitter.info(
                            "浏览器模式2 当前需要邮箱验证码，请在任务控制卡片中输入邮箱收到的 6 位验证码并提交...",
                            step="wait_otp",
                        )
                        otp_code = _wait_manual_v2_email_code(
                            step="wait_otp",
                            prompt=f"模式2当前正在验证邮箱 {ctx.email}，请输入该邮箱收到的验证码。",
                        )
                        if not otp_code:
                            raise RuntimeError("浏览器模式2 未收到手动输入的邮箱验证码")
                    else:
                        emitter.info(
                            f"浏览器正在等待邮箱 {ctx.email} 的验证码... "
                            + f"(timeout={current_wait_timeout}s, resend={otp_resend_attempts}/{otp_max_resend_attempts})",
                            step="wait_otp",
                        )
                        otp_code = _wait_for_mail_otp(
                            ctx,
                            timeout_seconds=current_wait_timeout,
                        )
                        if not otp_code:
                            if _schedule_otp_resend(
                                f"浏览器等待邮箱 OTP 超时（{current_wait_timeout}s）",
                                step="wait_otp",
                            ):
                                continue
                            raise RuntimeError("浏览器模式等待邮箱 OTP 超时，且重发验证码仍未成功收到新验证码")
                    submit_attempt_count = int(otp_code_submit_attempts.get(otp_code, 0) or 0)
                    if submit_attempt_count >= otp_same_code_retry_limit:
                        emitter.info(
                            f"浏览器收到重复 OTP，且同一验证码已尝试 {submit_attempt_count}/{otp_same_code_retry_limit} 次，继续等待新验证码: {otp_code}",
                            step="wait_otp",
                        )
                        time.sleep(1.0)
                        continue
                    otp_code_submit_attempts[otp_code] = submit_attempt_count + 1
                    tried_otp_codes.add(otp_code)
                    otp_resend_attempts = 0
                    if submit_attempt_count > 0:
                        emitter.info(
                            f"浏览器再次收到历史 OTP，准备第 {submit_attempt_count + 1}/{otp_same_code_retry_limit} 次提交: {otp_code}",
                            step="wait_otp",
                        )
                    else:
                        emitter.success(f"浏览器收到验证码: {otp_code}", step="wait_otp")
                    emitter.info(f"浏览器正在提交邮箱 OTP: {otp_code}", step="verify_otp")
                    emitter.info("浏览器正在等待 OTP 输入控件就绪...", step="verify_otp")
                    if not _wait_and_fill_otp(page, otp_code, timeout_seconds=10.0):
                        emitter.warn(
                            "浏览器 OTP 控件诊断: " + _summarize_otp_controls(page),
                            step="verify_otp",
                        )
                        raise RuntimeError("浏览器模式填写 OTP 失败")
                    fill_confirm_deadline = time.time() + 3.0
                    while time.time() < fill_confirm_deadline and not _otp_controls_match_code(page, otp_code):
                        _sleep_with_page(page, 180)
                    emitter.info(
                        "邮箱 OTP 已写入控件: "
                        + ("是" if _otp_controls_match_code(page, otp_code) else "否")
                        + "，controls="
                        + _summarize_otp_controls(page),
                        step="verify_otp",
                    )
                    emitter.info(
                        "邮箱 OTP 提交前诊断: "
                        + f"url={_mask_secret(current_url, head=56, tail=12)}, "
                        + "cookies="
                        + _browser_cookie_presence_summary(context)
                        + ", actions="
                        + _summarize_primary_actions(page)
                        + ", network="
                        + _summarize_recent_network_events(recent_network_events, limit=8),
                        step="verify_otp",
                    )
                    if is_manual_v2_mode:
                        api_result = _submit_email_otp_via_page_api(page, otp_code)
                        api_status = int(api_result.get("status") or 0)
                        api_text = str(api_result.get("text") or "")
                        api_json = api_result.get("json") if isinstance(api_result.get("json"), dict) else {}
                        api_continue_url = str(api_json.get("continue_url") or "").strip()
                        api_page_type = str(((api_json.get("page") or {}).get("type")) or "").strip()
                        emitter.info(
                            "浏览器模式2 OTP 接口直提结果: "
                            + f"status={api_status}, ok={'是' if api_result.get('ok') else '否'}, "
                            + f"page.type={api_page_type or '-'}, "
                            + f"continue_url={_mask_secret(api_continue_url, head=56, tail=12) if api_continue_url else '-'}, "
                            + f"body={_preview_text(api_text, 220) or '-'}",
                            step="verify_otp",
                        )
                        if api_result.get("ok"):
                            if api_continue_url:
                                try:
                                    page.goto(
                                        api_continue_url,
                                        wait_until="domcontentloaded",
                                        timeout=cfg["browser_timeout_ms"],
                                    )
                                except Exception as exc:
                                    emitter.warn(f"浏览器模式2 OTP 接口校验成功后跳转 continue_url 失败: {exc}", step="verify_otp")
                                _wait_for_load(page, timeout_ms=2500)
                            manual_v2_email_verification_recover_attempts = 0
                            manual_v2_email_otp_completed = True
                            continue
                    _sleep_with_page(page, random.randint(350, 850))
                    submit_clicked = False
                    submit_locator = _first_visible_locator(
                        page,
                        [
                            'button:has-text("Continue")',
                            '[role="button"]:has-text("Continue")',
                            'button:has-text("Verify")',
                            '[role="button"]:has-text("Verify")',
                            'button:has-text("Verify email")',
                            '[role="button"]:has-text("Verify email")',
                            'button:has-text("Submit")',
                            '[role="button"]:has-text("Submit")',
                            'button:has-text("Next")',
                            '[role="button"]:has-text("Next")',
                            'button:has-text("Confirm")',
                            '[role="button"]:has-text("Confirm")',
                            'button:has-text("继续")',
                            '[role="button"]:has-text("继续")',
                            'button:has-text("下一步")',
                            '[role="button"]:has-text("下一步")',
                        ],
                    )
                    if submit_locator is not None:
                        try:
                            submit_locator.click(timeout=1500)
                            submit_clicked = True
                        except Exception:
                            submit_clicked = False
                    if (not submit_clicked) and submit_locator is not None:
                        submit_clicked = _request_submit_with_button(submit_locator)
                    elif submit_locator is not None:
                        _sleep_with_page(page, 180)
                        submit_clicked = _request_submit_with_button(submit_locator) or submit_clicked
                    if (not submit_clicked) and (not is_manual_v2_mode):
                        submit_clicked = _click_primary_action(
                            page,
                            ["Continue", "Verify", "Verify email", "Submit", "Next", "Confirm", "下一步", "继续"],
                            allow_generic_fallback=False,
                        )
                    emitter.info(
                        f"浏览器 OTP 提交动作: {'已触发按钮/回车' if submit_clicked else '未找到明确提交动作，仅等待页面变化'}",
                        step="verify_otp",
                    )
                    post_otp_url, post_otp_body = _wait_for_page_stabilize(
                        current_url,
                        body_text,
                        step="verify_otp",
                        action_label="OTP 已提交",
                        timeout_ms=12000,
                    )
                    otp_transition_deadline = time.time() + 8
                    retriggered_submit = False
                    otp_post_submit_wait_logged = False
                    post_otp_resend_reason = ""
                    retrigger_submit_not_before = time.time() + 2.5
                    while time.time() < otp_transition_deadline:
                        _wait_for_load(page, timeout_ms=1200)
                        post_otp_url, post_otp_body = _describe_page(page)
                        post_otp_state = _classify_page_state(post_otp_url, post_otp_body, page)
                        if not post_otp_state.startswith("otp"):
                            break
                        if post_otp_state == "otp_loading":
                            if not otp_post_submit_wait_logged:
                                otp_post_submit_wait_logged = True
                                emitter.info("OTP 提交后页面仍在切换中，继续等待页面稳定...", step="verify_otp")
                            _sleep_with_page(page, 500)
                            continue
                        post_otp_body_lower = str(post_otp_body or "").lower()
                        if any(
                            hint in post_otp_body_lower
                            for hint in (
                                "invalid code",
                                "incorrect code",
                                "expired code",
                                "try again",
                                "wrong code",
                                "code is invalid",
                                "code is incorrect",
                                "code expired",
                                "verification failed",
                                "验证码无效",
                                "验证码错误",
                                "验证码已过期",
                                "验证失败",
                            )
                        ):
                            emitter.warn(
                                "OTP 提交后页面提示验证码可能无效或已过期，准备优先触发一次验证码重发...",
                                step="verify_otp",
                            )
                            post_otp_resend_reason = "OTP 提交后页面提示验证码无效/错误/已过期"
                            break
                        if time.time() < retrigger_submit_not_before:
                            if not otp_post_submit_wait_logged:
                                otp_post_submit_wait_logged = True
                                emitter.info("OTP 提交后页面仍在切换中，继续等待页面稳定...", step="verify_otp")
                            _sleep_with_page(page, 500)
                            continue
                        if is_manual_v2_mode:
                            _sleep_with_page(page, 500)
                            continue
                        if not retriggered_submit:
                            retriggered_submit = True
                            emitter.info("OTP 提交后仍停留在验证页，尝试再次触发一次提交...", step="verify_otp")
                            _click_primary_action(
                                page,
                                ["Continue", "Verify", "Verify email", "Submit", "Next", "Confirm", "下一步", "继续"],
                                allow_generic_fallback=False,
                            )
                            try:
                                page.keyboard.press("Enter")
                            except Exception:
                                pass
                        else:
                            _sleep_with_page(page, 500)
                    if _classify_page_state(post_otp_url, post_otp_body, page).startswith("otp"):
                        emitter.warn(
                            "OTP 提交后仍停留在验证页诊断: "
                            + f"url={_mask_secret(post_otp_url, head=56, tail=12)}, "
                            + f"state={_classify_page_state(post_otp_url, post_otp_body, page)}, "
                            + f"body={_preview_text(post_otp_body, 220) or '-'}, "
                            + "controls="
                            + _summarize_otp_controls(page)
                            + ", actions="
                            + _summarize_primary_actions(page)
                            + ", cookies="
                            + _browser_cookie_presence_summary(context)
                            + ", network="
                            + _summarize_recent_network_events(recent_network_events, limit=12),
                            step="verify_otp",
                        )
                        resend_reason = post_otp_resend_reason or "OTP 提交后仍停留在验证页"
                        if _schedule_otp_resend(resend_reason, step="verify_otp"):
                            continue
                        raise RuntimeError(
                            "浏览器模式 OTP 提交后仍停留在验证页，且无法继续触发重发验证码"
                        )
                    if is_manual_v2_mode and manual_v2_login_flow_started and email_submitted:
                        manual_v2_email_verification_recover_attempts = 0
                        manual_v2_email_otp_completed = True
                    continue

                # 限流页优先于授权/社交登录分支，避免被误判成 workspace 继续乱点。
                if _is_rate_limit_error_page(current_url, body_text):
                    rate_limit_recover_attempts += 1
                    emitter.warn(
                        "浏览器注册命中 OpenAI 限流页（Too many requests / rate_limit_exceeded），"
                        + f"第 {rate_limit_recover_attempts}/3 次处理；"
                        + "这通常是同一 IP/指纹短时间提交过频，不是 HeroSMS 取号失败。"
                        + f" detail={_preview_text(body_text, 180)}",
                        step="runtime",
                    )
                    if rate_limit_recover_attempts > 3:
                        raise RuntimeError(
                            "浏览器注册连续命中 OpenAI 限流（rate_limit_exceeded），请更换代理/冷却后再试: "
                            + _preview_text(body_text, 180)
                        )
                    if _try_recover_timeout_error_page(
                        current_url,
                        body_text,
                        step="runtime",
                        action_label="限流页已冷却并触发 Try again",
                        timeout_ms=25000,
                    ):
                        latest_url, latest_body = _describe_page(page, force_refresh=True)
                        if not _is_rate_limit_error_page(latest_url, latest_body):
                            rate_limit_recover_attempts = 0
                        continue
                    if is_manual_v2_mode and not manual_v2_login_flow_started:
                        if manual_v2_auto_phone_mode:
                            _finish_manual_v2_sms_provider(success=False)
                            manual_v2_phone_number = ""
                            manual_v2_sms_activation_id = ""
                            manual_v2_sms_purchased_at = 0.0
                            manual_v2_sms_provider_done = False
                        _prepare_manual_v2_signup_flow(
                            "浏览器模式2 步骤1命中 OpenAI 限流且 Try again 未恢复，冷却后回到步骤1重新取号/输号..."
                        )
                        if _sleep_with_page_until(page, 15000, ctx.stop_event):
                            return None
                        continue
                    raise RuntimeError(
                        "浏览器注册命中 OpenAI 限流且无法自动恢复: "
                        + _preview_text(body_text, 180)
                    )

                # 检测第三方 OAuth 登录页（Google/Microsoft/Apple 等）
                # 步骤1若误点 Continue with Google 会进这里；步骤2若手机号绑定第三方账户也会进这里。
                _third_party_oauth_domains = (
                    "accounts.google.com",
                    "login.microsoftonline.com",
                    "appleid.apple.com",
                    "login.live.com",
                )
                if any(domain in current_url_lower for domain in _third_party_oauth_domains):
                    third_party_host = (
                        current_url_lower.split("/")[2]
                        if "/" in current_url_lower
                        else current_url_lower
                    )
                    if is_manual_v2_mode and manual_v2_login_flow_started:
                        raise RuntimeError(
                            f"浏览器模式2 第二步登录后被重定向到第三方登录页 ({third_party_host})，"
                            f"说明该手机号绑定了第三方账户（Google/Microsoft/Apple），无法继续注册，需要重新拉取浏览器重新注册"
                        )
                    if is_manual_v2_mode and not manual_v2_login_flow_started:
                        # 步骤1误入 Google/Apple 登录：立刻弃号重开，避免把注册密码填进 Google 密码框。
                        emitter.warn(
                            f"浏览器模式2 步骤1误入第三方登录页 ({third_party_host})，"
                            + "通常是登录方式页误点了 Continue with Google/Apple；"
                            + "已废弃当前号码并回到步骤1重开手机号流程...",
                            step="add_phone",
                        )
                        if manual_v2_auto_phone_mode:
                            _finish_manual_v2_sms_provider(success=False)
                            manual_v2_phone_number = ""
                            manual_v2_sms_activation_id = ""
                            manual_v2_sms_purchased_at = 0.0
                            manual_v2_sms_provider_done = False
                        _prepare_manual_v2_signup_flow(
                            f"浏览器模式2 步骤1误入第三方登录页 ({third_party_host})，回到步骤1重新取号/输号..."
                        )
                        continue
                    # 非 manual_v2 模式下也不应该在第三方登录页上尝试授权操作
                    _sleep_with_page(page, 1000)
                    continue

                _is_third_party_page = any(domain in current_url_lower for domain in _third_party_oauth_domains)
                _is_social_choice_page = _is_social_login_choice_page(current_url, body_text, page)
                if _is_social_choice_page and is_manual_v2_mode and not manual_v2_login_flow_started:
                    # 步骤1若回到 Google/Apple/Phone 登录方式页：只允许点手机入口，绝不点 Continue/Google。
                    emitter.warn(
                        "浏览器模式2 步骤1当前停在社交登录方式选择页（含 Continue with Google/Apple/Phone），"
                        + "不会执行授权页 Continue，优先点 Continue with phone 拉回手机号流程..."
                        + f" actions={_summarize_primary_actions(page)}",
                        step="add_phone",
                    )
                    phone_entry_clicked = _click_exact_action_texts(
                        page,
                        [
                            "Continue with phone",
                            "Use phone instead",
                            "继续使用手机登录",
                            "使用手机",
                            "手机登录",
                        ],
                        allow_generic_submit=False,
                        timeout_ms=1500,
                    )
                    if not phone_entry_clicked:
                        phone_entry_clicked = _click_first(
                            page,
                            [
                                'a[data-auth-provider="phone"]',
                                'button[data-auth-provider="phone"]',
                                'a:has-text("Continue with phone")',
                                'button:has-text("Continue with phone")',
                                '[role="button"]:has-text("Continue with phone")',
                            ],
                            timeout_ms=1200,
                        )
                    if phone_entry_clicked:
                        emitter.info(
                            "浏览器模式2 已在社交登录方式页点击 Continue with phone，等待回到手机号输入...",
                            step="add_phone",
                        )
                        _wait_for_load(page, timeout_ms=2500)
                    else:
                        _sleep_with_page(page, 800)
                    continue

                if (
                    not _is_third_party_page
                    and not _is_social_choice_page
                    and not _is_rate_limit_error_page(current_url, body_text)
                    and not _is_retryable_error_page(current_url, body_text)
                    and _is_codex_consent_page(current_url, body_text)
                ):
                    if not manual_v2_workspace_logged:
                        manual_v2_workspace_logged = True
                        emitter.info(
                            f"浏览器流程进入 Codex 授权页: {_mask_secret(current_url, head=48, tail=12)}",
                            step="workspace",
                        )
                        emitter.info(
                            "Codex 授权页动作诊断: " + _summarize_primary_actions(page),
                            step="workspace",
                        )
                    confirm_clicked = _click_primary_action(
                        page,
                        [
                            "Continue",
                            "Authorize",
                            "Allow",
                            "Next",
                            "Confirm",
                            "Continue with ChatGPT",
                            "Continue with Codex",
                            "Use ChatGPT",
                            "Accept",
                            "Agree",
                            "继续",
                            "允许",
                            "确认",
                            "同意",
                            "接受",
                        ],
                    )
                    if not confirm_clicked:
                        try:
                            page.keyboard.press("Enter")
                            confirm_clicked = True
                        except Exception:
                            confirm_clicked = False
                    if confirm_clicked:
                        emitter.info(
                            "浏览器正在推进 Codex 授权页确认动作...",
                            step="workspace",
                        )
                    _wait_for_load(page)
                    continue

                if (
                    not _is_third_party_page
                    and not _is_social_choice_page
                    and not _is_rate_limit_error_page(current_url, body_text)
                    and not _is_retryable_error_page(current_url, body_text)
                    and any(keyword in current_url_lower for keyword in ("consent", "workspace", "organization"))
                ):
                    if not manual_v2_workspace_logged:
                        manual_v2_workspace_logged = True
                        emitter.info(
                            f"浏览器流程进入授权页: {_mask_secret(current_url, head=48, tail=12)}",
                            step="workspace",
                        )
                        emitter.info(
                            "授权页动作诊断: " + _summarize_primary_actions(page),
                            step="workspace",
                        )
                    workspace_clicked = _click_first(
                        page,
                        [
                            '[role="radio"][aria-checked="false"]',
                            '[role="option"]',
                            '[role="listitem"]',
                            'button:has-text("Personal")',
                            '[role="button"]:has-text("Personal")',
                            'button:has-text("Workspace")',
                            '[role="button"]:has-text("Workspace")',
                            'button:has-text("Continue as")',
                            '[role="button"]:has-text("Continue as")',
                            'button:has-text("Use workspace")',
                            '[role="button"]:has-text("Use workspace")',
                        ],
                        timeout_ms=1200,
                    )
                    confirm_clicked = _click_primary_action(
                        page,
                        ["Continue", "Authorize", "Allow", "Next", "继续", "允许", "Confirm", "确认"],
                    )
                    if workspace_clicked or confirm_clicked:
                        emitter.info(
                            "浏览器正在推进授权页选择/确认动作...",
                            step="workspace",
                        )
                    _wait_for_load(page)
                    continue

                if (
                    is_manual_v2_mode
                    and manual_v2_login_flow_started
                    and not manual_v2_oauth_resumed
                    and not _is_third_party_page
                    and not _is_social_choice_page
                    and (
                        manual_v2_email_otp_completed
                        or ("code=" in current_url_lower and "state=" in current_url_lower)
                        or any(keyword in current_url_lower for keyword in ("consent", "workspace", "organization"))
                    )
                ):
                    manual_v2_oauth_resumed = True
                    manual_v2_post_login_pending_email = False
                    manual_v2_bridge_entered_at = 0.0
                    manual_v2_bridge_logged = False
                    emitter.info(
                        "浏览器模式2 已进入最终授权阶段，继续沿用当前这条 OAuth/PKCE 上下文完成授权与回调，不再重新拉起新的 OAuth。",
                        step="oauth_init",
                    )

                if (
                    not _is_third_party_page
                    and not _is_social_choice_page
                    and not _is_rate_limit_error_page(current_url, body_text)
                    and not _is_retryable_error_page(current_url, body_text)
                    and not _is_codex_consent_page(current_url, body_text)
                    and any(keyword in body_lower for keyword in ("authorize", "workspace", "organization", "allow access"))
                ):
                    if not manual_v2_workspace_logged:
                        manual_v2_workspace_logged = True
                        emitter.info("浏览器正在尝试确认授权...", step="workspace")
                        emitter.info("授权页动作诊断: " + _summarize_primary_actions(page), step="workspace")
                    _click_first(
                        page,
                        [
                            '[role="radio"][aria-checked="false"]',
                            '[role="option"]',
                            '[role="listitem"]',
                            'button:has-text("Personal")',
                            '[role="button"]:has-text("Personal")',
                            'button:has-text("Workspace")',
                            '[role="button"]:has-text("Workspace")',
                        ],
                        timeout_ms=1000,
                    )
                    _click_primary_action(page, ["Continue", "Authorize", "Allow", "Next", "继续", "允许", "Confirm", "确认"])
                    _wait_for_load(page)
                    continue

                if not current_url:
                    raise RuntimeError("浏览器页面当前 URL 为空，流程异常")

                if _is_timeout_error_page(current_url, body_text):
                    timeout_recover_attempts += 1
                    if timeout_recover_attempts > 2:
                        raise RuntimeError(
                            "浏览器注册页面连续出现超时错误页: "
                            + _preview_text(body_text, 180)
                        )
                    timeout_step = "create_password" if (
                        password_submitted
                        or _is_create_account_password_page(current_url, body_text, page)
                        or _is_reset_password_new_password_page(current_url, body_text, page)
                    ) else "oauth_init"
                    if _try_recover_timeout_error_page(
                        current_url,
                        body_text,
                        step=timeout_step,
                        action_label="超时错误页已触发当前页重试",
                        timeout_ms=15000,
                    ):
                        continue
                    if is_manual_v2_mode and not manual_v2_login_flow_started:
                        timeout_recover_attempts = 0
                        _prepare_manual_v2_signup_flow(
                            "浏览器模式2 第一步注册流程出现超时错误页，准备回到步骤1重新输入手机号并重新注册..."
                        )
                        continue
                    _restart_current_page_oauth_flow(
                        target_phase=("login" if current_phase != "login" else current_phase),
                        reason="浏览器注册页面出现超时错误页，准备在当前页面重新打开并重新登录...",
                    )
                    continue

                if "error" in current_url_lower or "something went wrong" in body_lower:
                    raise RuntimeError(
                        "浏览器注册页面出现异常: "
                        + _preview_text(body_text, 180)
                    )

                time.sleep(0.35)

            raise RuntimeError("浏览器注册超时，未在限定时间内获取 callback")
        except Exception:
            _finish_manual_v2_sms_provider(success=False)
            if cfg.get("browser_keep_open_on_error"):
                preserve_browser_on_error = True
                emitter.warn(
                    "浏览器流程异常，已保留浏览器现场，便于人工继续观察排查",
                    step="runtime",
                )
                raise
    finally:
        watchdog_stop.set()
        if watchdog_thread is not None and watchdog_thread.is_alive():
            watchdog_thread.join(timeout=0.5)
        # 看门狗已经主动杀掉浏览器，现场不可继续复用；即使配置要求保留错误现场，也必须走强制收尾。
        if watchdog_triggered.is_set():
            preserve_browser_on_error = False
        final_rss = _process_tree_rss_bytes()
        if preserve_browser_on_error and final_rss >= memory_soft_limit:
            preserve_browser_on_error = False
            emitter.warn(
                "进程内存已接近 PM2 上限，忽略错误现场保留并立即关闭浏览器，避免触发 SIGKILL："
                + f"rss={final_rss / 1024 / 1024:.0f}MB, soft_limit={memory_soft_limit / 1024 / 1024:.0f}MB",
                step="memory",
            )
        if preserve_browser_on_error:
            if launch_resources is not None:
                launch_resources.playwright = playwright
                with _PRESERVED_BROWSER_RESOURCES_LOCK:
                    if launch_resources not in _PRESERVED_BROWSER_RESOURCES:
                        _PRESERVED_BROWSER_RESOURCES.append(launch_resources)
            emitter.info(
                "浏览器现场保留信息: "
                + f"mode={launch_resources.launch_mode if launch_resources is not None else '-'}, "
                + f"user_data_dir={launch_resources.temp_user_data_dir if launch_resources is not None else '-'}",
                step="runtime",
            )
        else:
            if launch_resources is not None:
                # 看门狗已终止 Chrome 时，跳过 context/browser/CDP close；这些调用依赖已失联的
                # Playwright 通道，可能再次卡住外层重试。进程/profile 清理仍在 helper 内执行。
                _close_launch_resources(
                    launch_resources,
                    skip_browser_protocol=watchdog_triggered.is_set(),
                )
            try:
                # stop 只关闭 Playwright driver，不再访问 Chrome；即使浏览器已被看门狗清理也应执行。
                playwright.stop()
            except Exception:
                pass
        try:
            wired_page_ids.clear()
            recent_network_events.clear()
        except Exception:
            pass
        _prune_page_snapshot_cache()
        gc.collect()
