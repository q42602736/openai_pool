from __future__ import annotations

import importlib
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
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


DEFAULT_BROWSER_CONFIG: Dict[str, Any] = {
    "register_mode": "browser",
    "browser_headless": True,
    "browser_timeout_ms": 90000,
    "browser_slow_mo_ms": 0,
    "browser_executable_path": "",
    "browser_locale": "en-US",
    "browser_timezone": "America/New_York",
    "browser_block_media": True,
    "browser_realistic_profile": False,
    "browser_clear_runtime_state": True,
}


_PRESERVED_BROWSER_RESOURCES: list[BrowserLaunchResources] = []
_PRESERVED_BROWSER_RESOURCES_LOCK = threading.Lock()
_ACTIVE_TEMP_USER_DATA_DIRS: set[str] = set()
_ACTIVE_TEMP_USER_DATA_DIRS_LOCK = threading.Lock()
_UC_TEMP_DIR_PREFIX = "opo_uc_"
_UC_STALE_DIR_TTL_SECONDS = 6 * 60 * 60
_LOOPBACK_CALLBACK_TTL_SECONDS = 30 * 60
_LOOPBACK_CALLBACK_HUB_LOCK = threading.Lock()
_LOOPBACK_CALLBACK_HUB: Optional["_LoopbackCallbackHub"] = None


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

    raw_keep_open = None
    if isinstance(raw, dict) and "browser_keep_open_on_error" in raw:
        raw_keep_open = raw.get("browser_keep_open_on_error")

    return {
        "register_mode": register_mode,
        "browser_headless": False if register_mode in {"browser_manual", "browser_manual_v2"} else bool(source.get("browser_headless", True)),
        "browser_timeout_ms": timeout_ms,
        "browser_slow_mo_ms": slow_mo_ms,
        "browser_executable_path": executable_path,
        "browser_locale": locale,
        "browser_timezone": timezone_id,
        "browser_block_media": bool(source.get("browser_block_media", True)),
        "browser_realistic_profile": bool(source.get("browser_realistic_profile", False)),
        "browser_clear_runtime_state": bool(source.get("browser_clear_runtime_state", True)),
        "browser_keep_open_on_error": bool(
            raw_keep_open if raw_keep_open is not None else (not bool(source.get("browser_headless", True)))
        ),
    }


def _close_launch_resources(resources: Optional[BrowserLaunchResources]) -> None:
    if resources is None:
        return
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
    temp_user_data_dir = str(resources.temp_user_data_dir or "").strip()
    if temp_user_data_dir:
        _unregister_active_temp_user_data_dir(temp_user_data_dir)
        if not bool(getattr(resources, "persistent_user_data_dir", False)):
            shutil.rmtree(temp_user_data_dir, ignore_errors=True)
    try:
        if resources.playwright is not None:
            resources.playwright.stop()
    except Exception:
        pass


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
    if page is not None:
        try:
            page.wait_for_timeout(int(milliseconds))
            return
        except Exception:
            pass
    time.sleep(wait_seconds)


def _wait_for_load(page: Any, timeout_ms: int = 2500) -> None:
    try:
        page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
    except Exception:
        pass
    try:
        page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 1800))
    except Exception:
        pass
    _sleep_with_page(page, 350)


def _page_snapshot_signature(url: str, body_text: str) -> str:
    url_text = str(url or "").strip().lower()
    body_norm = re.sub(r"\s+", " ", str(body_text or "").strip().lower())
    return f"{url_text}|{body_norm[:240]}"


def _first_visible_locator(page: Any, selectors: list[str]) -> Any:
    for selector in selectors:
        try:
            locator = page.locator(selector)
            if locator.count() <= 0:
                continue
            for index in range(min(locator.count(), 8)):
                item = locator.nth(index)
                if item.is_visible():
                    return item
        except Exception:
            continue
    return None


def _click_first(page: Any, selectors: list[str], *, timeout_ms: int = 800) -> bool:
    locator = _first_visible_locator(page, selectors)
    if locator is None:
        return False
    try:
        locator.click(timeout=timeout_ms)
        return True
    except Exception:
        try:
            locator.first.click(timeout=timeout_ms)
            return True
        except Exception:
            return False


def _click_locator_human_like(page: Any, locator: Any, *, timeout_ms: int = 1200) -> bool:
    if locator is None:
        return False
    try:
        box = locator.bounding_box()
    except Exception:
        box = None
    if box:
        try:
            target_x = float(box["x"]) + float(box["width"]) * 0.5 + random.uniform(-4.0, 4.0)
            target_y = float(box["y"]) + float(box["height"]) * 0.5 + random.uniform(-3.0, 3.0)
            page.mouse.move(target_x - random.uniform(24.0, 60.0), target_y - random.uniform(12.0, 32.0), steps=random.randint(6, 12))
            page.wait_for_timeout(random.randint(120, 260))
            page.mouse.move(target_x, target_y, steps=random.randint(8, 18))
            page.wait_for_timeout(random.randint(90, 220))
            page.mouse.down()
            page.wait_for_timeout(random.randint(35, 90))
            page.mouse.up()
            return True
        except Exception:
            pass
    try:
        locator.click(timeout=timeout_ms, delay=random.randint(60, 140))
        return True
    except Exception:
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
        count = min(labels.count(), 24)
    except Exception:
        return False

    for index in range(count):
        try:
            label = labels.nth(index)
            if not label.is_visible():
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
                    nested_count = min(nested.count(), 4)
                    for nested_index in range(nested_count):
                        candidate = nested.nth(nested_index)
                        if candidate.is_visible():
                            target = candidate
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
            count = min(locator.count(), limit)
            for index in range(count):
                item = locator.nth(index)
                try:
                    if item.is_visible():
                        results.append(item)
                        if len(results) >= limit:
                            return results
                except Exception:
                    continue
        except Exception:
            continue
    return results


def _locator_metadata(locator: Any) -> Dict[str, str]:
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
                return {
                    tag: (el.tagName || '').toLowerCase(),
                    type: (el.getAttribute('type') || '').toLowerCase(),
                    role: (el.getAttribute('role') || '').toLowerCase(),
                    name: (el.getAttribute('name') || '').toLowerCase(),
                    id: (el.getAttribute('id') || '').toLowerCase(),
                    aria_label: (el.getAttribute('aria-label') || '').toLowerCase(),
                    placeholder: (el.getAttribute('placeholder') || '').toLowerCase(),
                    autocomplete: (el.getAttribute('autocomplete') || '').toLowerCase(),
                    aria_haspopup: (el.getAttribute('aria-haspopup') || '').toLowerCase(),
                    aria_valuemin: (el.getAttribute('aria-valuemin') || '').toLowerCase(),
                    aria_valuemax: (el.getAttribute('aria-valuemax') || '').toLowerCase(),
                    aria_valuenow: (el.getAttribute('aria-valuenow') || '').toLowerCase(),
                    aria_valuetext: (el.getAttribute('aria-valuetext') || '').toLowerCase(),
                    data_type: (el.getAttribute('data-type') || '').toLowerCase(),
                    contenteditable: (el.getAttribute('contenteditable') || '').toLowerCase(),
                    value: (typeof el.value === 'string' ? el.value : '').trim().toLowerCase(),
                    nested_value: nestedEditable ? (((typeof nestedEditable.value === 'string' ? nestedEditable.value : '') || nestedEditable.textContent || '')).trim().toLowerCase() : '',
                    text: ((el.innerText || el.textContent || '')).trim().toLowerCase(),
                    parent_text: parent ? ((parent.innerText || parent.textContent || '')).trim().toLowerCase() : '',
                    labels: labels.filter(Boolean).join(' ').toLowerCase(),
                };
            }"""
        )
        if isinstance(data, dict):
            return {str(k): str(v or "") for k, v in data.items()}
    except Exception:
        pass
    return {}


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


def _write_birthdate_segment(locator: Any, value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    meta = _locator_metadata(locator)
    if meta.get("role", "") == "spinbutton":
        try:
            locator.evaluate(
                """(el) => {
                    if (el && typeof el.focus === 'function') {
                        el.focus();
                    }
                }"""
            )
        except Exception:
            pass
        try:
            locator.click(timeout=1200)
        except Exception:
            pass
        for hotkey in ("Meta+A", "Control+A", "Backspace", "Delete"):
            try:
                locator.press(hotkey, timeout=1200)
            except Exception:
                pass
        for writer in (
            lambda: locator.type(text, delay=55, timeout=1200),
            lambda: locator.press_sequentially(text, timeout=1200),
            lambda: _write_text_to_locator(locator, text, timeout_ms=1200),
        ):
            try:
                writer()
            except Exception:
                continue
            try:
                locator.press("Tab", timeout=1200)
            except Exception:
                pass
            time.sleep(0.12)
            if _birthdate_segment_contains(locator, text):
                return True
        return False
    if not _write_text_to_locator(locator, text):
        return False
    return _birthdate_segment_contains(locator, text)


def _write_birthdate_segment_candidates(locator: Any, candidates: list[str]) -> bool:
    seen: set[str] = set()
    for value in candidates:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        if _write_birthdate_segment(locator, text):
            return True
    return False


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
    if year_locator is None or month_locator is None or day_locator is None:
        return False

    month_candidates = [month.zfill(2), str(int(month))]
    day_candidates = [day.zfill(2), str(int(day))]
    return (
        _write_birthdate_segment_candidates(month_locator, month_candidates)
        and _write_birthdate_segment_candidates(day_locator, day_candidates)
        and _write_birthdate_segment_candidates(year_locator, [year])
    )


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


def _click_primary_action(page: Any, preferred_texts: list[str], *, allow_generic_fallback: bool = True) -> bool:
    selectors: list[str] = []
    for text in preferred_texts:
        safe_text = text.replace('"', '\\"')
        selectors.extend(
            [
                f'button:has-text("{safe_text}")',
                f'[role="button"]:has-text("{safe_text}")',
                f'input[type="submit"][value*="{safe_text}"]',
            ]
        )
    if allow_generic_fallback:
        selectors.extend(
            [
                'button[type="submit"]',
                'form button:not([disabled])',
                'main button:not([disabled])',
                'button:not([disabled])',
            ]
        )
    if _click_first(page, selectors, timeout_ms=1500):
        return True
    try:
        page.keyboard.press("Enter")
        return True
    except Exception:
        return False


def _request_submit_with_button(locator: Any) -> bool:
    if locator is None:
        return False
    try:
        return bool(
            locator.evaluate(
                """(el) => {
                    const form = el.closest('form');
                    if (!form) return false;
                    if (typeof form.requestSubmit === 'function') {
                        form.requestSubmit(el);
                        return true;
                    }
                    form.submit();
                    return true;
                }"""
            )
        )
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
    try:
        return str(
            page.evaluate(
                """() => {
                    if (!document.body) return "";
                    return document.body.textContent || document.body.innerText || "";
                }"""
            )
            or ""
        )
    except Exception:
        return ""


def _is_session_ended_page(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    return bool(
        "session has ended" in body_lower
        or "your session has ended" in body_lower
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
) -> Optional[str]:
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
) -> Optional[Dict[str, Any]]:
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


def _is_profile_page(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    return bool(
        "about-you" in url_lower
        or "let's confirm your age" in body_lower
        or "what's your name" in body_lower
        or "full name" in body_lower
        or "birthday" in body_lower
        or "date of birth" in body_lower
        or "确认你的年龄" in body_lower
        or "你的名字" in body_lower
        or "全名" in body_text
        or "生日" in body_text
        or "出生日期" in body_text
    )


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


def _detect_otp_inputs(page: Any) -> Dict[str, Any]:
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
    if single_input is not None and _is_birthdate_segment(single_input):
        single_input = None

    segmented = []
    try:
        inputs = page.locator('input, [contenteditable="true"], [role="spinbutton"], [role="textbox"]')
        count = min(inputs.count(), 16)
        for index in range(count):
            item = inputs.nth(index)
            try:
                if not item.is_visible():
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
                if (
                    maxlength == "1"
                    or inputmode == "numeric"
                    or autocomplete == "one-time-code"
                    or item_type == "tel"
                    or (role in {"spinbutton", "textbox"} and ("code" in aria_label or "digit" in aria_label or data_type in {"otp", "code"}))
                    or (role in {"spinbutton", "textbox"} and text_value in {"", "•", "-", "_"})
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
        limit=16,
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
        limit=20,
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
    try:
        locator.evaluate(
            """(el, newValue) => {
                const applyValue = (node, val) => {
                    node.focus();
                    if ('value' in node) {
                        node.value = val;
                    } else if (node.isContentEditable) {
                        node.textContent = val;
                    } else {
                        return false;
                    }
                    node.dispatchEvent(new Event('input', { bubbles: true }));
                    node.dispatchEvent(new Event('change', { bubbles: true }));
                    return true;
                };
                return applyValue(el, newValue);
            }""",
            text,
        )
        return True
    except Exception:
        return False


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
    _sleep_with_page(page, 500)

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
            'input[name*="age" i]',
            'input[id*="age" i]',
            'input[placeholder*="age" i]',
            'input[aria-label*="age" i]',
            'input[placeholder*="年龄"]',
            'input[aria-label*="年龄"]',
            'input[name*="年龄"]',
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
    if not (
        _fill_input_by_label(page, ["全名", "姓名", "full name", "name"], ctx.profile_name)
        or _fill_first(
            page,
            [
                'input[name="name"]',
                'input[autocomplete="name"]',
                'input[placeholder*="name" i]',
                'input[id*="name" i]',
                'input[type="text"]',
            ],
            ctx.profile_name,
        )
    ):
        return False, "name"

    body_text = _get_body_text(page)
    body_lower = str(body_text or "").lower()
    prefers_age = (
        "confirm your age" in body_lower
        or "your age" in body_lower
        or " age " in f" {body_lower} "
        or "年龄" in body_text
    )
    if prefers_age:
        if not _fill_age(page, ctx.profile_birthdate):
            return False, "age"
    else:
        if not _fill_birthdate(page, ctx.profile_birthdate):
            if not _fill_age(page, ctx.profile_birthdate):
                return False, "birthdate"

    if not _ensure_about_you_checkbox(page):
        return False, "checkbox"
    return True, ("age" if prefers_age else "birthdate")


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


def _describe_page(page: Any) -> tuple[str, str]:
    current_url = ""
    body_text = ""
    try:
        current_url = str(page.url or "").strip()
    except Exception:
        current_url = ""
    try:
        body_text = _get_body_text(page)
    except Exception:
        body_text = ""
    return current_url, body_text


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
        if "/log-in/password" in url_lower:
            return 175
        if "/create-account/password" in url_lower:
            return 172
        if "/reset-password/new-password" in url_lower:
            return 170
        if "contact-verification" in url_lower:
            return 168
        if "/reset-password" in url_lower:
            return 166
        if "about-you" in url_lower:
            return 164
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
    )


def _is_contact_verification_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    if "contact-verification" in url_lower:
        return True
    if "verify your phone" in body_lower or "contact verification" in body_lower:
        return True
    phone_otp_input = _first_visible_locator(
        page,
        [
            'input[inputmode="numeric"]',
            'input[autocomplete="one-time-code"]',
            'input[name*="code" i]',
            'input[name*="otp" i]',
        ],
    )
    return phone_otp_input is not None and ("phone" in body_lower or "sms" in body_lower)


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


def _is_create_account_password_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
    if "/reset-password/new-password" in url_lower:
        return False
    if "/create-account/password" in url_lower:
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


def _is_login_password_page(url: str, body_text: str, page: Any) -> bool:
    url_lower = str(url or "").lower()
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
    try:
        return str(locator.input_value(timeout=timeout_ms) or "").strip()
    except Exception:
        try:
            return str(locator.get_attribute("value") or "").strip()
        except Exception:
            return ""


def _manual_phone_input_ready(page: Any) -> bool:
    locator = _first_visible_locator(
        page,
        [
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
    return bool(
        ("continue with phone" in body_lower or "继续使用手机登录" in body_text)
        and phone_input is not None
    )


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


def _is_login_with_bridge_page(url: str, body_text: str) -> bool:
    url_lower = str(url or "").lower()
    body_lower = str(body_text or "").lower()
    return bool(
        "chatgpt.com/auth/login_with" in url_lower
        or ("login_with" in url_lower and "chatgpt.com" in url_lower)
        or ("continue with" in body_lower and "chatgpt" in body_lower)
    )


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
    body_lower = str(body_text or "").lower()
    if _is_profile_page(url, body_text):
        return False
    if _is_phone_verification_page(url, body_text, page):
        return False
    if _is_contact_verification_page(url, body_text, page):
        return False
    return bool(
        "email-verification" in str(url or "").lower()
        or "email otp" in body_lower
        or "verification code" in body_lower
        or _detect_otp_inputs(page).get("mode")
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
    if _is_session_ended_page(url, body_text):
        return "session_ended"
    if _is_timeout_error_page(url, body_text):
        return "timeout_error"
    if _is_phone_verification_page(url, body_text, page):
        return "add_phone"
    if _is_contact_verification_page(url, body_text, page):
        return "contact_verification"
    if any(keyword in url_lower for keyword in ("consent", "workspace", "organization")):
        return "workspace"
    if any(keyword in body_lower for keyword in ("authorize", "workspace", "organization", "allow access")):
        return "workspace"
    if _is_profile_page(url, body_text):
        return "profile"
    if _is_otp_page(url, body_text, page):
        return "otp_ready" if _is_otp_page_ready(url, body_text, page) else "otp_loading"
    if _first_visible_locator(
        page,
        [
            'input[type="password"]',
            'input[name="password"]',
            'input[name="new-password"]',
            'input[autocomplete="new-password"]',
        ],
    ) is not None:
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
    if "chatgpt.com" in url_lower:
        return "chatgpt"
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


def _cleanup_stale_temp_user_data_dirs(emitter: Any) -> None:
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


def _resolve_uc_user_data_dir(cfg: Dict[str, Any], emitter: Any) -> tuple[str, bool]:
    register_mode = str(cfg.get("register_mode") or "").strip().lower()
    temp_user_data_dir = tempfile.mkdtemp(prefix="opo_uc_")
    _register_active_temp_user_data_dir(temp_user_data_dir)
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
        options.add_argument("--disable-gpu")
        options.add_argument("--no-first-run")
        options.add_argument("--no-default-browser-check")
        options.add_argument("--ignore-certificate-errors")
        if cfg.get("browser_realistic_profile", True):
            options.add_argument("--disable-features=ImprovedCookieControls,ThirdPartyStoragePartitioning,BlockThirdPartyCookies")
        options.add_argument("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
        options.add_argument("--webrtc-ip-handling-policy=disable_non_proxied_udp")
        options.add_argument("--enforce-webrtc-ip-permission-check")
        options.add_argument(f"--user-data-dir={temp_user_data_dir}")
        try:
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

    cfg = normalize_browser_config(browser_config)
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
    login_add_phone_retry_attempts = 0
    login_add_phone_retry_limit = 3
    register_mode = str(cfg.get("register_mode") or "browser").strip().lower()
    is_manual_mode = register_mode == "browser_manual"
    is_manual_v2_mode = register_mode == "browser_manual_v2"
    use_plain_browser_env = False
    otp_wait_timeout_seconds = 20
    otp_max_resend_attempts = 20
    otp_same_code_retry_limit = 2
    otp_resend_attempts = 0
    wired_page_ids: set[int] = set()
    recent_network_events = deque(maxlen=40)
    manual_v2_login_oauth = None
    manual_v2_phone_number = ""
    manual_v2_wait_phone_logged = False
    manual_v2_wait_contact_logged = False
    manual_v2_contact_seen = False
    manual_v2_login_flow_started = False
    manual_v2_phone_entry_clicked = False
    manual_v2_login_phone_prefilled = False
    manual_v2_login_phone_submitted = False
    manual_v2_login_password_prefilled = False
    manual_v2_post_login_pending_email = False
    manual_v2_bridge_entered_at = 0.0
    manual_v2_bridge_logged = False
    manual_v2_post_login_recover_attempts = 0
    manual_v2_email_verification_recover_attempts = 0
    manual_v2_email_verification_logged = False
    manual_v2_email_otp_completed = False
    manual_v2_oauth_resumed = False
    manual_v2_waiting_phone_retry = False
    manual_v2_waiting_phone_retry_logged = False
    manual_v2_require_phone_resubmit = False
    manual_v2_password_page_logged = False
    manual_v2_wait_phone_last_url = ""
    manual_v2_entry_bootstrap_logged = False
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
                candidate_url, candidate_body = _describe_page(candidate_page)
            except Exception:
                continue
            if "code=" in str(candidate_url or "").lower() and "state=" in str(candidate_url or "").lower():
                _record_callback(candidate_url)
            else:
                callback_candidate = _extract_callback_url_from_page(candidate_url, candidate_body)
                if callback_candidate:
                    _record_callback(callback_candidate)
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
                try:
                    candidate_url = str(candidate_page.url or "").strip()
                except Exception:
                    candidate_url = ""
                score = _page_priority_from_url(candidate_url)
                if preferred_page is not None and candidate_page is preferred_page:
                    score += 3
                if page is not None and candidate_page is page:
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

    def _start_oauth_flow(page: Any, oauth_start: Any, phase: str) -> None:
        if phase == "login":
            emitter.info("浏览器注册阶段已结束，正在当前浏览器窗口重新拉起登录流程获取 Token...", step="oauth_init")
        else:
            emitter.info("正在当前浏览器窗口启动注册流程...", step="oauth_init")
        page.goto(str(oauth_start.auth_url), wait_until="domcontentloaded", timeout=cfg["browser_timeout_ms"])
        _wait_for_load(page, timeout_ms=2500)
        emitter.info(
            f"浏览器{('登录' if phase == 'login' else '注册')}流程落点: {_mask_secret(page.url, head=48, tail=12)}",
            step="oauth_init",
        )
        if not cfg["browser_headless"]:
            emitter.info("当前为可见浏览器模式，可直接观察页面流程用于排查", step="oauth_init")

    def _bootstrap_manual_v2_phone_entry(current_url: str, body_text: str) -> bool:
        url_lower = str(current_url or "").lower()
        body_lower = str(body_text or "").lower()
        if "chatgpt.com" not in url_lower:
            return False
        if _has_phone_input(page):
            return False
        clicked = False
        if _click_first(
            page,
            [
                'a:has-text("Sign up")',
                'button:has-text("Sign up")',
                '[role="button"]:has-text("Sign up")',
                'a:has-text("免费注册")',
                'button:has-text("免费注册")',
                '[role="button"]:has-text("免费注册")',
                'a:has-text("注册")',
                'button:has-text("注册")',
                '[role="button"]:has-text("注册")',
            ],
            timeout_ms=1200,
        ):
            emitter.info("浏览器模式2 已自动点击首页注册入口，准备拉起手机号注册界面...", step="oauth_init")
            _wait_for_load(page, timeout_ms=2000)
            clicked = True
        if _has_phone_input(page):
            return True
        if _click_first(
            page,
            [
                'button:has-text("Continue with phone")',
                '[role="button"]:has-text("Continue with phone")',
                'button:has-text("Use phone instead")',
                '[role="button"]:has-text("Use phone instead")',
                'button:has-text("Phone")',
                '[role="button"]:has-text("Phone")',
                'button:has-text("手机号")',
                '[role="button"]:has-text("手机号")',
                'button:has-text("使用手机")',
                '[role="button"]:has-text("使用手机")',
                'button:has-text("手机登录")',
                '[role="button"]:has-text("手机登录")',
            ],
            timeout_ms=1200,
        ):
            emitter.info("浏览器模式2 已自动切换到手机号注册入口，等待你输入手机号...", step="oauth_init")
            _wait_for_load(page, timeout_ms=2000)
            clicked = True
        if _has_phone_input(page):
            return True
        if clicked:
            return True
        if (
            "sign up" in body_lower
            or "免费注册" in body_text
            or "注册" in body_text
            or "continue with phone" in body_lower
            or "use phone instead" in body_lower
            or "使用手机" in body_text
        ):
            return True
        return False

    def _bootstrap_manual_v2_login_entry(current_url: str, body_text: str) -> bool:
        url_lower = str(current_url or "").lower()
        body_lower = str(body_text or "").lower()
        if "auth.openai.com/log-in" not in url_lower:
            return False
        if _is_phone_input_page(current_url, body_text, page):
            return True
        if _click_first(
            page,
            [
                'button:has-text("Continue with phone")',
                '[role="button"]:has-text("Continue with phone")',
                'button:has-text("Use phone instead")',
                '[role="button"]:has-text("Use phone instead")',
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
            ],
            timeout_ms=1200,
        ):
            emitter.info("浏览器模式2 已在 auth.openai.com/log-in 页面切换到手机号登录入口，等待你输入手机号...", step="oauth_init")
            _wait_for_load(page, timeout_ms=2000)
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
            latest_url, latest_body = _describe_page(page)
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
        return _describe_page(page)

    def _prepare_manual_v2_login_flow(reason: str) -> None:
        nonlocal current_phase, email_submitted, password_submitted, profile_submitted
        nonlocal current_oauth, manual_v2_login_oauth
        nonlocal manual_v2_contact_seen, manual_v2_wait_contact_logged
        nonlocal manual_v2_login_flow_started, manual_v2_phone_entry_clicked
        nonlocal manual_v2_login_phone_prefilled, manual_v2_login_password_prefilled
        nonlocal manual_v2_login_phone_submitted, manual_v2_post_login_pending_email
        nonlocal manual_v2_bridge_entered_at, manual_v2_bridge_logged
        nonlocal manual_v2_post_login_recover_attempts
        nonlocal manual_v2_email_verification_recover_attempts
        nonlocal manual_v2_email_verification_logged
        nonlocal manual_v2_email_otp_completed
        nonlocal manual_v2_oauth_resumed, manual_v2_wait_phone_logged
        nonlocal manual_v2_wait_phone_last_url, manual_v2_password_page_logged, manual_v2_phone_number
        nonlocal manual_v2_waiting_phone_retry, manual_v2_waiting_phone_retry_logged
        nonlocal manual_v2_require_phone_resubmit, manual_v2_reset_password_flow_started
        nonlocal manual_v2_reset_password_continue_clicked
        nonlocal page
        callback_state["url"] = ""
        current_phase = "login"
        email_submitted = False
        password_submitted = False
        profile_submitted = False
        manual_v2_contact_seen = False
        manual_v2_wait_contact_logged = False
        manual_v2_login_flow_started = True
        manual_v2_phone_entry_clicked = False
        manual_v2_login_phone_prefilled = False
        manual_v2_login_phone_submitted = False
        manual_v2_login_password_prefilled = False
        manual_v2_post_login_pending_email = False
        manual_v2_bridge_entered_at = 0.0
        manual_v2_bridge_logged = False
        manual_v2_post_login_recover_attempts = 0
        manual_v2_email_verification_recover_attempts = 0
        manual_v2_email_verification_logged = False
        manual_v2_email_otp_completed = False
        manual_v2_oauth_resumed = False
        manual_v2_wait_phone_logged = False
        manual_v2_wait_phone_last_url = ""
        manual_v2_password_page_logged = False
        manual_v2_waiting_phone_retry = False
        manual_v2_waiting_phone_retry_logged = False
        manual_v2_require_phone_resubmit = False
        manual_v2_reset_password_flow_started = False
        manual_v2_reset_password_continue_clicked = False
        emitter.info(reason, step="oauth_init")
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
    emitter.info(f"本次浏览器指纹: {describe_fingerprint(ctx.fingerprint_profile)}", step="oauth_init")

    playwright = sync_playwright().start()
    launch_resources: Optional[BrowserLaunchResources] = None
    preserve_browser_on_error = False
    try:
        try:
            launch_resources = _launch_via_local_uc_bridge(playwright, ctx, cfg)
            emitter.info(f"浏览器已切换为本地 uc 桥接模式: {launch_resources.launch_mode}", step="oauth_init")
        except Exception as exc:
            raise RuntimeError(f"本地 uc 启动失败，无法继续注册流程: {exc}") from exc

        browser = launch_resources.browser
        context = launch_resources.context
        page = launch_resources.page
        if not use_plain_browser_env:
            try:
                context.route("**/*", _handle_route)
            except Exception:
                pass
            try:
                context.add_init_script(ctx.fingerprint_profile.to_init_script())
            except Exception:
                pass
        _wire_page_once(page)
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
                page.goto("https://chatgpt.com/", wait_until="domcontentloaded", timeout=cfg["browser_timeout_ms"])
                _wait_for_load(page, timeout_ms=2500)
                emitter.info(
                    f"浏览器模式2 步骤1首页落点: {_mask_secret(page.url, head=48, tail=12)}",
                    step="oauth_init",
                )
                if not cfg["browser_headless"]:
                    emitter.info("当前为可见浏览器模式，可直接观察 ChatGPT 首页到手机注册入口的切换过程", step="oauth_init")
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

                if not callback_state["url"]:
                    loopback_callback = _consume_loopback_callback()
                    if loopback_callback:
                        emitter.info("本地 OAuth 回调监听已收到 callback，准备交换 Token...", step="get_token")
                if callback_state["url"]:
                    callback_url_value = str(callback_state["url"] or "").strip()
                    callback_is_real = ("code=" in callback_url_value and "state=" in callback_url_value)
                    oauth_for_exchange = _active_oauth_start()
                    if is_manual_v2_mode and not manual_v2_oauth_resumed and not callback_is_real:
                        emitter.info("浏览器模式2 当前仍处于注册前半段，忽略提前出现的 callback 线索，等待进入后续授权流程...", step="get_token")
                        callback_state["url"] = ""
                    else:
                        if is_manual_v2_mode and not manual_v2_oauth_resumed and callback_is_real:
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
                            if is_manual_v2_mode and "state mismatch" in str(exc).lower() and callback_is_real:
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
                            elif "token result missing email/account_id" in str(exc).lower():
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
                        return token_json

                active_page = _resolve_active_page(page, timeout_ms=1500)
                if active_page is None:
                    if callback_state["url"]:
                        continue
                    _sleep_with_page(None, 300)
                    continue

                current_url, body_text = _describe_page(page)
                current_url_lower = current_url.lower()
                body_lower = body_text.lower()
                otp_route_locked = ("email-verification" in current_url_lower or "email-otp" in current_url_lower)
                callback_candidate = _extract_callback_url_from_page(current_url, body_text)
                if callback_candidate and not callback_state["url"]:
                    callback_is_real = ("code=" in callback_candidate and "state=" in callback_candidate)
                    if is_manual_v2_mode and not manual_v2_oauth_resumed and not callback_is_real:
                        emitter.info("浏览器模式2 注册前半段检测到 callback 线索，暂不处理，等待后续授权流程重新拉起...", step="get_token")
                    else:
                        if is_manual_v2_mode and not manual_v2_oauth_resumed and callback_is_real:
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
                    is_create_password_page = _is_create_account_password_page(current_url, body_text, page)
                    is_reset_new_password_page = _is_reset_password_new_password_page(current_url, body_text, page)
                    is_login_password_page = _is_login_password_page(current_url, body_text, page)
                    is_phone_stage_page = (
                        not is_create_password_page
                        and not is_reset_new_password_page
                        and not is_login_password_page
                        and (
                            "chatgpt.com" in current_url_lower
                            or _is_phone_input_page(current_url, body_text, page)
                            or _is_phone_verification_page(current_url, body_text, page)
                        )
                    )
                    captured_phone = _extract_input_value_by_hints(
                        page,
                        ["phone", "mobile", "手机号", "电话", "tel"],
                    )
                    if captured_phone:
                        manual_v2_phone_number = captured_phone

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
                        and "chatgpt.com" in current_url_lower
                    ):
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
                    else:
                        manual_v2_entry_bootstrap_logged = False

                    if is_create_password_page:
                        manual_v2_wait_phone_logged = False
                        manual_v2_wait_phone_last_url = ""
                        if not manual_v2_password_page_logged:
                            manual_v2_password_page_logged = True
                            emitter.info(
                                "浏览器模式2 已检测到创建密码页，准备自动填写密码: "
                                + _mask_secret(current_url, head=56, tail=12),
                                step="create_password",
                            )
                    else:
                        manual_v2_password_page_logged = False

                    if (
                        not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                        and not is_create_password_page
                        and not is_login_password_page
                        and _is_phone_input_page(current_url, body_text, page)
                    ):
                        if manual_v2_reset_password_flow_started or manual_v2_reset_password_continue_clicked:
                            manual_v2_reset_password_flow_started = False
                            manual_v2_reset_password_continue_clicked = False
                            manual_v2_password_page_logged = False
                        if _manual_phone_input_ready(page):
                            if not manual_v2_wait_phone_logged or manual_v2_wait_phone_last_url != current_url + "#ready":
                                manual_v2_wait_phone_logged = True
                                manual_v2_wait_phone_last_url = current_url + "#ready"
                                emitter.info(
                                    "浏览器模式2 检测到你已输入步骤1手机号，请你手动点击继续；提交后程序会自动接管后续流程...",
                                    step="add_phone",
                                )
                            _sleep_with_page(page, 800)
                            continue
                        if not manual_v2_wait_phone_logged or manual_v2_wait_phone_last_url != current_url:
                            manual_v2_wait_phone_logged = True
                            manual_v2_wait_phone_last_url = current_url
                            emitter.info(
                                "浏览器模式2 已进入步骤1手机号输入页，请先手动输入手机号；输完后请你手动点击继续...",
                                step="add_phone",
                            )
                        _sleep_with_page(page, 800)
                        continue

                    if (
                        not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                        and is_login_password_page
                        and not manual_v2_reset_password_flow_started
                    ):
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
                        if _click_primary_action(page, ["Continue", "Next", "继续", "下一步"], allow_generic_fallback=True):
                            manual_v2_reset_password_continue_clicked = True
                            emitter.info("浏览器模式2 已进入 reset-password 页面，已自动点击继续，等待短信验证码...", step="create_password")
                            _wait_for_load(page, timeout_ms=2500)
                            continue

                    if _is_contact_verification_page(current_url, body_text, page):
                        _extend_manual_v2_deadline(3600)
                        manual_v2_contact_seen = True
                        manual_v2_waiting_phone_retry = False
                        manual_v2_waiting_phone_retry_logged = False
                        manual_v2_require_phone_resubmit = False
                        if _manual_contact_verification_ready(page):
                            if _click_primary_action(page, ["Continue", "Verify", "Submit", "继续", "下一步"], allow_generic_fallback=True):
                                emitter.info("浏览器模式2 检测到你已填好手机验证码，已自动点击继续...", step="phone_verification")
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
                        _prepare_manual_v2_login_flow("浏览器模式2 已完成首次重置密码，重新打开第二步手机登录流程...")
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
                        _prepare_manual_v2_login_flow("浏览器模式2 已完成首次重置密码成功页，重新打开第二步手机登录流程...")
                        continue

                    if (
                        not manual_v2_login_flow_started
                        and not manual_v2_contact_seen
                        and not is_create_password_page
                        and not _is_reset_password_new_password_page(current_url, body_text, page)
                        and not _is_login_password_page(current_url, body_text, page)
                        and not password_submitted
                        and (
                            is_phone_stage_page
                            or _is_phone_flow_page(current_url, body_text)
                        )
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
                        manual_v2_contact_seen
                        and not manual_v2_login_flow_started
                        and _is_profile_page(current_url, body_text)
                        and not profile_submitted
                    ):
                        _extend_manual_v2_deadline(1800)
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
                        if not _click_primary_action(page, ["完成帐户创建", "完成账户创建", "Continue", "Next", "Create account", "完成", "继续"]):
                            raise RuntimeError("浏览器模式2 提交 about-you 资料失败")
                        profile_submitted = True
                        _wait_for_page_stabilize(
                            previous_url,
                            previous_body,
                            step="create_account",
                            action_label="about-you 资料已提交",
                            timeout_ms=20000,
                        )
                        emitter.success("浏览器模式2 已完成 about-you，转入手机登录补邮箱流程...", step="create_account")
                        _prepare_manual_v2_login_flow("浏览器模式2 正在清理注册残留状态，并重新打开手机登录流程...")
                        continue

                    if manual_v2_contact_seen and not manual_v2_login_flow_started:
                        if _is_create_account_password_page(current_url, body_text, page):
                            _extend_manual_v2_deadline(1800)
                            manual_v2_wait_contact_logged = False
                            manual_v2_waiting_phone_retry = False
                            manual_v2_waiting_phone_retry_logged = False
                            manual_v2_require_phone_resubmit = False
                            manual_v2_wait_phone_logged = False
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
                            _sleep_with_page(page, 800)
                            continue
                        emitter.info(
                            "浏览器模式2 短信验证码提交后进入过渡页，继续观察后续跳转，不再仅凭离开 contact-verification 就判定完成。"
                            + f" current_url={_mask_secret(current_url, head=56, tail=12)}"
                            + f", state={_classify_page_state(current_url, body_text, page)}",
                            step="phone_verification",
                        )
                        _sleep_with_page(page, 800)
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
                        if manual_v2_post_login_pending_email:
                            session_fast_path_token = _try_browser_session_fast_path(current_url)
                            if session_fast_path_token:
                                return session_fast_path_token
                        if (
                            manual_v2_post_login_pending_email
                            and manual_v2_bridge_entered_at > 0
                            and _has_manual_v2_login_session(context)
                            and time.time() - manual_v2_bridge_entered_at >= 12
                        ):
                            emitter.warn(
                                "浏览器模式2 在 login_with 桥接页等待超过 12 秒仍未自然落到绑定邮箱页，继续等待站点自身跳转，不再强制改页。",
                                step="oauth_init",
                            )
                        _sleep_with_page(page, 800)
                        continue

                    if (
                        manual_v2_login_flow_started
                        and manual_v2_post_login_pending_email
                        and "auth.openai.com/log-in" in current_url_lower
                        and manual_v2_login_phone_submitted
                        and manual_v2_post_login_recover_attempts < 2
                    ):
                        manual_v2_post_login_recover_attempts += 1
                        emitter.warn(
                            "浏览器模式2 第二步密码提交后又回到了 log-in 页面，判定为 login_with 桥接回跳；"
                            + f"开始第 {manual_v2_post_login_recover_attempts}/2 次恢复尝试。"
                            + " cookies="
                            + _browser_cookie_presence_summary(context),
                            step="oauth_init",
                        )
                        session_fast_path_token = _try_browser_session_fast_path(current_url)
                        if session_fast_path_token:
                            return session_fast_path_token
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
                        if (
                            manual_v2_post_login_recover_attempts >= 2
                            and _has_manual_v2_login_session(context)
                        ):
                            emitter.warn(
                                "浏览器模式2 在 login_with 自然桥接两次回跳后仍未进入绑定邮箱页，"
                                + "当前确认登录态已建立，改为执行安全补跳 add-email...",
                                step="create_email",
                            )
                            _goto_manual_v2_add_email("浏览器模式2 在自然桥接失败后安全补跳 add-email")
                        else:
                            emitter.info(
                                "桥接回跳后先继续观察一次站点自然跳转，暂不立即强制打开 add-email...",
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
                                if not manual_v2_wait_phone_logged or manual_v2_wait_phone_last_url != current_url:
                                    manual_v2_wait_phone_logged = True
                                    manual_v2_wait_phone_last_url = current_url
                                    emitter.info(
                                        "浏览器模式2 当前位于手机号输入页，正等待读取你已输入的手机号，再自动提交登录...",
                                        step="create_email",
                                    )
                                _sleep_with_page(page, 800)
                                continue
                            manual_v2_wait_phone_logged = False
                            manual_v2_wait_phone_last_url = current_url
                            if not _write_text_to_locator(phone_input, manual_v2_phone_number):
                                raise RuntimeError("浏览器模式2 填写手机号失败")
                            # 精确提交手机号表单：优先用手机号输入框所在 form 的 submit，
                            # 避免误点 "Continue with Google" 等第三方登录按钮
                            _phone_form_submitted = _request_submit_with_button(phone_input)
                            if not _phone_form_submitted:
                                # form.requestSubmit 失败时，尝试精确点击排除第三方按钮的 Continue
                                _phone_form_submitted = _click_first(
                                    page,
                                    [
                                        'button[type="submit"]:not(:has-text("Google")):not(:has-text("Microsoft")):not(:has-text("Apple"))',
                                        'form button:not([disabled]):not(:has-text("Google")):not(:has-text("Microsoft")):not(:has-text("Apple"))',
                                    ],
                                    timeout_ms=1500,
                                )
                            if not _phone_form_submitted:
                                _phone_form_submitted = _click_primary_action(
                                    page, ["Continue", "Next", "\u7ee7\u7eed", "\u4e0b\u4e00\u6b65"], allow_generic_fallback=False
                                )
                            if not _phone_form_submitted:
                                try:
                                    page.keyboard.press("Enter")
                                    _phone_form_submitted = True
                                except Exception:
                                    pass
                            if not _phone_form_submitted:
                                raise RuntimeError("浏览器模式2 提交手机号失败")
                            manual_v2_login_phone_submitted = True
                            manual_v2_post_login_pending_email = False
                            manual_v2_bridge_entered_at = 0.0
                            manual_v2_bridge_logged = False
                            manual_v2_post_login_recover_attempts = 0
                            emitter.info("浏览器模式2 已提交手机号，等待密码页...", step="create_email")
                            _wait_for_load(page, timeout_ms=5000)
                            _post_phone_url, _post_phone_body = _describe_page(page)
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
                        emitter.info(f"浏览器模式2 已进入 add-email 页面，准备绑定邮箱: {ctx.email}", step="create_email")
                        emitter.info(
                            "进入 add-email 前会话诊断: cookies="
                            + _browser_cookie_presence_summary(context),
                            step="create_email",
                        )
                        if not _fill_first(
                            page,
                            [
                                'input[name="email"]',
                                'input[autocomplete="email"]',
                                'input[id*="-email" i]',
                                'input[placeholder*="email" i]',
                                'input[placeholder*="电子邮件" i]',
                            ],
                            ctx.email,
                        ):
                            raise RuntimeError("浏览器模式2 在 add-email 页面填写邮箱失败")
                        previous_url = current_url
                        previous_body = body_text
                        if not _click_primary_action(
                            page,
                            ["Continue", "Next", "Verify", "继续", "下一步"],
                            allow_generic_fallback=True,
                        ):
                            raise RuntimeError("浏览器模式2 在 add-email 页面提交邮箱失败")
                        email_submitted = True
                        _wait_for_page_stabilize(
                            previous_url,
                            previous_body,
                            step="create_email",
                            action_label="add-email 邮箱已提交",
                            timeout_ms=12000,
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
                        and not _is_create_account_password_page(current_url, body_text, page)
                    ):
                        _extend_manual_v2_deadline(1800)
                        if current_url:
                            emitter.info(
                                "浏览器模式2 密码已提交，当前等待进入短信验证码页，当前页面: "
                                + _mask_secret(current_url, head=56, tail=12),
                                step="phone_verification",
                            )
                        _sleep_with_page(page, 800)
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
                            phone_done = False
                            if callback_state["url"] or _scan_context_pages_for_callback():
                                phone_done = True
                            elif "chatgpt.com" in new_url_lower:
                                phone_done = True
                            elif "code=" in new_url_lower and "state=" in new_url_lower:
                                phone_done = True
                            elif any(kw in new_url_lower for kw in ("consent", "workspace", "organization")):
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
                    if is_manual_v2_mode and manual_v2_login_flow_started and current_phase == "login":
                        manual_v2_post_login_pending_email = True
                        manual_v2_bridge_entered_at = 0.0
                        manual_v2_bridge_logged = False
                        manual_v2_post_login_recover_attempts = 0
                    emitter.info(
                        ("浏览器登录密码已提交，密码: " if current_phase == "login" else "浏览器注册密码已提交，密码: ")
                        + ctx.account_password,
                        step="create_password",
                    )
                    if is_manual_v2_mode and manual_v2_login_flow_started and current_phase == "login":
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
                    if not _click_primary_action(page, ["完成帐户创建", "完成账户创建", "Continue", "Next", "Create account", "完成", "继续"]):
                        raise RuntimeError("浏览器模式提交账户资料失败")
                    profile_submitted = True
                    _wait_for_page_stabilize(
                        previous_url,
                        previous_body,
                        step="create_account",
                        action_label="账户资料已提交",
                        timeout_ms=20000,
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
                        emitter.info("浏览器流程进入邮箱 OTP 阶段，页面已就绪，开始轮询邮箱...", step="send_otp")
                        otp_wait_started = True
                    otp_page_ready_logged = False
                    current_wait_timeout = otp_wait_timeout_seconds
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

                # 检测第三方 OAuth 登录页（Google/Microsoft/Apple 等）
                # 如果步骤2登录提交手机号后被重定向到第三方登录页，说明该手机号绑定了第三方账户，无法继续
                _third_party_oauth_domains = (
                    "accounts.google.com",
                    "login.microsoftonline.com",
                    "appleid.apple.com",
                    "login.live.com",
                )
                if any(domain in current_url_lower for domain in _third_party_oauth_domains):
                    if is_manual_v2_mode and manual_v2_login_flow_started:
                        raise RuntimeError(
                            f"浏览器模式2 第二步登录后被重定向到第三方登录页 ({current_url_lower.split('/')[2] if '/' in current_url_lower else current_url_lower})，"
                            f"说明该手机号绑定了第三方账户（Google/Microsoft/Apple），无法继续注册，需要重新拉取浏览器重新注册"
                        )
                    # 非 manual_v2 模式下也不应该在第三方登录页上尝试授权操作
                    _sleep_with_page(page, 1000)
                    continue

                _is_third_party_page = any(domain in current_url_lower for domain in _third_party_oauth_domains)
                if not _is_third_party_page and any(keyword in current_url_lower for keyword in ("consent", "workspace", "organization")):
                    emitter.info(
                        f"浏览器流程进入授权页: {_mask_secret(current_url, head=48, tail=12)}",
                        step="workspace",
                    )
                    _click_primary_action(page, ["Continue", "Authorize", "Allow", "Next", "继续", "允许"])
                    _wait_for_load(page)
                    continue

                if (
                    is_manual_v2_mode
                    and manual_v2_login_flow_started
                    and not manual_v2_oauth_resumed
                    and not _is_third_party_page
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

                if not _is_third_party_page and any(keyword in body_lower for keyword in ("authorize", "workspace", "organization", "allow access")):
                    emitter.info("浏览器正在尝试确认授权...", step="workspace")
                    _click_primary_action(page, ["Continue", "Authorize", "Allow", "Next", "继续", "允许"])
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

                time.sleep(0.8)

            raise RuntimeError("浏览器注册超时，未在限定时间内获取 callback")
        except Exception:
            if cfg.get("browser_keep_open_on_error"):
                preserve_browser_on_error = True
                emitter.warn(
                    "浏览器流程异常，已保留浏览器现场，便于人工继续观察排查",
                    step="runtime",
                )
            raise
    finally:
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
                _close_launch_resources(launch_resources)
            try:
                playwright.stop()
            except Exception:
                pass
