"""
Codex 免费账号额度检测工具模块

提供 check_quota 方法，通过 Codex API 检测账号额度和有效性。
"""

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

CODEX_API_URL = "https://chatgpt.com/backend-api/codex/responses"
CODEX_CLIENT_VERSION = "0.101.0"
CODEX_USER_AGENT = "codex_cli_rs/0.101.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464"

MINIMAL_REQUEST = {
    "model": "gpt-5",
    "store": False,
    "instructions": "",
    "input": [
        {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "hi"}],
        }
    ],
    "stream": True,
}


def build_headers(account: dict) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "Authorization": f"Bearer {account.get('access_token', '')}",
        "User-Agent": CODEX_USER_AGENT,
        "Version": CODEX_CLIENT_VERSION,
        "Session_id": str(uuid.uuid4()),
        "Originator": "codex_cli_rs",
        "Connection": "keep-alive",
    }
    if account.get("account_id"):
        headers["Chatgpt-Account-Id"] = account["account_id"]
    return headers


def is_token_locally_expired(account: dict) -> bool:
    expired_str = account.get("expired") or account.get("expire", "")
    if not expired_str:
        return False
    try:
        dt = datetime.fromisoformat(expired_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(tz=timezone.utc) > dt
    except Exception:
        return False


def format_ts(ts) -> str:
    try:
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()
        else:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def format_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    parts = []
    if d:
        parts.append(f"{d}天")
    if h:
        parts.append(f"{h}小时")
    if m or not parts:
        parts.append(f"{m}分钟")
    return "".join(parts)


def parse_quota_headers(headers) -> dict:
    info = {}
    for key, field, cast in [
        ("x-codex-primary-used-percent", "used_percent", int),
        ("x-codex-primary-reset-at", "reset_at", int),
        ("x-codex-primary-reset-after-seconds", "reset_after_seconds", int),
        ("x-codex-primary-window-minutes", "window_minutes", int),
    ]:
        val = headers.get(key, "")
        if val:
            try:
                info[field] = cast(val)
            except ValueError:
                pass
    plan = headers.get("x-codex-plan-type", "")
    if plan:
        info["plan_type"] = plan
    return info


def create_session(max_workers: int = 10) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=1, status_forcelist=[502, 503, 504])
    adapter = HTTPAdapter(
        pool_connections=max_workers,
        pool_maxsize=max_workers,
        max_retries=retry,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def check_quota(
    account: dict,
    session: Optional[requests.Session] = None,
    timeout: int = 20,
) -> dict:
    base = {
        "used_percent": None,
        "reset_at": None,
        "reset_after": None,
        "window_min": None,
        "plan_type": None,
    }

    if is_token_locally_expired(account):
        return {
            **base,
            "status": "expired_token",
            "http_code": None,
            "detail": "access_token 已过期（本地判断）",
        }
    if not account.get("access_token"):
        return {
            **base,
            "status": "error",
            "http_code": None,
            "detail": "缺少 access_token 字段",
        }

    try:
        if session:
            resp = session.post(
                CODEX_API_URL,
                headers=build_headers(account),
                json=MINIMAL_REQUEST,
                stream=True,
                timeout=timeout,
            )
        else:
            resp = requests.post(
                CODEX_API_URL,
                headers=build_headers(account),
                json=MINIMAL_REQUEST,
                stream=True,
                timeout=timeout,
            )
    except requests.exceptions.Timeout:
        return {**base, "status": "error", "http_code": None, "detail": "请求超时"}
    except requests.exceptions.ConnectionError as exc:
        return {**base, "status": "error", "http_code": None, "detail": f"网络错误: {exc}"}

    http_code = resp.status_code
    quota = parse_quota_headers(resp.headers)
    rb = {
        "used_percent": quota.get("used_percent"),
        "reset_at": quota.get("reset_at"),
        "reset_after": quota.get("reset_after_seconds"),
        "window_min": quota.get("window_minutes"),
        "plan_type": quota.get("plan_type"),
    }

    if http_code == 200:
        in_tok = 0
        out_tok = 0
        try:
            for raw in resp.iter_lines():
                if not raw:
                    continue
                line = raw.decode("utf-8", errors="ignore")
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    usage = json.loads(data).get("response", {}).get("usage", {})
                    if usage:
                        in_tok = usage.get("input_tokens", 0)
                        out_tok = usage.get("output_tokens", 0)
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            resp.close()

        pct = rb["used_percent"]
        rem = (100 - pct) if pct is not None else None
        reset_str = ""
        if rb["reset_at"]:
            reset_str = f" | 重置于 {format_ts(rb['reset_at'])}"
        elif rb["reset_after"] is not None:
            reset_str = f" | {format_duration(rb['reset_after'])}后重置"
        detail = (
            f"已用={pct}% 剩余={rem}% | 输入={in_tok} 输出={out_tok}{reset_str}"
            if pct is not None
            else f"额度未知{reset_str}"
        )
        return {**rb, "status": "available", "http_code": 200, "detail": detail}

    if http_code == 429:
        reset_str = ""
        if rb["reset_at"]:
            reset_str = f" | 重置于 {format_ts(rb['reset_at'])}"
        elif rb["reset_after"] is not None:
            reset_str = f" | {format_duration(rb['reset_after'])}后重置"
        else:
            try:
                body = resp.json()
                reset_at = body.get("error", {}).get("resets_at") or body.get("resets_at")
                if reset_at:
                    rb["reset_at"] = reset_at
                    reset_str = f" | 重置于 {format_ts(reset_at)}"
            except Exception:
                pass
        resp.close()
        return {
            **rb,
            "status": "exhausted",
            "http_code": 429,
            "detail": f"额度已耗尽{reset_str}",
        }

    if http_code in (401, 403):
        resp.close()
        return {
            **rb,
            "status": "expired_token",
            "http_code": http_code,
            "detail": f"Token 无效或未授权 (HTTP {http_code})",
        }

    body = ""
    try:
        body = resp.text[:200]
    except Exception:
        pass
    resp.close()
    return {
        **rb,
        "status": "error",
        "http_code": http_code,
        "detail": f"未知响应 (HTTP {http_code}): {body}",
    }
