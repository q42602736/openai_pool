"""
OpenAI 账号存活检测工具模块

提供两种检测方式:
  1. try_refresh_token  — 通过 refresh_token 刷新来判断账号是否存活
  2. check_access_token — 通过 access_token 调用 /v1/models 来验证账号状态
"""

import base64
import json
import random
import time
from typing import Any, Dict, Optional, Tuple

from curl_cffi import requests

TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
MODELS_URL = "https://api.openai.com/v1/models"

IMPERSONATE_LIST = ["chrome", "chrome110", "chrome116", "safari", "edge"]

DELETED_KEYWORDS = [
    "user_not_found",
    "account_deactivated",
    "account_deleted",
    "user_deactivated",
    "account not found",
    "deleted",
    "deactivated",
    "banned",
    "disabled",
    "suspended",
]


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


def _contains_deleted_keyword(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in DELETED_KEYWORDS)


def try_refresh_token(
    refresh_tok: str,
    proxies: Any = None,
    max_tries: int = 3,
) -> Tuple[str, Optional[dict], str]:
    if not refresh_tok:
        return "token_invalid", None, "refresh_token 为空"

    last_error = ""
    for attempt in range(1, max_tries + 1):
        try:
            resp = requests.post(
                TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "client_id": CLIENT_ID,
                    "refresh_token": refresh_tok,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
                proxies=proxies,
                impersonate=random.choice(IMPERSONATE_LIST),
                timeout=30,
            )

            if resp.status_code == 200:
                return "alive", resp.json(), ""

            error_data = {}
            try:
                error_data = resp.json()
            except Exception:
                pass

            error_code = str(error_data.get("error", ""))
            error_desc = str(error_data.get("error_description", ""))
            full_error = f"{error_code}: {error_desc} (HTTP {resp.status_code})"

            if _contains_deleted_keyword(resp.text):
                return "deleted", None, full_error

            if error_code == "invalid_grant":
                return "token_invalid", None, full_error

            last_error = full_error
        except Exception as exc:
            last_error = str(exc)

        if attempt < max_tries:
            time.sleep(random.uniform(1, 3))

    return "error", None, f"重试 {max_tries} 次后仍失败: {last_error}"


def check_access_token(
    access_tok: str,
    proxies: Any = None,
    max_tries: int = 3,
) -> Tuple[str, str]:
    if not access_tok:
        return "expired", "access_token 为空"

    last_error = ""
    for attempt in range(1, max_tries + 1):
        try:
            resp = requests.get(
                MODELS_URL,
                headers={
                    "Authorization": f"Bearer {access_tok}",
                    "Accept": "application/json",
                },
                proxies=proxies,
                impersonate=random.choice(IMPERSONATE_LIST),
                timeout=20,
            )

            if resp.status_code == 200:
                return "alive", ""

            body = resp.text
            if resp.status_code == 401:
                if _contains_deleted_keyword(body):
                    return "deleted", f"HTTP 401: {body[:200]}"
                return "expired", "HTTP 401: token 已过期"

            if resp.status_code == 403:
                if _contains_deleted_keyword(body):
                    return "deleted", f"HTTP 403: {body[:200]}"
                if "insufficient permissions" in body.lower() or "missing scopes" in body.lower():
                    return "alive", ""
                if "country" in body.lower() or "unsupported" in body.lower():
                    return "geo_blocked", "HTTP 403: 地区限制"
                return "expired", f"HTTP 403: {body[:200]}"

            last_error = f"HTTP {resp.status_code}: {body[:200]}"
        except Exception as exc:
            last_error = str(exc)

        if attempt < max_tries:
            time.sleep(random.uniform(1, 3))

    return "error", f"重试 {max_tries} 次后仍失败: {last_error}"
