from __future__ import annotations

import base64
import copy
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

AUTH_CLAIM_KEY = "https://api.openai.com/auth"


def _b64url_encode_json(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_jwt_payload(token: Any) -> Dict[str, Any]:
    raw = str(token or "").strip()
    if raw.count(".") < 2:
        return {}
    payload = raw.split(".")[1]
    if not payload:
        return {}
    pad = "=" * ((4 - (len(payload) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((payload + pad).encode("ascii"))
        data = json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _first_non_empty_str(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _auth_claims(payload: Dict[str, Any]) -> Dict[str, Any]:
    auth = payload.get(AUTH_CLAIM_KEY) if isinstance(payload, dict) else {}
    return auth if isinstance(auth, dict) else {}


def _epoch_from_value(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        epoch = int(value)
        return epoch if epoch > 0 else 0
    text = str(value or "").strip()
    if not text:
        return 0
    if text.isdigit():
        try:
            epoch = int(text)
        except (TypeError, ValueError):
            return 0
        return epoch if epoch > 0 else 0
    iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(iso_text)
    except Exception:
        return 0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _rfc3339_from_epoch(epoch: int) -> str:
    if not isinstance(epoch, int) or epoch <= 0:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def build_compat_id_token(
    *,
    email: str,
    exp: int,
    chatgpt_account_id: str,
    chatgpt_user_id: str = "",
    plan_type: str = "",
) -> str:
    if not email or exp <= 0:
        return ""
    header = {"alg": "none", "typ": "JWT"}
    auth_payload = {
        "chatgpt_account_id": str(chatgpt_account_id or "").strip(),
        "chatgpt_user_id": str(chatgpt_user_id or "").strip(),
        "plan_type": str(plan_type or "").strip(),
    }
    payload = {
        "email": email,
        "exp": int(exp),
        "iat": int(time.time()),
        AUTH_CLAIM_KEY: auth_payload,
    }
    return f"{_b64url_encode_json(header)}.{_b64url_encode_json(payload)}."


def normalize_token_data(
    token_data: Dict[str, Any],
    *,
    default_type: str = "codex",
) -> Dict[str, Any]:
    source = copy.deepcopy(token_data if isinstance(token_data, dict) else {})
    credentials = source.get("credentials") if isinstance(source.get("credentials"), dict) else {}
    user = source.get("user") if isinstance(source.get("user"), dict) else {}
    account = source.get("account") if isinstance(source.get("account"), dict) else {}

    access_token = _first_non_empty_str(
        source.get("access_token"),
        source.get("accessToken"),
        credentials.get("access_token"),
        credentials.get("accessToken"),
    )
    refresh_token = _first_non_empty_str(
        source.get("refresh_token"),
        source.get("refreshToken"),
        credentials.get("refresh_token"),
        credentials.get("refreshToken"),
    )
    id_token = _first_non_empty_str(
        source.get("id_token"),
        source.get("idToken"),
        credentials.get("id_token"),
        credentials.get("idToken"),
    )
    session_token = _first_non_empty_str(
        source.get("session_token"),
        source.get("sessionToken"),
        credentials.get("session_token"),
        credentials.get("sessionToken"),
    )

    access_payload = decode_jwt_payload(access_token)
    access_auth = _auth_claims(access_payload)
    id_payload = decode_jwt_payload(id_token)
    id_auth = _auth_claims(id_payload)

    email = _first_non_empty_str(
        source.get("email"),
        credentials.get("email"),
        user.get("email"),
        id_payload.get("email"),
        access_payload.get("email"),
    ).lower()
    chatgpt_account_id = _first_non_empty_str(
        source.get("chatgpt_account_id"),
        source.get("account_id"),
        credentials.get("chatgpt_account_id"),
        credentials.get("account_id"),
        account.get("id"),
        id_auth.get("chatgpt_account_id"),
        access_auth.get("chatgpt_account_id"),
    )
    chatgpt_user_id = _first_non_empty_str(
        source.get("chatgpt_user_id"),
        credentials.get("chatgpt_user_id"),
        user.get("id"),
        id_auth.get("chatgpt_user_id"),
        access_auth.get("chatgpt_user_id"),
    )
    plan_type = _first_non_empty_str(
        source.get("plan_type"),
        credentials.get("plan_type"),
        id_auth.get("plan_type"),
        access_auth.get("plan_type"),
    )

    expires_epoch = max(
        _epoch_from_value(id_payload.get("exp")),
        _epoch_from_value(access_payload.get("exp")),
        _epoch_from_value(source.get("expires_at")),
        _epoch_from_value(source.get("expired")),
        _epoch_from_value(source.get("expires")),
        _epoch_from_value(credentials.get("expires_at")),
        _epoch_from_value(credentials.get("expired")),
        _epoch_from_value(source.get("exp")),
        _epoch_from_value(credentials.get("exp")),
    )
    expires_at = _first_non_empty_str(
        source.get("expires_at"),
        source.get("expired"),
        credentials.get("expires_at"),
        credentials.get("expired"),
        _rfc3339_from_epoch(expires_epoch),
    )
    last_refresh = _first_non_empty_str(
        source.get("last_refresh"),
        credentials.get("last_refresh"),
    )

    id_email = _first_non_empty_str(id_payload.get("email"))
    id_account_id = _first_non_empty_str(id_auth.get("chatgpt_account_id"))
    if email and expires_epoch > 0 and (not id_token or not id_email or not id_account_id):
        compat_id_token = build_compat_id_token(
            email=email,
            exp=expires_epoch,
            chatgpt_account_id=chatgpt_account_id,
            chatgpt_user_id=chatgpt_user_id,
            plan_type=plan_type,
        )
        if compat_id_token:
            id_token = compat_id_token

    normalized = dict(source)
    if access_token:
        normalized["access_token"] = access_token
    if refresh_token:
        normalized["refresh_token"] = refresh_token
    if id_token:
        normalized["id_token"] = id_token
    if session_token:
        normalized["session_token"] = session_token
    if email:
        normalized["email"] = email
    if chatgpt_account_id:
        normalized["account_id"] = chatgpt_account_id
        normalized["chatgpt_account_id"] = chatgpt_account_id
    if chatgpt_user_id:
        normalized["chatgpt_user_id"] = chatgpt_user_id
    if plan_type:
        normalized["plan_type"] = plan_type
    if expires_at:
        normalized["expires_at"] = expires_at
        normalized["expired"] = expires_at
    if last_refresh:
        normalized["last_refresh"] = last_refresh
    elif access_token or refresh_token or session_token:
        normalized["last_refresh"] = _rfc3339_from_epoch(int(time.time()))
    if default_type and not str(normalized.get("type") or "").strip():
        normalized["type"] = default_type

    normalized_credentials = dict(credentials)
    if access_token:
        normalized_credentials["access_token"] = access_token
    if refresh_token:
        normalized_credentials["refresh_token"] = refresh_token
    if id_token:
        normalized_credentials["id_token"] = id_token
    if session_token:
        normalized_credentials["session_token"] = session_token
    if chatgpt_account_id:
        normalized_credentials["account_id"] = chatgpt_account_id
        normalized_credentials["chatgpt_account_id"] = chatgpt_account_id
    if chatgpt_user_id:
        normalized_credentials["chatgpt_user_id"] = chatgpt_user_id
    if plan_type:
        normalized_credentials["plan_type"] = plan_type
    if expires_epoch > 0:
        normalized_credentials["expires_at"] = expires_epoch
    if last_refresh:
        normalized_credentials["last_refresh"] = last_refresh
    if normalized_credentials:
        normalized["credentials"] = normalized_credentials

    return normalized
