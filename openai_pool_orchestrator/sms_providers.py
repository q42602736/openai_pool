"""
SMS Provider 抽象层
当前支持兼容 handler_api.php 风格的短信平台：
- HeroSMS
- SMSBower
用于浏览器模式2自动取号与短信验证码轮询。
"""

from __future__ import annotations

import time
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from curl_cffi import requests


HERO_SMS_CANCEL_MIN_WAIT_SECONDS = 120


DEFAULT_PHONE_COUNTRIES: List[Dict[str, Any]] = [
    {"isoCode": "GB", "dialCode": "44", "name": "英国", "aliases": ["United Kingdom", "UK", "Britain", "Great Britain"]},
    {"isoCode": "US", "dialCode": "1", "name": "美国", "aliases": ["United States", "USA", "America"]},
    {"isoCode": "CA", "dialCode": "1", "name": "加拿大", "aliases": ["Canada"]},
    {"isoCode": "AU", "dialCode": "61", "name": "澳大利亚", "aliases": ["Australia"]},
    {"isoCode": "NZ", "dialCode": "64", "name": "新西兰", "aliases": ["New Zealand"]},
    {"isoCode": "IE", "dialCode": "353", "name": "爱尔兰", "aliases": ["Ireland"]},
    {"isoCode": "DE", "dialCode": "49", "name": "德国", "aliases": ["Germany", "Deutschland"]},
    {"isoCode": "FR", "dialCode": "33", "name": "法国", "aliases": ["France"]},
    {"isoCode": "ES", "dialCode": "34", "name": "西班牙", "aliases": ["Spain"]},
    {"isoCode": "IT", "dialCode": "39", "name": "意大利", "aliases": ["Italy"]},
    {"isoCode": "NL", "dialCode": "31", "name": "荷兰", "aliases": ["Netherlands", "Holland"]},
    {"isoCode": "BE", "dialCode": "32", "name": "比利时", "aliases": ["Belgium"]},
    {"isoCode": "AT", "dialCode": "43", "name": "奥地利", "aliases": ["Austria"]},
    {"isoCode": "CH", "dialCode": "41", "name": "瑞士", "aliases": ["Switzerland"]},
    {"isoCode": "SE", "dialCode": "46", "name": "瑞典", "aliases": ["Sweden"]},
    {"isoCode": "NO", "dialCode": "47", "name": "挪威", "aliases": ["Norway"]},
    {"isoCode": "DK", "dialCode": "45", "name": "丹麦", "aliases": ["Denmark"]},
    {"isoCode": "FI", "dialCode": "358", "name": "芬兰", "aliases": ["Finland"]},
    {"isoCode": "PL", "dialCode": "48", "name": "波兰", "aliases": ["Poland"]},
    {"isoCode": "PT", "dialCode": "351", "name": "葡萄牙", "aliases": ["Portugal"]},
    {"isoCode": "CZ", "dialCode": "420", "name": "捷克", "aliases": ["Czech Republic", "Czechia"]},
    {"isoCode": "GR", "dialCode": "30", "name": "希腊", "aliases": ["Greece"]},
    {"isoCode": "RO", "dialCode": "40", "name": "罗马尼亚", "aliases": ["Romania"]},
    {"isoCode": "HU", "dialCode": "36", "name": "匈牙利", "aliases": ["Hungary"]},
    {"isoCode": "TR", "dialCode": "90", "name": "土耳其", "aliases": ["Turkey", "Turkiye"]},
    {"isoCode": "IL", "dialCode": "972", "name": "以色列", "aliases": ["Israel"]},
    {"isoCode": "AE", "dialCode": "971", "name": "阿联酋", "aliases": ["UAE", "United Arab Emirates"]},
    {"isoCode": "SA", "dialCode": "966", "name": "沙特阿拉伯", "aliases": ["Saudi Arabia"]},
    {"isoCode": "SG", "dialCode": "65", "name": "新加坡", "aliases": ["Singapore"]},
    {"isoCode": "MY", "dialCode": "60", "name": "马来西亚", "aliases": ["Malaysia"]},
    {"isoCode": "TH", "dialCode": "66", "name": "泰国", "aliases": ["Thailand"]},
    {"isoCode": "VN", "dialCode": "84", "name": "越南", "aliases": ["Vietnam"]},
    {"isoCode": "PH", "dialCode": "63", "name": "菲律宾", "aliases": ["Philippines"]},
    {"isoCode": "ID", "dialCode": "62", "name": "印度尼西亚", "aliases": ["Indonesia"]},
    {"isoCode": "IN", "dialCode": "91", "name": "印度", "aliases": ["India"]},
    {"isoCode": "JP", "dialCode": "81", "name": "日本", "aliases": ["Japan"]},
    {"isoCode": "KR", "dialCode": "82", "name": "韩国", "aliases": ["South Korea", "Korea Republic"]},
    {"isoCode": "HK", "dialCode": "852", "name": "中国香港", "aliases": ["Hong Kong"]},
    {"isoCode": "TW", "dialCode": "886", "name": "中国台湾", "aliases": ["Taiwan"]},
    {"isoCode": "BR", "dialCode": "55", "name": "巴西", "aliases": ["Brazil"]},
    {"isoCode": "MX", "dialCode": "52", "name": "墨西哥", "aliases": ["Mexico"]},
    {"isoCode": "AR", "dialCode": "54", "name": "阿根廷", "aliases": ["Argentina"]},
    {"isoCode": "CL", "dialCode": "56", "name": "智利", "aliases": ["Chile"]},
    {"isoCode": "CO", "dialCode": "57", "name": "哥伦比亚", "aliases": ["Colombia"]},
    {"isoCode": "PE", "dialCode": "51", "name": "秘鲁", "aliases": ["Peru"]},
    {"isoCode": "ZA", "dialCode": "27", "name": "南非", "aliases": ["South Africa"]},
    {"isoCode": "EG", "dialCode": "20", "name": "埃及", "aliases": ["Egypt"]},
    {"isoCode": "NG", "dialCode": "234", "name": "尼日利亚", "aliases": ["Nigeria"]},
]


def _normalize_proxy_url(proxy: str) -> str:
    value = str(proxy or "").strip()
    if not value:
        return ""
    if "://" in value:
        return value
    if ":" in value:
        return f"http://{value}"
    return ""


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


class SMSProvider(ABC):
    @abstractmethod
    def acquire_number(
        self,
        *,
        proxy: str = "",
        stop_event: Optional[threading.Event] = None,
    ) -> Dict[str, Any]:
        """返回至少包含 activation_id / phone_number 的字典。"""

    @abstractmethod
    def mark_ready(self, activation_id: str, *, proxy: str = "") -> None:
        """标记号码已准备接收短信。"""

    @abstractmethod
    def wait_for_code(
        self,
        activation_id: str,
        *,
        proxy: str = "",
        timeout_seconds: int = 300,
        poll_interval_seconds: float = 5.0,
        stop_event: Optional[threading.Event] = None,
    ) -> str:
        """轮询短信验证码，超时或停止时返回空字符串。"""

    def complete(self, activation_id: str, *, proxy: str = "") -> None:
        return None

    def cancel(self, activation_id: str, *, proxy: str = "") -> None:
        return None

    def get_balance(self, *, proxy: str = "") -> Optional[float]:
        return None

    def peek_code(self, activation_id: str, *, proxy: str = "") -> str:
        return ""


class HeroSMSAcquireRetryableError(RuntimeError):
    """HeroSMS 当前轮无号，可在当前流程内继续重试。"""


class HeroSMSAcquireStoppedError(RuntimeError):
    """HeroSMS 取号过程中收到停止请求，当前流程应立即收尾。"""


HANDLER_API_PROVIDER_LABELS: Dict[str, str] = {
    "hero_sms": "HeroSMS",
    "smsbower": "SMSBower",
}

SMSBOWER_AUTO_COUNTRY_ID = 0
SMSBOWER_EXCLUDED_COUNTRY_ISO_CODES = {"ID", "PH", "RO"}
SMSBOWER_EXCLUDED_COUNTRY_NAMES = {
    "indonesia",
    "indonesian",
    "philippines",
    "philippine",
    "romania",
    "romanian",
    "印度尼西亚",
    "菲律宾",
    "罗马尼亚",
}


def normalize_handler_api_country(value: Any, *, default: int = 16, allow_zero: bool = False) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return int(default)
    if allow_zero and parsed == 0:
        return 0
    if parsed >= 1:
        return parsed
    return int(default)


def _build_default_country_catalogs() -> tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    catalog_by_iso: Dict[str, Dict[str, Any]] = {
        str(item.get("isoCode") or "").strip().upper(): item
        for item in DEFAULT_PHONE_COUNTRIES
        if str(item.get("isoCode") or "").strip()
    }
    catalog_by_dial: Dict[str, Dict[str, Any]] = {
        str(item.get("dialCode") or "").strip().lstrip("+"): item
        for item in DEFAULT_PHONE_COUNTRIES
        if str(item.get("dialCode") or "").strip()
    }
    return catalog_by_iso, catalog_by_dial


def normalize_handler_api_country_row(
    *,
    country_id: Any,
    api_name: Any = "",
    iso_code: Any = "",
    dial_code: Any = "",
) -> Dict[str, Any]:
    parsed_country_id = HeroSMSProvider._parse_integer(country_id)
    normalized_iso = str(iso_code or "").strip().upper()
    normalized_dial = str(dial_code or "").strip().lstrip("+")
    catalog_by_iso, catalog_by_dial = _build_default_country_catalogs()
    catalog_item = catalog_by_iso.get(normalized_iso) or catalog_by_dial.get(normalized_dial) or {}
    display_name = str(
        catalog_item.get("name")
        or api_name
        or normalized_iso
        or normalized_dial
        or parsed_country_id
        or ""
    ).strip()
    return {
        "hero_sms_country": int(parsed_country_id or 0),
        "name": display_name,
        "api_name": str(api_name or "").strip(),
        "iso_code": normalized_iso,
        "dial_code": normalized_dial,
    }


def is_virtual_phone_country_name(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    hints = (
        "virtual",
        "voip",
        "non-fixed",
        "non fixed",
        "internet",
        "online",
    )
    return any(hint in text for hint in hints)


def is_smsbower_excluded_country(*, iso_code: Any = "", name: Any = "", api_name: Any = "") -> bool:
    normalized_iso = str(iso_code or "").strip().upper()
    if normalized_iso in SMSBOWER_EXCLUDED_COUNTRY_ISO_CODES:
        return True
    haystacks = [
        str(name or "").strip().lower(),
        str(api_name or "").strip().lower(),
    ]
    return any(any(blocked in text for blocked in SMSBOWER_EXCLUDED_COUNTRY_NAMES) for text in haystacks if text)


def parse_price_range(value: Any) -> tuple[Optional[float], Optional[float]]:
    text = str(value or "").strip()
    if not text:
        return None, None
    normalized = text.replace("—", "-").replace("–", "-").replace("~", "-").replace(" ", "")
    if "-" not in normalized:
        single = HeroSMSProvider._parse_number(normalized)
        return single, single
    left_text, right_text = normalized.split("-", 1)
    left_number = HeroSMSProvider._parse_number(left_text)
    right_number = HeroSMSProvider._parse_number(right_text)
    if left_number is None and right_number is None:
        return None, None
    if left_number is None:
        left_number = right_number
    if right_number is None:
        right_number = left_number
    if left_number is None or right_number is None:
        return None, None
    return (left_number, right_number) if left_number <= right_number else (right_number, left_number)


def _interruptible_sleep(seconds: float, stop_event: Optional[threading.Event] = None) -> bool:
    duration = max(0.0, float(seconds or 0.0))
    if duration <= 0:
        return bool(stop_event and stop_event.is_set())
    if stop_event is None:
        time.sleep(duration)
        return False
    return bool(stop_event.wait(duration))


class HeroSMSProvider(SMSProvider):
    BASE_URL = "https://hero-sms.com/stubs/handler_api.php"
    API_V1_BASE_URL = "https://hero-sms.com/api/v1"
    MAX_ACCEPTABLE_PRICE_RATIO = 1.05
    MAX_ACCEPTABLE_PRICE_DELTA = 0.0005
    AUTO_PRICE_ESCALATION_RATIO = 1.05
    AUTO_PRICE_ESCALATION_DELTA = 0.002
    PRICE_COMPARE_EPSILON = 1e-9

    def __init__(
        self,
        *,
        api_key: str,
        service: str = "",
        country: int = 16,
        operator: str = "",
        target_price: Any = "",
        fixed_price: bool = True,
        max_acquire_retries: int = 5,
    ) -> None:
        self.api_key = str(api_key or "").strip()
        self.service = str(service or "").strip()
        self.country = normalize_handler_api_country(
            country,
            default=16,
            allow_zero=self._supports_global_auto_country(),
        )
        self.operator = str(operator or "").strip()
        self.target_price_raw = str(target_price or "").strip()
        self.min_target_price, self.max_target_price = parse_price_range(self.target_price_raw)
        self.target_price = self.max_target_price
        self.fixed_price = _as_bool(fixed_price, default=True) and self.min_target_price is not None and self.max_target_price is not None
        try:
            self.max_acquire_retries = max(1, int(max_acquire_retries or 5))
        except (TypeError, ValueError):
            self.max_acquire_retries = 5

    def _supports_global_auto_country(self) -> bool:
        return False

    def _resolve_catalog_country(self, *, proxy: str = "") -> Dict[str, Any]:
        country_id = int(self.country or 16)
        if country_id == 16:
            return {"hero_sms_country": 16, "name": "英国", "iso_code": "GB", "dial_code": "44", "api_name": ""}
        try:
            countries = self.list_countries(proxy=proxy)
        except Exception:
            countries = []
        catalog_by_iso: Dict[str, Dict[str, Any]] = {
            str(item.get("isoCode") or "").strip().upper(): item
            for item in DEFAULT_PHONE_COUNTRIES
            if str(item.get("isoCode") or "").strip()
        }
        catalog_by_dial: Dict[str, Dict[str, Any]] = {
            str(item.get("dialCode") or "").strip().lstrip("+"): item
            for item in DEFAULT_PHONE_COUNTRIES
            if str(item.get("dialCode") or "").strip()
        }
        for row in countries:
            if self._parse_integer(row.get("heroSmsCountry")) != country_id:
                continue
            iso_code = str(row.get("isoCode") or "").strip().upper()
            dial_code = str(row.get("dialCode") or "").strip().lstrip("+")
            catalog_item = catalog_by_iso.get(iso_code) or catalog_by_dial.get(dial_code) or {}
            return {
                "hero_sms_country": country_id,
                "name": str(catalog_item.get("name") or row.get("apiName") or "").strip(),
                "iso_code": iso_code,
                "dial_code": dial_code,
                "api_name": str(row.get("apiName") or "").strip(),
            }
        return {
            "hero_sms_country": country_id,
            "name": "",
            "iso_code": "",
            "dial_code": "",
            "api_name": "",
        }

    @staticmethod
    def _parse_number(value: Any) -> Optional[float]:
        if value is None:
            return None
        text = str(value).strip()
        digits = "".join(ch for ch in text if ch.isdigit() or ch == ".")
        if not digits:
            return None
        try:
            return float(digits)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_integer(value: Any) -> Optional[int]:
        if value is None:
            return None
        text = str(value).strip()
        digits = "".join(ch for ch in text if ch.isdigit() or ch == "-")
        if not digits:
            return None
        try:
            return int(digits)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _price_tier_has_usable_stock(item: Any) -> bool:
        if not isinstance(item, dict):
            return False
        count = HeroSMSProvider._parse_integer(item.get("count"))
        physical_count = HeroSMSProvider._parse_integer(item.get("physical_count"))
        if count is not None:
            return count > 0
        if physical_count is not None:
            return physical_count > 0
        return False

    @classmethod
    def _select_preferred_price_tier(cls, tiers: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not tiers:
            return None
        in_stock = [item for item in tiers if cls._price_tier_has_usable_stock(item)]
        if in_stock:
            return in_stock[0]
        return tiers[0]

    def _resolve_actual_price_ceiling(self, expected_price: Optional[float]) -> Optional[float]:
        if self.max_target_price is not None:
            return self.max_target_price
        if expected_price is None:
            return None
        return max(
            expected_price * self.MAX_ACCEPTABLE_PRICE_RATIO,
            expected_price + self.MAX_ACCEPTABLE_PRICE_DELTA,
        )

    def _resolve_actual_price_floor(self, expected_price: Optional[float]) -> Optional[float]:
        if self.min_target_price is not None:
            return self.min_target_price
        return expected_price

    def _has_price_range(self) -> bool:
        return (
            self.min_target_price is not None
            and self.max_target_price is not None
            and abs(self.min_target_price - self.max_target_price) > self.PRICE_COMPARE_EPSILON
        )

    def _price_target_label(self) -> str:
        if self.min_target_price is None and self.max_target_price is None:
            return "-"
        if self._has_price_range():
            return f"${self.min_target_price}-${self.max_target_price}"
        return f"${self.max_target_price if self.max_target_price is not None else self.min_target_price}"

    def _price_in_target_range(self, price: Any) -> bool:
        parsed_price = self._parse_number(price)
        if parsed_price is None:
            return False
        if self.min_target_price is not None and parsed_price < (self.min_target_price - self.PRICE_COMPARE_EPSILON):
            return False
        if self.max_target_price is not None and parsed_price > (self.max_target_price + self.PRICE_COMPARE_EPSILON):
            return False
        return True

    def _get_price_mode(self) -> str:
        if self.max_target_price is None and self.min_target_price is None:
            return "auto"
        if self._has_price_range():
            return "range"
        if self.fixed_price:
            return "fixed"
        return "ceiling"

    def _provider_label(self) -> str:
        return "SMSBower" if "smsbower" in str(self.BASE_URL or "").lower() else "HeroSMS"

    @classmethod
    def _is_matching_price_tier(cls, left: Any, right: Any) -> bool:
        left_number = cls._parse_number(left)
        right_number = cls._parse_number(right)
        if left_number is None or right_number is None:
            return False
        return abs(left_number - right_number) <= cls.PRICE_COMPARE_EPSILON

    def _request(self, action: str, *, proxy: str = "", timeout_seconds: int = 30, **params: Any) -> Any:
        normalized_proxy = _normalize_proxy_url(proxy)
        proxies = {"http": normalized_proxy, "https": normalized_proxy} if normalized_proxy else None
        response = requests.get(
            self.BASE_URL,
            params={
                "api_key": self.api_key,
                "action": action,
                **params,
            },
            proxies=proxies,
            timeout=timeout_seconds,
            impersonate="chrome",
        )
        content_type = str(response.headers.get("content-type") or "").lower()
        if "application/json" in content_type:
            try:
                return response.json()
            except Exception:
                pass
        text = str(response.text or "").strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return response.json()
            except Exception:
                return text
        return text

    def _request_offers(self, *, proxy: str = "", timeout_seconds: int = 30, service: str = "", country: Optional[int] = None) -> Any:
        normalized_proxy = _normalize_proxy_url(proxy)
        proxies = {"http": normalized_proxy, "https": normalized_proxy} if normalized_proxy else None
        params: Dict[str, Any] = {}
        if service:
            params["services"] = service
        if country is not None:
            params["countries"] = str(int(country))
        response = requests.get(
            f"{self.API_V1_BASE_URL}/activations/offers",
            headers={
                "Authorization": f"ApiKey {self.api_key}",
                "Accept": "application/json",
            },
            params=params,
            proxies=proxies,
            timeout=timeout_seconds,
            impersonate="chrome",
        )
        content_type = str(response.headers.get("content-type") or "").lower()
        if "application/json" in content_type:
            return response.json()
        text = str(response.text or "").strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return response.json()
            except Exception:
                return text
        return text

    def get_balance(self, *, proxy: str = "") -> Optional[float]:
        data = self._request("getBalance", proxy=proxy)
        if isinstance(data, str):
            text = str(data or "").strip()
            if text.startswith("ACCESS_BALANCE:"):
                return self._parse_number(text.split(":", 1)[1].strip())
            return self._parse_number(text)
        if isinstance(data, dict):
            return self._parse_number(
                data.get("balance")
                or data.get("amount")
                or data.get("available_balance")
            )
        return None

    def list_services(self, *, proxy: str = "") -> List[Dict[str, Any]]:
        data = self._request("getServicesList", proxy=proxy)
        if isinstance(data, str):
            try:
                import json as _json
                data = _json.loads(data)
            except Exception:
                return []
        payload = data.get("services") if isinstance(data, dict) and isinstance(data.get("services"), list) else data
        if not isinstance(payload, list):
            return []
        rows: List[Dict[str, Any]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            code = str(item.get("code") or item.get("service") or item.get("id") or "").strip()
            name = str(item.get("name") or item.get("title") or item.get("service_name") or "").strip()
            if not code:
                continue
            rows.append({
                "code": code,
                "name": name or code,
            })
        rows.sort(key=lambda item: (str(item.get("name") or ""), str(item.get("code") or "")))
        return rows

    @staticmethod
    def _parse_countries_response(data: Any) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []

        def push_country(country_id: Any, payload: Any) -> None:
            parsed_country_id = HeroSMSProvider._parse_integer(country_id)
            if parsed_country_id is None:
                return
            if isinstance(payload, str):
                result.append({
                    "heroSmsCountry": parsed_country_id,
                    "apiName": payload.strip(),
                    "isoCode": "",
                    "dialCode": "",
                })
                return
            if not isinstance(payload, dict):
                return
            result.append({
                "heroSmsCountry": parsed_country_id,
                "apiName": str(
                    payload.get("name")
                    or payload.get("country")
                    or payload.get("title")
                    or payload.get("eng")
                    or payload.get("en")
                    or payload.get("label")
                    or ""
                ).strip(),
                "isoCode": str(
                    payload.get("isoCode")
                    or payload.get("iso")
                    or payload.get("code")
                    or payload.get("iso2")
                    or ""
                ).strip().upper(),
                "dialCode": str(
                    payload.get("dialCode")
                    or payload.get("phoneCode")
                    or payload.get("prefix")
                    or ""
                ).strip().lstrip("+"),
            })

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    push_country(item.get("id") or item.get("countryId") or item.get("country_id"), item)
            return result

        if not isinstance(data, dict):
            return result

        for key, value in data.items():
            if str(key).isdigit():
                push_country(key, value)
                continue
            if isinstance(value, dict):
                nested_id = value.get("id") or value.get("countryId") or value.get("country_id")
                if nested_id is not None:
                    push_country(nested_id, value)
        if result:
            return result
        for key in ("data", "result", "countries", "response"):
            nested = data.get(key)
            if nested:
                nested_result = HeroSMSProvider._parse_countries_response(nested)
                if nested_result:
                    return nested_result
        return result

    def list_countries(self, *, proxy: str = "") -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        seen_ids: set[int] = set()
        for action in ("getCountries", "getCountriesList"):
            try:
                data = self._request(action, proxy=proxy)
            except Exception:
                continue
            if isinstance(data, str):
                try:
                    import json as _json
                    data = _json.loads(data)
                except Exception:
                    continue
            rows = self._parse_countries_response(data)
            for row in rows:
                country_id = self._parse_integer(row.get("heroSmsCountry"))
                if country_id is None or country_id in seen_ids:
                    continue
                seen_ids.add(country_id)
                merged.append({
                    "heroSmsCountry": country_id,
                    "apiName": str(row.get("apiName") or "").strip(),
                    "isoCode": str(row.get("isoCode") or "").strip().upper(),
                    "dialCode": str(row.get("dialCode") or "").strip().lstrip("+"),
                })
        return merged

    @staticmethod
    def _parse_top_countries_response(data: Any) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []

        def push_row(item: Any) -> None:
            if not isinstance(item, dict):
                return
            country_id = HeroSMSProvider._parse_integer(
                item.get("country") or item.get("countryId") or item.get("country_id") or item.get("id")
            )
            price = HeroSMSProvider._parse_number(
                item.get("price") or item.get("cost") or item.get("retail_price") or item.get("retailPrice")
            )
            count = HeroSMSProvider._parse_integer(
                item.get("count") or item.get("qty") or item.get("available") or item.get("stock") or item.get("total")
            )
            if country_id is None or price is None:
                return
            rows.append({
                "heroSmsCountry": country_id,
                "price": price,
                "count": count,
                "apiName": str(
                    item.get("name")
                    or item.get("countryName")
                    or item.get("country_name")
                    or item.get("title")
                    or item.get("text")
                    or item.get("label")
                    or item.get("countryText")
                    or ""
                ).strip(),
                "isoCode": str(
                    item.get("isoCode") or item.get("iso") or item.get("code") or item.get("iso2") or ""
                ).strip().upper(),
                "dialCode": str(
                    item.get("dialCode") or item.get("phoneCode") or item.get("prefix") or item.get("phone_prefix") or ""
                ).strip().lstrip("+"),
            })

        if isinstance(data, list):
            for item in data:
                push_row(item)
            return rows
        if not isinstance(data, dict):
            return rows
        for key, value in data.items():
            if str(key).isdigit() and isinstance(value, dict):
                push_row(value)
        if rows:
            return rows
        for key in ("data", "result", "response"):
            nested = data.get(key)
            if nested:
                nested_rows = HeroSMSProvider._parse_top_countries_response(nested)
                if nested_rows:
                    return nested_rows
        return rows

    @staticmethod
    def _unwrap_price_matrix(raw: Any) -> Any:
        if not isinstance(raw, dict):
            return raw
        for key in ("data", "result", "prices", "countries", "response"):
            nested = raw.get(key)
            if isinstance(nested, dict):
                return HeroSMSProvider._unwrap_price_matrix(nested)
        return raw

    @staticmethod
    def _extract_price_from_node(node: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(node, dict):
            return None
        price = HeroSMSProvider._parse_number(
            node.get("cost") or node.get("price") or node.get("activationCost") or node.get("amount") or node.get("rate")
        )
        count = HeroSMSProvider._parse_integer(
            node.get("count") or node.get("qty") or node.get("available") or node.get("stock") or node.get("total")
        )
        physical_count = HeroSMSProvider._parse_integer(
            node.get("physicalCount") or node.get("physical_count") or node.get("realCount")
        )
        if price is None and count is None and physical_count is None:
            return None
        return {"price": price, "count": count, "physical_count": physical_count}

    @classmethod
    def _extract_country_price_options(cls, raw: Any, country_id: int, service: str) -> List[Dict[str, Any]]:
        matrix = cls._unwrap_price_matrix(raw)
        service_key = str(service or "").strip()
        id_key = str(country_id)

        def walk(node: Any, results: List[Dict[str, Any]], seen: set[tuple[Any, Any, Any]]) -> None:
            if isinstance(node, dict):
                extracted = cls._extract_price_from_node(node)
                if extracted and extracted.get("price") is not None:
                    key = (
                        extracted.get("price"),
                        extracted.get("count"),
                        extracted.get("physical_count"),
                    )
                    if key not in seen:
                        seen.add(key)
                        results.append(extracted)
                for value in node.values():
                    walk(value, results, seen)
            elif isinstance(node, list):
                for item in node:
                    walk(item, results, seen)

        candidates: List[Any] = []
        if isinstance(matrix, list):
            for item in matrix:
                if not isinstance(item, dict):
                    continue
                item_country_id = cls._parse_integer(
                    item.get("countryId") or item.get("country_id") or item.get("country") or item.get("id")
                )
                if item_country_id != country_id:
                    continue
                candidates.append(item)
                service_node = item.get(service_key) or item.get("serviceData") or item.get("data")
                if service_node is not None:
                    candidates.append(service_node)
        elif isinstance(matrix, dict):
            candidates.extend([
                (matrix.get(service_key) or {}).get(id_key) if isinstance(matrix.get(service_key), dict) else None,
                (matrix.get(id_key) or {}).get(service_key) if isinstance(matrix.get(id_key), dict) else None,
                (matrix.get(id_key) or {}).get("default") if isinstance(matrix.get(id_key), dict) else None,
                matrix.get(id_key),
                matrix.get(service_key),
            ])

        options: List[Dict[str, Any]] = []
        seen: set[tuple[Any, Any, Any]] = set()
        for candidate in candidates:
            walk(candidate, options, seen)
        options.sort(key=lambda item: (float(item.get("price") or 999999.0), -int(item.get("count") or 0)))
        return options

    @classmethod
    def _extract_country_price(cls, raw: Any, country_id: int, service: str) -> Optional[Dict[str, Any]]:
        options = cls._extract_country_price_options(raw, country_id, service)
        return options[0] if options else None

    @classmethod
    def _extract_offers_price_tiers(cls, raw: Any, country_id: int, service: str) -> List[Dict[str, Any]]:
        payload = raw.get("data") if isinstance(raw, dict) and isinstance(raw.get("data"), dict) else raw
        if not isinstance(payload, dict):
            return []
        service_node = payload.get(str(service or "").strip())
        if not isinstance(service_node, dict):
            return []
        country_node = service_node.get(str(country_id))
        if not isinstance(country_node, dict):
            return []

        price_map = country_node.get("map")
        counts = country_node.get("counts") if isinstance(country_node.get("counts"), dict) else {}
        prices = country_node.get("prices") if isinstance(country_node.get("prices"), dict) else {}
        total_count = cls._parse_integer(counts.get("total"))
        physical_count = cls._parse_integer(counts.get("physical"))
        default_price_count = cls._parse_integer(counts.get("defaultPrice"))
        default_price = cls._parse_number(prices.get("default"))
        min_price = cls._parse_number(prices.get("min"))
        retail_price = cls._parse_number(prices.get("retail"))

        rows: List[Dict[str, Any]] = []
        seen: set[tuple[Any, Any, Any, Any]] = set()

        if isinstance(price_map, dict):
            for key, value in price_map.items():
                price = cls._parse_number(key)
                count = cls._parse_integer(value)
                if price is None:
                    continue
                signature = (
                    price,
                    count,
                    physical_count,
                    default_price == price,
                )
                if signature in seen:
                    continue
                seen.add(signature)
                rows.append({
                    "price": price,
                    "count": count,
                    "physical_count": physical_count,
                    "is_default_price": bool(default_price is not None and price == default_price),
                    "is_min_price": bool(min_price is not None and price == min_price),
                    "default_price_count": default_price_count,
                    "total_count": total_count,
                    "retail_price": retail_price,
                    "source": "offers_map",
                    "signature": "|".join([
                        str(price),
                        str(count),
                        str(physical_count),
                        str(bool(default_price is not None and price == default_price)),
                    ]),
                })

        if (
            default_price is not None
            and (default_price_count is None or default_price_count > 0)
            and not any(
                cls._parse_number(item.get("price")) == default_price
                for item in rows
            )
        ):
            signature = (
                default_price,
                default_price_count,
                physical_count,
                True,
            )
            if signature not in seen:
                rows.append({
                    "price": default_price,
                    "count": default_price_count,
                    "physical_count": physical_count,
                    "is_default_price": True,
                    "is_min_price": bool(min_price is not None and default_price == min_price),
                    "default_price_count": default_price_count,
                    "total_count": total_count,
                    "retail_price": retail_price,
                    "source": "offers_default",
                    "signature": "|".join([
                        str(default_price),
                        str(default_price_count),
                        str(physical_count),
                        "True",
                    ]),
                })

        rows.sort(
            key=lambda item: (
                float(item.get("price") or 999999.0),
                -int(item.get("count") or 0),
                0 if item.get("is_default_price") else 1,
            )
        )
        return rows

    @classmethod
    def _format_price_tier_stock_for_display(cls, item: Dict[str, Any]) -> Optional[int]:
        count = cls._parse_integer(item.get("count"))
        if count is not None and count > 0:
            return count
        return None

    def get_top_countries_by_service(self, *, proxy: str = "") -> List[Dict[str, Any]]:
        for action in ("getTopCountriesByServiceRank", "getTopCountriesByService"):
            try:
                data = self._request(action, proxy=proxy, service=self.service)
            except Exception:
                continue
            if isinstance(data, str):
                try:
                    import json as _json
                    data = _json.loads(data)
                except Exception:
                    continue
            rows = self._parse_top_countries_response(data)
            if rows:
                rows.sort(key=lambda item: (float(item.get("price") or 999999.0), -int(item.get("count") or 0)))
                return rows
        return []

    def list_country_prices(self, countries: List[Dict[str, Any]], *, proxy: str = "") -> List[Dict[str, Any]]:
        matrix = None
        for action in ("getPricesVerification", "getPrices"):
            try:
                matrix = self._request(action, proxy=proxy, service=self.service)
                break
            except Exception:
                continue
        if matrix is None:
            return []
        if isinstance(matrix, str):
            try:
                import json as _json
                matrix = _json.loads(matrix)
            except Exception:
                return []
        priced: List[Dict[str, Any]] = []
        for country in countries:
            country_id = self._parse_integer(country.get("heroSmsCountry"))
            if country_id is None:
                continue
            parsed = self._extract_country_price(matrix, country_id, self.service)
            if not parsed or parsed.get("price") is None:
                continue
            priced.append({
                **country,
                "price": parsed.get("price"),
                "count": parsed.get("count"),
            })
        priced.sort(key=lambda item: (float(item.get("price") or 999999.0), -int(item.get("count") or 0)))
        return priced

    def get_operators(self, *, country: int, proxy: str = "") -> List[str]:
        data = self._request("getOperators", proxy=proxy, country=country)
        if not isinstance(data, dict):
            return []
        raw = data.get("countryOperators", {}).get(str(country)) or data.get("countryOperators", {}).get(int(country)) or []
        if not isinstance(raw, list):
            return []
        return [str(item or "").strip() for item in raw if str(item or "").strip()]

    def get_operator_quote_options(self, *, country: int, proxy: str = "") -> List[Dict[str, Any]]:
        operators = self.get_operators(country=country, proxy=proxy)
        if not operators:
            return []
        options: List[Dict[str, Any]] = []
        for operator in operators:
            try:
                data = self._request("getPrices", proxy=proxy, service=self.service, country=country, operator=operator)
                parsed = self._extract_country_price(data, country, self.service)
                options.append({
                    "operator": operator,
                    "price": parsed.get("price") if parsed else None,
                    "count": parsed.get("count") if parsed else None,
                    "physical_count": parsed.get("physical_count") if parsed else None,
                    "source": "operator",
                })
            except Exception as exc:
                options.append({
                    "operator": operator,
                    "price": None,
                    "count": None,
                    "physical_count": None,
                    "source": "operator",
                    "error": str(exc),
                })
        options.sort(key=lambda item: (float(item.get("price") or 999999.0), -int(item.get("count") or 0)))
        return options

    def get_price_tier_options(self, *, country: int, proxy: str = "") -> List[Dict[str, Any]]:
        try:
            offers_data = self._request_offers(proxy=proxy, service=self.service, country=country)
            offers_rows = self._extract_offers_price_tiers(offers_data, country, self.service)
            if offers_rows:
                return offers_rows
        except Exception:
            pass
        for action in ("getPricesVerification", "getPrices"):
            try:
                data = self._request(action, proxy=proxy, service=self.service, country=country)
            except Exception:
                continue
            if isinstance(data, str):
                try:
                    import json as _json
                    data = _json.loads(data)
                except Exception:
                    continue
            options = self._extract_country_price_options(data, country, self.service)
            if options:
                normalized: List[Dict[str, Any]] = []
                for item in options:
                    normalized.append({
                        "price": item.get("price"),
                        "count": item.get("count"),
                        "physical_count": item.get("physical_count"),
                        "is_default_price": False,
                        "is_min_price": False,
                        "default_price_count": None,
                        "total_count": None,
                        "retail_price": None,
                        "source": "compat_prices",
                        "signature": "|".join([
                            str(item.get("price")),
                            str(item.get("count")),
                            str(item.get("physical_count")),
                        ]),
                    })
                return normalized
        return []

    def resolve_country_and_operator(self, *, proxy: str = "") -> Dict[str, Any]:
        base = self._resolve_catalog_country(proxy=proxy)
        country_id = self._parse_integer(base.get("hero_sms_country"))
        if country_id is None:
            country_id = normalize_handler_api_country(
                self.country,
                default=16,
                allow_zero=self._supports_global_auto_country(),
            )
        aggregate_price = None
        aggregate_count = None
        price_tier_options = self.get_price_tier_options(country=country_id, proxy=proxy)
        preferred_price_tier = self._select_preferred_price_tier(price_tier_options)
        priced_rows = self.list_country_prices(
            [{
                "heroSmsCountry": country_id,
                "isoCode": base.get("iso_code"),
                "dialCode": base.get("dial_code"),
                "apiName": base.get("api_name"),
                "name": base.get("name"),
            }],
            proxy=proxy,
        )
        if priced_rows:
            aggregate_price = priced_rows[0].get("price")
            aggregate_count = priced_rows[0].get("count")
        if preferred_price_tier:
            aggregate_price = preferred_price_tier.get("price")
            aggregate_count = preferred_price_tier.get("count")
        selected_operator = str(self.operator or "").strip()
        operator_rows: List[Dict[str, Any]] = []
        selected_operator_price = None
        selected_operator_count = None
        if selected_operator:
            operator_rows = self.get_operator_quote_options(country=country_id, proxy=proxy)
            for row in operator_rows:
                if str(row.get("operator") or "").strip().lower() == selected_operator.lower():
                    selected_operator = str(row.get("operator") or "").strip()
                    selected_operator_price = row.get("price")
                    selected_operator_count = row.get("count")
                    break
        return {
            **base,
            "hero_sms_country": country_id,
            "aggregate_price": aggregate_price,
            "aggregate_count": aggregate_count,
            "price_tier_options": price_tier_options,
            "preferred_price_tier": preferred_price_tier or {},
            "target_price": self.target_price,
            "operator_options": operator_rows,
            "selected_operator": selected_operator,
            "selected_operator_price": selected_operator_price,
            "selected_operator_count": selected_operator_count,
        }

    def _ensure_fixed_price_matches_known_tier(self, selection: Dict[str, Any]) -> None:
        if not self.fixed_price or (self.min_target_price is None and self.max_target_price is None):
            return
        price_tier_options = selection.get("price_tier_options") if isinstance(selection.get("price_tier_options"), list) else []
        operator_options = selection.get("operator_options") if isinstance(selection.get("operator_options"), list) else []
        candidate_prices: List[Any] = []
        candidate_prices.extend(item.get("price") for item in price_tier_options if isinstance(item, dict))
        candidate_prices.extend(item.get("price") for item in operator_options if isinstance(item, dict))
        if selection.get("selected_operator_price") is not None:
            candidate_prices.append(selection.get("selected_operator_price"))
        if not candidate_prices:
            return
        if any(self._price_in_target_range(price) for price in candidate_prices):
            return
        normalized_prices = sorted(
            {
                round(float(price), 6)
                for price in candidate_prices
                if self._parse_number(price) is not None
            }
        )
        raise RuntimeError(
            f"{self._provider_label()} 固定价模式要求目标价格必须命中当前真实价档/区间: "
            + f"target={self._price_target_label()}, available={normalized_prices or '-'}。"
            + "如果你想手填一个区间上限，请改用“只作价格上限”。"
        )

    def _resolve_ceiling_price_candidates(self, selection: Dict[str, Any]) -> List[float]:
        if self.max_target_price is None or self.fixed_price:
            return []
        price_tier_options = selection.get("price_tier_options") if isinstance(selection.get("price_tier_options"), list) else []
        operator_options = selection.get("operator_options") if isinstance(selection.get("operator_options"), list) else []
        candidate_prices: List[float] = []
        for row in price_tier_options:
            if not isinstance(row, dict):
                continue
            price = self._parse_number(row.get("price"))
            if price is None or not self._price_in_target_range(price):
                continue
            candidate_prices.append(price)
        for row in operator_options:
            if not isinstance(row, dict):
                continue
            price = self._parse_number(row.get("price"))
            if price is None or not self._price_in_target_range(price):
                continue
            candidate_prices.append(price)
        selected_operator_price = self._parse_number(selection.get("selected_operator_price"))
        if selected_operator_price is not None and self._price_in_target_range(selected_operator_price):
            candidate_prices.append(selected_operator_price)
        normalized_prices = sorted({round(float(price), 6) for price in candidate_prices})
        return normalized_prices

    def _resolve_fixed_price_provider_ids(self, selection: Dict[str, Any]) -> List[int]:
        if not self.fixed_price or (self.min_target_price is None and self.max_target_price is None):
            return []
        rows = selection.get("price_tier_options") if isinstance(selection.get("price_tier_options"), list) else []
        provider_ids: List[int] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if not self._price_in_target_range(row.get("price")):
                continue
            raw_ids = row.get("provider_ids")
            if not isinstance(raw_ids, list):
                continue
            for provider_id in raw_ids:
                parsed_provider_id = self._parse_integer(provider_id)
                if parsed_provider_id is None or parsed_provider_id in provider_ids:
                    continue
                provider_ids.append(parsed_provider_id)
        return provider_ids

    def acquire_number(
        self,
        *,
        proxy: str = "",
        stop_event: Optional[threading.Event] = None,
    ) -> Dict[str, Any]:
        last_error = ""
        provider_label = self._provider_label()
        selection = self.resolve_country_and_operator(proxy=proxy)
        self._ensure_fixed_price_matches_known_tier(selection)
        selected_country_id = self._parse_integer(selection.get("hero_sms_country"))
        if selected_country_id is None:
            selected_country_id = normalize_handler_api_country(
                self.country,
                default=16,
                allow_zero=self._supports_global_auto_country(),
            )
        selected_operator = str(selection.get("selected_operator") or "").strip()
        operator_was_auto_selected = not str(self.operator or "").strip() and bool(selected_operator)
        price_tier_options = selection.get("price_tier_options") if isinstance(selection.get("price_tier_options"), list) else []
        auto_price_candidates = [
            item for item in price_tier_options
            if self._parse_number(item.get("price")) is not None
        ]
        exact_ceiling_candidates = self._resolve_ceiling_price_candidates(selection)
        exact_ceiling_mode = bool(self.max_target_price is not None and not self.fixed_price and exact_ceiling_candidates)
        hidden_ceiling_fallback = bool(self.max_target_price is not None and not self.fixed_price and not exact_ceiling_candidates)
        exact_fixed_provider_ids = self._resolve_fixed_price_provider_ids(selection)
        exact_ceiling_index = 0
        auto_price_index = 0
        auto_price_floor = None
        expected_price = self.max_target_price
        if expected_price is None:
            expected_price = self._parse_number(selection.get("selected_operator_price"))
        if expected_price is None:
            expected_price = self._parse_number(selection.get("aggregate_price"))
        if exact_ceiling_mode:
            expected_price = exact_ceiling_candidates[0]
        if expected_price is not None:
            auto_price_floor = expected_price
        if expected_price is not None:
            for index, item in enumerate(auto_price_candidates):
                if self._parse_number(item.get("price")) == expected_price:
                    auto_price_index = index
                    break
        balance_before = self.get_balance(proxy=proxy)
        debug_events: List[str] = []
        country_candidates = selection.get("country_candidates") if isinstance(selection.get("country_candidates"), list) else []
        auto_country_mode = bool(selection.get("auto_country_mode")) and bool(country_candidates)
        country_candidate_index = 0

        def _apply_country_selection(country_selection: Dict[str, Any]) -> None:
            nonlocal selection
            nonlocal selected_country_id
            nonlocal selected_operator
            nonlocal operator_was_auto_selected
            nonlocal price_tier_options
            nonlocal auto_price_candidates
            nonlocal exact_ceiling_candidates
            nonlocal exact_ceiling_mode
            nonlocal hidden_ceiling_fallback
            nonlocal exact_fixed_provider_ids
            nonlocal exact_ceiling_index
            nonlocal auto_price_index
            nonlocal auto_price_floor
            nonlocal expected_price
            selection = dict(country_selection)
            selected_country_id = self._parse_integer(selection.get("hero_sms_country")) or selected_country_id
            selected_operator = str(selection.get("selected_operator") or "").strip()
            operator_was_auto_selected = not str(self.operator or "").strip() and bool(selected_operator)
            price_tier_options = selection.get("price_tier_options") if isinstance(selection.get("price_tier_options"), list) else []
            auto_price_candidates = [
                item for item in price_tier_options
                if self._parse_number(item.get("price")) is not None
            ]
            exact_ceiling_candidates = self._resolve_ceiling_price_candidates(selection)
            exact_ceiling_mode = bool(self.max_target_price is not None and not self.fixed_price and exact_ceiling_candidates)
            hidden_ceiling_fallback = bool(self.max_target_price is not None and not self.fixed_price and not exact_ceiling_candidates)
            exact_fixed_provider_ids = self._resolve_fixed_price_provider_ids(selection)
            exact_ceiling_index = 0
            auto_price_index = 0
            expected_price = self.max_target_price
            if expected_price is None:
                expected_price = self._parse_number(selection.get("selected_operator_price"))
            if expected_price is None:
                expected_price = self._parse_number(selection.get("aggregate_price"))
            if exact_ceiling_mode:
                expected_price = exact_ceiling_candidates[0]
            auto_price_floor = expected_price if expected_price is not None else None
            if expected_price is not None:
                for index, item in enumerate(auto_price_candidates):
                    if self._parse_number(item.get("price")) == expected_price:
                        auto_price_index = index
                        break

        if auto_country_mode:
            _apply_country_selection(country_candidates[0])
        else:
            _apply_country_selection(selection)

        def _build_failure_message(message: str) -> str:
            parts = [str(message or "").strip()]
            preview_rows: List[str] = []
            for item in price_tier_options[:8]:
                preview_rows.append(
                    f"${item.get('price') if item.get('price') is not None else '-'}"
                    + f"/stock={item.get('count') if item.get('count') is not None else '-'}"
                )
            if preview_rows:
                parts.append("price_tiers=" + ", ".join(preview_rows))
            if hidden_ceiling_fallback:
                parts.append(
                    "ceiling_mode=hidden_pool"
                    + f"(visible tiers within {self._price_target_label()}: none)"
                )
            if debug_events:
                parts.append("trace=" + " || ".join(str(item) for item in debug_events[:20]))
            return " | ".join(part for part in parts if part)

        for attempt in range(1, self.max_acquire_retries + 1):
            if stop_event is not None and stop_event.is_set():
                raise HeroSMSAcquireStoppedError(f"{provider_label} 取号已停止")
            current_operator = selected_operator
            debug_events.append(
                "第 "
                + str(attempt)
                + " 次尝试"
                + f"，运营商 {current_operator or 'ANY'}"
                + f"，价格模式 {self._get_price_mode()}"
                + (
                    f"，价格区间 {self._price_target_label()}"
                    if self._has_price_range()
                    else (
                        f"，价格上限 ${self.max_target_price}"
                        if self.max_target_price is not None and not self.fixed_price
                        else f"，目标价 {self._price_target_label()}"
                    )
                )
                + (
                    f"，预期从隐藏低价池中拿到命中 {self._price_target_label()} 的号码"
                    if hidden_ceiling_fallback and (self.min_target_price is not None or self.max_target_price is not None)
                    else f"，当前优先尝试价位 ${expected_price if expected_price is not None else '-'}"
                )
                + (
                    f"，上限候选档位 {exact_ceiling_index + 1}/{len(exact_ceiling_candidates)}"
                    if exact_ceiling_mode
                    else ""
                )
                + f"，取号前余额 ${balance_before if balance_before is not None else '-'}"
            )
            try:
                params: Dict[str, Any] = {
                    "service": self.service,
                    "country": selected_country_id,
                }
                if current_operator:
                    params["operator"] = current_operator
                request_max_price = self.max_target_price if self.max_target_price is not None else expected_price
                if exact_ceiling_mode and expected_price is not None:
                    request_max_price = expected_price
                request_min_price = self.min_target_price if self.min_target_price is not None else None
                if request_max_price is not None:
                    params["maxPrice"] = request_max_price
                    if self.fixed_price or exact_ceiling_mode:
                        params["fixedPrice"] = "true"
                if request_min_price is not None:
                    params["minPrice"] = request_min_price
                if self.fixed_price and exact_fixed_provider_ids:
                    params["providerIds"] = ",".join(str(item) for item in exact_fixed_provider_ids)
                data = self._request("getNumberV2", proxy=proxy, **params)
            except Exception as exc:
                last_error = f"{provider_label} API 请求失败: {exc}"
                debug_events.append(f"第 {attempt} 次尝试请求接口失败：{exc}")
                if attempt < self.max_acquire_retries:
                    if _interruptible_sleep(5.0, stop_event):
                        raise HeroSMSAcquireStoppedError(f"{provider_label} 取号已停止") from exc
                    continue
                raise RuntimeError(last_error) from exc

            response_code = ""
            response_message = ""
            if isinstance(data, dict):
                response_code = str(
                    data.get("title")
                    or data.get("code")
                    or data.get("status")
                    or data.get("error")
                    or ""
                ).strip().upper()
                response_message = str(
                    data.get("details")
                    or data.get("message")
                    or data.get("description")
                    or ""
                ).strip()
            elif isinstance(data, str):
                response_code = str(data or "").strip().upper()

            if response_code in {"NO_BALANCE", "BAD_KEY", "NO_NUMBERS"}:
                debug_events.append(
                    f"第 {attempt} 次尝试接口返回 {response_code}，运营商 {current_operator or 'ANY'}，说明：{response_message or '-'}"
                )
                if response_code == "NO_BALANCE":
                    raise RuntimeError(f"{provider_label} 余额不足")
                if response_code == "BAD_KEY":
                    raise RuntimeError(f"{provider_label} API Key 无效")
                if response_code == "NO_NUMBERS":
                    if current_operator and operator_was_auto_selected:
                        selected_operator = ""
                        expected_price = exact_ceiling_candidates[exact_ceiling_index] if exact_ceiling_mode else (
                            self.max_target_price
                            if self.max_target_price is not None
                            else self._parse_number(selection.get("aggregate_price"))
                        )
                        debug_events.append(
                            f"第 {attempt} 次尝试已从运营商 {current_operator} 回退到国家聚合池，"
                            + f"新的优先价位 ${expected_price if expected_price is not None else '-'}"
                        )
                        last_error = f"{provider_label} 自动选择的运营商当前无号，已回退到国家聚合池重试取号"
                        if _interruptible_sleep(1.0, stop_event):
                            raise HeroSMSAcquireStoppedError(f"{provider_label} 取号已停止")
                        continue
                    if exact_ceiling_mode and exact_ceiling_index + 1 < len(exact_ceiling_candidates):
                        exact_ceiling_index += 1
                        expected_price = exact_ceiling_candidates[exact_ceiling_index]
                        last_error = (
                            f"{provider_label} 上限模式当前最低档无号，已切到上限内下一档继续尝试: "
                            + f"country={selected_country_id}, service={self.service}, next_expected=${expected_price}"
                        )
                        debug_events.append(
                            f"第 {attempt} 次尝试改为上限内下一档，新的优先价位 ${expected_price}，候选序号 {exact_ceiling_index + 1}"
                        )
                        if _interruptible_sleep(1.0, stop_event):
                            raise HeroSMSAcquireStoppedError(f"{provider_label} 取号已停止")
                        continue
                    if self.max_target_price is None and auto_price_index + 1 < len(auto_price_candidates):
                        auto_price_index += 1
                        next_price = self._parse_number(auto_price_candidates[auto_price_index].get("price"))
                        if next_price is not None:
                            if auto_price_floor is not None:
                                auto_price_ceiling = min(
                                    auto_price_floor * self.AUTO_PRICE_ESCALATION_RATIO,
                                    auto_price_floor + self.AUTO_PRICE_ESCALATION_DELTA,
                                )
                                if next_price > auto_price_ceiling:
                                    last_error = (
                                        f"{provider_label} 自动最低价可用号已超出允许涨价范围，停止继续抬价: "
                                        + f"country={selected_country_id}, service={self.service}, "
                                        + f"base=${auto_price_floor}, next=${next_price}, ceiling=${round(auto_price_ceiling, 6)}"
                                    )
                                    debug_events.append(
                                        f"第 {attempt} 次尝试停止继续抬价：基准价 ${auto_price_floor}，下一档 ${next_price}，允许上限 ${round(auto_price_ceiling, 6)}"
                                    )
                                    raise RuntimeError(last_error)
                            expected_price = next_price
                            last_error = (
                                f"{provider_label} 当前最低价档无号，已自动切换到下一档价格重试取号: "
                                + f"country={selected_country_id}, service={self.service}, next_expected=${expected_price}"
                            )
                            debug_events.append(
                                f"第 {attempt} 次尝试切到下一价格档，新的优先价位 ${expected_price}，档位序号 {auto_price_index + 1}"
                            )
                            if _interruptible_sleep(1.0, stop_event):
                                raise HeroSMSAcquireStoppedError(f"{provider_label} 取号已停止")
                            continue
                    if self.max_target_price is not None or self.min_target_price is not None:
                        last_error = (
                            f"{provider_label} 在设定价格区间内无可用号码: "
                            + f"attempt={attempt}, operator={current_operator or 'ANY'}, "
                            + f"country={selected_country_id}, service={self.service}, "
                            + f"target={self._price_target_label()}"
                        )
                    else:
                        last_error = (
                            f"{provider_label} 当前无可用号码: "
                            + f"attempt={attempt}, operator={current_operator or 'ANY'}, "
                            + f"country={selected_country_id}, service={self.service}"
                        )
                    if auto_country_mode and country_candidate_index + 1 < len(country_candidates):
                        country_candidate_index += 1
                        _apply_country_selection(country_candidates[country_candidate_index])
                        debug_events.append(
                            f"第 {attempt} 次尝试切换到自动国家候选 {country_candidate_index + 1}/{len(country_candidates)}："
                            + f"{str(selection.get('name') or '-')} (ID {selected_country_id})，参考价 ${selection.get('aggregate_price')}"
                        )
                        if _interruptible_sleep(1.0, stop_event):
                            raise HeroSMSAcquireStoppedError(f"{provider_label} 取号已停止")
                        continue
                    if attempt < self.max_acquire_retries:
                        if _interruptible_sleep(3.0, stop_event):
                            raise HeroSMSAcquireStoppedError(f"{provider_label} 取号已停止")
                        continue
                    raise HeroSMSAcquireRetryableError(_build_failure_message(last_error + "（重试耗尽）"))
                raise RuntimeError(f"{provider_label} 获取号码失败: {data}")

            if not isinstance(data, dict):
                debug_events.append(f"第 {attempt} 次尝试返回结构异常：{type(data).__name__}，响应码 {response_code or '-'}")
                raise RuntimeError(f"{provider_label} 获取号码返回异常结构: {type(data).__name__}: {data}")

            activation_id = str(data.get("activationId") or data.get("id") or "").strip()
            phone_number = str(data.get("phoneNumber") or data.get("phone") or "").strip()
            if not activation_id or not phone_number:
                debug_events.append(f"第 {attempt} 次尝试返回结果缺少 activationId 或 phoneNumber：{data}")
                raise RuntimeError(f"{provider_label} 获取号码缺少 activationId/phoneNumber: {data}")
            actual_cost = self._parse_number(data.get("activationCost"))
            if self.fixed_price and (self.min_target_price is not None or self.max_target_price is not None) and actual_cost is not None:
                if not self._price_in_target_range(actual_cost):
                    debug_events.append(
                        f"第 {attempt} 次尝试固定价/区间不匹配：目标 {self._price_target_label()}，实际成交价 ${actual_cost}，运营商 {current_operator or 'ANY'}"
                    )
                    last_error = (
                        f"{self._provider_label()} 固定价模式要求实际成交价必须命中目标价/区间: "
                        + f"target={self._price_target_label()}, actual=${actual_cost}, "
                        + f"operator={current_operator or '-'}, country={selected_country_id}"
                    )
                    try:
                        self.cancel(activation_id, proxy=proxy)
                    except Exception:
                        pass
                    if attempt < self.max_acquire_retries:
                        if _interruptible_sleep(2.0, stop_event):
                            raise HeroSMSAcquireStoppedError(f"{self._provider_label()} 取号已停止")
                        continue
                    raise RuntimeError(last_error)
            if expected_price is not None and actual_cost is not None:
                max_allowed_price = self._resolve_actual_price_ceiling(expected_price)
                min_allowed_price = self._resolve_actual_price_floor(expected_price)
                if (
                    (max_allowed_price is not None and actual_cost > (max_allowed_price + self.PRICE_COMPARE_EPSILON))
                    or (min_allowed_price is not None and actual_cost < (min_allowed_price - self.PRICE_COMPARE_EPSILON))
                ):
                    debug_events.append(
                        f"第 {attempt} 次尝试实际成交价超出范围：预期 ${expected_price}，允许区间 ${min_allowed_price if min_allowed_price is not None else '-'}-${max_allowed_price if max_allowed_price is not None else '-'}，实际 ${actual_cost}，运营商 {current_operator or 'ANY'}"
                    )
                    if self.max_target_price is not None or self.min_target_price is not None:
                        last_error = (
                            f"{provider_label} 实际成交价超出设定价格区间: "
                            f"target={self._price_target_label()}, actual={actual_cost}, "
                            f"operator={current_operator or '-'}, country={selected_country_id}"
                        )
                    else:
                        last_error = (
                            f"{provider_label} 实际成交价高于预期报价: "
                            f"expected={expected_price}, actual={actual_cost}, "
                            f"operator={current_operator or '-'}, country={selected_country_id}"
                        )
                    try:
                        self.cancel(activation_id, proxy=proxy)
                    except Exception:
                        pass
                    if attempt < self.max_acquire_retries:
                        if _interruptible_sleep(2.0, stop_event):
                            raise HeroSMSAcquireStoppedError(f"{provider_label} 取号已停止")
                        continue
                    raise RuntimeError(last_error)
            if not phone_number.startswith("+"):
                phone_number = f"+{phone_number}"
            if (
                auto_country_mode
                and is_smsbower_excluded_country(
                    iso_code=str(selection.get("iso_code") or "").strip().upper(),
                    name=selection.get("name"),
                    api_name=selection.get("api_name"),
                )
            ):
                debug_events.append(
                    f"第 {attempt} 次尝试命中自动国家排除名单：{str(selection.get('name') or '-')} ({str(selection.get('iso_code') or '').strip().upper() or '-'})，"
                    + "已取消当前激活并切换下一国家候选"
                )
                try:
                    self.cancel(activation_id, proxy=proxy)
                except Exception:
                    pass
                last_error = (
                    f"{provider_label} 自动国家模式命中过滤国家，已废弃当前号码: "
                    + f"country={selected_country_id}, name={str(selection.get('name') or '-').strip() or '-'}"
                )
                if country_candidate_index + 1 < len(country_candidates):
                    country_candidate_index += 1
                    _apply_country_selection(country_candidates[country_candidate_index])
                    if _interruptible_sleep(1.0, stop_event):
                        raise HeroSMSAcquireStoppedError(f"{provider_label} 取号已停止")
                    continue
                raise HeroSMSAcquireRetryableError(_build_failure_message(last_error))
            balance_after = self.get_balance(proxy=proxy)
            debug_events.append(
                f"第 {attempt} 次尝试成功，运营商 {current_operator or 'ANY'}，实际成交价 ${actual_cost if actual_cost is not None else data.get('activationCost')}，"
                + f"取号后余额 ${balance_after if balance_after is not None else '-'}"
            )
            return {
                "activation_id": activation_id,
                "phone_number": phone_number,
                "activation_cost": actual_cost if actual_cost is not None else data.get("activationCost"),
                "target_price": self.target_price,
                "min_price": self.min_target_price,
                "max_price": self.max_target_price if (self.min_target_price is not None or self.max_target_price is not None) and not self.fixed_price else None,
                "price_mode": self._get_price_mode(),
                "used_hidden_ceiling_fallback": hidden_ceiling_fallback,
                "visible_ceiling_candidates": exact_ceiling_candidates,
                "operator": selected_operator,
                "operator_fallback_to_aggregate": bool(operator_was_auto_selected and not selected_operator),
                "country": selected_country_id,
                "service": self.service,
                "country_name": str(selection.get("name") or "").strip(),
                "country_iso_code": str(selection.get("iso_code") or "").strip().upper(),
                "country_dial_code": str(selection.get("dial_code") or "").strip().lstrip("+"),
                "aggregate_price": selection.get("aggregate_price"),
                "aggregate_count": selection.get("aggregate_count"),
                "price_tier_options": selection.get("price_tier_options") or [],
                "operator_options": selection.get("operator_options") or [],
                "selected_operator_price": selection.get("selected_operator_price"),
                "selected_operator_count": selection.get("selected_operator_count"),
                "auto_country_mode": auto_country_mode,
                "country_candidates_total": len(country_candidates) if auto_country_mode else 0,
                "balance_before": balance_before,
                "balance_after": balance_after,
                "debug_events": debug_events,
            }

        raise HeroSMSAcquireRetryableError(_build_failure_message(last_error or f"{provider_label} 获取号码失败"))

    def mark_ready(self, activation_id: str, *, proxy: str = "") -> None:
        if not str(activation_id or "").strip():
            raise RuntimeError("HeroSMS mark_ready 缺少 activation_id")
        result = self._request("setStatus", proxy=proxy, id=str(activation_id).strip(), status=1)
        if isinstance(result, str):
            text = str(result or "").strip().upper()
            if text and not text.startswith(("ACCESS_", "STATUS_")) and "OK" not in text:
                raise RuntimeError(f"HeroSMS mark_ready 返回异常: {result}")

    def _get_status(self, activation_id: str, *, proxy: str = "") -> Dict[str, Any]:
        activation = str(activation_id or "").strip()
        if not activation:
            return {"received": False, "code": ""}
        request_errors: List[str] = []
        for action in ("getStatusV2", "getStatus"):
            try:
                data = self._request(action, proxy=proxy, id=activation)
            except Exception as exc:
                request_errors.append(f"{action}:{exc}")
                continue
            if isinstance(data, str):
                text = str(data or "").strip()
                upper_text = text.upper()
                if upper_text == "STATUS_WAIT_CODE":
                    return {"received": False, "code": ""}
                if upper_text == "STATUS_CANCEL":
                    return {"received": False, "code": "", "cancelled": True}
                if upper_text.startswith("STATUS_OK:"):
                    return {"received": True, "code": text.split(":", 1)[1].strip()}
                if upper_text.startswith("STATUS_WAIT_RETRY:"):
                    return {"received": True, "code": text.split(":", 1)[1].strip()}
                if upper_text in {"BAD_ACTION", "BAD_STATUS", "NO_ACTIVATION"}:
                    request_errors.append(f"{action}:{upper_text}")
                    continue
                return {"received": False, "code": ""}
            if not isinstance(data, dict):
                continue
            error_text = str(
                data.get("error")
                or data.get("title")
                or data.get("code")
                or data.get("status")
                or ""
            ).strip()
            if error_text:
                normalized_error = error_text.upper()
                if normalized_error in {"BAD_ACTION", "BAD_STATUS", "NO_ACTIVATION"} or "BAD TYPE PARAMETER" in normalized_error:
                    request_errors.append(f"{action}:{error_text}")
                    continue
            sms_payload = data.get("sms") if isinstance(data.get("sms"), dict) else {}
            sms_code = str(
                sms_payload.get("code")
                or data.get("code")
                or data.get("smsCode")
                or ""
            ).strip()
            if sms_code:
                return {"received": True, "code": sms_code}
            if str(data.get("cancelled") or "").strip().lower() == "true":
                return {"received": False, "code": "", "cancelled": True}
        if request_errors:
            return {"received": False, "code": "", "errors": request_errors}
        return {"received": False, "code": ""}

    def wait_for_code(
        self,
        activation_id: str,
        *,
        proxy: str = "",
        timeout_seconds: int = 300,
        poll_interval_seconds: float = 5.0,
        stop_event: Optional[threading.Event] = None,
    ) -> str:
        activation = str(activation_id or "").strip()
        if not activation:
            return ""
        deadline = time.time() + max(10, int(timeout_seconds or 0))
        interval = max(1.0, float(poll_interval_seconds or 0))
        while time.time() < deadline:
            if stop_event is not None and stop_event.is_set():
                return ""
            try:
                status = self._get_status(activation, proxy=proxy)
            except Exception:
                if _interruptible_sleep(interval, stop_event):
                    return ""
                continue
            if status.get("cancelled"):
                return ""
            code = str(status.get("code") or "").strip()
            if status.get("received") and code:
                return code
            if _interruptible_sleep(interval, stop_event):
                return ""
        return ""

    def peek_code(self, activation_id: str, *, proxy: str = "") -> str:
        activation = str(activation_id or "").strip()
        if not activation:
            return ""
        try:
            status = self._get_status(activation, proxy=proxy)
        except Exception:
            return ""
        if status.get("cancelled"):
            return ""
        code = str(status.get("code") or "").strip()
        if status.get("received") and code:
            return code
        return ""

    def complete(self, activation_id: str, *, proxy: str = "") -> None:
        if not str(activation_id or "").strip():
            return
        result = self._request("setStatus", proxy=proxy, id=str(activation_id).strip(), status=6)
        if isinstance(result, str):
            text = str(result or "").strip().upper()
            if text and not text.startswith(("ACCESS_", "STATUS_")) and "OK" not in text:
                raise RuntimeError(f"HeroSMS complete 返回异常: {result}")

    def cancel(self, activation_id: str, *, proxy: str = "") -> Dict[str, Any]:
        if not str(activation_id or "").strip():
            return {"ok": False, "code": "EMPTY_ACTIVATION_ID", "message": "缺少 activation_id", "retryable": False}
        result = self._request("setStatus", proxy=proxy, id=str(activation_id).strip(), status=8)
        if isinstance(result, dict):
            code = str(result.get("title") or result.get("code") or result.get("status") or result.get("error") or "").strip().upper()
            details = str(result.get("details") or result.get("message") or result.get("description") or "").strip()
            if code in ("ACCESS_CANCEL", "STATUS_CANCEL"):
                return {"ok": True, "code": code, "message": details or "取消成功", "retryable": False}
            if code == "EARLY_CANCEL_DENIED":
                min_wait = HERO_SMS_CANCEL_MIN_WAIT_SECONDS
                info = result.get("info") if isinstance(result.get("info"), dict) else {}
                try:
                    min_wait = max(1, int(info.get("minActivationTime") or min_wait))
                except (TypeError, ValueError):
                    min_wait = HERO_SMS_CANCEL_MIN_WAIT_SECONDS
                return {
                    "ok": False,
                    "code": code,
                    "message": details or "未到最短取消等待时间",
                    "retryable": True,
                    "retry_after_seconds": min_wait,
                }
            if code in ("FREE_CANCELLATION_EXPIRED", "OTP_RECEIVED", "ACTIVATION_NOT_ACTIVE", "NO_ACTIVATION"):
                return {"ok": False, "code": code, "message": details or f"取消不可执行: {code}", "retryable": False}
            if code:
                return {"ok": False, "code": code, "message": details or f"取消返回异常: {result}", "retryable": False}
        if isinstance(result, str):
            text = str(result or "").strip().upper()
            if text in ("ACCESS_CANCEL", "STATUS_CANCEL"):
                return {"ok": True, "code": text, "message": "取消成功", "retryable": False}
            if text == "EARLY_CANCEL_DENIED":
                return {
                    "ok": False,
                    "code": text,
                    "message": "未到最短取消等待时间，需至少等待 120 秒",
                    "retryable": True,
                    "retry_after_seconds": HERO_SMS_CANCEL_MIN_WAIT_SECONDS,
                }
            if text in ("FREE_CANCELLATION_EXPIRED", "OTP_RECEIVED", "ACTIVATION_NOT_ACTIVE", "NO_ACTIVATION"):
                return {"ok": False, "code": text, "message": f"取消不可执行: {text}", "retryable": False}
            if text and not text.startswith(("ACCESS_", "STATUS_")) and "OK" not in text:
                raise RuntimeError(f"HeroSMS cancel 返回异常: {result}")
        return {"ok": True, "code": str(result or "ACCESS_CANCEL"), "message": "取消成功", "retryable": False}


class SMSBowerProvider(HeroSMSProvider):
    BASE_URL = "https://smsbower.page/stubs/handler_api.php"
    API_V1_BASE_URL = "https://smsbower.page/api/v1"

    def _supports_global_auto_country(self) -> bool:
        return True

    @staticmethod
    def _coerce_json_payload(data: Any) -> Any:
        if not isinstance(data, str):
            return data
        try:
            import json as _json
            return _json.loads(data)
        except Exception:
            return data

    @staticmethod
    def _normalize_price_tier_rows(rows: List[Dict[str, Any]], source: str) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for item in rows:
            normalized.append({
                "price": item.get("price"),
                "count": item.get("count"),
                "physical_count": item.get("physical_count"),
                "is_default_price": False,
                "is_min_price": False,
                "default_price_count": None,
                "total_count": None,
                "retail_price": None,
                "source": source,
                "signature": "|".join([
                    str(item.get("price")),
                    str(item.get("count")),
                    str(item.get("physical_count")),
                ]),
                "provider_ids": item.get("provider_ids") if isinstance(item.get("provider_ids"), list) else [],
            })
        return normalized

    def _request_global_price_matrix(self, *, proxy: str = "") -> tuple[Any, str]:
        for action in ("getPricesV3", "getPricesV2", "getPrices"):
            try:
                data = self._request(action, proxy=proxy, service=self.service)
            except Exception:
                continue
            parsed = self._coerce_json_payload(data)
            if isinstance(parsed, (dict, list)):
                return parsed, action
        return None, ""

    def get_global_price_tier_options(self, *, proxy: str = "") -> List[Dict[str, Any]]:
        raw_matrix, action = self._request_global_price_matrix(proxy=proxy)
        if raw_matrix is None:
            return []
        matrix = self._unwrap_price_matrix(raw_matrix)
        country_ids: set[int] = set()
        if isinstance(matrix, dict):
            for key in matrix.keys():
                parsed_country_id = self._parse_integer(key)
                if parsed_country_id is not None:
                    country_ids.add(parsed_country_id)
        for item in self.list_countries(proxy=proxy):
            parsed_country_id = self._parse_integer(item.get("heroSmsCountry"))
            if parsed_country_id is not None:
                country_ids.add(parsed_country_id)
        grouped: Dict[float, Dict[str, Any]] = {}
        for country_id in country_ids:
            rows = self._extract_country_price_options(raw_matrix, country_id, self.service)
            for item in rows:
                price = self._parse_number(item.get("price"))
                if price is None:
                    continue
                bucket = grouped.setdefault(price, {
                    "price": price,
                    "count": 0,
                    "physical_count": 0,
                    "provider_ids": set(),
                })
                parsed_count = self._parse_integer(item.get("count"))
                parsed_physical = self._parse_integer(item.get("physical_count"))
                if parsed_count is not None:
                    bucket["count"] = int(bucket.get("count") or 0) + parsed_count
                if parsed_physical is not None:
                    bucket["physical_count"] = int(bucket.get("physical_count") or 0) + parsed_physical
                raw_provider_ids = item.get("provider_ids")
                if isinstance(raw_provider_ids, list):
                    for provider_id in raw_provider_ids:
                        parsed_provider_id = self._parse_integer(provider_id)
                        if parsed_provider_id is not None:
                            bucket["provider_ids"].add(parsed_provider_id)
        rows = self._normalize_price_tier_rows(
            [
                {
                    "price": price,
                    "count": value.get("count"),
                    "physical_count": value.get("physical_count"),
                    "provider_ids": sorted(value.get("provider_ids") or []),
                }
                for price, value in grouped.items()
            ],
            f"smsbower_global_{action or 'prices'}",
        )
        rows.sort(key=lambda item: (float(item.get("price") or 999999.0), -int(item.get("count") or 0)))
        return rows

    def _build_global_country_candidates(self, *, proxy: str = "") -> List[Dict[str, Any]]:
        raw_matrix, action = self._request_global_price_matrix(proxy=proxy)
        if raw_matrix is None:
            return []
        countries_by_id: Dict[int, Dict[str, Any]] = {}
        for item in self.list_countries(proxy=proxy):
            parsed_country_id = self._parse_integer(item.get("heroSmsCountry"))
            if parsed_country_id is None:
                continue
            countries_by_id[parsed_country_id] = normalize_handler_api_country_row(
                country_id=parsed_country_id,
                api_name=item.get("apiName"),
                iso_code=item.get("isoCode"),
                dial_code=item.get("dialCode"),
            )
        matrix = self._unwrap_price_matrix(raw_matrix)
        if isinstance(matrix, dict):
            for key in matrix.keys():
                parsed_country_id = self._parse_integer(key)
                if parsed_country_id is None or parsed_country_id in countries_by_id:
                    continue
                countries_by_id[parsed_country_id] = normalize_handler_api_country_row(country_id=parsed_country_id)
        candidates: List[Dict[str, Any]] = []
        for country_id, base_country in countries_by_id.items():
            if is_virtual_phone_country_name(base_country.get("name")) or is_virtual_phone_country_name(base_country.get("api_name")):
                continue
            if is_smsbower_excluded_country(
                iso_code=base_country.get("iso_code"),
                name=base_country.get("name"),
                api_name=base_country.get("api_name"),
            ):
                continue
            parsed_rows = self._extract_country_price_options(raw_matrix, country_id, self.service)
            if not parsed_rows:
                continue
            price_tier_options = self._normalize_price_tier_rows(parsed_rows, f"smsbower_{action or 'prices'}")
            if not price_tier_options:
                continue
            if self.min_target_price is None and self.max_target_price is None:
                matched_rows = list(price_tier_options)
            elif self.fixed_price:
                matched_rows = [
                    row for row in price_tier_options
                    if self._price_in_target_range(row.get("price"))
                ]
            else:
                matched_rows = []
                for row in price_tier_options:
                    parsed_price = self._parse_number(row.get("price"))
                    if parsed_price is None or not self._price_in_target_range(parsed_price):
                        continue
                    matched_rows.append(row)
            if not matched_rows:
                continue
            preferred_row = self._select_preferred_price_tier(matched_rows) or matched_rows[0]
            candidates.append({
                **base_country,
                "aggregate_price": preferred_row.get("price"),
                "aggregate_count": preferred_row.get("count"),
                "price_tier_options": price_tier_options,
                "preferred_price_tier": preferred_row,
                "target_price": self.target_price,
                "operator_options": [],
                "selected_operator": "",
                "selected_operator_price": None,
                "selected_operator_count": None,
                "candidate_match_price": preferred_row.get("price"),
                "candidate_match_count": preferred_row.get("count"),
                "candidate_source": "global_auto_country",
            })
        candidates.sort(
            key=lambda item: (
                float(item.get("candidate_match_price") or 999999.0),
                -int(item.get("candidate_match_count") or 0),
                str(item.get("name") or ""),
                int(item.get("hero_sms_country") or 0),
            )
        )
        return candidates

    def resolve_country_and_operator(self, *, proxy: str = "") -> Dict[str, Any]:
        if self.country != SMSBOWER_AUTO_COUNTRY_ID:
            return super().resolve_country_and_operator(proxy=proxy)
        candidates = self._build_global_country_candidates(proxy=proxy)
        if not candidates:
            if (self.min_target_price is not None or self.max_target_price is not None) and self.fixed_price:
                raise RuntimeError(
                    f"SMSBower 自动国家模式下，没有国家命中固定价/区间 {self._price_target_label()}。"
                )
            if self.min_target_price is not None or self.max_target_price is not None:
                raise RuntimeError(
                    f"SMSBower 自动国家模式下，没有国家存在命中价格区间 {self._price_target_label()} 的可用价档。"
                )
            raise RuntimeError("SMSBower 自动国家模式下，没有找到可用国家报价。")
        first = dict(candidates[0])
        first["country_candidates"] = [dict(item) for item in candidates]
        first["auto_country_mode"] = True
        first["selected_country_count"] = len(candidates)
        return first

    def _get_status(self, activation_id: str, *, proxy: str = "") -> Dict[str, Any]:
        activation = str(activation_id or "").strip()
        if not activation:
            return {"received": False, "code": ""}
        for action in ("getStatus", "getStatusV2"):
            try:
                data = self._request(action, proxy=proxy, id=activation)
            except Exception:
                continue
            if isinstance(data, str):
                text = str(data or "").strip()
                upper_text = text.upper()
                if upper_text == "STATUS_WAIT_CODE":
                    return {"received": False, "code": ""}
                if upper_text == "STATUS_CANCEL":
                    return {"received": False, "code": "", "cancelled": True}
                if upper_text.startswith("STATUS_OK:"):
                    return {"received": True, "code": text.split(":", 1)[1].strip()}
                if upper_text.startswith("STATUS_WAIT_RETRY:"):
                    return {"received": True, "code": text.split(":", 1)[1].strip()}
                continue
            if not isinstance(data, dict):
                continue
            error_text = str(
                data.get("error")
                or data.get("title")
                or data.get("code")
                or data.get("status")
                or ""
            ).strip().upper()
            if error_text and ("BAD TYPE PARAMETER" in error_text or error_text in {"BAD_ACTION", "BAD_STATUS", "NO_ACTIVATION"}):
                continue
            sms_payload = data.get("sms") if isinstance(data.get("sms"), dict) else {}
            sms_code = str(
                sms_payload.get("code")
                or data.get("code")
                or data.get("smsCode")
                or ""
            ).strip()
            if sms_code:
                return {"received": True, "code": sms_code}
        return {"received": False, "code": ""}

    @classmethod
    def _extract_country_price_options(cls, raw: Any, country_id: int, service: str) -> List[Dict[str, Any]]:
        matrix = cls._unwrap_price_matrix(raw)
        service_key = str(service or "").strip()
        id_key = str(country_id)

        def push_result(
            results: List[Dict[str, Any]],
            seen: set[tuple[Any, Any, Any, tuple[int, ...]]],
            *,
            price: Any,
            count: Any,
            physical_count: Any,
            provider_ids: Optional[List[int]] = None,
        ) -> None:
            parsed_price = cls._parse_number(price)
            parsed_count = cls._parse_integer(count)
            parsed_physical = cls._parse_integer(physical_count)
            normalized_provider_ids = tuple(sorted({
                parsed_id
                for parsed_id in (
                    cls._parse_integer(item)
                    for item in (provider_ids or [])
                )
                if parsed_id is not None
            }))
            if parsed_price is None and parsed_count is None and parsed_physical is None:
                return
            signature = (parsed_price, parsed_count, parsed_physical, normalized_provider_ids)
            if signature in seen:
                return
            seen.add(signature)
            row: Dict[str, Any] = {
                "price": parsed_price,
                "count": parsed_count,
                "physical_count": parsed_physical,
            }
            if normalized_provider_ids:
                row["provider_ids"] = list(normalized_provider_ids)
            results.append(row)

        results: List[Dict[str, Any]] = []
        seen: set[tuple[Any, Any, Any, tuple[int, ...]]] = set()

        if isinstance(matrix, dict):
            country_node = matrix.get(id_key) if isinstance(matrix.get(id_key), dict) else None
            service_node = country_node.get(service_key) if isinstance(country_node, dict) and isinstance(country_node.get(service_key), dict) else None
            if isinstance(service_node, dict):
                all_v3 = True
                for provider_id, item in service_node.items():
                    if not isinstance(item, dict):
                        all_v3 = False
                        break
                    if cls._parse_number(item.get("price")) is None and cls._parse_integer(item.get("count")) is None:
                        all_v3 = False
                        break
                if all_v3 and service_node:
                    grouped: Dict[float, Dict[str, Any]] = {}
                    for provider_id, item in service_node.items():
                        if not isinstance(item, dict):
                            continue
                        parsed_price = cls._parse_number(item.get("price"))
                        if parsed_price is None:
                            continue
                        parsed_count = cls._parse_integer(item.get("count"))
                        parsed_physical = cls._parse_integer(
                            item.get("physicalCount") or item.get("physical_count") or item.get("realCount")
                        )
                        parsed_provider_id = cls._parse_integer(item.get("provider_id") or provider_id)
                        bucket = grouped.setdefault(parsed_price, {
                            "price": parsed_price,
                            "count": 0,
                            "physical_count": parsed_physical,
                            "provider_ids": [],
                        })
                        if parsed_count is not None:
                            bucket["count"] = int(bucket.get("count") or 0) + parsed_count
                        if bucket.get("physical_count") is None and parsed_physical is not None:
                            bucket["physical_count"] = parsed_physical
                        if parsed_provider_id is not None and parsed_provider_id not in bucket["provider_ids"]:
                            bucket["provider_ids"].append(parsed_provider_id)
                    for item in grouped.values():
                        push_result(
                            results,
                            seen,
                            price=item.get("price"),
                            count=item.get("count"),
                            physical_count=item.get("physical_count"),
                            provider_ids=item.get("provider_ids"),
                        )
                    results.sort(key=lambda item: (float(item.get("price") or 999999.0), -int(item.get("count") or 0)))
                    return results

        return super()._extract_country_price_options(raw, country_id, service)

    def get_price_tier_options(self, *, country: int, proxy: str = "") -> List[Dict[str, Any]]:
        if int(country) == SMSBOWER_AUTO_COUNTRY_ID:
            return self.get_global_price_tier_options(proxy=proxy)
        for action in ("getPricesV3", "getPricesV2", "getPrices"):
            try:
                data = self._request(action, proxy=proxy, service=self.service, country=country)
            except Exception:
                continue
            data = self._coerce_json_payload(data)
            if not isinstance(data, (dict, list)):
                continue
            options = self._extract_country_price_options(data, country, self.service)
            if options:
                return self._normalize_price_tier_rows(options, f"smsbower_{action}")
        return super().get_price_tier_options(country=country, proxy=proxy)


def schedule_hero_sms_delayed_cancel(
    *,
    provider: SMSProvider,
    activation_id: str,
    purchased_at: float,
    proxy: str = "",
    min_wait_seconds: int = HERO_SMS_CANCEL_MIN_WAIT_SECONDS,
    provider_label: str = "HeroSMS",
    logger: Optional[Any] = None,
) -> Optional[threading.Thread]:
    activation = str(activation_id or "").strip()
    if not activation:
        return None
    delay_seconds = max(0.0, float(min_wait_seconds) - max(0.0, time.time() - float(purchased_at or 0.0)))

    def _log(message: str) -> None:
        if callable(logger):
            try:
                logger(message)
            except Exception:
                pass

    def _runner() -> None:
        if delay_seconds > 0:
            _log(
                f"{provider_label} 延迟取消已入队: "
                + f"activation_id={activation}, remaining={round(delay_seconds, 1)}s"
            )
            time.sleep(delay_seconds)
        try:
            result = provider.cancel(activation, proxy=proxy)
        except Exception as exc:
            _log(f"{provider_label} 延迟取消执行异常: activation_id={activation}, error={exc}")
            return
        code = str((result or {}).get("code") or "")
        if result and result.get("ok"):
            _log(f"{provider_label} 延迟取消成功: activation_id={activation}, code={code or 'ACCESS_CANCEL'}")
            return
        retryable = bool(result and result.get("retryable"))
        retry_after = 0.0
        try:
            retry_after = max(0.0, float((result or {}).get("retry_after_seconds") or 0.0))
        except (TypeError, ValueError):
            retry_after = 0.0
        if retryable and retry_after > 0:
            retry_delay = max(0.0, retry_after - max(0.0, time.time() - float(purchased_at or 0.0)))
            _log(
                f"{provider_label} 延迟取消仍被拒绝，准备再次等待后重试: "
                + f"activation_id={activation}, code={code or '-'}, retry_after={round(retry_delay, 1)}s"
            )
            if retry_delay > 0:
                time.sleep(retry_delay)
            try:
                retry_result = provider.cancel(activation, proxy=proxy)
            except Exception as exc:
                _log(f"{provider_label} 延迟取消重试异常: activation_id={activation}, error={exc}")
                return
            retry_code = str((retry_result or {}).get("code") or "")
            if retry_result and retry_result.get("ok"):
                _log(f"{provider_label} 延迟取消重试成功: activation_id={activation}, code={retry_code or 'ACCESS_CANCEL'}")
            else:
                _log(
                    f"{provider_label} 延迟取消重试结束但未成功: "
                    + f"activation_id={activation}, code={retry_code or '-'}, message={str((retry_result or {}).get('message') or '-')}"
                )
            return
        _log(
            f"{provider_label} 延迟取消结束但未成功: "
            + f"activation_id={activation}, code={code or '-'}, message={str((result or {}).get('message') or '-')}"
        )

    worker = threading.Thread(
        target=_runner,
        name=f"hero-sms-cancel-{activation}",
        daemon=True,
    )
    worker.start()
    return worker


def create_sms_provider_from_browser_config(browser_config: Optional[Dict[str, Any]]) -> Optional[SMSProvider]:
    cfg = browser_config if isinstance(browser_config, dict) else {}
    phone_mode = str(cfg.get("browser_manual_v2_phone_mode") or "").strip().lower()
    api_key = str(cfg.get("hero_sms_api_key") or "").strip()
    service = str(cfg.get("hero_sms_service") or "").strip()
    if phone_mode not in ("hero_sms", "smsbower") or not api_key or not service:
        return None
    provider_cls = HeroSMSProvider if phone_mode == "hero_sms" else SMSBowerProvider
    return provider_cls(
        api_key=api_key,
        service=service,
        country=cfg.get("hero_sms_country", 16),
        operator=str(cfg.get("hero_sms_operator") or "").strip(),
        target_price=cfg.get("hero_sms_target_price") or "",
        fixed_price=_as_bool(cfg.get("hero_sms_fixed_price", True), default=True),
        max_acquire_retries=cfg.get("hero_sms_max_acquire_retries") or 5,
    )


def list_hero_sms_countries(
    *,
    api_key: str,
    service: str = "",
    proxy: str = "",
    provider_mode: str = "hero_sms",
) -> List[Dict[str, Any]]:
    service_text = str(service or "").strip()
    if not api_key:
        return []
    provider_cls = HeroSMSProvider if str(provider_mode or "").strip().lower() != "smsbower" else SMSBowerProvider
    provider = provider_cls(
        api_key=api_key,
        service=service_text,
    )
    api_rows = provider.list_countries(proxy=proxy)
    rows: List[Dict[str, Any]] = []
    for item in api_rows:
        rows.append(normalize_handler_api_country_row(
            country_id=item.get("heroSmsCountry"),
            api_name=item.get("apiName"),
            iso_code=item.get("isoCode"),
            dial_code=item.get("dialCode"),
        ))
    rows.sort(key=lambda item: (str(item.get("name") or ""), int(item.get("hero_sms_country") or 0)))
    return rows


def list_handler_api_services(
    *,
    api_key: str,
    service: str = "",
    proxy: str = "",
    provider_mode: str = "hero_sms",
) -> List[Dict[str, Any]]:
    api_key_text = str(api_key or "").strip()
    if not api_key_text:
        return []
    provider_cls = HeroSMSProvider if str(provider_mode or "").strip().lower() != "smsbower" else SMSBowerProvider
    provider = provider_cls(
        api_key=api_key_text,
        service=str(service or "").strip(),
    )
    return provider.list_services(proxy=proxy)


def list_hero_sms_operator_quotes(
    *,
    api_key: str,
    service: str,
    country: int,
    proxy: str = "",
    provider_mode: str = "hero_sms",
) -> List[Dict[str, Any]]:
    service_text = str(service or "").strip()
    if not api_key or not service_text:
        return []
    try:
        country_id = max(1, int(country or 0))
    except (TypeError, ValueError):
        return []
    provider_cls = HeroSMSProvider if str(provider_mode or "").strip().lower() != "smsbower" else SMSBowerProvider
    provider = provider_cls(
        api_key=api_key,
        service=service_text,
        country=country_id,
    )
    rows = provider.get_operator_quote_options(country=country_id, proxy=proxy)
    normalized: List[Dict[str, Any]] = []
    for item in rows:
        normalized.append({
            "operator": str(item.get("operator") or "").strip(),
            "price": item.get("price"),
            "count": item.get("count"),
            "physical_count": item.get("physical_count"),
            "error": str(item.get("error") or "").strip(),
            "signature": "|".join([
                str(item.get("price")),
                str(item.get("count")),
                str(item.get("physical_count")),
                str(item.get("error") or ""),
            ]),
        })
    return normalized


def list_hero_sms_price_tiers(
    *,
    api_key: str,
    service: str,
    country: int,
    operator: str = "",
    proxy: str = "",
    provider_mode: str = "hero_sms",
) -> List[Dict[str, Any]]:
    service_text = str(service or "").strip()
    if not api_key or not service_text:
        return []
    try:
        country_id = max(1, int(country or 0))
    except (TypeError, ValueError):
        return []
    provider_cls = HeroSMSProvider if str(provider_mode or "").strip().lower() != "smsbower" else SMSBowerProvider
    provider = provider_cls(
        api_key=api_key,
        service=service_text,
        country=country_id,
        operator=str(operator or "").strip(),
    )
    rows = provider.get_operator_quote_options(country=country_id, proxy=proxy) if str(operator or "").strip() else provider.get_price_tier_options(country=country_id, proxy=proxy)
    normalized: List[Dict[str, Any]] = []
    for item in rows:
        normalized.append({
            "price": item.get("price"),
            "count": item.get("count"),
            "physical_count": item.get("physical_count"),
            "is_default_price": bool(item.get("is_default_price", False)),
            "is_min_price": bool(item.get("is_min_price", False)),
            "default_price_count": item.get("default_price_count"),
            "total_count": item.get("total_count"),
            "retail_price": item.get("retail_price"),
            "source": str(item.get("source") or ""),
            "operator": str(item.get("operator") or "").strip(),
            "signature": str(item.get("signature") or ""),
        })
    return normalized
