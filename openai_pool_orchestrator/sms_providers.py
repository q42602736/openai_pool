"""
SMS Provider 抽象层
当前提供 HeroSMS，用于浏览器模式2自动取号与短信验证码轮询。
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


class SMSProvider(ABC):
    @abstractmethod
    def acquire_number(self, *, proxy: str = "") -> Dict[str, Any]:
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
        try:
            self.country = int(country or 16)
        except (TypeError, ValueError):
            self.country = 16
        self.operator = str(operator or "").strip()
        self.target_price_raw = str(target_price or "").strip()
        self.target_price = self._parse_number(self.target_price_raw)
        self.fixed_price = bool(fixed_price) and self.target_price is not None
        try:
            self.max_acquire_retries = max(1, int(max_acquire_retries or 5))
        except (TypeError, ValueError):
            self.max_acquire_retries = 5

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
        if self.target_price is not None:
            return self.target_price
        if expected_price is None:
            return None
        return max(
            expected_price * self.MAX_ACCEPTABLE_PRICE_RATIO,
            expected_price + self.MAX_ACCEPTABLE_PRICE_DELTA,
        )

    def _get_price_mode(self) -> str:
        if self.target_price is None:
            return "auto"
        if self.fixed_price:
            return "fixed"
        return "ceiling"

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
        country_id = int(base.get("hero_sms_country") or self.country or 16)
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

    def acquire_number(self, *, proxy: str = "") -> Dict[str, Any]:
        last_error = ""
        selection = self.resolve_country_and_operator(proxy=proxy)
        selected_country_id = self._parse_integer(selection.get("hero_sms_country")) or int(self.country or 16)
        selected_operator = str(selection.get("selected_operator") or "").strip()
        operator_was_auto_selected = not str(self.operator or "").strip() and bool(selected_operator)
        price_tier_options = selection.get("price_tier_options") if isinstance(selection.get("price_tier_options"), list) else []
        auto_price_candidates = [
            item for item in price_tier_options
            if self._parse_number(item.get("price")) is not None
        ]
        auto_price_index = 0
        auto_price_floor = None
        expected_price = self.target_price
        if expected_price is None:
            expected_price = self._parse_number(selection.get("selected_operator_price"))
        if expected_price is None:
            expected_price = self._parse_number(selection.get("aggregate_price"))
        if expected_price is not None:
            auto_price_floor = expected_price
        if expected_price is not None:
            for index, item in enumerate(auto_price_candidates):
                if self._parse_number(item.get("price")) == expected_price:
                    auto_price_index = index
                    break
        balance_before = self.get_balance(proxy=proxy)
        debug_events: List[str] = []
        for attempt in range(1, self.max_acquire_retries + 1):
            current_operator = selected_operator
            debug_events.append(
                "attempt="
                + str(attempt)
                + f", operator={current_operator or 'ANY'}"
                + f", price_mode={self._get_price_mode()}"
                + (
                    f", max_price=${self.target_price}"
                    if self.target_price is not None and not self.fixed_price
                    else f", target_price=${self.target_price if self.target_price is not None else '-'}"
                )
                + f", expected=${expected_price if expected_price is not None else '-'}"
                + f", balance_before=${balance_before if balance_before is not None else '-'}"
            )
            try:
                params: Dict[str, Any] = {
                    "service": self.service,
                    "country": selected_country_id,
                }
                if current_operator:
                    params["operator"] = current_operator
                request_max_price = self.target_price if self.target_price is not None else expected_price
                if request_max_price is not None:
                    params["maxPrice"] = request_max_price
                    if self.fixed_price:
                        params["fixedPrice"] = "true"
                data = self._request("getNumberV2", proxy=proxy, **params)
            except Exception as exc:
                last_error = f"HeroSMS API 请求失败: {exc}"
                debug_events.append(f"attempt={attempt}, request_error={exc}")
                if attempt < self.max_acquire_retries:
                    time.sleep(5.0)
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
                    f"attempt={attempt}, response={response_code}, operator={current_operator or 'ANY'}, message={response_message or '-'}"
                )
                if response_code == "NO_BALANCE":
                    raise RuntimeError("HeroSMS 余额不足")
                if response_code == "BAD_KEY":
                    raise RuntimeError("HeroSMS API Key 无效")
                if response_code == "NO_NUMBERS":
                    if current_operator and operator_was_auto_selected:
                        selected_operator = ""
                        expected_price = (
                            self.target_price
                            if self.target_price is not None
                            else self._parse_number(selection.get("aggregate_price"))
                        )
                        debug_events.append(
                            f"attempt={attempt}, fallback=aggregate, from_operator={current_operator}, "
                            + f"new_expected=${expected_price if expected_price is not None else '-'}"
                        )
                        last_error = "HeroSMS 自动选择的运营商当前无号，已回退到国家聚合池重试取号"
                        time.sleep(1.0)
                        continue
                    if self.target_price is None and auto_price_index + 1 < len(auto_price_candidates):
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
                                        "HeroSMS 自动最低价可用号已超出允许涨价范围，停止继续抬价: "
                                        + f"country={selected_country_id}, service={self.service}, "
                                        + f"base=${auto_price_floor}, next=${next_price}, ceiling=${round(auto_price_ceiling, 6)}"
                                    )
                                    debug_events.append(
                                        f"attempt={attempt}, stop=auto_price_ceiling, base=${auto_price_floor}, next=${next_price}, ceiling=${round(auto_price_ceiling, 6)}"
                                    )
                                    raise RuntimeError(last_error)
                            expected_price = next_price
                            last_error = (
                                "HeroSMS 当前最低价档无号，已自动切换到下一档价格重试取号: "
                                + f"country={selected_country_id}, service={self.service}, next_expected=${expected_price}"
                            )
                            debug_events.append(
                                f"attempt={attempt}, fallback=next_price_tier, new_expected=${expected_price}, tier_index={auto_price_index}"
                            )
                            time.sleep(1.0)
                            continue
                    if self.target_price is not None:
                        last_error = (
                            "HeroSMS 在设定价格上限内无可用号码: "
                            + f"attempt={attempt}, operator={current_operator or 'ANY'}, "
                            + f"country={selected_country_id}, service={self.service}, "
                            + f"max_price=${self.target_price}"
                        )
                    else:
                        last_error = (
                            "HeroSMS 当前无可用号码: "
                            + f"attempt={attempt}, operator={current_operator or 'ANY'}, "
                            + f"country={selected_country_id}, service={self.service}"
                        )
                    if attempt < self.max_acquire_retries:
                        time.sleep(3.0)
                        continue
                    raise RuntimeError(last_error + "（重试耗尽）")
                raise RuntimeError(f"HeroSMS 获取号码失败: {data}")

            if not isinstance(data, dict):
                debug_events.append(f"attempt={attempt}, invalid_response_type={type(data).__name__}, response={response_code or '-'}")
                raise RuntimeError(f"HeroSMS 获取号码返回异常结构: {type(data).__name__}: {data}")

            activation_id = str(data.get("activationId") or data.get("id") or "").strip()
            phone_number = str(data.get("phoneNumber") or data.get("phone") or "").strip()
            if not activation_id or not phone_number:
                debug_events.append(f"attempt={attempt}, missing_fields={data}")
                raise RuntimeError(f"HeroSMS 获取号码缺少 activationId/phoneNumber: {data}")
            actual_cost = self._parse_number(data.get("activationCost"))
            if expected_price is not None and actual_cost is not None:
                max_allowed_price = self._resolve_actual_price_ceiling(expected_price)
                if max_allowed_price is not None and actual_cost > (max_allowed_price + self.PRICE_COMPARE_EPSILON):
                    debug_events.append(
                        f"attempt={attempt}, overpriced expected=${expected_price}, allowed=${max_allowed_price}, actual=${actual_cost}, "
                        + f"operator={current_operator or 'ANY'}"
                    )
                    if self.target_price is not None:
                        last_error = (
                            "HeroSMS 实际成交价超过设定价格上限: "
                            f"max_price={self.target_price}, actual={actual_cost}, "
                            f"operator={current_operator or '-'}, country={selected_country_id}"
                        )
                    else:
                        last_error = (
                            "HeroSMS 实际成交价高于预期报价: "
                            f"expected={expected_price}, actual={actual_cost}, "
                            f"operator={current_operator or '-'}, country={selected_country_id}"
                        )
                    try:
                        self.cancel(activation_id, proxy=proxy)
                    except Exception:
                        pass
                    if attempt < self.max_acquire_retries:
                        time.sleep(2.0)
                        continue
                    raise RuntimeError(last_error)
            if not phone_number.startswith("+"):
                phone_number = f"+{phone_number}"
            balance_after = self.get_balance(proxy=proxy)
            debug_events.append(
                f"attempt={attempt}, success operator={current_operator or 'ANY'}, actual=${actual_cost if actual_cost is not None else data.get('activationCost')}, "
                + f"balance_after=${balance_after if balance_after is not None else '-'}"
            )
            return {
                "activation_id": activation_id,
                "phone_number": phone_number,
                "activation_cost": actual_cost if actual_cost is not None else data.get("activationCost"),
                "target_price": self.target_price,
                "max_price": self.target_price if self.target_price is not None and not self.fixed_price else None,
                "price_mode": self._get_price_mode(),
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
                "balance_before": balance_before,
                "balance_after": balance_after,
                "debug_events": debug_events,
            }

        raise RuntimeError(last_error or "HeroSMS 获取号码失败")

    def mark_ready(self, activation_id: str, *, proxy: str = "") -> None:
        if not str(activation_id or "").strip():
            raise RuntimeError("HeroSMS mark_ready 缺少 activation_id")
        result = self._request("setStatus", proxy=proxy, id=str(activation_id).strip(), status=1)
        if isinstance(result, str):
            text = str(result or "").strip().upper()
            if text and not text.startswith(("ACCESS_", "STATUS_")) and "OK" not in text:
                raise RuntimeError(f"HeroSMS mark_ready 返回异常: {result}")

    def _get_status(self, activation_id: str, *, proxy: str = "") -> Dict[str, Any]:
        data = self._request("getStatusV2", proxy=proxy, id=str(activation_id).strip())
        if isinstance(data, str):
            if data == "STATUS_WAIT_CODE":
                return {"received": False, "code": ""}
            if data == "STATUS_CANCEL":
                return {"received": False, "code": "", "cancelled": True}
            if data.startswith("STATUS_OK:"):
                return {"received": True, "code": data.split(":", 1)[1].strip()}
            return {"received": False, "code": ""}
        if not isinstance(data, dict):
            return {"received": False, "code": ""}
        sms_payload = data.get("sms") if isinstance(data.get("sms"), dict) else {}
        sms_code = str(sms_payload.get("code") or "").strip()
        return {"received": bool(sms_code), "code": sms_code}

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
                time.sleep(interval)
                continue
            if status.get("cancelled"):
                return ""
            code = str(status.get("code") or "").strip()
            if status.get("received") and code:
                return code
            time.sleep(interval)
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


def schedule_hero_sms_delayed_cancel(
    *,
    provider: SMSProvider,
    activation_id: str,
    purchased_at: float,
    proxy: str = "",
    min_wait_seconds: int = HERO_SMS_CANCEL_MIN_WAIT_SECONDS,
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
                "HeroSMS 延迟取消已入队: "
                + f"activation_id={activation}, remaining={round(delay_seconds, 1)}s"
            )
            time.sleep(delay_seconds)
        try:
            result = provider.cancel(activation, proxy=proxy)
        except Exception as exc:
            _log(f"HeroSMS 延迟取消执行异常: activation_id={activation}, error={exc}")
            return
        code = str((result or {}).get("code") or "")
        if result and result.get("ok"):
            _log(f"HeroSMS 延迟取消成功: activation_id={activation}, code={code or 'ACCESS_CANCEL'}")
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
                "HeroSMS 延迟取消仍被拒绝，准备再次等待后重试: "
                + f"activation_id={activation}, code={code or '-'}, retry_after={round(retry_delay, 1)}s"
            )
            if retry_delay > 0:
                time.sleep(retry_delay)
            try:
                retry_result = provider.cancel(activation, proxy=proxy)
            except Exception as exc:
                _log(f"HeroSMS 延迟取消重试异常: activation_id={activation}, error={exc}")
                return
            retry_code = str((retry_result or {}).get("code") or "")
            if retry_result and retry_result.get("ok"):
                _log(f"HeroSMS 延迟取消重试成功: activation_id={activation}, code={retry_code or 'ACCESS_CANCEL'}")
            else:
                _log(
                    "HeroSMS 延迟取消重试结束但未成功: "
                    + f"activation_id={activation}, code={retry_code or '-'}, message={str((retry_result or {}).get('message') or '-')}"
                )
            return
        _log(
            "HeroSMS 延迟取消结束但未成功: "
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
    auto_enabled = str(cfg.get("browser_manual_v2_phone_mode") or "").strip().lower() == "hero_sms"
    api_key = str(cfg.get("hero_sms_api_key") or "").strip()
    service = str(cfg.get("hero_sms_service") or "").strip()
    if not auto_enabled or not api_key or not service:
        return None
    return HeroSMSProvider(
        api_key=api_key,
        service=service,
        country=cfg.get("hero_sms_country") or 16,
        operator=str(cfg.get("hero_sms_operator") or "").strip(),
        target_price=cfg.get("hero_sms_target_price") or "",
        fixed_price=bool(cfg.get("hero_sms_fixed_price", True)),
        max_acquire_retries=cfg.get("hero_sms_max_acquire_retries") or 5,
    )


def list_hero_sms_countries(
    *,
    api_key: str,
    service: str = "",
    proxy: str = "",
) -> List[Dict[str, Any]]:
    service_text = str(service or "").strip()
    if not api_key or not service_text:
        return []
    provider = HeroSMSProvider(
        api_key=api_key,
        service=service_text,
    )
    api_rows = provider.list_countries(proxy=proxy)
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
    rows: List[Dict[str, Any]] = []
    for item in api_rows:
        iso_code = str(item.get("isoCode") or "").strip().upper()
        dial_code = str(item.get("dialCode") or "").strip().lstrip("+")
        catalog_item = catalog_by_iso.get(iso_code) or catalog_by_dial.get(dial_code) or {}
        display_name = str(catalog_item.get("name") or item.get("apiName") or iso_code or dial_code or item.get("heroSmsCountry") or "").strip()
        rows.append({
            "hero_sms_country": int(item.get("heroSmsCountry") or 0),
            "name": display_name,
            "api_name": str(item.get("apiName") or "").strip(),
            "iso_code": iso_code,
            "dial_code": dial_code,
        })
    rows.sort(key=lambda item: (str(item.get("name") or ""), int(item.get("hero_sms_country") or 0)))
    return rows


def list_hero_sms_operator_quotes(
    *,
    api_key: str,
    service: str,
    country: int,
    proxy: str = "",
) -> List[Dict[str, Any]]:
    service_text = str(service or "").strip()
    if not api_key or not service_text:
        return []
    try:
        country_id = max(1, int(country or 0))
    except (TypeError, ValueError):
        return []
    provider = HeroSMSProvider(
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
) -> List[Dict[str, Any]]:
    service_text = str(service or "").strip()
    if not api_key or not service_text:
        return []
    try:
        country_id = max(1, int(country or 0))
    except (TypeError, ValueError):
        return []
    provider = HeroSMSProvider(
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
