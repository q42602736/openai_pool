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
    MAX_ACCEPTABLE_PRICE_RATIO = 1.05
    MAX_ACCEPTABLE_PRICE_DELTA = 0.0005

    def __init__(
        self,
        *,
        api_key: str,
        service: str = "",
        country: int = 16,
        operator: str = "",
        max_acquire_retries: int = 5,
    ) -> None:
        self.api_key = str(api_key or "").strip()
        self.service = str(service or "").strip()
        try:
            self.country = int(country or 16)
        except (TypeError, ValueError):
            self.country = 16
        self.operator = str(operator or "").strip()
        try:
            self.max_acquire_retries = max(1, int(max_acquire_retries or 5))
        except (TypeError, ValueError):
            self.max_acquire_retries = 5

    def _resolve_catalog_country(self) -> Dict[str, Any]:
        country_id = int(self.country or 16)
        if country_id == 16:
            return {"hero_sms_country": 16, "name": "英国", "iso_code": "GB", "dial_code": "44", "api_name": ""}
        for item in DEFAULT_PHONE_COUNTRIES:
            if str(item.get("isoCode") or "").strip().upper() == "GB" and country_id == 16:
                return {"hero_sms_country": 16, "name": "英国", "iso_code": "GB", "dial_code": "44", "api_name": ""}
        return {
            "hero_sms_country": country_id,
            "name": "",
            "iso_code": "",
            "dial_code": "",
            "api_name": "",
        }

    @staticmethod
    def _parse_number(value: Any) -> Optional[float]:
        text = str(value or "").strip()
        digits = "".join(ch for ch in text if ch.isdigit() or ch == ".")
        if not digits:
            return None
        try:
            return float(digits)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_integer(value: Any) -> Optional[int]:
        text = str(value or "").strip()
        digits = "".join(ch for ch in text if ch.isdigit() or ch == "-")
        if not digits:
            return None
        try:
            return int(digits)
        except (TypeError, ValueError):
            return None

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
    def _extract_country_price(cls, raw: Any, country_id: int, service: str) -> Optional[Dict[str, Any]]:
        matrix = cls._unwrap_price_matrix(raw)
        service_key = str(service or "").strip()
        id_key = str(country_id)
        if isinstance(matrix, list):
            for item in matrix:
                if not isinstance(item, dict):
                    continue
                item_country_id = cls._parse_integer(
                    item.get("countryId") or item.get("country_id") or item.get("country") or item.get("id")
                )
                if item_country_id != country_id:
                    continue
                direct = cls._extract_price_from_node(item)
                if direct:
                    return direct
                service_node = item.get(service_key) or item.get("serviceData") or item.get("data")
                nested = cls._extract_price_from_node(service_node)
                if nested:
                    return nested
            return None
        if not isinstance(matrix, dict):
            return None
        candidates = [
            ((matrix.get(service_key) or {}).get(id_key) if isinstance(matrix.get(service_key), dict) else None),
            ((matrix.get(id_key) or {}).get(service_key) if isinstance(matrix.get(id_key), dict) else None),
            ((matrix.get(id_key) or {}).get("default") if isinstance(matrix.get(id_key), dict) else None),
            matrix.get(id_key),
            matrix.get(service_key),
        ]
        for candidate in candidates:
            extracted = cls._extract_price_from_node(candidate)
            if extracted:
                return extracted
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

    def resolve_country_and_operator(self, *, proxy: str = "") -> Dict[str, Any]:
        base = self._resolve_catalog_country()
        country_id = int(base.get("hero_sms_country") or self.country or 16)
        aggregate_price = None
        aggregate_count = None
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
        expected_price = self._parse_number(selection.get("selected_operator_price"))
        if expected_price is None:
            expected_price = self._parse_number(selection.get("aggregate_price"))
        balance_before = self.get_balance(proxy=proxy)
        debug_events: List[str] = []
        for attempt in range(1, self.max_acquire_retries + 1):
            current_operator = selected_operator
            debug_events.append(
                "attempt="
                + str(attempt)
                + f", operator={current_operator or 'ANY'}"
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
                data = self._request("getNumberV2", proxy=proxy, **params)
            except Exception as exc:
                last_error = f"HeroSMS API 请求失败: {exc}"
                debug_events.append(f"attempt={attempt}, request_error={exc}")
                if attempt < self.max_acquire_retries:
                    time.sleep(5.0)
                    continue
                raise RuntimeError(last_error) from exc

            if isinstance(data, str):
                if data == "NO_BALANCE":
                    debug_events.append(f"attempt={attempt}, response=NO_BALANCE")
                    raise RuntimeError("HeroSMS 余额不足")
                if data == "BAD_KEY":
                    debug_events.append(f"attempt={attempt}, response=BAD_KEY")
                    raise RuntimeError("HeroSMS API Key 无效")
                if data == "NO_NUMBERS":
                    debug_events.append(f"attempt={attempt}, response=NO_NUMBERS, operator={current_operator or 'ANY'}")
                    if current_operator and operator_was_auto_selected:
                        selected_operator = ""
                        expected_price = self._parse_number(selection.get("aggregate_price"))
                        debug_events.append(
                            f"attempt={attempt}, fallback=aggregate, from_operator={current_operator}, "
                            + f"new_expected=${expected_price if expected_price is not None else '-'}"
                        )
                        last_error = "HeroSMS 自动选择的运营商当前无号，已回退到国家聚合池重试取号"
                        time.sleep(1.0)
                        continue
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
                debug_events.append(f"attempt={attempt}, invalid_response_type={type(data).__name__}")
                raise RuntimeError(f"HeroSMS 获取号码返回异常结构: {type(data).__name__}")

            activation_id = str(data.get("activationId") or data.get("id") or "").strip()
            phone_number = str(data.get("phoneNumber") or data.get("phone") or "").strip()
            if not activation_id or not phone_number:
                debug_events.append(f"attempt={attempt}, missing_fields={data}")
                raise RuntimeError(f"HeroSMS 获取号码缺少 activationId/phoneNumber: {data}")
            actual_cost = self._parse_number(data.get("activationCost"))
            if expected_price is not None and actual_cost is not None:
                max_allowed_price = max(
                    expected_price * self.MAX_ACCEPTABLE_PRICE_RATIO,
                    expected_price + self.MAX_ACCEPTABLE_PRICE_DELTA,
                )
                if actual_cost > max_allowed_price:
                    debug_events.append(
                        f"attempt={attempt}, overpriced expected=${expected_price}, actual=${actual_cost}, "
                        + f"operator={current_operator or 'ANY'}"
                    )
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
                "operator": selected_operator,
                "operator_fallback_to_aggregate": bool(operator_was_auto_selected and not selected_operator),
                "country": selected_country_id,
                "service": self.service,
                "country_name": str(selection.get("name") or "").strip(),
                "country_iso_code": str(selection.get("iso_code") or "").strip().upper(),
                "country_dial_code": str(selection.get("dial_code") or "").strip().lstrip("+"),
                "aggregate_price": selection.get("aggregate_price"),
                "aggregate_count": selection.get("aggregate_count"),
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
        self._request("setStatus", proxy=proxy, id=str(activation_id).strip(), status=1)

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
        try:
            self._request("setStatus", proxy=proxy, id=str(activation_id).strip(), status=6)
        except Exception:
            return

    def cancel(self, activation_id: str, *, proxy: str = "") -> None:
        if not str(activation_id or "").strip():
            return
        try:
            self._request("setStatus", proxy=proxy, id=str(activation_id).strip(), status=8)
        except Exception:
            return


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
