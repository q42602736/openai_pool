"""RoxyBrowser 本地 API 适配。

只负责「把 Roxy 的指纹浏览器窗口开起来并交出 CDP 地址」，页面自动化仍由
Playwright 通过 connect_over_cdp 完成，因此本模块不依赖任何浏览器驱动库。

典型调用顺序（单窗口串行注册）：
    client.modify_proxy(...)        # 把代理池取到的 IP 写进资料
    client.clear_local_cache(...)   # 复用同一资料，必须清掉上一个号的 cookie
    client.random_fingerprint(...)  # 换一套平台侧指纹
    data = client.open_browser(...) # 拿 ws / http 调试地址
"""

from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Optional


LogFn = Callable[[str], None]

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_ROXY_API_BASE = "http://127.0.0.1:50000"


class RoxyBrowserError(RuntimeError):
    """RoxyBrowser 本地 API 调用失败。"""


def _noop_log(_: str) -> None:
    return None


def normalize_api_base(value: Any) -> str:
    """Roxy 本地 API 只监听本机，非本机地址一律拒绝。"""
    raw = str(value or DEFAULT_ROXY_API_BASE).strip().rstrip("/")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != "http" or not parsed.hostname or parsed.hostname not in _LOCAL_HOSTS:
        raise RoxyBrowserError(f"Roxy API 地址必须是本机 HTTP 地址，例如 {DEFAULT_ROXY_API_BASE}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise RoxyBrowserError("Roxy API 地址端口无效") from exc
    if not port:
        raise RoxyBrowserError("Roxy API 地址缺少端口")
    return raw


def profile_id_from_config(config: Dict[str, Any]) -> str:
    """取资料 ID；配置里填了多个也只用第一个（本项目单窗口串行注册）。"""
    raw = config.get("roxy_profile_id") or config.get("roxy_profile_ids") or ""
    if isinstance(raw, (list, tuple, set)):
        parts = [str(item).strip() for item in raw]
    else:
        parts = re.split(r"[,\s]+", str(raw).strip())
    for item in parts:
        profile_id = item.strip()
        if profile_id:
            return profile_id
    return ""


def normalize_workspace_id(value: Any) -> int:
    """接受纯数字工作区 ID，或 Roxy 团队 ID（CAI0001 形式）。"""
    if isinstance(value, bool):
        value = ""
    raw = str(value or "").strip()
    if raw.isdigit():
        workspace_id = int(raw)
    else:
        team_id_match = re.fullmatch(r"CAI0*(\d+)", raw, flags=re.IGNORECASE)
        workspace_id = int(team_id_match.group(1)) if team_id_match else 0
    if workspace_id <= 0:
        raise RoxyBrowserError("请填写 Roxy 工作区数字 ID，或团队 ID（CAI 开头）")
    return workspace_id


def validate_roxy_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """校验并返回归一化后的 Roxy 连接参数，任一缺失都直接抛错。"""
    api_base = normalize_api_base(config.get("roxy_api_base"))
    api_key = str(config.get("roxy_api_key") or "").strip()
    if not api_key:
        raise RoxyBrowserError("请填写 Roxy API Key")
    workspace_id = normalize_workspace_id(config.get("roxy_workspace_id"))
    profile_id = profile_id_from_config(config)
    if not profile_id:
        raise RoxyBrowserError("请填写 Roxy 资料 ID（窗口 dirId）")
    try:
        timeout_sec = max(3.0, min(float(config.get("roxy_api_timeout_sec") or 20), 120.0))
    except (TypeError, ValueError):
        timeout_sec = 20.0
    return {
        "api_base": api_base,
        "api_key": api_key,
        "workspace_id": workspace_id,
        "profile_id": profile_id,
        "timeout_sec": timeout_sec,
    }


def proxy_info_from_url(proxy_url: Any) -> Dict[str, Any]:
    """把代理池返回的 URL 映射成 Roxy 的 proxyInfo。

    传空值时返回 noproxy，等价于把资料改回直连。
    """
    raw = str(proxy_url or "").strip()
    if not raw:
        return {
            "moduleId": 0,
            "proxyMethod": "custom",
            "proxyCategory": "noproxy",
        }

    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urllib.parse.urlparse(raw)
    scheme = (parsed.scheme or "http").lower()
    if scheme in {"socks5", "socks5h", "socks"}:
        protocol = "SOCKS5"
    elif scheme == "https":
        protocol = "HTTPS"
    else:
        protocol = "HTTP"

    host = str(parsed.hostname or "").strip()
    if not host:
        raise RoxyBrowserError(f"代理地址无法解析出主机名: {proxy_url!r}")
    try:
        port = int(parsed.port or 0)
    except (TypeError, ValueError) as exc:
        raise RoxyBrowserError(f"代理地址端口无效: {proxy_url!r}") from exc
    if port <= 0:
        raise RoxyBrowserError(f"代理地址缺少端口: {proxy_url!r}")

    return {
        "moduleId": 0,
        "proxyMethod": "custom",
        "proxyCategory": protocol,
        "ipType": "IPV6" if ":" in host else "IPV4",
        "protocol": protocol,
        "host": host,
        "port": port,
        "proxyUserName": urllib.parse.unquote(parsed.username or ""),
        "proxyPassword": urllib.parse.unquote(parsed.password or ""),
    }


class RoxyClient:
    """调用 RoxyBrowser 本机 API，API Key 只出现在请求头。"""

    def __init__(self, api_base: Any, api_key: Any, *, timeout_sec: Any = 20) -> None:
        self.api_base = normalize_api_base(api_base)
        self.api_key = str(api_key or "").strip()
        if not self.api_key:
            raise RoxyBrowserError("请填写 Roxy API Key")
        try:
            self.timeout_sec = max(3.0, float(timeout_sec or 20))
        except (TypeError, ValueError):
            self.timeout_sec = 20.0

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> tuple["RoxyClient", Dict[str, Any]]:
        settings = validate_roxy_config(config)
        client = cls(
            settings["api_base"],
            settings["api_key"],
            timeout_sec=settings["timeout_sec"],
        )
        return client, settings

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.api_base}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        body = None
        headers = {"token": self.api_key}
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_sec) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise RoxyBrowserError(f"Roxy API {path} 返回 HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RoxyBrowserError(
                f"无法连接 Roxy API（请确认 Roxy 客户端已启动且 API 已启用）：{exc.reason}"
            ) from exc
        except OSError as exc:
            raise RoxyBrowserError(f"Roxy API 网络错误：{exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RoxyBrowserError(f"Roxy API {path} 返回了无效 JSON") from exc
        if not isinstance(data, dict):
            raise RoxyBrowserError(f"Roxy API {path} 返回格式错误")
        return data

    @staticmethod
    def _require_success(result: Dict[str, Any], path: str) -> Dict[str, Any]:
        if result.get("code") != 0:
            message = str(result.get("msg") or "未知错误")
            raise RoxyBrowserError(f"Roxy API {path} 失败：{message}")
        data = result.get("data")
        return data if isinstance(data, dict) else {}

    def health(self) -> bool:
        try:
            result = self._request("GET", "/health")
        except RoxyBrowserError:
            return False
        return result.get("code") == 0

    def open_browser(
        self,
        *,
        profile_id: str,
        headless: bool = False,
        args: Optional[list] = None,
    ) -> Dict[str, Any]:
        """打开资料窗口，返回含 ws / http 调试地址的 data。

        headless=True 走 Roxy 自己的无头启动；注意无头下 Turnstile 通过率明显偏低。
        """
        payload: Dict[str, Any] = {"dirId": profile_id, "headless": bool(headless)}
        if args:
            payload["args"] = list(args)
        result = self._request("POST", "/browser/open", payload)
        data = self._require_success(result, "/browser/open")

        ws_url = str(data.get("ws") or data.get("wsUrl") or "").strip()
        http_address = str(
            data.get("http")
            or data.get("httpUrl")
            or data.get("debuggerAddress")
            or data.get("debugPort")
            or ""
        ).strip()
        if not http_address:
            port = data.get("port") or data.get("debug_port") or data.get("remoteDebuggingPort")
            if port:
                http_address = f"127.0.0.1:{port}"
        if not ws_url and not http_address:
            raise RoxyBrowserError(f"Roxy API /browser/open 未返回调试地址，原始 data={data!r}")
        data["ws"] = ws_url
        data["http"] = http_address
        return data

    def close_browser(self, profile_id: str) -> None:
        """关闭资料窗口；窗口本就没开时视为成功。"""
        result = self._request("POST", "/browser/close", {"dirId": profile_id})
        if result.get("code") == 0:
            return
        message = str(result.get("msg") or "").lower()
        if any(token in message for token in ("not", "close", "不存在", "已关", "未打开")):
            return
        raise RoxyBrowserError(f"Roxy API /browser/close 失败：{result.get('msg') or '未知错误'}")

    def clear_local_cache(self, workspace_id: int, profile_id: str) -> None:
        result = self._request(
            "POST",
            "/browser/clear_local_cache",
            {
                "workspaceId": workspace_id,
                "dirIds": [profile_id],
                "type": "cloud",
            },
        )
        self._require_success(result, "/browser/clear_local_cache")

    def random_fingerprint(self, workspace_id: int, profile_id: str) -> None:
        result = self._request(
            "POST",
            "/browser/random_env",
            {
                "workspaceId": workspace_id,
                "dirId": profile_id,
            },
        )
        self._require_success(result, "/browser/random_env")

    def modify_proxy(self, workspace_id: int, profile_id: str, proxy_url: Any) -> Dict[str, Any]:
        """把代理写进资料。

        /browser/mdf 是增量更新，只传 proxyInfo 不会动资料的其他配置。
        """
        proxy_info = proxy_info_from_url(proxy_url)
        result = self._request(
            "POST",
            "/browser/mdf",
            {
                "workspaceId": workspace_id,
                "dirId": profile_id,
                "proxyInfo": proxy_info,
            },
        )
        self._require_success(result, "/browser/mdf")
        return proxy_info


def normalize_debugger_address(value: Any) -> str:
    """把 ws:// 或带路径的地址统一压成 host:port。"""
    addr = str(value or "").strip()
    if not addr:
        return ""
    if "://" in addr:
        addr = addr.split("://", 1)[-1]
    if "/" in addr:
        addr = addr.split("/", 1)[0]
    return addr.strip()


def _cdp_endpoint_ready(debugger_address: str, *, timeout_sec: float = 1.0) -> tuple[bool, str]:
    """探测远程调试口是否可连：先 TCP，再试 HTTP 调试接口。"""
    addr = normalize_debugger_address(debugger_address)
    if not addr:
        return False, "调试地址为空"
    host, _, port_text = addr.rpartition(":")
    host = host or "127.0.0.1"
    try:
        port = int(port_text)
    except ValueError:
        return False, f"地址无效 {addr}"

    try:
        with socket.create_connection((host, port), timeout=max(0.3, float(timeout_sec))):
            pass
    except OSError as exc:
        return False, f"tcp:{exc}"

    http_timeout = max(0.4, float(timeout_sec))
    last_detail = "tcp-ok"
    for path in ("/json/version", "/json/list"):
        try:
            request = urllib.request.Request(f"http://{addr}{path}", method="GET")
            with urllib.request.urlopen(request, timeout=http_timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
            if not raw:
                last_detail = f"{path}:空响应"
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return True, f"{path}:非 JSON"
            if isinstance(data, dict):
                return True, str(data.get("Browser") or data.get("webSocketDebuggerUrl") or path)
            if isinstance(data, list):
                return True, f"{path}:tabs={len(data)}"
            return True, path
        except OSError as exc:
            last_detail = f"{path}:{exc}"
            continue
    # TCP 通但 HTTP 没通算半就绪，交给上层直接尝试附着
    return True, f"tcp-only({last_detail})"


def wait_cdp_ready(
    debugger_address: str,
    *,
    timeout_sec: float = 25.0,
    interval_sec: float = 0.35,
    log: Optional[LogFn] = None,
) -> str:
    """轮询到调试口可用为止，返回规范化的 host:port。"""
    log = log or _noop_log
    addr = normalize_debugger_address(debugger_address)
    if not addr:
        raise RoxyBrowserError("CDP 调试地址为空")
    deadline = time.time() + max(3.0, float(timeout_sec))
    attempt = 0
    last_detail = ""
    while time.time() < deadline:
        attempt += 1
        ok, detail = _cdp_endpoint_ready(addr, timeout_sec=0.9)
        if ok:
            log(f"[Roxy] CDP 已就绪 {addr}（{detail}），尝试 {attempt} 次")
            return addr
        last_detail = detail
        if attempt == 1 or attempt % 5 == 0:
            log(f"[Roxy] 等待 CDP {addr}，剩余 {max(0.0, deadline - time.time()):.0f}s（{detail}）")
        time.sleep(max(0.15, float(interval_sec)))
    raise RoxyBrowserError(f"CDP 调试口在 {timeout_sec:.0f}s 内未就绪：{addr}；最后错误：{last_detail}")


def fetch_browser_ws(debugger_address: str) -> str:
    """从 /json/version 取 browser 级 webSocketDebuggerUrl。"""
    addr = normalize_debugger_address(debugger_address)
    if not addr:
        return ""
    try:
        request = urllib.request.Request(f"http://{addr}/json/version", method="GET")
        with urllib.request.urlopen(request, timeout=3.0) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
        ws_url = str((payload or {}).get("webSocketDebuggerUrl") or "").strip()
        return ws_url if ws_url.startswith("ws") else ""
    except (OSError, json.JSONDecodeError, AttributeError):
        return ""
