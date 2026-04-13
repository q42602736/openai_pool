"""
auto_scheduler.py - 自动调度器
每1小时检测有效账号数量（通过实际探测 401/403 判定无效），
当有效数量 < 100 时自动触发 ncs_register.py 批量注册。
"""

import os
import time
import subprocess
import sys
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ================= 配置 =================

CHECK_INTERVAL_SECONDS = 3600       # 检查间隔：1小时
ACCOUNT_THRESHOLD = 150             # 有效账号数量阈值
REGISTER_SCRIPT = "ncs_register.py" # 注册脚本文件名

# 注册参数（对应 ncs_register.py 的 main() 交互）
AUTO_PARAMS = {
    "proxy": "",              # 代理地址，留空=不使用代理
    "cpa_cleanup": "n",       # 注册前是否清理 CPA 无效号: "y" 或 "n"
                              # （调度器自己已经做了探测+删除，建议设 "n" 避免重复）
    "total_accounts": 10,     # 每次注册数量（实际会取 max(此值, 缺口数)）
    "max_workers": 3,         # 并发数
}

# 探测配置
PROBE_MAX_COUNT = 150        # 每次最多探测多少个账号（0 = 不限制，全部探测）
PROBE_WORKERS = 12           # 探测并发数
PROBE_TIMEOUT = 10           # 单次探测超时（秒）


# ================= 加载 config.json =================

def _load_account_count_config() -> dict:
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    defaults = {
        "token_json_dir": "codex_tokens",
        "ak_file": "ak.txt",
        "upload_api_url": "",
        "upload_api_token": "",
        "proxy": "",
    }
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                defaults.update(cfg)
        except Exception as e:
            print(f"[警告] 读取 config.json 失败: {e}")
    return defaults


# ================= 工具：规范化 CPA API 路径 =================

def _cpa_auth_files_url(raw_url: str) -> str:
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(raw_url.strip())
    path = parsed.path.rstrip("/")
    if not path.endswith("/auth-files"):
        if "/management" in path:
            path = path.split("/management")[0] + "/management/auth-files"
        else:
            path = path + "/auth-files"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _cpa_api_call_url(auth_files_url: str) -> str:
    return auth_files_url.replace("/auth-files", "/api-call")


# ================= 有效账号检测（本地回退） =================

def count_valid_accounts_local(cfg: dict) -> int:
    """本地文件统计（不做真实探测，仅作回退）"""
    base_dir = os.path.dirname(os.path.abspath(__file__))

    token_dir = cfg["token_json_dir"]
    if not os.path.isabs(token_dir):
        token_dir = os.path.join(base_dir, token_dir)
    if os.path.isdir(token_dir):
        count = len([f for f in os.listdir(token_dir) if f.endswith(".json")])
        print(f"[检测] 本地 token_json_dir 文件数: {count}")
        return count

    ak_file = cfg["ak_file"]
    if not os.path.isabs(ak_file):
        ak_file = os.path.join(base_dir, ak_file)
    if os.path.exists(ak_file):
        with open(ak_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        print(f"[检测] 本地 ak.txt 行数: {len(lines)}")
        return len(lines)

    print("[检测] 未找到本地账号文件，视为 0")
    return 0


# ================= 有效账号检测（CPA 探测版） =================

def count_valid_accounts_by_probe(cfg: dict) -> int:
    """
    从 CPA 平台拉取 auth-files 列表，并发探测每个 token：
    - 响应 401 / 403 → 无效，自动从 CPA 删除
    - 响应 200 / 429 / 其他 → 视为有效（429 是限流，账号本身没问题）
    - 探测异常 → 保守处理，视为有效，不删除

    支持 PROBE_MAX_COUNT 限制单次最多探测数量。
    """
    api_url = cfg.get("upload_api_url", "").strip()
    api_token = cfg.get("upload_api_token", "").strip()

    if not api_url or not api_token:
        print("[检测] 未配置 CPA API（upload_api_url/upload_api_token），回退本地统计")
        return count_valid_accounts_local(cfg)

    try:
        from curl_cffi import requests as curl_requests
    except ImportError:
        print("[检测] curl_cffi 未安装，回退本地统计")
        return count_valid_accounts_local(cfg)

    list_url = _cpa_auth_files_url(api_url)
    api_call_url = _cpa_api_call_url(list_url)
    headers = {"Authorization": f"Bearer {api_token}"}

    # ---- 1. 拉取 auth-files 列表 ----
    try:
        resp = curl_requests.get(list_url, headers=headers, timeout=15)
        if resp.status_code != 200:
            print(f"[检测] 拉取 auth-files 失败: {resp.status_code}，回退本地统计")
            return count_valid_accounts_local(cfg)
        data = resp.json()
        files = data.get("files", []) if isinstance(data, dict) else []
    except Exception as e:
        print(f"[检测] 拉取 auth-files 异常: {e}，回退本地统计")
        return count_valid_accounts_local(cfg)

    total_files = len(files)
    if total_files == 0:
        print("[检测] auth-files 列表为空，有效账号: 0")
        return 0

    # ---- 2. 决定探测范围 ----
    skipped_count = 0
    if PROBE_MAX_COUNT > 0 and total_files > PROBE_MAX_COUNT:
        import random
        probe_files = random.sample(files, PROBE_MAX_COUNT)
        skipped_count = total_files - PROBE_MAX_COUNT
        print(f"[检测] 共 {total_files} 个账号，随机抽样探测 {PROBE_MAX_COUNT} 个（跳过 {skipped_count} 个）")
    else:
        probe_files = files
        print(f"[检测] 共 {total_files} 个账号，全部探测...")

    # ---- 3. 并发探测 ----
    valid_count = 0
    invalid_names = []

    def probe_one(file_obj: dict):
        auth_index = str(file_obj.get("auth_index") or "").strip()
        name = str(file_obj.get("name") or "").strip()
        if not auth_index:
            # 没有 auth_index 无法探测，保守视为有效
            return name, True, 0

        payload = {
            "auth_index": auth_index,
            "method": "POST",
            "url": "https://chatgpt.com/backend-api/codex/responses/compact",
            "header": {
                "Authorization": "Bearer $TOKEN$",
                "Content-Type": "application/json",
                "User-Agent": "codex_cli_rs/0.101.0",
            },
            "data": json.dumps(
                {"model": "gpt-5.1-codex", "input": [{"role": "user", "content": "ping"}]},
                ensure_ascii=False,
            ),
        }
        try:
            r = curl_requests.post(
                api_call_url, headers=headers, json=payload, timeout=PROBE_TIMEOUT
            )
            r.raise_for_status()
            body = r.json()
            status_code = int(body.get("status_code") or 0)
            is_valid = status_code not in (401, 403)
            return name, is_valid, status_code
        except Exception:
            # 探测本身异常（网络等），保守不删
            return name, True, -1

    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        future_map = {pool.submit(probe_one, f): f for f in probe_files}
        done = 0
        for future in as_completed(future_map):
            done += 1
            name, is_valid, status_code = future.result()
            if is_valid:
                valid_count += 1
            else:
                invalid_names.append(name)
                print(f"[检测] 无效账号 ({status_code}): {name}")
            if done % 20 == 0 or done == len(probe_files):
                print(f"[检测] 进度 {done}/{len(probe_files)}，有效: {valid_count}，无效: {len(invalid_names)}")

    # 未探测的部分保守视为全部有效
    estimated_valid = valid_count + skipped_count
    print(f"[检测] 探测完成: 探测有效 {valid_count}，未探测(视为有效) {skipped_count}，"
          f"无效(401/403) {len(invalid_names)}")
    print(f"[检测] 预估有效账号总数: {estimated_valid}")

    # ---- 4. 自动删除 401/403 账号 ----
    if invalid_names:
        print(f"[检测] 开始删除 {len(invalid_names)} 个无效账号...")
        deleted = 0
        for name in invalid_names:
            try:
                dr = curl_requests.delete(
                    list_url, params={"name": name}, headers=headers, timeout=10
                )
                if 200 <= dr.status_code < 300:
                    deleted += 1
                else:
                    print(f"[检测] 删除失败: {name} -> HTTP {dr.status_code}")
            except Exception as e:
                print(f"[检测] 删除异常: {name} -> {e}")
        print(f"[检测] 已删除 {deleted}/{len(invalid_names)} 个无效账号")

    return estimated_valid


# ================= 自动触发注册 =================

def build_register_input(params: dict, cfg: dict) -> str:
    """
    构造模拟 ncs_register.py main() 交互的 stdin 输入序列。
    顺序对应 main() 中的 input() 调用：
      1. 使用默认代理? (Y/n)   —— 仅当 config.json 有代理或环境变量有代理时出现
      2. 注册前清理 CPA? (Y/n) —— 仅当 upload_api_url 非空时出现
      3. 注册账号数量
      4. 并发数
    """
    lines = []

    default_proxy = cfg.get("proxy", "").strip()
    env_proxy = (
        os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        or os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or ""
    )
    configured_proxy = params.get("proxy", "").strip()

    if default_proxy:
        if configured_proxy and configured_proxy != default_proxy:
            lines.append("n")
            lines.append(configured_proxy)
        else:
            lines.append("y")
    elif env_proxy:
        if configured_proxy and configured_proxy != env_proxy:
            lines.append("n")
            lines.append(configured_proxy)
        else:
            lines.append("y")
    else:
        # 无默认代理，直接输入（可为空）
        lines.append(configured_proxy)

    # CPA 清理（仅当配置了 upload_api_url 时 main() 才会问）
    if cfg.get("upload_api_url", "").strip():
        lines.append(params.get("cpa_cleanup", "n"))

    lines.append(str(params.get("total_accounts", 10)))
    lines.append(str(params.get("max_workers", 3)))

    return "\n".join(lines) + "\n"


def trigger_registration(params: dict, cfg: dict) -> bool:
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), REGISTER_SCRIPT)
    if not os.path.exists(script_path):
        print(f"[错误] 注册脚本不存在: {script_path}")
        return False

    stdin_input = build_register_input(params, cfg)
    print(f"\n[触发注册] 调用 {REGISTER_SCRIPT}")
    print(f"[触发注册] stdin 参数预览:\n{stdin_input.strip()}")
    print(f"[触发注册] 开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    try:
        result = subprocess.run(
            [sys.executable, script_path],
            input=stdin_input,
            text=True,
            timeout=7200,   # 最长等待 2 小时
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        print(f"\n[触发注册] 完成，返回码: {result.returncode}")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("[触发注册] 超时（2小时），已终止")
        return False
    except Exception as e:
        print(f"[触发注册] 执行异常: {e}")
        return False


# ================= 主循环 =================

def main():
    print("=" * 60)
    print("  账号自动补充调度器")
    print(f"  检查间隔  : {CHECK_INTERVAL_SECONDS // 60} 分钟")
    print(f"  触发阈值  : < {ACCOUNT_THRESHOLD} 个有效账号")
    print(f"  注册脚本  : {REGISTER_SCRIPT}")
    print(f"  最大探测数: {PROBE_MAX_COUNT if PROBE_MAX_COUNT > 0 else '不限制（全量）'}")
    print(f"  探测并发数: {PROBE_WORKERS}")
    print("=" * 60)

    cfg = _load_account_count_config()
    use_cpa = bool(cfg.get("upload_api_url") and cfg.get("upload_api_token"))
    print(f"[Info] 账号计数方式: {'CPA API 探测（401/403自动删除）' if use_cpa else '本地文件统计'}")
    print(f"[Info] 按 Ctrl+C 停止调度器\n")

    while True:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{'─' * 60}")
        print(f"[{now_str}] 开始检测有效账号数量...")

        try:
            if use_cpa:
                count = count_valid_accounts_by_probe(cfg)
            else:
                count = count_valid_accounts_local(cfg)
        except Exception as e:
            print(f"[检测] 统计异常: {e}，本次跳过（保守不触发注册）")
            count = ACCOUNT_THRESHOLD

        print(f"[检测] 当前有效账号: {count} 个 (阈值: {ACCOUNT_THRESHOLD})")

        if count < ACCOUNT_THRESHOLD:
            needed = ACCOUNT_THRESHOLD - count
            print(f"[检测] ⚠️  账号不足！缺口 {needed} 个，触发自动注册...")
            register_params = dict(AUTO_PARAMS)
            register_params["total_accounts"] = max(
                int(AUTO_PARAMS.get("total_accounts", 10)), needed
            )
            trigger_registration(register_params, cfg)
            # 注册完成后重新加载配置
            cfg = _load_account_count_config()
            use_cpa = bool(cfg.get("upload_api_url") and cfg.get("upload_api_token"))
        else:
            print(f"[检测] ✅ 账号数量充足，无需注册")

        next_check = datetime.fromtimestamp(time.time() + CHECK_INTERVAL_SECONDS)
        print(f"[调度] 下次检查时间: {next_check.strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            time.sleep(CHECK_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            print("\n[调度] 已手动停止调度器")
            break


if __name__ == "__main__":
    main()