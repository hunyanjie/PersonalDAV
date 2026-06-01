"""测试 MCP 鉴权中间件 — 通过 HTTP 直打端点验证 401/403/200 + 日志落盘"""
import sys, time, io
sys.path.insert(0, '.')
import httpx
from services.mcp_server import MCPServer
from services.auth_service import AuthService
from utils.logger import logger
import logging

MCP_PORT = 8102
srv = MCPServer()
auth = AuthService()
errors = []
results = []

def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  {tag}  {name}  {detail}")
    if not ok:
        errors.append(name)

def log_capture():
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    return buf, handler

def main():
    global auth
    auth.clear_password()
    assert srv.start(host="127.0.0.1", port=MCP_PORT), "MCP server start failed"
    url = f"http://127.0.0.1:{MCP_PORT}/sse"
    time.sleep(0.5)

    def http_get(path="", **kwargs):
        """使用 stream 避免 SSE 流式响应阻塞"""
        target = url if not path else f"http://127.0.0.1:{MCP_PORT}{path}"
        with httpx.Client() as c:
            with c.stream("GET", target, **kwargs) as r:
                return r

    print("=== 无密码 — 应放行 ===")
    r = http_get()
    check("无密码 200", r.status_code == 200, f"status={r.status_code}")

    print("\n=== 设置密码后 — 应拦截无令牌请求 ===")
    auth.set_password("auth-test-pw")
    token = auth.get_mcp_token()
    from services.settings_service import SettingsService
    ss = SettingsService()
    ss.set_setting("bypass_localhost", "False")

    r = http_get()
    check("无令牌 401", r.status_code == 401, f"status={r.status_code}")

    r = http_get(headers={"Authorization": "Bearer invalid_token_123"})
    check("无效令牌 401", r.status_code == 401, f"status={r.status_code}")

    r = http_get(headers={"Authorization": f"Bearer {token}"})
    check("有效令牌 200", r.status_code == 200, f"status={r.status_code}")

    print("\n=== IP 黑白名单 ===")

    ss.set_setting("ip_blacklist", "127.0.0.1")
    r = http_get(headers={"Authorization": f"Bearer {token}"})
    check("IP 黑名单封禁 403", r.status_code == 403, f"status={r.status_code}")
    ss.set_setting("ip_blacklist", "")

    ss.set_setting("ip_whitelist", "192.168.1.1")
    r = http_get(headers={"Authorization": f"Bearer {token}"})
    check("IP 不在白名单 403", r.status_code == 403, f"status={r.status_code}")
    ss.set_setting("ip_whitelist", "")

    print("\n=== 访问频率限制 ===")

    ss.set_setting("rate_limit_enabled", "True")
    ss.set_setting("rate_limit_max", "3")
    ss.set_setting("bypass_localhost", "True")
    r = http_get()
    check("频率限制第1次 200", r.status_code == 200, f"status={r.status_code}")
    r = http_get()
    check("频率限制第2次 200", r.status_code == 200, f"status={r.status_code}")
    r = http_get()
    check("频率限制第3次 200", r.status_code == 200, f"status={r.status_code}")
    r = http_get()
    check("频率限制第4次 429", r.status_code == 429, f"status={r.status_code}")
    ss.set_setting("rate_limit_enabled", "False")

    print("\n=== 免密码 IP ===")
    ss.set_setting("bypass_localhost", "False")
    r = http_get()
    check("关闭本机免密 401", r.status_code == 401, f"status={r.status_code}")

    ss.set_setting("bypass_localhost", "True")
    r = http_get()
    check("重开本机免密 200", r.status_code == 200, f"status={r.status_code}")

    ss.set_setting("bypass_localhost", "False")
    ss.set_setting("ip_bypass_auth", "127.0.0.1")
    r = http_get()
    check("IP 免密名单 200", r.status_code == 200, "127.0.0.1 in bypass list")
    ss.set_setting("bypass_localhost", "True")
    ss.set_setting("ip_bypass_auth", "")

    print("\n=== 鉴权日志落盘 ===")
    log_buf, log_handler = log_capture()
    # 有密码+关闭本机免密状态，发一次无令牌请求触发失败日志
    ss.set_setting("bypass_localhost", "False")
    r = http_get()
    _ = r.status_code
    # 再发一次有效令牌请求触发成功日志
    token = auth.get_mcp_token()
    r = http_get(headers={"Authorization": f"Bearer {token}"})
    _ = r.status_code
    ss.set_setting("bypass_localhost", "True")
    auth.clear_password()
    logger.removeHandler(log_handler)
    log_text = log_buf.getvalue()
    check("日志不为空", bool(log_text), f'共 {len(log_text)} 字符')
    found_fail = "登录失败" in log_text
    found_success = "登录成功" in log_text
    found_ip = "127.0.0.1" in log_text
    found_mcp = "[MCP]" in log_text
    check("包含登录失败日志", found_fail, "")
    check("包含登录成功日志", found_success, "")
    check("包含客户端 IP", found_ip, "")
    check("包含 MCP 协议标识", found_mcp, "")

    srv.stop()
    print(f"\n{'='*40}")
    if errors:
        print(f"!!! {len(errors)} 个检查失败:")
        for e in errors:
            print(f"  - {e}")
    else:
        print("所有鉴权检查通过")
    sys.exit(1 if errors else 0)

if __name__ == "__main__":
    main()
