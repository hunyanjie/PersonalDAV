"""一键运行全部测试：pytest 单元测试 + MCP 内部/HTTP 集成测试 + 鉴权测试"""
import subprocess
import sys
from pathlib import Path

TEST_DIR = Path(__file__).parent

def run_pytest():
    result = subprocess.run([sys.executable, "-m", "pytest", str(TEST_DIR), "-v"], capture_output=False)
    return result.returncode

def run(name, label):
    print(f"\n========== {label} ==========")
    result = subprocess.run([sys.executable, str(TEST_DIR / name)], capture_output=False)
    if result.returncode == 0:
        print(f"{label} 通过")
    else:
        print(f"{label} 失败")
    return result.returncode

if __name__ == "__main__":
    exit_code = 0

    ret = run_pytest()
    if ret != 0:
        exit_code = ret

    ret = run("_run_mcp_tools_check.py", "MCP 内部工具检查")
    if ret != 0:
        exit_code = ret

    ret = run("_run_mcp_http_check.py", "MCP HTTP 工具检查")
    if ret != 0:
        exit_code = ret

    ret = run("test_mcp_auth_http.py", "MCP 鉴权测试")
    if ret != 0:
        exit_code = ret

    if exit_code == 0:
        print("\n所有测试通过")
    else:
        print(f"\n部分测试失败，退出码: {exit_code}")
    sys.exit(exit_code)
