"""一键运行全部测试：pytest 单元测试 + MCP 工具集成检查"""
import subprocess
import sys
from pathlib import Path

TEST_DIR = Path(__file__).parent

def run_pytest():
    result = subprocess.run([sys.executable, "-m", "pytest", str(TEST_DIR), "-v"], capture_output=False)
    return result.returncode

def run_mcp_check():
    print("\n========== MCP 工具集成检查 ==========")
    result = subprocess.run([sys.executable, str(TEST_DIR / "_run_mcp_tools_check.py")], capture_output=False)
    if result.returncode == 0:
        print("MCP 工具检查通过")
    else:
        print("MCP 工具检查失败")
    return result.returncode

if __name__ == "__main__":
    exit_code = 0

    ret = run_pytest()
    if ret != 0:
        exit_code = ret

    ret = run_mcp_check()
    if ret != 0:
        exit_code = ret

    if exit_code == 0:
        print("\n所有测试通过")
    else:
        print(f"\n部分测试失败，退出码: {exit_code}")
    sys.exit(exit_code)
