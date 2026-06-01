"""从 CHANGELOG.md 提取指定版本的更新日志"""
import re
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: extract_release_notes.py <version>", file=sys.stderr)
        sys.exit(1)
    version = sys.argv[1]
    with open("CHANGELOG.md", "r", encoding="utf-8") as f:
        content = f.read()
    pattern = rf"## v{re.escape(version)}.*?(?=## v|\Z)"
    match = re.search(pattern, content, re.DOTALL)
    if match:
        with open("release_notes.md", "w", encoding="utf-8") as out:
            out.write(match.group(0).strip())
        print(f"提取 v{version} 更新日志成功")
    else:
        print(f"未找到 v{version} 的更新日志", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
