"""从 CHANGELOG.md 提取指定版本的更新日志，并追加版本对比链接"""
import re
import sys

REPO = "hunyanjie/PersonalDAV"

def find_prev_version(content: str, current: str) -> str | None:
    versions = re.findall(r"^## v(\d+\.\d+)$", content, re.MULTILINE)
    for i, v in enumerate(versions):
        if v == current and i + 1 < len(versions):
            return versions[i + 1]
    return None

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
        body = match.group(0).strip()
        prev = find_prev_version(content, version)
        if prev:
            body += f"\n\n**Full Changelog**: https://github.com/{REPO}/compare/v{prev}...v{version}"
        with open("release_notes.md", "w", encoding="utf-8") as out:
            out.write(body)
        print(f"提取 v{version} 更新日志成功")
    else:
        print(f"未找到 v{version} 的更新日志", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
