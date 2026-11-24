"""从 CHANGELOG.md 提取指定版本的更新日志，并追加版本对比链接。"""
import re
import sys
from pathlib import Path

REPO = "hunyanjie/PersonalDAV"
VERSION_HEADING = re.compile(r"^## v(\d+(?:\.\d+)+)\b", re.MULTILINE)


def find_prev_version(content: str, current: str) -> str | None:
    versions = VERSION_HEADING.findall(content)
    for i, version in enumerate(versions):
        if version == current and i + 1 < len(versions):
            return versions[i + 1]
    return None


def extract_notes(content: str, version: str) -> str | None:
    pattern = rf"^## v{re.escape(version)}(?![\d.]).*?(?=^## v\d|\Z)"
    match = re.search(pattern, content, re.DOTALL | re.MULTILINE)
    if not match:
        return None
    body = match.group(0).strip()
    prev = find_prev_version(content, version)
    if prev:
        body += f"\n\n**Full Changelog**: https://github.com/{REPO}/compare/v{prev}...v{version}"
    return body


def main():
    if len(sys.argv) < 2:
        print("Usage: extract_release_notes.py <version>", file=sys.stderr)
        sys.exit(1)
    version = sys.argv[1]
    content = Path("CHANGELOG.md").read_text(encoding="utf-8")
    body = extract_notes(content, version)
    if body is None:
        print(f"未找到 v{version} 的更新日志", file=sys.stderr)
        sys.exit(1)
    Path("release_notes.md").write_text(body, encoding="utf-8")
    print(f"提取 v{version} 更新日志成功")


if __name__ == "__main__":
    main()
