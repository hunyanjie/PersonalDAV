import ipaddress
import re


def validate_port(port_str: str) -> tuple[bool, str]:
    try:
        p = int(port_str)
        if p < 1 or p > 65535:
            return False, "端口范围: 1-65535"
        if p < 1024:
            return False, "建议使用 1024-65535 端口（低于 1024 需管理员权限）"
        return True, ""
    except (ValueError, TypeError):
        return False, "请输入有效数字"


def validate_ip_pattern(pattern: str) -> tuple[bool, str]:
    p = pattern.strip()
    if not p:
        return True, ""
    try:
        ipaddress.ip_address(p)
        return True, ""
    except ValueError:
        pass
    try:
        ipaddress.ip_network(p, strict=False)
        return True, ""
    except ValueError:
        pass
    if '*' in p:
        import fnmatch
        test = p.replace('*', '0')
        try:
            ipaddress.ip_address(test)
            return True, ""
        except ValueError:
            pass
    return False, f"无效的 IP 格式: {p}"


def validate_ip_list(text: str) -> list[tuple[str, str]]:
    errors = []
    for line in re.split(r'[\n,，]+', text):
        p = line.strip()
        if p:
            ok, msg = validate_ip_pattern(p)
            if not ok:
                errors.append((p, msg))
    return errors


def validate_password_strength(password: str) -> tuple[bool, str]:
    if not password:
        return False, "密码不能为空"
    if len(password) < 6:
        return False, "密码长度至少 6 位"
    score = 0
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1
    if len(password) >= 10:
        score += 1
    labels = {0: "极弱", 1: "弱", 2: "中等", 3: "强", 4: "很强", 5: "极强"}
    level = labels.get(score, "未知")
    if score < 2:
        return False, f"密码强度: {level}（建议包含大小写字母、数字和特殊字符）"
    return True, f"密码强度: {level}"
