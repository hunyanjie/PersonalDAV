import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from config import DATA_DIR


def generate_self_signed_cert(cert_path, key_path, common_name="localhost"):
    """生成自签名 SSL 证书和私钥，返回 (cert_path, key_path)"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PersonalDAV"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )

    os.makedirs(os.path.dirname(cert_path) or ".", exist_ok=True)

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path


def get_cert_info(cert_path):
    """提取证书信息，返回 dict 或 None"""
    if not cert_path or not os.path.isfile(cert_path):
        return None
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        now = datetime.datetime.now(datetime.timezone.utc)
        nva = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
        nvb = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
        remaining = (nva - now).days
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "valid_from": nvb.strftime("%Y-%m-%d"),
            "valid_to": nva.strftime("%Y-%m-%d"),
            "remaining_days": remaining,
            "is_self_signed": cert.subject.rfc4514_string() == cert.issuer.rfc4514_string(),
        }
    except Exception:
        return None


def should_renew(cert_path, days_before=30):
    """检查证书是否需要在 days_before 天内续期"""
    info = get_cert_info(cert_path)
    if info is None:
        return True
    return info["remaining_days"] <= days_before


def ensure_default_cert(data_dir=None):
    """确保默认证书存在，不存在则自动生成"""
    data_dir = data_dir or DATA_DIR
    cert_path = os.path.join(data_dir, "ssl", "cert.pem")
    key_path = os.path.join(data_dir, "ssl", "key.pem")
    if not os.path.isfile(cert_path) or not os.path.isfile(key_path) or should_renew(cert_path, 0):
        os.makedirs(os.path.join(data_dir, "ssl"), exist_ok=True)
        generate_self_signed_cert(cert_path, key_path)
    return cert_path, key_path
