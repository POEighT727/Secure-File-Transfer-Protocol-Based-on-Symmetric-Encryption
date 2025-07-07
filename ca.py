from datetime import datetime, timedelta, timezone
import uuid
import json
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# 证书结构
class SimpleCertificate:
    def __init__(self, serial_number, subject_name, public_key, issuer_name, valid_from, valid_to, signature):
        self.serial_number = serial_number
        self.subject_name = subject_name
        self.public_key = public_key
        self.issuer_name = issuer_name
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.signature = signature

    def serialize(self) -> bytes:
        # 验证签名时的原始数据（不含签名）
        return f"{self.serial_number}|{self.subject_name}|{self.get_public_key_pem()}|{self.issuer_name}|{self.valid_from.isoformat()}|{self.valid_to.isoformat()}".encode()

    def get_public_key_pem(self) -> str:
        # 导出公钥 PEM 格式字符串
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def to_dict(self) -> dict:
        return {
            "serial_number": self.serial_number,
            "subject_name": self.subject_name,
            "public_key_pem": self.get_public_key_pem(),
            "issuer_name": self.issuer_name,
            "valid_from": self.valid_from.isoformat(),
            "valid_to": self.valid_to.isoformat(),
            "signature_hex": self.signature.hex(),
        }

    @staticmethod
    def from_dict(data: dict):
        public_key = serialization.load_pem_public_key(data["public_key_pem"].encode())
        valid_from = datetime.fromisoformat(data["valid_from"])
        valid_to = datetime.fromisoformat(data["valid_to"])
        signature = bytes.fromhex(data["signature_hex"])
        return SimpleCertificate(
            serial_number=data["serial_number"],
            subject_name=data["subject_name"],
            public_key=public_key,
            issuer_name=data["issuer_name"],
            valid_from=valid_from,
            valid_to=valid_to,
            signature=signature
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @staticmethod
    def from_json(json_str: str):
        data = json.loads(json_str)
        return SimpleCertificate.from_dict(data)



# 证书签名请求
class SimpleCSR:
    def __init__(self, subject_name, public_key, signature):
        self.subject_name = subject_name
        self.public_key = public_key
        self.signature = signature  # 申请者私钥签名

    def serialize(self) -> bytes:
        # CSR 签名的内容，不包含 signature 本身
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        return f"{self.subject_name}|{pem}".encode()

def create_csr(subject_name, private_key, public_key) -> SimpleCSR:
    csr = SimpleCSR(subject_name, public_key, None)
    message = csr.serialize()
    signature = private_key.sign(message, hashes.SHA256())
    csr.signature = signature
    return csr

def verify_csr(csr: SimpleCSR) -> bool:
    try:
        csr.public_key.verify(csr.signature, csr.serialize(), hashes.SHA256())
        print("CSR 验证通过，申请者拥有对应私钥")
        return True
    except InvalidSignature:
        print("CSR 验证失败，签名无效")
        return False



# CA 类
class SimpleCA:
    def __init__(self, name="SimpleCA"):
        self.name = name
        self.private_key = dsa.generate_private_key(key_size=2048)
        self.public_key = self.private_key.public_key()
        self.cert_list = []
        self.revoked_serials = set()

    def sign_certificate(self, subject_name, public_key, valid_days=365) -> SimpleCertificate:
        now = datetime.now(timezone.utc)
        valid_to = now + timedelta(days=valid_days)
        serial = uuid.uuid4().hex

        message = f"{serial}|{subject_name}|{public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}|{self.name}|{now.isoformat()}|{valid_to.isoformat()}".encode()
        signature = self.private_key.sign(message, hashes.SHA256())

        cert = SimpleCertificate(serial, subject_name, public_key, self.name, now, valid_to, signature)
        self.cert_list.append(cert)
        print(f"颁发证书，序列号: {serial}")
        return cert

    def sign_csr(self, csr: SimpleCSR, valid_days=365) -> SimpleCertificate | None:
        if not verify_csr(csr):
            print("CSR 验证失败，拒绝签发")
            return None
        return self.sign_certificate(csr.subject_name, csr.public_key, valid_days)

    def revoke_certificate(self, serial_number):
        self.revoked_serials.add(serial_number)
        print(f"已吊销证书，序列号: {serial_number}")

    def restore_certificate(self, serial_number):
        if serial_number in self.revoked_serials:
            self.revoked_serials.remove(serial_number)
            print(f"已恢复吊销证书，序列号: {serial_number}")
        else:
            print(f"未找到吊销记录，序列号: {serial_number}")

    def get_all_certificates(self):
        return self.cert_list

    def export_certificate(self, cert: SimpleCertificate) -> str:
        return cert.to_json()

    def import_certificate(self, cert_str: str) -> SimpleCertificate:
        return SimpleCertificate.from_json(cert_str)


# 验证证书
def verify_certificate(cert: SimpleCertificate, ca_public_key, revoked_serials: set) -> bool:
    try:
        ca_public_key.verify(cert.signature, cert.serialize(), hashes.SHA256())
    except InvalidSignature:
        print("签名无效，证书伪造或被篡改")
        return False

    now = datetime.now(timezone.utc)
    if not (cert.valid_from <= now <= cert.valid_to):
        print("证书已过期或尚未生效")
        return False

    if cert.serial_number in revoked_serials:
        print(f"证书已被吊销，序列号: {cert.serial_number}")
        return False

    print("证书合法")
    return True



# 示例流程
if __name__ == "__main__":
    # 用户生成密钥对
    user_private_key = dsa.generate_private_key(key_size=2048)
    user_public_key = user_private_key.public_key()

    # 用户创建 CSR（此处应在用户端执行）
    csr = create_csr("UserA", user_private_key, user_public_key)

    # 初始化 CA
    ca = SimpleCA()

    # CA 验证 CSR 并签发证书
    cert = ca.sign_csr(csr)

    if cert:
        # 导出证书为 JSON 字符串
        cert_str = ca.export_certificate(cert)
        print("导出的证书 JSON 字符串：\n", cert_str)

        # 导入证书
        imported_cert = ca.import_certificate(cert_str)

        # 验证证书
        verify_certificate(imported_cert, ca.public_key, ca.revoked_serials)

        # 吊销证书
        ca.revoke_certificate(imported_cert.serial_number)

        # 验证（应提示吊销）
        verify_certificate(imported_cert, ca.public_key, ca.revoked_serials)

        # 恢复吊销
        ca.restore_certificate(imported_cert.serial_number)

        # 再次验证（应合法）
        verify_certificate(imported_cert, ca.public_key, ca.revoked_serials)
