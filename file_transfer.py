import os
import base64
from ca import SimpleCA, create_csr, SimpleCertificate, verify_certificate
from kms import generate_aes_key, save_json, load_json, get_user_key, register_user,authorize_user
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# 初始化 CA 和 KMS
ca = SimpleCA()

# 用户注册并生成密钥对
def user_register(username):
    # KMS 注册
    register_user(username)
    # 生成 DSA 密钥对
    from cryptography.hazmat.primitives.asymmetric import dsa
    priv = dsa.generate_private_key(key_size=2048)
    pub = priv.public_key()
    # 生成证书签名请求
    csr = create_csr(username, priv, pub)
    # CA 签发证书
    cert = ca.sign_csr(csr)
    # 保存私钥和证书
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{username}_priv.pem", "wb") as f:
        f.write(priv_pem)
    with open(f"{username}_cert.json", "w", encoding="utf-8") as f:
        f.write(cert.to_json())
    print(f"[+] {username} 注册完成，证书和私钥已保存")
    return priv, pub, cert

# 文件加密传输
def encrypt_and_sign_file(sender, receiver, plaintext_path, ciphertext_path, signature_path):
    # 获取 AES 密钥
    key = get_user_key(receiver,sender)
    if key is None:
        raise Exception("无法获取密钥")
    # 加载明文
    with open(plaintext_path, "rb") as f:
        data = f.read()
    # 加密
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    with open(ciphertext_path, "wb") as f:
        f.write(nonce + ct)
    # 签名
    with open(f"{sender}_priv.pem", "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    signature = priv.sign(nonce + ct, hashes.SHA256())
    with open(signature_path, "wb") as f:
        f.write(signature)
    print(f"[+] 文件加密并签名完成")

def verify_and_decrypt_file(sender, receiver, ciphertext_path, signature_path, output_path):
    # 加载证书
    with open(f"{sender}_cert.json", "r", encoding="utf-8") as f:
        cert = SimpleCertificate.from_json(f.read())
    # 验证证书
    if not verify_certificate(cert, ca.public_key, ca.revoked_serials):
        raise Exception("证书无效")
    # 验证签名
    with open(ciphertext_path, "rb") as f:
        ct = f.read()
    with open(signature_path, "rb") as f:
        signature = f.read()
    try:
        cert.public_key.verify(signature, ct, hashes.SHA256())
        print("[✓] 签名验证通过")
    except InvalidSignature:
        print("[!] 签名验证失败")
        return
    # 解密
    key = get_user_key(receiver)
    if key is None:
        raise Exception("无法获取密钥")
    nonce, real_ct = ct[:12], ct[12:]
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, real_ct, None)
    with open(output_path, "wb") as f:
        f.write(pt)
    print(f"[+] 文件解密完成，输出到 {output_path}")


if __name__ == "__main__":
    # 1. Alice 和 Bob 注册
    user_register("Alice")
    user_register("Bob")
    authorize_user("Alice", "Bob")

    # 2. Bob 发送文件给 Alice
    with open("plain.txt", "wb") as f:
        f.write(b"Hello Alice, this is a secret file from Bob.")
    encrypt_and_sign_file("Bob", "Alice", "plain.txt", "cipher.bin", "cipher.sig")

    # 3. Alice 验证并解密
    verify_and_decrypt_file("Bob", "Alice", "cipher.bin", "cipher.sig", "decrypted.txt")
