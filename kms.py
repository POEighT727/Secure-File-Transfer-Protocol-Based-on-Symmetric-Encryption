import os
import json
import base64
import argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 配置路径 
KEY_DB_PATH = "key_store.json"
ACCESS_DB_PATH = "access_control.json"

# 工具函数
def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f)

# 密钥相关操作
def generate_aes_key():
    return AESGCM.generate_key(bit_length=256)

def register_user(username):
    store = load_json(KEY_DB_PATH)
    if username in store:
        print(f"[!] 用户 {username} 已存在")
        return
    key = generate_aes_key()
    store[username] = base64.b64encode(key).decode()
    save_json(KEY_DB_PATH, store)
    print(f"[+] 为用户 {username} 成功生成密钥")

def update_key(username):
    store = load_json(KEY_DB_PATH)
    if username not in store:
        print(f"[!] 用户 {username} 不存在")
        return
    key = generate_aes_key()
    store[username] = base64.b64encode(key).decode()
    save_json(KEY_DB_PATH, store)
    print(f"[+] 用户 {username} 的密钥已更新")

def revoke_user(username):
    store = load_json(KEY_DB_PATH)
    if username in store:
        del store[username]
        save_json(KEY_DB_PATH, store)
        print(f"[-] 已撤销用户 {username} 的密钥")
    else:
        print(f"[!] 用户 {username} 不存在")

def get_user_key(username, requestor=None):
    store = load_json(KEY_DB_PATH)
    access = load_json(ACCESS_DB_PATH)

    if username not in store:
        print(f"[!] 用户 {username} 不存在")
        return None

    if requestor and requestor != username:
        if requestor not in access.get(username, []):
            print(f"[!] 拒绝访问：{requestor} 无权访问 {username} 的密钥")
            return None

    key_b64 = store[username]
    print(f"[✓] {requestor or username} 获取 {username} 密钥成功：{key_b64}")
    return base64.b64decode(key_b64)

# 访问控制
def authorize_user(owner, delegate):
    access = load_json(ACCESS_DB_PATH)
    if owner not in access:
        access[owner] = []
    if delegate not in access[owner]:
        access[owner].append(delegate)
        save_json(ACCESS_DB_PATH, access)
        print(f"[+] 授权成功：{delegate} 可访问 {owner} 的密钥")
    else:
        print(f"[!] {delegate} 已被授权访问 {owner}")

def list_authorized_users(owner):
    access = load_json(ACCESS_DB_PATH)
    if owner in access:
        print(f"[✓] 被授权访问 {owner} 密钥的用户有：{access[owner]}")
    else:
        print(f"[!] {owner} 当前没有授权任何人")

# 备份与恢复
def backup_keys(filepath):
    store = load_json(KEY_DB_PATH)
    save_json(filepath, store)
    print(f"[+] 密钥已备份至 {filepath}")

def restore_keys(filepath):
    data = load_json(filepath)
    save_json(KEY_DB_PATH, data)
    print(f"[+] 密钥已从 {filepath} 恢复")

# 通过命令行接口演示流程
def main():
    parser = argparse.ArgumentParser(description="简易密钥管理系统 KMS")
    sub = parser.add_subparsers(dest="command")

    # 注册用户
    r = sub.add_parser("register")
    r.add_argument("username")

    # 获取密钥
    g = sub.add_parser("get")
    g.add_argument("username")
    g.add_argument("--as", dest="requestor", help="请求者身份")

    # 更新密钥
    u = sub.add_parser("update")
    u.add_argument("username")

    # 撤销密钥
    d = sub.add_parser("revoke")
    d.add_argument("username")

    # 授权用户
    a = sub.add_parser("authorize")
    a.add_argument("owner")
    a.add_argument("delegate")

    # 查看授权
    l = sub.add_parser("list")
    l.add_argument("owner")

    # 备份
    b = sub.add_parser("backup")
    b.add_argument("filepath")

    # 恢复
    rb = sub.add_parser("restore")
    rb.add_argument("filepath")

    args = parser.parse_args()

    if args.command == "register":
        register_user(args.username)
    elif args.command == "get":
        get_user_key(args.username, args.requestor)
    elif args.command == "update":
        update_key(args.username)
    elif args.command == "revoke":
        revoke_user(args.username)
    elif args.command == "authorize":
        authorize_user(args.owner, args.delegate)
    elif args.command == "list":
        list_authorized_users(args.owner)
    elif args.command == "backup":
        backup_keys(args.filepath)
    elif args.command == "restore":
        restore_keys(args.filepath)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
