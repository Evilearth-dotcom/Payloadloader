# Payloadloader
## 免杀加载器

使用python3编写的加密工具

## 安装库
如果您是Linux系统以下命令：
sudo apt-get install python3-tk
如果您是windows系统以下命令：
pip install colorama
pip install pefile

### 
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


usage: Payloadloader.exe [-h] -e EXE -o OUTPUT [-x XOR] [-r]

Payload loader...

options:
  -h, --help            show this help message and exit
  -e EXE, --exe EXE     要注入的exe文件路径
  -o OUTPUT, --output OUTPUT
                        输出exe文件路径
  -x XOR, --xor XOR     XOR加密密钥,默认123
  -r, --show_log        显示执行过程的日志

###



## 以下是使用Payloadloader加密过的效果图 
1.未加密：

![A8594AFE8496D9A814F306FFD5E71DDB](https://github.com/user-attachments/assets/75fe9a7d-c168-4ca5-938f-f460b298c839)

2.已加密：

![d](https://github.com/user-attachments/assets/16421140-f4bf-4e8b-a975-3f7548bf6b24)







思路在于msfvenom将恶意payload注入到合法的文件当中
