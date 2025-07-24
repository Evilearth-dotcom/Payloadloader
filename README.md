# Payloadloader
## 免杀加载器

使用python3编写的加密工具,思路诞生于
msfvenom将恶意payload注入到合法的文件当中

<img width="1271" height="500" alt="ED615AC474C87AF6B28B9F783CB7E7C4" src="https://github.com/user-attachments/assets/2d708e33-9ffa-4977-9933-abc4d0c93d72" />


# [+] Payloadloader v2.0
# [+] Author: Anonfsocialize
# [+] Telegram: (https://t.me/Anonfsocialize)
# [+] Github: https://github.com/TR1123

## usage: Payloadloader.exe [-h] -e EXE -o OUTPUT [-x XOR] [-r]

## Payload loader...

## options:
  -h, --help            show this help message and exit
  -e EXE, --exe EXE     要注入的exe文件路径
  -o OUTPUT, --output OUTPUT
                        输出exe文件路径
  -x XOR, --xor XOR     XOR加密密钥,默认123
  -r, --show_log        显示执行过程的日志



## 安装库
如果您是Linux系统以下命令：
sudo apt-get install python3-tk
如果您是windows系统以下命令：
pip install colorama
pip install pefile




## 前提 
1.你需要一个合法的PE文件，其中含有数字签名，没有也可以，使用工具 Payloadloader.py -e 病毒或木马 -o 合法的PE文件 -x 123 -r  

2.加密过程中切勿退出，关闭程序否则会加密失败同时可能会导致合法文件失效

## 其它语言的PE文件是否有效？

1.经过测试我分别使用了易语言PE文件和GoPE文件经过Payloadloader.py程序加密处理可以达到混淆效果

2.但是有一些加密后的PE文件可以绕过主流查毒软件 



## 以下是使用Payloadloader加密过的效果图 
1.未加密：

![A8594AFE8496D9A814F306FFD5E71DDB](https://github.com/user-attachments/assets/75fe9a7d-c168-4ca5-938f-f460b298c839)

2.已加密：

![d](https://github.com/user-attachments/assets/16421140-f4bf-4e8b-a975-3f7548bf6b24)


# 如有合作开发免杀工具，请向我联系
# 我所在的社交平台：
Telegram: (https://t.me/Anonfsocialize)
QQ：663680370





