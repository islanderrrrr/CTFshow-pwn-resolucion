# 挑战简介
先了解一下简单的32位shellcode吧

# 思路
只是认识shellcode，代码什么得都给你写好了，你访问就行了

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

p = remote("pwn.challenge.ctf.show",28283)
elf = ELF('D:\edge 下载\pwn')
p.interactive()

```
