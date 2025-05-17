# 挑战简介
先了解一下简单的64位shellcode吧

# 思路
64位shellcode，解法同上  

但是来都来了，不如讲一讲32位和64位shellcode处理区别  

**32位系统**  
- 使用32位寄存器：eax, ebx, ecx, edx, esi, edi
- 可用寄存器数量较少
- 参数传递主要通过栈完成

**64位系统**
- 使用64位寄存器：rax, rbx, rcx, rdx, rsi, rdi, r8-r15等
- 额外的8个通用寄存器(r8-r15)
- 参数传递主要通过寄存器完成(前6个参数)，更多参数才使用栈


```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

p = remote("pwn.challenge.ctf.show",28269)
elf = ELF('D:\edge 下载\pwn')
p.interactive()

```
