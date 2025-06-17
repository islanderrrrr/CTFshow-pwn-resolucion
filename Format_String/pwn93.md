# 挑战简介
emmm，再来一道基础原理？

# 思路
就是教你每一个格式化字符串的用法示例,一共5个实例

1. func1() - 栈信息泄露攻击
```
int func1()
{
  return printf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s");
}
```
使用了24个连续的%s格式说明符，但没有对应的参数  
printf会从栈上读取参数，将栈上的值当作字符串指针来解引用  
这可能导致：  
- 泄露栈上的内存地址
- 程序崩溃（如果栈上的值不是有效的字符串指针）
- 泄露敏感信息

2. func2() - 内存地址泄露
```
int func2()
{
  return printf("%08x-%07x-%p-%p-%p");
}
```

使用格式说明符但没有提供对应参数  
%08x和%07x：以16进制格式输出栈上的值  
%p：以指针格式输出栈上的值  
攻击者可以获得：  
- 栈上的数据
- 内存布局信息
- 可能的返回地址、函数指针等
3. func3() - 结构化信息泄露
```
int func3()
{
  return printf("AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p");
}
```
以"AAAA"作为标记，后跟12个%p  
攻击者可以：  
- 通过"AAAA"标记找到自己控制的数据在栈上的位置
- 泄露12个栈位置的指针值
- 分析内存布局，为进一步攻击做准备

4. func4() - 任意内存写入攻击
```
unsigned __int64 func4()
{
  char v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("%0134512640d%n\n", 1LL, &v1);
  return __readfsqword(0x28u) ^ v2;
}
```
%0134512640d：输出134,512,640个字符的数字1  
%n：将到目前为止已输出的字符数写入对应的内存地址  
这里会将134,512,640这个值写入v1的地址  
如果攻击者能控制格式字符串，可以：  
- 修改任意内存位置的值
- 覆盖返回地址
- 修改函数指针
5. func5() - 多种长度的内存写入
```
unsigned __int64 func5()
{
  char v1; // [rsp+1h] [rbp-2Fh]
  char v2; // [rsp+2h] [rbp-2Eh]
  char v3; // [rsp+4h] [rbp-2Ch]
  char v4; // [rsp+8h] [rbp-28h]
  char v5; // [rsp+10h] [rbp-20h]
  __int64 v6; // [rsp+1Ah] [rbp-16h]
  int v7; // [rsp+22h] [rbp-Eh]
  __int16 v8; // [rsp+26h] [rbp-Ah]
  unsigned __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v6 = 6071732385558062408LL;  // 字符串数据
  v7 = 1869116230;
  v8 = 119;
  printf("%s %hhn\n", &v6, &v1);   // 写入1字节
  printf("%s %hn\n", &v6, &v2);    // 写入2字节
  printf("%s %n\n", &v6, &v3);     // 写入4字节
  printf("%s %ln\n", &v6, &v4);    // 写入8字节(long)
  printf("%s %lln\n", &v6, &v5);   // 写入8字节(long long)
  return __readfsqword(0x28u) ^ v9;
}
```
演示了不同长度修饰符的%n用法：  
- %hhn：写入1字节（char）
- %hn：写入2字节（short）
- %n：写入4字节（int）
- %ln：写入8字节（long）
- %lln：写入8字节（long long）
每次都会将字符串长度写入对应变量  
攻击者可以精确控制写入的数据长度

至于答案则在输入'7'
```
from pwn import *
from LibcSearcher import *
context(arch = "amd64",os = 'linux',log_level = 'debug')

#context(arch = "i386",os = 'linux',log_level = 'debug')

#io = process("./pwn")

io = remote('pwn.challenge.ctf.show',28234)

elf = ELF('D:\edge 下载\pwn')

#io.sendline('7')
io.interactive()
```
