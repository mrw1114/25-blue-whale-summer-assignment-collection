# 暑期妙木山修炼Week1

## 1.BUUCTF--简单注册器

题目给的是一个apk，说明是安卓逆向

用jadx打开

![image-20260717150015871](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260717150015871.png)

发现了一个有flag名字的文件，打开发现有mainactivity，直接跟进

里面有很显眼的一段与flag有关的逻辑，猜测经过这个逻辑后得到的就是结果

因此直接把这段代码复制运行一下就行了

![image-20260717150332027](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260717150332027.png)

另外，此题实际上只要输入满足上面的四个条件，底下的变换便会进行，并输出固定的flag，因此如果可以动态调试或者直接输入的话，编一个满足四个条件的输入，应该就能显示答案。



## 2.BUUCTF--Younter-Driver

![image-20260721162703420](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260721162703420.png)

打开主函数发现这是一道多线程题

  ::hObject = CreateMutexW(0, 0, 0);   创建互斥锁，使只有一个进程能在运行

 hObject = CreateThread(0, 0, StartAddress, 0, 0, 0);
  Thread = CreateThread(0, 0, sub_41119F, 0, 0, 0);     创建的两个进程

![image-20260721162924059](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260721162924059.png)

![image-20260721162937529](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260721162937529.png)

打开这两个线程可以看到只有一个区别，就是第一个线程多了一个sub41112C函数处理

主函数中dword418008为-1时程序结束，而418008为29，因此要进行三十个线程

Sleep(0x64u) ------让一个线程停止，可以降低cpu占用率

ReleaseMutex(hObject);-------释放互斥锁，让另一个进程运行

补充：一般都是用锁外sleep，即先释放互斥锁，再sleep，这样使得一边在工作的同时另一边休息，使效率翻倍，但是此题不知道为什么用的是锁内sleep，这样非常浪费时间，睡觉的时候另一个线程还在苦苦等待互斥锁释放，不过就结果而言是一样的，都是交替进行。



因此奇数次会受到处理，偶数次保持不变。再来看经过了什么处理。

![image-20260721164742175](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260721164742175.png)

红字是堆栈指针警告，说明参数顺序可能是错误的

下文一直用的a2+a1但是实际上跟a1+a2是一个意思，也就是说看哪个是地址哪个是偏移量就行了，不用严格照这个顺序

a2+a1=a2[a1]或a1[a2]

再来看函数，是一个替换字母表，大写字母换成字母表中的a1[a2]-38位，小写字母换成a1[a2]-96位

![image-20260721165906922](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260721165906922.png)

主函数最终进行比较，要使变换后的等于418004

已知字母表和最终结果，直接写脚本反推

```
des='TOiZiZtOrYaToUwPnToBsOaOapsyS'
table='QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm'
flag=''
for i in range(29) :
    if i%2==0 :
        flag+=des[i]
    else:
        if ord(des[i])<=ord('Z'):
            flag+=chr(table.index(des[i])+96)
        else:
            flag+=chr(table.index(des[i])+38)

print(flag)
```

得到结果ThisisthreadofwindowshahaIsES，由于最终只比较了前29位，因此最后一个不知道，只能爆破尝试

最终结果为ThisisthreadofwindowshahaIsESE



## 3.BUUCTF--findit

题目给了一个apk文件，用jadx打开，定位到mainactivity

![image-20260721194901900](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260721194901900.png)

发现了这题的关键部分，首先对数组x处理，对结果进行比较，通过后再对数组y操作，得到答案

因此这题都不用管x部分，直接复制y部分运行即可，x部分只是验证作用

**public** **class** q {



​	**public** **static** **void** main(String[] args) {

​		**char**[] y = **new** **char**[38];



​		**final** **char**[] a = {'T', 'h', 'i', 's', 'I', 's', 'T', 'h', 'e', 'F', 'l', 'a', 'g', 'H', 'o', 'm', 'e'};

​        **final** **char**[] b = {'p', 'v', 'k', 'q', '{', 'm', '1', '6', '4', '6', '7', '5', '2', '6', '2', '0', '3', '3', 'l', '4', 'm', '4', '9', 'l', 'n', 'p', '7', 'p', '9', 'm', 'n', 'k', '2', '8', 'k', '7', '5', '}'};

​                    **for** (**int** i2 = 0; i2 < 38; i2++) {

​                        **if** ((b[i2] >= 'A' && b[i2] <= 'Z') || (b[i2] >= 'a' && b[i2] <= 'z')) {

​                            y[i2] = (**char**) (b[i2] + 16);

​                            **if** ((y[i2] > 'Z' && y[i2] < 'a') || y[i2] >= 'z') {

​                                y[i2] = (**char**) (y[i2] - 26);

​                            }

​                        } **else** {

​                            y[i2] = b[i2];

​                        }

​                    }

​                    String n = String.*valueOf*(y);

​                   

​                

​         System.**out**.println(n);

​	}



}

得到结果flag{c164675262033b4c49bdf7f9cda28a75}



## 4.BUUCTF--rome

先shift+F12定位到关键部分

![](C:\Users\kanade\Pictures\Screenshots\屏幕截图 2026-07-22 151157.png)

![屏幕截图 2026-07-22 151210](C:\Users\kanade\Pictures\Screenshots\屏幕截图 2026-07-22 151210.png)

这里v12有30个位置，前16个存放字符，后面空余的位置题目使用v12【17】创建了一个4字节指针用来存放数字当索引用，这样不用再创建新变量，节省空间

后面是一个移位处理，大写字母右移了14位，小写字母右移了18位

因此对结果以同样方式分别右移12位，8位即可得到结果

```
s='Qsw3sj_lz4_Ujw@l'
flag=''
for i in range(16):
    if ord(s[i])<91 and ord(s[i])>64:
        flag+=chr((ord(s[i])-53)%26+65)
    elif ord(s[i])>96 and ord(s[i])<123:
        flag+=chr((ord(s[i])-89)%26+97)
    else:
        flag+=s[i]

print(flag)
```

结果flag{Cae3ar_th4_Gre@t}



## 5.BUUCTF--login

打开文件后发现给的竟然是个网页

ctrl+U查看源码

![image-20260722155317858](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260722155317858.png)

可以大致看出是rot13相关

直接rot13解密得到ClientSideLoginsAreEasy@flare-on.com



## 6.BUUCTF--pyre

给了一个pyc文件，用pycdc反编译得到

print 'Welcome to Re World!'
print 'Your input1 is your flag~'
l = len(input1)
for i in range(l):
    num = ((input1[i] + i) % 128 + 128) % 128
    code += num

for i in range(l - 1):
    code[i] = code[i] ^ code[i + 1]

print code
code = [
    '\x1f',
    '\x12',
    '\x1d',
    '(',
    '0',
    '4',
    '\x01',
    '\x06',
    '\x14',
    '4',
    ',',
    '\x1b',
    'U',
    '?',
    'o',
    '6',
    '*',
    ':',
    '\x01',
    'D',
    ';',
    '%',
    '\x13']

直接写脚本反推即可

```
code = [
    '\x1f',
    '\x12',
    '\x1d',
    '(',
    '0',
    '4',
    '\x01',
    '\x06',
    '\x14',
    '4',
    ',',
    '\x1b',
    'U',
    '?',
    'o',
    '6',
    '*',
    ':',
    '\x01',
    'D',
    ';',
    '%',
    '\x13']
flag=''
for i in range (22):
    code[21-i]=chr(ord(code[22-i])^ord(code[21-i]))
for i in range (23):
    flag+=chr((ord(code[i])-i)%128)
print(flag)
```

结果GWHT{Just_Re_1s_Ha66y!}



## 7.BUUCTF--Maze

一道迷宫题，打开发现关键部分反编译不了，因为有花指令，要去花后才能反编译，但是实际上根据字符串中的迷宫内容也能直接偷鸡做，因为这题迷宫没有放在动态下。

## 8.BUUCTF--xxor

打开主函数

![image-20260724004749995](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260724004749995.png)

这题的逻辑是，输入六个数往v6里存，v6是一个64位整型数组，把它转成char指针使其地址一个一个字节移动，每次移动4个字节，也就是说每次都是填一个数据的一半，即32位，这也正好与下文的高低位对应。

中间一段是对输入的数进行处理，先不看，看最后的比较函数

![image-20260724005940870](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260724005940870.png)

根据这个可以得到变换后的输入，就是一个解方程，我找了一个别人写好的z3脚本，注意数都要换成16进制

```
from z3 import *

a0, a1, a2, a3, a4, a5 = Ints('a0 a1 a2 a3 a4 a5')
s = Solver()
s.add(a2 - a3 == 0x84A236FF)
s.add(a3 + a4 == 0xFA6CB703)
s.add(a2 - a4 == 0x42D731A8)
s.add(a0 == 0xDF48EF7E)
s.add(a5 == 0x84F30420)
s.add(a1 == 0x20CAACF4)
if s.check() == sat:
    print(s.model())
```

结果[a4 = 2652626477,
 a0 = 3746099070,
 a5 = 2230518816,
 a2 = 3774025685,
 a1 = 550153460,
 a3 = 1548802262]

有了最终结果再根据中间的变换反推输入

![image-20260724014930080](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260724014930080.png)

很明显是个tea算法，写脚本

#include <stdio.h>
int main()
{
    int a1[6] = { 3746099070,550153460,3774025685,1548802262,2652626477,2230518816 };
    unsigned int a2[4] = { 2,2,3,4 };
    unsigned int v3;
    unsigned int v4;
    int v5;
    for (unsigned int j = 0; j < 5; j += 2)
    {
        v3 = a1[j];
        v4 = a1[j + 1];
        v5 = 1166789954 * 64;
        for (unsigned int i = 0; i < 64; i++)
        {
            v4 -= (v3 + v5 + 20) ^ ((v3 << 6) + a2[2]) ^ ((v3 >> 9) + a2[3]) ^ 0x10;
            v3 -= (v4 + v5 + 11) ^ ((v4 << 6) + *a2) ^ ((v4 >> 9) + a2[1]) ^ 0x20;
            v5 -= 1166789954;
        }
        a1[j] = v3;
        a1[j + 1] = v4;
    }//小端序
    for (unsigned int i = 0; i < 6; i++)
        printf("%c%c%c", *((char*)&a1[i] + 2), *((char*)&a1[i] + 1), *(char*)&a1[i]);
}

这里省事用的别人的，不过我没看懂为什么最后打印只打印三个字节，怎么知道输入有没有填满4字节的，但是这题就用4字节打印应该也没有影响，因为空字符不会显示



## 9.BUUCTF--usualcrypt

![image-20260725134124108](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260725134124108.png)

先看主函数，403CF8很明显是个print函数，然后先对输入进行函数操作，后面都是将结果与一个已知量进行比较，也就是根据结果反推输入的题

![](C:\Users\kanade\Pictures\Screenshots\屏幕截图 2026-07-25 134441.png)

![屏幕截图 2026-07-25 134456](C:\Users\kanade\Pictures\Screenshots\屏幕截图 2026-07-25 134456.png)

打开加密函数，可以看出是一个base64加密（分了三组，三字节转四字节，出现0x3F，61（=）），但是要注意的是开头用了一个sub401000，结尾用了一个sub401030，要看这两个函数又进行了什么操作

第一个是替换了一下加密表

![image-20260725143331929](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260725143331929.png)

脚本

#include <stdio.h>
int main()
{

char b[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char c;
int i=6;
printf("sss\n");
do
{
	c=b[i+10];
	b[i+10]=b[i];
	b[i++]=c;
}
while(i<15);

printf("%s",b);

}

得到码表：ABCDEFQRSTUVWXYPGHIJKLMNOZabcdefghijklmnopqrstuvwxyz0123456789+/

![image-20260725194756789](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260725194756789.png)

最后返回时的函数很明显是一个大小写互换

因此直接把最终结果换大小写，再用新的base表解码即可

flag{bAse64_h2s_a_Surprise}



## 10.BUUCTF--helloworldgo

这题主要是了解一下go语言，go语言写的程序一般比较大，伪代码也特别多和乱，这题查找字符串flag即可



## 11.BUUCTF--igniteme

![image-20260726162034122](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260726162034122.png)

看主函数发现关键在于sub401050这个函数上，只要这个函数对了就成功

![image-20260726162144719](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260726162144719.png)

401020相当于strlen，v4是个值，这题的逻辑就是逆序后一位与现在这位异或，第一位与v4异或，最后比较

因此只要知道v4就能写脚本反推了，v4打开函数后发现是用会被写的移位循环，所以采用动调在这句话后下断点来看v4的值

![](C:\Users\kanade\Pictures\Screenshots\屏幕截图 2026-07-26 161926.png)

得到v4是4后就可以写脚本了

```
a=[0x0D, 0x26, 0x49, 0x45, 0x2A, 0x17, 0x78, 0x44, 0x2B, 0x6C,
  0x5D, 0x5E, 0x45, 0x12, 0x2F, 0x17, 0x2B, 0x44, 0x6F, 0x6E,
  0x56, 0x09, 0x5F, 0x45, 0x47, 0x73, 0x26, 0x0A, 0x0D, 0x13,
  0x17, 0x48, 0x42, 0x01, 0x40, 0x4D, 0x0C, 0x02, 0x69, 0x00]
v=4
flag=''
for i in range(len(a)-1,-1,-1):
    flag+=chr(a[i]^v)
    v=a[i]^v
print(flag[::-1])
```

答案flag{R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com}



## 12.BUUCTF--crackRTF

![image-20260726201943210](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260726201943210.png)

打开后顺着分析，首先必须输入长度必须为6，然后把输入拼接一个字符串，经过sub40100A后比较

看看这个加密函数是什么

![image-20260726202630834](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260726202630834.png)

这里可以看到是跟hash有关的加密，但是我不知道具体是哪种，上网查找后发现0x8004u通常在CryptCreateHash函数中出现且这个标志着sha1，0x8003u是md5

```
from hashlib import *
enc = '6e32d0943418c2c33385bc35a1470250dd8923a9'
flag1 = ''
for i in range(10000,999999):
    if sha1((str(i) + "@DBApp").encode("utf8")).hexdigest() == enc:
        flag1 += str(i) + "@DBApp"
print(flag1)
```

这里也是借鉴的别人写的脚本，以后遇到hash可以照葫芦画瓢

得到123321

第二次几乎跟第一次一样，只是换成了0x8003u，也就是md5

由于第一次是全部已知转成数字了，第二次不知道字符串是什么组成，爆破数字得不到结果，用脚本不现实，但是在线网站是可以直接爆破的

直接输入两次密码就可得到一个rtf文件，里面是flag

但是这题并非是想让我们这样做，底下还有一个函数

![image-20260726213451081](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260726213451081.png)

当然也是啥都看不懂，上网学习了一下别人的wp，才知道这是要用一个叫resourcehacker的软件（查找资源）

![image-20260726214003170](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260726214003170.png)

里面还有一个函数，大致意思就是用资源的前六位和密码前六位异或，得到rtf文件的文件头，于是我们反过来异或就得到第二次的密码了

这题实在是有点......不知道这个查找资源究竟有啥用，还专门要有这个软件，有网的话还是在线爆破吧...



## 13.BUUCTF--rsa

![image-20260727124623759](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260727124623759.png)

题目给了一个flag流量包和公钥文件，首先需要公钥解析，直接用脚本

```
from Crypto.PublicKey import RSA
with open('pub.key','rb') as f:
    key = RSA.import_key(f.read())
    print('n = %d' % key.n)
    print('e = %d' % key.e)
```

得到n和e后可以得到p,q,phi,此题密文是这个流量包，对于这种形式的密文也直接上脚本就行

```
import rsa

e= 65537
n= 86934482296048119190666062003494800588905656017203025617216654058378322103517
p= 285960468890451637935629440372639283459
q= 304008741604601924494328155975272418463
d= 81176168860169991027846870170527607562179635470395365333547868786951080991441

key = rsa.PrivateKey(n,e,d,q,p)         #在pkcs标准中,pkcs#1规定,私钥包含(n,e,d,p,q)

with open(r"D:\re题目\b02a8dfce5ad8cfdfa0a94c826aab55f50162d0b54e541fe2a404934b76ce276\output\flag.enc","rb") as f:  #以二进制读模式，读取密文
    f = f.read()
    print(rsa.decrypt(f,key))           # f:公钥加密结果  key:私钥
```

得到b'flag{decrypt_256}\n'



## 14.BUUCTF--overlong

![image-20260727173839172](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260727173839172.png)

![](C:\Users\kanade\Pictures\Screenshots\屏幕截图 2026-07-27 173849.png)

![屏幕截图 2026-07-27 173858](C:\Users\kanade\Pictures\Screenshots\屏幕截图 2026-07-27 173858.png)

程序的主要逻辑和函数如上，就是对原始数据进行加密然后显示，但是原始数据是很长的，这里只用到了28位，从输出结果可以看到程序应该是没输出完的，因此让它全部用上就行。

第一种方法就是传统的复现流程

char unk_402008[] =
{
  224, 129, 137, 192, 160, 193, 174, 224, 129, 165,
  193, 182, 240, 128, 129, 165, 224, 129, 178, 240,
  128, 128, 160, 224, 129, 162, 114, 111, 193, 171,
  101, 224, 128, 160, 224, 129, 180, 224, 129, 168,
  193, 165,  32, 193, 165, 224, 129, 174,  99, 193,
  175, 224, 129, 164, 240, 128, 129, 169, 110, 193,
  167, 192, 186,  32,  73, 240, 128, 129, 159, 193,
  161, 193, 159, 193, 141, 224, 129, 159, 193, 180,
  240, 128, 129, 159, 240, 128, 129, 168, 193, 159,
  240, 128, 129, 165, 224, 129, 159, 193, 165, 224,
  129, 159, 240, 128, 129, 174, 193, 159, 240, 128,
  129, 131, 193, 159, 224, 129, 175, 224, 129, 159,
  193, 132,  95, 224, 129, 169, 240, 128, 129, 159,
  110, 224, 129, 159, 224, 129, 167, 224, 129, 128,
  240, 128, 129, 166, 240, 128, 129, 172, 224, 129,
  161, 193, 178, 193, 165, 240, 128, 128, 173, 240,
  128, 129, 175, 110, 192, 174, 240, 128, 129, 163,
  111, 240, 128, 129, 173
};
int __cdecl sub_401000(char* a1, char* a2)
{
    int v3; // [esp+0h] [ebp-8h]
    char v4; // [esp+4h] [ebp-4h]

    if ((int)(unsigned __int8)*a2 >> 3 == 30)
    {
        v4 = a2[3] & 0x3F | ((a2[2] & 0x3F) << 6);
        v3 = 4;
    }
    else if ((int)(unsigned __int8)*a2 >> 4 == 14)
    {
        v4 = a2[2] & 0x3F | ((a2[1] & 0x3F) << 6);
        v3 = 3;
    }
    else if ((int)(unsigned __int8)*a2 >> 5 == 6)
    {
        v4 = a2[1] & 0x3F | ((*a2 & 0x1F) << 6);
        v3 = 2;
    }
    else
    {
        v4 = *a2;
        v3 = 1;
    }
    *a1 = v4;
    return v3;
}
unsigned int __cdecl sub_401160(char* a1,char* a2, unsigned int a3)
{
    unsigned int i; // [esp+4h] [ebp-4h]

    for (i = 0; i < a3; ++i)
    {
        a2 += sub_401000(a1, a2);
        if (!*a1++)
            break;
    }
    return i;
}
int main()
{
    char Text[128]; // [esp+0h] [ebp-84h] BYREF
    int v6; // [esp+80h] [ebp-4h]

    v6 = sub_401160(Text, unk_402008, 28);
    Text[v6] = 0;
    int i;
    for (i = 0; i < 28; ++i)
    {
        printf("%c", Text[i]);
    }
    return 0;
}

这里最好就是用c语言，用python转换起来就复杂了，把代码中的28改大就行

但是这题真正要学的不是这个，而是通过动态调试修改程序

![image-20260727175603870](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260727175603870.png)

通过查找找到1C，发现了一个push1C，就是说传入28，把28修改成80，在运行就能得到最终结果

![image-20260727175420099](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260727175420099.png)



## 15.BUUCTF--re

这题考的就是z3约束，正好好好学习一下怎么写

![image-20260727203557119](C:\Users\kanade\AppData\Roaming\Typora\typora-user-images\image-20260727203557119.png)

首先import，然后声明变量的类型及名字，然后创建solver()，约束条件用add，最后必须check(),打印print（ .model())

```
from z3 import *
s=Solver()
a1=[0]*32
for i in range(32):
    a1[i]=Int("a1["+str(i)+"]")
s.add( 1629056 * a1[0] == 166163712 )
s.add( 6771600 * a1[1] == 731332800 )
s.add( 3682944 * a1[2] == 357245568 )
s.add( 10431000 * a1[3] == 1074393000 )
s.add( 3977328 * a1[4] == 489211344 )
s.add( 5138336 * a1[5] == 518971936 )
s.add( 7532250 * a1[7] == 406741500 )
s.add( 5551632 * a1[8] == 294236496 )
s.add( 3409728 * a1[9] == 177305856 )
s.add( 13013670 * a1[10] == 650683500 )
s.add( 6088797 * a1[11] == 298351053 )
s.add( 7884663 * a1[12] == 386348487 )
s.add( 8944053 * a1[13] == 438258597 )
s.add( 5198490 * a1[14] == 249527520 )
s.add( 4544518 * a1[15] == 445362764 )
s.add( 3645600 * a1[17] == 174988800 )
s.add( 10115280 * a1[16] == 981182160 )
s.add( 9667504 * a1[18] == 493042704 )
s.add( 5364450 * a1[19] == 257493600 )
s.add( 13464540 * a1[20] == 767478780 )
s.add( 5488432 * a1[21] == 312840624 )
s.add( 14479500 * a1[22] == 1404511500 )
s.add( 6451830 * a1[23] == 316139670 )
s.add( 6252576 * a1[24] == 619005024 )
s.add( 7763364 * a1[25] == 372641472 )
s.add( 7327320 * a1[26] == 373693320 )
s.add( 8741520 * a1[27] == 498266640 )
s.add( 8871876 * a1[28] == 452465676 )
s.add( 4086720 * a1[29] == 208422720 )
s.add( 9374400 * a1[30] == 515592000 )
s.add(5759124 * a1[31] == 719890500)
s.check()
print(s.model())

a1 = [0]*32
a1[31] = 125
a1[30] = 55
a1[29] = 51
a1[28] = 51
a1[27] = 57
a1[26] = 51
a1[25] = 48
a1[24] = 99
a1[23] = 49
a1[22] = 97
a1[21] = 57
a1[20] = 57
a1[19] = 48
a1[18] = 51
a1[16] = 97
a1[17] = 48
a1[15] = 98
a1[14] = 48
a1[13] = 49
a1[12] = 49
a1[11] = 49
a1[10] = 50
a1[9] = 52
a1[8] = 53
a1[7] = 54
a1[5] = 101
a1[4] = 123
a1[3] = 103
a1[2] = 97
a1[1] = 108
a1[0] = 102
for i in range(32):
    if i == 6:
        continue
    print(chr(a1[i]), end="")
```

要注意的是z3变量不能用于普通的类型的式子中，因此最好全部把结果拿出来后再转换打印

不过这题有点问题，题目没给a1【6】，但是网上有大佬爆破出来是1

flag{e165421110ba03099a1c039337}
