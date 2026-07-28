# 基础题目练习

CTFshow-web入门

# 信息收集：

## web3：

拦截打开，在HTTP历史记录里面能找到抓到的包，右键发送到重放器，发送过去，能看到回显有flag信息

![image](assets/image-20260122141647-mkp8yg3.png)

![image](assets/image-20260122141751-36cb1ta.png)

## web4-robots

robots.txt是网站管理者写的，为访问网站的搜索引擎爬虫提供抓取指令，这些爬虫会自愿遵循这些指令。

```c
# Robots.txt file from http://www.seovip.cn
# All robots will spider the domain

User-agent: *//指定哪些搜索引擎爬虫应遵守随后的规则（例如：*（通配符，表示所有搜索爬虫）、Googlebot、Bingbot等）
Disallow://指示应禁止爬取的URL
Allow://允许爬的网站
```

题目提示后台地址写入robots,在url后面加上\robots.txt ，访问到如下信息，接着访问flagishere.txt能得到flag

![image](assets/image-20260122142551-8pn4eih.png)

![image](assets/image-20260122142713-pckr4ea.png)

## web5

提示：`phps源码泄露有时候能帮上忙`

![image](assets/image-20260122144553-1r814yl.png)

[web备份文件_文件泄露 - Sdegree - 博客园](https://www.cnblogs.com/sdegree/articles/17638970.html)

[web信息泄露 - Overlord Blog](https://blog.overlordzj.cn/2024/09/26/ctf/data/web/%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2/)

[Fuzzing-Dicts/常见网站备份文件字典（2954）.txt at master · 3had0w/Fuzzing-Dicts · GitHub](https://github.com/3had0w/Fuzzing-Dicts/blob/master/%E5%B8%B8%E8%A7%81%E7%BD%91%E7%AB%99%E5%A4%87%E4%BB%BD%E6%96%87%E4%BB%B6%E5%AD%97%E5%85%B8%EF%BC%882954%EF%BC%89.txt)

## web6

提示：`解压源码到当前目录，测试正常，收工`

和上次思路差不多，这题没有提示什么泄露，需要自己用工具扫描。使用的工具是dirsearch，使用指令`dirsearch -u url`

dirsearch主要功能：

1. **目录和文件枚举（啥意思。网站为什么会有隐藏目录，文件，后台，配置文件，备份文件啥的）**

- 扫描网站或 Web 应用的隐藏目录和文件
- 发现管理员后台、配置文件、备份文件等
- 寻找潜在的敏感信息泄露

2. **渗透测试用途**

- ​**信息收集阶段**：发现网站结构和潜在入口点
- ​**漏洞发现**：寻找未授权访问、备份文件泄露等
- **内容发现**：识别隐藏的管理界面、API端点等

使用上面的指令就是找出网站的备份文件www.zip文件，flag就在压缩包中

![image](assets/image-20260122160702-vnmw114.png)

![image](assets/image-20260122160550-xkhl2xn.png)

## web7

提示：`版本控制很重要，但不要部署到生产环境更重要。`

这个题目同样和上题类似，web5是php源码泄露，web6是备份文件泄露，这题是版本控制泄露。常见的版本控制泄露包括`.git`​和`.svn`

还是用`dirsaerch -u url` 扫出来有哪些版本泄露

![image](assets/image-20260122161815-1q63bwm.png)

![image](assets/image-20260122161546-mj9bsmr.png)

## web8

和web7一样的过程，web7是git版本泄露，这题是svn版本泄露

![image](assets/image-20260122162047-d8x644x.png)

## web9

vim缓存泄露，尝试访问/index.php.swp ，文件下载成功

vim的备份文件后缀位.swp，并且需要用`vim 文件名（无.swp）`来重新访问，windows直接打开是16进制的，更换编码格式为UTF-8，或者用linux系统打开

![image](assets/image-20260122162550-2tvr4mn.png)

## web10

提示：`cookie 只是一块饼干，不能存放任何隐私数据`

提示隐私数据存放在cookie中，f12打开查看cookie

![image](assets/image-20260122163644-8ovwb7k.png)

## web12

提示：`有时候网站上的公开信息，就是管理员常用密码`

完全没头绪，提示管理员常用密码，但是没看到哪里需要输入的，有个邮件提交也提交不了

需要用dirsearch扫一下，发现有/admin的目录，访问需要密码，然后就想到提示网站上公开信息，翻翻网站能看到

![image](assets/image-20260122171059-ywudsun.png)

![image](assets/image-20260122170945-10rk4a9.png)

![image](assets/image-20260122170957-mtnudy4.png)

## web13

提示：`技术文档里面不要出现敏感信息，部署到生产环境后及时修改默认密码`

感觉是提示技术文档里面有默认密码，先来扫一下看看，没扫出来啥，感觉找不到技术文档呢，找半天原来是在网站最下面的document,真是考眼力和细心程度了

![image](assets/image-20260122172643-x6gzrrq.png)

打开这个文档就能看到url和默认用户名以及默认密码，需要注意的是your-domain是指网站的根域名，在此题中就是靶机的url地址

![image](assets/image-20260122173139-i7gn659.png)

![image](assets/image-20260122173101-o02rq6r.png)

## web14（editor目录）

提示：`有时候源码里面就能不经意间泄露重要(editor)的信息,默认配置害死人`

提示了editor，用dirsearch扫一下，访问http://d464333d-7f6b-46da-9106-4099bc63cd25.challenge.ctf.show/editor/

![image](assets/image-20260123155126-ndlb9g5.png)

是一个提交编辑文件的地方，一开始很懵，点了提交文件能看到有文件空间，挨个点一下找到文件fl000g.txt，应该就是这个，但是访问不来了，提交了文件也没啥用，看了wp才知道要访问url+flag文件的地址，而且根据访问url/editor成功，并且editoe和fl000g.txt的上级目录nothinghere是在同一级目录下，所以需要访问的是url/notinghere/fl000g.txt 才能得到flag

![image](assets/image-20260123155400-61y3ml9.png)

![image](assets/image-20260123155252-kv07mug.png)

![image](assets/image-20260123155058-vsllvq2.png)

## web15

提示：`公开的信息比如邮箱，可能造成信息泄露，产生严重后果`

拉到底部能看到邮箱是qq邮箱，能拿到qq号，去搜一下只有现居陕西西安，用dirsearch扫一下有/admin可以登录，猜到用户名是admin，但是密码不知道，还想一直试，其实需要用忘记密码去试，（还是都要点，看一下，感觉不是很细心）密保问题就是先居城市，之前的qq号就有用了，拿到密码登录就能看到flag

![image](assets/image-20260123162002-yrr887a.png)

![image](assets/image-20260123161935-fx1rb1d.png)

![image](assets/image-20260123161952-mn3aeyx.png)

## web16

提示：`对于测试用的探针，使用完毕后要及时删除，可能会造成信息泄露`

看提示应该是探针泄露

**PHP探针**实际上是一种Web脚本程序，主要是用来探测虚拟空间、服务器的运行状况，而本质上是通过[PHP语言](https://so.csdn.net/so/search?q=PHP%E8%AF%AD%E8%A8%80&spm=1001.2101.3001.7020)实现探测PHP服务器敏感信息的脚本文件，通常用于探测网站目录、服务器操作系统、PHP版本、数据库版本、CPU、内存、组件支持等，基本能够很全面的了解服务器的各项信息。

常用的探针名字一般为tz.php

![image](assets/image-20260123165446-j46ez67.png)

![image](assets/image-20260123165332-gm5mvta.png)

## web17

提示：`备份的sql文件会泄露敏感信息`

猜测是xx.sql，试着拿dirsearch扫一下，扫出来/backup.sql 应该没错了，访问后下载了一个文件，打开sql文件，拿到flag

![image](assets/image-20260123170009-9wkhbla.png)

![image](assets/image-20260123170138-0rtli9w.png)

## web18

提示：`不要着急，休息，休息一会儿，玩101分给你flag`

f12修改js中的游戏参数数值，有两处判断b.y和score，第一个需要b.y大于100，第二处需要score>100在这两个地方下断点，分别修改b.y和score的值满足要求即可通关，通关之后提示访问110.php访问后拿到flag

![image](assets/image-20260123171620-f3u81c7.png)

![image](assets/image-20260123171443-akda5j6.png)

![image](assets/image-20260123171737-4s1u2v8.png)

## web19

提示：**密钥什么的，就不要放在前端了**

说明前端有密钥，ctrl+u看到源码有一段注释，输入正确的用户名和密码就能拿到flag，isset函数作用是检验变量是否存在

![image](assets/image-20260123172454-cvavikg.png)

能看出来给出的p是密码加密后的数据，加密方式也能找到，是cbc模式的aes加密，key,iv,都给出，解密得到密码，输入用户名和密码即可得到flag。

![image](assets/image-20260123173044-n4jjog7.png)

![image](assets/image-20260123172927-8z2ri97.png)

![image](assets/image-20260123172948-h417a2q.png)

## web20

dirsearch扫出来/db 但是是403，有点搞不明白，看wp说用dirsearch再扫url/adb ,扫出来了/adb/mdb ，访问回下载一个文件，flag出来了

![image](assets/image-20260126171824-i3vf65l.png)

![image](assets/image-20260126172105-f3332sm.png)

## [SWPUCTF 2021 新生赛]jicao

![image](assets/image-20260604182356-ctvx46o.png)

大概了解代码后是需要满足用post请求id-w11mNB同时json中x=w11m

用post请求id值的几种方法

1.命令行工具curl

![image](assets/image-20260611180232-5xsxshj.png)

![image](assets/image-20260611181925-hatewc8.png)

### curl请求方法

1.GET请求（默认）

​`curl https://api.example.com/users`

2.POST请求

-X 或者 -request 指定请求方法（POST，PUT，DELETE）

-d 或者 -data ：发送数据

比如

​`curl -X POST -d "username=johndoe&password=123456" https://api.example.com/login`

```python
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"name": "John", "age": 30}' \
  https://api.example.com/users
```

BP请求POST和GET方法

## [SWPUCTF 2021 新生赛]easy\_md5（PHP弱类型比较+MD5绕过）

![image](assets/image-20260623223828-aatmnxz.png)

初次理解是get传递的name参数和post传递的possword参数需要满足不相等但是md5相等？考察的是md5绕过和php弱类型比较

### MD5绕过的两种方法

1.PHP在进行“\=\=”（弱类型比较）时，会先转换字符串类型，再进行字符串比较，而进行md5后以0e开头的都会被PHP识别为科学计数法，即0e\*被视作0的\*次方，结果都为0，故我们只需找到md5后为0e\*的字符串，常用md5后为0e\*的有

```python
    QNKCDZO    
    240610708 
    byGcY   
    sonZ7y  
    aabg7XSs   
    aabC9RqS   
    s878926199a   
    s155964671a   
    s214587387a   
    s1091221200a
```

![image](assets/image-20260701153200-fffaygt.png)

2.PHP md5函数接收的参数为string（字符串型），如果传入arry（数组型）就无法计算其md5值，但不会报错，导致数组md5值都相等.

![image](assets/image-20260701144925-xcn0yia.png)

## web21

tip:爆破什么的都是基操

题目提示爆破，并且给了一个密码本

![image](assets/image-20260716171527-ibfjzpj.png)

应该是爆破用户名和密码

### 如何使用BP爆破密码：

打开内置浏览器，分别把输入用户名和密码前后抓包，能看到请求多了一个Authorization,以及一个加密的base64密文，把密文拿去解密能看到是我们输入的用户名和密码

![image](assets/image-20260717175229-79801i0.png)

![image](assets/image-20260717175703-nxyn71o.png)

所以需要爆破的地方就是这里

具体爆破操作：  
将抓到的包发给Intruder,接着选择攻击类型，位置，payload设置等等

#### 1.选择攻击类型

![image](assets/image-20260705155827-l8gnnja.png)

**攻击类型**：攻击类型有几种狙击手，撞击物，交叉，集束炸弹（什么是字典：相当于你准备的值列表，里面放着想要爆破的内容，比如用户名不变，密码改变，上传了一个密码.txt数据集，就是一组字典；用户名密码都变，需要两组数据集用户名和密码，这就是多个字典）

**单一字典（狙击手/ 撞击物）**

狙击手：适用于标记多个位置，但是每次请求只替换其中一个位置，其他位置保持不变，，比如用户名固定，密码遍历；或者密码固定，用户名遍历

撞击物：适用于标记多个位置，但是所以位置都是替换成同一个payload,用户名和密码都填一样的值

**有多个字典（交叉/ 集束炸弹）**

交叉：每组字典一一对应，比如用户名列表[A,B,C],密码列表[1,2,3]，那么测试的请求就是Aq1,B2,C3

集束炸弹：所有字典笛卡尔积全排列组合，比如用户名是[A,B,C]，密码是[1,2,3]，那么测试的请求就是A1，A2，A3，B1，B2...

#### 2.添加payload位置

![image](assets/image-20260717194459-6famdav.png)

#### 3.设置payload和payload处理

**payload集数量**：不同的攻击类型payload集数量也不一样，狙击手固定1个，撞击物固定1个，交叉payload集等于标记的位置数，集束炸弹的payload集等于标记的位置数。

**payload类型**:

简单列表：手动输入或者粘贴一些值

指定文件：读取电脑上的txt字典文件

自定义迭代器：把多个词笛卡尔积组合在一起生成组合，比如admin001,admin002等

这题因为加密的部分是用户名和密码组合，所以使用自定义迭代器

![image](assets/image-20260705155936-1klei0l.png)

接着设置payload,根据组合应该是 admin:password 这样的组合

![image](assets/image-20260717200642-xh7ok56.png)![image](assets/image-20260717200656-xtesxbl.png)![image](assets/image-20260717200734-6gy9cv2.png)

**payload处理**

对payload进行加密或者其他处理，这是是base64加密

![image](assets/image-20260717200920-dfx05y7.png)

开始攻击，找到了一个状态码200的，解码拿到用户名和密码，接着输入正确的用户名密码就可以啦

![image](assets/image-20260717202203-6be9zov.png)

![image](assets/image-20260717202252-pgafs24.png)

​`ctfshow{c0853c77-297e-431e-a59a-a50006ff0efd}`

## web22

子域名爆破，题目提示是`域名也可以爆破的，试试爆破这个ctf.show的子域名`

因为更新了之后域名失效了，所以直接看wp

[子域名爆破の几种方式 - Bssn520 - 博客园](https://www.cnblogs.com/Bssn007/p/16817428.html)

## web23

提示是：`还爆破？这么多代码，告辞！`

```python
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-03 11:43:51
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-03 11:56:11
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/
error_reporting(0);

include('flag.php');
if(isset($_GET['token'])){#获取get传入的token值
    $token = md5($_GET['token']);#md5加密
    if(substr($token, 1,1)===substr($token, 14,1) && substr($token, 14,1) ===substr($token, 17,1)){#要求md5值的索引1，14，17的值要相等，substr函数是从字符串
#中取子串
        if((intval(substr($token, 1,1))+intval(substr($token, 14,1))+substr($token, 17,1))/substr($token, 1,1)===intval(substr($token, 31,1))){
            echo $flag;#1，14+17位置的值/1要求等于31的
        }
    }
}else{
    highlight_file(__FILE__);

}
?>
```

代码审计相关的爆破，

```python
import hashlib
for i in range(0,1000):
    token=str(i)
    md5_hash=hashlib.md5(token.encode('utf-8')).hexdigest()
    if (md5_hash[1]==md5_hash[14]==md5_hash[17]) and md5_hash[1].isdigit() == True and md5_hash[1]!='0' and md5_hash[31].isdigit() == True and md5_hash[31]!='0':
        if (int(md5_hash[1])+int(md5_hash[14])+int(md5_hash[17]))/int(md5_hash[1])==int(md5_hash[31]):
            print(md5_hash)
            print(token)
##
##f85454e8279be180185cac7d243c5eb3
#422
```

![image](assets/image-20260717223947-02r2jbn.png)

## web24

要求输入的r和mt_srand(xx)随机数相等，直接测试一下出来的随机数是多少，然后以get方式传入参数

![image](assets/image-20260717225031-g99tx1w.png)

![image](assets/image-20260717225011-e1rxgos.png)

![image](assets/image-20260717225001-4slgfm0.png)

#
