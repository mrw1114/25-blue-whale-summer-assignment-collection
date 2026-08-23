# 奇怪的APP

1. 题目来源：moectf2026
2. 题目方向：RE；知识点：安卓逆向、jadx使用、Base编码识别

## 解题思路

题目附件是 apk，拿到 jadx 里查看下：

![jadx查看apk](img/app-jadx.png)

发现源代码里有一串类似 base 的串，解一下看看：

![解码base串](img/app-base.png)

那就继续找剩余的几部分：

![剩余部分2](img/app-part2.png)

![剩余部分3](img/app-part3.png)

![剩余部分4](img/app-part4.png)

一共四部分，组合下就是 flag：

## Flag

`moectf{Apk_REv3rse_1s_fuN_r1ghT?!!!}`
