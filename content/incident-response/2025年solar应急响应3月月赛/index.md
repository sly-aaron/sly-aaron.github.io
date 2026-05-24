---
title: "2025年Solar应急响应3月月赛"
date: 2026-05-23
lastmod: "2026-05-23T11:37:51+0800"
---
<!-- generated-by: obsidian_git_blog_pipeline -->

## 【签到】和黑客去Battle把！
```plain
某某文化有限公司被加密啦！老板给了小王5000美元请你帮助小王和黑客谈判争取使用最低的价格买下密钥！
【用户ID为登录青少年CTF平台的手机号】
【本题为模拟请勿当真！禁止攻击平台！】
```

拷打ai

![](assets/1767763584013-ca5f073a-8e92-4de6-8822-c004ab075a17.png)

```plain
flag{H7Q44S85842W6TQZPERS72ED}
```

## 逆向
📊 程序全面分析报告

🔍 基本信息

+ 文件类型: Windows PE可执行文件 (x64)
+ 编译器: MSVC (Microsoft Visual C++)
+ 主要语言: C++ (使用了STL)

🎯 程序功能

这是一个RC4加密程序，用于加密`flag.txt`文件并生成`flag.txt.freefix`。

📋 详细流程

1. 读取输入文件

```plain
// 打开flag.txt

std::ifstream file("flag.txt");

// 读取全部内容到内存
```

2. 生成随机密钥

```plain
GetTickCount();  // 获取系统启动后的毫秒数

srand(TickCount); // 设置随机种子

// 从字符集生成16个随机字符

charset = "qa0wserdf1tg9yuhjio2pklz8xbvcn4mPL7JKOIHUG3YTF6DSREAWQZX5MNCBV"

key = random_select(charset, 16)  // 16字符密钥
```

3. RC4加密

函数 `sub_140001350` 实现了标准的RC4算法：

初始化阶段 (KSA):

+ 创建S-box: S[0] = 0, S[1] = 1, ..., S[255] = 255
+ 使用密钥打乱S-box

密钥流生成 (PRGA):

+ 通过S-box生成伪随机密钥流

加密:

+ `密文 = 明文 XOR 密钥流`

4. 输出结果

将加密后的数据写入 `flag.txt.freefix`

🔑 关键数据

字符集 (地址: `0x140005548`):

```plain
qa0wserdf1tg9yuhjio2pklz8xbvcn4mPL7JKOIHUG3YTF6DSREAWQZX5MNCBV
```

S-box初始化常量:

+ `xmmword_1400056B0`: `00 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00`
+ `xmmword_1400056C0`: `FF 00 00 00 FF 00 00 00 FF 00 00 00 FF 00 00 00`

⚠️ 重要说明

这是一个加密程序，不是解密程序！

程序逻辑：

+ 输入: `flag.txt` (明文)
+ 输出: `flag.txt.freefix` (RC4加密后的密文)

🎯 逆向工程结论

这个程序的作用是：

1. 读取 `flag.txt` 文件
2. 使用随机生成的16字符密钥进行RC4加密
3. 将加密结果写入 `flag.txt.freefix`



```plain
from Crypto.Cipher import ARC4

cipher = open("flag.txt.freefix", "rb").read()

charset = b"qa0wserdf1tg9yuhjio2pklz8xbvcn4mPL7JKOIHUG3YTF6DSREAWQZX5MNCBV"

def ms_rand_gen(seed: int):
    # MSVC rand(): state = state*214013 + 2531011; return (state>>16)&0x7fff
    state = seed & 0xffffffff
    while True:
        state = (state * 214013 + 2531011) & 0xffffffff
        yield (state >> 16) & 0x7fff

def key_from_seed(seed: int) -> bytes:
    g = ms_rand_gen(seed)
    return bytes(charset[next(g) % 62] for _ in range(16))

def find_seed(limit: int):
    for seed in range(limit + 1):
        key = key_from_seed(seed)
        if ARC4.new(key).decrypt(cipher[:4]) == b"flag":
            return seed, key
    return None, None

seed, key = find_seed(2_000_000)
print("seed:", seed)
print("key :", key.decode())

pt = ARC4.new(key).decrypt(cipher)
print("plaintext:", pt.decode())

```

![](assets/1767773383931-fdb0f0cc-3b24-4e6a-9a50-ba5d60aa60c2.png)

```plain
flag{hello_www.sierting.com_fodhaoijsa08324082}
```

## 窃密排查
### 窃密排查1
```plain
发现内部数据被窃取，进行紧急上机。请通过黑客遗留痕迹进行排查：
找到黑客窃密工具的账号
容器账号密码：root:Solar@2025_03!
```

![](assets/1767783159081-8f3182aa-4b75-471a-8e3b-e214d98d0e58.png)

先把ip ping出来，然后根据给出端口ssh

```plain
ssh -p 54774 root@27.221.126.87
```

![](assets/1767783356542-f7f018bd-907a-4a1a-8c8b-835e3faab44e.png)

发现在/root里，能看到很多隐藏文件，ai一下都是啥

![](assets/1767783470504-43c59bd2-1ce3-446c-8ea5-92f2a54e74cc.png)

这个比较可疑，结合题目内部数据被窃取，可能就是和mege云存储服务有关

进入文件夹查看

![](assets/1767783532940-5078d0c6-af90-4873-8e4a-c5bc91e82a64.png)

看看日志，继续分析

![](assets/1767783617515-ce570a06-bf0c-44fc-8362-ba84f8162165.png)

 程序成功登录，使用的账户是 `25solar3abc@habenwir.com`

欸，试出来就是这个

```plain
flag{25solar3abc@habenwir.com}
```

### 窃密排查2
```plain
发现内部数据被窃取，进行紧急上机。请通过黑客遗留痕迹进行排查：
获取黑客账号找到flag
容器账号密码：root:Solar@2025_03!
```

接上题，知道mega是云存储服务后，查看一下mega相关命令

![](assets/1767784486119-70a28b2a-8c8b-4080-8f7e-7d2121731f99.png)

能看到有mega-login，那下一步应该需要我们登录

继续分析上题得到的黑客账户，可以看到形式上像邮箱

查询该邮箱，发现记录在yopmail.com   

![](assets/1767784593869-4fb7b3fb-32e6-4cf2-8040-c003fce4324a.png)

访问该公共邮箱平台[YOPmail : 临时、匿名的免费邮箱地址。](https://yopmail.com/zh/)

![](assets/1767784635804-4233e392-a138-4918-8757-f322a1ac4ced.png)

登录后发现没邮件了，应该是复盘导致的问题

![](assets/1767784701914-a2c5e9ed-e6a9-4d2f-b23c-7ba6994010c0.png)

正常应该能看到有封邮件是recover code恢复密钥

![](assets/1767784753748-61a6e31a-39eb-48f4-9938-278ca5a201a6.png)

```plain
PFpAmEojkQ8mHdICF1dpKQ
```

尝试恢复mega账户[帐户恢复 - MEGA](https://mega.nz/recovery)，会发送重置链接到邮箱

![](assets/1767784995119-27a77f3c-bec2-4fbc-8863-875be3ec5fe2.png)

输入密钥恢复后，重新设置密码

![](assets/1767785022871-0329c6b0-0310-4c0c-9a13-c09981b47f5a.png)

在共享项目中找到flag

```plain
flag{h4S8_h4m1_8Wlq_b3Xz}
```

### 窃密排查3
```plain
发现内部数据被窃取，进行紧急上机。请通过黑客遗留痕迹进行排查：
获取黑客最终转移账号找到flag
容器账号密码：root:Solar@2025_03!
```

继续查看mega账号，右上角微信标识进入聊天，能看到aa发来了session

![](assets/1767785207233-b3b39399-d50a-4973-a789-07d61ef252bc.png)

接下来就是用session登录megacmd

但是环境的mega-cmd不太行，可以在自己的虚拟机上下载mega-cmd然后登录

```plain
#使用 Snap 安装/更新
apt install snapd

systemctl enabel snapd
systemctl start snapd

snapd install mega-cmd 

#进入megacmd
mega-cmd
#登录
login <session>
```

![](assets/1767787003911-beb5a3a0-747d-4716-9378-3b079542cacd.png)

直接卡住了，这感觉是比赛结束后把账户删了

看看别人的wp吧，做不了了

![](assets/1767787153547-d229d290-13b2-4319-860d-98bdb5aed440.png)

```plain
flag{okay_solar_misc_you_win}
```

## 溯源排查
### 溯源排查1
```plain
某企业的阿里云服务器，现已将镜像从阿里云下载下来，该服务器存在奇怪的外连，请排查出外连地址
```

进入镜像后看一下pwd，是/root目录，ls -la查看一下文件

![](assets/1767838755038-eae05c04-2112-4861-babc-f9b8c8c7ba5f.png)

这种给了镜像的还是用火眼分析更权威一点

火眼分析能直接看到删除的文件

![](assets/1767838663889-7d5fddb9-08ba-4c98-9158-07b190329670.png)这些文件的内容完全相同，均为 Systemd 服务配置文件，指向一个可执行程序 `/usr/local/systemd/journaled`

```plain
[Unit]
Description=journaled
ConditionFileIsExecutable=/usr/local/systemd/journaled

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/usr/local/systemd/journaled

Restart=always

RestartSec=120
EnvironmentFile=-/etc/sysconfig/systemd-journaled

[Install]
WantedBy=multi-user.target
```

系统日志服务正确的写法是 `systemd-journald`，这里明显不正常，将 `/usr/local/systemd/journaled` 文件提取出来，用在线沙箱分析

我将放弃微步云沙箱，加入奇安信情报沙箱这个更权威沙箱（）

![](assets/1767835627694-8bdf571e-8b6b-437e-9980-de328fc3c68d.png)

![](assets/1767835530446-f511934e-d7bc-47f9-9b9a-29852fe387c9.png)

```plain
flag{156.238.230.167}
```

### 溯源排查2
```plain
排查外连进程程序的绝对路径
```

见上题

```plain
flag{/usr/local/systemd/journaled}
```

### 溯源排查3
```plain
排查后门，提交其完整名称
```

为了找到后门的启动服务，可以搜索 `journaled`，最终在 `/etc/systemd/system` 找到了完全相同的、名为 `systemd-journaled.service` 的服务文件

![](assets/1767838901031-d869b8c3-dac0-4205-8e18-84a268151c0e.png)

```plain
flag{systemd-journaled.service}
```

### 溯源排查4
```plain
业务系统已被删除，找出可能存在漏洞的应用
```

根据题目中的“业务系统已被删除”，找到根目录下被删除的 `nacos` 目录，以及一个被删除的压缩包 `nacos-server-2.2.2.tar.gz`

![](assets/1767839104547-1cda9795-62bf-4e79-bfa1-ff1b5f9eec7c.png)

```plain
flag{nacos}
```

### 溯源排查5
```plain
请提交漏洞cve编号
```

这题直接网上查洞，结合找到的 `nacos` 压缩包版本为 2.2.2，查找 2.2.2 及以后修复的漏洞

![](assets/1767840205912-b3c99970-d1c9-494e-ae78-bf20c5c3f0f9.png)

```plain
flag{CNVD-2023-45001}
```

### 溯源排查6
```plain
找出黑客利用漏洞使用的工具的地址，该工具为开源工具
```

在 `/tmp` 目录下发现可疑的 `nacos_data_temp` 文件，提取出来进行分析，发现 `nacos_data_temp` 是一个恶意注入的 Java 包

![](assets/1767840361969-e4273e9a-e866-4130-ae53-044c97507c7f.png)

`defineClass` 里是一段 Base64 编码信息，我们解码一下并反编译，得到一个 Webshell 后门

![](assets/1767840364857-ed2292b7-271a-42c5-aa03-799472817a09.png)

审计代码的 `doFilter` 方法，发现：

+ 需要 `Referer` 设置为 `https://www.google.com/` 才能生效
+ `x-client-data` 支持设置为 `cmd/rebeyond/godzilla` 三种，并有不同的适配

结合开源项目搜索，找到了 [ c0olw/NacosRce ](https://github.com/c0olw/NacosRce) 工具与这样的特性吻合

```plain
flag{https://github.com/c0olw/NacosRce}
```

