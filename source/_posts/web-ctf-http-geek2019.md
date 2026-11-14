---
title: "[极客大挑战 2019] Http：Referer、User-Agent、X-Forwarded-For，以及被反向代理吞掉的那一步"
date: 2026-11-14 11:00:00
updated: 2026-11-14 11:00:00
categories:
  - CTF
  - Web
  - HTTP 基础
tags:
  - HTTP
  - Referer
  - User-Agent
  - X-Forwarded-For
  - 反向代理
  - Burp Suite
  - 极客大挑战
description: 从 F12 里的隐藏链接开始，依次伪造 Referer、User-Agent、X-Forwarded-For。网上大多数 writeup 到 XFF 就结束了，但在 CTF2 的 openresty 网关后面这一步会失败：反代把 XFF 重写成了真实客户端 IP。改用 tcp-ctf2 直连、把 Burp 端口改成 9999 并勾上 HTTPS，就能绕过网关拿到 flag。顺便讲清楚请求头的信任边界和反代改写的原理。
difficulty: 入门
topic: HTTP 基础
series: HTTP 基础
series_order: 1
permalink: 2026/11/14/web-ctf-http-geek2019/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（适合刚接触 Burp Repeater 和请求头伪造的同学）
- **考点**：隐藏链接、`Referer` 伪造、`User-Agent` 伪造、`X-Forwarded-For` 伪造、反向代理对请求头的改写
- **工具**：浏览器 F12、Burp Suite（Repeater）、`curl`
- **三道门**：来源站点 `Referer` → 指定浏览器 `User-Agent: Syclover` → 本地访问 `X-Forwarded-For: 127.0.0.1`
- **真正的坑**：走 `http-ctf2` 网关时，openresty 会把 `X-Forwarded-For` 改写成真实客户端 IP，伪造无效
- **解法**：换成 `tcp-ctf2` 直连，端口改成 `9999`，Burp 勾上 HTTPS，再重复同样的请求头
- **flag**：`CTF2{c56bfec1-c066-4ca7-bc25-120666c2d5ac}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：HTTP 请求/响应的基本结构、会用浏览器 F12、知道 Burp 怎么抓包和重放
- **工具**：浏览器、Burp Suite。没有 Burp 也能做，文末有 `curl` 版本
- **环境**：文中的靶场地址是当时的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- 本文所有操作仅用于**授权靶场和教学**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`F12 找隐藏链接` → `访问 Secret.php` → `伪造 Referer` → `伪造 User-Agent` → `伪造 X-Forwarded-For` → `发现被反代改写` → `换 tcp 直连` → `Burp 改端口 + HTTPS` → `重放请求` → `拿 flag`
{% endnote %}

## 题目入口：F12 里的 Secret.php

打开靶场，页面看起来只是一个普通的安全小组介绍页。直接看源码，或者按 `F12` 打开开发者工具，能在一段 `<section>` 里找到这个：

![F12 里的隐藏链接](image.png)

*图 1：`<a>` 标签的 `href` 指向 `Secret.php`，但被 `onclick="return false"` 和样式藏了起来*

关键代码是：

```html
<a style="border:none;cursor:default;" onclick="return false" href="Secret.php">氛围</a>
```

这里有两个“隐藏”手段：

| 手段 | 作用 |
| --- | --- |
| `onclick="return false;"` | 点击时不跳转，看起来像普通文字 |
| `border:none; cursor:default;` | 去掉下划线和手型光标，视觉上不像链接 |

但 `href` 是骗不了人的。浏览器地址栏直接访问 `Secret.php`：

![访问 Secret.php](image-1.png)

*图 2：页面提示 `It doesn't come from 'https://Sycsecret.buuoj.cn'`*

翻译过来就是：**这个请求不是从 `https://Sycsecret.buuoj.cn` 来的。**

这句话已经把手要伸向哪个请求头说得很清楚了——`Referer`。

{% note info %}
**F12 能看到，说明“隐藏”只是前端障眼法。** HTML、CSS、JavaScript 都在客户端，任何“看不见的链接”都可以在源码、Elements 面板或者网络请求里找回来。CTF 里遇到“页面上什么都没有”的题，第一步永远是看源码和请求，而不是盯着页面发呆。
{% endnote %}

## 第一道门：Referer

`Referer` 是浏览器自动带上的请求头，用来告诉服务器“我是从哪个页面点过来的”。

比如你在 `https://a.com/page` 里点了一个指向 `https://b.com/secret` 的链接，浏览器发往 `b.com` 的请求大概长这样：

```http
GET /secret HTTP/1.1
Host: b.com
Referer: https://a.com/page
```

服务端在 PHP 里通过 `$_SERVER['HTTP_REFERER']` 读取它。题目要求来源是 `https://Sycsecret.buuoj.cn`，那就在 Burp Repeater 里手动加上：

```http
Referer: https://Sycsecret.buuoj.cn
```

![加上 Referer](image-3.png)

*图 3：请求头里补上 `Referer`，页面回显变成 `Please use "Syclover" browser`*

第一道门开了，但门后面还有一道。

{% note warning %}
**Referer 完全可以伪造。** 它只是客户端自愿带上的一个字符串，浏览器地址栏直接输入、从书签打开、HTTPS 跳 HTTP 等场景甚至根本不会带。服务端如果拿它做权限判断，等于把门禁卡交给访客自己填写。
{% endnote %}

## 第二道门：User-Agent

`User-Agent` 用来标识客户端类型和版本。正常浏览器会发一长串：

```http
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...
```

题目回显 `Please use "Syclover" browser`，意思是要一个叫 `Syclover` 的浏览器。这个浏览器当然不存在，直接把 UA 改成：

```http
User-Agent: Syclover
```

![改 User-Agent](image-4.png)

*图 4：`User-Agent: Syclover`，页面又变成 `No!!! you can only read this locally!!!`*

服务端大概率是 `strpos($_SERVER['HTTP_USER_AGENT'], 'Syclover')` 之类的判断。**它只检查字符串里有没有 `Syclover`，不会真的去识别浏览器。** 所以写 `Syclover` 可以，写 `Mozilla/5.0 Syclover` 也可以。

第二道门也开了，剩下最后一句：`you can only read this locally`。

## 第三道门：X-Forwarded-For

“只能本地访问”通常有两种实现：

| 实现方式 | 读取的变量 | 能不能伪造 |
| --- | --- | --- |
| 看 TCP 连接的对端地址 | `$_SERVER['REMOTE_ADDR']` | 不能直接伪造 |
| 看代理转发头 | `$_SERVER['HTTP_X_FORWARDED_FOR']` | 可以伪造 |

`X-Forwarded-For`（简称 XFF）是代理服务器常用的头，格式是：

```http
X-Forwarded-For: 客户端IP, 代理1IP, 代理2IP
```

按最直觉的做法，加上：

```http
X-Forwarded-For: 127.0.0.1
```

![加了 XFF 却没过](image-5.png)

*图 5：XFF 已经写上 `127.0.0.1`，页面却仍然是 `No!!! you can only read this locally!!!`*

到这一步，网上大多数 writeup 就结束了。**但如果你是在 CTF2 的 `http-ctf2` 环境里做，这里会卡住。** 这不是 payload 写错了，而是请求在网络链路上被改过了。

## 诡异的地方：反向代理把 XFF 改掉了

先把链路画出来。直接访问题目容器时是这样的：

```text
浏览器  ──请求──>  题目容器（PHP）
                    ↑
              XFF 原样送达
```

而通过 `http-ctf2` 网关时，中间多了一层 openresty：

```text
浏览器  ──请求──>  openresty 网关  ──请求──>  题目容器（PHP）
                    ↑
              这里会重写 XFF
```

openresty / Nginx 作为反向代理时，通常会有类似这样的配置：

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

`$proxy_add_x_forwarded_for` 的语义是“**在客户端已有的 XFF 后面追加真实 IP**”。也就是说，你发：

```http
X-Forwarded-For: 127.0.0.1
```

到容器时可能变成：

```http
X-Forwarded-For: 127.0.0.1, 你的真实公网IP
```

如果后端取的是**最后一个**地址，看到的就是你的真实 IP，伪造自然失败。

有些网关更直接，用 `$remote_addr` 整个覆盖：

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
```

这种情况下，不管你在请求里写什么，容器收到的都只有真实 IP。

{% note warning %}
**同一份 payload，换个网络位置结果就不同。** 网上 writeup 用的是旧 BUUCTF 的 `nodeX:端口` 直连，请求直接打到题目容器；CTF2 的 `http-ctf2` 走的是统一网关，网关出于“记录真实来源”的目的改写了 XFF。**不是题变了，是中间多了一个会改包的代理。**
{% endnote %}

### 为什么代理要改 XFF

从平台的角度看，这是“正确”的行为：

- 统一入口、统一证书、统一限流；
- 日志里记录真实客户端 IP，而不是攻击者随手写的值；
- 防止后端把伪造的 XFF 当成可信来源。

问题在于，**这道题恰好需要伪造 XFF**。安全设计和题目考点在这里撞车了。

### 这也解释了为什么只加 XFF 不够

| 请求头 | 网关是否改写 | 结果 |
| --- | --- | --- |
| `Referer` | 一般不改 | 伪造有效 |
| `User-Agent` | 一般不改 | 伪造有效 |
| `X-Forwarded-For` | 可能追加或覆盖 | 伪造可能失效 |
| `X-Real-IP` | 可能覆盖 | 同上 |

所以前两道门能过，第三道门过不去。**要绕过的不是题目的过滤，而是网关的改写。**

## 找到直连入口：http-ctf2 → tcp-ctf2

CTF2 其实提供了直连方式。它不在页面上放按钮，但地址是存在的：

| 入口 | 地址格式 | 端口 | 说明 |
| --- | --- | --- | --- |
| 网关 | `xxx.http-ctf2.dasctf.com` | `80` | 经过 openresty 反向代理 |
| 直连 | `xxx.tcp-ctf2.dasctf.com` | `9999` | 直接映射到题目容器，TLS 封装 |

也就是说，把主机名里的 `http` 换成 `tcp`，端口换成 `9999`：

```text
原地址：https://e7c236f6624602a29f3c0f5a.http-ctf2.dasctf.com/Secret.php
新地址：https://e7c236f6624602a29f3c0f5a.tcp-ctf2.dasctf.com:9999/Secret.php
```

![改成 tcp 地址](image-6.png)

*图 6：在地址里加上 `tcp`，端口改成 `9999`*

浏览器历史里能更直观地看到两个地址的差别：

![两个地址对比](image-7.png)

*图 7：`http-ctf2` 和 `tcp-ctf2` 是同一道题的两个入口*

`tcp-ctf2` 这一层没有 HTTP 反向代理，请求会直接进入容器，`X-Forwarded-For` 不再被改写。**这就是绕过“反代改包”的关键。**

{% note info %}
**为什么直连还是 `https`？** 因为平台的 TCP 入口在外面套了一层 TLS，`9999` 端口上说的不是明文 HTTP。用浏览器访问要写 `https://`，用 Burp 要勾 `Use HTTPS`，用 pwntools 要写 `remote(..., ssl=True, sni=HOST)`。这一点在 Pwn 题的远程连接里也一样。
{% endnote %}

## 在 Burp 里改端口

直连地址拿到后，Burp 里不能只改 URL 那一行，**目标端口也要改**。这是最容易漏的一步。

在 Repeater 顶部点目标地址旁边的小铅笔（或 `Configure target details`）：

![配置 Burp 目标](image-8.png)

*图 8：Host 是 `*.tcp-ctf2.dasctf.com`，Port 改成 `9999`，勾上 `Use HTTPS`*

三个地方都要对：

| 配置项 | 值 |
| --- | --- |
| Host | `xxx.tcp-ctf2.dasctf.com` |
| Port | `9999` |
| Use HTTPS | ✅ 勾上 |

如果 Burp 提示证书错误，接受临时证书即可；如果 TLS 握手失败，可以试试勾上 `Override SNI`，把 SNI 也写成这个主机名。

然后重复前面的步骤，把三个请求头都带上：

```http
GET /Secret.php HTTP/2
Host: e7c236f6624602a29f3c0f5a.tcp-ctf2.dasctf.com
Referer: https://Sycsecret.buuoj.cn
User-Agent: Syclover
X-Forwarded-For: 127.0.0.1
```

这次 `X-Forwarded-For` 不会被网关改写，容器看到的就是 `127.0.0.1`。

## 拿到 flag

发送请求，响应里直接回显 flag：

![拿到 flag](image-9.png)

*图 9：`X-Forwarded-For: 127.0.0.1` 生效，页面返回 flag*

```text
CTF2{c56bfec1-c066-4ca7-bc25-120666c2d5ac}
```

## 知识点补充

### 1. 三个请求头分别在说什么

| 请求头 | 典型值 | 作用 | 能否伪造 |
| --- | --- | --- | --- |
| `Referer` | `https://a.com/page` | 请求来源页面 | 可以 |
| `User-Agent` | `Mozilla/5.0 ...` | 客户端标识 | 可以 |
| `X-Forwarded-For` | `1.2.3.4, 10.0.0.1` | 代理链上的客户端 IP | 可以（除非被代理改写） |
| `X-Real-IP` | `1.2.3.4` | 单值版客户端 IP | 可以 |
| `Forwarded` | `for=1.2.3.4;proto=https` | RFC 7239 标准转发头 | 可以 |
| `Cookie` | `username=admin` | 客户端状态 | 可以 |

共同点：**它们都是客户端写的字符串，不是身份证明。** 服务端只能把它们当“线索”，不能当“凭证”。

### 2. `REMOTE_ADDR` 和 `HTTP_X_FORWARDED_FOR` 的区别

PHP 里这两类变量来源完全不同：

| 变量 | 来源 | 是否可信 |
| --- | --- | --- |
| `$_SERVER['REMOTE_ADDR']` | TCP 连接的对端地址 | 相对可信（除非对端是代理） |
| `$_SERVER['HTTP_X_FORWARDED_FOR']` | 请求头 `X-Forwarded-For` | 客户端可写，默认不可信 |

如果题目代码写的是：

```php
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
    die('No!!! you can only read this locally!!!');
}
```

那加 XFF 是没用的，必须真的从本机发起连接。但这题在直连环境下加 XFF 能过，说明它读的是 `HTTP_X_FORWARDED_FOR`——一个典型的**把客户端头当成本地判断依据**的错误。

### 3. 反向代理改写 XFF 的几种写法

| 配置 | 效果 | 对伪造的影响 |
| --- | --- | --- |
| `proxy_set_header X-Forwarded-For $remote_addr;` | 完全覆盖 | 伪造无效 |
| `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` | 追加真实 IP | 看后端取第几个 |
| `proxy_set_header X-Real-IP $remote_addr;` | 覆盖单值头 | 伪造无效 |
| 不设置 | 原样透传 | 伪造有效 |

如果后端取 `X-Forwarded-For` 的**第一个**值，追加模式下伪造仍然有效；如果取**最后一个**，就失效。安全做法是只信任已知代理的地址，用 Nginx 的 `set_real_ip_from` + `real_ip_header` 从右往左剥掉可信代理，而不是直接取第一个。

### 4. 为什么“直连”能绕过

| 路径 | 中间层 | XFF 是否被改 |
| --- | --- | --- |
| `http-ctf2` | openresty 反向代理 | 可能被追加/覆盖 |
| `tcp-ctf2` | 直接映射容器端口 | 不改 |

这不是 CTF 特有的东西。现实里也经常遇到：同一个应用，走公司网关和走内网直连，看到的 `X-Forwarded-For`、`Host`、`X-Forwarded-Proto` 完全不同。**排查请求头问题时，先画链路，再怀疑代码。**

### 5. 常见的本地判断绕过写法

如果目标读的是 XFF，除了 `127.0.0.1`，还可以试：

```text
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: localhost
X-Forwarded-For: 127.1
X-Forwarded-For: ::1
X-Forwarded-For: 127.0.0.1, 127.0.0.1
X-Real-IP: 127.0.0.1
Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
Forwarded: for=127.0.0.1
```

不同框架读的头不一样：Express 常用 `req.ip`（信任代理时读 XFF），Django 用 `REMOTE_ADDR` 或 `X-Forwarded-For`，Flask 的 `request.remote_addr` 默认不读 XFF。**先枚举，再决定用哪个头。**

### 6. 用 curl 复现

没有 Burp 时，一条命令就能把三个头带上：

```bash
curl -k 'https://<host>.tcp-ctf2.dasctf.com:9999/Secret.php' \
  -H 'Referer: https://Sycsecret.buuoj.cn' \
  -H 'User-Agent: Syclover' \
  -H 'X-Forwarded-For: 127.0.0.1'
```

- `-k`：跳过证书校验。CTF 的临时证书不受信任，不加会报 SSL 错误；**只对授权靶场用**；
- `-H`：逐个头覆盖，`User-Agent` 会替换 curl 默认的 `curl/x.y.z`；
- 如果 DNS 解析不到，可以用 `--resolve` 把域名指到 IP。

想对比网关和直连的差异，可以分别请求两个地址，看响应头里的 `Server` 和回显：

```bash
curl -k -s -D - 'https://<host>.http-ctf2.dasctf.com/Secret.php' -o /dev/null
curl -k -s -D - 'https://<host>.tcp-ctf2.dasctf.com:9999/Secret.php' -o /dev/null
```

## 新手常见问题

{% note info %}
**Q1：F12 看到的链接为什么点不动？**

因为 `<a>` 上写了 `onclick="return false;"`，点击事件被 JavaScript 拦掉了；样式又把下划线和手型光标去掉了。但这只是前端障眼法，`href` 还在，直接复制到地址栏就能访问。
{% endnote %}

{% note info %}
**Q2：Referer 是什么？为什么能随便改？**

`Referer` 是浏览器告诉服务器“我从哪个页面点过来”的请求头。它只是 HTTP 报文里的一行文本，客户端想写什么就写什么。Burp、curl、浏览器扩展都能改。服务端只能拿它做统计或粗粒度判断，不能当权限凭证。
{% endnote %}

{% note info %}
**Q3：为什么地址栏直接访问时没有 Referer？**

因为 Referer 通常由“点击链接/加载资源”触发。地址栏输入、书签、从 HTTPS 跳到 HTTP、或者页面设置了 `Referrer-Policy: no-referrer`，都可能不带 Referer。所以服务端如果强依赖 Referer，正常用户也可能被误伤。
{% endnote %}

{% note info %}
**Q4：我加了 `X-Forwarded-For: 127.0.0.1`，为什么还是提示只能本地访问？**

先确认链路。如果走的是 `http-ctf2` 网关，openresty 很可能把 XFF 追加或覆盖成了真实客户端 IP，后端看到的不是你写的值。换成 `tcp-ctf2` 直连、端口 `9999` 再试，这一步通常就通了。
{% endnote %}

{% note info %}
**Q5：怎么判断中间有没有反向代理？**

看响应头里的 `Server`（比如 `openresty`、`nginx`）、看主机名里的 `http-ctf2`、对比直连和网关的回显。也可以用 `curl -D -` 打印响应头。更直接的办法：同一个请求分别打两个入口，看 `X-Forwarded-For` 相关的行为是否不同。
{% endnote %}

{% note info %}
**Q6：为什么直连端口是 9999？**

这是 CTF2 平台给 TCP 直连分配的端口，不是题目代码里的端口。不同平台、不同题目的端口可能不同，以平台给出的连接信息为准。本文的 `9999` 只适用于当时的 CTF2 环境。
{% endnote %}

{% note info %}
**Q7：Burp 改了 URL 还是连不上？**

最常见的原因是只改了 URL，没改 Target 的端口和协议。检查三件事：Host 是不是 `*.tcp-ctf2.dasctf.com`、Port 是不是 `9999`、`Use HTTPS` 有没有勾上。如果还不行，试试 `Override SNI`，或者换 `curl -k` 排除 Burp 配置问题。
{% endnote %}

{% note info %}
**Q8：为什么直连也要 HTTPS？**

因为平台的 TCP 入口在外面套了 TLS，`9999` 端口上跑的不是明文 HTTP。浏览器写 `https://`，Burp 勾 `Use HTTPS`，pwntools 写 `ssl=True`。用 `http://` 去连会直接握手失败。
{% endnote %}

{% note info %}
**Q9：能不能用浏览器插件改请求头？**

可以，但不如 Burp 稳。浏览器插件改的是浏览器发出的请求，遇到 TLS、HTTP/2、端口配置问题时不好排查。CTF 里推荐 Burp Repeater，能清楚看到最终发出去的每一个头。
{% endnote %}

{% note info %}
**Q10：这题的现实意义是什么？**

它把“请求头信任边界”讲得很直白：`Referer`、`User-Agent`、`X-Forwarded-For` 都是客户端可写的。现实里的越权、内网绕过、IP 白名单绕过，很多都是服务端错误地信任了这些头。反过来，代理改写 XFF 又是平台侧的正确防护——两边都没错，错的是“用 XFF 做本地判断”这个设计。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | 操作 | 结果 |
| --- | --- | --- | --- |
| 1 | 找入口 | F12 看源码，找 `href="Secret.php"` | 发现隐藏链接 |
| 2 | 触发第一道门 | 访问 `/Secret.php` | 提示来源不是 `Sycsecret.buuoj.cn` |
| 3 | 伪造来源 | 加 `Referer: https://Sycsecret.buuoj.cn` | 提示使用 `Syclover` 浏览器 |
| 4 | 伪造 UA | 加 `User-Agent: Syclover` | 提示只能本地访问 |
| 5 | 伪造本地 IP | 加 `X-Forwarded-For: 127.0.0.1` | 网关环境下失败 |
| 6 | 换直连 | `http-ctf2` → `tcp-ctf2`，端口 `9999` | 绕过反代改写 |
| 7 | 配置 Burp | Host 改 `tcp`，Port `9999`，勾 HTTPS | 请求直达容器 |
| 8 | 重放 | 三个头一起带 | 回显 flag |

## 顺手聊聊怎么防

这道题的“漏洞”本质是**把客户端可控的请求头当成了安全判断依据**。防护要分两层看：

| 层面 | 措施 | 说明 |
| --- | --- | --- |
| 应用 | 不要用 `Referer` / `User-Agent` 做权限判断 | 它们只是提示信息，不是凭证 |
| 应用 | 本地接口用 `REMOTE_ADDR` 或真正的认证 | 更好的做法是只监听 `127.0.0.1`，或加 token |
| 应用 | 不要信任客户端传来的 `X-Forwarded-For` | 除非请求确实来自已知代理 |
| 代理 | 覆盖或剥离客户端伪造的转发头 | `proxy_set_header X-Forwarded-For $remote_addr;` |
| 代理 | 只信任已知代理链 | Nginx `set_real_ip_from` + `real_ip_header` |
| 运维 | 管理接口不要暴露在公网 | 内网访问、VPN、零信任网关 |
| 监控 | 记录真实来源并限速 | 方便溯源，也能挡住批量探测 |

一个相对安全的 Nginx 配置思路：

```nginx
# 只信任来自这些网段的 XFF
set_real_ip_from 10.0.0.0/8;
real_ip_header X-Forwarded-For;
real_ip_recursive on;

# 发给后端时用解析后的真实 IP 覆盖，避免客户端伪造
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
```

{% note success %}
**一条原则**：请求头是“客户端说的话”，不是“客户端是谁”。身份要从连接、凭证、签名里来，不能从 `Referer`、`User-Agent`、`X-Forwarded-For` 里来。
{% endnote %}

## 小结

这道题的技术点不复杂，但它是理解“请求头伪造”和“网络链路”的好例子：

- **隐藏链接只是前端障眼法**：`onclick="return false"` 挡不住地址栏，F12 一看就现形；
- **`Referer` 和 `User-Agent` 都是客户端可写的**：题目让你伪造，你就伪造；
- **`X-Forwarded-For` 的坑在链路上**：同样的 payload，直连能过，走 openresty 网关就失效；
- **反向代理会改写转发头**：`$proxy_add_x_forwarded_for` 追加、`$remote_addr` 覆盖，后端取第一个还是最后一个，结果完全不同；
- **换入口比换 payload 更有效**：`http-ctf2` → `tcp-ctf2`，端口 `9999`，请求绕过网关直达容器；
- **Burp 改目标要改三处**：Host、Port、HTTPS，少一个都连不上；
- **现实里的对应问题**：IP 白名单绕过、内网接口越权、日志里的假来源，很多都源于“信任了不该信任的头”。

下一题可以往这几个方向走：

| 方向 | 要解决的问题 |
| --- | --- |
| 代理链与真实 IP | `X-Forwarded-For` 多值、`X-Real-IP`、`Forwarded` 的优先级 |
| Host 头攻击 | 虚拟主机路由、密码重置链接污染 |
| 请求走私 | `Content-Length` / `Transfer-Encoding` 不一致 |
| HTTP/2 伪头 | `:authority`、`Host` 与 SNI 的差异 |
| 认证绕过 | Cookie、JWT、Session 的签名与校验 |

{% note success %}
**一条经验**：遇到“加了某个头却没反应”的题，先别怀疑 payload。画一遍请求链路，确认这个头有没有被中间层改过、有没有真的到达后端。**很多时候不是你不会绕，而是请求根本没按你以为的路线走。**
{% endnote %}
